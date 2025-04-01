/*
 * Copyright 2024 LY Corporation
 *
 * LY Corporation licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

package jp.co.lycorp.webauthn.authenticator.objectgenerator

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.google.common.truth.Truth.assertThat
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import jp.co.lycorp.webauthn.model.AndroidKeyAttestationStatement
import jp.co.lycorp.webauthn.model.AttestationObject
import jp.co.lycorp.webauthn.model.AuthenticatorExtensionsOutput
import jp.co.lycorp.webauthn.model.COSEAlgorithmIdentifier
import jp.co.lycorp.webauthn.model.NoneAttestationStatement
import jp.co.lycorp.webauthn.model.getSignatureAlgorithmName
import jp.co.lycorp.webauthn.util.Fido2Util
import jp.co.lycorp.webauthn.util.SecureExecutionHelper
import jp.co.lycorp.webauthn.util.toBase64url
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class Fido2ObjectGeneratorTest {

    private lateinit var hash: ByteArray
    private lateinit var rpId: String
    private lateinit var aaguid: ByteArray
    private lateinit var credId: String
    private lateinit var keyAlias: String
    private var signCount: UInt = 0u
    private var extensions: AuthenticatorExtensionsOutput? = null
    private var signature: Signature? = null

    @BeforeEach
    fun setUp() {
        hash = ByteArray(32)
        rpId = "example.com"
        aaguid = ByteArray(16)
        credId = Fido2Util.generateRandomByteArray(32).toBase64url()
        signCount = 1u
        extensions = null
        keyAlias = credId
    }

    private fun createAttestationObject(generator: Fido2ObjectGenerator): AttestationObject {
        val attestationObject: AttestationObject = generator.createAttestationObject(
            hash,
            rpId,
            aaguid,
            credId,
            signCount,
            extensions,
            signature
        )

        assertThat(attestationObject).isNotNull()
        assertThat(attestationObject.fmt).isEqualTo(generator.fmt.value)
        return attestationObject
    }

    @Test
    fun testNoneObjectGeneratorCreateAttestationObject() {
        generateKey(keyAlias)
        signature = null
        val generator = NoneObjectGenerator()
        val attestationObject = createAttestationObject(generator)
        assertThat(attestationObject.attStmt).isInstanceOf(NoneAttestationStatement::class.java)
    }

    @Test
    fun testAndroidKeyObjectGeneratorCreateAttestationObject() {
        val keyPair = generateKey(keyAlias)
        signature = Signature.getInstance(
            COSEAlgorithmIdentifier.ES256.getSignatureAlgorithmName()
        ).apply { initSign(keyPair.private) }
        val generator = AndroidKeyObjectGenerator()
        val attestationObject = createAttestationObject(generator)
        assertThat(attestationObject.attStmt).isInstanceOf(AndroidKeyAttestationStatement::class.java)

        val verificationSignature = Signature.getInstance("SHA256withECDSA")
        verificationSignature.initVerify(keyPair.public)
        verificationSignature.update(attestationObject.authData + hash)
        val androidKeyAttestationStatement = attestationObject.attStmt as? AndroidKeyAttestationStatement
        val isVerified = verificationSignature.verify(androidKeyAttestationStatement!!.sig)
        assertThat(isVerified).isTrue()
    }

    @AfterEach
    fun tearDown() {
        SecureExecutionHelper.deleteKey(keyAlias)
    }

    private fun generateKey(alias: String): KeyPair {
        val keyPairGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            "AndroidKeyStore"
        )

        val keyGenParameterSpec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        ).run {
            setDigests(KeyProperties.DIGEST_SHA256)
            setUserAuthenticationRequired(false)
            build()
        }

        keyPairGenerator.initialize(keyGenParameterSpec)
        return keyPairGenerator.generateKeyPair()
    }
}
