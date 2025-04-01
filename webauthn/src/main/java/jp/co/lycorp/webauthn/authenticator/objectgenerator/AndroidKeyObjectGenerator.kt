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

import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.ECPublicKey
import jp.co.lycorp.webauthn.model.AndroidKeyAttestationStatement
import jp.co.lycorp.webauthn.model.AttestationObject
import jp.co.lycorp.webauthn.model.AttestationStatement
import jp.co.lycorp.webauthn.model.AttestationStatementFormat
import jp.co.lycorp.webauthn.model.AttestedCredData
import jp.co.lycorp.webauthn.model.AuthenticatorExtensionsOutput
import jp.co.lycorp.webauthn.model.COSEAlgorithmIdentifier
import jp.co.lycorp.webauthn.model.EC2COSEKey
import jp.co.lycorp.webauthn.util.SecureExecutionHelper
import jp.co.lycorp.webauthn.util.base64urlToByteArray

internal class AndroidKeyObjectGenerator : Fido2ObjectGenerator() {
    override val fmt: AttestationStatementFormat = AttestationStatementFormat.ANDROID_KEY

    override fun createAttestationObject(
        hash: ByteArray,
        rpId: String,
        aaguid: ByteArray,
        credId: String,
        signCount: UInt,
        extensions: AuthenticatorExtensionsOutput?,
        signature: Signature?
    ): AttestationObject {
        val credIdBytes = credId.base64urlToByteArray()
        val keyAlias = credId
        val publicKey = SecureExecutionHelper.getPublicKey(keyAlias)
        val encodedCredPubKey = EC2COSEKey(publicKey as ECPublicKey)
            .toCBOR()
        val rpIdHash = MessageDigest.getInstance("SHA-256").digest(rpId.toByteArray())
        val attestedCredData = AttestedCredData(
            aaguid,
            credIdBytes,
            encodedCredPubKey
        )
        val authenticatorData =
            createAuthenticatorData(
                signCount = signCount,
                rpIdHash = rpIdHash,
                extensions = extensions?.toCBOR(),
                attestedCredData = attestedCredData,
            )
        val authenticatorDataBytes = authenticatorData.toByteArray()
        signature!!.update(authenticatorDataBytes + hash)
        val sig = signature.sign()
        val certChain = SecureExecutionHelper.getX509Certificates(keyAlias)
        val x5c = certChain.map { it.encoded }
        val attStmt: AttestationStatement = AndroidKeyAttestationStatement(
            alg = COSEAlgorithmIdentifier.ES256.value,
            sig = sig,
            x5c = x5c,
        )

        return AttestationObject(authenticatorDataBytes, fmt.value, attStmt)
    }
}
