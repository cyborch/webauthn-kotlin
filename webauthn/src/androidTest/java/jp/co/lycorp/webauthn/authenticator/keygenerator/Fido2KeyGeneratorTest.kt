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

package jp.co.lycorp.webauthn.authenticator.keygenerator

import com.google.common.truth.Truth.assertThat
import java.security.KeyStore
import jp.co.lycorp.webauthn.model.COSEAlgorithmIdentifier
import jp.co.lycorp.webauthn.util.Fido2Util
import jp.co.lycorp.webauthn.util.toBase64url
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test

class Fido2KeyGeneratorTest {

    private val generatedAliases = mutableListOf<String>()

    private fun generateRandomAlias(): String {
        return Fido2Util.generateRandomByteArray(32).toBase64url()
    }

    private fun testKeyGenerator(keyGenerator: jp.co.lycorp.webauthn.authenticator.keygenerator.Fido2KeyGenerator) {
        val challenges = arrayOf(null, ByteArray(32) { it.toByte() })
        val strongBoxOptions = arrayOf(true, false)

        for (challenge in challenges) {
            for (isStrongBoxBacked in strongBoxOptions) {
                val keyAlias = generateRandomAlias()
                generatedAliases.add(keyAlias)

                try {
                    keyGenerator.generateFido2Key(
                        keyAlias = keyAlias,
                        challenge = challenge,
                        publicKeyAlgorithm = COSEAlgorithmIdentifier.ES256,
                        isStrongBoxBacked = isStrongBoxBacked
                    )
                } catch (e: Exception) {
                    assertThat(e).isNull()
                }

                val keyStore = KeyStore.getInstance("AndroidKeyStore").also {
                    it.load(null)
                }
                assertThat(keyStore.containsAlias(keyAlias)).isTrue()
            }
        }
    }

    @Test
    fun testBiometricKeyGeneratorGenerateFido2Key() {
        val keyGenerator = jp.co.lycorp.webauthn.authenticator.keygenerator.BiometricKeyGenerator()
        testKeyGenerator(keyGenerator)
    }

    @Test
    fun testDeviceCredentialKeyGeneratorGenerateFido2Key() {
        val keyGenerator =
            jp.co.lycorp.webauthn.authenticator.keygenerator.DeviceCredentialKeyGenerator()
        testKeyGenerator(keyGenerator)
    }

    @AfterEach
    fun tearDown() {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").also {
            it.load(null)
        }
        for (alias in generatedAliases) {
            if (keyStore.containsAlias(alias)) {
                keyStore.deleteEntry(alias)
            }
        }
        generatedAliases.clear()
    }
}
