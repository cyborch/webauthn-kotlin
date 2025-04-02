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

package jp.co.lycorp.webauthn.authenticator

import jp.co.lycorp.webauthn.authenticator.keygenerator.BiometricKeyGenerator
import jp.co.lycorp.webauthn.authenticator.keygenerator.DeviceCredentialKeyGenerator
import jp.co.lycorp.webauthn.authenticator.objectgenerator.AndroidKeyObjectGenerator
import jp.co.lycorp.webauthn.authenticator.objectgenerator.NoneObjectGenerator
import jp.co.lycorp.webauthn.db.CredentialSourceStorage
import jp.co.lycorp.webauthn.handler.BiometricAuthenticationHandler
import jp.co.lycorp.webauthn.handler.DeviceCredentialAuthenticationHandler
import jp.co.lycorp.webauthn.model.AttestationStatementFormat
import jp.co.lycorp.webauthn.model.AuthenticationMethod
import jp.co.lycorp.webauthn.model.AuthenticatorType
import jp.co.lycorp.webauthn.model.Fido2PromptInfo
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers

class AuthenticatorProvider(
    private val db: CredentialSourceStorage,
    private val databaseDispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val authenticationDispatcher: CoroutineDispatcher = Dispatchers.Main,
) {
    internal fun getAuthenticator(
        authenticationMethod: AuthenticationMethod,
        attestationStatement: AttestationStatementFormat,
        fido2PromptInfo: Fido2PromptInfo? = null,
    ): Authenticator {
        val authenticationHandler = when (authenticationMethod) {
            AuthenticationMethod.Biometric -> BiometricAuthenticationHandler(
                authenticationDispatcher
            )
            AuthenticationMethod.DeviceCredential -> DeviceCredentialAuthenticationHandler(
                authenticationDispatcher
            )
        }
        val fido2KeyGenerator = when (authenticationMethod) {
            AuthenticationMethod.Biometric -> BiometricKeyGenerator()
            AuthenticationMethod.DeviceCredential -> DeviceCredentialKeyGenerator()
        }
        val fido2ObjectGenerator = when (attestationStatement) {
            AttestationStatementFormat.NONE -> NoneObjectGenerator()
            AttestationStatementFormat.ANDROID_KEY -> AndroidKeyObjectGenerator()
            else -> AndroidKeyObjectGenerator()
        }
        val authType: AuthenticatorType = AuthenticatorType.getAuthenticatorType(
            authenticationMethod,
            attestationStatement
        )

        return Authenticator(
            db = db,
            authenticationHandler = authenticationHandler,
            fido2KeyGenerator = fido2KeyGenerator,
            fido2ObjectGenerator = fido2ObjectGenerator,
            authType = authType,
            fido2PromptInfo = fido2PromptInfo,
            databaseDispatcher = databaseDispatcher,
        )
    }
}
