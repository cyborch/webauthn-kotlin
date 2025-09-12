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

package com.linecorp.webauthn.model

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.UUID

enum class AuthenticatorType(val authenticatorName: String, val aaguid: UUID) {
    BiometricNone("BiometricNone", UUID.fromString("fca28135-9915-4c70-de30-56de200fd2cb")),
    BiometricAndroidKey("BiometricAndroidKey", UUID.fromString("8c120a4d-52b3-99ef-eaf6-7cfb2a3e3f89")),
    DeviceCredentialNone("DeviceCredentialNone", UUID.fromString("616fcfb7-8fe1-4b6a-ec90-5db1424a9b36")),
    DeviceCredentialAndroidKey("DeviceCredentialAndroidKey", UUID.fromString("2b7a96a3-f571-ee4c-632c-c5458dfadfe3")),
    ;

    fun aaguidBytes(): ByteArray = ByteBuffer.wrap(ByteArray(16)).apply {
        order(ByteOrder.BIG_ENDIAN)
        putLong(aaguid.mostSignificantBits)
        putLong(aaguid.leastSignificantBits)
    }.array()

    fun getAuthenticationMethod(): AuthenticationMethod = when (this) {
        BiometricNone -> AuthenticationMethod.Biometric
        BiometricAndroidKey -> AuthenticationMethod.Biometric
        DeviceCredentialNone -> AuthenticationMethod.DeviceCredential
        DeviceCredentialAndroidKey -> AuthenticationMethod.DeviceCredential
    }

    fun getAttestationStatementFormat(): AttestationStatementFormat = when (this) {
        BiometricNone -> AttestationStatementFormat.NONE
        BiometricAndroidKey -> AttestationStatementFormat.ANDROID_KEY
        DeviceCredentialNone -> AttestationStatementFormat.NONE
        DeviceCredentialAndroidKey -> AttestationStatementFormat.ANDROID_KEY
    }

    companion object {
        fun getAuthenticatorType(
            authenticationMethod: AuthenticationMethod,
            attestationStatementFormat: AttestationStatementFormat,
        ): AuthenticatorType = when (authenticationMethod) {
            AuthenticationMethod.Biometric -> {
                when (attestationStatementFormat) {
                    AttestationStatementFormat.NONE -> BiometricNone
                    AttestationStatementFormat.ANDROID_KEY -> BiometricAndroidKey
                }
            }
            AuthenticationMethod.DeviceCredential -> {
                when (attestationStatementFormat) {
                    AttestationStatementFormat.NONE -> DeviceCredentialNone
                    AttestationStatementFormat.ANDROID_KEY -> DeviceCredentialAndroidKey
                }
            }
        }
    }
}
