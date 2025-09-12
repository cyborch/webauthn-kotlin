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

package com.linecorp.webauthn.authenticator.objectgenerator

import com.linecorp.webauthn.model.AttestationObject
import com.linecorp.webauthn.model.AttestationStatementFormat
import com.linecorp.webauthn.model.AttestedCredData
import com.linecorp.webauthn.model.AuthenticatorExtensionsOutput
import com.linecorp.webauthn.model.EC2COSEKey
import com.linecorp.webauthn.model.NoneAttestationStatement
import com.linecorp.webauthn.util.SecureExecutionHelper
import com.linecorp.webauthn.util.base64urlToByteArray
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.ECPublicKey

internal class NoneObjectGenerator : Fido2ObjectGenerator() {
    override val fmt: AttestationStatementFormat = AttestationStatementFormat.NONE

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
        val encodedCredPubKey = EC2COSEKey(publicKey as ECPublicKey).toCBOR()
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

        return AttestationObject(authenticatorDataBytes, fmt.value, NoneAttestationStatement())
    }
}
