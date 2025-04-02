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
import jp.co.lycorp.webauthn.model.AssertionObject
import jp.co.lycorp.webauthn.model.AttestationObject
import jp.co.lycorp.webauthn.model.AttestationStatementFormat
import jp.co.lycorp.webauthn.model.AttestedCredData
import jp.co.lycorp.webauthn.model.AuthenticatorData
import jp.co.lycorp.webauthn.model.AuthenticatorDataFlags
import jp.co.lycorp.webauthn.model.AuthenticatorExtensionsOutput

internal abstract class Fido2ObjectGenerator {

    abstract val fmt: AttestationStatementFormat

    abstract fun createAttestationObject(
        hash: ByteArray,
        rpId: String,
        aaguid: ByteArray,
        credId: String,
        signCount: UInt,
        extensions: AuthenticatorExtensionsOutput?,
        signature: Signature? = null
    ): AttestationObject

    fun createAssertionObject(
        hash: ByteArray,
        rpId: String,
        signCount: UInt,
        signature: Signature,
        extensions: AuthenticatorExtensionsOutput?,
    ): AssertionObject {
        val rpIdHash = MessageDigest.getInstance("SHA-256").digest(rpId.toByteArray())

        val authenticatorData =
            createAuthenticatorData(
                signCount = signCount,
                rpIdHash = rpIdHash,
                extensions = extensions?.toCBOR(),
                attestedCredData = null
            )
        val authenticatorDataBytes = authenticatorData.toByteArray()
        signature.update(authenticatorDataBytes + hash)
        val sig = signature.sign()

        return AssertionObject(
            authenticatorDataBytes,
            sig,
        )
    }

    protected fun createAuthenticatorData(
        signCount: UInt,
        rpIdHash: ByteArray,
        userPresent: Boolean = true,
        userVerified: Boolean = true,
        extensions: ByteArray? = null,
        attestedCredData: AttestedCredData?,
    ): AuthenticatorData {
        val attestedCredDataBytes = attestedCredData?.toByteArray()
        val flags =
            createFlags(
                userPresent,
                userVerified,
                attestedCredData != null,
                extensions,
            )
        return AuthenticatorData(
            rpIdHash,
            flags,
            signCount,
            attestedCredDataBytes,
            extensions
        )
    }

    protected fun createFlags(
        userPresent: Boolean,
        userVerified: Boolean,
        attestedCredDataIncluded: Boolean,
        extensions: ByteArray?,
    ): UByte {
        val up = userPresent
        val uv = userVerified
        val at = attestedCredDataIncluded
        val ed = extensions != null
        return AuthenticatorDataFlags.makeFlags(up, uv, at, ed)
    }
}
