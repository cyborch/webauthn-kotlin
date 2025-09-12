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

package com.linecorp.webauthn.authenticator.keygenerator

import com.linecorp.webauthn.model.COSEAlgorithmIdentifier
import java.security.KeyPair

abstract class Fido2KeyGenerator {
    val lock = Any()

    abstract fun generateFido2Key(
        keyAlias: String,
        challenge: ByteArray?,
        publicKeyAlgorithm: COSEAlgorithmIdentifier,
        isStrongBoxBacked: Boolean,
        userAuthenticationRequired: Boolean = true
    ): KeyPair
}
