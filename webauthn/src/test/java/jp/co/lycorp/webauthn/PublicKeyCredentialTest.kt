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

package jp.co.lycorp.webauthn

import android.content.Context
import android.util.Log
import androidx.fragment.app.FragmentActivity
import com.google.common.truth.Truth.assertThat
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import java.security.KeyPairGenerator
import jp.co.lycorp.webauthn.authenticator.Authenticator
import jp.co.lycorp.webauthn.authenticator.AuthenticatorProvider
import jp.co.lycorp.webauthn.exceptions.WebAuthnException
import jp.co.lycorp.webauthn.model.AttestationConveyancePreference
import jp.co.lycorp.webauthn.model.AttestationStatementFormat
import jp.co.lycorp.webauthn.model.AuthenticationMethod
import jp.co.lycorp.webauthn.model.AuthenticatorGetAssertionResult
import jp.co.lycorp.webauthn.model.AuthenticatorMakeCredentialResult
import jp.co.lycorp.webauthn.model.AuthenticatorSelectionCriteria
import jp.co.lycorp.webauthn.model.AuthenticatorType
import jp.co.lycorp.webauthn.model.COSEAlgorithmIdentifier
import jp.co.lycorp.webauthn.model.ClientExtensionInput
import jp.co.lycorp.webauthn.model.CredentialProtection
import jp.co.lycorp.webauthn.model.PublicKeyCredentialDescriptor
import jp.co.lycorp.webauthn.model.PublicKeyCredentialParams
import jp.co.lycorp.webauthn.model.PublicKeyCredentialRpEntity
import jp.co.lycorp.webauthn.model.PublicKeyCredentialSource
import jp.co.lycorp.webauthn.model.PublicKeyCredentialType
import jp.co.lycorp.webauthn.model.PublicKeyCredentialUserEntity
import jp.co.lycorp.webauthn.model.UserVerificationRequirement
import jp.co.lycorp.webauthn.publickeycredential.PublicKeyCredential
import jp.co.lycorp.webauthn.rp.AuthenticationData
import jp.co.lycorp.webauthn.rp.AuthenticationOptions
import jp.co.lycorp.webauthn.rp.RegistrationData
import jp.co.lycorp.webauthn.rp.RegistrationOptions
import jp.co.lycorp.webauthn.rp.RelyingParty
import jp.co.lycorp.webauthn.util.Fido2Util
import jp.co.lycorp.webauthn.util.MockCredentialSourceStorage
import jp.co.lycorp.webauthn.util.toBase64url
import kotlin.reflect.KClass
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class PublicKeyCredentialTest {

    private val mockActivity = mockk<FragmentActivity>()
    private val mockContext = mockk<Context>()
    private val mockAuthenticatorProvider = mockk<AuthenticatorProvider>()
    private val mockRelyingParty = mockk<RelyingParty>()
    private val mockAuthenticator = mockk<Authenticator>()
    private val mockDb = MockCredentialSourceStorage()

    private lateinit var publicKeyCredential: PublicKeyCredential

    private val dummyByteArray = ByteArray(32) { 0 }
    private val dummyRpEntity = PublicKeyCredentialRpEntity("example.com", "Example Relying Party")
    private val dummyUserEntity = PublicKeyCredentialUserEntity("user123", "User Name", "Display Name")
    private val es256CredParams = PublicKeyCredentialParams(
        PublicKeyCredentialType.PUBLIC_KEY,
        COSEAlgorithmIdentifier.ES256
    )
    private val registeredCredId = Fido2Util.generateRandomByteArray(32).toBase64url()
    private val registeredRpEntity = PublicKeyCredentialRpEntity("registered.com", "Example Registered Relying Party")
    private val registeredUserEntity = PublicKeyCredentialUserEntity("reg_user", "Reg User", "Reg User")
    private val registeredCredSource = jp.co.lycorp.webauthn.model.PublicKeyCredentialSource(
        id = registeredCredId,
        rpId = registeredRpEntity.id,
        userHandle = registeredUserEntity.id,
        aaguid = AuthenticatorType.BiometricAndroidKey.aaguid,
    )
    private val registeredCredDescriptor = PublicKeyCredentialDescriptor(
        type = PublicKeyCredentialType.PUBLIC_KEY.value,
        id = registeredCredSource.id,
        transports = null,
    )

    private val dummyRegistrationData: RegistrationData = RegistrationData(
        attestation = AttestationConveyancePreference.DIRECT,
        authenticatorSelection = AuthenticatorSelectionCriteria(null, UserVerificationRequirement.REQUIRED.value),
        challenge = Fido2Util.generateRandomByteArray(32).toBase64url(),
        excludeCredentials = emptyList(),
        extensions = ClientExtensionInput(),
        pubKeyCredParams = listOf(es256CredParams),
        rp = dummyRpEntity,
        user = dummyUserEntity,
    )
    private val dummyAuthenticationData: AuthenticationData = AuthenticationData(
        allowCredentials = listOf(registeredCredDescriptor),
        challenge = Fido2Util.generateRandomByteArray(32).toBase64url(),
        extensions = ClientExtensionInput(),
        rpId = dummyRpEntity.id,
        userVerification = UserVerificationRequirement.REQUIRED,
    )
    private val dummyRegistrationOptions: RegistrationOptions = RegistrationOptions(
        AttestationConveyancePreference.DIRECT,
        AuthenticatorSelectionCriteria(null, UserVerificationRequirement.PREFERRED.value),
        CredentialProtection(),
        dummyUserEntity.displayName,
        dummyUserEntity.name
    )
    private val dummyAuthenticationOptions: AuthenticationOptions = AuthenticationOptions(
        UserVerificationRequirement.PREFERRED,
        dummyUserEntity.name
    )

    private val keyPair = KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair()

    @BeforeEach
    fun setUp() {
        publicKeyCredential = PublicKeyCredential(
            rpClient = mockRelyingParty,
            db = mockDb,
            authenticationMethod = AuthenticationMethod.Biometric,
            attestationStatement = AttestationStatementFormat.ANDROID_KEY,
            authenticatorProvider = mockAuthenticatorProvider,
        )

        // Mock static Log class
        mockkStatic(Log::class)
        every { Log.v(any(), any()) } returns 0
        every { Log.d(any(), any()) } returns 0
        every { Log.i(any(), any()) } returns 0
        every { Log.e(any(), any()) } returns 0

        // Mock Activity and Context
        coEvery { mockActivity.applicationContext } returns mockContext

        // Mock Biometric Authenticator actions
        coEvery {
            mockAuthenticator.makeCredential(any(), any(), any(), any(), any(), any(), any())
        } returns Result.success(AuthenticatorMakeCredentialResult(dummyByteArray, dummyByteArray))
        coEvery {
            mockAuthenticator.getAssertion(any(), any(), any(), any(), any())
        } returns Result.success(
            AuthenticatorGetAssertionResult(dummyByteArray, dummyByteArray, dummyByteArray, dummyByteArray)
        )

        // Mock AuthenticatorProvider
        coEvery { mockAuthenticatorProvider.getAuthenticator(any(), any()) } returns mockAuthenticator

        // Mock RelyingParty actions
        coEvery { mockRelyingParty.getRegistrationData(any()) } returns dummyRegistrationData
        coEvery { mockRelyingParty.verifyRegistration(any()) } returns Unit
        coEvery { mockRelyingParty.getAuthenticationData(any()) } returns dummyAuthenticationData
        coEvery { mockRelyingParty.verifyAuthentication(any()) } returns Unit

        // Mock Fido2Util object
        mockkObject(Fido2Util)
        coEvery { Fido2Util.getPackageFacetID(any()) } returns "TEST_FACET_ID"
    }

    @Test
    fun `should throw TypeException when options user id length is invalid`() = runBlocking {
        listOf(
            generateString("a", 0),
            generateString("a", 65),
        ).forEach { invalidUserId ->
            coEvery {
                mockRelyingParty.getRegistrationData(any())
            } returns dummyRegistrationData.copy(user = dummyUserEntity.copy(id = invalidUserId))

            val result = publicKeyCredential.create(mockActivity, dummyRegistrationOptions, null)
            assertThat(result.isFailure).isTrue()
            assertThat(result.exceptionOrNull()).isInstanceOf(WebAuthnException.CoreException.TypeException::class.java)
        }
    }

    @Test
    fun `should work well when register and authenticate with valid parameters`() = runBlocking {
        coEvery { mockAuthenticatorProvider.getAuthenticator(any(), any()) } returns mockAuthenticator

        val regResult = publicKeyCredential.create(mockActivity, dummyRegistrationOptions, null)
        assertThat(regResult.isSuccess).isTrue()

        val authResult = publicKeyCredential.get(mockActivity, dummyAuthenticationOptions, null)
        assertThat(authResult.isSuccess).isTrue()
    }

    @Test
    fun `should allow concurrent execution of register with different rpEntity`(): Unit = runBlocking {
        val times = 10
        val registeredRpId = mutableListOf<String>()
        coEvery {
            mockAuthenticator.makeCredential(any(), any(), any(), any(), any(), any(), any())
        } coAnswers {
            val rpEntity: PublicKeyCredentialRpEntity = secondArg()
            if (rpEntity.id !in registeredRpId) {
                registeredRpId.add(rpEntity.id)
                Result.success(AuthenticatorMakeCredentialResult(dummyByteArray, dummyByteArray))
            } else {
                Result.failure(WebAuthnException.CoreException.InvalidStateException())
            }
        }

        performConcurrentExecution(times) {
            val newRpEntity = PublicKeyCredentialRpEntity("https://test-rp.com/$it", "test_rp")
            coEvery { mockRelyingParty.getRegistrationData(any()) } returns RegistrationData(
                attestation = AttestationConveyancePreference.DIRECT,
                authenticatorSelection = AuthenticatorSelectionCriteria(
                    null, UserVerificationRequirement.REQUIRED.value
                ),
                challenge = Fido2Util.generateRandomByteArray(32).toBase64url(),
                excludeCredentials = emptyList(),
                extensions = ClientExtensionInput(),
                pubKeyCredParams = listOf(es256CredParams),
                rp = newRpEntity,
                user = dummyUserEntity,
            )
            publicKeyCredential.create(mockActivity, dummyRegistrationOptions, null)
        }
    }

    @Test
    fun `should propagate exception when Authenticator throws exception`() = runBlocking {
        listOf(
            WebAuthnException.CoreException.InvalidStateException::class,
            WebAuthnException.CoreException.NotAllowedException::class,
        ).forEach { exceptionType ->
            coEvery {
                mockAuthenticator.makeCredential(any(), any(), any(), any(), any(), any(), any())
            } returns Result.failure(getExceptionBasedOnType(exceptionType))

            val regResult = publicKeyCredential.create(mockActivity, dummyRegistrationOptions, null)
            assertThat(regResult.isFailure).isTrue()
            assertThat(regResult.exceptionOrNull()).isInstanceOf(exceptionType.java)

            coEvery {
                mockAuthenticator.getAssertion(any(), any(), any(), any(), any())
            } returns Result.failure(getExceptionBasedOnType(exceptionType))

            val authResult = publicKeyCredential.get(mockActivity, dummyAuthenticationOptions, null)
            assertThat(authResult.isFailure).isTrue()
            assertThat(authResult.exceptionOrNull()).isInstanceOf(exceptionType.java)
        }
    }

    private fun generateString(pattern: String, length: Int): String {
        return pattern.repeat((length + pattern.length - 1) / pattern.length).take(length)
    }

    private fun performConcurrentExecution(times: Int, block: suspend (Int) -> Unit) = runTest {
        (1..times).map {
            async {
                block(it)
            }
        }.map { it.await() }
    }

    private fun getExceptionBasedOnType(exceptionClass: KClass<out Throwable>): Throwable {
        return when (exceptionClass) {
            WebAuthnException.CoreException.NotAllowedException::class ->
                WebAuthnException.CoreException.NotAllowedException()
            WebAuthnException.CoreException.InvalidStateException::class ->
                WebAuthnException.CoreException.InvalidStateException()
            else -> Exception("Unknown exception type")
        }
    }
}
