package com.passman.app

import android.app.KeyguardManager
import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import java.security.KeyStore
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import uniffi.passman_uniffi.KeystoreBridge
import uniffi.passman_uniffi.KeystoreFailure
import uniffi.passman_uniffi.SecurityLevel
import uniffi.passman_uniffi.WrapOutput

/**
 * The Android `Keystore` mechanics (Android plan Task 8) — the security-critical
 * shim the host `passman-hsm` orchestrates against via the UniFFI `KeystoreBridge`.
 *
 * Obligations (the host suite cannot verify these; the on-device tests are the
 * gate):
 *  1. `updateAAD([slotTag])` on **both** encrypt and decrypt — binds a blob to
 *     its slot; omitting it symmetrically still round-trips but voids the
 *     cross-slot binding (the highest-risk item).
 *  2. Delete the key on **any** post-keygen failure inside [wrap] (GCM-nonce
 *     safety, invariant 6).
 *  3. IV strictly from `cipher.iv`; a fresh key per [wrap].
 *  4. Map biometric outcomes precisely (only `KeyPermanentlyInvalidated` →
 *     [KeystoreFailure.KeyInvalidated]; lockout/timeout/cancel are transient).
 *  5. Scrub plaintext `ByteArray`s; never put secret/message into a thrown error.
 *
 * @param requireAuth per-use biometric/credential auth (production: `true`). The
 *   instrumented AAD/tamper tests pass `false` so the crypto-binding controls
 *   run headlessly — orthogonal to, and not a substitute for, the auth path.
 * @param activityProvider supplies the current [FragmentActivity] for the
 *   `BiometricPrompt` (and the `KeyguardManager` probe).
 */
class KeystoreBridgeImpl(
    private val appContext: Context,
    private val requireAuth: Boolean,
    private val activityProvider: () -> FragmentActivity?,
) : KeystoreBridge {

    private val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    override fun wrap(alias: String, slotTag: UByte, material: ByteArray): WrapOutput {
        generateKey(alias)
        try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, secretKey(alias))
            cipher.updateAAD(byteArrayOf(slotTag.toByte())) // obligation 1 (encrypt)
            authenticate(cipher)
            val iv = cipher.iv // obligation 3
            val ciphertext = cipher.doFinal(material)
            return WrapOutput(iv, ciphertext, securityLevelOf(alias))
        } catch (t: Throwable) {
            runCatching { keyStore.deleteEntry(alias) } // obligation 2
            throw t.asKeystoreFailure()
        } finally {
            material.fill(0) // obligation 5
        }
    }

    override fun unwrap(
        alias: String,
        slotTag: UByte,
        iv: ByteArray,
        ciphertext: ByteArray,
    ): ByteArray {
        try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, secretKey(alias), GCMParameterSpec(GCM_TAG_BITS, iv))
            cipher.updateAAD(byteArrayOf(slotTag.toByte())) // obligation 1 (decrypt)
            authenticate(cipher)
            // A wrong slot (AAD) or a tampered blob fails the GCM tag here.
            return cipher.doFinal(ciphertext)
        } catch (t: Throwable) {
            throw t.asKeystoreFailure()
        }
    }

    override fun invalidate(alias: String) {
        // Idempotent: a missing alias is success.
        runCatching { keyStore.deleteEntry(alias) }.getOrElse { throw KeystoreFailure.Backend() }
    }

    override fun probe(): SecurityLevel {
        val km = appContext.getSystemService(KeyguardManager::class.java)
        if (km == null || !km.isDeviceSecure) throw KeystoreFailure.NoSecureLockOrHardware()
        // Mint and destroy a throwaway hardware key to read its security level.
        val probeAlias = "passman-probe-${UUID.randomUUID()}"
        return try {
            generateKey(probeAlias)
            securityLevelOf(probeAlias)
        } catch (t: Throwable) {
            throw t.asKeystoreFailure()
        } finally {
            runCatching { keyStore.deleteEntry(probeAlias) }
        }
    }

    // ----- key generation -----------------------------------------------------

    private fun generateKey(alias: String) {
        val builder = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setInvalidatedByBiometricEnrollment(true)
        if (requireAuth) {
            builder.setUserAuthenticationRequired(true)
            // API 30+: per-use auth (timeout 0) — the security-critical choice.
            builder.setUserAuthenticationParameters(
                0,
                KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
            )
        }
        // Prefer StrongBox; fall back to TEE if the secure element is unavailable.
        try {
            generateWith(builder.setIsStrongBoxBacked(true).build())
        } catch (_: StrongBoxUnavailableException) {
            generateWith(builder.setIsStrongBoxBacked(false).build())
        }
    }

    private fun generateWith(spec: KeyGenParameterSpec) {
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        generator.init(spec)
        generator.generateKey()
    }

    private fun secretKey(alias: String): SecretKey =
        keyStore.getKey(alias, null) as? SecretKey ?: throw KeystoreFailure.Backend()

    @Suppress("DEPRECATION")
    private fun securityLevelOf(alias: String): SecurityLevel {
        return try {
            val key = secretKey(alias)
            val factory = SecretKeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE)
            val info = factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo
            when {
                android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.S ->
                    when (info.securityLevel) {
                        KeyProperties.SECURITY_LEVEL_STRONGBOX -> SecurityLevel.STRONG_BOX
                        KeyProperties.SECURITY_LEVEL_SOFTWARE,
                        KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE,
                        KeyProperties.SECURITY_LEVEL_UNKNOWN,
                        -> if (info.isInsideSecureHardware) {
                            SecurityLevel.TRUSTED_ENVIRONMENT
                        } else {
                            SecurityLevel.SOFTWARE
                        }
                        else -> SecurityLevel.TRUSTED_ENVIRONMENT
                    }
                info.isInsideSecureHardware -> SecurityLevel.TRUSTED_ENVIRONMENT
                else -> SecurityLevel.SOFTWARE
            }
        } catch (_: Throwable) {
            SecurityLevel.SOFTWARE
        }
    }

    // ----- async BiometricPrompt -> synchronous bridge ------------------------

    private fun authenticate(cipher: Cipher) {
        if (!requireAuth) return
        val activity = activityProvider() ?: throw KeystoreFailure.NoSecureLockOrHardware()
        val latch = CountDownLatch(1)
        var failure: KeystoreFailure? = null
        activity.runOnUiThread {
            val prompt = BiometricPrompt(
                activity,
                activity.mainExecutor,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        latch.countDown()
                    }

                    override fun onAuthenticationError(code: Int, msg: CharSequence) {
                        failure = mapAuthError(code)
                        latch.countDown()
                    }
                    // onAuthenticationFailed = a non-terminal mismatch; let the user retry.
                },
            )
            val info = BiometricPrompt.PromptInfo.Builder()
                .setTitle("Unlock passman")
                .setSubtitle("Authenticate to use your vault key")
                .setAllowedAuthenticators(
                    androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG or
                        androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL,
                )
                .build()
            prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
        }
        // Bound the wait: if the BiometricPrompt callback never fires (e.g. the
        // activity is recreated), await() would otherwise block forever. On
        // timeout, fail the op cleanly as a transient cancellation.
        if (!latch.await(60, TimeUnit.SECONDS)) throw KeystoreFailure.Cancelled()
        failure?.let { throw it }
    }

    /** Obligation 4: only a permanently-invalidated key is non-transient. */
    private fun mapAuthError(code: Int): KeystoreFailure = when (code) {
        BiometricPrompt.ERROR_USER_CANCELED,
        BiometricPrompt.ERROR_NEGATIVE_BUTTON,
        BiometricPrompt.ERROR_CANCELED,
        -> KeystoreFailure.Cancelled()
        BiometricPrompt.ERROR_LOCKOUT,
        BiometricPrompt.ERROR_LOCKOUT_PERMANENT,
        BiometricPrompt.ERROR_TIMEOUT,
        -> KeystoreFailure.Lockout()
        BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL,
        BiometricPrompt.ERROR_HW_NOT_PRESENT,
        BiometricPrompt.ERROR_HW_UNAVAILABLE,
        -> KeystoreFailure.NoSecureLockOrHardware()
        else -> KeystoreFailure.Backend()
    }

    /** Normalize a Java exception to a data-free [KeystoreFailure] (obligation 5). */
    private fun Throwable.asKeystoreFailure(): KeystoreFailure = when (this) {
        is KeystoreFailure -> this
        is android.security.keystore.KeyPermanentlyInvalidatedException -> KeystoreFailure.KeyInvalidated()
        is javax.crypto.AEADBadTagException -> KeystoreFailure.AuthFailed()
        is javax.crypto.BadPaddingException -> KeystoreFailure.AuthFailed()
        is android.security.keystore.UserNotAuthenticatedException -> KeystoreFailure.Lockout()
        else -> KeystoreFailure.Backend()
    }

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val GCM_TAG_BITS = 128
    }
}
