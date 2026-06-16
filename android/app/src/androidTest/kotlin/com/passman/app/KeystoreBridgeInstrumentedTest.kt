package com.passman.app

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.util.UUID
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import uniffi.passman_uniffi.KeystoreFailure

/**
 * On-device verification of the `KeystoreBridgeImpl` against the **real** Android
 * `Keystore` (Android plan Task 11). These are the anti-vacuous-pass negative
 * controls the host suite cannot run: they prove the slot-tag AAD binding (the
 * highest-risk obligation) and GCM tamper rejection actually hold on a device.
 *
 * Auth is disabled here (`requireAuth = false`) so the crypto-binding controls
 * run without a biometric prompt — orthogonal to the binding itself. The per-use
 * auth path is exercised by the app; its automation is a separate spike.
 */
@RunWith(AndroidJUnit4::class)
class KeystoreBridgeInstrumentedTest {

    private val ctx = InstrumentationRegistry.getInstrumentation().targetContext
    private val bridge = KeystoreBridgeImpl(ctx, requireAuth = false) { null }

    private fun alias() = "passman-test-${UUID.randomUUID()}"
    private fun secret() = ByteArray(32) { (it * 7 + 1).toByte() }

    private val vaultKey: UByte = 1u
    private val totpSeed: UByte = 2u

    @Test
    fun enroll_unwrap_round_trip_recovers_the_secret() {
        val alias = alias()
        val plaintext = secret()
        try {
            val wrapped = bridge.wrap(alias, vaultKey, plaintext.copyOf())
            assertEquals("GCM IV is 12 bytes", 12, wrapped.iv.size)
            val recovered = bridge.unwrap(alias, vaultKey, wrapped.iv, wrapped.ciphertext)
            assertArrayEquals(plaintext, recovered)
        } finally {
            bridge.invalidate(alias)
        }
    }

    @Test
    fun cross_slot_blob_is_rejected() {
        // A VaultKey blob (AAD=[1]) must not unwrap as a TotpSeed (AAD=[2]) —
        // the AAD slot binding is the highest-risk obligation.
        val alias = alias()
        try {
            val wrapped = bridge.wrap(alias, vaultKey, secret())
            try {
                bridge.unwrap(alias, totpSeed, wrapped.iv, wrapped.ciphertext)
                fail("cross-slot unwrap must be rejected (AAD mismatch)")
            } catch (_: KeystoreFailure.AuthFailed) {
                // expected: the GCM tag fails under the wrong AAD.
            }
        } finally {
            bridge.invalidate(alias)
        }
    }

    @Test
    fun tampered_ciphertext_is_rejected() {
        val alias = alias()
        try {
            val wrapped = bridge.wrap(alias, vaultKey, secret())
            val tampered = wrapped.ciphertext.copyOf()
            tampered[tampered.size - 1] = (tampered.last().toInt() xor 0x01).toByte()
            try {
                bridge.unwrap(alias, vaultKey, wrapped.iv, tampered)
                fail("a tampered blob must be rejected")
            } catch (_: KeystoreFailure.AuthFailed) {
                // expected: GCM tag verification fails.
            }
        } finally {
            bridge.invalidate(alias)
        }
    }

    @Test
    fun repeat_unwrap_of_the_same_blob_is_stable() {
        // The persisted blob unwraps to the same secret across repeated begin/
        // complete cycles (§6.6 — durable across calls).
        val alias = alias()
        val plaintext = secret()
        try {
            val wrapped = bridge.wrap(alias, vaultKey, plaintext.copyOf())
            val first = bridge.unwrap(alias, vaultKey, wrapped.iv, wrapped.ciphertext)
            val second = bridge.unwrap(alias, vaultKey, wrapped.iv, wrapped.ciphertext)
            assertArrayEquals(plaintext, first)
            assertArrayEquals(first, second)
        } finally {
            bridge.invalidate(alias)
        }
    }

    @Test
    fun invalidate_is_idempotent() {
        val alias = alias()
        bridge.wrap(alias, vaultKey, secret())
        bridge.invalidate(alias)
        // A second invalidate of a now-missing alias must not throw.
        bridge.invalidate(alias)
    }

    @Test
    fun uniffi_native_bridge_loads_and_round_trips() {
        // Task 10 Step 1: force the libpassman_uniffi.so load + a trivial
        // Kotlin -> Rust -> Kotlin FFI call. Throws (UnsatisfiedLinkError /
        // UniFFI checksum mismatch) if the native bridge is broken on-device.
        uniffi.passman_uniffi.androidInit()
    }
}
