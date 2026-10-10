package com.passman.app

import android.app.KeyguardManager
import android.os.SystemClock
import androidx.fragment.app.FragmentActivity
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.Until
import java.util.UUID
import java.util.concurrent.atomic.AtomicInteger
import java.util.regex.Pattern
import kotlin.concurrent.thread
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The real per-use auth path, which [KeystoreBridgeInstrumentedTest] turns off:
 * every key use shows the screen-lock prompt, and this test types the PIN. With
 * auth off, feeding the AAD before the prompt went unseen and broke every real
 * create. Needs a test phone with a PIN screen lock (a fingerprint as well is
 * fine) and that PIN passed in:
 *
 *   adb shell am instrument -w -e devicePin 1234 \
 *     -e class com.passman.app.KeystoreAuthPathTest \
 *     com.passman.app.test/androidx.test.runner.AndroidJUnitRunner
 *
 * Skipped without it (CI's emulator has no screen lock).
 */
@RunWith(AndroidJUnit4::class)
class KeystoreAuthPathTest {

    @Test
    fun wrap_and_unwrap_each_ask_for_the_screen_lock_and_round_trip() {
        val pin = InstrumentationRegistry.getArguments().getString("devicePin")
        assumeTrue("no devicePin argument", pin != null)
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val ctx = instrumentation.targetContext
        assumeTrue(
            "no secure screen lock",
            ctx.getSystemService(KeyguardManager::class.java).isDeviceSecure,
        )
        val device = UiDevice.getInstance(instrumentation)

        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            var activity: FragmentActivity? = null
            scenario.onActivity { activity = it }
            val bridge = KeystoreBridgeImpl(ctx, requireAuth = true) { activity }
            val prompts = AtomicInteger()
            val typist = thread {
                repeat(2) { if (enterPin(device, pin!!)) prompts.incrementAndGet() }
            }
            val alias = "passman-test-${UUID.randomUUID()}"
            val secret = ByteArray(32) { (it * 7 + 1).toByte() }
            try {
                val wrapped = bridge.wrap(alias, 1u, secret.copyOf())
                val recovered = bridge.unwrap(alias, 1u, wrapped.iv, wrapped.ciphertext)
                assertArrayEquals(secret, recovered)
            } finally {
                typist.join()
                bridge.invalidate(alias)
            }
            assertEquals("each key use must ask for the screen lock", 2, prompts.get())
        }
    }

    /**
     * Waits for the prompt's PIN field, types the PIN and waits for it to close.
     * Works with or without a fingerprint enrolled: with one, the prompt opens on
     * the fingerprint view, so this first taps its switch-to-PIN button. That
     * button is found by the stock Android id, or else by its text; Samsung's
     * exact text is a best guess.
     */
    private fun enterPin(device: UiDevice, pin: String): Boolean {
        // Stock Android and Samsung's own prompt both name the field lockPassword.
        val field = By.res(Pattern.compile(".*:id/lockPassword"))
        val useCredential = listOf(
            By.res(Pattern.compile(".*:id/button_use_credential")),
            By.clickable(true)
                .text(Pattern.compile(".*use (pin|password|pattern).*", Pattern.CASE_INSENSITIVE)),
        )
        val deadline = SystemClock.uptimeMillis() + PROMPT_WAIT_MS
        while (!device.hasObject(field)) {
            val left = deadline - SystemClock.uptimeMillis()
            if (left <= 0) return false
            val button = useCredential.firstNotNullOfOrNull { device.findObject(it) }
            if (button == null) {
                device.wait(Until.hasObject(field), minOf(left, POLL_MS))
            } else {
                // Tap once only, then give the PIN view the rest of the time to show.
                button.click()
                device.wait(Until.findObject(field), left) ?: return false
            }
        }
        device.executeShellCommand("input text $pin")
        device.pressEnter()
        // Wait for this prompt to close so the next wait sees the next prompt.
        device.wait(Until.gone(field), PROMPT_WAIT_MS)
        return true
    }

    private companion object {
        const val PROMPT_WAIT_MS = 20_000L
        const val POLL_MS = 500L
    }
}
