package com.passman.app

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.PersistableBundle
import java.security.MessageDigest
import uniffi.passman_uniffi.CallbackException
import uniffi.passman_uniffi.ClipboardBridge

/**
 * The OS clipboard (Android plan §5.3). The platform impl computes the SHA-256
 * cookie digest (core never hashes); the write is flagged sensitive on API 33+
 * so a clipboard-history manager excludes it. On API 30-32 (minSdk is 30) the
 * flag does not exist, so the caller's 30 s auto-clear is the mitigation — see
 * [write].
 */
class ClipboardBridgeImpl(private val context: Context) : ClipboardBridge {

    private val manager: ClipboardManager? =
        context.getSystemService(ClipboardManager::class.java)

    override fun write(secret: String): ByteArray {
        val clip = ClipData.newPlainText("passman", secret).apply {
            // EXTRA_IS_SENSITIVE asks the OS to exclude this clip from the
            // clipboard preview toast and from clipboard history. It is ONLY
            // honored on Android 13+ (API 33). minSdk here is 30, so on API
            // 30-32 a copied password IS eligible for the preview/history and we
            // cannot opt out (there is no pre-33 equivalent flag). For those
            // releases the mitigation is the caller's 30 s auto-clear, which wipes
            // the clip (and any single-slot history entry) shortly after the copy.
            // We do NOT raise minSdk — that would drop API 30-32 devices.
            if (Build.VERSION.SDK_INT >= 33) {
                description.extras = PersistableBundle().apply {
                    putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
                }
            }
        }
        (manager ?: throw CallbackException.Failed()).setPrimaryClip(clip)
        return sha256(secret)
    }

    override fun readDigest(): ByteArray? {
        val clip = manager?.primaryClip ?: return null
        if (clip.itemCount == 0) return null
        val text = clip.getItemAt(0).coerceToText(context)?.toString() ?: return null
        return sha256(text)
    }

    override fun setText(text: String) {
        (manager ?: throw CallbackException.Failed())
            .setPrimaryClip(ClipData.newPlainText("passman", text))
    }

    private fun sha256(value: String): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(value.toByteArray(Charsets.UTF_8))
}
