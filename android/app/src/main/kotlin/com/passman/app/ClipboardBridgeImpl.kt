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
 * cookie digest (core never hashes); the write is flagged sensitive so a
 * clipboard-history manager excludes it.
 */
class ClipboardBridgeImpl(private val context: Context) : ClipboardBridge {

    private val manager: ClipboardManager? =
        context.getSystemService(ClipboardManager::class.java)

    override fun write(secret: String): ByteArray {
        val clip = ClipData.newPlainText("passman", secret).apply {
            // EXTRA_IS_SENSITIVE excludes the clip from clipboard previews/history.
            // The key is only honored on Android 13+ (API 33); guard accordingly.
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
