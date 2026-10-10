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

    /**
     * The shell's backstop for the 30 s auto-clear. Not part of [ClipboardBridge]:
     * the core never calls it. The caller asks the core to clear first and waits
     * a moment before calling this: the core's clear returns before the work is
     * done, and running both at once could empty the clipboard before the core
     * swaps in its fact.
     *
     * The core often cannot clear: Android 10+ refuses clipboard reads to an
     * app that is not in front, so the core sees an empty clipboard, and once
     * the session is locked the core ignores the request. So clear here when
     * the clipboard still holds the copied secret ([digest]), or when Android
     * will not let us look. That blind clear also wipes anything copied
     * elsewhere since; the user accepted that. Clearing needs no focus.
     */
    fun clearIfOursOrUnreadable(digest: ByteArray) {
        val current = readDigest()
        if (current == null || MessageDigest.isEqual(current, digest)) {
            manager?.clearPrimaryClip()
        }
    }

    private fun sha256(value: String): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(value.toByteArray(Charsets.UTF_8))
}
