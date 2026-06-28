package com.passman.app

import android.graphics.Bitmap
import android.graphics.Color
import androidx.compose.foundation.Image
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.produceState
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Encode `content` as a square QR [ImageBitmap] of `size` px, or `null` if the
 * encoder rejects the input (the caller then shows the raw text instead).
 */
private fun qrBitmap(content: String, size: Int): ImageBitmap? {
    val matrix = try {
        QRCodeWriter().encode(content, BarcodeFormat.QR_CODE, size, size)
    } catch (_: Exception) {
        // WriterException (e.g. content too long for the chosen size) — degrade to
        // the text fallback instead of crashing the screen.
        return null
    }
    // Fill one IntArray and blit it in a single setPixels call: still O(size^2),
    // but a single bitmap crossing instead of one per pixel.
    val pixels = IntArray(size * size)
    for (y in 0 until size) {
        val row = y * size
        for (x in 0 until size) {
            pixels[row + x] = if (matrix.get(x, y)) Color.BLACK else Color.WHITE
        }
    }
    val bitmap = Bitmap.createBitmap(size, size, Bitmap.Config.RGB_565)
    bitmap.setPixels(pixels, 0, size, 0, 0, size, size)
    return bitmap.asImageBitmap()
}

/** A scannable QR code for `content` (e.g. the `otpauth://` provisioning URI). */
@Composable
fun QrCode(content: String, modifier: Modifier = Modifier, size: Int = 512) {
    // Generate off the main thread: encode + the per-pixel fill is real work and
    // must not block the frame. produceState holds null until the bitmap is ready
    // (or stays null if encoding failed → text fallback below).
    val image by produceState<ImageBitmap?>(initialValue = null, content, size) {
        value = withContext(Dispatchers.Default) { qrBitmap(content, size) }
    }
    val bmp = image
    if (bmp != null) {
        Image(bitmap = bmp, contentDescription = "TOTP setup QR code", modifier = modifier)
    } else {
        Text(content, style = MaterialTheme.typography.bodySmall, modifier = modifier)
    }
}
