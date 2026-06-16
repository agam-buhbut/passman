package com.passman.app

import android.graphics.Bitmap
import android.graphics.Color
import androidx.compose.foundation.Image
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter

/** Encode `content` as a square QR [ImageBitmap] of `size` px. */
private fun qrBitmap(content: String, size: Int): ImageBitmap {
    val matrix = QRCodeWriter().encode(content, BarcodeFormat.QR_CODE, size, size)
    val bitmap = Bitmap.createBitmap(size, size, Bitmap.Config.RGB_565)
    for (x in 0 until size) {
        for (y in 0 until size) {
            bitmap.setPixel(x, y, if (matrix.get(x, y)) Color.BLACK else Color.WHITE)
        }
    }
    return bitmap.asImageBitmap()
}

/** A scannable QR code for `content` (e.g. the `otpauth://` provisioning URI). */
@Composable
fun QrCode(content: String, modifier: Modifier = Modifier, size: Int = 512) {
    val image = remember(content, size) { qrBitmap(content, size) }
    Image(bitmap = image, contentDescription = "TOTP setup QR code", modifier = modifier)
}
