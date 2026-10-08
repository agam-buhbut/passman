package com.passman.app

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

/** The TOTP setup screen shows the key from the otpauth link in groups of four. */
@RunWith(AndroidJUnit4::class)
class TotpKeyForDisplayTest {

    @Test
    fun keyIsTakenFromTheLinkAndGroupedByFour() {
        val uri = "otpauth://totp/passman:vault?secret=HT2IRGXPWNW3PZVQG2&issuer=passman&digits=6"
        assertEquals("HT2I RGXP WNW3 PZVQ G2", totpKeyForDisplay(uri))
    }

    @Test
    fun keyAtTheEndOfTheLinkIsShownWhole() {
        assertEquals("ABCD EFGH", totpKeyForDisplay("otpauth://totp/x?issuer=p&secret=ABCDEFGH"))
    }

    @Test
    fun aLinkWithNoKeyShowsNothing() {
        assertEquals("", totpKeyForDisplay("otpauth://totp/x?issuer=p"))
    }
}
