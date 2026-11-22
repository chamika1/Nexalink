package com.nexalink.app.security

import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class PairingChallengeTest {
    @Test fun expiresAfterTwoMinutes() {
        val challenge = PairingChallenge.create(1000L)
        assertTrue(challenge.isValid(1000L))
        assertTrue(challenge.isValid(120999L))
        assertFalse(challenge.isValid(121000L))
        assertFalse(challenge.isValid(999L))
    }

    @Test fun uniqueNonces() {
        assertNotEquals(PairingChallenge.create().nonce, PairingChallenge.create().nonce)
    }
}
