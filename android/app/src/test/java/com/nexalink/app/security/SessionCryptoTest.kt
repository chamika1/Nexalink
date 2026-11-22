package com.nexalink.app.security

import org.junit.Assert.*
import org.junit.Test
import javax.crypto.AEADBadTagException

class SessionCryptoTest {
    @Test fun bothSidesDeriveSameDirectionalKey() {
        val a = SessionCrypto.ephemeralKeyPair()
        val b = SessionCrypto.ephemeralKeyPair()
        val context = "authenticated-transcript".toByteArray()
        val ab = SessionCrypto.deriveKey(a, b.public.encoded, context, true)
        val ba = SessionCrypto.deriveKey(b, a.public.encoded, context, true)
        assertArrayEquals(ab.encoded, ba.encoded)
        val opposite = SessionCrypto.deriveKey(b, a.public.encoded, context, false)
        assertFalse(ab.encoded.contentEquals(opposite.encoded))
    }

    @Test fun decryptRejectsReplayAndTampering() {
        val a = SessionCrypto.ephemeralKeyPair()
        val b = SessionCrypto.ephemeralKeyPair()
        val context = "authenticated-transcript".toByteArray()
        val key = SessionCrypto.deriveKey(a, b.public.encoded, context, true)
        val sender = SessionCipher(key, context)
        val receiver = SessionCipher(key, context)
        val frame = sender.encrypt("hello".toByteArray())
        assertEquals("hello", String(receiver.decrypt(frame)))
        assertThrows(IllegalArgumentException::class.java) { receiver.decrypt(frame) }
        val altered = sender.encrypt("secret".toByteArray())
        altered[altered.lastIndex] = (altered.last().toInt() xor 1).toByte()
        assertThrows(AEADBadTagException::class.java) { receiver.decrypt(altered) }
    }

    @Test fun wrongTranscriptFailsAuthentication() {
        val a = SessionCrypto.ephemeralKeyPair()
        val b = SessionCrypto.ephemeralKeyPair()
        val context = "authenticated-transcript".toByteArray()
        val key = SessionCrypto.deriveKey(a, b.public.encoded, context, true)
        val frame = SessionCipher(key, context).encrypt("hello".toByteArray())
        assertThrows(AEADBadTagException::class.java) {
            SessionCipher(key, "other-session".toByteArray()).decrypt(frame)
        }
    }
}
