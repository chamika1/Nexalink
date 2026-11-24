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

    @Test fun rejectsOutOfOrderWithoutConsumingExpectedSequence() {
        val key = SessionCrypto.deriveKey(
            SessionCrypto.ephemeralKeyPair(), SessionCrypto.ephemeralKeyPair().public.encoded,
            "sequence-test".toByteArray(), true
        )
        val sender = SessionCipher(key, "sequence-test".toByteArray())
        val receiver = SessionCipher(key, "sequence-test".toByteArray())
        val first = sender.encrypt("first".toByteArray())
        val second = sender.encrypt("second".toByteArray())
        assertThrows(IllegalArgumentException::class.java) { receiver.decrypt(second) }
        assertEquals("first", String(receiver.decrypt(first)))
        assertEquals("second", String(receiver.decrypt(second)))
        assertThrows(IllegalArgumentException::class.java) { receiver.decrypt(first) }
    }

    @Test fun enforcesWindowsPayloadLimit() {
        val key = javax.crypto.spec.SecretKeySpec(ByteArray(32) { 3 }, "AES")
        val cipher = SessionCipher(key, "limit-test".toByteArray())
        assertEquals(48_036, cipher.encrypt(ByteArray(48_000)).size)
        assertThrows(IllegalArgumentException::class.java) { cipher.encrypt(ByteArray(48_001)) }
        assertThrows(IllegalArgumentException::class.java) { cipher.decrypt(ByteArray(48_037)) }
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
