package com.nexalink.app.security

import org.junit.Assert.*
import org.junit.Test
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature

class AuthenticatedSessionFactoryTest {
    private fun keyPair(): KeyPair =
        KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair()

    private fun fingerprint(spki: ByteArray) =
        MessageDigest.getInstance("SHA-256").digest(spki)
            .joinToString(":") { "%02X".format(it.toInt() and 255) }

    private fun sign(key: KeyPair, transcript: ByteArray): ByteArray {
        val signer = Signature.getInstance("SHA256withECDSA")
        signer.initSign(key.private)
        signer.update(transcript)
        return signer.sign()
    }

    private data class Fixture(
        val aliceId: KeyPair,
        val bobId: KeyPair,
        val aliceEphemeral: KeyPair,
        val bobEphemeral: KeyPair,
        val transcript: SessionTranscript,
        val aliceSignature: ByteArray,
        val bobSignature: ByteArray
    )

    private fun fixture(): Fixture {
        val aliceId = keyPair()
        val bobId = keyPair()
        val aliceEphemeral = keyPair()
        val bobEphemeral = keyPair()
        val transcript = SessionTranscript(
            aliceId.public.encoded, bobId.public.encoded,
            aliceEphemeral.public.encoded, bobEphemeral.public.encoded,
            ByteArray(32) { 17 }, ByteArray(32) { 18 }
        )
        val bytes = transcript.bytes()
        return Fixture(
            aliceId, bobId, aliceEphemeral, bobEphemeral, transcript,
            sign(aliceId, bytes), sign(bobId, bytes)
        )
    }

    @Test fun mutuallyPinnedDevicesDeriveInteroperableDirectionalCiphers() {
        val f = fixture()
        val code = f.transcript.verificationCode()
        val alice = AuthenticatedSessionFactory.establish(
            "session-12345678", fingerprint(f.bobId.public.encoded), f.transcript,
            f.aliceId.public.encoded, f.bobId.public.encoded,
            f.aliceEphemeral, f.bobEphemeral.public.encoded,
            f.aliceSignature, f.bobSignature, true, code
        )
        val bob = AuthenticatedSessionFactory.establish(
            "session-12345678", fingerprint(f.aliceId.public.encoded), f.transcript,
            f.bobId.public.encoded, f.aliceId.public.encoded,
            f.bobEphemeral, f.aliceEphemeral.public.encoded,
            f.bobSignature, f.aliceSignature, false, code
        )
        assertEquals(code, alice.verificationCode)
        assertEquals("hello from Android", String(
            bob.inboundCipher.decrypt(alice.outboundCipher.encrypt("hello from Android".toByteArray()))
        ))
        assertEquals("reply from Windows", String(
            alice.inboundCipher.decrypt(bob.outboundCipher.encrypt("reply from Windows".toByteArray()))
        ))
    }

    @Test fun rejectsWrongPinCodeSignatureAndEphemeralSubstitution() {
        val f = fixture()
        val code = f.transcript.verificationCode()
        val wrong = keyPair()
        assertThrows(IllegalArgumentException::class.java) {
            AuthenticatedSessionFactory.establish(
                "session-12345678", fingerprint(wrong.public.encoded), f.transcript,
                f.aliceId.public.encoded, wrong.public.encoded,
                f.aliceEphemeral, f.bobEphemeral.public.encoded,
                f.aliceSignature, f.bobSignature, true, code
            )
        }
        assertThrows(IllegalArgumentException::class.java) {
            AuthenticatedSessionFactory.establish(
                "session-12345678", fingerprint(f.bobId.public.encoded), f.transcript,
                f.aliceId.public.encoded, f.bobId.public.encoded,
                f.aliceEphemeral, f.bobEphemeral.public.encoded,
                f.aliceSignature, f.bobSignature, true, "000000"
            )
        }
        val altered = f.bobSignature.clone().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
        assertThrows(IllegalArgumentException::class.java) {
            AuthenticatedSessionFactory.establish(
                "session-12345678", fingerprint(f.bobId.public.encoded), f.transcript,
                f.aliceId.public.encoded, f.bobId.public.encoded,
                f.aliceEphemeral, f.bobEphemeral.public.encoded,
                f.aliceSignature, altered, true, code
            )
        }
        val substituted = keyPair()
        assertThrows(IllegalArgumentException::class.java) {
            AuthenticatedSessionFactory.establish(
                "session-12345678", fingerprint(f.bobId.public.encoded), f.transcript,
                f.aliceId.public.encoded, f.bobId.public.encoded,
                f.aliceEphemeral, substituted.public.encoded,
                f.aliceSignature, f.bobSignature, true, code
            )
        }
    }
}
