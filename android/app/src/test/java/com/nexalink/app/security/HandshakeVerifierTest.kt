package com.nexalink.app.security

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.Signature

class HandshakeVerifierTest {
    private fun identity() = KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair()

    private fun sign(privateKey: java.security.PrivateKey, transcript: ByteArray): ByteArray =
        Signature.getInstance("SHA256withECDSA").run {
            initSign(privateKey)
            update(transcript)
            sign()
        }

    @Test fun acceptsValidPinnedIdentityAndTranscript() {
        val peer = identity()
        val transcript = "session-12345678|initiator|responder|ephemeral-keys".toByteArray()
        assertTrue(HandshakeVerifier.verify(
            peer.public.encoded, peer.public.encoded, transcript,
            sign(peer.private, transcript)
        ))
    }

    @Test fun rejectsSubstitutedIdentity() {
        val trusted = identity()
        val attacker = identity()
        val transcript = "session-12345678".toByteArray()
        assertFalse(HandshakeVerifier.verify(
            trusted.public.encoded, attacker.public.encoded, transcript,
            sign(attacker.private, transcript)
        ))
    }

    @Test fun rejectsModifiedTranscriptAndSignature() {
        val peer = identity()
        val transcript = "session-12345678".toByteArray()
        val signature = sign(peer.private, transcript)
        assertFalse(HandshakeVerifier.verify(
            peer.public.encoded, peer.public.encoded,
            "session-87654321".toByteArray(), signature
        ))
        val corrupted = signature.clone()
        corrupted[corrupted.lastIndex] = (corrupted.last().toInt() xor 1).toByte()
        assertFalse(HandshakeVerifier.verify(
            peer.public.encoded, peer.public.encoded, transcript, corrupted
        ))
    }
}
