package com.nexalink.app.security

import org.junit.Assert.*
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.Signature
import java.util.Base64

class SessionSecurityTest {
    private fun encoded(bytes: ByteArray) =
        Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

    private fun transcript(): SessionTranscript {
        val generator = KeyPairGenerator.getInstance("EC").apply { initialize(256) }
        return SessionTranscript(
            "session-123456789",
            encoded(generator.generateKeyPair().public.encoded),
            encoded(generator.generateKeyPair().public.encoded),
            encoded(ByteArray(32) { 1 }),
            encoded(ByteArray(32) { 2 })
        )
    }

    @Test fun transcriptIsDeterministicAndRoleBound() {
        val t = transcript()
        assertArrayEquals(t.bytes(), t.copy().bytes())
        assertEquals(6, t.verificationCode().length)
        assertFalse(t.bytes().contentEquals(t.copy(
            initiatorPublicKey = t.responderPublicKey,
            responderPublicKey = t.initiatorPublicKey
        ).bytes()))
    }

    @Test fun transcriptRejectsReusedNonce() {
        val t = transcript()
        assertThrows(IllegalArgumentException::class.java) {
            t.copy(responderNonce = t.initiatorNonce).bytes()
        }
    }

    @Test fun signatureVerifiesOnlyForCorrectTranscript() {
        val generator = KeyPairGenerator.getInstance("EC").apply { initialize(256) }
        val a = generator.generateKeyPair()
        val b = generator.generateKeyPair()
        val t = SessionTranscript("session-123456789",
            encoded(a.public.encoded), encoded(b.public.encoded),
            encoded(ByteArray(32) { 1 }), encoded(ByteArray(32) { 2 }))
        val signer = Signature.getInstance("SHA256withECDSA")
        signer.initSign(a.private)
        signer.update(t.bytes())
        val proof = encoded(signer.sign())
        val auth = SessionAuthenticator()
        assertTrue(auth.verify(t, true, proof))
        assertFalse(auth.verify(t, false, proof))
        assertFalse(auth.verify(t.copy(sessionId = "session-123456780"), true, proof))
    }

    @Test fun consentIsDeniedByDefaultAndRevocable() {
        val consent = SessionConsent()
        assertFalse(consent.allowed("peer", SessionCapability.SCREEN_VIEW, 100))
        assertThrows(IllegalArgumentException::class.java) {
            consent.approve("peer", SessionCapability.SCREEN_VIEW, 1000, 100, false)
        }
        consent.approve("peer", SessionCapability.SCREEN_VIEW, 1000, 100, true)
        assertTrue(consent.allowed("peer", SessionCapability.SCREEN_VIEW, 500))
        assertFalse(consent.allowed("peer", SessionCapability.REMOTE_INPUT, 500))
        assertFalse(consent.allowed("peer", SessionCapability.SCREEN_VIEW, 1100))
        consent.revoke("peer", SessionCapability.SCREEN_VIEW)
        assertFalse(consent.allowed("peer", SessionCapability.SCREEN_VIEW, 500))
    }
}
