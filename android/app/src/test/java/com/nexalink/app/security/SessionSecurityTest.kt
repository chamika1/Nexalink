package com.nexalink.app.security

import org.junit.Assert.*
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.Signature
import java.util.Base64

class SessionSecurityTest {
    private fun transcript(): SessionTranscript {
        val generator = KeyPairGenerator.getInstance("EC").apply { initialize(256) }
        val aIdentity = generator.generateKeyPair().public.encoded
        val bIdentity = generator.generateKeyPair().public.encoded
        val aEphemeral = generator.generateKeyPair().public.encoded
        val bEphemeral = generator.generateKeyPair().public.encoded
        return SessionTranscript(
            aIdentity, bIdentity, aEphemeral, bEphemeral,
            ByteArray(32) { 1 }, ByteArray(32) { 2 }
        )
    }

    @Test fun transcriptIsDeterministicAndRoleBound() {
        val t = transcript()
        assertArrayEquals(t.bytes(), t.copy().bytes())
        assertEquals(6, t.verificationCode().length)
        assertFalse(t.bytes().contentEquals(t.copy(
            initiatorIdentitySpki = t.responderIdentitySpki,
            responderIdentitySpki = t.initiatorIdentitySpki
        ).bytes()))
    }

    @Test fun transcriptRejectsReusedNonceAndEphemeralKey() {
        val t = transcript()
        assertThrows(IllegalArgumentException::class.java) {
            t.copy(responderNonce = t.initiatorNonce).bytes()
        }
        assertThrows(IllegalArgumentException::class.java) {
            t.copy(responderEphemeralSpki = t.initiatorEphemeralSpki).bytes()
        }
    }

    @Test fun transcriptMatchesWindowsCanonicalInteroperabilityVector() {
        val t = SessionTranscript(
            "alice-id".toByteArray(), "bob-id".toByteArray(),
            "alice-ephemeral".toByteArray(), "bob-ephemeral".toByteArray(),
            ByteArray(32) { 1 }, ByteArray(32) { 2 }
        )
        val expectedHex = "6e6578616c696e6b2d61757468656e746963617465642d73657373696f6e2d76310000000008616c6963652d696400000006626f622d69640000000f616c6963652d657068656d6572616c0000000d626f622d657068656d6572616c000000200101010101010101010101010101010101010101010101010101010101010101000000200202020202020202020202020202020202020202020202020202020202020202"
        val actualHex = t.bytes().joinToString("") { "%02x".format(it.toInt() and 255) }
        assertEquals(expectedHex, actualHex)
    }

    @Test fun signatureVerifiesOnlyForCorrectTranscript() {
        val generator = KeyPairGenerator.getInstance("EC").apply { initialize(256) }
        val a = generator.generateKeyPair()
        val b = generator.generateKeyPair()
        val t = SessionTranscript(
            a.public.encoded, b.public.encoded,
            generator.generateKeyPair().public.encoded,
            generator.generateKeyPair().public.encoded,
            ByteArray(32) { 1 }, ByteArray(32) { 2 }
        )
        val signer = Signature.getInstance("SHA256withECDSA")
        signer.initSign(a.private)
        signer.update(t.bytes())
        val proof = signer.sign()
        assertTrue(SessionAuthenticator.verifySignature(a.public.encoded, t.bytes(), proof))
        assertFalse(SessionAuthenticator.verifySignature(b.public.encoded, t.bytes(), proof))
        assertFalse(SessionAuthenticator.verifySignature(a.public.encoded, "modified".toByteArray(), proof))
    }

    @Test fun consentIsDeniedByDefaultAndScopedToOneSession() {
        val consent = SessionConsent()
        val first = "session-12345678"
        val second = "session-87654321"
        assertFalse(consent.allowed("peer", first, SessionCapability.SCREEN_VIEW, 100))
        assertThrows(IllegalArgumentException::class.java) {
            consent.approve("peer", first, SessionCapability.SCREEN_VIEW, 1000, 100, false)
        }
        consent.approve("peer", first, SessionCapability.SCREEN_VIEW, 1000, 100, true)
        assertTrue(consent.allowed("peer", first, SessionCapability.SCREEN_VIEW, 500))
        assertFalse(consent.allowed("peer", second, SessionCapability.SCREEN_VIEW, 500))
        assertFalse(consent.allowed("peer", first, SessionCapability.REMOTE_INPUT, 500))
        assertFalse(consent.allowed("peer", first, SessionCapability.SCREEN_VIEW, 1100))
        consent.revoke("peer", first, SessionCapability.SCREEN_VIEW)
        assertFalse(consent.allowed("peer", first, SessionCapability.SCREEN_VIEW, 500))
    }
}
