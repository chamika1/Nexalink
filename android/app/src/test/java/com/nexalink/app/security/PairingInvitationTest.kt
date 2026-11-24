package com.nexalink.app.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPairGenerator
import java.util.Base64

class PairingInvitationTest {
    @Test fun roundTrip() {
        val key = KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair()
        val encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(key.public.encoded)
        val original = PairingInvitation(1, "Living Room PC", encoded)
        val parsed = PairingInvitation.parse(original.serialize())
        assertEquals(original, parsed)
        assertEquals(95, parsed.fingerprint().length)
    }

    @Test fun rejectsUnknownVersion() {
        assertThrows(IllegalArgumentException::class.java) {
            PairingInvitation.parse("nexalink:pair:2:abc:def")
        }
    }

    @Test fun rejectsInvalidKey() {
        assertThrows(IllegalArgumentException::class.java) {
            PairingInvitation.parse("nexalink:pair:1:QQ:AA")
        }
    }

    @Test fun rejectsInvalidDerAndDifferentCurve() {
        val invalidDer = Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(91))
        assertThrows(IllegalArgumentException::class.java) {
            PairingInvitation.parse("nexalink:pair:1:UEM:$invalidDer")
        }
        val key = KeyPairGenerator.getInstance("EC").apply { initialize(384) }.generateKeyPair()
        val wrongCurve = Base64.getUrlEncoder().withoutPadding().encodeToString(key.public.encoded)
        assertThrows(IllegalArgumentException::class.java) {
            PairingInvitation.parse("nexalink:pair:1:UEM:$wrongCurve")
        }
    }

    @Test fun stateRequiresApprovals() {
        val session = PairingSession("PC", "fingerprint")
        assertThrows(IllegalArgumentException::class.java) { session.verifyFingerprint() }
        val waiting = session.requestApproval().approveLocally().remoteApproved()
        assertEquals(PairingStatus.VERIFIED, waiting.verifyFingerprint().status)
        assertTrue(waiting.reject().status == PairingStatus.REJECTED)
    }
}
