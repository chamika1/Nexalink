package com.nexalink.app.security

import org.junit.Assert.*
import org.junit.Test

class SessionConsentSecurityTest {
    @Test fun separateCapabilitiesAndSessionsRequireSeparateApproval() {
        val consent = SessionConsent()
        consent.approve("peer-a", "session-12345678", SessionCapability.CHAT, 60_000, 1000, true)
        assertTrue(consent.allowed("peer-a", "session-12345678", SessionCapability.CHAT, 1000))
        assertFalse(consent.allowed("peer-a", "session-87654321", SessionCapability.CHAT, 1000))
        assertFalse(consent.allowed("peer-a", "session-12345678", SessionCapability.LOCATION, 1000))
        assertFalse(consent.allowed("peer-b", "session-12345678", SessionCapability.CHAT, 1000))
        assertFalse(consent.allowed("peer-a", "session-12345678", SessionCapability.REMOTE_INPUT, 1000))
    }

    @Test fun expiredAndRevokedConsentFailClosed() {
        val consent = SessionConsent()
        val session = "session-12345678"
        consent.approve("peer-a", session, SessionCapability.CHAT, 10, 1000, true)
        assertTrue(consent.allowed("peer-a", session, SessionCapability.CHAT, 1009))
        assertFalse(consent.allowed("peer-a", session, SessionCapability.CHAT, 1010))
        consent.approve("peer-a", session, SessionCapability.CHAT, 10, 1000, true)
        consent.revokeSession("peer-a", session)
        assertFalse(consent.allowed("peer-a", session, SessionCapability.CHAT, 1000))
    }

    @Test fun rejectsUnapprovedExcessiveAndOverflowingGrants() {
        val consent = SessionConsent()
        assertThrows(IllegalArgumentException::class.java) {
            consent.approve("peer-a", "session-12345678", SessionCapability.CHAT, 100, 1000, false)
        }
        assertThrows(IllegalArgumentException::class.java) {
            consent.approve("peer-a", "session-12345678", SessionCapability.CHAT, 900_001, 1000, true)
        }
        assertThrows(ArithmeticException::class.java) {
            consent.approve("peer-a", "session-12345678", SessionCapability.CHAT, 100, Long.MAX_VALUE, true)
        }
        assertFalse(consent.allowed("peer-a", "session-12345678", SessionCapability.CHAT, 1000))
    }

    @Test fun closeOrRevokeOneSessionDoesNotGrantOrRevokeAnother() {
        val consent = SessionConsent()
        consent.approve("peer-a", "session-12345678", SessionCapability.CHAT, 60_000, 1000, true)
        consent.approve("peer-a", "session-87654321", SessionCapability.CHAT, 60_000, 1000, true)
        consent.revokeSession("peer-a", "session-12345678")
        assertFalse(consent.allowed("peer-a", "session-12345678", SessionCapability.CHAT, 1000))
        assertTrue(consent.allowed("peer-a", "session-87654321", SessionCapability.CHAT, 1000))
    }
}
