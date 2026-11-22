package com.nexalink.app.security

import org.junit.Assert.*
import org.junit.Test

class SessionConsentSecurityTest {
    @Test fun separateCapabilitiesRequireSeparateApproval() {
        val consent = SessionConsent()
        consent.approve("peer-a", SessionCapability.CHAT, 60_000, 1000, true)
        assertTrue(consent.allowed("peer-a", SessionCapability.CHAT, 1000))
        assertFalse(consent.allowed("peer-a", SessionCapability.LOCATION, 1000))
        assertFalse(consent.allowed("peer-b", SessionCapability.CHAT, 1000))
        assertFalse(consent.allowed("peer-a", SessionCapability.REMOTE_INPUT, 1000))
    }

    @Test fun expiredAndRevokedConsentFailClosed() {
        val consent = SessionConsent()
        consent.approve("peer-a", SessionCapability.CHAT, 10, 1000, true)
        assertTrue(consent.allowed("peer-a", SessionCapability.CHAT, 1009))
        assertFalse(consent.allowed("peer-a", SessionCapability.CHAT, 1010))
        consent.approve("peer-a", SessionCapability.CHAT, 10, 1000, true)
        consent.revokeAll("peer-a")
        assertFalse(consent.allowed("peer-a", SessionCapability.CHAT, 1000))
    }

    @Test fun rejectsUnapprovedExcessiveAndOverflowingGrants() {
        val consent = SessionConsent()
        assertThrows(IllegalArgumentException::class.java) {
            consent.approve("peer-a", SessionCapability.CHAT, 100, 1000, false)
        }
        assertThrows(IllegalArgumentException::class.java) {
            consent.approve("peer-a", SessionCapability.CHAT, 900_001, 1000, true)
        }
        assertThrows(ArithmeticException::class.java) {
            consent.approve("peer-a", SessionCapability.CHAT, 100, Long.MAX_VALUE, true)
        }
        assertFalse(consent.allowed("peer-a", SessionCapability.CHAT, 1000))
    }
}
