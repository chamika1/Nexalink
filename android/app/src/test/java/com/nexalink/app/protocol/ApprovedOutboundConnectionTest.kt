package com.nexalink.app.protocol

import com.nexalink.app.security.SessionCapability
import com.nexalink.app.security.SessionCipher
import com.nexalink.app.security.SessionConsent
import org.junit.Assert.assertThrows
import org.junit.Test
import java.net.ServerSocket
import javax.crypto.spec.SecretKeySpec

class ApprovedOutboundConnectionTest {
    private fun cipher() = SessionCipher(
        SecretKeySpec(ByteArray(32) { 7 }, "AES"),
        "authenticated test transcript".toByteArray()
    )

    @Test fun refusesConnectionWithoutSessionConsent() {
        val consent = SessionConsent()
        assertThrows(IllegalStateException::class.java) {
            ApprovedOutboundConnection.connect(
                "127.0.0.1", 12345, "peer-1", "session-12345678",
                consent, cipher(), cipher()
            )
        }
    }

    @Test fun approvalAllowsLoopbackConnectionButSessionRevocationBlocksSending() {
        ServerSocket(0).use { listener ->
            val consent = SessionConsent()
            val now = 1_000L
            val session = "session-12345678"
            consent.approve("peer-1", session, SessionCapability.CHAT, 60_000, now, true)
            ApprovedOutboundConnection.connect(
                "127.0.0.1", listener.localPort, "peer-1", session,
                consent, cipher(), cipher(), { now }
            ).use { connection ->
                listener.accept().use {
                    consent.revokeSession("peer-1", session)
                    assertThrows(IllegalStateException::class.java) {
                        connection.sendChat("blocked".toByteArray())
                    }
                }
            }
        }
    }

    @Test fun anotherSessionsConsentCannotAuthorizeThisConnection() {
        val consent = SessionConsent()
        consent.approve("peer-1", "session-87654321", SessionCapability.CHAT, 60_000, 1000, true)
        assertThrows(IllegalStateException::class.java) {
            ApprovedOutboundConnection.connect(
                "127.0.0.1", 12345, "peer-1", "session-12345678",
                consent, cipher(), cipher(), { 1000 }
            )
        }
    }

    @Test fun expiredConsentBlocksConnection() {
        val consent = SessionConsent()
        consent.approve("peer-1", "session-12345678", SessionCapability.CHAT, 1, 1000, true)
        assertThrows(IllegalStateException::class.java) {
            ApprovedOutboundConnection.connect(
                "127.0.0.1", 12345, "peer-1", "session-12345678",
                consent, cipher(), cipher(), { 1001 }
            )
        }
    }
}
