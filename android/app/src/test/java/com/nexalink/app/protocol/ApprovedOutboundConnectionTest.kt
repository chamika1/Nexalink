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

    @Test fun refusesConnectionWithoutConsent() {
        val consent = SessionConsent()
        assertThrows(IllegalStateException::class.java) {
            ApprovedOutboundConnection.connect(
                "127.0.0.1", 12345, "peer-1", "session-12345678",
                consent, cipher(), cipher()
            )
        }
    }

    @Test fun approvalAllowsLoopbackConnectionButRevocationBlocksSending() {
        ServerSocket(0).use { listener ->
            val consent = SessionConsent()
            val now = 1_000L
            consent.approve("peer-1", SessionCapability.CHAT, 60_000, now, true)
            ApprovedOutboundConnection.connect(
                "127.0.0.1", listener.localPort, "peer-1", "session-12345678",
                consent, cipher(), cipher(), { now }
            ).use { connection ->
                listener.accept().use {
                    consent.revoke("peer-1", SessionCapability.CHAT)
                    assertThrows(IllegalStateException::class.java) {
                        connection.sendChat("blocked".toByteArray())
                    }
                }
            }
        }
    }

    @Test fun expiredConsentBlocksConnection() {
        val consent = SessionConsent()
        consent.approve("peer-1", SessionCapability.CHAT, 1, 1_000, true)
        assertThrows(IllegalStateException::class.java) {
            ApprovedOutboundConnection.connect(
                "127.0.0.1", 12345, "peer-1", "session-12345678",
                consent, cipher(), cipher(), { 1_001L }
            )
        }
    }
}
