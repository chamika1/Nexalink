package com.nexalink.app.protocol

import com.nexalink.app.security.SessionCapability
import com.nexalink.app.security.SessionCipher
import com.nexalink.app.security.SessionConsent
import java.io.Closeable
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Outbound-only TCP transport. The caller MUST independently authenticate both
 * identities and the signed handshake transcript before constructing ciphers.
 * No listener, automatic reconnect, or remote-control capability is provided.
 */
class ApprovedOutboundConnection private constructor(
    private val socket: Socket,
    private val peerId: String,
    private val sessionId: String,
    private val consent: SessionConsent,
    private val outbound: SessionCipher,
    private val inbound: SessionCipher,
    private val nowMillis: () -> Long
) : Closeable {
    private var closed = false

    @Synchronized
    fun sendChat(message: ByteArray) {
        checkAllowed()
        SecureFrame.send(socket.getOutputStream(), outbound, sessionId, message)
    }

    @Synchronized
    fun receiveChat(): ByteArray {
        checkAllowed()
        return SecureFrame.receive(socket.getInputStream(), inbound, sessionId)
    }

    private fun checkAllowed() {
        check(!closed && !socket.isClosed) { "Connection closed" }
        check(consent.allowed(peerId, SessionCapability.CHAT, nowMillis())) {
            "Explicit chat approval required"
        }
    }

    @Synchronized
    override fun close() {
        if (!closed) {
            closed = true
            consent.revoke(peerId, SessionCapability.CHAT)
            socket.close()
        }
    }

    companion object {
        fun connect(
            host: String,
            port: Int,
            peerId: String,
            sessionId: String,
            consent: SessionConsent,
            outbound: SessionCipher,
            inbound: SessionCipher,
            nowMillis: () -> Long = System::currentTimeMillis,
            timeoutMillis: Int = 5_000
        ): ApprovedOutboundConnection {
            require(host.isNotBlank() && host.length <= 253)
            require(port in 1..65535)
            require(peerId.isNotBlank() && sessionId.length in 8..128)
            require(timeoutMillis in 1..15_000)
            check(consent.allowed(peerId, SessionCapability.CHAT, nowMillis())) {
                "Explicit chat approval required before connecting"
            }
            val socket = Socket()
            try {
                socket.connect(InetSocketAddress(host, port), timeoutMillis)
                socket.soTimeout = timeoutMillis
                socket.tcpNoDelay = true
                return ApprovedOutboundConnection(
                    socket, peerId, sessionId, consent, outbound, inbound, nowMillis
                )
            } catch (error: Exception) {
                socket.close()
                throw error
            }
        }
    }
}
