package com.nexalink.app.protocol
import android.os.SystemClock

import com.nexalink.app.security.TrustedPeerStore
import com.nexalink.app.security.WireHandshake
import com.nexalink.app.security.SessionCapability
import com.nexalink.app.security.SessionCipher
import com.nexalink.app.security.SessionConsent
import java.io.Closeable
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Outbound-only TCP transport. The caller must first complete authenticated
 * handshake verification and obtain local consent for this exact session.
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
        require(message.size <= SessionCipher.MAX_PLAINTEXT_BYTES)
        exchange { SecureFrame.send(socket.getOutputStream(), outbound, sessionId, message) }
    }

    @Synchronized
    fun receiveChat(): ByteArray {
        return exchange { SecureFrame.receive(socket.getInputStream(), inbound, sessionId) }
    }

    private inline fun <T> exchange(operation: () -> T): T {
        try {
            checkAllowed()
            return operation()
        } catch (error: Exception) {
            runCatching { close() }
            throw error
        }
    }

    private fun checkAllowed() {
        check(!closed && !socket.isClosed) { "Connection closed" }
        check(consent.allowed(peerId, sessionId, SessionCapability.CHAT, nowMillis())) {
            "Explicit approval for this session is required"
        }
    }

    @Synchronized
    override fun close() {
        if (!closed) {
            closed = true
            consent.revokeSession(peerId, sessionId)
            socket.close()
        }
    }

    companion object {
        /** Perform the handshake and obtain chat approval on the same socket. Run off the UI thread. */
        internal fun connectAuthenticated(
            address: InetSocketAddress,
            peer: TrustedPeerStore.Peer,
            consent: SessionConsent,
            confirmCode: (String) -> String?,
            approveChat: () -> Boolean,
            nowMillis: () -> Long = SystemClock::elapsedRealtime,
            timeoutMillis: Int = 5_000
        ): ApprovedOutboundConnection {
            require(!address.isUnresolved && address.port in 1..65535)
            require(timeoutMillis in 1..15_000)
            val socket = Socket()
            try {
                socket.connect(address, timeoutMillis)
                socket.soTimeout = timeoutMillis
                socket.tcpNoDelay = true
                val material = WireHandshake.initiateWithKeystore(
                    socket.getInputStream(), socket.getOutputStream(), peer, confirmCode
                )
                check(material.peerId == peer.id) { "Peer identity does not match the stored pin" }
                val approved = approveChat()
                consent.approve(
                    material.peerId, material.sessionId, SessionCapability.CHAT,
                    60_000L, nowMillis(), approved
                )
                return ApprovedOutboundConnection(
                    socket, material.peerId, material.sessionId, consent,
                    material.outboundCipher, material.inboundCipher, nowMillis
                )
            } catch (error: Exception) {
                runCatching { socket.close() }
                throw error
            }
        }

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
            check(consent.allowed(peerId, sessionId, SessionCapability.CHAT, nowMillis())) {
                "Explicit approval for this session is required before connecting"
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
