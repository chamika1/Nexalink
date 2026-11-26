package com.nexalink.app.rtc

import android.content.Context
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import org.webrtc.DataChannel
import org.webrtc.IceCandidate
import org.webrtc.MediaConstraints
import org.webrtc.MediaStream
import org.webrtc.PeerConnection
import org.webrtc.PeerConnectionFactory
import org.webrtc.SdpObserver
import org.webrtc.SessionDescription
import java.io.Closeable
import java.io.InputStream
import java.io.IOException
import java.io.OutputStream
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicReference

internal class RtcStream(context: Context, private val create: Boolean) : Closeable {
    private val gathered = CompletableDeferred<Unit>()
    private val finished = CompletableDeferred<Unit>()
    private val opened = CompletableDeferred<DataChannel>()
    private val selectedChannel = AtomicReference<DataChannel>()
    private val incoming = Channel<ByteArray>(8)
    private var current = ByteArray(0)
    private var offset = 0

    private val connection = requireNotNull(factory(context).createPeerConnection(
        PeerConnection.RTCConfiguration(listOf(
            PeerConnection.IceServer.builder("stun:stun.l.google.com:19302").createIceServer()
        )).apply { sdpSemantics = PeerConnection.SdpSemantics.UNIFIED_PLAN },
        object : PeerConnection.Observer {
            override fun onIceGatheringChange(state: PeerConnection.IceGatheringState) {
                if (state == PeerConnection.IceGatheringState.COMPLETE) gathered.complete(Unit)
            }
            override fun onIceConnectionChange(state: PeerConnection.IceConnectionState) {
                if (state == PeerConnection.IceConnectionState.FAILED ||
                    state == PeerConnection.IceConnectionState.CLOSED) {
                    incoming.close()
                    opened.completeExceptionally(IOException("WebRTC connection closed"))
                }
            }
            override fun onDataChannel(channel: DataChannel) {
                if (create || channel.label() != LABEL) {
                    channel.close()
                    return
                }
                observe(channel)
            }
            override fun onSignalingChange(state: PeerConnection.SignalingState) = Unit
            override fun onIceConnectionReceivingChange(receiving: Boolean) = Unit
            override fun onIceCandidate(candidate: IceCandidate) = Unit
            override fun onIceCandidatesRemoved(candidates: Array<out IceCandidate>) = Unit
            override fun onAddStream(stream: MediaStream) = Unit
            override fun onRemoveStream(stream: MediaStream) = Unit
            override fun onRenegotiationNeeded() = Unit
        }
    ))

    private fun observe(channel: DataChannel) {
        if (!selectedChannel.compareAndSet(null, channel)) {
            channel.close()
            return
        }
        val observer = object : DataChannel.Observer {
            override fun onBufferedAmountChange(previousAmount: Long) = Unit
            override fun onStateChange() {
                when (channel.state()) {
                    DataChannel.State.OPEN -> { opened.complete(channel) }
                    DataChannel.State.CLOSED -> {
                        incoming.close()
                        finished.complete(Unit)
                        opened.completeExceptionally(IOException("WebRTC connection closed"))
                    }
                    else -> Unit
                }
            }
            override fun onMessage(buffer: DataChannel.Buffer) {
                val size = buffer.data.remaining()
                if (!buffer.binary || size !in 1..CHUNK ||
                    incoming.trySend(ByteArray(size).also { buffer.data.get(it) }).isFailure) {
                    incoming.cancel()
                    channel.close()
                }
            }
        }
        channel.registerObserver(observer)
        if (channel.state() == DataChannel.State.OPEN && !opened.isCompleted) observer.onStateChange()
    }

    suspend fun negotiate(server: Rendezvous, room: Rendezvous.Room) {
        if (create) {
            observe(connection.createDataChannel(LABEL, DataChannel.Init()))
        } else {
            val offer = server.waitFor(room, SessionDescription.Type.OFFER)
            sdp { connection.setRemoteDescription(it, offer) }
        }

        val description = sdp {
            if (create) connection.createOffer(it, MediaConstraints())
            else connection.createAnswer(it, MediaConstraints())
        }
        sdp { connection.setLocalDescription(it, requireNotNull(description)) }
        gathered.await()
        server.publish(room, connection.localDescription)
        if (create) {
            val answer = server.waitFor(room, SessionDescription.Type.ANSWER)
            sdp { connection.setRemoteDescription(it, answer) }
        }
        opened.await()
    }

    val input: InputStream = object : InputStream() {
        override fun read(): Int {
            val byte = ByteArray(1)
            return if (read(byte, 0, 1) == -1) -1 else byte[0].toInt() and 255
        }

        override fun read(buffer: ByteArray, start: Int, count: Int): Int {
            if (count == 0) return 0
            if (offset == current.size) {
                current = runBlocking { withTimeout(30_000) { incoming.receiveCatching().getOrNull() } }
                    ?: return -1
                offset = 0
            }
            val size = minOf(count, current.size - offset)
            current.copyInto(buffer, start, offset, offset + size)
            offset += size
            return size
        }
    }

    val output: OutputStream = object : OutputStream() {
        override fun write(value: Int) = write(byteArrayOf(value.toByte()))

        override fun write(buffer: ByteArray, start: Int, count: Int) {
            val channel = runBlocking { opened.await() }
            for (offset in start until start + count step CHUNK) {
                val size = minOf(CHUNK, start + count - offset)
                check(channel.bufferedAmount() <= 256 * 1024)
                val bytes = ByteBuffer.wrap(buffer, offset, size).slice()
                check(channel.send(DataChannel.Buffer(bytes, true))) { "WebRTC send failed" }
            }
        }
    }

    private suspend fun sdp(operation: (SdpObserver) -> Unit): SessionDescription? {
        val result = CompletableDeferred<SessionDescription?>()
        operation(object : SdpObserver {
            override fun onCreateSuccess(description: SessionDescription) { result.complete(description) }
            override fun onSetSuccess() { result.complete(null) }
            override fun onCreateFailure(message: String) { result.completeExceptionally(IllegalStateException(message)) }
            override fun onSetFailure(message: String) { result.completeExceptionally(IllegalStateException(message)) }
        })
        return result.await()
    }

    suspend fun finish() {
        selectedChannel.get()?.close()
        withTimeoutOrNull(3_000) { finished.await() }
    }

    override fun close() {
        incoming.cancel()
        selectedChannel.get()?.unregisterObserver()
        connection.dispose()
        selectedChannel.get()?.dispose()
    }

    companion object {
        private const val LABEL = "nexalink-stream-v1"
        private const val CHUNK = 16 * 1024
        private var instance: PeerConnectionFactory? = null

        @Synchronized
        fun factory(context: Context): PeerConnectionFactory = instance ?: run {
            PeerConnectionFactory.initialize(
                PeerConnectionFactory.InitializationOptions.builder(context.applicationContext).createInitializationOptions()
            )
            PeerConnectionFactory.builder().createPeerConnectionFactory().also { instance = it }
        }
    }
}
