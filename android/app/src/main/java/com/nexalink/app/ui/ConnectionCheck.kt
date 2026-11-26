package com.nexalink.app.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.os.SystemClock

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.nexalink.app.protocol.ApprovedOutboundConnection
import com.nexalink.app.security.SessionConsent
import com.nexalink.app.security.SessionCapability
import com.nexalink.app.security.WireHandshake
import com.nexalink.app.protocol.SecureFrame
import com.nexalink.app.rtc.Rendezvous
import com.nexalink.app.rtc.RtcStream
import com.nexalink.app.security.TrustedPeerStore
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.coroutines.withTimeout
import java.net.InetAddress
import java.net.InetSocketAddress

@Composable
internal fun ConnectionCheck(peer: TrustedPeerStore.Peer, internet: Boolean = false) {
    val context = LocalContext.current
    var signalingUrl by remember { mutableStateOf("") }
    var roomCode by remember { mutableStateOf("") }
    var invite by remember { mutableStateOf("") }
    var host by remember { mutableStateOf("") }
    var port by remember { mutableStateOf("4242") }
    var code by remember { mutableStateOf<String?>(null) }
    var status by remember { mutableStateOf("") }
    var pending by remember { mutableStateOf<CompletableDeferred<Boolean>?>(null) }
    val scope = rememberCoroutineScope()

    DisposableEffect(Unit) {
        onDispose { pending?.complete(false) }
    }

    fun start(create: Boolean) {
        val approval = CompletableDeferred<Boolean>()
        pending = approval
        val addressInput = host.trim()
        val portInput = port.toIntOrNull()
        val serverUrl = signalingUrl.trim()
        val privateCode = roomCode.trim()
        invite = ""
        status = "Connecting…"
        scope.launch {
            try {
                val confirmed = withContext(Dispatchers.IO) {
                    val confirm: (String) -> String? = { displayed ->
                        runBlocking {
                            withContext(Dispatchers.Main) { code = displayed }
                            if (withTimeoutOrNull(60_000) { approval.await() } == true) displayed else null
                        }
                    }
                    if (internet) {
                        val server = Rendezvous(serverUrl)
                        val room = if (create) {
                            val (newRoom, invitation) = server.create()
                            withContext(Dispatchers.Main) {
                                invite = invitation
                                status = "Share the room code with your paired peer."
                            }
                            newRoom
                        } else {
                            server.join(privateCode)
                        }
                        RtcStream(context, create).use { stream ->
                            withTimeout(180_000) { stream.negotiate(server, room) }
                            val material = WireHandshake.initiateWithKeystore(
                                stream.input, stream.output, peer, confirm
                            )
                            check(material.peerId == peer.id)
                            val consent = SessionConsent()
                            val capability = SessionCapability.CHAT
                            consent.approve(peer.id, material.sessionId, capability, 60_000,
                                SystemClock.elapsedRealtime(), approval.await())
                            fun allowed() = consent.allowed(peer.id, material.sessionId, capability,
                                SystemClock.elapsedRealtime())
                            check(allowed())
                            SecureFrame.send(stream.output, material.outboundCipher, material.sessionId, REQUEST)
                            val reply = SecureFrame.receive(stream.input, material.inboundCipher, material.sessionId)
                            check(allowed())
                            val valid = reply.contentEquals(REPLY)
                            if (valid) {
                                SecureFrame.send(stream.output, material.outboundCipher, material.sessionId,
                                    "nexalink-connection-received-v1".toByteArray())
                                stream.finish()
                            }
                            valid
                        }
                    } else {
                        val address = InetSocketAddress(InetAddress.getByName(addressInput), requireNotNull(portInput))
                        ApprovedOutboundConnection.connectAuthenticated(
                            address, peer, SessionConsent(), confirmCode = confirm,
                            approveChat = { runBlocking { approval.await() } }, timeoutMillis = 15_000
                        ).use { connection ->
                            connection.sendChat(REQUEST)
                            connection.receiveChat().contentEquals(REPLY)
                        }
                    }
                }
                status = if (confirmed) "Encrypted connection check passed." else "Unexpected connection response."
            } catch (error: kotlinx.coroutines.TimeoutCancellationException) {
                status = "Connection timed out."
            } catch (error: kotlinx.coroutines.CancellationException) {
                throw error
            } catch (_: Exception) {
                status = if (internet) "Connection check ended. Check the room code, signaling URL and direct network route."
                    else "Connection check ended. Check the address, Windows listener, and approvals."
            } finally {
                code = null
                pending = null
                invite = ""
            }
        }
    }

    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text("Check connection to ${peer.name}")
        if (internet) {
            OutlinedTextField(signalingUrl, { signalingUrl = it.take(512) },
                label = { Text("HTTPS signaling URL") }, singleLine = true,
                enabled = pending == null, modifier = Modifier.fillMaxWidth())
            val ready = signalingUrl.startsWith("https://") && pending == null
            Button(enabled = ready, onClick = { start(true) }) { Text("Create room") }
            OutlinedTextField(roomCode, { roomCode = it.take(128) },
                label = { Text("Private room code") }, singleLine = true,
                enabled = pending == null, modifier = Modifier.fillMaxWidth())
            Button(enabled = ready && roomCode.isNotBlank(), onClick = { start(false) }) { Text("Join room") }
            if (invite.isNotEmpty()) {
                Button(onClick = {
                    context.getSystemService(ClipboardManager::class.java)?.setPrimaryClip(
                        ClipData.newPlainText("NexaLink room", invite)
                    )
                }) { Text("Copy private room code") }
            }
        } else {
            OutlinedTextField(host, { host = it.take(253) }, label = { Text("Windows IP address") },
                singleLine = true, enabled = pending == null, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(port, { port = it.take(5) }, label = { Text("Port") },
                singleLine = true, enabled = pending == null, modifier = Modifier.fillMaxWidth())
            Button(enabled = pending == null && host.isNotBlank() && (port.toIntOrNull() ?: 0) in 1..65535,
                onClick = { start(true) }) { Text("Check encrypted connection") }
        }

        code?.let { displayed ->
            Text("Session code $displayed. Compare with Windows before approving this one-time encrypted check.")
            Button(enabled = pending?.isCompleted == false, onClick = { pending?.complete(true) }) {
                Text("Codes match. Approve check")
            }
            Button(enabled = pending?.isCompleted == false, onClick = { pending?.complete(false) }) {
                Text("Decline")
            }
        }
        if (status.isNotBlank()) Text(status)
    }
}

private val REQUEST = "nexalink-connection-check-v1".toByteArray()
private val REPLY = "nexalink-connection-ok-v1".toByteArray()
