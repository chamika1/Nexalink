package com.nexalink.app.ui

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
import androidx.compose.ui.unit.dp
import com.nexalink.app.protocol.ApprovedOutboundConnection
import com.nexalink.app.security.SessionConsent
import com.nexalink.app.security.TrustedPeerStore
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.net.InetAddress
import java.net.InetSocketAddress

@Composable
internal fun ConnectionCheck(peer: TrustedPeerStore.Peer) {
    var host by remember { mutableStateOf("") }
    var port by remember { mutableStateOf("4242") }
    var code by remember { mutableStateOf<String?>(null) }
    var status by remember { mutableStateOf("") }
    var pending by remember { mutableStateOf<CompletableDeferred<Boolean>?>(null) }
    val scope = rememberCoroutineScope()

    DisposableEffect(Unit) {
        onDispose { pending?.complete(false) }
    }

    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text("Check connection to ${peer.name}")
        OutlinedTextField(host, { host = it.take(253) }, label = { Text("Windows IP address") },
            singleLine = true, enabled = pending == null, modifier = Modifier.fillMaxWidth())
        OutlinedTextField(port, { port = it.take(5) }, label = { Text("Port") },
            singleLine = true, enabled = pending == null, modifier = Modifier.fillMaxWidth())
        Button(enabled = pending == null && host.isNotBlank() && (port.toIntOrNull() ?: 0) in 1..65535,
            onClick = {
                val approval = CompletableDeferred<Boolean>()
                pending = approval
                val addressInput = host.trim()
                val portInput = port.toInt()
                status = "Connecting…"
                scope.launch {
                    try {
                        val confirmed = withContext(Dispatchers.IO) {
                            val address = InetSocketAddress(InetAddress.getByName(addressInput), portInput)
                            ApprovedOutboundConnection.connectAuthenticated(
                                address, peer, SessionConsent(),
                                confirmCode = { displayed ->
                                    runBlocking {
                                        withContext(Dispatchers.Main) { code = displayed }
                                        withTimeoutOrNull(60_000) { approval.await() }?.let {
                                            if (it) displayed else null
                                        }
                                    }
                                },
                                approveChat = { runBlocking { approval.await() } },
                                timeoutMillis = 15_000
                            ).use { connection ->
                                connection.sendChat("nexalink-connection-check-v1".toByteArray())
                                connection.receiveChat().contentEquals("nexalink-connection-ok-v1".toByteArray())
                            }
                        }
                        status = if (confirmed) "Encrypted connection check passed." else "Unexpected connection response."
                    } catch (error: kotlinx.coroutines.CancellationException) {
                        throw error
                    } catch (_: Exception) {
                        status = "Connection check ended. Check the address, Windows listener, and approvals."
                    } finally {
                        code = null
                        pending = null
                    }
                }
            }) { Text("Check encrypted connection") }

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
