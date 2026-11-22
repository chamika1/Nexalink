package com.nexalink.app.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.graphics.Bitmap
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.google.zxing.BarcodeFormat
import com.google.zxing.MultiFormatWriter
import com.google.zxing.common.BitMatrix
import com.nexalink.app.security.DeviceIdentityStore
import com.nexalink.app.security.PairingInvitation
import java.util.Base64

@Composable
fun PairingScreen() {
    val context = LocalContext.current
    var deviceName by remember { mutableStateOf(android.os.Build.MODEL.take(64).ifBlank { "Android" }) }
    var incoming by remember { mutableStateOf("") }
    var invitation by remember { mutableStateOf("") }
    var peerName by remember { mutableStateOf("") }
    var peerFingerprint by remember { mutableStateOf("") }
    var status by remember { mutableStateOf("Not paired. No network connection.") }
    var localFingerprint by remember { mutableStateOf("") }

    Column(
        modifier = Modifier.verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Text("Device identity & pairing invitation")
        Text("QR codes contain a public key only. Scanning or pasting does not grant access.")
        OutlinedTextField(
            value = deviceName, onValueChange = { deviceName = it.take(64) },
            label = { Text("Device name") }, modifier = Modifier.fillMaxWidth()
        )
        Button(onClick = {
            runCatching {
                val key = DeviceIdentityStore().publicKey()
                val encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(key.encoded)
                val created = PairingInvitation(1, deviceName.trim(), encoded)
                invitation = created.serialize()
                localFingerprint = created.fingerprint()
                status = "Invitation generated locally. Waiting for secure transport."
            }.onFailure { status = "Could not access device identity: ${it.javaClass.simpleName}" }
        }) { Text("Generate my QR invitation") }

        if (invitation.isNotBlank()) {
            val bitmap = remember(invitation) { runCatching { invitationQr(invitation) }.getOrNull() }
            if (bitmap != null) Image(bitmap.asImageBitmap(), contentDescription = "Pairing invitation QR code")
            else Text("QR too large; use copy invitation.")
            Text("My fingerprint: $localFingerprint")
            Button(onClick = {
                val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                clipboard.setPrimaryClip(ClipData.newPlainText("NexaLink pairing invitation", invitation))
            }) { Text("Copy invitation") }
        }

        OutlinedTextField(
            value = incoming, onValueChange = { incoming = it.take(6000) },
            label = { Text("Paste peer invitation") },
            modifier = Modifier.fillMaxWidth(), minLines = 3
        )
        Button(onClick = {
            runCatching { PairingInvitation.parse(incoming.trim()) }
                .onSuccess {
                    peerName = it.deviceName
                    peerFingerprint = it.fingerprint()
                    status = "Invitation parsed. Verify the fingerprint with the other person using a trusted channel. No pairing has occurred."
                }.onFailure {
                    peerName = ""
                    peerFingerprint = ""
                    status = "Invalid or unsupported invitation."
                }
        }) { Text("Inspect invitation") }

        if (peerName.isNotBlank()) {
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Peer: $peerName")
                    Text("Fingerprint: $peerFingerprint")
                    Text("Do not trust this identity until both sides authenticate and approve.")
                    Button(onClick = {
                        incoming = ""
                        peerName = ""
                        peerFingerprint = ""
                        status = "Invitation discarded."
                    }) { Text("Discard invitation") }
                }
            }
        }
        Text(status)
    }
}

private fun invitationQr(value: String): Bitmap {
    val matrix: BitMatrix = MultiFormatWriter().encode(value, BarcodeFormat.QR_CODE, 600, 600)
    val pixels = IntArray(600 * 600) { i ->
        if (matrix[i % 600, i / 600]) android.graphics.Color.BLACK else android.graphics.Color.WHITE
    }
    return Bitmap.createBitmap(pixels, 600, 600, Bitmap.Config.ARGB_8888)
}
