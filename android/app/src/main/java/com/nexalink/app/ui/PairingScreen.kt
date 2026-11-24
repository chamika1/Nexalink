package com.nexalink.app.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.graphics.Bitmap
import android.os.SystemClock
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import com.google.zxing.BarcodeFormat
import com.google.zxing.MultiFormatWriter
import com.google.zxing.common.BitMatrix
import com.nexalink.app.security.DeviceIdentityStore
import com.nexalink.app.security.ManualPairing
import com.nexalink.app.security.PairingInvitation
import com.nexalink.app.security.TrustedPeerStore
import java.util.Base64

@Composable
fun PairingScreen() {
    val context = LocalContext.current
    val identity = remember { lazy { DeviceIdentityStore() } }
    var deviceName by remember { mutableStateOf(android.os.Build.MODEL.take(64).ifBlank { "Android" }) }
    var incoming by remember { mutableStateOf("") }
    var invitation by remember { mutableStateOf("") }
    var localFingerprint by remember { mutableStateOf("") }
    var peer by remember { mutableStateOf<PairingInvitation?>(null) }
    var pairing by remember { mutableStateOf<ManualPairing?>(null) }
    var confirmed by remember { mutableStateOf(false) }
    var challenge by remember { mutableStateOf("") }
    var peerChallenge by remember { mutableStateOf("") }
    var response by remember { mutableStateOf("") }
    var status by remember { mutableStateOf("") }

    fun resetVerification() {
        pairing = null
        confirmed = false
        challenge = ""
        peerChallenge = ""
        response = ""
    }

    Column(
        modifier = Modifier.verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Text("Exchange invitations, then compare the full fingerprints on both devices in person or over a trusted channel.")
        OutlinedTextField(
            value = deviceName, onValueChange = { deviceName = it.take(64) },
            label = { Text("Device name") }, modifier = Modifier.fillMaxWidth()
        )
        Button(onClick = {
            runCatching {
                val publicKey = identity.value.publicKey().encoded
                val encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(publicKey)
                val created = PairingInvitation(1, deviceName.trim(), encoded)
                invitation = created.serialize()
                localFingerprint = created.fingerprint()
                status = ""
            }.onFailure {
                invitation = ""
                status = "Could not create invitation. Use a device name of up to 64 UTF-8 bytes."
            }
        }) { Text("Generate invitation") }

        if (invitation.isNotBlank()) {
            val bitmap = remember(invitation) { runCatching { invitationQr(invitation) }.getOrNull() }
            if (bitmap != null) Image(bitmap.asImageBitmap(), contentDescription = "Pairing invitation QR code")
            Button(onClick = { copy(context, "NexaLink invitation", invitation) }) {
                Text("Copy invitation")
            }
        }
        if (localFingerprint.isNotBlank()) Text("My fingerprint: $localFingerprint")

        OutlinedTextField(
            value = incoming, onValueChange = {
                incoming = it.take(6000)
                peer = null
                resetVerification()
                status = ""
            },
            label = { Text("Peer invitation") },
            modifier = Modifier.fillMaxWidth(), minLines = 2
        )
        Button(onClick = {
            peer = null
            resetVerification()
            runCatching {
                val candidate = PairingInvitation.parse(incoming.trim())
                localFingerprint = identity.value.fingerprint()
                require(candidate.fingerprint() != localFingerprint)
                peer = candidate
                status = ""
            }.onFailure { status = "Enter a valid invitation from another device." }
        }) { Text("Inspect invitation") }

        peer?.let { candidate ->
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(candidate.deviceName)
                    val fingerprint = remember(candidate) { candidate.fingerprint() }
                    Text("Peer fingerprint: $fingerprint")
                    Row(
                        modifier = Modifier.fillMaxWidth().toggleable(
                            value = confirmed,
                            role = Role.Checkbox,
                            onValueChange = { checked ->
                                resetVerification()
                                confirmed = checked
                                if (checked) pairing = ManualPairing(
                                    localFingerprint, candidate, SystemClock::elapsedRealtime
                                )
                                status = ""
                            }
                        ).padding(vertical = 8.dp),
                        horizontalArrangement = Arrangement.spacedBy(12.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Checkbox(checked = confirmed, onCheckedChange = null)
                        Text("I compared the full fingerprint with the owner of this device.")
                    }

                    pairing?.let { active ->
                        Text("Send your challenge to the peer. It expires after two minutes.")
                        Button(onClick = {
                            challenge = active.createChallenge()
                            response = ""
                            status = "Challenge created."
                            copy(context, "NexaLink challenge", challenge)
                        }) { Text("Create and copy challenge") }

                        OutlinedTextField(
                            value = peerChallenge, onValueChange = { peerChallenge = it.take(80) },
                            label = { Text("Challenge from peer") }, modifier = Modifier.fillMaxWidth()
                        )
                        Button(enabled = peerChallenge.isNotBlank(), onClick = {
                            runCatching { active.respond(peerChallenge.trim()) }
                                .onSuccess {
                                    copy(context, "NexaLink response", it)
                                    status = "Signed response copied. Send it back to the peer."
                                }
                                .onFailure { status = "Could not sign the peer's challenge." }
                        }) { Text("Sign and copy response") }

                        OutlinedTextField(
                            value = response, onValueChange = { response = it.take(400) },
                            label = { Text("Signed response from peer") }, modifier = Modifier.fillMaxWidth()
                        )
                        Button(enabled = challenge.isNotBlank() && response.isNotBlank(), onClick = {
                            runCatching {
                                if (!active.verify(response.trim())) {
                                    status = "Response is invalid or expired. Check it or create a new challenge."
                                    return@runCatching
                                }
                                challenge = ""
                                response = ""
                                TrustedPeerStore(context).addVerified(candidate.deviceName, candidate.encodedPublicKey, confirmed)
                                status = "Verified device saved."
                            }.onFailure { status = "Could not save the device. Create a new challenge and try again." }
                        }) { Text("Verify response and save device") }
                    }
                }
            }
        }
        if (status.isNotBlank()) Text(status)
    }
}

private fun copy(context: Context, label: String, value: String) {
    val clipboard = context.getSystemService(ClipboardManager::class.java)
    clipboard.setPrimaryClip(ClipData.newPlainText(label, value))
}

private fun invitationQr(value: String): Bitmap {
    val matrix: BitMatrix = MultiFormatWriter().encode(value, BarcodeFormat.QR_CODE, 600, 600)
    val pixels = IntArray(600 * 600) { i ->
        if (matrix[i % 600, i / 600]) android.graphics.Color.BLACK else android.graphics.Color.WHITE
    }
    return Bitmap.createBitmap(pixels, 600, 600, Bitmap.Config.ARGB_8888)
}
