package com.nexalink.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

private enum class HomeTab(val title: String) {
    DEVICES("Devices"), CHAT("Chat"), LOCATION("Location")
}

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { MaterialTheme { Surface { NexaLinkHome() } } }
    }
}

@Composable
private fun NexaLinkHome() {
    var selected by rememberSaveable { mutableStateOf(HomeTab.DEVICES) }
    var showPairingInfo by rememberSaveable { mutableStateOf(false) }
    Scaffold(
        bottomBar = {
            NavigationBar {
                HomeTab.entries.forEach { tab ->
                    NavigationBarItem(
                        selected = selected == tab,
                        onClick = { selected = tab; showPairingInfo = false },
                        icon = { Text(tab.title.take(1)) },
                        label = { Text(tab.title) }
                    )
                }
            }
        }
    ) { padding: PaddingValues ->
        Column(
            modifier = Modifier.fillMaxSize().padding(padding).padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Text("NexaLink", style = MaterialTheme.typography.headlineLarge)
            when (selected) {
                HomeTab.DEVICES -> {
                    Text("My Devices", style = MaterialTheme.typography.headlineMedium)
                    Text("No paired devices yet.")
                    Button(onClick = { showPairingInfo = !showPairingInfo }) {
                        Text("Pair a device")
                    }
                    if (showPairingInfo) {
                        Text("Pairing preview only. Secure QR pairing and device verification are not implemented yet.")
                        Text("Future flow: scan QR → verify both devices → approve pairing.")
                    }
                }
                HomeTab.CHAT -> {
                    Text("Private Chat", style = MaterialTheme.typography.headlineMedium)
                    Text("Messaging is not connected yet. No messages are being sent.")
                }
                HomeTab.LOCATION -> {
                    Text("Family Location", style = MaterialTheme.typography.headlineMedium)
                    Text("Location sharing is OFF.")
                    Text("Location permission is not requested by this prototype.")
                }
            }
            Text("Prototype v0.1 • No active connections", style = MaterialTheme.typography.labelMedium)
        }
    }
}
