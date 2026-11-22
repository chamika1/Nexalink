package com.nexalink.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
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

private enum class HomeTab(val title: String, val subtitle: String) {
    DEVICES("Devices", "Paired devices will appear here."),
    CHAT("Chat", "Private messaging is coming soon."),
    LOCATION("Location", "Location sharing is off by default.")
}

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Surface { NexaLinkHome() }
            }
        }
    }
}

@Composable
private fun NexaLinkHome() {
    var selected by rememberSaveable { mutableStateOf(HomeTab.DEVICES) }
    Scaffold(
        bottomBar = {
            NavigationBar {
                HomeTab.entries.forEach { tab ->
                    NavigationBarItem(
                        selected = selected == tab,
                        onClick = { selected = tab },
                        icon = { Text(tab.title.take(1)) },
                        label = { Text(tab.title) }
                    )
                }
            }
        }
    ) { padding: PaddingValues ->
        Column(
            modifier = Modifier.fillMaxSize().padding(padding).padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Text("NexaLink", style = MaterialTheme.typography.headlineLarge)
            Text(selected.title, style = MaterialTheme.typography.headlineMedium)
            Text(selected.subtitle, style = MaterialTheme.typography.bodyLarge)
            Text("Prototype • No devices connected", style = MaterialTheme.typography.labelMedium)
        }
    }
}
