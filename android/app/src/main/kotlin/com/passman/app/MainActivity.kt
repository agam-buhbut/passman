package com.passman.app

import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.passman_uniffi.EntryItem
import uniffi.passman_uniffi.FieldKind
import uniffi.passman_uniffi.KdfChoice
import uniffi.passman_uniffi.PassmanApp

/** Top-level screen state. */
private enum class Screen { GATE, VAULT }

class MainActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    PassmanRoot(activity = this)
                }
            }
        }
    }
}

@Composable
private fun PassmanRoot(activity: FragmentActivity) {
    val scope = rememberCoroutineScope()
    val vaultFile = remember { File(activity.filesDir, "vault.pmv") }
    val app = remember {
        PassmanApp.open(
            vaultFile.absolutePath,
            KeystoreBridgeImpl(activity.applicationContext, requireAuth = true) { activity },
            ClipboardBridgeImpl(activity.applicationContext),
            factOverwrite = true,
        )
    }

    var screen by remember { mutableStateOf(Screen.GATE) }
    var entries by remember { mutableStateOf(listOf<EntryItem>()) }
    var status by remember { mutableStateOf("") }
    var revealed by remember { mutableStateOf("") }

    fun run(block: suspend () -> Unit) = scope.launch {
        status = "Working…"
        try {
            withContext(Dispatchers.IO) { block() }
            status = ""
        } catch (t: Throwable) {
            status = t.message ?: "Error"
        }
    }

    when (screen) {
        Screen.GATE -> GateScreen(
            vaultExists = vaultFile.exists(),
            status = status,
            onCreate = { master ->
                run {
                    val uri = app.createVault(master, KdfChoice.MEDIUM)
                    entries = app.list()
                    revealed = uri
                    screen = Screen.VAULT
                }
            },
            onUnlock = { master, code ->
                run {
                    entries = app.unlock(master, code)
                    screen = Screen.VAULT
                }
            },
        )
        Screen.VAULT -> VaultScreen(
            entries = entries,
            status = status,
            revealed = revealed,
            onReveal = { item ->
                run { revealed = app.reveal(item.id, FieldKind.PASSWORD) }
            },
            onCopy = { item ->
                run { app.copy(item.id, FieldKind.PASSWORD); status = "Copied" }
            },
            onAdd = { label, user, pass ->
                run { entries = app.add(label, user, pass, "", "") }
            },
            onLock = {
                run {
                    app.lock()
                    entries = listOf()
                    revealed = ""
                    screen = Screen.GATE
                }
            },
        )
    }
}

@Composable
private fun GateScreen(
    vaultExists: Boolean,
    status: String,
    onCreate: (String) -> Unit,
    onUnlock: (String, String) -> Unit,
) {
    var master by remember { mutableStateOf("") }
    var code by remember { mutableStateOf("") }
    Column(Modifier.padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("passman", style = MaterialTheme.typography.headlineMedium)
        OutlinedTextField(
            master, { master = it }, label = { Text("Master password") },
            visualTransformation = PasswordVisualTransformation(), modifier = Modifier.fillMaxWidth(),
        )
        if (vaultExists) {
            OutlinedTextField(code, { code = it }, label = { Text("TOTP code") }, modifier = Modifier.fillMaxWidth())
            Button({ onUnlock(master, code) }, Modifier.fillMaxWidth()) { Text("Unlock") }
        } else {
            Text("No vault yet — create one.")
            Button({ onCreate(master) }, Modifier.fillMaxWidth()) { Text("Create vault") }
        }
        if (status.isNotEmpty()) Text(status)
    }
}

@Composable
private fun VaultScreen(
    entries: List<EntryItem>,
    status: String,
    revealed: String,
    onReveal: (EntryItem) -> Unit,
    onCopy: (EntryItem) -> Unit,
    onAdd: (String, String, String) -> Unit,
    onLock: () -> Unit,
) {
    var label by remember { mutableStateOf("") }
    var user by remember { mutableStateOf("") }
    var pass by remember { mutableStateOf("") }
    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Text("Vault (${entries.size})", style = MaterialTheme.typography.titleLarge)
            Button(onLock) { Text("Lock") }
        }
        if (revealed.isNotEmpty()) {
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    if (revealed.startsWith("otpauth://")) {
                        Text("Scan with your authenticator app (shown once):")
                        QrCode(revealed, Modifier.size(220.dp))
                        Text(revealed, style = MaterialTheme.typography.bodySmall)
                    } else {
                        Text(revealed)
                    }
                }
            }
        }
        LazyColumn(verticalArrangement = Arrangement.spacedBy(6.dp), modifier = Modifier.fillMaxWidth()) {
            items(entries) { item ->
                Card(Modifier.fillMaxWidth()) {
                    Row(Modifier.padding(12.dp).fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                        Text(item.label)
                        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                            Button({ onReveal(item) }) { Text("Reveal") }
                            Button({ onCopy(item) }) { Text("Copy") }
                        }
                    }
                }
            }
        }
        Text("Add entry", style = MaterialTheme.typography.titleMedium)
        OutlinedTextField(label, { label = it }, label = { Text("Label") }, modifier = Modifier.fillMaxWidth())
        OutlinedTextField(user, { user = it }, label = { Text("Username") }, modifier = Modifier.fillMaxWidth())
        OutlinedTextField(pass, { pass = it }, label = { Text("Password") }, modifier = Modifier.fillMaxWidth())
        Button({ onAdd(label, user, pass); label = ""; user = ""; pass = "" }, Modifier.fillMaxWidth()) { Text("Add") }
        if (status.isNotEmpty()) Text(status)
    }
}
