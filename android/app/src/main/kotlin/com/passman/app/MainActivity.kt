package com.passman.app

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import java.io.File
import java.io.IOException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.passman_uniffi.AppException
import uniffi.passman_uniffi.EntryItem
import uniffi.passman_uniffi.FieldKind
import uniffi.passman_uniffi.KdfChoice
import uniffi.passman_uniffi.PassmanApp
import uniffi.passman_uniffi.RecoveryChoice
import uniffi.passman_uniffi.estimateStrength

/** Top-level screen state. */
private enum class Screen { GATE, VAULT }

class MainActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Block screenshots, screen recording, and the recents/app-switcher
        // snapshot — the revealed password and the plaintext TOTP seed are
        // on screen (threats #5/#16).
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE,
        )
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
    // Defense-in-depth: never crash the whole app if opening the vault fails.
    // `open` can return AppError.Setup (e.g. the lockfile cannot be created);
    // surface it on a screen instead of letting the exception escape and kill
    // composition.
    //
    // open() does disk I/O (vault read + single-instance lockfile), so it must
    // not run on the main thread during first composition. produceState emits
    // null while the work runs on Dispatchers.IO, then a Result once it
    // completes; first composition shows a loading screen instead of blocking.
    val appResult by produceState<Result<PassmanApp>?>(initialValue = null) {
        value = withContext(Dispatchers.IO) {
            runCatching {
                PassmanApp.open(
                    vaultFile.absolutePath,
                    KeystoreBridgeImpl(activity.applicationContext, requireAuth = true) { activity },
                    ClipboardBridgeImpl(activity.applicationContext),
                    factOverwrite = true,
                )
            }
        }
    }
    val result = appResult
    if (result == null) {
        LoadingScreen()
        return
    }
    val app = result.getOrNull()
    if (app == null) {
        StartupErrorScreen(result.exceptionOrNull()?.message ?: "Could not open passman.")
        return
    }

    var screen by remember { mutableStateOf(Screen.GATE) }
    var entries by remember { mutableStateOf(listOf<EntryItem>()) }
    var status by remember { mutableStateOf("") }
    var revealed by remember { mutableStateOf("") }
    var inFlight by remember { mutableStateOf(false) }

    // The pending clipboard auto-clear; a fresh copy cancels the prior one so we
    // never wipe a newer clip after the older clip's 30 s elapses.
    val clearJob = remember { mutableStateOf<Job?>(null) }

    // Lock on backgrounding: ON_STOP drops the keys immediately instead of
    // waiting out the 120 s session timeout, and returns to the gate.
    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_STOP) {
                // Drop the keys off the main thread: never block/ANR the main
                // thread on a PassmanApp FFI call inside a lifecycle callback.
                // lock() is fire-and-forget on the core side; the Compose state
                // resets below stay on the main thread.
                scope.launch(Dispatchers.Default) { runCatching { app.lock() } }
                clearJob.value?.cancel()
                clearJob.value = null
                entries = listOf()
                revealed = ""
                screen = Screen.GATE
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    fun run(working: String = "Working…", block: suspend () -> Unit) = scope.launch {
        inFlight = true
        status = working
        try {
            withContext(Dispatchers.IO) { block() }
            // Preserve a terminal message the block set (e.g. the copy notice);
            // otherwise clear the in-progress status.
            if (status == working) status = ""
        } catch (t: AppException.SessionLocked) {
            // The session timed out (or was locked). Return to the gate instead
            // of leaving the user on the vault screen issuing locked-state ops.
            entries = listOf()
            revealed = ""
            screen = Screen.GATE
            status = "Session locked — unlock again."
        } catch (t: Throwable) {
            status = friendlyError(t)
        } finally {
            inFlight = false
        }
    }

    // B7 recovery backup. The derived bytes are recovery key material: they live
    // only between exportRecovery() returning and the SAF write, then are zeroed.
    var showExportDialog by remember { mutableStateOf(false) }
    val pendingBackup = remember { mutableStateOf<ByteArray?>(null) }

    // SAF: let the user pick where the .pmrec file goes, then write the pending
    // bytes to the returned Uri off the main thread. Opening the system picker
    // stops this activity, so the ON_STOP observer above locks the session and
    // returns to the gate — the write still succeeds because the bytes were
    // captured before the picker launched and need no live session.
    val saveLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream"),
    ) { uri ->
        val bytes = pendingBackup.value
        if (bytes == null) return@rememberLauncherForActivityResult
        if (uri == null) {
            bytes.fill(0)
            pendingBackup.value = null
            status = "Backup cancelled."
            return@rememberLauncherForActivityResult
        }
        scope.launch {
            inFlight = true
            status = "Saving backup…"
            try {
                withContext(Dispatchers.IO) {
                    val out = activity.contentResolver.openOutputStream(uri)
                        ?: throw IOException("Could not open the chosen location.")
                    out.use { it.write(bytes) }
                }
                status = "Backup saved."
            } catch (t: Throwable) {
                // The failure is I/O on the chosen Uri; no secret is in the text.
                status = "Couldn't save the backup — please try again."
            } finally {
                bytes.fill(0)
                pendingBackup.value = null
                inFlight = false
            }
        }
    }

    // Derive the recovery key (slow Argon2, off-main), then hand the bytes to the
    // SAF picker. The dialog closes on success so the master password is not held
    // in its TextField state beyond the call.
    fun startExport(master: String, code: String, preset: RecoveryChoice) {
        scope.launch {
            inFlight = true
            status = "Deriving recovery key…"
            try {
                val bytes = withContext(Dispatchers.IO) { app.exportRecovery(master, code, preset) }
                pendingBackup.value = bytes
                showExportDialog = false
                status = "Choose where to save the backup…"
                saveLauncher.launch("passman-recovery.pmrec")
            } catch (t: AppException.SessionLocked) {
                showExportDialog = false
                entries = listOf()
                revealed = ""
                screen = Screen.GATE
                status = "Session locked — unlock again."
            } catch (t: Throwable) {
                // Keep the dialog open so the user can correct the password/code.
                status = friendlyError(t)
            } finally {
                inFlight = false
            }
        }
    }

    // B8: confirm the freshly provisioned authenticator. The boolean result feeds
    // back into the post-create card's local state on the main thread.
    fun confirmTotp(code: String, onResult: (Boolean) -> Unit) {
        scope.launch {
            inFlight = true
            status = "Checking code…"
            try {
                val ok = withContext(Dispatchers.IO) { app.verifyTotp(code) }
                status = ""
                onResult(ok)
            } catch (t: AppException.SessionLocked) {
                entries = listOf()
                revealed = ""
                screen = Screen.GATE
                status = "Session locked — unlock again."
            } catch (t: Throwable) {
                status = friendlyError(t)
                onResult(false)
            } finally {
                inFlight = false
            }
        }
    }

    when (screen) {
        Screen.GATE -> GateScreen(
            vaultExists = vaultFile.exists(),
            status = status,
            inFlight = inFlight,
            onCreate = { master, kdf ->
                run("Deriving the vault key — this is deliberately slow…") {
                    // KDF hardness is chosen in GateScreen and defaults to LOW
                    // (see the rationale there).
                    val uri = app.createVault(master, kdf)
                    entries = app.list()
                    revealed = uri
                    screen = Screen.VAULT
                }
            },
            onUnlock = { master, code ->
                run("Deriving the vault key — this is deliberately slow…") {
                    entries = app.unlock(master, code)
                    screen = Screen.VAULT
                }
            },
        )
        Screen.VAULT -> VaultScreen(
            entries = entries,
            status = status,
            revealed = revealed,
            inFlight = inFlight,
            onReveal = { item ->
                run { revealed = app.reveal(item.id, FieldKind.PASSWORD) }
            },
            onCopy = { item ->
                run {
                    // Capture the cookie digest on the IO dispatcher (run{} wraps
                    // the whole block in withContext(IO)), then hop to the main
                    // thread to touch Compose state: clearJob is a mutableStateOf,
                    // and its cancel/reassign — plus the status write — must not run
                    // off the main thread. scope.launch defaults to Main, so the
                    // 30 s auto-clear job is created from the main-dispatched body.
                    val digest = app.copy(item.id, FieldKind.PASSWORD)
                    withContext(Dispatchers.Main) {
                        clearJob.value?.cancel()
                        clearJob.value = scope.launch {
                            delay(30_000)
                            withContext(Dispatchers.IO) { app.clearClipboard(digest) }
                        }
                        status = "Copied — clears in 30 s"
                    }
                }
            },
            onAdd = { label, user, pass ->
                run { entries = app.add(label, user, pass, "", "") }
            },
            onClearRevealed = { revealed = "" },
            onConfirmTotp = { code, onResult -> confirmTotp(code, onResult) },
            onExportRecovery = { showExportDialog = true },
            onLock = {
                run {
                    app.lock()
                    clearJob.value?.cancel()
                    clearJob.value = null
                    entries = listOf()
                    revealed = ""
                    screen = Screen.GATE
                }
            },
        )
    }

    if (showExportDialog) {
        ExportRecoveryDialog(
            inFlight = inFlight,
            onDismiss = { if (!inFlight) showExportDialog = false },
            onExport = { master, code, preset -> startExport(master, code, preset) },
        )
    }
}

@Composable
private fun StartupErrorScreen(message: String) {
    Column(Modifier.padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("passman couldn't start", style = MaterialTheme.typography.headlineSmall)
        Text(message)
    }
}

@Composable
private fun LoadingScreen() {
    Column(Modifier.padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("passman", style = MaterialTheme.typography.headlineMedium)
        CircularProgressIndicator()
        Text("Opening your vault…")
    }
}

/**
 * Map a core error to a friendly, actionable line (mirrors the CLI taxonomy:
 * bad credentials, locked out, already running, no hardware). The core already
 * returns user-facing detail strings; this normalizes them and, crucially,
 * replaces the bare technical fallback so the user never sees a raw "Error".
 */
private fun friendlyError(t: Throwable): String = when (t) {
    is AppException.SessionLocked -> "Session locked — unlock again."
    is AppException.Failed -> friendlyDetail(t.detail)
    is AppException.Setup -> friendlyDetail(t.detail)
    else -> t.message ?: "Something went wrong. Please try again."
}

private fun friendlyDetail(detail: String): String {
    val d = detail.lowercase()
    return when {
        "another" in d || "already" in d || "in use" in d ->
            "passman is already open for this vault elsewhere."
        "locked out" in d || "try again in" in d -> detail // carries the remaining-time hint
        "incorrect" in d || "credential" in d || "totp" in d ->
            "Incorrect master password or TOTP code."
        "hardware" in d || "key store" in d ->
            "This device has no usable secure hardware key store."
        else -> detail.removePrefix("could not open the vault: ")
            .replaceFirstChar { it.uppercaseChar() }
    }
}

@Composable
private fun GateScreen(
    vaultExists: Boolean,
    status: String,
    inFlight: Boolean,
    onCreate: (String, KdfChoice) -> Unit,
    onUnlock: (String, String) -> Unit,
) {
    var master by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var code by remember { mutableStateOf("") }
    // Default to LOW (256 MiB Argon2). MEDIUM's 1 GiB working set risks the
    // lowmemorykiller / OOM on phones, and the Keystore-bound second factor
    // already gates offline guessing — so a lighter KDF is an acceptable
    // trade-off here. The user can still opt up to MEDIUM.
    var kdf by remember { mutableStateOf(KdfChoice.LOW) }

    // B8 live strength readout. estimateStrength needs no session and is cheap,
    // but we still keep it off the main thread and debounce rapid keystrokes.
    val strengthScore by produceState<Int?>(initialValue = null, master) {
        value = null
        if (master.isEmpty()) return@produceState
        delay(150)
        value = withContext(Dispatchers.Default) { estimateStrength(master).toInt() }
    }

    Column(Modifier.padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("passman", style = MaterialTheme.typography.headlineMedium)
        OutlinedTextField(
            master, { master = it }, label = { Text("Master password") },
            visualTransformation = PasswordVisualTransformation(), modifier = Modifier.fillMaxWidth(),
        )
        if (vaultExists) {
            OutlinedTextField(
                code, { code = it }, label = { Text("TOTP code") },
                modifier = Modifier.fillMaxWidth(),
                keyboardOptions = KeyboardOptions(
                    keyboardType = KeyboardType.Number,
                    imeAction = ImeAction.Done,
                ),
                keyboardActions = KeyboardActions(onDone = { onUnlock(master, code) }),
            )
            Button({ onUnlock(master, code) }, Modifier.fillMaxWidth(), enabled = !inFlight) { Text("Unlock") }
        } else {
            OutlinedTextField(
                confirm, { confirm = it }, label = { Text("Confirm master password") },
                visualTransformation = PasswordVisualTransformation(), modifier = Modifier.fillMaxWidth(),
            )
            // Local guards: the two fields must match and we require 12+ chars.
            val mismatch = confirm.isNotEmpty() && master != confirm
            val tooShort = master.isNotEmpty() && master.length < 12
            when {
                mismatch -> Text("Passwords don't match.")
                tooShort -> Text("Use at least 12 characters for your master password.")
                else -> Text("No vault yet — create one.")
            }
            // B8: live strength readout. A 0 score is too weak — block create.
            if (master.isNotEmpty()) {
                val score = strengthScore
                when {
                    score == null -> Text("Strength: …")
                    score == 0 -> Text("Strength: ${strengthLabel(score)} — choose a stronger password.")
                    else -> Text("Strength: ${strengthLabel(score)}")
                }
            }
            Text("Key hardness", style = MaterialTheme.typography.labelLarge)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                KdfOption("Low (recommended)", kdf == KdfChoice.LOW) { kdf = KdfChoice.LOW }
                KdfOption("Medium", kdf == KdfChoice.MEDIUM) { kdf = KdfChoice.MEDIUM }
            }
            Button(
                { onCreate(master, kdf) },
                Modifier.fillMaxWidth(),
                enabled = !inFlight && master.length >= 12 && master == confirm && strengthScore != 0,
            ) { Text("Create vault") }
        }
        if (inFlight) CircularProgressIndicator()
        if (status.isNotEmpty()) Text(status)
    }
}

/** A single KDF-hardness choice: filled when selected, text-only otherwise. */
@Composable
private fun KdfOption(label: String, selected: Boolean, onClick: () -> Unit) {
    if (selected) {
        Button(onClick) { Text(label) }
    } else {
        TextButton(onClick) { Text(label) }
    }
}

/** Coarse 0..=4 strength score to a label (mirrors estimate_strength). */
private fun strengthLabel(score: Int): String = when (score) {
    0 -> "Weak"
    1 -> "Fair"
    2 -> "Good"
    3 -> "Strong"
    else -> "Excellent"
}

@Composable
private fun VaultScreen(
    entries: List<EntryItem>,
    status: String,
    revealed: String,
    inFlight: Boolean,
    onReveal: (EntryItem) -> Unit,
    onCopy: (EntryItem) -> Unit,
    onAdd: (String, String, String) -> Unit,
    onClearRevealed: () -> Unit,
    onConfirmTotp: (String, (Boolean) -> Unit) -> Unit,
    onExportRecovery: () -> Unit,
    onLock: () -> Unit,
) {
    var label by remember { mutableStateOf("") }
    var user by remember { mutableStateOf("") }
    var pass by remember { mutableStateOf("") }
    val isProvisioningUri = revealed.startsWith("otpauth://")

    // A password reveal is obscured by default; tapping toggles it visible.
    // Reset to hidden whenever a new value is revealed.
    var showRevealed by remember(revealed) { mutableStateOf(false) }

    // Auto-hide a revealed password after 10 s (mirrors GTK). The one-time
    // otpauth provisioning URI is exempt — it is dismissed manually (item 6).
    LaunchedEffect(revealed) {
        if (revealed.isNotEmpty() && !isProvisioningUri) {
            delay(10_000)
            onClearRevealed()
        }
    }

    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Text("Vault (${entries.size})", style = MaterialTheme.typography.titleLarge)
            Button(onLock) { Text("Lock") }
        }
        // The onboarding card below carries its own export button while the
        // one-time QR is shown; avoid a duplicate here in that state.
        if (!isProvisioningUri) {
            TextButton(onExportRecovery, enabled = !inFlight) { Text("Export recovery backup") }
        }
        if (revealed.isNotEmpty()) {
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    if (isProvisioningUri) {
                        Text("Scan with your authenticator app (shown once):")
                        QrCode(revealed, Modifier.size(220.dp))
                        Text(revealed, style = MaterialTheme.typography.bodySmall)

                        // B8: confirm the authenticator was provisioned before
                        // letting the user leave this one-time screen.
                        var totpCode by remember { mutableStateOf("") }
                        var confirmed by remember { mutableStateOf(false) }
                        var confirmMsg by remember { mutableStateOf("") }
                        if (confirmed) {
                            Text("Authenticator confirmed ✓")
                        } else {
                            Text("Confirm by entering the current 6-digit code:")
                            OutlinedTextField(
                                totpCode,
                                { totpCode = it; confirmMsg = "" },
                                label = { Text("TOTP code") },
                                modifier = Modifier.fillMaxWidth(),
                                keyboardOptions = KeyboardOptions(
                                    keyboardType = KeyboardType.Number,
                                    imeAction = ImeAction.Done,
                                ),
                                keyboardActions = KeyboardActions(onDone = {
                                    onConfirmTotp(totpCode) { ok ->
                                        confirmed = ok
                                        confirmMsg = if (ok) "" else "That code didn't match — try again"
                                    }
                                }),
                            )
                            Button(
                                {
                                    onConfirmTotp(totpCode) { ok ->
                                        confirmed = ok
                                        confirmMsg = if (ok) "" else "That code didn't match — try again"
                                    }
                                },
                                Modifier.fillMaxWidth(),
                                enabled = !inFlight && totpCode.isNotEmpty(),
                            ) { Text("Confirm") }
                            if (confirmMsg.isNotEmpty()) Text(confirmMsg)
                        }

                        // B7 onboarding nudge: without a backup, a lost or wiped
                        // device means a permanently lost vault.
                        Card(Modifier.fillMaxWidth()) {
                            Column(
                                Modifier.padding(12.dp),
                                verticalArrangement = Arrangement.spacedBy(6.dp),
                            ) {
                                Text(
                                    "Create a recovery backup now",
                                    style = MaterialTheme.typography.titleSmall,
                                )
                                Text(
                                    "Without a backup, a lost or wiped device means a " +
                                        "permanently lost vault.",
                                )
                                Button(
                                    onExportRecovery,
                                    Modifier.fillMaxWidth(),
                                    enabled = !inFlight,
                                ) { Text("Export recovery backup") }
                            }
                        }

                        Button(
                            onClearRevealed,
                            Modifier.fillMaxWidth(),
                            enabled = confirmed,
                        ) { Text("Continue to vault") }
                    } else {
                        Text(if (showRevealed) revealed else "••••••••")
                        TextButton({ showRevealed = !showRevealed }) {
                            Text(if (showRevealed) "Hide" else "Show")
                        }
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
                            Button({ onReveal(item) }, enabled = !inFlight) { Text("Reveal") }
                            Button({ onCopy(item) }, enabled = !inFlight) { Text("Copy") }
                        }
                    }
                }
            }
        }
        Text("Add entry", style = MaterialTheme.typography.titleMedium)
        OutlinedTextField(label, { label = it }, label = { Text("Label") }, modifier = Modifier.fillMaxWidth())
        OutlinedTextField(user, { user = it }, label = { Text("Username") }, modifier = Modifier.fillMaxWidth())
        OutlinedTextField(pass, { pass = it }, label = { Text("Password") }, modifier = Modifier.fillMaxWidth())
        Button(
            { onAdd(label, user, pass); label = ""; user = ""; pass = "" },
            Modifier.fillMaxWidth(),
            enabled = !inFlight,
        ) { Text("Add") }
        if (inFlight) CircularProgressIndicator()
        if (status.isNotEmpty()) Text(status)
    }
}

/**
 * B7 credential collection for a recovery export. Gathers the master password, a
 * fresh TOTP code, and an Argon2id cost preset, then hands them to [onExport].
 * The caller dismisses the dialog once the (slow) derivation starts, so the
 * master password is not retained in TextField state beyond the call.
 */
@Composable
private fun ExportRecoveryDialog(
    inFlight: Boolean,
    onDismiss: () -> Unit,
    onExport: (String, String, RecoveryChoice) -> Unit,
) {
    var master by remember { mutableStateOf("") }
    var code by remember { mutableStateOf("") }
    var preset by remember { mutableStateOf(RecoveryChoice.DEFAULT) }

    AlertDialog(
        onDismissRequest = onDismiss,
        confirmButton = {
            Button(
                { onExport(master, code, preset) },
                enabled = !inFlight && master.isNotEmpty() && code.isNotEmpty(),
            ) { Text("Create backup") }
        },
        dismissButton = {
            TextButton(onDismiss, enabled = !inFlight) { Text("Cancel") }
        },
        title = { Text("Export recovery backup") },
        text = {
            Column(
                Modifier.verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text("A single-factor offline backup — keep the file somewhere safe.")
                OutlinedTextField(
                    master,
                    { master = it },
                    label = { Text("Master password") },
                    visualTransformation = PasswordVisualTransformation(),
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    code,
                    { code = it },
                    label = { Text("Fresh TOTP code") },
                    modifier = Modifier.fillMaxWidth(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                )
                Text("Backup strength", style = MaterialTheme.typography.labelLarge)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    KdfOption("Floor", preset == RecoveryChoice.FLOOR) { preset = RecoveryChoice.FLOOR }
                    KdfOption("Default", preset == RecoveryChoice.DEFAULT) { preset = RecoveryChoice.DEFAULT }
                    KdfOption("Paranoid", preset == RecoveryChoice.PARANOID) { preset = RecoveryChoice.PARANOID }
                }
                if (inFlight) {
                    CircularProgressIndicator()
                    Text("Deriving recovery key…")
                }
            }
        },
    )
}
