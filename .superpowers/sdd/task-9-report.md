# Task 9 — Android (Kotlin/Compose) security + UX fixes

STATUS: COMPLETE (cannot build — no Android SDK on this machine; on-device build required)

Scope: only the three assigned files were edited:
- `android/app/src/main/kotlin/com/passman/app/MainActivity.kt`
- `android/app/src/main/kotlin/com/passman/app/ClipboardBridgeImpl.kt`
- `android/app/src/main/kotlin/com/passman/app/KeystoreBridgeImpl.kt`

NOTE on working tree: the tree was NOT clean at start — many pre-existing
modifications exist across the Rust crates and other files from prior tasks
(task-1..task-7). I did not touch any of those. My edits are confined to the
three files above. No files created/deleted/renamed. No Gradle dependencies
added. No tests modified. Not committed.

API cross-check against `android/app/src/main/kotlin/uniffi/passman_uniffi/passman_uniffi.kt`:
- `PassmanAppInterface.copy(id: kotlin.ByteArray, field: FieldKind): kotlin.ByteArray` — `@Throws(AppException::class)`. Returns the cookie digest as `ByteArray`. CONFIRMED (line 2327 / 2520).
- `PassmanAppInterface.clearClipboard(digest: kotlin.ByteArray)` — fire-and-forget, NOT `@Throws`. CONFIRMED (line 2317 / 2500).
- `PassmanAppInterface.lock()` — no throws. CONFIRMED (line 2360).
- `FieldKind.PASSWORD` — CONFIRMED enum variant (line 3002).
- The digest type from `copy(...)` (`ByteArray`) matches `clearClipboard(...)`'s parameter (`ByteArray`) exactly — passed through directly.

---

## Item 1 [S1, HIGH] — Clipboard auto-clear after copy

File: MainActivity.kt (`PassmanRoot`, `onCopy`).

- Added `val clearJob = remember { mutableStateOf<Job?>(null) }` to hold the pending clear.
- `onCopy` now captures the digest: `val digest = app.copy(item.id, FieldKind.PASSWORD)`,
  cancels any prior pending clear (`clearJob.value?.cancel()`), then launches on the
  recomposition-surviving `scope`: `scope.launch { delay(30_000); withContext(Dispatchers.IO) { app.clearClipboard(digest) } }`.
- Status set to `"Copied — clears in 30 s"`.
- The clear job is also cancelled on Lock (item 4 onLock) and on background ON_STOP (item 4).
- The `run()` helper was adjusted so a terminal status set inside the block (the
  copy notice) is preserved instead of being blanked: `if (status == working) status = ""`.
  (The original code had `status = "Copied"` clobbered by `status = ""`; fixed.)
- WorkManager fallback for backgrounded clears: NOT added (would be a new dependency).
  Noted as a FOLLOW-UP. The lock-on-background (item 4) mitigates the gap.

## Item 2 [S1 secondary] — Mark the clip sensitive

File: ClipboardBridgeImpl.kt (`write`).

- The `EXTRA_IS_SENSITIVE` flag was already present in the file; the task asked to
  guard it with `Build.VERSION.SDK_INT >= 33` (the key is only honored on Android 13+).
  Wrapped the existing `description.extras = PersistableBundle()...` in
  `if (Build.VERSION.SDK_INT >= 33) { ... }`.

## Item 3 [S3, MED] — FLAG_SECURE

File: MainActivity.kt (`MainActivity.onCreate`).

- Added, before `setContent`:
  `window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)`.

## Item 4 [UX/security] — Lock on backgrounding

File: MainActivity.kt (`PassmanRoot`).

- `val lifecycleOwner = LocalLifecycleOwner.current` + a `DisposableEffect(lifecycleOwner)`
  registering a `LifecycleEventObserver`. On `Lifecycle.Event.ON_STOP`: `runCatching { app.lock() }`,
  cancel the pending clear job, clear `entries`/`revealed`, navigate `screen = Screen.GATE`.
  Observer removed in `onDispose`.
- `app.lock()` wrapped in `runCatching` because the observer fires outside the `run()`
  try/catch (lock() is not @Throws, but defensive).

## Item 5 [S5, MED] — Reveal masked by default + auto-hide

File: MainActivity.kt (`VaultScreen`).

- Password reveal is obscured by default: `Text(if (showRevealed) revealed else "••••••••")`
  with a `TextButton` toggle ("Show"/"Hide"). `showRevealed` is
  `remember(revealed) { mutableStateOf(false) }` so it resets to hidden on each new reveal.
- Auto-hide: `LaunchedEffect(revealed)` — if `revealed` is non-empty and NOT an
  `otpauth://` provisioning URI, `delay(10_000)` then `onClearRevealed()`.
- The provisioning URI branch is exempt from auto-hide (handled by item 6).

## Item 6 [UX] — Manual dismiss for the one-time TOTP QR

File: MainActivity.kt (`VaultScreen`).

- Added a `Button(onClearRevealed)` labelled "Done — I've added it to my authenticator"
  inside the `otpauth://` branch. No timer on the setup QR (manual dismiss only).
- `onClearRevealed = { revealed = "" }` wired from `PassmanRoot`.

## Item 7 [UX] — Feedback on the slow Argon2 unlock/create

File: MainActivity.kt (`PassmanRoot`, `GateScreen`, `VaultScreen`).

- Added `var inFlight by remember { mutableStateOf(false) }`. `run()` sets it true on
  entry, false in `finally`.
- `run(working: String = "Working…", ...)` — create/unlock pass
  `"Deriving the vault key — this is deliberately slow…"`.
- `GateScreen` / `VaultScreen` take an `inFlight` param; Create/Unlock/Add buttons get
  `enabled = !inFlight`; a `CircularProgressIndicator()` shows while `inFlight`.

## Item 8 [UX] — Biometric latch timeout

File: KeystoreBridgeImpl.kt (`authenticate`).

- `latch.await()` → `if (!latch.await(60, TimeUnit.SECONDS)) throw KeystoreFailure.Cancelled()`.
  `Cancelled()` is a confirmed transient `KeystoreFailure` variant (already used in `mapAuthError`).

## Item 9 [UX/a11y] — Numeric keyboard + Done IME on TOTP

File: MainActivity.kt (`GateScreen`).

- TOTP `OutlinedTextField` now has
  `keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number, imeAction = ImeAction.Done)`
  and `keyboardActions = KeyboardActions(onDone = { onUnlock(master, code) })`.

---

## NEW imports added

MainActivity.kt:
- `android.view.WindowManager`
- `androidx.compose.foundation.text.KeyboardActions`
- `androidx.compose.foundation.text.KeyboardOptions`
- `androidx.compose.material3.CircularProgressIndicator`
- `androidx.compose.material3.TextButton`
- `androidx.compose.runtime.DisposableEffect`
- `androidx.compose.runtime.LaunchedEffect`
- `androidx.compose.ui.platform.LocalLifecycleOwner`
- `androidx.compose.ui.text.input.ImeAction`
- `androidx.compose.ui.text.input.KeyboardType`
- `androidx.lifecycle.Lifecycle`
- `androidx.lifecycle.LifecycleEventObserver`
- `kotlinx.coroutines.Job`
- `kotlinx.coroutines.delay`
  (existing already-present: `Dispatchers`, `launch`, `withContext`, `rememberCoroutineScope`,
   `PasswordVisualTransformation`, all compose layout/material3/runtime imports.)

ClipboardBridgeImpl.kt:
- `android.os.Build`

KeystoreBridgeImpl.kt:
- `java.util.concurrent.TimeUnit`

## External symbols referenced (for fast typo-spotting on the on-device build)

- `WindowManager.LayoutParams.FLAG_SECURE`
- `KeyboardOptions(keyboardType = ..., imeAction = ...)`, `KeyboardActions(onDone = ...)`
- `KeyboardType.Number`, `ImeAction.Done`
- `CircularProgressIndicator()`, `TextButton(onClick) { ... }`, `Button(..., enabled = ...)`
- `DisposableEffect(key) { ... onDispose { } }`, `LaunchedEffect(key) { ... }`
- `LocalLifecycleOwner.current` (from `androidx.compose.ui.platform`)
- `lifecycleOwner.lifecycle.addObserver(...)` / `.removeObserver(...)`
- `LifecycleEventObserver { owner, event -> }`, `Lifecycle.Event.ON_STOP`
- `kotlinx.coroutines.Job`, `delay(Long)`, `scope.launch { }`, `withContext(Dispatchers.IO) { }`
- `mutableStateOf<Job?>(null)`
- `Build.VERSION.SDK_INT`, `ClipDescription.EXTRA_IS_SENSITIVE`, `PersistableBundle`
- `CountDownLatch.await(60, TimeUnit.SECONDS): Boolean`, `KeystoreFailure.Cancelled()`
- `app.copy(ByteArray, FieldKind): ByteArray`, `app.clearClipboard(ByteArray)`, `app.lock()`

---

## CONCERNS / UNCERTAINTIES (flag for on-device build confirmation)

1. **`LocalLifecycleOwner` import path (MEDIUM).** I used
   `androidx.compose.ui.platform.LocalLifecycleOwner`. With compose-bom 2024.10.01 +
   activity-compose 1.9.3 and NO explicit `lifecycle-runtime-compose` dependency in
   `app/build.gradle.kts`, the platform accessor is the safe one (provided transitively
   by compose-ui). In newer setups this is deprecated in favour of
   `androidx.lifecycle.compose.LocalLifecycleOwner`, which would require the
   `lifecycle-runtime-compose` artifact (NOT declared — would be a new dependency).
   If the build warns "deprecated", that is expected and harmless. If it errors
   "unresolved reference: LocalLifecycleOwner" from `androidx.compose.ui.platform`,
   the alternative is to add `androidx.lifecycle:lifecycle-runtime-compose` and switch
   the import — but that is a new Gradle dependency and must be approved first.

2. **`androidx.lifecycle.Lifecycle` / `LifecycleEventObserver` (LOW).** These come from
   `lifecycle-common`/`lifecycle-runtime`, pulled transitively by activity-compose 1.9.3.
   Expected present. Confirm no "unresolved reference".

3. **`CircularProgressIndicator` overload (LOW).** Called with no args:
   `CircularProgressIndicator()`. In material3 (compose-bom 2024.10.01) the zero-arg
   indeterminate overload exists; confirm no "no value passed for parameter 'progress'"
   (that would mean a different overload is being resolved — unlikely for material3).

4. **`description.extras` setter in ClipboardBridgeImpl (LOW, pre-existing).** Unchanged
   semantically; only the API-33 guard was added. `ClipData.description` is a
   `ClipDescription` whose `extras` is settable. This already compiled in prior tasks.

5. **Status preservation in `run()` (LOW).** `if (status == working) status = ""` relies
   on string identity of the working message; the copy block sets a different string so
   the notice survives. Verified by inspection. If any future op sets status to exactly
   the working message and expects it cleared, that edge would differ — not the case here.
