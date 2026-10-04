#![no_main]
//! Coverage-guided fuzzing of the recovery-file parser (`architecture.md` §10):
//! recovery exports are attacker-controlled at rest. `import` parses the binary
//! structure (magic, version, kdf id/params, salt, length-prefixed fields)
//! BEFORE doing any key derivation, so malformed inputs — the attack surface —
//! fail fast in the parser without touching Argon2. `import` additionally bounds
//! the header KDF cost with the universal anti-DoS *ceiling*
//! (`KdfParams::within_limits()` — `MAX_M_KIB`/`MAX_T`/`MAX_P`), rejecting an
//! attacker-chosen cost before any derivation so a hostile header can't force an
//! unbounded allocation. This is a ceiling, not a floor: the strength *floor* is
//! enforced only on the export side.
//!
//! The ceiling still admits up to 8 GiB, and a real derivation needs its full
//! memory cost, so the fuzzer soon finds an in-range header that makes libFuzzer
//! stop with out-of-memory (`-rss_limit_mb`) or a timeout: a limit of the
//! harness, not a parser bug. The harness therefore calls `import_within_memory`
//! with a tiny "available memory" figure, so the production host-memory check
//! caps what a fuzzed header can make Argon2id do (and gets fuzzed as well).

use libfuzzer_sys::fuzz_target;
use passman_crypto::SecretString;

/// "Available memory" passed to the host-memory check, in KiB. The check admits
/// at most 80% of it (816 KiB) per derivation; with the ceiling's 24 passes that
/// is about 19 MiB of Argon2 work, roughly 0.2 s per run under ASan on a laptop.
/// Costlier headers get the same clean `Kdf` error a small device would.
const FUZZ_AVAILABLE_KIB: u64 = 1024;

fuzz_target!(|data: &[u8]| {
    // The password is irrelevant to the structural parse that handles malformed
    // input; a panic on any input is a bug.
    let _ = passman_recovery::import_within_memory(
        data,
        &SecretString::new("fuzz".to_owned()),
        Some(FUZZ_AVAILABLE_KIB),
    );
});
