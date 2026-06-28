#![no_main]
//! Coverage-guided fuzzing of the recovery-file parser (`architecture.md` §10):
//! recovery exports are attacker-controlled at rest. `import` parses the binary
//! structure (magic, version, kdf id/params, salt, length-prefixed fields)
//! BEFORE doing any key derivation, so malformed inputs — the attack surface —
//! fail fast in the parser without touching Argon2. Run with `-rss_limit_mb` and
//! `-timeout` so the rare structurally-valid input that reaches the (≥1 GiB,
//! floor-enforced) KDF is bounded rather than hanging the fuzzer.

use libfuzzer_sys::fuzz_target;
use passman_crypto::SecretString;

fuzz_target!(|data: &[u8]| {
    // The password is irrelevant to the structural parse that handles malformed
    // input; a panic on any input is a bug.
    let _ = passman_recovery::import(data, &SecretString::new("fuzz".to_owned()));
});
