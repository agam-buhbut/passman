#![no_main]
//! Coverage-guided fuzzing of the vault binary parser — the #1 attack surface
//! (`architecture.md` §10): attacker-controlled bytes at the vault path. The
//! parser is pure (`&[u8] -> Result`) and the crate is `#![forbid(unsafe_code)]`,
//! so ANY panic, integer overflow, unbounded allocation, or hang on arbitrary
//! input is a bug for the fuzzer to surface.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Must never panic; a malformed file is a clean `Err`, never a crash.
    let _ = passman_vault::Vault::from_bytes(data);
});
