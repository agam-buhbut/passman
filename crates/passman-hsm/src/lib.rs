//! `passman-hsm` — hardware-backed key storage abstraction.
//!
//! Defines the [`HardwareKeyStore`] trait (two independent slots, two-phase
//! unwrap with a biometric prompt), the opaque wrap-blob outer format
//! (`architecture.md` §6.3), and the supporting error/capability types. A
//! feature-gated software [`mock`] backend simulates wrap/unwrap for testing
//! `passman-core` without real hardware.
//!
//! Unlike the pure crates, this crate is *not* `#![forbid(unsafe_code)]`: the
//! real platform backends (TPM2, `NCrypt`, Android Keystore — added separately)
//! require FFI. Unsafe is confined to those backend modules; the trait, the
//! wire format, and the mock contain none.
//!
//! # Modules
//!
//! - [`store`] — the [`HardwareKeyStore`] trait.
//! - [`slot`] — [`HsmSlot`] (the two slots) and [`HsmKind`] (backend ids).
//! - [`blob`] — the opaque [`WrappedBlob`] outer format (§6.3).
//! - [`handle`] — the opaque, zeroizing [`UnwrapHandle`].
//! - [`prompt`] — the [`BiometricPrompter`] callback and [`PromptResult`].
//! - [`capabilities`] — [`HsmCapabilities`] / [`LockoutRecovery`].
//! - [`error`] — the [`HsmError`] taxonomy.
//! - [`mock`] — feature-gated software backend (test/dev only).
//! - [`linux`] — feature-gated Linux backends (TPM2, `SecretService`); present
//!   only on Linux and only when a backend feature is enabled.

// With *no* backend feature enabled, the trait and the `UnwrapHandle`/`HsmSlot`
// plumbing exist but have no constructor or consumer (every backend — the mock
// and the Linux backends — is feature-gated). That is expected scaffolding, not
// genuinely-unused code, so suppress `dead_code` only in the no-backend
// configuration. When any backend feature is on, the lint is fully active.
#![cfg_attr(
    not(any(
        feature = "mock",
        feature = "secret-service",
        feature = "tpm2",
        feature = "android-keystore"
    )),
    allow(dead_code)
)]

pub mod blob;
pub mod capabilities;
pub mod error;
pub mod handle;
pub mod prompt;
pub mod slot;
pub mod store;

#[cfg(feature = "mock")]
pub mod mock;

// Android hardware-Keystore backend (wire 0x02, §6.4). Pure-Rust orchestration
// over a foreign KeystoreWrapper; gated on the `android-keystore` feature so the
// default build is unaffected. Compiles on any host (no platform APIs here).
#[cfg(feature = "android-keystore")]
pub mod android;

// Linux platform backends. All submodules are feature-gated inside `linux`, so
// the module is empty (and harmless) on a default Linux build with no backend
// feature; it does not exist at all on non-Linux targets.
#[cfg(target_os = "linux")]
pub mod linux;

pub use blob::WrappedBlob;
pub use capabilities::{HsmCapabilities, HsmLockoutStatus, LockoutRecovery};
pub use error::HsmError;
pub use handle::UnwrapHandle;
pub use prompt::{BiometricPrompter, PromptResult};
pub use slot::{HsmKind, HsmSlot};
pub use store::HardwareKeyStore;

#[cfg(feature = "android-keystore")]
pub use android::{
    AndroidKeyStore, KeystoreError, KeystoreSecurityLevel, KeystoreWrapper, WrappedParts,
};
