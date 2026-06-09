//! Linux platform backends for [`crate::HardwareKeyStore`].
//!
//! Two real backends, each behind an opt-in cargo feature, runtime-selected by
//! [`select_linux_backend`] following the policy of `architecture.md` §6.2
//! (TPM2 first, then `SecretService`, then refuse unless software is allowed):
//!
//! - [`tpm2::Tpm2KeyStore`] (feature `tpm2`) — seals slot material in a TPM 2.0
//!   sealed `KEYEDHASH` object under the SRK (§6.4). The first choice.
//! - [`secret_service::SecretServiceKeyStore`] (feature `secret-service`) —
//!   stores slot material in the session keyring over D-Bus
//!   `org.freedesktop.secrets`. The documented weaker fallback: no hardware
//!   dictionary-attack lockout (§6.2).
//!
//! Both backends use `PlatformCtx = ()`: each self-manages its TPM context /
//! D-Bus connection, and the desktop shell injects no handle (an approved
//! refinement of §6.5).
//!
//! With no backend feature enabled this module is empty — the default build
//! pulls in neither `keyring` nor `tss-esapi` and is byte-for-byte unchanged.

#[cfg(feature = "secret-service")]
pub mod secret_service;

#[cfg(all(target_os = "linux", feature = "tpm2"))]
pub mod tpm2;

// `select` defines the `LinuxKeyStore` enum and `select_linux_backend`. It is
// always compiled on Linux (even with no backend feature) so the selection
// entry point exists and can render the "no acceptable backend" guidance; the
// enum's variants are themselves feature-gated.
mod select;

pub use select::{select_linux_backend, LinuxKeyStore};

#[cfg(feature = "secret-service")]
pub use secret_service::SecretServiceKeyStore;

#[cfg(all(target_os = "linux", feature = "tpm2"))]
pub use tpm2::Tpm2KeyStore;
