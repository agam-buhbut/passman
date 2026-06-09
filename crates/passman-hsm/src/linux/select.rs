//! Runtime selection of the Linux backend (`architecture.md` §6.2).
//!
//! Selection order: **TPM2 first**, then **`SecretService`** (the documented
//! weaker fallback), then **refuse** unless the caller opted into software.
//! Which backends are even *candidates* depends on the compiled feature set:
//! `tpm2` makes the TPM path available, `secret-service` the keyring path.
//!
//! The [`crate::HardwareKeyStore`] trait is not object-safe (it has an
//! associated `PlatformCtx`), so a `Box<dyn HardwareKeyStore>` is impossible.
//! [`LinuxKeyStore`] is the dispatch enum that lets `passman-core` hold "the
//! selected Linux backend" behind one concrete type with `PlatformCtx = ()`.

use passman_crypto::SecretBytes;

use crate::blob::WrappedBlob;
use crate::capabilities::HsmCapabilities;
use crate::error::HsmError;
use crate::handle::UnwrapHandle;
use crate::prompt::BiometricPrompter;
use crate::slot::{HsmKind, HsmSlot};
use crate::store::HardwareKeyStore;

/// The selected Linux hardware-key-store backend.
///
/// One variant per compiled backend feature; with neither feature enabled the
/// enum is uninhabited (no variants) and only [`select_linux_backend`]'s
/// "refuse" path is reachable. Implements [`HardwareKeyStore`] by forwarding to
/// the active variant, so callers treat it as a single backend.
#[derive(Debug)]
pub enum LinuxKeyStore {
    /// TPM 2.0 sealed-object backend (§6.4). The preferred backend.
    #[cfg(all(target_os = "linux", feature = "tpm2"))]
    Tpm2(super::tpm2::Tpm2KeyStore),
    /// `SecretService` keyring fallback (§6.2). Weaker: no hardware DA.
    #[cfg(feature = "secret-service")]
    SecretService(super::secret_service::SecretServiceKeyStore),
}

impl HardwareKeyStore for LinuxKeyStore {
    type PlatformCtx = ();

    fn kind(&self) -> HsmKind {
        match self {
            #[cfg(all(target_os = "linux", feature = "tpm2"))]
            Self::Tpm2(inner) => inner.kind(),
            #[cfg(feature = "secret-service")]
            Self::SecretService(inner) => inner.kind(),
            // With no backend feature compiled in, the enum has no variants and
            // this match is empty; the arm below keeps the code well-formed in
            // that configuration without being reachable.
            #[cfg(not(any(feature = "tpm2", feature = "secret-service")))]
            _ => unreachable!("LinuxKeyStore is uninhabited with no backend feature"),
        }
    }

    fn capabilities(&self) -> HsmCapabilities {
        match self {
            #[cfg(all(target_os = "linux", feature = "tpm2"))]
            Self::Tpm2(inner) => inner.capabilities(),
            #[cfg(feature = "secret-service")]
            Self::SecretService(inner) => inner.capabilities(),
            #[cfg(not(any(feature = "tpm2", feature = "secret-service")))]
            _ => unreachable!("LinuxKeyStore is uninhabited with no backend feature"),
        }
    }

    fn enroll(
        &self,
        slot: HsmSlot,
        material: &SecretBytes,
        ctx: &Self::PlatformCtx,
        prompter: &dyn BiometricPrompter,
    ) -> Result<WrappedBlob, HsmError> {
        match self {
            #[cfg(all(target_os = "linux", feature = "tpm2"))]
            Self::Tpm2(inner) => inner.enroll(slot, material, ctx, prompter),
            #[cfg(feature = "secret-service")]
            Self::SecretService(inner) => inner.enroll(slot, material, ctx, prompter),
            #[cfg(not(any(feature = "tpm2", feature = "secret-service")))]
            _ => {
                let _ = (slot, material, ctx, prompter);
                unreachable!("LinuxKeyStore is uninhabited with no backend feature")
            }
        }
    }

    fn begin_unwrap(
        &self,
        slot: HsmSlot,
        wrapped: &WrappedBlob,
        ctx: &Self::PlatformCtx,
    ) -> Result<UnwrapHandle, HsmError> {
        match self {
            #[cfg(all(target_os = "linux", feature = "tpm2"))]
            Self::Tpm2(inner) => inner.begin_unwrap(slot, wrapped, ctx),
            #[cfg(feature = "secret-service")]
            Self::SecretService(inner) => inner.begin_unwrap(slot, wrapped, ctx),
            #[cfg(not(any(feature = "tpm2", feature = "secret-service")))]
            _ => {
                let _ = (slot, wrapped, ctx);
                unreachable!("LinuxKeyStore is uninhabited with no backend feature")
            }
        }
    }

    fn complete_unwrap(
        &self,
        handle: UnwrapHandle,
        prompter: &dyn BiometricPrompter,
    ) -> Result<SecretBytes, HsmError> {
        match self {
            #[cfg(all(target_os = "linux", feature = "tpm2"))]
            Self::Tpm2(inner) => inner.complete_unwrap(handle, prompter),
            #[cfg(feature = "secret-service")]
            Self::SecretService(inner) => inner.complete_unwrap(handle, prompter),
            #[cfg(not(any(feature = "tpm2", feature = "secret-service")))]
            _ => {
                let _ = (handle, prompter);
                unreachable!("LinuxKeyStore is uninhabited with no backend feature")
            }
        }
    }

    fn invalidate(
        &self,
        slot: HsmSlot,
        wrapped: &WrappedBlob,
        ctx: &Self::PlatformCtx,
    ) -> Result<(), HsmError> {
        match self {
            #[cfg(all(target_os = "linux", feature = "tpm2"))]
            Self::Tpm2(inner) => inner.invalidate(slot, wrapped, ctx),
            #[cfg(feature = "secret-service")]
            Self::SecretService(inner) => inner.invalidate(slot, wrapped, ctx),
            #[cfg(not(any(feature = "tpm2", feature = "secret-service")))]
            _ => {
                let _ = (slot, wrapped, ctx);
                unreachable!("LinuxKeyStore is uninhabited with no backend feature")
            }
        }
    }
}

/// Select the Linux backend per `architecture.md` §6.2.
///
/// Order: a usable TPM 2.0 (when the `tpm2` feature is built) wins; otherwise
/// the `SecretService` keyring (when the `secret-service` feature is built) is
/// used as the documented weaker fallback; otherwise selection refuses.
///
/// `allow_software` reflects the `--allow-software-hsm` opt-in (§6.2). On Linux
/// the only "software" backend is `SecretService` (there is no in-tree software
/// HSM in production — the mock is test-only). Because `SecretService` is the
/// designed fallback rather than a pure-software stand-in, it is offered
/// whenever the feature is present *and* either a TPM is unavailable or the
/// caller has acknowledged a weaker backend. The flag's role here is to gate
/// proceeding with the non-hardware-DA fallback when no TPM is present: if a TPM
/// is absent, `SecretService` is compiled in, but `allow_software` is `false`,
/// selection refuses and guides the user (mirroring the table's "refused unless
/// `--allow-software-hsm`" cell, since the keyring lacks hardware DA).
///
/// # Errors
///
/// - [`HsmError::HardwareAbsent`] if no acceptable backend is available: no
///   usable TPM and either no `SecretService` feature or `allow_software` not
///   granted. The message guides the user toward the opt-in.
/// - [`HsmError::Backend`] if no backend feature was compiled into this binary
///   at all (a build-configuration error rather than a runtime condition).
#[allow(unused_variables)] // `allow_software` is unused when no fallback feature is built.
pub fn select_linux_backend(allow_software: bool) -> Result<LinuxKeyStore, HsmError> {
    // 1. Prefer a usable TPM 2.0. An early return keeps the TPM path independent
    //    of the (cfg-selected) fallback tail below. If a probe says a TPM exists
    //    but opening a context fails, fall through rather than hard-failing, so a
    //    flaky resource manager does not strand the user.
    #[cfg(all(target_os = "linux", feature = "tpm2"))]
    if super::tpm2::Tpm2KeyStore::is_available() {
        if let Ok(store) = super::tpm2::Tpm2KeyStore::new() {
            return Ok(LinuxKeyStore::Tpm2(store));
        }
    }

    // 2. No TPM was selected. The fallback decision is a single tail expression,
    //    chosen by feature set so there is exactly one trailing value (no
    //    cfg-conditional `return` that would be a no-op tail in some configs).
    fallback_after_no_tpm(allow_software)
}

/// Resolve the post-TPM fallback: the `SecretService` keyring (gated on the
/// software opt-in, since it has no hardware DA — §6.2), or a refusal.
///
/// Split out from [`select_linux_backend`] so each feature configuration has a
/// single tail expression. `allow_software` is unused when no fallback feature
/// is compiled.
#[allow(unused_variables, clippy::unnecessary_wraps)]
fn fallback_after_no_tpm(allow_software: bool) -> Result<LinuxKeyStore, HsmError> {
    #[cfg(feature = "secret-service")]
    {
        if allow_software {
            Ok(LinuxKeyStore::SecretService(
                super::secret_service::SecretServiceKeyStore::new(),
            ))
        } else {
            Err(HsmError::HardwareAbsent)
        }
    }

    // No keyring fallback in this binary.
    #[cfg(not(feature = "secret-service"))]
    {
        // `tpm2` built but no TPM usable (we tried above): hardware is absent.
        #[cfg(all(target_os = "linux", feature = "tpm2"))]
        {
            Err(HsmError::HardwareAbsent)
        }
        // Neither backend feature built: a misconfigured binary.
        #[cfg(not(all(target_os = "linux", feature = "tpm2")))]
        {
            Err(HsmError::Backend(
                "no HSM backend compiled in (enable the tpm2 or secret-service feature)".to_owned(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(not(any(feature = "tpm2", feature = "secret-service")))]
    #[test]
    fn refuses_with_no_backend_feature() {
        use super::select_linux_backend;
        use crate::error::HsmError;
        let err = select_linux_backend(true).expect_err("must refuse with no backend");
        assert!(matches!(err, HsmError::Backend(_)));
    }

    // With only `secret-service`: no TPM path, so software must be allowed.
    #[cfg(all(feature = "secret-service", not(feature = "tpm2")))]
    #[test]
    fn secret_service_requires_allow_software() {
        use super::{select_linux_backend, LinuxKeyStore};
        use crate::error::HsmError;
        use crate::slot::HsmKind;
        use crate::store::HardwareKeyStore;

        let err = select_linux_backend(false).expect_err("must refuse without opt-in");
        assert!(matches!(err, HsmError::HardwareAbsent));

        let store = select_linux_backend(true).expect("opt-in selects SecretService");
        match store {
            LinuxKeyStore::SecretService(s) => assert_eq!(s.kind(), HsmKind::SecretService),
            // No other variant exists in this feature combination.
        }
    }
}
