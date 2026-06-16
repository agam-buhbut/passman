//! The [`HardwareKeyStore`] trait — the backend-agnostic key-storage contract.
//!
//! Two independent slots ([`HsmSlot`]), a two-phase unwrap so
//! [`HardwareKeyStore::complete_unwrap`] can drive a native biometric prompt at
//! the moment the key is released, and an associated [`HardwareKeyStore::PlatformCtx`]
//! that stays **Rust-internal** and never crosses the `UniFFI` boundary (§6.5).
//!
//! `passman-core` maps the [`HsmError`] taxonomy exactly as in §4.3 (see
//! [`crate::HsmError`]).

use passman_crypto::SecretBytes;

use crate::blob::WrappedBlob;
use crate::capabilities::{HsmCapabilities, HsmLockoutStatus};
use crate::error::HsmError;
use crate::handle::UnwrapHandle;
use crate::prompt::BiometricPrompter;
use crate::slot::{HsmKind, HsmSlot};

/// A hardware-backed key store: wraps slot key material under a
/// device-held key and unwraps it in two phases.
///
/// Implementors are `Send + Sync` so a single store can be shared. The
/// associated [`Self::PlatformCtx`] (`?Sized`) is the platform handle the
/// operation runs against (`&TctiContext`, `HWND`, `&JObject`, `()`, …); it is
/// Rust-internal only and is constructed inside the binding crate (§6.5).
pub trait HardwareKeyStore: Send + Sync {
    /// The platform handle this backend operates against. Rust-internal only;
    /// never appears on the `UniFFI` surface (§6.5).
    type PlatformCtx: ?Sized;

    /// Which backend this is (drives the wrap-blob `hsm_kind` byte and UX copy).
    fn kind(&self) -> HsmKind;

    /// What this backend can do, for UX messaging (§4.9).
    fn capabilities(&self) -> HsmCapabilities;

    /// Query the backend's *current* native dictionary-attack lockout state
    /// (`architecture.md` §4.3 step 3). `passman-core` calls this before the
    /// unwraps; a [`HsmLockoutStatus::LockedOut`] short-circuits the unlock so
    /// the UI never fires a biometric prompt against an already-locked device.
    ///
    /// The default returns [`HsmLockoutStatus::Available`]: a backend with no
    /// cheaply-queryable counter (the software mock, the `SecretService`
    /// fallback, Android — whose lockout surfaces only as a prompt error, and
    /// the no-PIN TPM2 object) inherits it. That is **not** a hole in the
    /// security model: a real lockout still fails the unlock closed via the
    /// unwrap error path (e.g. TPM2 maps `TPM_RC_LOCKOUT` to
    /// [`HsmError::Transient`]). Only a backend that can pre-query its DA
    /// counter cheaply and reliably should override this.
    ///
    /// # Errors
    ///
    /// Returns an [`HsmError`] only if the *query itself* fails (e.g.
    /// [`HsmError::HardwareAbsent`]); a successful query of a locked device
    /// returns `Ok(LockedOut { .. })`. `passman-core` treats a query *error* as
    /// non-fatal (the unwrap path still fails closed on a real lockout).
    fn lockout_status(
        &self,
        ctx: &Self::PlatformCtx,
    ) -> Result<HsmLockoutStatus, HsmError> {
        let _ = ctx;
        Ok(HsmLockoutStatus::Available)
    }

    /// Wrap `material` for `slot`, returning an opaque [`WrappedBlob`].
    ///
    /// Takes a `prompter` because on Android per-use auth gates the encrypt
    /// path too, so enrollment itself fires a biometric prompt (§6.4).
    ///
    /// # Errors
    ///
    /// Returns an [`HsmError`]: [`HsmError::Cancelled`] if the user dismisses
    /// the prompt, [`HsmError::Transient`] for a retryable failure,
    /// [`HsmError::HardwareAbsent`] if no backend is available, or
    /// [`HsmError::Backend`] for a backend-specific failure. Never yields a
    /// blob if the prompt was cancelled.
    fn enroll(
        &self,
        slot: HsmSlot,
        material: &SecretBytes,
        ctx: &Self::PlatformCtx,
        prompter: &dyn BiometricPrompter,
    ) -> Result<WrappedBlob, HsmError>;

    /// Begin unwrapping `wrapped` for `slot`: validate the blob and open any
    /// transient session, returning an [`UnwrapHandle`] for phase two.
    ///
    /// No biometric prompt fires here; the prompt is in
    /// [`Self::complete_unwrap`] so the UI can sequence both slots first (§4.3).
    ///
    /// # Errors
    ///
    /// Returns [`HsmError::MalformedBlob`] if the blob is not valid for this
    /// backend/slot, or another [`HsmError`] for a session-open failure.
    fn begin_unwrap(
        &self,
        slot: HsmSlot,
        wrapped: &WrappedBlob,
        ctx: &Self::PlatformCtx,
    ) -> Result<UnwrapHandle, HsmError>;

    /// Complete the unwrap begun by [`Self::begin_unwrap`], driving the
    /// biometric/PIN prompt and returning the recovered material.
    ///
    /// Consumes `handle` (single-use). Dropping a handle instead cleans up the
    /// session without releasing material.
    ///
    /// # Errors
    ///
    /// Returns [`HsmError::Cancelled`] if the user dismisses the prompt (no
    /// material is yielded), [`HsmError::Transient`] for a retryable failure,
    /// [`HsmError::PermanentlyInvalidated`] if the key is gone, or
    /// [`HsmError::Backend`] on a decrypt/verification failure.
    fn complete_unwrap(
        &self,
        handle: UnwrapHandle,
        prompter: &dyn BiometricPrompter,
    ) -> Result<SecretBytes, HsmError>;

    /// Invalidate (destroy) the wrapping key for `slot`.
    ///
    /// Used as the last step of rotation (§6.6), after the new vault header is
    /// durably written.
    ///
    /// # Errors
    ///
    /// Returns an [`HsmError`] if the backend could not destroy the key.
    fn invalidate(
        &self,
        slot: HsmSlot,
        wrapped: &WrappedBlob,
        ctx: &Self::PlatformCtx,
    ) -> Result<(), HsmError>;
}
