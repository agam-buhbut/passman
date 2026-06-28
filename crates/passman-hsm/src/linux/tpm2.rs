//! Linux TPM 2.0 backend (feature `tpm2`).
//!
//! # Build & verification
//!
//! This module links against the system TSS 2.0 libraries via `tss-esapi` 7
//! (`libtss2-dev` + `pkg-config` at build time; the pregenerated `tss-esapi-sys`
//! bindings cover the installed TSS2 release, so no `bindgen`/`clang` is needed).
//! The enroll → unwrap round-trip, the per-slot in-seal binding, and the §4.3
//! error routing are verified against an isolated `swtpm` (see the tests at the
//! bottom of this file). The whole module is gated
//! `#[cfg(all(target_os = "linux", feature = "tpm2"))]`, so with the feature off
//! it can never affect any other build configuration.
//!
//! # What it does (§6.4)
//!
//! Slot material (the 32-byte `K_hsm` or TOTP seed `S`), prefixed with a 1-byte
//! slot tag, is sealed into a TPM `KEYEDHASH` sealed-data object under the
//! Storage Root Key (SRK) at the persistent handle `0x81000001`. The wrapped
//! blob holds the marshalled public and private portions of that object plus
//! the enrollment uuid; the sealing key never leaves the TPM. The slot tag is
//! covered by the sealed-object integrity, so a blob presented for the wrong
//! slot is rejected on unseal (parity with the mock/SecretService slot binding).
//!
//! - **PCR policy:** off by default (§6.4, D19) — binding to PCR[0,2,4,7] would
//!   brick the slot on firmware/bootloader updates. The payload records
//!   `pcr_policy_present = 0x00` for forward compatibility.
//! - **authValue PIN:** off by default (§6.4). When absent there is no TPM
//!   dictionary-attack counter on this object, so [`HsmCapabilities`] reports
//!   `max_attempts_before_lockout = None`; a future PIN would flip that to
//!   `Some(..)`.
//!
//! # Bus confidentiality (null session — accepted residual)
//!
//! Both the seal (`create` in [`enroll`](Tpm2KeyStore::enroll)) and the unseal
//! (in [`complete_unwrap`](Tpm2KeyStore::complete_unwrap)) run under
//! `execute_with_nullauth_session`, i.e. a **NULL (unsalted, non-encrypting)**
//! session. A NULL session neither salts the session key nor sets the
//! `TPMA_SESSION` decrypt/encrypt attributes, so the sensitive `create`
//! parameter (the `slot_tag ‖ secret` being sealed) and the `unseal` response
//! (that same secret) cross the TPM command bus **in cleartext**. An attacker
//! who can *passively* sniff the physical bus (LPC/SPI/I²C between CPU and TPM)
//! could therefore recover the slot secret. This is an **accepted residual**:
//! the threat model's primary adversary does not have physical bus access, and
//! an attacker who does already has stronger avenues against a powered device.
//!
//! Upgrade path (deferred — needs real-hardware validation): replace the NULL
//! session with a **salted, SRK-bound HMAC session** that carries
//! `TPMA_SESSION` *decrypt* on the sensitive-data `create` parameter and
//! *encrypt* on the `unseal` response. Those attributes encrypt the sensitive
//! parameters to a session key derived against the TPM (the salt is sealed to
//! the SRK), closing the passive-sniff gap without any change to the on-disk
//! blob format.
//!
//! # `PlatformCtx`
//!
//! `()` — the backend opens its own [`Context`] per operation (an approved §6.5
//! refinement). It targets `/dev/tpmrm0` (the in-kernel resource manager) by
//! default, or whatever `TctiNameConf::from_environment_variable` resolves
//! (`TPM2TOOLS_TCTI` / `TCTI`) so CI can point it at a `swtpm`.
//!
//! # Two-phase unwrap and `Send`
//!
//! A [`Context`] holds raw FFI pointers and is not `Send`, but [`UnwrapHandle`]
//! must be `Send`. So the phases do **not** share a live TPM context or
//! transient handle: [`begin_unwrap`](Tpm2KeyStore::begin_unwrap) only parses
//! the blob into plain bytes (which are `Send`), and
//! [`complete_unwrap`](Tpm2KeyStore::complete_unwrap) opens a fresh context,
//! loads the object under the SRK, unseals, and flushes. This is sound because
//! the Linux TPM2 path has no biometric prompt to interleave between the phases
//! (authorisation, if any, is the optional authValue PIN), so nothing is lost
//! by deferring all TPM work to phase two.

use std::convert::TryFrom;
use std::path::Path;
use std::str::FromStr;

use passman_crypto::SecretBytes;
use tss_esapi::{
    attributes::ObjectAttributesBuilder,
    handles::{KeyHandle, ObjectHandle, PersistentTpmHandle, TpmHandle},
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        dynamic_handles::Persistent,
        key_bits::RsaKeyBits,
        resource_handles::{Hierarchy, Provision},
    },
    structures::{
        CreateKeyResult, Digest, KeyedHashScheme, Private, Public, PublicBuilder, PublicKeyRsa,
        PublicKeyedHashParameters, PublicRsaParametersBuilder, RsaExponent, RsaScheme,
        SensitiveData, SymmetricDefinitionObject,
    },
    traits::{Marshall, UnMarshall},
    Context, TctiNameConf, WrapperErrorKind,
};

use crate::blob::WrappedBlob;
use crate::capabilities::{HsmCapabilities, LockoutRecovery};
use crate::error::HsmError;
use crate::handle::UnwrapHandle;
use crate::prompt::BiometricPrompter;
use crate::slot::{HsmKind, HsmSlot};
use crate::store::HardwareKeyStore;

/// The persistent handle of the SRK (standard TCG owner-hierarchy SRK, §6.4).
const SRK_PERSISTENT_HANDLE: u32 = 0x8100_0001;

/// The default TPM device the in-kernel resource manager exposes. Probed for
/// existence before attempting to open a context.
const TPM_RM_DEVICE: &str = "/dev/tpmrm0";

/// `pcr_policy_present` byte for a slot sealed with no PCR policy (§6.4, D19).
const PCR_POLICY_ABSENT: u8 = 0x00;

/// Length of the enrollment uuid in the payload (§6.4).
const UUID_LEN: usize = 16;

/// Lockout-cooldown advertised when (some day) an authValue PIN is set. The
/// default no-PIN object has no DA counter, so this is only used to populate
/// [`LockoutRecovery::TimeBased`] in `capabilities`; the actual reset interval
/// is the TPM's owner-configured `newMaxTries`/`recoveryTime`, which we cannot
/// read cheaply here, so we advertise a conservative placeholder.
const DA_RESET_PLACEHOLDER_SECS: u64 = 24 * 60 * 60;

/// A TPM 2.0 sealed-object key store.
///
/// Stateless: each operation opens its own [`Context`]. See the
/// [module docs](self) for the sealing scheme and the unverified-build caveat.
#[derive(Debug, Default)]
pub struct Tpm2KeyStore {
    _private: (),
}

impl Tpm2KeyStore {
    /// Construct a TPM2 backend, eagerly checking that a context can be opened.
    ///
    /// # Errors
    ///
    /// Returns [`HsmError::HardwareAbsent`] if no TPM context can be opened
    /// (no device, resource manager unavailable, and no TCTI env override).
    pub fn new() -> Result<Self, HsmError> {
        // Open and immediately drop a context to fail fast if the TPM is absent.
        let _ctx = open_context()?;
        Ok(Self { _private: () })
    }

    /// Cheap availability probe used by `select_linux_backend` (§6.2).
    ///
    /// True when the resource-manager device exists *or* a TCTI environment
    /// variable is set (swtpm/mssim) *and* a context actually opens.
    #[must_use]
    pub fn is_available() -> bool {
        let env_tcti = std::env::var_os("TPM2TOOLS_TCTI").is_some()
            || std::env::var_os("TCTI").is_some()
            || std::env::var_os("TPM2_TCTI").is_some();
        if !env_tcti && !Path::new(TPM_RM_DEVICE).exists() {
            return false;
        }
        open_context().is_ok()
    }
}

impl HardwareKeyStore for Tpm2KeyStore {
    type PlatformCtx = ();

    fn kind(&self) -> HsmKind {
        HsmKind::Tpm2
    }

    fn capabilities(&self) -> HsmCapabilities {
        // No biometric (TPM auth is a PIN/policy, not a fingerprint), not a
        // discrete StrongBox, and PCR binding is off by default (D19). With no
        // authValue PIN there is no per-object DA counter, so the attempt limit
        // is `None`; a future PIN would set it. Lockout, when a PIN is set, is
        // time-based (TPM DA cooldown). A distinct per-slot PIN *is* supported
        // by the backend design (the optional TOTP-seed PIN of §1.6), even
        // though it is off by default.
        HsmCapabilities {
            biometric_supported: false,
            strongbox_backed: false,
            pcr_bound: false,
            max_attempts_before_lockout: None,
            lockout_recovery: LockoutRecovery::TimeBased {
                reset_after: std::time::Duration::from_secs(DA_RESET_PLACEHOLDER_SECS),
            },
            supports_distinct_slot_pin: true,
        }
    }

    fn enroll(
        &self,
        slot: HsmSlot,
        material: &SecretBytes,
        _ctx: &Self::PlatformCtx,
        _prompter: &dyn BiometricPrompter,
    ) -> Result<WrappedBlob, HsmError> {
        // No prompt on Linux TPM2 (no biometric); §6.4.
        let mut context = open_context()?;

        // Seal `slot_tag ‖ secret` under the SRK as a no-auth, no-PCR KEYEDHASH
        // object. The leading slot tag is covered by the TPM sealed-object
        // integrity, so `complete_unwrap` can cryptographically reject a blob
        // presented for the wrong slot (§6.4) — parity with the slot binding the
        // mock (AEAD AD) and SecretService (entry name) backends provide.
        let mut to_seal = Vec::with_capacity(1 + material.expose().len());
        to_seal.push(slot.tag());
        to_seal.extend_from_slice(material.expose());
        let sensitive = SensitiveData::try_from(to_seal)
            .map_err(|_| HsmError::Backend("secret too large to seal".to_owned()))?;
        let sealed_public = build_sealed_object_public()?;

        // `move` so the (single-use) closure takes ownership of `sealed_public`
        // and `sensitive` — no clone of the sensitive material is made.
        // NULL session: the sensitive `create` parameter is not bus-encrypted —
        // see "Bus confidentiality" in the module docs (accepted residual).
        let create_result: CreateKeyResult = context
            .execute_with_nullauth_session(move |ctx| {
                let srk = ensure_srk(ctx)?;
                ctx.create(srk, sealed_public, None, Some(sensitive), None, None)
            })
            .map_err(map_tpm_error)?;

        // Marshal the object. `Public::marshall` serialises the TPMT_PUBLIC
        // public area; `Private` is a length-checked buffer whose `value()` is
        // the TPM2B_PRIVATE contents. These are symmetric with the unmarshalling
        // in `complete_unwrap`, which is all the round-trip requires.
        let pub_bytes = create_result.out_public.marshall().map_err(map_tpm_error)?;
        let priv_bytes = create_result.out_private.value().to_vec();

        let mut uuid = [0u8; UUID_LEN];
        passman_crypto::fill_random(&mut uuid);

        let payload = encode_payload(&uuid, &pub_bytes, &priv_bytes)?;
        WrappedBlob::from_parts(HsmKind::Tpm2, payload)
    }

    fn begin_unwrap(
        &self,
        slot: HsmSlot,
        wrapped: &WrappedBlob,
        _ctx: &Self::PlatformCtx,
    ) -> Result<UnwrapHandle, HsmError> {
        if wrapped.kind() != HsmKind::Tpm2 {
            return Err(HsmError::MalformedBlob {
                reason: "blob kind is not Tpm2",
            });
        }
        // Parse only — no TPM context here (the context is !Send and a biometric
        // prompt never interleaves on Linux). The TPM load+unseal happens in
        // `complete_unwrap`, which also checks the unsealed slot tag against the
        // `expected_tag` recorded here.
        let parsed = decode_payload(wrapped.payload())?;
        Ok(UnwrapHandle::for_tpm2(Tpm2UnwrapState {
            public: parsed.public,
            private: parsed.private,
            expected_tag: slot.tag(),
        }))
    }

    fn complete_unwrap(
        &self,
        handle: UnwrapHandle,
        _prompter: &dyn BiometricPrompter,
    ) -> Result<SecretBytes, HsmError> {
        // No prompt on Linux TPM2; §6.4.
        let state = handle.into_tpm2()?;

        let public = Public::unmarshall(&state.public).map_err(map_tpm_error)?;
        let private = Private::try_from(state.private).map_err(|_| HsmError::MalformedBlob {
            reason: "TPM2 private blob too large",
        })?;

        let mut context = open_context()?;
        // `move` so the single-use closure owns `public`/`private` (neither is
        // secret on its own — the private blob is encrypted to the TPM). The
        // closure returns the unsealed `slot_tag ‖ secret`; the slot check is
        // done outside so it surfaces as an `HsmError`, not a `tss_esapi::Error`.
        // NULL session: the `unseal` response is not bus-encrypted — see "Bus
        // confidentiality" in the module docs (accepted residual).
        let sealed: SecretBytes = context
            .execute_with_nullauth_session(move |ctx| {
                let srk = ensure_srk(ctx)?;
                let object: KeyHandle = ctx.load(srk, private, public)?;
                let object_handle = ObjectHandle::from(object);
                let unsealed = ctx.unseal(object_handle);
                // Flush the transient object regardless of unseal outcome so we
                // do not leak a TPM object slot; the flush result is intentionally
                // discarded (the unseal outcome below is what we report).
                let _ = ctx.flush_context(object_handle);
                let data = unsealed?;
                Ok::<SecretBytes, tss_esapi::Error>(SecretBytes::new(data.value().to_vec()))
            })
            .map_err(map_tpm_error)?;

        // Verify the TPM-integrity-protected slot tag and strip it. A blob sealed
        // for a different slot fails here instead of yielding the wrong secret —
        // the cryptographic enforcement of the `HsmSlot` binding invariant.
        let bytes = sealed.expose();
        let (&tag, secret) = bytes.split_first().ok_or(HsmError::MalformedBlob {
            reason: "TPM2 unsealed data is empty (missing slot tag)",
        })?;
        if tag != state.expected_tag {
            return Err(HsmError::MalformedBlob {
                reason: "TPM2 sealed slot tag does not match the requested slot",
            });
        }
        Ok(SecretBytes::new(secret.to_vec()))
    }

    fn invalidate(
        &self,
        _slot: HsmSlot,
        wrapped: &WrappedBlob,
        _ctx: &Self::PlatformCtx,
    ) -> Result<(), HsmError> {
        // The sealed object lives entirely inside the wrap blob (it is loaded
        // transiently each unwrap and never persisted), so there is no
        // per-slot persistent TPM object to evict — destroying the blob (the
        // vault rewrite, §6.6) is what invalidates the slot. The shared SRK at
        // 0x81000001 is deliberately *not* evicted here: it is a long-lived
        // primary that other slots (and re-enrollment) depend on, and evicting
        // it would strand every other sealed object.
        //
        // We still validate the blob kind so a caller passing the wrong blob
        // gets a clear error rather than a silent success.
        if wrapped.kind() != HsmKind::Tpm2 {
            return Err(HsmError::MalformedBlob {
                reason: "blob kind is not Tpm2",
            });
        }
        Ok(())
    }
}

/// Open a TPM [`Context`], preferring an env-configured TCTI (so CI can target
/// a `swtpm`) and otherwise the in-kernel resource manager at `/dev/tpmrm0`.
fn open_context() -> Result<Context, HsmError> {
    // `from_environment_variable` reads TPM2TOOLS_TCTI / TCTI and friends; if
    // unset it errors, in which case fall back to the resource-manager device
    // via the `device:<path>` TCTI string (TctiNameConf implements FromStr).
    let tcti = TctiNameConf::from_environment_variable()
        .or_else(|_| TctiNameConf::from_str(&format!("device:{TPM_RM_DEVICE}")))
        .map_err(|_| HsmError::HardwareAbsent)?;
    Context::new(tcti).map_err(|_| HsmError::HardwareAbsent)
}

/// Ensure the SRK exists at the persistent handle and return a usable
/// [`KeyHandle`] for it, creating + persisting it if absent.
///
/// Must be called inside an `execute_with_nullauth_session` closure (it uses the
/// session for `create_primary`/`evict_control`).
fn ensure_srk(ctx: &mut Context) -> Result<KeyHandle, tss_esapi::Error> {
    // `SRK_PERSISTENT_HANDLE` (0x81000001) is a valid persistent-handle constant
    // by construction; `new` only rejects out-of-range values. Map the (dead)
    // error path rather than `expect`, to honour the no-panic-outside-tests rule.
    let persistent = PersistentTpmHandle::new(SRK_PERSISTENT_HANDLE)
        .map_err(|_| tss_esapi::Error::WrapperError(WrapperErrorKind::InvalidParam))?;
    let tpm_handle = TpmHandle::Persistent(persistent);

    // If the SRK is already persisted, get a transient ESYS handle for it.
    if let Ok(existing) = ctx.tr_from_tpm_public(tpm_handle) {
        return Ok(KeyHandle::from(existing));
    }

    // Otherwise create the primary under the owner hierarchy and persist it.
    let srk_public = build_srk_public().map_err(tss_esapi_from_hsm)?;
    let primary = ctx.create_primary(Hierarchy::Owner, srk_public, None, None, None, None)?;

    // Persist at 0x81000001. If another process raced us and the handle is now
    // in use, recover by reading the existing object instead of failing.
    if ctx
        .evict_control(
            Provision::Owner,
            primary.key_handle.into(),
            Persistent::Persistent(persistent),
        )
        .is_ok()
    {
        Ok(primary.key_handle)
    } else {
        // Raced: flush the transient primary we just made (the persistent one is
        // what we will use) and read back the persisted handle.
        let _ = ctx.flush_context(primary.key_handle.into());
        let existing = ctx.tr_from_tpm_public(tpm_handle)?;
        Ok(KeyHandle::from(existing))
    }
}

/// Build the standard TCG SRK template: a restricted RSA-2048 storage (decrypt)
/// primary with an AES-128-CFB child-protection scheme, fixed to the TPM and
/// parent, no auth value, sensitive-data origin in the TPM.
fn build_srk_public() -> Result<Public, HsmError> {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_restricted(true)
        .with_decrypt(true)
        .with_sign_encrypt(false)
        .with_st_clear(false)
        .with_admin_with_policy(false)
        .with_no_da(false)
        .build()
        .map_err(map_tpm_error)?;

    let rsa_params = PublicRsaParametersBuilder::new()
        .with_symmetric(SymmetricDefinitionObject::AES_128_CFB)
        // A storage (decrypt-restricted) parent uses the NULL asymmetric scheme;
        // the symmetric definition above is what protects its children.
        .with_scheme(RsaScheme::Null)
        .with_key_bits(RsaKeyBits::Rsa2048)
        .with_exponent(RsaExponent::default())
        .with_is_signing_key(false)
        .with_is_decryption_key(true)
        .with_restricted(true)
        .build()
        .map_err(map_tpm_error)?;

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Rsa)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_rsa_parameters(rsa_params)
        .with_rsa_unique_identifier(PublicKeyRsa::default())
        .build()
        .map_err(map_tpm_error)
}

/// Build the [`Public`] template for the sealed KEYEDHASH data object: a
/// non-restricted KEYEDHASH with a NULL scheme (a pure sealed-data object —
/// not signing, not deriving), `userWithAuth`, no sign/decrypt, no PCR policy.
fn build_sealed_object_public() -> Result<Public, HsmError> {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        // The sensitive data is supplied by us (not generated in the TPM), so
        // sensitive-data-origin is false for a sealed-data object.
        .with_sensitive_data_origin(false)
        .with_user_with_auth(true)
        .with_restricted(false)
        .with_decrypt(false)
        .with_sign_encrypt(false)
        .with_st_clear(false)
        .with_admin_with_policy(false)
        .with_no_da(false)
        .build()
        .map_err(map_tpm_error)?;

    // NULL keyed-hash scheme = a sealed data object (no HMAC, no XOR).
    let keyed_hash_params = PublicKeyedHashParameters::new(KeyedHashScheme::Null);

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_keyed_hash_parameters(keyed_hash_params)
        .with_keyed_hash_unique_identifier(Digest::default())
        .build()
        .map_err(map_tpm_error)
}

/// Encode the §6.4 TPM2 payload:
/// `pcr_policy_present(1) ‖ uuid(16) ‖ pub_len(u16-LE) ‖ TPM2B_PUBLIC ‖
///  priv_len(u16-LE) ‖ TPM2B_PRIVATE`.
fn encode_payload(
    uuid: &[u8; UUID_LEN],
    pub_bytes: &[u8],
    priv_bytes: &[u8],
) -> Result<Vec<u8>, HsmError> {
    let pub_len = u16::try_from(pub_bytes.len())
        .map_err(|_| HsmError::Backend("marshalled TPM2B_PUBLIC exceeds u16".to_owned()))?;
    let priv_len = u16::try_from(priv_bytes.len())
        .map_err(|_| HsmError::Backend("marshalled TPM2B_PRIVATE exceeds u16".to_owned()))?;

    let mut payload = Vec::with_capacity(1 + UUID_LEN + 2 + pub_bytes.len() + 2 + priv_bytes.len());
    payload.push(PCR_POLICY_ABSENT);
    payload.extend_from_slice(uuid);
    payload.extend_from_slice(&pub_len.to_le_bytes());
    payload.extend_from_slice(pub_bytes);
    payload.extend_from_slice(&priv_len.to_le_bytes());
    payload.extend_from_slice(priv_bytes);
    Ok(payload)
}

/// The parsed TPM2 payload fields needed to reload the sealed object.
///
/// Holds only TPM wire-format bytes — the public area and the `TPM2B_PRIVATE`,
/// which is encrypted to the TPM and carries no plaintext secret — so deriving
/// `Debug` (used by the codec tests' `expect_err`) leaks nothing sensitive.
#[derive(Debug)]
struct ParsedPayload {
    public: Vec<u8>,
    private: Vec<u8>,
}

/// Parse the §6.4 TPM2 payload. Fully bounds-checked and panic-free (the blob
/// sits on disk and is attacker-controllable): every length is validated
/// against the remaining input, and trailing bytes are rejected.
fn decode_payload(payload: &[u8]) -> Result<ParsedPayload, HsmError> {
    // pcr_policy_present(1) ‖ uuid(16) ‖ pub_len(2) ‖ pub ‖ priv_len(2) ‖ priv
    let mut cursor = payload;

    let (&pcr_present, rest) = cursor.split_first().ok_or(HsmError::MalformedBlob {
        reason: "TPM2 payload missing pcr_policy_present byte",
    })?;
    // Only the no-PCR form is produced/understood today (D19). A set byte means
    // a policy we cannot satisfy here, so reject rather than silently ignore.
    if pcr_present != PCR_POLICY_ABSENT {
        return Err(HsmError::MalformedBlob {
            reason: "TPM2 payload declares a PCR policy this build does not support",
        });
    }
    cursor = rest;

    let (uuid, rest) = cursor
        .split_at_checked(UUID_LEN)
        .ok_or(HsmError::MalformedBlob {
            reason: "TPM2 payload truncated in enrollment uuid",
        })?;
    let _ = uuid; // The uuid is informational here; the blob carries the object.
    cursor = rest;

    let public = read_len_prefixed(&mut cursor, "TPM2B_PUBLIC")?;
    let private = read_len_prefixed(&mut cursor, "TPM2B_PRIVATE")?;

    if !cursor.is_empty() {
        return Err(HsmError::MalformedBlob {
            reason: "trailing bytes after TPM2 payload",
        });
    }

    Ok(ParsedPayload { public, private })
}

/// Read a `u16-LE` length prefix and that many bytes, advancing `cursor`.
fn read_len_prefixed(cursor: &mut &[u8], field: &'static str) -> Result<Vec<u8>, HsmError> {
    let _ = field;
    let (len_bytes, rest) = cursor.split_at_checked(2).ok_or(HsmError::MalformedBlob {
        reason: "TPM2 payload truncated in a length prefix",
    })?;
    let len = usize::from(u16::from_le_bytes([len_bytes[0], len_bytes[1]]));
    let (data, rest) = rest.split_at_checked(len).ok_or(HsmError::MalformedBlob {
        reason: "TPM2 payload length prefix exceeds remaining input",
    })?;
    *cursor = rest;
    Ok(data.to_vec())
}

/// Map a [`tss_esapi::Error`] to the crate [`HsmError`] taxonomy (§4.3 routing).
///
/// The routing principle (§4.3): transient/cancelled never penalise an attempt;
/// a permanently-gone key routes to recovery. For the TPM:
///
/// - A TPM **dictionary-attack lockout** (`TPM_RC_LOCKOUT`), explicit **retry**
///   (`TPM_RC_RETRY`/`TPM_RC_YIELDED`), **NV-rate** throttle, or transient
///   object/session memory pressure → [`HsmError::Transient`]: retrying after
///   the condition clears is appropriate and must not count as a failed attempt.
/// - A **cleared or rotated TPM** surfaces as `TPM_RC_INTEGRITY` when the sealed
///   blob no longer verifies under the SRK → [`HsmError::PermanentlyInvalidated`]:
///   re-enrollment via recovery import is the only path back (§6.6). Only the
///   unambiguous integrity code is routed here; `TPM_RC_HANDLE`/`VALUE` are left
///   as `Backend` so a benign handle hiccup cannot false-trip slot loss.
/// - Everything else → [`HsmError::Backend`] with a fixed, non-secret label.
///   The TPM error's `Display` is a return-code description (never secret
///   material), but to honour the `HsmError` contract strictly we emit only a
///   fixed descriptor and never interpolate it.
///
/// Unrecognised codes (and wrapper-level faults like a marshalling error) map
/// to [`HsmError::Backend`] with a fixed label, so nothing is silently swallowed.
fn map_tpm_error(err: tss_esapi::Error) -> HsmError {
    use tss_esapi::constants::Tss2ResponseCodeKind as Kind;

    // Only a TPM response code carries §4.3-relevant routing; a wrapper-level
    // error (marshalling, invalid param) is a local fault, not a hardware state.
    let kind = match err {
        tss_esapi::Error::Tss2Error(rc) => rc.kind(),
        tss_esapi::Error::WrapperError(_) => None,
    };
    let Some(kind) = kind else {
        return HsmError::Backend("TPM 2.0 backend error".to_owned());
    };

    match kind {
        // Transient — the caller must NOT count these as a failed attempt
        // (§4.3). `Lockout` is the TPM's own dictionary-attack cooldown (the
        // primary anti-hammering control, §4.3); `Retry`/`Yielded` are explicit
        // "try again" codes; `NvRate` is NV write-rate throttling; the
        // memory/context-gap warnings are resource pressure that clears once
        // transient objects/sessions are flushed; `Testing` is the power-on
        // self-test still running.
        Kind::Lockout
        | Kind::Retry
        | Kind::Yielded
        | Kind::NvRate
        | Kind::Testing
        | Kind::ContextGap
        | Kind::Memory
        | Kind::ObjectMemory
        | Kind::SessionMemory
        | Kind::ObjectHandles
        | Kind::SessionHandles => HsmError::Transient,

        // Caller aborted — same no-penalty / no-material contract as a cancelled
        // biometric prompt.
        Kind::Canceled => HsmError::Cancelled,

        // The sealed blob fails integrity under the current SRK: the TPM was
        // cleared or the owner primary rotated, so the wrapping key is gone for
        // good and only a recovery import restores the slot (§4.3, §6.6). We
        // route *only* `Integrity` here — not the more ambiguous `Handle`/`Value`
        // codes — so a benign handle hiccup can never trigger the destructive
        // "slot permanently lost → recovery required" path on a false positive.
        Kind::Integrity => HsmError::PermanentlyInvalidated,

        // Everything else: a fixed, non-secret label. The TPM's own message is
        // only a return-code description (not secret), but the `HsmError`
        // contract forbids interpolating backend strings, so we emit a constant.
        _ => HsmError::Backend("TPM 2.0 backend error".to_owned()),
    }
}

/// Bridge an [`HsmError`] back into a [`tss_esapi::Error`] so helper functions
/// used inside an `execute_with_nullauth_session` closure (which must return
/// `tss_esapi::Error`) can surface a build-time template failure. Only used for
/// the SRK-template construction path, which cannot fail at runtime once built.
fn tss_esapi_from_hsm(_err: HsmError) -> tss_esapi::Error {
    tss_esapi::Error::WrapperError(WrapperErrorKind::InternalError)
}

/// Transient state the TPM2 backend stashes in an [`UnwrapHandle`].
///
/// Holds the marshalled public area and the private blob as plain bytes — these
/// are `Send` (unlike a live [`Context`]/[`KeyHandle`]) so the handle stays
/// `Send`. They are not secret on their own (the private blob is encrypted to
/// the TPM), but are consumed single-use via the handle. The sealed secret is
/// only ever materialised inside `complete_unwrap`'s session and wrapped in a
/// zeroizing [`SecretBytes`] immediately.
pub(crate) struct Tpm2UnwrapState {
    /// Marshalled TPM2 public area (`Public::marshall` output).
    public: Vec<u8>,
    /// `TPM2B_PRIVATE` contents (`Private::value()`).
    private: Vec<u8>,
    /// The slot tag the caller requested this unwrap for. `complete_unwrap`
    /// checks it against the (TPM-integrity-protected) tag prefix recovered from
    /// the sealed object, rejecting a blob minted for a different slot.
    expected_tag: u8,
}

#[cfg(test)]
mod tests {
    //! TPM2 tests run only against an isolated `swtpm` (never `/dev/tpm0`).
    //!
    //! These will **not** run on the development machine (no `libtss2`, so the
    //! `tpm2` feature does not even compile here). They are written so that,
    //! once `libtss2-dev` is installed and `swtpm` is on `PATH`, a CI job can
    //! exercise the full enroll → unwrap → round-trip path against a throwaway
    //! software TPM in a tempdir.

    use super::{
        decode_payload, encode_payload, map_tpm_error, Tpm2KeyStore, PCR_POLICY_ABSENT, UUID_LEN,
    };
    use crate::error::HsmError;
    use crate::slot::HsmSlot;
    use crate::store::HardwareKeyStore;
    use passman_crypto::SecretBytes;
    use std::net::{TcpListener, TcpStream};
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    // --- Pure payload codec tests (no TPM, always compile/run when feature on) ---

    #[test]
    fn payload_round_trips() {
        let uuid = [0x5Au8; UUID_LEN];
        let public = vec![0x01, 0x02, 0x03, 0x04];
        let private = vec![0xAA; 70];
        let payload = encode_payload(&uuid, &public, &private).expect("encode");
        assert_eq!(payload[0], PCR_POLICY_ABSENT);
        let parsed = decode_payload(&payload).expect("decode");
        assert_eq!(parsed.public, public);
        assert_eq!(parsed.private, private);
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let uuid = [0u8; UUID_LEN];
        let mut payload = encode_payload(&uuid, &[1, 2], &[3, 4]).expect("encode");
        payload.push(0xFF);
        let err = decode_payload(&payload).expect_err("trailing must fail");
        assert!(matches!(err, HsmError::MalformedBlob { .. }));
    }

    #[test]
    fn decode_rejects_truncated_length_prefix() {
        // pcr byte + full uuid + a single byte where a 2-byte pub_len is needed.
        let mut payload = vec![PCR_POLICY_ABSENT];
        payload.extend_from_slice(&[0u8; UUID_LEN]);
        payload.push(0x01);
        let err = decode_payload(&payload).expect_err("truncated len must fail");
        assert!(matches!(err, HsmError::MalformedBlob { .. }));
    }

    #[test]
    fn decode_rejects_overlong_length_prefix() {
        let mut payload = vec![PCR_POLICY_ABSENT];
        payload.extend_from_slice(&[0u8; UUID_LEN]);
        payload.extend_from_slice(&10u16.to_le_bytes()); // claims 10 pub bytes
        payload.extend_from_slice(&[0xAB; 2]); // supplies only 2
        let err = decode_payload(&payload).expect_err("overlong len must fail");
        assert!(matches!(err, HsmError::MalformedBlob { .. }));
    }

    #[test]
    fn decode_rejects_unknown_pcr_policy_byte() {
        let mut payload = vec![0x01]; // PCR policy "present" — unsupported here
        payload.extend_from_slice(&[0u8; UUID_LEN]);
        payload.extend_from_slice(&0u16.to_le_bytes());
        payload.extend_from_slice(&0u16.to_le_bytes());
        let err = decode_payload(&payload).expect_err("unknown pcr byte must fail");
        assert!(matches!(err, HsmError::MalformedBlob { .. }));
    }

    #[test]
    fn map_tpm_error_routes_per_section_4_3() {
        use tss_esapi::constants::Tss2ResponseCode;
        // Raw TCG TPM 2.0 response codes (Library Spec Part 2, Table 17). bindgen
        // drops these computed macros, so the spec values are spelled out here;
        // `map_tpm_error` must route them per §4.3 however they were produced.
        let mapped =
            |rc: u32| map_tpm_error(tss_esapi::Error::Tss2Error(Tss2ResponseCode::from(rc)));

        // Transient — must never count as a failed attempt: LOCKOUT, RETRY,
        // YIELDED, NV_RATE, TESTING, and MEMORY/OBJECT_MEMORY/SESSION_MEMORY/
        // CONTEXT_GAP resource pressure.
        for rc in [
            0x921u32, 0x922, 0x908, 0x920, 0x90A, 0x904, 0x902, 0x903, 0x901,
        ] {
            assert!(
                matches!(mapped(rc), HsmError::Transient),
                "rc {rc:#x} should route to Transient"
            );
        }
        // CANCELED — caller aborted.
        assert!(matches!(mapped(0x909), HsmError::Cancelled));
        // INTEGRITY — cleared/rotated TPM; the only permanently-invalidated code.
        assert!(matches!(mapped(0x09F), HsmError::PermanentlyInvalidated));
        // HANDLE, VALUE, FAILURE — deliberately NOT permanent → Backend.
        for rc in [0x08Bu32, 0x084, 0x101] {
            assert!(
                matches!(mapped(rc), HsmError::Backend(_)),
                "rc {rc:#x} should route to Backend"
            );
        }
    }

    // --- swtpm-backed integration test (only with a software TPM available) ---

    /// Find a free TCP port `P` such that both `P` and `P+1` are bindable on
    /// loopback (swtpm needs a data socket at `P` and a control socket at `P+1`,
    /// the mssim-protocol convention the `swtpm`/`mssim` TCTIs assume). Binds to
    /// `:0` to let the OS pick, then confirms the successor port is also free.
    fn find_free_port_pair() -> Option<u16> {
        for _ in 0..128 {
            let probe = TcpListener::bind("127.0.0.1:0").ok()?;
            let port = probe.local_addr().ok()?.port();
            drop(probe);
            if port == u16::MAX {
                continue;
            }
            // Both must bind right now; drop the listeners so swtpm can claim them.
            if TcpListener::bind(("127.0.0.1", port)).is_ok()
                && TcpListener::bind(("127.0.0.1", port + 1)).is_ok()
            {
                return Some(port);
            }
        }
        None
    }

    /// Poll until `port` accepts a TCP connection or a short deadline passes.
    /// This is a subprocess-readiness wait (swtpm needs a beat to bind after
    /// `spawn`), not a fixed synchronization sleep: it returns as soon as the
    /// socket is up, and is bounded so a dead swtpm cannot hang the suite.
    fn wait_for_port(port: u16) -> bool {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        false
    }

    /// An isolated software TPM spawned over loopback TCP in a fresh tempdir.
    /// Kills the process and clears the `TCTI` env var on drop so tests never
    /// touch a real `/dev/tpm*` and leave no global state behind.
    ///
    /// TCP (not a unix socket) because tss-esapi 7's `swtpm`/`mssim` TCTI config
    /// (`NetworkTPMConfig`) models only `host`/`port` — a `path=` conf is
    /// silently dropped to the `localhost:2321` default.
    struct SwtpmHarness {
        child: Child,
        _state_dir: tempfile::TempDir,
    }

    impl SwtpmHarness {
        /// Spawn `swtpm` in TCP `socket` mode. Returns `None` only if `swtpm` is
        /// not installed (legitimate skip). If `swtpm` *is* present but never
        /// becomes reachable, that is a broken test environment, not a reason to
        /// silently pass — so this panics rather than returning `None`.
        fn spawn() -> Option<Self> {
            let have_swtpm = Command::new("swtpm")
                .arg("--version")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|s| s.success());
            if !have_swtpm {
                eprintln!("SKIP TPM2 swtpm test: `swtpm` not found on PATH");
                return None;
            }

            let state_dir = tempfile::tempdir().expect("tempdir");
            let port = find_free_port_pair().expect("no free loopback port pair for swtpm");

            let child = Command::new("swtpm")
                .arg("socket")
                .arg("--tpm2")
                .arg("--tpmstate")
                .arg(format!("dir={}", state_dir.path().display()))
                .arg("--server")
                .arg(format!("type=tcp,port={port},bindaddr=127.0.0.1"))
                .arg("--ctrl")
                .arg(format!("type=tcp,port={},bindaddr=127.0.0.1", port + 1))
                .arg("--flags")
                .arg("not-need-init,startup-clear")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn swtpm");

            // Point tss-esapi's `from_environment_variable` (reads TPM2TOOLS_TCTI,
            // then TCTI, then TEST_TCTI) at this swtpm over TCP.
            std::env::set_var("TCTI", format!("swtpm:host=127.0.0.1,port={port}"));

            let harness = Self {
                child,
                _state_dir: state_dir,
            };
            assert!(
                wait_for_port(port),
                "swtpm present but never opened port {port}"
            );
            Some(harness)
        }
    }

    impl Drop for SwtpmHarness {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
            std::env::remove_var("TCTI");
        }
    }

    struct NoPrompter;
    impl crate::prompt::BiometricPrompter for NoPrompter {
        fn prompt(&self, _reason: String) -> Result<crate::prompt::PromptResult, HsmError> {
            Ok(crate::prompt::PromptResult::Authenticated)
        }
    }

    #[test]
    fn enroll_unwrap_roundtrip_against_swtpm() {
        let Some(_harness) = SwtpmHarness::spawn() else {
            return; // swtpm absent — skip (also the whole feature is off here).
        };

        // swtpm is up (readiness-checked); a context-open failure here is a real
        // bug, so surface it rather than skipping.
        let store = Tpm2KeyStore::new().expect("open swtpm context");

        // NOTE: on a fresh swtpm the first enroll logs a benign
        // `ESYS ... Esys_TR_FromTPMPublic ... ErrorCode (0x...18b)` to stderr —
        // that is `TPM_RC_HANDLE` for the not-yet-persisted SRK, which
        // `ensure_srk` catches and recovers from by creating + persisting it.
        let vault_secret = SecretBytes::new(vec![0x42; 32]);
        let seed_secret = SecretBytes::new(vec![0x17; 32]);

        let vault_blob = store
            .enroll(HsmSlot::VaultKey, &vault_secret, &(), &NoPrompter)
            .expect("enroll VaultKey");
        // The second enroll reuses the now-persisted SRK (no ReadPublic error).
        let seed_blob = store
            .enroll(HsmSlot::TotpSeed, &seed_secret, &(), &NoPrompter)
            .expect("enroll TotpSeed");

        let unwrap = |slot, blob| {
            let handle = store.begin_unwrap(slot, blob, &()).expect("begin_unwrap");
            store.complete_unwrap(handle, &NoPrompter)
        };

        // Each slot round-trips to its own distinct secret.
        assert_eq!(
            unwrap(HsmSlot::VaultKey, &vault_blob)
                .expect("unwrap VaultKey")
                .expose(),
            vault_secret.expose()
        );
        assert_eq!(
            unwrap(HsmSlot::TotpSeed, &seed_blob)
                .expect("unwrap TotpSeed")
                .expose(),
            seed_secret.expose()
        );

        // Cross-slot binding: a VaultKey blob presented as TotpSeed is rejected
        // by the in-seal tag check, not silently unsealed to the vault secret.
        let err = unwrap(HsmSlot::TotpSeed, &vault_blob).expect_err("cross-slot must fail");
        assert!(matches!(err, HsmError::MalformedBlob { .. }), "got {err:?}");

        // Repeatability: the same persisted blob unwraps again to the same secret
        // — passman-core re-unwraps the stored blob on every unlock, so a one-shot
        // load must not be assumed.
        assert_eq!(
            unwrap(HsmSlot::VaultKey, &vault_blob)
                .expect("re-unwrap VaultKey")
                .expose(),
            vault_secret.expose()
        );
    }
}
