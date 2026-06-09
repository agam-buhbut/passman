//! Slot and backend-kind enumerations.
//!
//! There are exactly two wrapped slots (`architecture.md` §1.6): the vault key
//! `K_hsm` ([`HsmSlot::VaultKey`]) and the TOTP seed `S` ([`HsmSlot::TotpSeed`]),
//! each an independent wrap blob so the seed does not free-ride on the
//! vault-key unwrap.
//!
//! [`HsmKind`] identifies which backend produced a wrap blob; its byte values
//! are part of the on-disk wire format (§6.3) and must remain stable.

use crate::error::HsmError;

/// Which of the two independent HSM-wrapped slots a key belongs to.
///
/// The slot is bound into the wrap (e.g. via AEAD associated data) so a
/// `VaultKey` blob can never be unwrapped as a `TotpSeed` and vice versa.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HsmSlot {
    /// The vault key `K_hsm` — the hardware-held cryptographic factor.
    VaultKey,
    /// The TOTP seed `S`, in its own slot (§1.6).
    TotpSeed,
}

impl HsmSlot {
    /// The single-byte domain tag for this slot, used in wrap-payload binding.
    ///
    /// This is *not* the same namespace as [`HsmKind`] wire bytes; it identifies
    /// the slot within a backend payload.
    #[must_use]
    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::VaultKey => 0x00,
            Self::TotpSeed => 0x01,
        }
    }
}

/// The hardware backend that produced a [`crate::WrappedBlob`].
///
/// The discriminant byte values are fixed by the wire format (§6.3) and must
/// not change: changing one would silently re-interpret existing on-disk blobs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HsmKind {
    /// TPM 2.0 (Linux), wire byte `0x00`.
    Tpm2,
    /// Windows `NCrypt` `RSA-OAEP` (Platform Crypto Provider), wire byte `0x01`.
    NCryptRsa,
    /// Android hardware Keystore `AES-256-GCM`, wire byte `0x02`.
    AndroidGcm,
    /// Apple Secure Enclave (deferred), wire byte `0x03`.
    SecureEnclave,
    /// Linux `SecretService` keyring fallback, wire byte `0x04`.
    SecretService,
    /// In-memory software mock (test/dev only — no hardware protection), wire
    /// byte `0xFF`.
    SoftwareMock,
}

impl HsmKind {
    /// The wire byte for this kind, as written in the wrap-blob header (§6.3).
    #[must_use]
    pub const fn to_byte(self) -> u8 {
        match self {
            Self::Tpm2 => 0x00,
            Self::NCryptRsa => 0x01,
            Self::AndroidGcm => 0x02,
            Self::SecureEnclave => 0x03,
            Self::SecretService => 0x04,
            Self::SoftwareMock => 0xFF,
        }
    }

    /// Map a wire byte to its [`HsmKind`].
    ///
    /// # Errors
    ///
    /// Returns [`HsmError::MalformedBlob`] for any byte that is not a defined
    /// kind, so an attacker-controlled blob cannot smuggle an unknown backend.
    pub const fn from_byte(byte: u8) -> Result<Self, HsmError> {
        match byte {
            0x00 => Ok(Self::Tpm2),
            0x01 => Ok(Self::NCryptRsa),
            0x02 => Ok(Self::AndroidGcm),
            0x03 => Ok(Self::SecureEnclave),
            0x04 => Ok(Self::SecretService),
            0xFF => Ok(Self::SoftwareMock),
            _ => Err(HsmError::MalformedBlob {
                reason: "unknown hsm_kind byte",
            }),
        }
    }
}
