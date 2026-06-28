//! Argon2id password-based key derivation.
//!
//! Derives a 256-bit key from a master password under tunable, deliberately
//! expensive [`KdfParams`]. The parameter struct has a stable 9-byte canonical
//! encoding that downstream crates bind into AEAD associated data, so the
//! encoding must never change for a given format version.

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroize;

use crate::error::CryptoError;
use crate::secret::{SecretArray, SecretString};

/// Length in bytes of the canonical [`KdfParams`] serialization.
pub const KDF_PARAMS_LEN: usize = 9;

/// Length in bytes of a derived key.
const DERIVED_KEY_LEN: usize = 32;

/// Maximum accepted Argon2id memory cost, in KiB (8 GiB).
///
/// Argon2 cost parameters reach this crate from attacker-controllable on-disk
/// headers (the vault and recovery files), and the `argon2` crate itself caps
/// `m`/`t` only at `u32::MAX` (~4 TiB). Without a ceiling a hostile header could
/// force a multi-terabyte allocation or a multi-hour derivation *before* any
/// authentication can fail — a pre-auth resource-exhaustion `DoS` (fatal on
/// mobile). These ceilings are the universal anti-DoS guardrail; they sit at the
/// strongest shipped preset (the recovery "Paranoid" preset is 8 GiB / t = 12)
/// so every legitimate configuration is still admitted. A per-context *strength
/// floor* (e.g. the recovery Floor) is a separate caller policy.
pub const MAX_M_KIB: u32 = 8 * 1024 * 1024;

/// Maximum accepted Argon2id time cost (passes). See [`MAX_M_KIB`].
pub const MAX_T: u32 = 24;

/// Maximum accepted Argon2id parallelism (lanes). See [`MAX_M_KIB`].
pub const MAX_P: u8 = 16;

/// Argon2id cost parameters.
///
/// `m_kib` is the memory cost in kibibytes, `t` the time cost (iterations), and
/// `p` the degree of parallelism. There is deliberately **no** `Default`:
/// callers must choose a preset (see the associated constants) or supply
/// explicit values, so a weak parameter set is never selected implicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory cost in kibibytes (KiB).
    pub m_kib: u32,
    /// Time cost (number of passes).
    pub t: u32,
    /// Degree of parallelism (lanes).
    pub p: u8,
}

impl KdfParams {
    /// Low preset (floor): 256 MiB, t = 4, p = 1. ~0.6 s on modern desktop CPUs.
    pub const LOW: Self = Self {
        m_kib: 262_144,
        t: 4,
        p: 1,
    };

    /// Medium preset (default): 1 GiB, t = 4, p = 1. ~2.5 s.
    pub const MEDIUM: Self = Self {
        m_kib: 1_048_576,
        t: 4,
        p: 1,
    };

    /// High preset: 4 GiB, t = 6, p = 1. ~12 s.
    pub const HIGH: Self = Self {
        m_kib: 4_194_304,
        t: 6,
        p: 1,
    };

    /// Serialize to the canonical 9-byte little-endian layout:
    /// `m_kib` (u32-LE) ‖ `t` (u32-LE) ‖ `p` (u8).
    ///
    /// This encoding is wire-stable: downstream crates bind it into AEAD
    /// associated data, so it must round-trip identically across versions.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; KDF_PARAMS_LEN] {
        let mut out = [0u8; KDF_PARAMS_LEN];
        out[0..4].copy_from_slice(&self.m_kib.to_le_bytes());
        out[4..8].copy_from_slice(&self.t.to_le_bytes());
        out[8] = self.p;
        out
    }

    /// Parse from the canonical 9-byte little-endian layout produced by
    /// [`KdfParams::to_bytes`].
    ///
    /// This is total: every 9-byte input maps to some `KdfParams`. Whether the
    /// parsed parameters are *acceptable* (meet a minimum cost) is a policy
    /// decision left to the caller; [`KdfParams::argon2id`] additionally
    /// rejects values the `argon2` crate considers structurally invalid.
    #[must_use]
    pub fn from_bytes(bytes: [u8; KDF_PARAMS_LEN]) -> Self {
        let m_kib = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let t = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let p = bytes[8];
        Self { m_kib, t, p }
    }

    /// Whether these parameters lie within the universal safety limits: at or
    /// above the Argon2id structural minimums (`p >= 1`, `t >= 1`,
    /// `m_kib >= 8 * p`) and at or below the crate ceilings ([`MAX_M_KIB`],
    /// [`MAX_T`], [`MAX_P`]).
    ///
    /// Every parser that derives a key from header-supplied parameters MUST
    /// reject params for which this returns `false` *before* calling
    /// [`argon2id`], to deny a pre-authentication resource-exhaustion `DoS`. The
    /// strength *floor* (a per-context minimum cost) is a separate policy applied
    /// by the caller. [`argon2id`] also enforces this as a backstop.
    #[must_use]
    pub fn within_limits(&self) -> bool {
        self.p >= 1
            && self.p <= MAX_P
            && self.t >= 1
            && self.t <= MAX_T
            && self.m_kib <= MAX_M_KIB
            && self.m_kib >= 8u32.saturating_mul(u32::from(self.p))
    }
}

/// Derive a 256-bit key from `password` and `salt` using Argon2id (v1.3).
///
/// The output is written straight into a zeroizing [`SecretArray<32>`]; no
/// plaintext-key copy outlives this function.
///
/// # Errors
///
/// Returns [`CryptoError::Kdf`] if the parameters are structurally invalid
/// (e.g. memory cost below the algorithm minimum) or the derivation itself
/// fails. The error message comes from the `argon2` crate and never contains
/// the password.
pub fn argon2id(
    password: &SecretString,
    salt: &[u8],
    params: &KdfParams,
) -> Result<SecretArray<32>, CryptoError> {
    // Backstop the universal anti-DoS ceiling here so NO derivation path can run
    // with out-of-range cost, even if a caller forgets the early check. The
    // `argon2` crate caps m/t only at u32::MAX, so this is the real bound.
    if !params.within_limits() {
        return Err(CryptoError::Kdf(
            "Argon2id parameters are outside the permitted range".to_owned(),
        ));
    }

    let argon_params = Params::new(
        params.m_kib,
        params.t,
        u32::from(params.p),
        Some(DERIVED_KEY_LEN),
    )
    .map_err(|e| CryptoError::Kdf(e.to_string()))?;

    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut out = [0u8; DERIVED_KEY_LEN];
    if let Err(e) = argon.hash_password_into(password.expose_bytes(), salt, &mut out) {
        // Scrub on the error path too. `zeroize` (not `fill`) so the write is a
        // volatile store the optimizer cannot elide.
        out.zeroize();
        return Err(CryptoError::Kdf(e.to_string()));
    }

    let key = SecretArray::new(out);
    // Scrub the transient stack buffer; the only live copy is now in `key`.
    out.zeroize();
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::{argon2id, KdfParams, MAX_M_KIB, MAX_P, MAX_T};
    use crate::secret::SecretString;

    #[test]
    fn within_limits_accepts_all_presets() {
        for p in [KdfParams::LOW, KdfParams::MEDIUM, KdfParams::HIGH] {
            assert!(p.within_limits(), "preset {p:?} must be within limits");
        }
    }

    #[test]
    fn within_limits_rejects_dos_costs() {
        // The argon2 crate would otherwise accept these (its cap is u32::MAX).
        assert!(!KdfParams {
            m_kib: u32::MAX,
            t: 4,
            p: 1
        }
        .within_limits());
        assert!(!KdfParams {
            m_kib: MAX_M_KIB + 1,
            t: 4,
            p: 1
        }
        .within_limits());
        assert!(!KdfParams {
            m_kib: 262_144,
            t: MAX_T + 1,
            p: 1
        }
        .within_limits());
        assert!(!KdfParams {
            m_kib: 262_144,
            t: 4,
            p: MAX_P + 1
        }
        .within_limits());
    }

    #[test]
    fn within_limits_rejects_structural_minimums() {
        assert!(!KdfParams {
            m_kib: 0,
            t: 4,
            p: 1
        }
        .within_limits());
        // m_kib < 8 * p
        assert!(!KdfParams {
            m_kib: 4,
            t: 4,
            p: 1
        }
        .within_limits());
        assert!(!KdfParams {
            m_kib: 262_144,
            t: 0,
            p: 1
        }
        .within_limits());
        assert!(!KdfParams {
            m_kib: 262_144,
            t: 4,
            p: 0
        }
        .within_limits());
    }

    #[test]
    fn argon2id_rejects_out_of_range_params_without_allocating() {
        // An absurd memory cost must fail fast (the within_limits backstop),
        // never attempt the multi-terabyte allocation.
        let pw = SecretString::new("correct horse battery staple".to_owned());
        let salt = [0u8; 16];
        let bad = KdfParams {
            m_kib: u32::MAX,
            t: 4,
            p: 1,
        };
        assert!(argon2id(&pw, &salt, &bad).is_err());
    }
}
