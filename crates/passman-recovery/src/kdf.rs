//! Recovery key derivation and the Argon2id cost presets.
//!
//! Recovery is the single-factor (password-only) escape hatch, so its Argon2id
//! cost is deliberately *higher* than the vault's (`architecture.md` §7.4): the
//! export's only barrier is the master password behind an expensive KDF. This
//! module exposes the three presets, the Floor below which `export` refuses,
//! and the two-step derivation that turns the password into `K_recovery`.

use passman_crypto::{argon2id, hkdf_master, KdfParams, SecretArray, SecretString};

use crate::error::RecoveryError;

/// HKDF-Expand domain-separation string for the recovery export key
/// (`architecture.md` §4.6). Owned by this crate.
pub const RECOVERY_INFO: &[u8] = b"recovery-export-v0";

/// Recovery Argon2id cost presets (`architecture.md` §7.4).
///
/// These map to [`KdfParams`] and are intentionally aggressive — far above the
/// vault presets — because the recovery export is single-factor.
///
/// All presets use `p = 1`: as in the vault design, memory cost is the real
/// GPU/ASIC barrier and raising parallelism mostly helps the attacker too.
///
/// Note: *restoring* a recovery file re-runs Argon2id at the file's own memory
/// cost (`passman_crypto::argon2id` refuses costs that exceed the host's RAM),
/// so a file created at a high preset must be restored on a machine with
/// comparable RAM (Default ≈ ≥5 GiB, Paranoid ≈ ≥9 GiB). Choose `Floor` if the
/// backup must be restorable on a constrained/mobile device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryPreset {
    /// Floor: 1 GiB, t = 4, p = 1 (~2.5 s). `export` refuses anything weaker.
    Floor,
    /// Default: 4 GiB, t = 8, p = 1 (~15 s).
    Default,
    /// Paranoid: 8 GiB, t = 12, p = 1 (~45 s).
    Paranoid,
}

impl RecoveryPreset {
    /// The [`KdfParams`] for this preset.
    #[must_use]
    pub const fn params(self) -> KdfParams {
        match self {
            // 1 GiB = 1_048_576 KiB.
            Self::Floor => KdfParams {
                m_kib: 1_048_576,
                t: 4,
                p: 1,
            },
            // 4 GiB = 4_194_304 KiB.
            Self::Default => KdfParams {
                m_kib: 4_194_304,
                t: 8,
                p: 1,
            },
            // 8 GiB = 8_388_608 KiB.
            Self::Paranoid => KdfParams {
                m_kib: 8_388_608,
                t: 12,
                p: 1,
            },
        }
    }
}

/// The recovery Floor parameters (`RecoveryPreset::Floor`): 1 GiB / t = 4 / p = 1.
///
/// `export` rejects any parameter set weaker than this (see [`meets_floor`]).
pub const FLOOR_PARAMS: KdfParams = RecoveryPreset::Floor.params();

/// Whether `params` meet or exceed the recovery [`FLOOR_PARAMS`] on **every**
/// axis (memory, time, and parallelism).
///
/// Each cost dimension must be at least the floor independently — a caller
/// cannot trade a higher time cost for sub-floor memory, since memory is the
/// dimension that actually resists parallel hardware. This is the gate
/// `export` applies before doing any expensive work.
#[must_use]
pub fn meets_floor(params: &KdfParams) -> bool {
    params.m_kib >= FLOOR_PARAMS.m_kib
        && params.t >= FLOOR_PARAMS.t
        && u32::from(params.p) >= u32::from(FLOOR_PARAMS.p)
}

/// Derive `K_recovery` from the master password and recovery salt
/// (`architecture.md` §7.1).
///
/// ```text
/// K_recovery_pw = Argon2id(password, recovery_salt, recovery_params)
/// K_recovery    = HKDF-Extract-and-Expand(
///                     salt = recovery_salt,
///                     ikm  = K_recovery_pw,
///                     info = RECOVERY_INFO)
/// ```
///
/// The transient `K_recovery_pw` is a zeroizing [`SecretArray<32>`] that scrubs
/// on drop; its bytes are borrowed (never copied into a non-zeroizing buffer)
/// when fed to HKDF as the IKM, so no un-scrubbed copy of the intermediate key
/// is left behind.
///
/// # Errors
///
/// Returns [`RecoveryError::Crypto`] if Argon2id rejects `recovery_params` as
/// structurally invalid (e.g. memory cost below the algorithm minimum). The
/// error never echoes the password.
pub(crate) fn derive_recovery_key(
    password: &SecretString,
    recovery_salt: &[u8; 32],
    recovery_params: &KdfParams,
) -> Result<SecretArray<32>, RecoveryError> {
    let k_recovery_pw = argon2id(password, recovery_salt, recovery_params)?;
    // `expose_bytes` borrows the zeroizing buffer; HKDF copies it internally
    // into its own HMAC state, but we never materialize a plaintext copy of the
    // IKM in a non-zeroizing local. `k_recovery_pw` scrubs on drop at end of fn.
    let k_recovery = hkdf_master(recovery_salt, k_recovery_pw.expose_bytes(), RECOVERY_INFO);
    Ok(k_recovery)
}

#[cfg(test)]
mod tests {
    use super::{meets_floor, RecoveryPreset, FLOOR_PARAMS};
    use passman_crypto::KdfParams;

    #[test]
    fn presets_match_architecture_table() {
        assert_eq!(
            RecoveryPreset::Floor.params(),
            KdfParams {
                m_kib: 1_048_576,
                t: 4,
                p: 1
            }
        );
        assert_eq!(
            RecoveryPreset::Default.params(),
            KdfParams {
                m_kib: 4_194_304,
                t: 8,
                p: 1
            }
        );
        assert_eq!(
            RecoveryPreset::Paranoid.params(),
            KdfParams {
                m_kib: 8_388_608,
                t: 12,
                p: 1
            }
        );
    }

    #[test]
    fn floor_const_equals_floor_preset() {
        assert_eq!(FLOOR_PARAMS, RecoveryPreset::Floor.params());
    }

    #[test]
    fn floor_check_accepts_floor_and_above() {
        assert!(meets_floor(&FLOOR_PARAMS));
        assert!(meets_floor(&RecoveryPreset::Default.params()));
        assert!(meets_floor(&RecoveryPreset::Paranoid.params()));
    }

    #[test]
    fn floor_check_rejects_sub_floor_on_any_axis() {
        // Below on memory.
        assert!(!meets_floor(&KdfParams {
            m_kib: FLOOR_PARAMS.m_kib - 1,
            t: FLOOR_PARAMS.t,
            p: FLOOR_PARAMS.p,
        }));
        // Below on time.
        assert!(!meets_floor(&KdfParams {
            m_kib: FLOOR_PARAMS.m_kib,
            t: FLOOR_PARAMS.t - 1,
            p: FLOOR_PARAMS.p,
        }));
        // The vault Medium preset (1 GiB but t=4) just meets memory but the
        // recovery floor demands the same; a typical tiny test param is well
        // below and must be rejected.
        assert!(!meets_floor(&KdfParams {
            m_kib: 8_192,
            t: 1,
            p: 1,
        }));
    }
}
