//! Entropy estimation and crack-time modelling.
//!
//! Two estimators (`architecture.md` §8.3):
//!
//! - **Generated** passwords: the closed form `H = length · log2(|charset|)`,
//!   exact because the generator samples uniformly.
//! - **Master** passwords: [`zxcvbn`] guess estimates, converted to bits via
//!   `bits ≡ log2(guesses)`.
//!
//! Crack-time figures here are deliberately illustrative back-of-the-envelope
//! estimates, **not** guarantees. Every constant and assumption is documented
//! at its definition so the UI can surface them honestly (`architecture.md`
//! §8.5).

use passman_crypto::KdfParams;
use zxcvbn::zxcvbn;

/// `log2(x) = log10(x) * LOG2_PER_LOG10`. zxcvbn reports `guesses_log10`; this
/// converts it to bits without re-taking a logarithm.
const LOG2_PER_LOG10: f64 = std::f64::consts::LOG2_10;

/// Assumed throughput of an attacker hashing a *fast* function (the password
/// itself, not the KDF) on commodity GPUs: 1e11 guesses/second. Illustrative.
const NAKED_GPU_GUESSES_PER_SEC: f64 = 1e11;

// --- KDF cost model constants (illustrative; see `kdf_guesses_per_sec`) ------

/// Reference Argon2id throughput used to anchor the KDF cost model: one
/// derivation at this *reference* cost takes ~`REFERENCE_SECONDS_PER_GUESS`.
///
/// The model assumes wall-time scales linearly with the dominant cost term
/// `m_kib · t` (memory passes), which is the standard first-order Argon2id cost
/// approximation. We anchor it on the Medium preset (1 GiB, t = 4) being ≈ 2.5 s
/// per derivation on a modern desktop CPU (`architecture.md` §4.8). An attacker
/// with better hardware is faster, but the *relative* hardening between presets
/// is what this conveys; the absolute figure is explicitly illustrative.
const REFERENCE_M_KIB: f64 = 1_048_576.0; // 1 GiB
const REFERENCE_T: f64 = 4.0;
const REFERENCE_SECONDS_PER_GUESS: f64 = 2.5;

/// Strength tier of a master password, keyed off entropy in bits
/// (`architecture.md` §8.4). zxcvbn saturates at ~64 bits, so the thresholds
/// are calibrated to that range (bits): Dangerous `< 30`, Weak `30..45`,
/// Acceptable `45..55`, Strong `55..62`, Excellent `>= 62`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrengthTier {
    /// `< 30` bits.
    Dangerous,
    /// `30..45` bits.
    Weak,
    /// `45..55` bits.
    Acceptable,
    /// `55..62` bits. The export gate (`architecture.md` §7.5) requires at
    /// least this tier.
    Strong,
    /// `>= 62` bits (the zxcvbn cap region).
    Excellent,
}

impl StrengthTier {
    /// Whether a vault with a master password of this tier may create a
    /// single-factor recovery export (`architecture.md` §7.5): Strong or above
    /// (`>= 55` zxcvbn-bits). Safe at this threshold because the export sits
    /// behind the 4 GiB Argon2id of §7.4 — see [`estimate_master`].
    #[must_use]
    pub fn allows_export(self) -> bool {
        matches!(self, StrengthTier::Strong | StrengthTier::Excellent)
    }
}

/// Illustrative crack-time estimates, in seconds, under three attacker models.
///
/// All figures are derived from a guess count and fixed throughput assumptions;
/// they are order-of-magnitude guidance, not promises (`architecture.md` §8.5).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CrackEstimates {
    /// Time to exhaust the guess space hashing the password directly on GPUs at
    /// [`NAKED_GPU_GUESSES_PER_SEC`]. The worst case for the defender.
    pub naked_gpu_seconds: f64,
    /// Time when the attacker must run one Argon2id derivation per guess at the
    /// vault's [`KdfParams`]. Always `>=` the naked-GPU time. The realistic
    /// figure shown inline in the UI.
    pub through_kdf_seconds: f64,
    /// Time under a Grover-style quantum search, modelled as halving the
    /// effective bits (square-root of the guess count) at the naked-GPU rate.
    pub quantum_grover_seconds: f64,
}

/// The result of estimating a master password's strength.
#[derive(Debug, Clone, PartialEq)]
pub struct MasterEntropy {
    /// Entropy in bits, defined as `log2(zxcvbn guesses)`.
    pub bits: f64,
    /// Tier derived from [`MasterEntropy::bits`] via [`classify`].
    pub tier: StrengthTier,
    /// Illustrative crack-time estimates.
    pub crack: CrackEstimates,
    /// zxcvbn's own human-readable feedback (warning then suggestions), each as
    /// a separate string. Empty when zxcvbn offers none.
    pub feedback: Vec<String>,
}

/// Closed-form entropy of a uniformly-generated password:
/// `length · log2(charset_size)` bits (`architecture.md` §8.3).
///
/// Returns `0.0` for a degenerate `charset_size < 2` (no entropy per character)
/// or `length == 0`, rather than a negative or non-finite value.
///
/// # Accepted residual
///
/// This closed form is exact only for i.i.d. uniform draws over the full
/// `charset_size` alphabet. The generator first places each required-class
/// minimum (sampled from that class's sub-alphabet) before filling the rest from
/// the full set, so a few positions are drawn from a smaller alphabet — making
/// the true entropy marginally *lower* than this figure. The gap is treated as
/// negligible: for the default policy (one-of-each minimums over the 94-char
/// set, length 40) it is a fraction of a bit against ~262, far above any gate.
#[must_use]
pub fn generated_entropy_bits(charset_size: usize, length: u16) -> f64 {
    if charset_size < 2 || length == 0 {
        return 0.0;
    }
    // A character set cannot exceed the Unicode scalar range (~1.1M), which fits
    // in u32; `f64::from(u32)` is then lossless, avoiding a precision-loss cast.
    // Saturate on the impossible overflow rather than panic.
    let size = u32::try_from(charset_size).unwrap_or(u32::MAX);
    f64::from(length) * f64::from(size).log2()
}

/// Map entropy in bits to a [`StrengthTier`] using the `architecture.md` §8.4
/// thresholds, calibrated to zxcvbn's ~64-bit ceiling. Ranges are half-open at
/// the top: `[30, 45)` is Weak, etc.
///
/// Non-finite or negative inputs (e.g. the empty-password `-inf` from zxcvbn)
/// classify as [`StrengthTier::Dangerous`].
#[must_use]
pub fn classify(bits: f64) -> StrengthTier {
    // NaN compares false against every bound, so handle it explicitly first and
    // treat it as the worst case rather than relying on a negated comparison.
    if bits.is_nan() || bits < 30.0 {
        StrengthTier::Dangerous
    } else if bits < 45.0 {
        StrengthTier::Weak
    } else if bits < 55.0 {
        StrengthTier::Acceptable
    } else if bits < 62.0 {
        StrengthTier::Strong
    } else {
        StrengthTier::Excellent
    }
}

/// Approximate attacker guesses/second when each guess costs one Argon2id
/// derivation at `kdf`.
///
/// Cost model (first-order, documented illustrative): Argon2id wall-time is
/// dominated by `m_kib · t` (memory × passes). We scale the reference
/// derivation time linearly in that product:
///
/// ```text
/// seconds_per_guess = REFERENCE_SECONDS_PER_GUESS
///                     · (m_kib · t) / (REFERENCE_M_KIB · REFERENCE_T)
/// guesses_per_sec   = 1 / seconds_per_guess
/// ```
///
/// Parallelism `p` is intentionally excluded: per `architecture.md` §4.8 it is
/// pinned to 1 and raising it helps the attacker as much as the defender, so it
/// is not a hardening lever. Degenerate zero parameters fall back to the
/// naked-GPU rate (no KDF cost).
fn kdf_guesses_per_sec(kdf: &KdfParams) -> f64 {
    let work = f64::from(kdf.m_kib) * f64::from(kdf.t);
    let reference_work = REFERENCE_M_KIB * REFERENCE_T;
    if work <= 0.0 {
        return NAKED_GPU_GUESSES_PER_SEC;
    }
    let seconds_per_guess = REFERENCE_SECONDS_PER_GUESS * (work / reference_work);
    1.0 / seconds_per_guess
}

/// Build crack-time estimates from a guess count and KDF parameters.
fn crack_estimates(guesses: f64, kdf: &KdfParams) -> CrackEstimates {
    let naked = guesses / NAKED_GPU_GUESSES_PER_SEC;
    let through_kdf = guesses / kdf_guesses_per_sec(kdf);
    // Grover: effective search space is sqrt(N); run those at the naked rate.
    let quantum = guesses.sqrt() / NAKED_GPU_GUESSES_PER_SEC;
    CrackEstimates {
        naked_gpu_seconds: naked,
        through_kdf_seconds: through_kdf,
        quantum_grover_seconds: quantum,
    }
}

/// Collect zxcvbn feedback (warning first, then each suggestion) into plain
/// strings. Returns an empty vec when zxcvbn provides no feedback (typically
/// for strong passwords).
fn collect_feedback(entropy: &zxcvbn::Entropy) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(fb) = entropy.feedback() {
        if let Some(warning) = fb.warning() {
            out.push(warning.to_string());
        }
        for suggestion in fb.suggestions() {
            out.push(suggestion.to_string());
        }
    }
    out
}

/// Estimate a master password's strength via zxcvbn (`architecture.md` §8.3).
///
/// `user_inputs` are personal tokens (username, email, name) zxcvbn penalizes
/// if the password resembles them. `kdf` is the vault's Argon2id configuration,
/// used for the through-KDF crack estimate.
///
/// `bits` is defined as `log2(guesses)`, computed from zxcvbn's
/// `guesses_log10`.
///
/// # zxcvbn guess cap
///
/// zxcvbn v3 caps `guesses` at `u64::MAX`, so `bits = log2(guesses)`
/// **saturates at ~64 bits**. The tier thresholds (§8.4) are calibrated to this
/// range: [`StrengthTier::Excellent`] begins at 62 bits (the cap region) and
/// the export gate ([`StrengthTier::allows_export`], §7.5) requires
/// [`StrengthTier::Strong`] at `>= 55` bits — reachable by a strong passphrase
/// and safe because the recovery export sits behind the 4 GiB Argon2id of §7.4.
/// Generated passwords are scored by [`generated_entropy_bits`] instead
/// (uncapped, ~262 bits for the default policy), so they clear any gate.
///
/// This function is infallible: a weak password yields a low tier, not an
/// error. The empty password (zxcvbn reports `guesses = 0`,
/// `guesses_log10 = -inf`) is mapped to `0.0` bits / [`StrengthTier::Dangerous`].
#[must_use]
pub fn estimate_master(password: &str, user_inputs: &[&str], kdf: &KdfParams) -> MasterEntropy {
    let entropy = zxcvbn(password, user_inputs);

    let log10 = entropy.guesses_log10();
    let bits = if log10.is_finite() {
        (log10 * LOG2_PER_LOG10).max(0.0)
    } else {
        // Empty password: guesses == 0, guesses_log10 == -inf.
        0.0
    };

    // Use the raw guess count for crack times. For the empty password this is
    // 0, yielding zero crack time, which is the correct (worst) interpretation.
    //
    // The sole `#[allow]` in this crate: u64 -> f64 is inherently lossy for
    // guess counts above 2^52, but crack-time figures are explicitly
    // order-of-magnitude illustrations (see the module docs and §8.5), so the
    // ~15 significant decimal digits an f64 retains are far more precision than
    // the estimate warrants. `try_from` is not applicable (no lossless path).
    #[allow(clippy::cast_precision_loss)]
    let guesses = entropy.guesses() as f64;

    MasterEntropy {
        bits,
        tier: classify(bits),
        crack: crack_estimates(guesses, kdf),
        feedback: collect_feedback(&entropy),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// These functions return an exact literal `0.0` (or `0.0 / x`) for their
    /// degenerate/empty cases. `clippy::float_cmp` discourages `== 0.0`, so this
    /// helper asserts "is zero" via an epsilon band, which is also robust if the
    /// computation ever changes to a near-zero value.
    fn is_zero(x: f64) -> bool {
        x.abs() < f64::EPSILON
    }

    #[test]
    fn generated_entropy_default_vault() {
        // 40 chars over the full 94-char set ≈ 262 bits.
        let bits = generated_entropy_bits(94, 40);
        assert!((bits - 262.18).abs() < 0.1, "got {bits}");
    }

    #[test]
    fn generated_entropy_degenerate() {
        assert!(is_zero(generated_entropy_bits(1, 40)));
        assert!(is_zero(generated_entropy_bits(94, 0)));
        assert!(is_zero(generated_entropy_bits(0, 40)));
    }

    #[test]
    fn tier_boundaries() {
        // §8.4 thresholds (calibrated to zxcvbn's ~64-bit cap); half-open tops.
        assert_eq!(classify(0.0), StrengthTier::Dangerous);
        assert_eq!(classify(29.999), StrengthTier::Dangerous);
        assert_eq!(classify(30.0), StrengthTier::Weak);
        assert_eq!(classify(44.999), StrengthTier::Weak);
        assert_eq!(classify(45.0), StrengthTier::Acceptable);
        assert_eq!(classify(54.999), StrengthTier::Acceptable);
        assert_eq!(classify(55.0), StrengthTier::Strong);
        assert_eq!(classify(61.999), StrengthTier::Strong);
        assert_eq!(classify(62.0), StrengthTier::Excellent);
        assert_eq!(classify(300.0), StrengthTier::Excellent);
    }

    #[test]
    fn export_gate_matches_strong_threshold() {
        // The recovery-export gate (§7.5) opens at Strong (>= 55 bits).
        assert!(!classify(54.999).allows_export());
        assert!(classify(55.0).allows_export());
        assert!(classify(62.0).allows_export());
        assert!(!classify(0.0).allows_export());
    }

    #[test]
    fn classify_handles_non_finite() {
        assert_eq!(classify(f64::NAN), StrengthTier::Dangerous);
        assert_eq!(classify(f64::NEG_INFINITY), StrengthTier::Dangerous);
        assert_eq!(classify(-10.0), StrengthTier::Dangerous);
        assert_eq!(classify(f64::INFINITY), StrengthTier::Excellent);
    }

    #[test]
    fn weak_password_lands_low_tier() {
        let est = estimate_master("password123", &[], &KdfParams::MEDIUM);
        assert!(
            matches!(est.tier, StrengthTier::Dangerous | StrengthTier::Weak),
            "expected weak, got {:?} ({} bits)",
            est.tier,
            est.bits
        );
        // zxcvbn flags this common password, so feedback should be present.
        assert!(!est.feedback.is_empty());
    }

    #[test]
    fn strong_password_is_export_eligible() {
        // zxcvbn caps `guesses` at u64::MAX, so a high-entropy password
        // saturates near ~64 bits. With the §8.4 tiers calibrated to that range
        // it reaches Strong (>= 55) or Excellent (>= 62) and therefore clears
        // the recovery-export gate (§7.5).
        let strong = estimate_master("xK7#mP2$qR9vL4nB8wZ!jH3tY6&", &[], &KdfParams::MEDIUM);
        let weak = estimate_master("password123", &[], &KdfParams::MEDIUM);

        assert!(
            strong.bits >= 55.0,
            "expected >=55 bits, got {} ({:?})",
            strong.bits,
            strong.tier
        );
        assert!(strong.bits > weak.bits);
        assert!(strong.tier.allows_export(), "tier {:?}", strong.tier);
        assert!(!weak.tier.allows_export());
    }

    #[test]
    fn through_kdf_is_at_least_naked_gpu() {
        // The Medium preset is far more expensive than a bare GPU hash, so the
        // KDF crack time must dominate.
        let est = estimate_master("Tr0ub4dour&3xtra", &[], &KdfParams::MEDIUM);
        assert!(est.crack.through_kdf_seconds >= est.crack.naked_gpu_seconds);
        assert!(est.crack.quantum_grover_seconds <= est.crack.naked_gpu_seconds);
    }

    #[test]
    fn empty_password_is_dangerous_with_zero_crack_time() {
        let est = estimate_master("", &[], &KdfParams::MEDIUM);
        assert!(is_zero(est.bits));
        assert_eq!(est.tier, StrengthTier::Dangerous);
        assert!(is_zero(est.crack.naked_gpu_seconds));
        assert!(is_zero(est.crack.through_kdf_seconds));
    }

    #[test]
    fn kdf_cost_scales_with_parameters() {
        // Higher cost params -> fewer guesses/sec -> longer through-KDF time.
        let low = estimate_master("Tr0ub4dour&3xtra", &[], &KdfParams::LOW);
        let high = estimate_master("Tr0ub4dour&3xtra", &[], &KdfParams::HIGH);
        assert!(high.crack.through_kdf_seconds > low.crack.through_kdf_seconds);
    }

    #[test]
    fn user_inputs_penalize_resemblance() {
        // A password equal to a user input should score very poorly.
        let est = estimate_master("amitayofer", &["amitayofer"], &KdfParams::MEDIUM);
        assert!(matches!(
            est.tier,
            StrengthTier::Dangerous | StrengthTier::Weak
        ));
    }
}
