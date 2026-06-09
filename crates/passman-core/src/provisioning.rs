//! TOTP provisioning-URI construction (`architecture.md` §7.6).
//!
//! Builds the `otpauth://totp/...` URI a shell renders as a QR code so the user
//! can add the seed to their authenticator app. The seed is base32-encoded
//! (RFC 4648, no padding, uppercase — the authenticator convention) and the
//! `algorithm`, `digits`, and `period` are set **explicitly** (§7.6) so the
//! provisioned profile is unambiguous.
//!
//! The returned URI embeds the seed, so it is a [`passman_crypto::SecretString`]
//! and is zeroized when the shell drops it after rendering.
//!
//! # Residual-secret note
//!
//! The intermediate base32 `String` transiently holds the seed. Core forbids
//! `unsafe` and does not depend on `zeroize`, so that one heap buffer cannot be
//! scrubbed in place here; the window is kept minimal (it is formatted into the
//! result and dropped immediately). This is the same accepted userspace
//! residual risk documented in `passman_crypto::secret` (allocator copies and
//! swap are out of scope at the architecture level).

use base32::Alphabet;

use passman_crypto::{SecretArray, SecretString};
use passman_totp::{TotpAlgorithm, TotpConfig};

use crate::app::{ProvisioningUri, KEY_LEN};

/// The issuer/label used in the provisioning URI. Non-secret.
const ISSUER: &str = "passman";

/// The account label segment after the issuer. Non-secret.
const ACCOUNT: &str = "vault";

/// Render a [`TotpAlgorithm`] as the `algorithm=` query value.
fn algorithm_param(algo: TotpAlgorithm) -> &'static str {
    match algo {
        TotpAlgorithm::Sha1 => "SHA1",
        TotpAlgorithm::Sha256 => "SHA256",
        TotpAlgorithm::Sha512 => "SHA512",
    }
}

/// Build the provisioning URI for `seed` under `cfg` (`architecture.md` §7.6).
///
/// Format:
/// `otpauth://totp/passman:vault?secret=<BASE32>&issuer=passman&algorithm=<ALG>&digits=<D>&period=<P>`
#[must_use]
pub(crate) fn build_provisioning_uri(
    seed: &SecretArray<KEY_LEN>,
    cfg: TotpConfig,
) -> ProvisioningUri {
    // RFC 4648 base32, uppercase, no padding (authenticator convention).
    let secret_b32 = base32::encode(Alphabet::Rfc4648 { padding: false }, seed.expose_bytes());

    let uri = format!(
        "otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}\
         &algorithm={algorithm}&digits={digits}&period={period}",
        issuer = ISSUER,
        account = ACCOUNT,
        secret = secret_b32,
        algorithm = algorithm_param(cfg.algorithm()),
        digits = cfg.digits(),
        period = cfg.period(),
    );

    // `secret_b32` drops here (see the module's residual-secret note); the URI
    // moves into a zeroizing SecretString.
    drop(secret_b32);
    SecretString::new(uri)
}

#[cfg(test)]
mod tests {
    use super::{algorithm_param, build_provisioning_uri};
    use crate::app::KEY_LEN;
    use base32::Alphabet;
    use passman_crypto::SecretArray;
    use passman_totp::{TotpAlgorithm, TotpConfig};

    #[test]
    fn algorithm_param_maps_each_variant() {
        assert_eq!(algorithm_param(TotpAlgorithm::Sha1), "SHA1");
        assert_eq!(algorithm_param(TotpAlgorithm::Sha256), "SHA256");
        assert_eq!(algorithm_param(TotpAlgorithm::Sha512), "SHA512");
    }

    #[test]
    fn uri_contains_base32_seed_and_explicit_params() {
        let seed = SecretArray::new([0x00u8; KEY_LEN]);
        let cfg = TotpConfig::default(); // SHA1, 6 digits, 30 s period
        let uri = build_provisioning_uri(&seed, cfg);
        let s = uri.expose();

        // All-zero 32-byte seed base32-encodes to 56 'A's (no padding).
        let expected_b32 = base32::encode(Alphabet::Rfc4648 { padding: false }, &[0u8; KEY_LEN]);
        assert!(s.contains(&format!("secret={expected_b32}")));
        assert!(s.starts_with("otpauth://totp/passman:vault?"));
        assert!(s.contains("algorithm=SHA1"));
        assert!(s.contains("digits=6"));
        assert!(s.contains("period=30"));
        assert!(s.contains("issuer=passman"));
    }

    #[test]
    fn non_default_config_is_reflected() {
        let seed = SecretArray::new([0xFFu8; KEY_LEN]);
        let cfg = TotpConfig::new(TotpAlgorithm::Sha256, 8, 60, 1).expect("valid cfg");
        let uri = build_provisioning_uri(&seed, cfg);
        let s = uri.expose();
        assert!(s.contains("algorithm=SHA256"));
        assert!(s.contains("digits=8"));
        assert!(s.contains("period=60"));
    }
}
