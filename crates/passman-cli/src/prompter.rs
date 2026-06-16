//! The desktop [`BiometricPrompter`].
//!
//! The Linux backends do not gate on a biometric: TPM2 reports
//! `biometric_supported = false` and, with no `authValue` PIN (the §6.4
//! default), unseal needs no prompt; the `SecretService` keyring is gated by the
//! login session, not a per-use prompt. So the desktop prompter authorises
//! unconditionally. (A distinct TOTP-seed PIN, §1.6, is a future enhancement;
//! it would read the PIN here.)

use passman_hsm::{BiometricPrompter, HsmError, PromptResult};

/// A prompter that authorises every operation without a prompt, matching the
/// no-PIN Linux TPM2 / `SecretService` backends.
#[derive(Debug, Default)]
pub struct DesktopPrompter;

impl BiometricPrompter for DesktopPrompter {
    fn prompt(&self, _reason: String) -> Result<PromptResult, HsmError> {
        Ok(PromptResult::Authenticated)
    }
}
