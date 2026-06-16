//! The desktop [`BiometricPrompter`] (no-op authorise — see the CLI's note: the
//! Linux TPM2 / `SecretService` backends do not gate on a per-use prompt).

use passman_hsm::{BiometricPrompter, HsmError, PromptResult};

/// Authorises every operation without a prompt.
#[derive(Debug, Default)]
pub struct DesktopPrompter;

impl BiometricPrompter for DesktopPrompter {
    fn prompt(&self, _reason: String) -> Result<PromptResult, HsmError> {
        Ok(PromptResult::Authenticated)
    }
}
