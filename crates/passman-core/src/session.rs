//! The opaque session token (`architecture.md` §5.1).
//!
//! A [`SessionToken`] is a random 256-bit value minted when a vault is unlocked
//! and held only inside [`crate::UnlockedApp`]. It is process-local, never
//! persisted, never crosses a network, and is dropped (invalidated) when the
//! session locks.
//!
//! **Currently advisory / reserved.** No API verifies a *presented* token today:
//! the real capability gate is ownership of the `&UnlockedApp` handle — holding
//! it *is* proof of acting within the live session, and dropping it (lock or
//! expiry) revokes that capability. The token (and its constant-time equality
//! below) is kept for a future *addressable*-session surface — e.g. a daemon or
//! FFI layer that routes privileged calls by an opaque session id rather than by
//! owning the handle. If such a surface is added, each privileged call SHOULD
//! constant-time-verify the presented token against the live one before acting.
//!
//! It is **not** a substitute for fresh re-authentication: operations that must
//! resist a hijacked session (recovery export — §7.5) re-verify the password,
//! TOTP, and biometric independently of any token.

use passman_crypto::random_secret;

/// Length of a session token in bytes (256-bit).
const TOKEN_LEN: usize = 32;

/// An opaque, unforgeable, process-local session handle.
///
/// Equality is provided (constant-time, via the underlying secret type) so a
/// future addressable-session caller could check a presented token against the
/// live one, but the bytes are never exposed: the type is deliberately a black
/// box. See the module docs — the token is currently advisory; ownership of the
/// unlocked-session handle is the load-bearing capability today.
pub struct SessionToken {
    /// 256 bits from the OS CSPRNG, zeroized on drop by the wrapper type.
    inner: passman_crypto::SecretArray<TOKEN_LEN>,
}

impl SessionToken {
    /// Mint a fresh random token from the OS CSPRNG.
    #[must_use]
    pub(crate) fn generate() -> Self {
        Self {
            inner: random_secret::<TOKEN_LEN>(),
        }
    }
}

/// Constant-time equality (delegated to the secret wrapper), so comparing a
/// presented token to the live one does not leak via timing.
impl PartialEq for SessionToken {
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

impl Eq for SessionToken {}

/// Redacted: never prints the token bytes.
impl std::fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionToken(***)")
    }
}

#[cfg(test)]
mod tests {
    use super::SessionToken;

    #[test]
    fn tokens_are_unique() {
        let a = SessionToken::generate();
        let b = SessionToken::generate();
        // Two 256-bit OS-random values colliding is astronomically unlikely.
        assert_ne!(a, b);
    }

    #[test]
    fn token_equals_itself() {
        let a = SessionToken::generate();
        // Self-equality (reflexive) without exposing bytes.
        assert_eq!(a, a);
    }

    #[test]
    fn debug_is_redacted() {
        let a = SessionToken::generate();
        assert_eq!(format!("{a:?}"), "SessionToken(***)");
    }
}
