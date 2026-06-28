//! The opaque two-phase-unwrap handle.
//!
//! [`crate::HardwareKeyStore::begin_unwrap`] returns an [`UnwrapHandle`] that
//! carries whatever transient state [`crate::HardwareKeyStore::complete_unwrap`]
//! needs — for a real backend a live session handle (e.g. a TPM session), for
//! the mock the parsed ciphertext plus a copy of the in-memory key.
//!
//! The handle is opaque to callers, [`Send`], single-use (it is consumed by
//! `complete_unwrap`), and zeroizes any secret material it holds on drop.
//!
//! # Zeroization
//!
//! Rather than derive `Zeroize` here (which would pull in the `zeroize` crate
//! directly), the handle composes the **already-zeroizing** secret types from
//! `passman-crypto` (`SecretArray`, `SecretBytes`). When the handle is dropped,
//! each field is dropped, and those fields scrub themselves via their own
//! `ZeroizeOnDrop` impls. A handle dropped without completing therefore both
//! abandons the session and scrubs the held material.

use core::fmt;

/// Opaque transient state bridging the two unwrap phases.
///
/// Construct only inside this crate (backends populate it in `begin_unwrap`).
/// The inner payload is an enum over the backends compiled in; any secret bytes
/// it holds live in `passman-crypto` zeroizing wrappers and are scrubbed on
/// drop.
pub struct UnwrapHandle {
    inner: HandleInner,
}

/// Redacted: never prints the held session state or key material.
impl fmt::Debug for UnwrapHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UnwrapHandle(***)")
    }
}

impl UnwrapHandle {
    /// Mock-backend constructor: stash the parsed ciphertext, nonce, slot tag,
    /// and a copy of the in-memory key for `complete_unwrap`.
    ///
    /// Crate-internal: only the `mock` module calls this.
    #[cfg(feature = "mock")]
    pub(crate) fn for_mock(state: crate::mock::MockUnwrapState) -> Self {
        Self {
            inner: HandleInner::Mock(state),
        }
    }

    /// Consume the handle for the mock backend, recovering its state.
    ///
    /// A mock-minted handle only ever holds the `Mock` variant: an
    /// [`UnwrapHandle`] is single-use and is consumed by the same backend that
    /// minted it (a caller pairs `begin_unwrap` and `complete_unwrap` on one
    /// store). The catch-all therefore guards against a routing *bug*, not normal
    /// flow — and it **fails closed** with the same
    /// [`HsmError::MalformedBlob`](crate::error::HsmError::MalformedBlob) the
    /// sibling `into_*` consumers return, rather than panicking, so a misrouted
    /// handle never aborts the process. With only `mock` enabled the arm is dead
    /// and `#[allow(unreachable_patterns)]` silences the redundancy.
    ///
    /// # Errors
    ///
    /// Returns [`HsmError::MalformedBlob`](crate::error::HsmError::MalformedBlob)
    /// if the handle was minted by a different backend.
    #[cfg(feature = "mock")]
    pub(crate) fn into_mock(self) -> Result<crate::mock::MockUnwrapState, crate::error::HsmError> {
        // The catch-all is intentional: the *other* `HandleInner` variants are
        // cfg-gated and the set present depends on the feature combination, so
        // they cannot be named statically here — hence
        // `match_wildcard_for_single_variants` is allowed. `unreachable_patterns`
        // covers the mock-only build where the wildcard is redundant.
        #[allow(unreachable_patterns, clippy::match_wildcard_for_single_variants)]
        match self.inner {
            HandleInner::Mock(state) => Ok(state),
            _ => Err(crate::error::HsmError::MalformedBlob {
                reason: "unwrap handle was not minted by the mock backend",
            }),
        }
    }

    /// `SecretService`-backend constructor: stash the slot and enrollment uuid
    /// so `complete_unwrap` can rebuild the keyring entry and fetch the secret.
    ///
    /// Crate-internal: only the `secret_service` module calls this.
    #[cfg(feature = "secret-service")]
    pub(crate) fn for_secret_service(
        state: crate::linux::secret_service::SecretServiceUnwrapState,
    ) -> Self {
        Self {
            inner: HandleInner::SecretService(state),
        }
    }

    /// Consume the handle for the `SecretService` backend, recovering its state.
    ///
    /// Rejects a handle minted by any other backend (see [`Self::into_mock`]).
    #[cfg(feature = "secret-service")]
    pub(crate) fn into_secret_service(
        self,
    ) -> Result<crate::linux::secret_service::SecretServiceUnwrapState, crate::error::HsmError>
    {
        // Catch-all intentional — see `into_mock` for why the other (cfg-gated)
        // variants cannot be named statically.
        #[allow(unreachable_patterns, clippy::match_wildcard_for_single_variants)]
        match self.inner {
            HandleInner::SecretService(state) => Ok(state),
            _ => Err(crate::error::HsmError::MalformedBlob {
                reason: "unwrap handle was not minted by the SecretService backend",
            }),
        }
    }

    /// TPM2-backend constructor: stash the parsed sealed-object bytes and slot
    /// so `complete_unwrap` can load under the SRK and unseal.
    ///
    /// Crate-internal: only the `tpm2` module calls this.
    #[cfg(all(target_os = "linux", feature = "tpm2"))]
    pub(crate) fn for_tpm2(state: crate::linux::tpm2::Tpm2UnwrapState) -> Self {
        Self {
            inner: HandleInner::Tpm2(state),
        }
    }

    /// Consume the handle for the TPM2 backend, recovering its state.
    ///
    /// Rejects a handle minted by any other backend (see [`Self::into_mock`]).
    #[cfg(all(target_os = "linux", feature = "tpm2"))]
    pub(crate) fn into_tpm2(
        self,
    ) -> Result<crate::linux::tpm2::Tpm2UnwrapState, crate::error::HsmError> {
        // Catch-all intentional — see `into_mock` for why the other (cfg-gated)
        // variants cannot be named statically.
        #[allow(unreachable_patterns, clippy::match_wildcard_for_single_variants)]
        match self.inner {
            HandleInner::Tpm2(state) => Ok(state),
            _ => Err(crate::error::HsmError::MalformedBlob {
                reason: "unwrap handle was not minted by the TPM2 backend",
            }),
        }
    }

    /// Android-backend constructor: stash the parsed alias / IV / ciphertext /
    /// slot tag so `complete_unwrap` can call the foreign `KeystoreWrapper`.
    ///
    /// Crate-internal: only the `android` module calls this.
    #[cfg(feature = "android-keystore")]
    pub(crate) fn for_android(state: crate::android::AndroidUnwrapState) -> Self {
        Self {
            inner: HandleInner::Android(state),
        }
    }

    /// Consume the handle for the Android backend, recovering its state.
    ///
    /// Rejects a handle minted by any other backend (see [`Self::into_mock`]).
    #[cfg(feature = "android-keystore")]
    pub(crate) fn into_android(
        self,
    ) -> Result<crate::android::AndroidUnwrapState, crate::error::HsmError> {
        // Catch-all intentional — see `into_mock` for why the other (cfg-gated)
        // variants cannot be named statically.
        #[allow(unreachable_patterns, clippy::match_wildcard_for_single_variants)]
        match self.inner {
            HandleInner::Android(state) => Ok(state),
            _ => Err(crate::error::HsmError::MalformedBlob {
                reason: "unwrap handle was not minted by the Android backend",
            }),
        }
    }
}

/// Per-backend transient state. One variant per backend compiled in.
///
/// When no backend feature is enabled this enum is **uninhabited** (zero
/// variants), so an [`UnwrapHandle`] cannot be constructed in that build —
/// which is correct: with no backend there is nothing to unwrap. Each backend
/// adds its own variant under its own feature gate.
enum HandleInner {
    #[cfg(feature = "mock")]
    Mock(crate::mock::MockUnwrapState),
    #[cfg(feature = "secret-service")]
    SecretService(crate::linux::secret_service::SecretServiceUnwrapState),
    #[cfg(all(target_os = "linux", feature = "tpm2"))]
    Tpm2(crate::linux::tpm2::Tpm2UnwrapState),
    #[cfg(feature = "android-keystore")]
    Android(crate::android::AndroidUnwrapState),
}

#[cfg(test)]
mod tests {
    // The mis-routing guard in `into_mock` only has another variant to construct
    // when a second backend feature is compiled in alongside `mock`. Use the
    // dependency-free `android-keystore` backend to mint a non-mock handle.
    #[cfg(all(feature = "mock", feature = "android-keystore"))]
    #[test]
    fn into_mock_rejects_a_handle_minted_by_another_backend() {
        use super::UnwrapHandle;
        use crate::android::AndroidUnwrapState;
        use crate::error::HsmError;

        // A routing bug that hands an Android-minted handle to the mock consumer
        // must fail closed (MalformedBlob), not panic via the former unreachable!.
        let handle = UnwrapHandle::for_android(AndroidUnwrapState {
            alias: "passman-deadbeef".to_owned(),
            iv: [0u8; 12],
            ciphertext: vec![0u8; 16],
            slot_tag: 0x00,
        });
        // `MockUnwrapState` (the Ok type) is not `Debug`, so match rather than
        // `expect_err`.
        match handle.into_mock() {
            Ok(_) => panic!("a non-mock handle must be rejected, not accepted"),
            Err(e) => assert!(matches!(e, HsmError::MalformedBlob { .. })),
        }
    }
}
