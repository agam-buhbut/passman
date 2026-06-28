//! The [`Progress`] reporting contract for long synchronous operations
//! (`architecture.md` §2.5).
//!
//! The only multi-second operations in `passman-core` are the Argon2id
//! derivations inside unlock / create / recovery import-export / master-password
//! change. The `argon2` crate exposes **no** per-iteration hook, so core cannot
//! emit incremental progress; it emits exactly a `start` before the derivation
//! and an `end` after (via an RAII [`ProgressGuard`], so `end` also fires on the
//! early-return and panic paths). The **shell** owns any heartbeat/spinner timer
//! it runs between those two signals — that is why this trait has no `heartbeat`
//! method (core could not drive one).
//!
//! The contract is FFI-shaped per §2.5: object-safe (no generics / associated
//! types), owned parameters (`UniFFI` foreign traits cannot take references), and
//! `Result` returns (a foreign-callback error must not panic across the FFI).
//! Progress is **cosmetic**: core swallows a callback error rather than letting a
//! buggy UI abort a security operation.
//!
//! No `Spawner` trait is provided: the core is synchronous and the shell already
//! invokes the blocking operations off its UI thread (§2.5), so a spawner core
//! would call back into adds an indirection with no benefit. (Ratified
//! deviation from §2.5's literal wording; re-addable later with no format
//! impact.)

use std::sync::Arc;

use thiserror::Error;

/// Brackets a long synchronous operation so the shell can show and hide an
/// **indeterminate** progress indicator (`architecture.md` §2.5).
///
/// Core calls [`Progress::start`] immediately before a multi-second Argon2id
/// derivation and [`Progress::end`] immediately after. It never calls anything
/// per-iteration (the `argon2` crate has no hook); a UI that wants a "still
/// working" pulse runs its own timer between the two calls.
///
/// `Send + Sync` so the injected handle can be shared across the worker thread
/// the shell runs unlock on. Implementations should be cheap and non-blocking.
pub trait Progress: Send + Sync {
    /// A long operation began. `label` names it for the UI (e.g. "Deriving
    /// vault key").
    ///
    /// # Errors
    ///
    /// May return [`ProgressError`] if the foreign callback fails; core treats
    /// the error as non-fatal (progress is cosmetic).
    fn start(&self, label: String) -> Result<(), ProgressError>;

    /// The long operation ended — success, error, or panic-unwind. Always
    /// called exactly once per [`Progress::start`] (the [`ProgressGuard`]
    /// guarantees it).
    ///
    /// # Errors
    ///
    /// May return [`ProgressError`]; core treats it as non-fatal.
    fn end(&self) -> Result<(), ProgressError>;
}

/// A foreign progress-callback failure. Carries no detail (and certainly no
/// secret): progress is cosmetic and core only ever swallows this.
#[derive(Debug, Error)]
#[error("progress callback failed")]
pub struct ProgressError;

/// The default no-op [`Progress`]: used whenever a shell injects none, so the
/// existing constructors and tests need no progress sink at all.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoProgress;

impl Progress for NoProgress {
    fn start(&self, _label: String) -> Result<(), ProgressError> {
        Ok(())
    }

    fn end(&self) -> Result<(), ProgressError> {
        Ok(())
    }
}

/// An RAII guard that emits [`Progress::start`] on construction and
/// [`Progress::end`] on drop.
///
/// Holds the shared [`Arc<dyn Progress>`] so the bracket is exception-safe: a
/// `?` early-return or a panic inside the bracketed section still runs `end` as
/// the guard drops. Both callbacks are cosmetic, so their errors are swallowed.
pub(crate) struct ProgressGuard {
    progress: Arc<dyn Progress>,
}

impl ProgressGuard {
    /// Start a progress bracket labelled `label`, returning the guard whose drop
    /// ends it.
    pub(crate) fn start(progress: &Arc<dyn Progress>, label: &str) -> Self {
        // Cosmetic: a failing foreign callback must never block a security op.
        let _ = progress.start(label.to_owned());
        Self {
            progress: Arc::clone(progress),
        }
    }
}

impl Drop for ProgressGuard {
    fn drop(&mut self) {
        let _ = self.progress.end();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    use super::{Progress, ProgressError, ProgressGuard};

    /// A [`Progress`] that tallies `start` / `end` calls.
    #[derive(Default)]
    struct Counts {
        starts: AtomicU64,
        ends: AtomicU64,
    }

    struct Counter(Arc<Counts>);

    impl Progress for Counter {
        fn start(&self, _label: String) -> Result<(), ProgressError> {
            self.0.starts.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn end(&self) -> Result<(), ProgressError> {
            self.0.ends.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[test]
    fn end_fires_on_early_return_via_question_mark() {
        // The success-balanced bracket is covered end-to-end at
        // `tests/core.rs::progress_brackets_each_argon2_operation`. This pins the
        // RAII contract on the *error* path: a `?` bail-out mid-bracket must still
        // run `end` as the guard drops while unwinding the stack frame.
        let counts = Arc::new(Counts::default());
        let progress: Arc<dyn Progress> = Arc::new(Counter(counts.clone()));

        let bracketed = || -> Result<(), ProgressError> {
            let _pg = ProgressGuard::start(&progress, "work");
            // Propagate an error before reaching the end of the bracket.
            Err(ProgressError)?;
            Ok(())
        };

        assert!(bracketed().is_err());
        assert_eq!(counts.starts.load(Ordering::SeqCst), 1, "start fired once");
        assert_eq!(
            counts.ends.load(Ordering::SeqCst),
            1,
            "end must fire on the `?` early-return path",
        );
    }
}
