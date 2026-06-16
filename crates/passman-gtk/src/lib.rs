//! `passman-gtk` — the Linux GTK4 desktop front-end (`architecture.md` §1.4).
//!
//! A thin shell over `passman-core`. The multi-second `unlock` and every
//! unlocked operation run on a worker thread (the [`session`] actor) so the GTK
//! main loop never blocks; the UI ([`ui`]) drives it over channels. The
//! [`session`] module is GTK-free and tested against the mock backend.

#![forbid(unsafe_code)]

pub mod clipboard;
mod prompter;
pub mod session;
mod ui;

pub use clipboard::SystemClipboard;
pub use prompter::DesktopPrompter;
pub use session::{Request, Response, Session};
pub use ui::run;
