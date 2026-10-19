//! openfirma's window: one screen per job, the common path first, every
//! decision shared with the CLI through the library crates (docs/adr/0006-gui-toolkit.md).

pub mod app;
pub mod errors;
pub mod keystore_io;
pub mod palette;
pub mod signing;
pub mod strings;
pub mod tsa;
pub mod verdicts;
pub mod wizard;

/// The window's type under the name `main.rs` (and downstream tests) use:
/// one obvious entry point, re-exported from the module that owns it.
pub use app::App as OpenfirmaApp;
