//! openfirma's window: one screen per job, the common path first, every
//! decision shared with the CLI through the library crates (docs/adr/0006-gui-toolkit.md).

pub mod app;
pub mod errors;
pub mod keystore_io;
pub mod signing;
pub mod strings;
pub mod tsa;
pub mod verdicts;
pub mod wizard;
