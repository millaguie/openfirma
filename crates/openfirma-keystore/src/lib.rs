//! Where certificates and private keys come from.
//!
//! Today that means PKCS#12 files, the container a real certificate arrives
//! in. The system stores come next, and they live here too: the NSS database
//! on Linux, the Windows-MY store, the macOS keychain. AutoFirma reaches them
//! through `afirma-core-keystores`, and its Java is the map of what each
//! platform actually offers.
//!
//! Everything in this crate is pure Rust. The one place that will bend is
//! PKCS#11, where the token vendor's shared library has to be loaded over FFI;
//! that bend deserves an ADR of its own before any code.

pub mod pkcs12;

pub use pkcs12::{Entry, Pkcs12};
