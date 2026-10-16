//! Certificate and key containers for openfirma.
//!
//! Two kinds of container exist in this crate and they are deliberately not
//! one abstraction. [`pkcs12`] reads a file you own: it decrypts the private
//! key into memory and hands back an `openfirma_core::signer::SoftwareSigner`.
//! [`store::SystemStore`] is a keystore that holds keys you cannot read — a
//! PKCS#11 token ([`pkcs11`]), the NSS shared database ([`nss`], which *is* a
//! PKCS#11 module), and on their own platforms the Windows certificate store
//! and the macOS keychain. A system store is asked to sign, never to hand
//! over a key; see docs/adr/0004-system-keystores.md for why both exist and
//! where the boundary sits.

pub mod nss;
pub mod pkcs11;
pub mod pkcs12;
mod store;

#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub mod macos;

pub use pkcs11::Pkcs11Store;
pub use pkcs12::Pkcs12;
pub use store::{KeyHandle, StoreCertificate, StoreSigner, SystemStore, boxed_signer};
