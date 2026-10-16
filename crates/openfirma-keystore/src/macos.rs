//! The macOS keychain (AutoFirma's `APPLE` keystore).
//!
//! Keychain identity lookup and signing is Security.framework: enumerate
//! identities with `SecIdentityCreateWithCopyDictionaryOfType`-style queries
//! (`kSecClassIdentity`), read each one's certificate with `SecIdentityCopyCertificate`,
//! and sign the digest with `SecKeyCreateSignature` using
//! `kSecKeyAlgorithmRSASignatureDigestPKCS1v15{SHA256,...}` — algorithms that,
//! exactly like PKCS#11's `CKM_SHAxxx_RSA_PKCS`, take the *digest* and return
//! the padded signature. Compiled only for `cfg(any(target_os = "macos",
//! target_os = "ios"))`; elsewhere it is absent and `--store macos` is a CLI
//! error.
//!
//! Like the Windows backend this hand-declares only the C symbols it calls, so
//! no Objective-C runtime bridge and no security-framework crate is needed —
//! everything used here is plain C FFI from `<Security/SecKey.h>` (ADR-0004).

#![cfg(any(target_os = "macos", target_os = "ios"))]

use std::ffi::c_void;
use std::ptr;

use openfirma_core::Result;
use openfirma_core::alg::DigestAlg;
use openfirma_core::error::Error;

use crate::store::{KeyHandle, StoreCertificate, SystemStore};

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    fn SecItemCopyMatching(query: *const c_void, result: *mut *mut c_void) -> i64; // OSStatus
    fn SecIdentityCopyCertificate(identity: *const c_void, cert: *mut *const c_void) -> i64;
    fn SecIdentityCopyPrivateKey(identity: *const c_void, key: *mut *const c_void) -> i64;
    fn SecKeyCreateSignature(
        key: *const c_void,
        algorithm: *const c_void,
        digest: *const c_void, // CFData of the digest
        error: *mut *mut c_void,
    ) -> *mut c_void; // CFData of the signature, NULL on failure
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFStringCreateWithCString(alloc: *const c_void, s: *const i8, encoding: u32) -> *mut c_void;
    fn CFDataCreate(alloc: *const c_void, bytes: *const u8, len: isize) -> *mut c_void;
    fn CFDataGetBytePtr(data: *const c_void) -> *const u8;
    fn CFDataGetLength(data: *const c_void) -> isize;
    fn CFRelease(cf: *const c_void);
}

/// A keychain of the current user. Identities (certificate + matching private
/// key pairs, which is exactly what `kSecClassIdentity` returns — the keychain
/// already applies the PKCS#11-style pairing rule for us) live in all
/// search-list keychains; no unlock prompt is needed to *list* them, and
/// `SecKeyCreateSignature` triggers the authorization dialog on first use per
/// key, which is macOS's intended PIN equivalent (see ADR-0004: --pin-env has
/// no meaning here).
pub struct MacStore;

impl MacStore {
    pub fn open() -> Result<Self> {
        Ok(Self)
    }
}

impl SystemStore for MacStore {
    fn certificates(&self) -> Result<Vec<StoreCertificate>> {
        Err(Error::Keystore(
            "the macOS keychain backend compiles on this target but its \
             Security.framework calls are unfinished: use --p12 or a PKCS#11 \
             module for now (ADR-0004, section 'what ships unfinished')"
                .into(),
        ))
    }

    fn sign_prehash(
        &self,
        cert: &StoreCertificate,
        alg: DigestAlg,
        prehash: &[u8],
    ) -> Result<Vec<u8>> {
        match &cert.key_handle {
            KeyHandle::MacApplicationTag(_) => {}
            #[allow(unreachable_patterns)]
            _ => {
                return Err(Error::Keystore(
                    "the macOS keychain was handed a key handle from another backend".into(),
                ));
            }
        }
        let _ = alg;
        let _ = prehash;
        Err(Error::Keystore(
            "the macOS keychain backend is not implemented on this build".into(),
        ))
    }
}

/// The `kSecKeyAlgorithmRSASignatureDigestPKCS1v15*` constants by digest, as
/// CFString names to hand SecKeyCreateSignature. Resolved lazily: these are
/// exported *symbols* whose value is a CFString, so their address is the
/// string object — fetching their addresses must happen after the framework
/// is loaded, hence OnceLock rather than link-time `dlsym` shuffling.
fn algorithm_for(digest: DigestAlg) -> Result<*const c_void> {
    // The names below are the public constant symbols (Security/SecKey.h); we
    // take their addresses as CFStringRef values.
    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        static kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1: c_void;
        static kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA224: c_void;
        static kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256: c_void;
        static kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384: c_void;
        static kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512: c_void;
    }
    Ok(match digest {
        DigestAlg::Sha1 => ptr::addr_of!(kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1).cast(),
        DigestAlg::Sha224 => ptr::addr_of!(kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA224).cast(),
        DigestAlg::Sha256 => ptr::addr_of!(kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256).cast(),
        DigestAlg::Sha384 => ptr::addr_of!(kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384).cast(),
        DigestAlg::Sha512 => ptr::addr_of!(kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512).cast(),
    })
}
