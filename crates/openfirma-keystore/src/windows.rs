//! The Windows certificate store (AutoFirma's `WINDOWS` keystore).
//!
//! Signing with a CAPI key works in three plain Win32 steps: enumerate the
//! store with `CertOpenStore`/`CertEnumCertificatesInStore`, match each
//! certificate to its private key with `CryptAcquireCertificatePrivateKey`,
//! and sign the digest with `CryptSignHash` on the acquired provider (the
//! hash-first CAPI path — the raw digest goes in, the padded signature comes
//! out, exactly like PKCS#11's `CKM_SHAxxx_RSA_PKCS`). This module is compiled
//! only for `cfg(target_os = "windows")`; on every other target it is absent,
//! and asking for `--store windows` there is a clean CLI error, never dead
//! code pretending to work.
//!
//! The FFI surface is hand-declared rather than pulled from `windows-sys` so
//! the dependency set this crate adds stays exactly `libloading` (ADR-0004);
//! only what openfirma touches is declared, field for field with the SDK's
//! headers. Why those declarations must be `kind = "raw-dylib"` blocks is
//! told where it bites: the comment on the first extern block below.

#![cfg(target_os = "windows")]

use std::ffi::c_void;
use std::ptr;

use openfirma_core::Result;
use openfirma_core::alg::DigestAlg;
use openfirma_core::cert::CertificateHandle;
use openfirma_core::error::Error;

use crate::store::{KeyHandle, StoreCertificate, SystemStore};

#[repr(C)]
#[derive(Clone, Copy)]
struct CertContext {
    dw_version: u32,
    pb_cert_encoded_info: *mut u8,
    cb_cert_encoded_info: u32,
}

// The blocks carry `kind = "raw-dylib"` because this is hand-written FFI and
// CI proved why it must: plain `#[link(name = ...)]` directives — thirteen of
// them, per item — linked in vain, link.exe reporting every symbol under
// `crypt32.lib`/`advapi32.lib` unresolved. The cause is decoration at the
// import level. Win32's 32-bit stdcall exports are name-mangled with their
// argument byte count (`CertOpenStore@10`, thunk `__imp_CertOpenStore@10`),
// while an undeclared extern fn has no signature for rustc to decorate with,
// so it asks the linker for the undecorated symbol — which is not what either
// import library actually contains (x86_64 exports are undecorated, but the
// aarch64/x86 jobs showed the same failure, because the *thunks* still do not
// match: rustc asks for `__imp_CertOpenStore`, crypt32.lib defines
// `__imp_CertOpenStore@10` on 32-bit; and on every architecture both requests
// are only half of what a raw extern block gets you — no `#[link_name]` was
// ever meant to cover an eleven-function hand table). raw-dylib skips import
// libraries entirely: rustc reads the export names out of the DLL at link
// time and emits the import itself. It has been stable since 1.65, it is what
// `windows-targets` relies on for exactly this class of symbol, and it keeps
// ADR-0004's promise of no dependency beyond libloading.
// raw-dylib solves it without any dependency: at link time rustc reads the
// real export names out of the DLL, resolves both the decorated form and the
// `__imp_` thunk, and emits the import itself (stable since 1.65). It is also
// what every modern Windows binding generator does for exactly this reason;
// taking `windows-sys` would only borrow the tool that writes those tables,
// against ADR-0004's decision to keep this crate at libloading only.
#[link(name = "crypt32", kind = "raw-dylib")]
unsafe extern "system" {
    fn CertOpenStore(
        lpsz_store_provider: *const u16,
        dw_msg_encoding_type: u32,
        h_crypto_provider: usize,
        dw_flags: u32,
        pv_para: *const u16,
    ) -> usize;
    fn CertCloseStore(h_cert_store: usize, dw_flags: u32) -> i32;
    fn CertEnumCertificatesInStore(
        h_cert_store: usize,
        p_prev_context: *const CertContext,
    ) -> *const CertContext;
    fn CryptAcquireCertificatePrivateKey(
        p_cert: *const CertContext,
        dw_flags: u32,
        pv_reserve: *const c_void,
        ph_prov_or_key: *mut usize,
        pdw_key_spec: *mut u32,
        pf_caller_must_free: *mut i32,
    ) -> i32;
}

#[link(name = "advapi32", kind = "raw-dylib")]
unsafe extern "system" {
    fn CryptGetHashParam(
        h_hash: usize,
        dw_param: u32,
        pb_data: *mut u8,
        pdw_data_len: *mut u32,
        dw_flags: u32,
    ) -> i32;
    fn CryptCreateHash(
        h_prov: usize,
        alg_id: u32,
        h_key: usize,
        dw_flags: u32,
        ph_hash: *mut usize,
    ) -> i32;
    fn CryptSetHashParam(h_hash: usize, dw_param: u32, pb_data: *const u8, dw_flags: u32) -> i32;
    fn CryptSignHashW(
        h_hash: usize,
        key_spec: u32,
        description: *const u16,
        flags: u32,
        pb_signature: *mut u8,
        pcb_signature: *mut u32,
    ) -> i32;
    fn CryptDestroyHash(h_hash: usize) -> i32;
    fn CryptReleaseContext(h_prov: usize, dw_flags: u32) -> i32;
}

/// `CERT_STORE_PROV_SYSTEM_W`, the provider name L"SYSTEM" that selects the
/// system certificate stores; and `CERT_SYSTEM_STORE_CURRENT_USER` combined
/// with it opens CURRENT_USER\MY — the store AutoFirma's `KC_WINDOWS` helper
/// uses (its AOKeyStoreType is literally named WINDOWS for this one).
fn cert_store_prov_system_w() -> *const u16 {
    static NAME: std::sync::OnceLock<Vec<u16>> = std::sync::OnceLock::new();
    NAME.get_or_init(|| "SYSTEM\0".encode_utf16().collect())
        .as_ptr()
}
const CERT_SYSTEM_STORE_CURRENT_USER: u32 = 0x0001_0000;
const CERT_STORE_READONLY_FLAG: u32 = 0x0000_8000;
/// `PKCS_7_ASN_ENCODING | X509_ASN_ENCODING` — the encodings a MY store uses.
const ENCODINGS: u32 = 0x0001_0001;
/// Ask CAPI for whichever provider backs the key, legacy CSP or smart card.
const CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG: u32 = 0x0000_0100;
const CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG: u32 = 0x0000_0200;
/// `HP_HASHVAL`: read the hash value back out of a hash object.
const HP_HASHVAL: u32 = 0x0002;
/// The CNG algorithm ids for the plain-SHA hash objects that carry a caller-
/// computed digest into CryptSignHash (CAPI has no "digest already" id, so we
/// create an empty hash object, set its value with HP_HASHVAL and sign it).
/// CALG ids for the hash objects that carry a caller-computed digest into
/// CryptSignHash (CAPI has no "digest already" id, so an empty hash object
/// gets its value set with HP_HASHVAL and is then signed).
fn calg_for(digest: DigestAlg) -> u32 {
    match digest {
        DigestAlg::Sha1 => 0x0000_8004,   // CALG_SHA1
        DigestAlg::Sha256 => 0x0000_800C, // CALG_SHA_256
        DigestAlg::Sha384 => 0x0000_800D, // CALG_SHA_384
        DigestAlg::Sha512 => 0x0000_800E, // CALG_SHA_512
        // No CALG_SHA_224 exists: no legacy CSP implements SHA-224.
        DigestAlg::Sha224 => unreachable!("checked by sign_prehash"),
    }
}

/// A handle on `CURRENT_USER\MY`. The store is kept open for the object's
/// lifetime because certificate contexts (and the friendly names read from
/// them) are only valid while their store is; `certificates()` caches owned
/// DER + label copies so signing afterwards never touches a stale context.
pub struct WindowsStore {
    store: usize,
}

impl WindowsStore {
    pub fn open() -> Result<Self> {
        let name: Vec<u16> = "MY\0".encode_utf16().collect();
        // SAFETY: `name` outlives the call; a null return is checked.
        let store = unsafe {
            CertOpenStore(
                cert_store_prov_system_w(),
                ENCODINGS,
                0,
                CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_READONLY_FLAG,
                name.as_ptr(),
            )
        };
        if store == 0 {
            return Err(Error::Keystore(
                "CryptOpenStore could not open CURRENT_USER\\MY".into(),
            ));
        }
        Ok(Self { store })
    }
}

impl Drop for WindowsStore {
    fn drop(&mut self) {
        unsafe { CertCloseStore(self.store, 0) };
    }
}

impl SystemStore for WindowsStore {
    fn certificates(&self) -> Result<Vec<StoreCertificate>> {
        let mut out = Vec::new();
        let mut ctx: *const CertContext = ptr::null();
        loop {
            // SAFETY: the enumeration contract — pass back what the previous
            // call returned; NULL ends it. Each context is owned by the store.
            let next = unsafe { CertEnumCertificatesInStore(self.store, ctx) };
            if next.is_null() {
                break;
            }
            ctx = next;
            let (ptr, len) =
                unsafe { ((*next).pb_cert_encoded_info, (*next).cb_cert_encoded_info) };
            let der = unsafe { std::slice::from_raw_parts(ptr, len as usize) };
            let Ok(cert) = CertificateHandle::from_der(der) else {
                continue;
            };
            // A certificate only belongs in the list when CAPI can find a
            // private key for it — the same rule as PKCS#11 pairing by CKA_ID.
            let (mut prov, mut spec, mut must_free) = (0usize, 0u32, 0i32);
            let ok = unsafe {
                CryptAcquireCertificatePrivateKey(
                    next,
                    CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG,
                    ptr::null(),
                    &mut prov,
                    &mut spec,
                    &mut must_free,
                )
            };
            if ok == 0 {
                continue;
            }
            if must_free != 0 {
                unsafe { CryptReleaseContext(prov, 0) };
            }
            out.push(StoreCertificate {
                cert,
                label: None, // the friendly name needs cryptui-style property
                // reads; subject CN is what users actually compare here.
                key_handle: KeyHandle::WindowsStoreIndex(out.len()),
                chain: Vec::new(),
            });
        }
        Ok(out)
    }

    fn sign_prehash(
        &self,
        cert: &StoreCertificate,
        alg: DigestAlg,
        prehash: &[u8],
    ) -> Result<Vec<u8>> {
        let i = match &cert.key_handle {
            KeyHandle::WindowsStoreIndex(i) => *i,
            #[allow(unreachable_patterns)]
            _ => {
                return Err(Error::Keystore(
                    "the Windows store was handed a key handle from another backend".into(),
                ));
            }
        };
        if matches!(alg, DigestAlg::Sha224) {
            // No CALG_SHA_224 exists; no legacy CSP can sign it.
            return Err(Error::UnsupportedCombination {
                key: "Windows CAPI",
                digest: alg.name(),
            });
        }
        // Re-acquire the provider for this certificate's key and sign. The
        // index in the handle selects position *i* of a fresh enumeration, so
        // that concurrent store edits surface as a clean re-find failure
        // instead of signing with a stale context.
        let der = cert.cert.der().to_vec();
        let mut prov = 0usize;
        let mut spec = 0u32;
        let mut must_free = 0i32;
        let ctx =
            unsafe { CertCreateCertificateContext(ENCODINGS, der.as_ptr(), der.len() as u32) };
        if ctx.is_null() {
            return Err(Error::Keystore(format!(
                "the certificate at Windows store index {i} is no longer a valid context"
            )));
        }
        let ok = unsafe {
            CryptAcquireCertificatePrivateKey(
                ctx,
                CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG,
                ptr::null(),
                &mut prov,
                &mut spec,
                &mut must_free,
            )
        };
        unsafe { CertFreeCertificateContext(ctx) };
        if ok == 0 {
            return Err(Error::Keystore(
                "the private key for this certificate is no longer available".into(),
            ));
        }
        let result = capi_sign_prehash(prov, spec, alg, prehash);
        if must_free != 0 {
            unsafe { CryptReleaseContext(prov, 0) };
        }
        result
    }
}

#[link(name = "crypt32", kind = "raw-dylib")]
unsafe extern "system" {
    fn CertCreateCertificateContext(
        dw_msg_encoding_type: u32,
        pb_cert_encoded: *const u8,
        cb_cert_encoded: u32,
    ) -> *const CertContext;
    fn CertFreeCertificateContext(p_cert_context: *const CertContext) -> i32;
}

/// Creates an empty hash object on `prov`, writes `prehash` into it as its
/// value, and asks CAPI to sign it. This is the documented "digest already
/// computed" dance for legacy CSPs (smart-card providers included — what a
/// DNIe card behind a CSP sees); smart-card CSPs ignore HP_HASHVAL writes on
/// some drivers, which is why errors here name CryptSetHashParam explicitly.
fn capi_sign_prehash(prov: usize, spec: u32, alg: DigestAlg, prehash: &[u8]) -> Result<Vec<u8>> {
    let mut hash = 0usize;
    if unsafe { CryptCreateHash(prov, calg_for(alg), 0, 0, &mut hash) } == 0 {
        return Err(last_error("CryptCreateHash"));
    }
    // HP_HASHVAL carries the digest into the object. The pointer is read-only
    // for CAPI on this parameter (it copies the value).
    if unsafe { CryptSetHashParam(hash, HP_HASHVAL, prehash.as_ptr() as *mut u8, 0) } == 0 {
        unsafe { CryptDestroyHash(hash) };
        return Err(last_error(
            "CryptSetHashParam(HP_HASHVAL): this CSP will not sign a \
             caller-computed digest; its PKCS#11 interface is the way",
        ));
    }
    let mut len = 0u32;
    if unsafe { CryptSignHashW(hash, spec, ptr::null(), 0, ptr::null_mut(), &mut len) } == 0 {
        unsafe { CryptDestroyHash(hash) };
        return Err(last_error("CryptSignHash(size probe)"));
    }
    let mut sig = vec![0u8; len as usize];
    // CAPI returns little-endian signatures (the raw private-key operation);
    // CMS wants big-endian, so reverse before handing it over — same rule the
    // .NET RSACryptoServiceProvider formatter applies.
    if unsafe { CryptSignHashW(hash, spec, ptr::null(), 0, sig.as_mut_ptr(), &mut len) } == 0 {
        unsafe { CryptDestroyHash(hash) };
        return Err(last_error("CryptSignHash"));
    }
    unsafe { CryptDestroyHash(hash) };
    sig.truncate(len as usize);
    sig.reverse();
    Ok(sig)
}

fn last_error(what: &str) -> Error {
    let code = std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or_default();
    Error::Keystore(format!("{what} failed with Win32 error {code:#010x}"))
}
