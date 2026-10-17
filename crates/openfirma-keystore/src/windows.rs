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
// import level: Win32's 32-bit exports carry their calling convention in the
// name, an undeclared extern asks the linker for a spelling that matches
// nothing, and on x86_64/aarch64 even the `__imp_` thunks differ per tooling.
// raw-dylib skips import libraries entirely: rustc writes the import itself,
// using exactly the symbol name the declaration resolves to — stable since
// 1.65 and what every modern Windows binding generator does, without adding
// a dependency beyond libloading (ADR-0004).
//
// Because rustc writes *that* name verbatim, the declaration is on the hook
// for what each DLL actually exports — and the loader checks it at process
// start, before a single test runs. That is exactly how the i686 job died:
// with STATUS_ENTRYPOINT_NOT_FOUND, naming nothing. Which spelling is right
// is per-DLL measured fact, not taste: crypt32 genuinely decorates its 32-bit
// exports (both CRYPT32.dll and every consumer of them — msvcrt-era link
// tables — read `CertOpenStore@20`), while advapi32.dll and ncrypt.dll export
// plain names on every architecture, so their blocks must say so with
// `import_name_type = "undecorated"` (windows-targets' raw-dylib macro passes
// exactly that for its x86 tables). Nothing about the ABI changes: these are
// all stdcall on x86 — the decoration was never wrong for *calling*, only as
// an import name. The two blocks below carry that key; crypt32 above does
// not, and that difference is load-or-die on i686.
//
// The loader's STATUS_ENTRYPOINT_NOT_FOUND named nothing (PE load failures
// never do), so the diagnosis came from reading the binary: a hand PE import
// dump of the test executable cross-checked against the DLLs' export strings,
// run in CI — five advapi32 names MISSING there, crypt32's table complete.
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

// ncrypt.dll and advapi32.dll export their names plain on every architecture
// — `NCryptFreeObject`, `CryptSignHashW`, no decoration (dumped from the i686
// runner's own System32) — so rustc must be told not to stdcall-decorate them
// when writing the import: without this, x86 resolves `extern "system"` names
// to `_CryptSignHashW@24` and the loader kills the process at startup with
// STATUS_ENTRYPOINT_NOT_FOUND, which is the bug this line fixes. crypt32's
// block above needs no key because that DLL really does export decorated
// names on 32-bit; the difference between the two blocks is measured fact,
// not taste — see the comment over there.
#[link(name = "ncrypt", kind = "raw-dylib", import_name_type = "undecorated")]
unsafe extern "system" {
    /// CNG signs (and stores its keys) through `NCrypt*` handles. A key that
    /// `CryptAcquireCertificatePrivateKey` returns with
    /// `CERT_NCRYPT_KEY_SPEC` is one of these — **not** an `HCRYPTPROV` — and
    /// must be freed through this family only. Mixing the handle families
    /// (feeding a CNG handle to `CryptCreateHash`, or releasing it with
    /// `CryptReleaseContext`) is undefined behavior, which is H-10; the
    /// branch in [`WindowsStore::sign_prehash`] is what refuses it until an
    /// `NCryptSignHash` signer exists. The declarations mirror the SDK
    /// headers: ncrypt.dll exports these as undecorated C names on every
    /// architecture, so raw-dylib resolves them like the crypt32 table.
    fn NCryptFreeObject(h_object: usize) -> u32;
}

// Undecorated like ncrypt: advapi32's exports are plain names on every
// architecture, and a decorated import is what made the 32-bit keystore test
// binary refuse to load at all (see the two comments above).
#[link(
    name = "advapi32",
    kind = "raw-dylib",
    import_name_type = "undecorated"
)]
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
/// Both flags below carry the SDK's values (`wincrypt.h`, mirrored by
/// windows-sys under Win32/Security/Cryptography): ALLOW is `0x00010000` and
/// PREFER `0x00020000` — finding A6.2, an earlier revision had `0x100` and
/// `0x200`, which CAPI ignores without complaining, so a CNG-only key (every
/// EC key on a modern machine, every minidriver card) stayed invisible.
const CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG: u32 = 0x0001_0000;
/// Prefer the CNG handle when a key exists in both stores. Kept deliberately
/// *off* on signing (see [`sign_prehash`]): openfirma's signer speaks PKCS#1
/// v1.5 through CAPI, and a CNG handle must go through `NCryptSignHash`, to
/// which we have no call path — passing it onward would hand an `NCRYPT
/// KEY_HANDLE` to functions expecting an `HCRYPTPROV`. Listing still passes
/// ALLOW so CNG-only keys (every EC key on a modern machine) are *seen*; the
/// handle is dropped immediately and signing refuses them by name.
const CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG: u32 = 0x0002_0000;
/// Never prompt the user, even for a smart card without a cached PIN. Listing
/// certificates must not ask anyone to unlock anything; without this flag a
/// PIN dialog can pop up per certificate while merely enumerating MY.
const CRYPT_ACQUIRE_SILENT_FLAG: u32 = 0x0000_0040;
/// `CERT_NCRYPT_KEY_SPEC`: what `pdwKeySpec` reports when the acquired handle
/// is a CNG key. The value must be checked before any CAPI call on the handle.
const CERT_NCRYPT_KEY_SPEC: u32 = 0xFFFF_FFFF;
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
            let (mut handle, mut spec, mut must_free) = (0usize, 0u32, 0i32);
            // SAFETY: `next` is a live store-owned context from the call
            // above; the out-pointers are locals alive across the call. The
            // returned handle's family depends on `spec`, and every one of
            // them is closed below before anything else can observe it:
            // CERT_NCRYPT_KEY_SPEC means CNG (`NCryptFreeObject`), anything
            // else a legacy CSP (`CryptReleaseContext`). SILENT keeps card
            // PINs from being demanded while merely listing.
            let ok = unsafe {
                CryptAcquireCertificatePrivateKey(
                    next,
                    CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_SILENT_FLAG,
                    ptr::null(),
                    &mut handle,
                    &mut spec,
                    &mut must_free,
                )
            };
            if ok == 0 {
                continue;
            }
            if must_free != 0 {
                // SAFETY: caller-must-free says the handle belongs to us, and
                // `spec` was just written by the same call that produced it.
                unsafe {
                    let freed = if spec == CERT_NCRYPT_KEY_SPEC {
                        NCryptFreeObject(handle) != 0
                    } else {
                        CryptReleaseContext(handle, 0) != 0
                    };
                    let _ = freed; // neither API reports much on a close path
                }
            }
            out.push(StoreCertificate {
                cert,
                label: None, // the friendly name needs cryptui-style property
                // reads; subject CN is what users actually compare here.
                key_handle: KeyHandle::WindowsStoreIndex(out.len()),
                // No equivalent of CKA_ALWAYS_AUTHENTICATE in the CryptoAPI
                // store index we read; A6 will revisit this with the NCrypt
                // path, where per-signature consent is a flag on the key.
                always_authenticate: false,
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
        // index in the handle records which entry of the listing this is (the
        // message on failure); finding A6.1: a context rebuilt from the DER
        // carries no CERT_KEY_PROV_INFO property — the key association is a
        // property of the *store's* contexts, so `CryptAcquireCertificatePrivateKey`
        // on a hand-made one answers CRYPT_E_NO_MATCH/NO_KEY_PROPERTY every
        // time. Re-enumerate MY and acquire on the store's own context; only
        // when the entry is no longer in the store (edited between listing
        // and signing) does the rebuilt context get tried, as a best effort.
        // The match is by DER bytes, never by position: the listing counts
        // only what it showed the user — certificates that failed to parse or
        // had no private key were skipped — so store position #n is not list
        // position #n whenever either list skipped anything.
        let der = cert.cert.der().to_vec();
        let owned =
            unsafe { CertCreateCertificateContext(ENCODINGS, der.as_ptr(), der.len() as u32) };
        if owned.is_null() {
            return Err(Error::Keystore(format!(
                "the certificate at Windows store index {i} is no longer a valid context"
            )));
        }
        let mut ctx = owned;
        let mut duplicate: *const CertContext = ptr::null();
        let mut probe: *const CertContext = ptr::null();
        loop {
            // SAFETY: the same enumeration contract as `certificates` — pass
            // back what the previous call returned, NULL ends it. The store's
            // contexts are owned by the store and live at least this long.
            probe = unsafe { CertEnumCertificatesInStore(self.store, probe) };
            if probe.is_null() {
                break;
            }
            let (ptr, len) =
                unsafe { ((*probe).pb_cert_encoded_info, (*probe).cb_cert_encoded_info) };
            let store_der = unsafe { std::slice::from_raw_parts(ptr, len as usize) };
            if store_der == der.as_slice() {
                // CertEnumCertificatesInStore's contract is "owned by the
                // enum": Rust 2024 makes that a dangling pointer the moment
                // this loop ends, so keep our own reference (the +1 refcount
                // `CertFindCertificateInStore` would hand out; freed after
                // the acquire below).
                duplicate = unsafe { CertDuplicateCertificateContext(probe) };
                if !duplicate.is_null() {
                    ctx = duplicate;
                }
                break;
            }
        }
        let mut handle = 0usize;
        let mut spec = 0u32;
        let mut must_free = 0i32;
        // SAFETY: `ctx` is non-null (the store's own context, or the freshly
        // created one); the out-pointers are locals alive across the call.
        // ALLOW (without PREFER) asks CAPI for the legacy provider when one
        // exists, which is what this signer can drive; a key that only
        // exists as CNG answers anyway — with CERT_NCRYPT_KEY_SPEC — and the
        // branch below refuses it rather than misusing the handle. No SILENT
        // here: signing is the moment the user may legitimately be asked for
        // their card PIN.
        let ok = unsafe {
            CryptAcquireCertificatePrivateKey(
                ctx,
                CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG,
                ptr::null(),
                &mut handle,
                &mut spec,
                &mut must_free,
            )
        };
        unsafe {
            // The duplicate's reference and the created one are ours to give
            // back; the store's context is freed by the store.
            if !duplicate.is_null() {
                CertFreeCertificateContext(duplicate);
            }
            CertFreeCertificateContext(owned);
        }
        if ok == 0 {
            return Err(Error::Keystore(
                "the private key for this certificate is no longer available".into(),
            ));
        }
        let result = if spec == CERT_NCRYPT_KEY_SPEC {
            // A CNG key. Signing it needs a whole NCryptSignHash path (with
            // the right BCRYPT_PKCS1_PADDING_INFO, and per-card decisions
            // about NCRYPT_SILENT_FLAG), which does not exist yet; refusing
            // here is honest, while continuing would feed an NCRYPT_KEY_HANDLE
            // to CryptCreateHash and free it with CryptReleaseContext — the
            // H-10 confusion. The listing saw the certificate because its key
            // exists; only signing it waits for the CNG signer.
            Err(Error::Keystore(
                "this certificate's private key lives in the CNG store, and \
                 openfirma's Windows signer drives legacy CSP providers only \
                 (PKCS#1 v1.5 via CryptSignHash); a card or key whose provider \
                 is CNG-only signs through its PKCS#11 interface instead"
                    .into(),
            ))
        } else {
            capi_sign_prehash(handle, spec, alg, prehash)
        };
        if must_free != 0 {
            // SAFETY: same handle/family pairing as the acquire above; the
            // CNG branch never signed anything with it, only refuses.
            unsafe {
                let freed = if spec == CERT_NCRYPT_KEY_SPEC {
                    NCryptFreeObject(handle) != 0
                } else {
                    CryptReleaseContext(handle, 0) != 0
                };
                let _ = freed; // the sign result is what the caller needs
            }
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
    /// Adds a reference to a certificate context and returns it. The store
    /// variants of the crypto provider functions need a context that belongs
    /// to a store, so signing takes its own reference on the listed one. Its
    /// import has existed in crypt32.dll since XP; `raw-dylib` resolves it at
    /// link time, which nothing here runs on a crypt32 lacking it would ever
    /// reach — the function has been in every supported Windows release.
    fn CertDuplicateCertificateContext(p_cert_context: *const CertContext) -> *const CertContext;
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
        // Read the error before CryptDestroyHash: that call can overwrite
        // GetLastError with whatever it hits on the way down, which used to
        // report someone else's failure code (H-10).
        let err = last_error(
            "CryptSetHashParam(HP_HASHVAL): this CSP will not sign a \
             caller-computed digest; its PKCS#11 interface is the way",
        );
        unsafe { CryptDestroyHash(hash) };
        return Err(err);
    }
    let mut len = 0u32;
    if unsafe { CryptSignHashW(hash, spec, ptr::null(), 0, ptr::null_mut(), &mut len) } == 0 {
        let err = last_error("CryptSignHash(size probe)");
        unsafe { CryptDestroyHash(hash) };
        return Err(err);
    }
    let mut sig = vec![0u8; len as usize];
    // CAPI returns little-endian signatures (the raw private-key operation);
    // CMS wants big-endian, so reverse before handing it over — same rule the
    // .NET RSACryptoServiceProvider formatter applies.
    if unsafe { CryptSignHashW(hash, spec, ptr::null(), 0, sig.as_mut_ptr(), &mut len) } == 0 {
        let err = last_error("CryptSignHash");
        unsafe { CryptDestroyHash(hash) };
        return Err(err);
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
