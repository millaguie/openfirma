//! PKCS#11 backend: a token or software module loaded at runtime with
//! `dlopen`/`GetProcAddress`, driven through the v2.40 function list.
//!
//! There is no build-time dependency on any vendor library and no linkage
//! against a PKCS#11 import library: [`Pkcs11Store::open`] takes the module
//! path, loads it with `libloading`, calls the single exported symbol
//! `C_GetFunctionList`, and reads every entry point from the returned table.
//! That is what ADR-0004 decided and why — AutoFirma does the same through
//! SunPKCS11's native layer (`AOKeyStoreManagerHelperPkcs11` + jna), because
//! a PKCS#11 module is a plugin, not a library you link.

mod nss_args;
/// The v2.40 wire shapes, public so the ABI test suite (`tests/pkcs11_abi.rs`)
/// can assert their byte layout for whichever target CI compiles it on —
/// including the Windows jobs no live module can reach. Not openfirma's API:
/// nothing outside this crate should grow to depend on them.
pub mod types;

use std::cell::Cell;
use std::ffi::{CString, c_void};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use libloading::Library;

use openfirma_core::Result;
use openfirma_core::alg::DigestAlg;
use openfirma_core::cert::CertificateHandle;
use openfirma_core::error::Error;
use openfirma_core::tlv::{sequence, tlv};
use zeroize::{Zeroize, Zeroizing};

use super::store::{KeyHandle, StoreCertificate, SystemStore};
use types::*;

/// Move a Rust length into the C `unsigned long` world: identical on LP64,
/// saturating where C's type is narrower (Windows MSVC ABIs). Saturating —
/// rather than wrapping — means a pathological buffer can only make a module
/// answer with its own length error; it cannot silently sign fewer bytes than
/// asked. No reachable input ever saturates: PINs, templates and digests are
/// tiny, and `C_Sign`'s data is one digest or DigestInfo.
const fn ul(n: usize) -> CkUlong {
    // widened comparison so it stays honest (and clippy-clean) on both LP64,
    // where the types are the same width, and LLP64, where they are not.
    if (n as u128) > (CkUlong::MAX as u128) {
        CkUlong::MAX
    } else {
        n as CkUlong
    }
}

pub use nss_args::NssInitializeArgs;

/// How a module wants to be initialized. NSS's softokn3 reads its database
/// location from an NSS-shaped arguments struct; every other module takes
/// plain NULL (and would answer CKR_ARGUMENTS_BAD to anything else, which is
/// what the spec tells modules to do with library parameters they don't know).
#[derive(Clone, Copy, PartialEq, Eq)]
enum InitShape {
    Generic,
    /// libsoftokn3 / the FIPS module: initialize with an `NssInitializeArgs`
    /// whose `LibraryParameters` is the config string.
    Nss,
}

impl InitShape {
    fn name(self) -> &'static str {
        match self {
            InitShape::Generic => "a generic PKCS#11 module",
            InitShape::Nss => "an NSS database",
        }
    }
}

/// Everything one loaded module gives us: its mapped library (kept alive for
/// as long as anything can call into it — see `Module::drop`) and the raw
/// function-list pointer that library owns.
pub(crate) struct Module {
    /// Dropping this dlcloses the image; nothing may call `functions` after,
    /// which is why they live in the same struct and are handed out only as
    /// borrows tied to `&self`.
    /// Read nowhere but by `Drop` and the borrow rules of `Module::f`; the
    /// name is kept plain because it *is* the mapping that keeps `functions`
    /// valid. Clippy's never-read lint is satisfied by `keep_alive`, whose
    /// debug_assert proves the library is still mapped on every call path.
    #[allow(dead_code)]
    library: Library,
    functions: *const CkFunctionList,
}

// The registry hands `Arc<Module>` across threads deliberately: modules are
// process-global singletons that outlive every thread using them (entries are
// never removed while a store exists), and Cryptoki serializes the calls we
// make per session. Two threads signing on one token is supported by the
// spec for serial sessions on different...  no — simpler and true: each
// sign/list operation opens its own session, and a Session is !Sync, so an
// Arc<Module> crossing threads only shares immutable pointers and
// module-global calls that Cryptoki's "not parallel" note protects by design.
unsafe impl Send for Module {}
unsafe impl Sync for Module {}

impl Module {
    /// The table pointer itself, for the two slots handled outside the typed
    /// prefix (`C_GetSlotInfo`).
    fn raw_table(&self) -> *const c_void {
        self.functions.cast()
    }

    fn f(&self) -> &CkFunctionList {
        // SAFETY: `functions` points into the mapped image of `self.library`,
        // borrowed here for exactly `&self`'s lifetime; while `self` is alive
        // the library is mapped and the table valid. It must be a raw pointer
        // rather than a stored reference because Rust lifetimes cannot express
        // "valid exactly as long as the Library next to me is not dropped".
        unsafe { &*self.functions }
    }
}

impl Drop for Module {
    fn drop(&mut self) {
        // A PKCS#11 module is a poor candidate for unloading: NSS documents
        // that reloading its libraries within one process is not supported,
        // and several vendor modules are simply not unloadable. The registry
        // therefore keeps every loaded module alive for the whole process, so
        // this Drop runs only at process exit. If it ever runs earlier, the
        // dlclose happens here while no borrow of `functions` can exist (the
        // borrow in `Module::f` is tied to `&self`).
    }
}

/// Process-wide registry of loaded modules. Cryptoki's C_Initialize is a
/// per-library global and several API functions are explicitly "not parallel"
/// among applications (spec section 5.4; softokn3 enforces it with its fork
/// check), so two `Pkcs11Store` instances pointing at the same module must
/// share one initialized library — opening SoftHSM twice and finalizing from
/// one of them would tear the sessions out from under the other. A process
/// therefore keeps at most one live handle per (module path, init shape), and
/// CKR_CRYPTOKI_ALREADY_INITIALIZED is absorbed as success.
/// One registry entry: the module path it was loaded from, how it was
/// initialized, and the live handle.
type RegistryEntry = (PathBuf, InitShape, Arc<Module>);

static MODULES: OnceLock<Mutex<Vec<RegistryEntry>>> = OnceLock::new();

fn registry() -> &'static Mutex<Vec<RegistryEntry>> {
    MODULES.get_or_init(|| Mutex::new(Vec::new()))
}

/// A PKCS#11 keystore: one token in one module. The PIN is held for the
/// store's lifetime because signing may happen long after listing, and the
/// token needs nothing beyond a login — exactly what `--pin-env` hands us
/// (see docs/adr/0004-system-keystores.md on where the PIN comes from).
pub struct Pkcs11Store {
    module: Arc<Module>,
    slot: CkSlotId,
    token_label: String,
    pin: Option<Zeroizing<String>>,
}

impl Pkcs11Store {
    /// Loads `module_path` (or reuses this process's handle for it) and picks
    /// the token whose label matches `token` when given, otherwise the first
    /// slot with a token present. `pin`, if any, is used for login at sign
    /// time; listing certificates never logs in.
    /// The PIN is checked at open time, not deferred to the first document:
    /// a wrong PIN is an action-worthy failure while the user still has the
    /// reader in hand. Listing itself never needs it (certificates are public
    /// unless the token hides everything), but logging in on `open` proves the
    /// credentials and reveals what a no-login listing cannot see.
    pub fn open(module_path: &Path, token: Option<&str>, pin: Option<String>) -> Result<Self> {
        let with_login = pin.is_some();
        Self::open_with(
            module_path,
            token,
            // The PIN is a secret of the same order as a PKCS#12 password and
            // lives as long as the store does (a token may sign long after
            // listing), so it enters Zeroizing at the door: from here every
            // copy zeroes when dropped. The plain Option<String> signature
            // stays because that is what `--pin-env` hands us, and the last
            // unprotected moment should be the variable's own buffer, not a
            // store field.
            pin.map(Zeroizing::new),
            InitShape::Generic,
            None,
            with_login,
        )
    }

    /// The NSS-shaped variant of [`Pkcs11Store::open`]: loads `module_path`
    /// (typically libsoftokn3.so / nss3.dll) and initializes it with the
    /// softokn3 config string in `db`. A bare database location (`sql:...`,
    /// a path, or either with a `~`) is wrapped into the `configDir='...'`
    /// form here; anything else — a full parameter string — must already be
    /// exactly what softokn3's parser wants and travels verbatim.
    pub fn open_nss(
        module_path: &Path,
        db: &str,
        token: Option<&str>,
        pin: Option<String>,
    ) -> Result<Self> {
        let pin = pin.map(Zeroizing::new);
        // Two defaults have to be overridden for the private-key database, so
        // an unqualified `--store nss` does the right thing (AutoFirma's NSS
        // helper works this way too — it points SunPKCS11 at the cert DB):
        // - The first token slot is NSS's *generic crypto* module: no
        //   certificates, and it refuses a user login outright
        //   (CKR_USER_TYPE_INVALID, measured). The certificate database is
        //   named "NSS Certificate DB" ("NSS FIPS User Keys" under FIPS mode);
        //   try those names when the caller did not name one.
        // - An empty PIN means "no password" *only after* logging in: softokn3
        //   hides every object of a logged-in token from sessions that have
        //   not authenticated, so listing needs the same login signing does.
        let db = crate::nss::config_string(db)?;
        let defaults_tried = [None, Some("NSS Certificate DB"), Some("NSS FIPS User Keys")];
        let mut last: Option<Error> = None;
        for want in defaults_tried {
            if want.is_some() && token.is_some() {
                break; // the caller named a token; their choice stands as-is
            }
            match Self::open_with(
                module_path,
                token.or(want),
                pin.clone(),
                InitShape::Nss,
                Some(&db),
                true,
            ) {
                Ok(store) => return Ok(store),
                Err(e) => last = Some(e),
            }
        }
        Err(last.expect("the None attempt always runs"))
    }

    /// The label of the token this store talks to, blank-padding trimmed.
    pub fn token_label(&self) -> &str {
        &self.token_label
    }

    fn open_with(
        module_path: &Path,
        token: Option<&str>,
        pin: Option<Zeroizing<String>>,
        init: InitShape,
        library_parameters: Option<&str>,
        login_up_front: bool,
    ) -> Result<Self> {
        let module = process_module(module_path, init, library_parameters)?;
        let slots = slots_with_tokens(&module)?;
        if slots.is_empty() {
            return Err(Error::Keystore(format!(
                "{} has no slot with a token present",
                module_path.display()
            )));
        }
        // Token label matching happens per slot; a wrong choice must name the
        // labels that were actually found, so collect them first.
        let mut found: Vec<(CkSlotId, String)> = Vec::new();
        for slot in slots {
            let info = token_info(&module, slot)?;
            found.push((slot, blank_padded(&info.label).to_string()));
        }
        let (slot, token_label) = match token {
            Some(want) => found
                .iter()
                .find(|(_, label)| label == want)
                .map(|(slot, label)| (*slot, label.clone()))
                .ok_or_else(|| {
                    Error::Keystore(format!(
                        "no token labeled '{want}' in {}; tokens present: {}",
                        module_path.display(),
                        found
                            .iter()
                            .map(|(_, l)| format!("'{l}'"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ))
                })?,
            None => found.into_iter().next().expect("checked non-empty above"),
        };
        let store = Self {
            module,
            slot,
            token_label,
            pin,
        };
        if login_up_front {
            // Fail early and where the user can act on it: a wrong or locked
            // PIN is reported with the token's own flags (see `login`). NSS
            // opens here too, because listing must see the private objects.
            let session = Session::open(&store.module, store.slot)?;
            store.login(&session)?;
        }
        Ok(store)
    }

    fn login(&self, session: &Session) -> Result<()> {
        // The CString is a second copy of the secret (C_Login wants a C
        // string), so its bytes are zeroed by hand after the call: zeroize's
        // Zeroizing only covers types that implement DefaultIsZeroes, which
        // CString does not, and `as_bytes_mut` is exactly what makes the
        // buffer writable again for that purpose.
        let pin = match &self.pin {
            Some(p) => CString::new(p.as_str())
                .map_err(|_| Error::Keystore("the PIN contains a NUL byte".into()))?,
            // No PIN given: ask for an explicit, interaction-free login. A
            // token configured with no PIN accepts this; one that needs a PIN
            // answers CKR_USER_NOT_LOGGED_IN / CKR_PIN_INCORRECT and the hint
            // in rv_hint points at --pin-env. NSS's own rule is that a NULL
            // PIN means "no password", which is exactly the shared-DB case.
            None => CString::default(),
        };
        let rv = (self.module.f().login)(
            session.handle,
            CKU_USER,
            pin.as_ptr() as *mut u8,
            ul(pin.as_bytes().len()),
        );
        // Zero the FFI copy on every path out of the call, success included;
        // into_bytes takes the buffer out so nothing can read it afterwards.
        pin.into_bytes().zeroize();
        if rv == CKR_OK || rv == CKR_USER_ALREADY_LOGGED_IN {
            return Ok(());
        }
        // Before blaming the PIN, read what the token says about it: a locked
        // or final-try PIN deserves its own message (CKR_PIN_LOCKED only comes
        // from C_Login after the lock already tripped; the flags are how a
        // warning arrives *before* the last try). SoftHSM and OpenSC both set
        // these on C_GetTokenInfo.
        let flags = token_info(&self.module, self.slot)?.flags;
        if flags & CKF_USER_PIN_LOCKED != 0 {
            return Err(Error::Keystore(format!(
                "the user PIN of token '{}' is locked — unlock it with the token's \
                 administration tool (softhsm2-util, pkcs11-tool)",
                self.token_label
            )));
        }
        let mut msg = format!(
            "logging into token '{}' failed: {}",
            self.token_label,
            describe(rv)
        );
        if flags & CKF_USER_PIN_FINAL_TRY != 0 {
            msg.push_str(" — this was the last try before the PIN locks itself");
        } else if flags & CKF_USER_PIN_COUNT_LOW != 0 {
            msg.push_str(" — the token reports only a few tries left before locking");
        }
        if !rv_hint(rv).is_empty() {
            msg.push_str(" — ");
            msg.push_str(rv_hint(rv));
        }
        Err(Error::Keystore(msg))
    }
}

impl SystemStore for Pkcs11Store {
    fn certificates(&self) -> Result<Vec<StoreCertificate>> {
        let session = Session::open(&self.module, self.slot)?;
        let mut certs = list_in_session(&session)?;
        if certs.is_empty() && !session.saw_any_certificate.get() {
            // Nothing visible at all (not even certificates): this token hides
            // its objects until someone logs in. SoftHSM and many real tokens
            // do exactly this for private key objects, and OpenSC's enumeration
            // logs in before listing for the same reason. If no PIN was given
            // the failure must say so rather than report an empty store.
            if self.pin.is_some() {
                self.login(&session)?;
                certs = list_in_session(&session)?;
            } else if !list_any_certificates(&session)? {
                return Err(Error::Keystore(format!(
                    "token '{}' shows no certificates without a login: pass \
                     --pin-env VAR with the environment variable holding its PIN",
                    self.token_label
                )));
            }
        } else if certs.is_empty() && self.pin.is_some() {
            // Certificates were public but no key paired with one — still the
            // hidden-keys case whenever a login could reveal them.
            self.login(&session)?;
            certs = list_in_session(&session)?;
        }
        Ok(certs)
    }

    fn sign_prehash(
        &self,
        cert: &StoreCertificate,
        alg: DigestAlg,
        prehash: &[u8],
    ) -> Result<Vec<u8>> {
        // Other targets have no other variants, so this only compiles into
        // the multi-variant check where more than one backend exists.
        let id = match &cert.key_handle {
            KeyHandle::Pkcs11Id(id) => id.clone(),
            #[allow(unreachable_patterns)]
            _ => {
                return Err(Error::Keystore(
                    "a PKCS#11 store was handed a key handle from another backend".into(),
                ));
            }
        };
        let session = Session::open(&self.module, self.slot)?;
        self.login(&session)?;
        sign_with_key(&session, &id, alg, prehash)
    }
}

/// The slots that currently report a token present: `C_GetSlotList` with
/// `CK_TRUE`, then filtered through `C_GetSlotInfo`'s `CKF_TOKEN_PRESENT`.
/// The filter is skipped when the module stubs `C_GetSlotInfo` — NSS's
/// softokn3 answers CKR_FUNCTION_CANCELED for it (probed), and its
/// token-present list from `CK_TRUE` is already exact. A slot that fails the
/// info call with any other error is skipped, not fatal: a reader without its
/// card must not stop a software token in another slot from being found.
fn slots_with_tokens(module: &Module) -> Result<Vec<CkSlotId>> {
    let has_slot_info = !slot_info_ptr(module).is_null();
    let mut count: CkUlong = 0;
    check(
        (module.f().get_slot_list)(1, std::ptr::null_mut(), &mut count),
        "C_GetSlotList",
    )?;
    let mut slots = vec![0 as CkSlotId; count as usize];
    check(
        (module.f().get_slot_list)(1, slots.as_mut_ptr(), &mut count),
        "C_GetSlotList",
    )?;
    slots.truncate(count as usize);
    if !has_slot_info {
        return Ok(slots);
    }
    let mut with_tokens = Vec::new();
    for slot in slots {
        let mut info = CkSlotInfo::default();
        // SAFETY: get_slot_info was checked non-null above; transmuting a
        // void* into its declared extern "C" signature is justified by the
        // PKCS#11 v2.40 table layout (offset 48 == C_GetSlotInfo).
        let call: extern "C" fn(CkSlotId, *mut CkSlotInfo) -> CkRv =
            unsafe { std::mem::transmute_copy(&slot_info_ptr(module)) };
        let rv = call(slot, &mut info);
        if rv == CKR_OK && info.flags & CKF_TOKEN_PRESENT != 0 {
            with_tokens.push(slot);
        }
    }
    Ok(with_tokens)
}

/// Raw access to the `C_GetSlotInfo` slot: NSS's softokn3 leaves it null in
/// its v2 list (its real v3 table carries C_CancelFunction there and refuses
/// the call anyway), so a partial-table reader must treat null as
/// "unsupported" rather than call through it — unlike the functions openfirma
/// requires, which `load_and_init` checks.
fn slot_info_ptr(module: &Module) -> *const c_void {
    // Read the pointer stored in slot 6 of the table (byte offset 48): no
    // dereference at all — `add` walks the array, `read` copies the entry.
    unsafe { (module.raw_table().cast::<*const c_void>()).add(6).read() }
}

/// Loads (or reuses) the process-wide handle for one module and makes sure it
/// is initialized. Fetching the function list before C_Initialize matches
/// what every module tested here expects: NSS documents reading the version
/// from the list first, and the symbol is a pure getter everywhere.
fn process_module(
    path: &Path,
    init: InitShape,
    library_parameters: Option<&str>,
) -> Result<Arc<Module>> {
    let mut reg = registry()
        .lock()
        .map_err(|_| Error::Keystore("the module registry was poisoned".into()))?;
    if let Some((_, shape, module)) = reg.iter().find(|(p, _, _)| p == path) {
        // Already loaded by an earlier store in this process — Cryptoki's
        // one-initialization-per-library rule makes the *library* the unit of
        // sharing, not the (path, shape) pair. Asking for it under a different
        // init shape afterwards is a programming error: the first caller's
        // C_Initialize already decided how this library was configured.
        if *shape != init {
            return Err(Error::Keystore(format!(
                "{} is already initialized in this process as {} and cannot be \
                 reopened as {}",
                path.display(),
                shape.name(),
                init.name()
            )));
        }
        return Ok(module.clone());
    }
    let module = Arc::new(load_and_init(path, init, library_parameters)?);
    reg.push((path.to_path_buf(), init, module.clone()));
    Ok(module)
}

fn load_and_init(path: &Path, init: InitShape, library_parameters: Option<&str>) -> Result<Module> {
    let library = unsafe { Library::new(path) }.map_err(|e| {
        Error::Keystore(format!(
            "cannot load PKCS#11 module {}: {e}. Pass the full path to the \
             vendor's module file (libsoftokn3.so, opensc-pkcs11.so, \
             aetap11.dll, ...)",
            path.display()
        ))
    })?;
    let get_list: libloading::Symbol<extern "C" fn(*mut *const c_void) -> CkRv> =
        unsafe { library.get(b"C_GetFunctionList\0") }.map_err(|e| {
            Error::Keystore(format!(
                "{} is not a PKCS#11 module: it exports no C_GetFunctionList ({e})",
                path.display()
            ))
        })?;
    let mut list: *const c_void = std::ptr::null_mut();
    check(get_list(&mut list), "C_GetFunctionList")?;
    if list.is_null() {
        return Err(Error::Keystore(format!(
            "{} returned a null function list",
            path.display()
        )));
    }
    let functions: *const CkFunctionList = list.cast();

    // The version pair travels in slot 0 of the same table. A module at 3.x
    // hands back a CK_FUNCTION_LIST_3_x whose prefix is identical (spec 4.12),
    // so anything >= 2.0 may be read as our layout; below that, refuse before
    // calling anything.
    let version = unsafe { (*functions).version };
    if version.major < 2 || std::env::var_os("OPENFIRMA_FORCE_OLD_VERSION_REJECTION").is_some() {
        // The environment override exists only so tests/pkcs11.rs can execute
        // this refusal branch on CI against a real module (a genuinely pre-2.0
        // module is otherwise impossible to ship in a test).
        return Err(Error::Keystore(format!(
            "{} reports PKCS#11 {}.{} and openfirma speaks 2.40",
            path.display(),
            version.major,
            version.minor
        )));
    }

    // Guard against a module whose table is shorter or differently shaped
    // than the prefix we declare, in the only way possible without calling
    // into it: every entry point we call must be non-null. v2.x requires
    // absent functions to be stubs rather than null, and NSS's 3.x lists keep
    // that promise for the whole v2 prefix, so a null here means the table is
    // not what its version claims — including the classic mislayout case, a
    // table read at six-byte displacement whose "slots" are version bytes and
    // garbage. Each slot is located through `function_slot_offset`, derived
    // from this target's ABI (and, for LP64, from the very field offsets
    // `types.rs` pins down), so the probe reads exactly what a call would
    // read — including Windows' packed table, where slots do not sit on
    // multiples of 8 and must be read unaligned.
    let called: [(*const c_void, &str); 12] = unsafe {
        let base = list.cast::<u8>();
        let slot = |k| (base.add(function_slot_offset(k)) as *const *const c_void).read_unaligned();
        [
            (slot(1), "C_Initialize"),
            (slot(5), "C_GetSlotList"),
            (slot(7), "C_GetTokenInfo"),
            (slot(13), "C_OpenSession"),
            (slot(14), "C_CloseSession"),
            (slot(19), "C_Login"),
            (slot(25), "C_GetAttributeValue"),
            (slot(27), "C_FindObjectsInit"),
            (slot(28), "C_FindObjects"),
            (slot(29), "C_FindObjectsFinal"),
            (slot(43), "C_SignInit"),
            (slot(44), "C_Sign"),
        ]
    };

    for (ptr, name) in called {
        if ptr.is_null() {
            return Err(Error::Keystore(format!(
                "the PKCS#11 function list of {} has no {name} — its table is \
                 not the v2.x layout openfirma expects",
                path.display()
            )));
        }
    }

    // Sanity-check what came back before calling any of it, in the only way
    // that works without entering the module: a table parsed at the wrong
    // offsets (the C1/H-4 family: packing or ulong-width disagreement between
    // this crate and the DLL) *looks* plausible — every slot reads as some
    // pointer into the DLL's image — but its version pair stops being 2/40.
    // A pre-packed read of a naturally aligned table (or the reverse) puts
    // two bytes of function code where `major` should be, and no real module
    // starts with those bytes as a version. Refuse the module by name instead
    // of calling through a displaced table: this is the runtime twin of the
    // compile-time assertions in types.rs, and it fires on whatever the first
    // call below would have been — C_Initialize, exactly what PDFiumPas's
    // load-time check does for the same reason.
    {
        let version = unsafe { (*functions).version };
        if !(2..=3).contains(&version.major) || version.minor > 99 {
            return Err(Error::Keystore(format!(
                "{} returns a function list whose version pair is {}.{} — that \
                 is not a v2.x table read at the right offsets (this build's \
                 PKCS#11 ABI does not match this module's)",
                path.display(),
                version.major,
                version.minor
            )));
        }
    }

    // Initialize once per process for this library. The parameters must
    // outlive the call: they point into `params`/`args` below.
    let params = library_parameters
        .map(CString::new)
        .transpose()
        .map_err(|_| Error::Keystore("the NSS database location contains a NUL byte".into()))?;
    let args = match (&init, &params) {
        (InitShape::Nss, Some(p)) => Some(NssInitializeArgs::new(p.as_ptr().cast::<u8>())),
        _ => None,
    };
    let init_ptr: *mut c_void = match &args {
        Some(a) => std::ptr::from_ref(a).cast_mut().cast(),
        None => std::ptr::null_mut(),
    };
    // SAFETY: `functions` was checked non-null, versioned >= 2.0, and the
    // initialize slot non-null above; `init_ptr` matches what `init` says the
    // module expects (NULL for generic modules — spec-permitted — or our
    // NssInitializeArgs whose layout was verified against live softokn3).
    let rv = unsafe { (*functions).initialize }(init_ptr);
    if rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED {
        return Err(Error::Keystore(format!(
            "C_Initialize on {} failed: {}",
            path.display(),
            describe(rv)
        )));
    }

    Ok(Module { library, functions })
}

/// A read-only session on a slot's token, closed on drop. Sessions are cheap
/// and per-operation here: holding one open between user interactions would
/// fight the tokens (and tests) that allow only a handful.
struct Session<'m> {
    module: &'m Module,
    handle: CkSessionHandle,
    /// Set by the last `list_in_session`: whether any certificate object was
    /// visible then. Distinguishes "token shows nothing without a login" from
    /// "certificates exist but none paired with a key". A Cell because listing
    /// takes &self while this is pure session-local bookkeeping.
    saw_any_certificate: Cell<bool>,
}

impl Session<'_> {
    fn set_saw_certificates(&self, saw: bool) {
        self.saw_any_certificate.set(saw);
    }
}

impl<'m> Session<'m> {
    fn open(module: &'m Module, slot: CkSlotId) -> Result<Self> {
        let mut handle: CkSessionHandle = 0;
        check(
            (module.f().open_session)(
                slot,
                CKF_SERIAL_SESSION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut handle,
            ),
            "C_OpenSession",
        )?;
        Ok(Self {
            module,
            handle,
            saw_any_certificate: Cell::new(false),
        })
    }

    fn find(&self, template: &[FindTemplate]) -> Result<Vec<CkObjectHandle>> {
        // The CK_ATTRIBUTE array borrows the value storage kept inside
        // `template`; both are locals alive across the whole find below.
        let mut tmpl: Vec<CkAttribute> = template.iter().map(CkAttribute::from).collect();
        check(
            (self.module.f().find_objects_init)(self.handle, tmpl.as_mut_ptr(), ul(tmpl.len())),
            "C_FindObjectsInit",
        )?;
        let mut objects = Vec::new();
        loop {
            let mut batch = [0 as CkObjectHandle; 32];
            let mut count: CkUlong = 0;
            let rv = (self.module.f().find_objects)(
                self.handle,
                batch.as_mut_ptr(),
                ul(batch.len()),
                &mut count,
            );
            if rv != CKR_OK {
                // The search must be abandoned explicitly before the error is
                // surfaced, or the next operation on this session inherits it.
                (self.module.f().find_objects_final)(self.handle);
                return Err(session_error("C_FindObjects", rv));
            }
            objects.extend_from_slice(&batch[..count as usize]);
            // count is the module's answer (CkUlong); compare at its width.
            if (count as usize) < batch.len() {
                break;
            }
        }
        check(
            (self.module.f().find_objects_final)(self.handle),
            "C_FindObjectsFinal",
        )?;
        Ok(objects)
    }

    /// Reads one variable-length attribute, sizing it first the documented
    /// two-call way (NULL value buffer to learn the length). Attributes that
    /// report `CK_UNAVAILABLE_INFORMATION` are reported as missing.
    fn attribute(&self, object: CkObjectHandle, attr: CkUlong) -> Result<Option<Vec<u8>>> {
        let mut tmpl = [CkAttribute {
            type_: attr,
            p_value: std::ptr::null_mut(),
            ul_value_len: 0,
        }];
        let rv = (self.module.f().get_attribute_value)(self.handle, object, tmpl.as_mut_ptr(), 1);
        if rv == CKR_ATTRIBUTE_SENSITIVE || rv == CKR_ATTRIBUTE_TYPE_INVALID {
            return Ok(None);
        }
        check(rv, "C_GetAttributeValue")?;
        // The length slot now holds what the module learned (C wrote back into
        // it through the template).
        let len = tmpl[0].ul_value_len;
        if len == CK_UNAVAILABLE_INFORMATION {
            return Ok(None);
        }
        if len > 1 << 20 {
            // A certificate is not a megabyte; a bogus length must not become
            // an allocation.
            return Err(Error::Keystore(format!(
                "PKCS#11 attribute {attr:#x} reported an implausible length ({len})"
            )));
        }
        let mut buf = vec![0u8; len as usize];
        let mut tmpl = [CkAttribute {
            type_: attr,
            p_value: buf.as_mut_ptr().cast(),
            ul_value_len: len,
        }];
        check(
            (self.module.f().get_attribute_value)(self.handle, object, tmpl.as_mut_ptr(), 1),
            "C_GetAttributeValue",
        )?;
        buf.truncate(tmpl[0].ul_value_len.min(len) as usize);
        Ok(Some(buf))
    }

    fn ulong(&self, object: CkObjectHandle, attr: CkUlong) -> Result<Option<CkUlong>> {
        // A fixed-width attribute read in one call. The buffer must be a real
        // CkUlong for the module to write into.
        let mut value: CkUlong = 0;
        let mut tmpl = [CkAttribute {
            type_: attr,
            p_value: std::ptr::from_mut(&mut value).cast(),
            ul_value_len: ul(std::mem::size_of::<CkUlong>()),
        }];
        let rv = (self.module.f().get_attribute_value)(self.handle, object, tmpl.as_mut_ptr(), 1);
        if rv == CKR_ATTRIBUTE_SENSITIVE || rv == CKR_ATTRIBUTE_TYPE_INVALID {
            return Ok(None);
        }
        check(rv, "C_GetAttributeValue")?;
        // C writes back the attribute's size (or UNAVAILABLE) through the
        // length slot; anything other than a full ulong means this object does
        // not carry the attribute.
        if tmpl[0].ul_value_len != ul(std::mem::size_of::<CkUlong>()) {
            return Ok(None);
        }
        Ok(Some(value))
    }
}

impl Drop for Session<'_> {
    fn drop(&mut self) {
        // Best effort on purpose: there is no caller to hand an error to, and
        // a failed close leaks at most one session.
        (self.module.f().close_session)(self.handle);
    }
}

/// A find-template entry that owns the value storage a real `CK_ATTRIBUTE`
/// must point at while FindObjectsInit runs. The variants keep their bytes on
/// the heap (Box/Vec), so the pointers handed to the module stay valid for the
/// whole find even though `CkAttribute` values are rebuilt and moved around.
///
/// The variant carries the *attribute type* it stands for — class or id —
/// because that is exactly what every template in this crate is; there is no
/// "any ulong" pretending to know its own tag.
enum FindTemplate {
    Class(Box<CkUlong>),
    Id(Vec<u8>),
}

impl FindTemplate {
    fn class(value: CkUlong) -> Self {
        FindTemplate::Class(Box::new(value))
    }

    fn id(value: Vec<u8>) -> Self {
        FindTemplate::Id(value)
    }
}

impl From<&FindTemplate> for CkAttribute {
    fn from(t: &FindTemplate) -> Self {
        // The type tags are fixed here because every template built in this
        // crate is one of these two; validity lives on FindTemplate's docs.
        match t {
            FindTemplate::Class(v) => CkAttribute {
                type_: CKA_CLASS,
                p_value: std::ptr::from_ref(v.as_ref()).cast_mut().cast(),
                ul_value_len: ul(std::mem::size_of::<CkUlong>()),
            },
            FindTemplate::Id(b) => CkAttribute {
                type_: CKA_ID,
                p_value: b.as_ptr().cast_mut().cast(),
                ul_value_len: ul(b.len()),
            },
        }
    }
}

fn token_info(module: &Module, slot: CkSlotId) -> Result<CkTokenInfo> {
    let mut info = CkTokenInfo::default();
    check(
        (module.f().get_token_info)(slot, &mut info),
        "C_GetTokenInfo",
    )?;
    Ok(info)
}

/// Lists certificates that have a signable private key on the same token,
/// paired by `CKA_ID` — what AutoFirma's PKCS#11 helper and OpenSC both do.
/// True when the token exposes at least one certificate object right now.
fn list_any_certificates(session: &Session) -> Result<bool> {
    Ok(!session
        .find(&[FindTemplate::class(CKO_CERTIFICATE)])?
        .is_empty())
}

fn list_in_session(session: &Session) -> Result<Vec<StoreCertificate>> {
    // Certificates first: on tokens with a public-object policy they need no
    // login at all; where they do, the caller logs in and asks again.
    let cert_objects = session.find(&[FindTemplate::class(CKO_CERTIFICATE)])?;
    session.set_saw_certificates(!cert_objects.is_empty());
    let mut key_ids: Vec<Vec<u8>> = Vec::new();
    for key_object in session.find(&[FindTemplate::class(CKO_PRIVATE_KEY)])? {
        if let Some(id) = session.attribute(key_object, CKA_ID)? {
            key_ids.push(id);
        }
    }

    let mut out = Vec::new();
    for object in cert_objects {
        match session.ulong(object, CKA_CERTIFICATE_TYPE)? {
            // CKC_X_509 (or no type at all, which some minimal modules give):
            // anything else — attribute certificates, WTLS — cannot be
            // embedded in a CMS as X.509.
            Some(CKC_X_509) | None => {}
            Some(other) => {
                tracing::debug!(
                    certificate_type = other,
                    "skipping non-X.509 certificate object"
                );
                continue;
            }
        }
        let Some(der) = session.attribute(object, CKA_VALUE)? else {
            tracing::debug!("certificate object carries no CKA_VALUE");
            continue; // no value = nothing to sign or embed
        };
        let Ok(cert) = CertificateHandle::from_der(&der) else {
            tracing::debug!("skipping unparseable certificate object on the token");
            continue;
        };
        // Pairing rule: the key must carry the same CKA_ID as the certificate.
        let Some(id) = session.attribute(object, CKA_ID)? else {
            tracing::warn!(
                subject = %cert.subject(),
                "a certificate on the token has no CKA_ID and cannot be paired \
                 with a private key; report this to the token vendor"
            );
            continue;
        };
        if !key_ids.contains(&id) {
            tracing::debug!(
                subject = %cert.subject(),
                "certificate on the token has no private key with a matching CKA_ID"
            );
            continue;
        }
        let label = session
            .attribute(object, CKA_LABEL)?
            .and_then(|b| String::from_utf8(b).ok())
            .map(|s| s.trim_end().to_string())
            .filter(|s| !s.is_empty());
        out.push(StoreCertificate {
            cert,
            label,
            key_handle: KeyHandle::Pkcs11Id(id),
            chain: Vec::new(), // see StoreCertificate::chain on why this stays empty
        });
    }
    Ok(out)
}

/// Signs `prehash` with the private key whose CKA_ID is `key_id`. The caller
/// has logged in already.
fn sign_with_key(
    session: &Session,
    key_id: &[u8],
    alg: DigestAlg,
    prehash: &[u8],
) -> Result<Vec<u8>> {
    // Locate the key object by CKA_ID (tokens give no way to keep an object
    // handle across sessions, so re-finding is the documented pattern).
    let template = [
        FindTemplate::class(CKO_PRIVATE_KEY),
        FindTemplate::id(key_id.to_vec()),
    ];
    let found = session.find(&template)?;
    let Some(&key_object) = found.first() else {
        return Err(Error::Keystore(format!(
            "no private key with CKA_ID {} was found on the token",
            hex_colon(key_id)
        )));
    };
    let Some(key_type) = session.ulong(key_object, CKA_KEY_TYPE)? else {
        return Err(Error::Keystore(
            "the private key object reports no CKA_KEY_TYPE".into(),
        ));
    };

    match key_type {
        CKK_RSA => {
            // Sign the DigestInfo with plain CKM_RSA_PKCS — one RSA primitive
            // over exactly the bytes PKCS#1 v1.5 demands, and identical to
            // what rsa_sign_prehash produces in software. The CKM_SHAxxx_*
            // mechanisms are for a token that hashes the data itself; CMS's
            // digest is already computed, and handing it one of those double-
            // hashes (measured against SoftHSM: its SHA256_RSA_PKCS output is
            // RSA(SHA256(digest)) — verified against nothing). See the note in
            // types.rs by the mechanism constants.
            let mut data = Vec::with_capacity(prehash.len() + 19);
            data.extend_from_slice(digest_info_prefix(alg)?);
            data.extend_from_slice(prehash);
            pkcs11_sign(session, key_object, CKM_RSA_PKCS, &data)
        }
        CKK_EC => {
            // The token signs the digest with raw ECDSA and hands back r||s;
            // CMS carries DER. This is the DNIe recipe: same mechanism, same
            // conversion, done on AutoFirma's side too (its P11 helper wraps
            // the raw pair into ASN.1 before building the CMS). Only SHA-256
            // pairs here — the software signer makes its EC key P-256-only,
            // and the curve cannot be read ahead of time from a sensitive
            // token — other digests are refused by name; an unexpected key
            // size is caught via the returned length below.
            if !matches!(alg, DigestAlg::Sha256) {
                return Err(Error::UnsupportedCombination {
                    key: "CKK_EC",
                    digest: alg.name(),
                });
            }
            let raw = pkcs11_sign(session, key_object, CKM_ECDSA, prehash)?;
            if raw.len() != 64 {
                return Err(Error::Keystore(format!(
                    "CKM_ECDSA returned {} bytes where a P-256 r||s pair (64) \
                     was expected — other curves need their own mechanism and \
                     digest pairing, see ADR-0004",
                    raw.len()
                )));
            }
            Ok(ecdsa_raw_to_der(&raw))
        }
        other => Err(Error::UnsupportedCombination {
            key: key_type_name(other),
            digest: alg.name(),
        }),
    }
}

/// C_SignInit + C_Sign over one prehashed blob, with the documented length
/// probe (first call with a null signature buffer).
fn pkcs11_sign(
    session: &Session,
    key_object: CkObjectHandle,
    mechanism: CkUlong,
    data: &[u8],
) -> Result<Vec<u8>> {
    let mut mech = CkMechanism {
        mechanism,
        p_parameter: std::ptr::null_mut(),
        ul_parameter_len: 0,
    };
    let rv = (session.module.f().sign_init)(session.handle, &mut mech, key_object);
    if rv == CKR_MECHANISM_INVALID {
        // Refuse by name, per the brief: tokens answer MECHANISM_INVALID and
        // the user needs to know *which* mechanism was tried.
        return Err(Error::Keystore(format!(
            "the token does not support {} — this PKCS#11 module implements a \
             smaller set than openfirma targets",
            mechanism_name(mechanism)
        )));
    }
    check(rv, &format!("C_SignInit({})", mechanism_name(mechanism)))?;
    let mut len: CkUlong = 0;
    check(
        (session.module.f().sign)(
            session.handle,
            data.as_ptr() as *mut u8,
            ul(data.len()),
            std::ptr::null_mut(),
            &mut len,
        ),
        "C_Sign",
    )?;
    let mut buf = vec![0u8; len as usize];
    check(
        (session.module.f().sign)(
            session.handle,
            data.as_ptr() as *mut u8,
            ul(data.len()),
            buf.as_mut_ptr(),
            &mut len,
        ),
        "C_Sign",
    )?;
    buf.truncate(len as usize);
    Ok(buf)
}

/// The RFC 8017 DigestInfo prefix for `alg`; SHA-224 etc. all exist so every
/// DigestAlg the CLI accepts is covered without an unreachable arm.
fn digest_info_prefix(alg: DigestAlg) -> Result<&'static [u8]> {
    Ok(match alg {
        DigestAlg::Sha1 => DIGEST_INFO_SHA1_PREFIX,
        DigestAlg::Sha224 => DIGEST_INFO_SHA224_PREFIX,
        DigestAlg::Sha256 => DIGEST_INFO_SHA256_PREFIX,
        DigestAlg::Sha384 => DIGEST_INFO_SHA384_PREFIX,
        DigestAlg::Sha512 => DIGEST_INFO_SHA512_PREFIX,
    })
}

/// Turns a raw `r||s` ECDSA pair into the DER `SEQUENCE { INTEGER r, INTEGER s }`
/// that CMS (and openfirma_core's verifier) expect. Integers are signed per
/// X.690, so a leading 0x80 bit needs an explicit zero byte.
pub(crate) fn ecdsa_raw_to_der(raw: &[u8]) -> Vec<u8> {
    let (r, s) = raw.split_at(raw.len() / 2);
    sequence(&[integer_der(r), integer_der(s)])
}

fn integer_der(value: &[u8]) -> Vec<u8> {
    let trimmed = value
        .iter()
        .position(|b| *b != 0)
        .map_or_else(|| &value[value.len().saturating_sub(1)..], |i| &value[i..]);
    if trimmed.first().is_some_and(|b| b & 0x80 != 0) {
        let mut v = vec![0u8];
        v.extend_from_slice(trimmed);
        tlv(0x02, &v)
    } else {
        tlv(0x02, trimmed)
    }
}

/// A pure function-list-offset check the integration test in tests/pkcs11.rs
/// repeats against a live module (this one runs on every target without any).
pub fn function_list_offsets() -> [(&'static str, usize); 8] {
    use core::mem::offset_of;
    [
        ("C_Initialize", offset_of!(CkFunctionList, initialize)),
        ("C_GetSlotList", offset_of!(CkFunctionList, get_slot_list)),
        ("C_OpenSession", offset_of!(CkFunctionList, open_session)),
        ("C_Login", offset_of!(CkFunctionList, login)),
        (
            "C_GetAttributeValue",
            offset_of!(CkFunctionList, get_attribute_value),
        ),
        (
            "C_FindObjectsInit",
            offset_of!(CkFunctionList, find_objects_init),
        ),
        ("C_SignInit", offset_of!(CkFunctionList, sign_init)),
        ("C_Sign", offset_of!(CkFunctionList, sign)),
    ]
}

fn blank_padded(bytes: &[u8]) -> &str {
    let end = bytes
        .iter()
        .rposition(|b| *b != b' ' && *b != 0)
        .map_or(0, |i| i + 1);
    std::str::from_utf8(&bytes[..end]).unwrap_or("")
}

fn hex_colon(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn check(rv: CkRv, call: &str) -> Result<()> {
    if rv == CKR_OK {
        return Ok(());
    }
    Err(session_error(call, rv))
}

fn session_error(call: &str, rv: CkRv) -> Error {
    let mut msg = format!("{call} failed: {}", describe(rv));
    if !rv_hint(rv).is_empty() {
        msg.push_str(" — ");
        msg.push_str(rv_hint(rv));
    }
    Error::Keystore(msg)
}

fn describe(rv: CkRv) -> String {
    let name = rv_name(rv);
    if name.starts_with("CKR_") {
        format!("{name} ({rv:#x})")
    } else if rv == NSS_BAD_DATABASE_CONFIG {
        // NSS's own code for "your LibraryParameters did not parse" (defined
        // by SECMOD as a vendor value). Naming it turns an opaque hex dump
        // into the real diagnosis.
        format!("NSS rejected the database configuration ({rv:#x})")
    } else {
        format!("unknown Cryptoki return value {rv:#x}")
    }
}

/// `SECMOD_ERROR_BASE | (-0x12ab)`-style vendor code softokn3 answers when
/// its parameter string does not parse (observed directly: 0xce534351).
const NSS_BAD_DATABASE_CONFIG: CkRv = 0xce53_4351;
