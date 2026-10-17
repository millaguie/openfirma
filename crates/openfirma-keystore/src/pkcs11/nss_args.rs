/// NSS-shaped `CK_C_INITIALIZE_ARGS`, the only reason openfirma builds an
/// initialize argument struct at all.
///
/// The PKCS#11 v2.40 order (mutex callbacks first, then `flags`, then a
/// reserved pointer) is *almost* what NSS's softokn3 expects: its own
/// `pkcs11t.h` keeps the same four mutex callbacks and `flags` in the same
/// slots, but renames the spec's reserved field to
/// `CK_CHAR_PTR *LibraryParameters` and adds `pReserved` after it, which
/// "must be NULL in all cases". The comment on that redefinition says it
/// outright: the official spec has no `LibraryParameters`; NSS needs a way to
/// point a library at its configuration, here the cert/key database. This was
/// verified against live libsoftokn3 on x86-64: with this shape and
/// `configDir='sql:...'` in `library_parameters`, C_Initialize returns CKR_OK
/// and the token lists its certificates; passing the spec's all-reserved
/// struct instead leaves the database at its `noCertDB,noModDB` default, and
/// Java-style parameter pairs return CKR_ARGUMENTS_BAD. The probes are
/// described in ADR-0004.
use super::types::CkUlong;

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct NssInitializeArgs {
    /// The four application-supplied mutex callbacks. NSS's own header comment
    /// documents their slots but softokn3 never calls them (it locks with
    /// NSPR); what it does check is shape only — all four set without
    /// `CKF_OS_LOCKING_OK` answers CKR_CANT_LOCK, *some* of them answers
    /// CKR_ARGUMENTS_BAD. Null is the compliant, verified-working shape: we
    /// pass neither callbacks nor anything to avoid them by.
    pub create_mutex: *mut core::ffi::c_void,
    pub destroy_mutex: *mut core::ffi::c_void,
    pub lock_mutex: *mut core::ffi::c_void,
    pub unlock_mutex: *mut core::ffi::c_void,
    /// Zero. NSS reads no meaning into any flag for this purpose — the flags
    /// field exists so the mutex-callback checks above can be skipped by
    /// callers that bring real OS locking — and CKR_OK was proven with zero
    /// against live softokn3 (CKF_OS_LOCKING_OK also works once the callbacks
    /// are null; not setting what we don't offer is the stricter shape).
    pub flags: CkUlong,
    /// NSS's extension to the spec's reserved field: the softokn3
    /// configuration string, e.g. `configDir='sql:/path/to/db'`. Callers may
    /// write either a bare database location or any full softokn3 parameter
    /// string; it travels verbatim.
    pub library_parameters: *const u8,
    /// Must be null whenever `LibraryParameters` is set; softokn3 uses its
    /// presence to tell this struct's length apart from the older one.
    pub p_reserved: *mut core::ffi::c_void,
}

impl NssInitializeArgs {
    /// An initialize-args pointing the module at `library_parameters`, passed
    /// verbatim (see the type-level docs on accepted shapes).
    pub fn new(library_parameters: *const u8) -> Self {
        Self {
            library_parameters,
            ..Default::default()
        }
    }
}
