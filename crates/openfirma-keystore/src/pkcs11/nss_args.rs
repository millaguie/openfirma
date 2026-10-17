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

/// The spec's `CK_C_INITIALIZE_ARGS` order is `callbacks, flags(ulong),
/// reserved(pointer)` and that is the byte order on *every* platform once
/// each one's packing rule is applied. On unix (LP64 and 32-bit alike)
/// natural alignment already places the ulong exactly there; on Windows the
/// cryptoki headers are consumed under `pack(1)` (see `types.rs`), which
/// removes x64 LLP64's temptation to float the two pointers ahead of the
/// 4-byte ulong, and the spec order comes out unchanged — this is precisely
/// what bindgen emits for cryptoki on `x86_64-pc-windows-msvc`. So only the
/// `repr` moves per platform, never the fields.
#[cfg_attr(windows, repr(C, packed))]
#[cfg_attr(not(windows), repr(C))]
#[derive(Default, Clone, Copy)]
pub struct NssInitializeArgs {
    /// The four application-supplied mutex callbacks. NSS's own header comment
    /// documents their slots but softokn3 never calls them (it locks with
    /// NSPR); what it does check is shape only — all four set without
    /// `CKF_OS_LOCKING_OK` answers CKR_CANT_LOCK, *some* of them answers
    /// CKR_ARGUMENTS_BAD. Null is the compliant, verified-working shape: we
    /// pass neither callbacks nor anything to avoid them by. The packed cfg
    /// mirrors how Windows consumes the same header (see `CkAttribute`): with
    /// `pack(1)`, C's member order puts the ulong before both pointers there
    /// too, and the field order below matches that read exactly — which is
    /// what bindgen produces for cryptoki on `x86_64-pc-windows-msvc`.
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

const _: () = {
    use core::mem::offset_of;
    // The four callback slots are consecutive pointers on every target: no
    // ABI we compile for ever inserts padding between them, packed or not.
    assert!(offset_of!(NssInitializeArgs, destroy_mutex) == core::mem::size_of::<*const u8>());
    assert!(offset_of!(NssInitializeArgs, unlock_mutex) == 3 * core::mem::size_of::<*const u8>());
    // Spec order everywhere once each platform's packing is applied: the
    // ulong sits after the callbacks and before the two pointers — natural
    // alignment gives it on unixes (verified against live softokn3), pack(1)
    // gives it on Windows, where a naturally aligned compiler would have
    // floated the 8-byte pointer ahead of the 4-byte flags. Same slot, same
    // meaning, both platforms.
    assert!(offset_of!(NssInitializeArgs, flags) == 4 * core::mem::size_of::<*const u8>());
    if !cfg!(windows) {
        // On unix, `flags` is ulong-width like the pointers, so C also
        // demands it before them; on Windows (packed) member order decides.
        assert!(
            offset_of!(NssInitializeArgs, library_parameters)
                > offset_of!(NssInitializeArgs, flags)
        );
    }
    assert!(
        offset_of!(NssInitializeArgs, p_reserved)
            > offset_of!(NssInitializeArgs, library_parameters)
    );
};

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
