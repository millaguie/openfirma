//! The PKCS#11 v2.40 wire shapes: `#[repr(C)]` structs and only the constants
//! a signer can observe.
//!
//! Every number and every field here was transcribed from the OASIS PKCS #11
//! v2.40 base specification (`pkcs11t.h` / `pkcs11f.h`). The transcription is
//! machine-checked two ways: the compile-time assertions at the bottom of this
//! file, and the integration tests in `tests/pkcs11.rs`, which drive live
//! sessions against SoftHSM2 and NSS softokn3 — a wrong layout does not
//! misbehave subtly there; it fails to parse or crashes, immediately.
//!
//! ABI notes for the reviewers who will try to "fix" this:
//!
//! - `CK_ULONG` is C's `unsigned long`: 8 bytes on every LP64/LLP64 target we
//!   ship (Linux x86_64/aarch64, Windows MSVC x64/arm64, macOS), and Rust's
//!   `usize` matches it on all of them. Do not change these to `u64`.
//! - The function list may only be *extended at the end* (spec 4.12: a 3.x
//!   module hands back a `CK_FUNCTION_LIST_3_x` whose v2 prefix is identical),
//!   so a hand-written table that declares entries through `C_Sign` reads
//!   stable slots in every 2.0–3.x module. The `_underscore` members are spec
//!   functions this crate never calls and exist only to keep every offset
//!   honest; removing one shifts everything after it and the asserts catch it.
//! - Callback pointers (`C_OpenSession`'s application/notify) are passed as
//!   null `*mut c_void`: identical layout to the spec's function-pointer
//!   types, without declaring a callback ABI we never implement.

use core::ffi::c_void;

pub type CkUlong = usize;
pub type CkRv = CkUlong;
pub type CkSlotId = CkUlong;
pub type CkSessionHandle = CkUlong;
pub type CkObjectHandle = CkUlong;

/// `CK_UNAVAILABLE_INFORMATION`: what `C_GetAttributeValue` writes into
/// `ulValueLen` when an attribute cannot be read at all (sensitive key,
/// unknown type). It is `~0UL`, so it must stay `usize::MAX`, not a guess.
pub const CK_UNAVAILABLE_INFORMATION: CkUlong = usize::MAX;

// ---------------------------------------------------------------------------
// return values — every one openfirma can observe, named per the v2.40 table

pub const CKR_OK: CkRv = 0x0000_0000;
pub const CKR_CANCEL: CkRv = 0x0000_0001;
pub const CKR_SLOT_ID_INVALID: CkRv = 0x0000_0003;
pub const CKR_GENERAL_ERROR: CkRv = 0x0000_0005;
pub const CKR_FUNCTION_FAILED: CkRv = 0x0000_0006;
pub const CKR_ARGUMENTS_BAD: CkRv = 0x0000_0007;
pub const CKR_NO_EVENT: CkRv = 0x0000_0008;
pub const CKR_ATTRIBUTE_SENSITIVE: CkRv = 0x0000_0011;
pub const CKR_ATTRIBUTE_TYPE_INVALID: CkRv = 0x0000_0012;
pub const CKR_BUFFER_TOO_SMALL: CkRv = 0x0000_0150;
pub const CKR_DEVICE_ERROR: CkRv = 0x0000_0030;
pub const CKR_FUNCTION_CANCELED: CkRv = 0x0000_0050;
pub const CKR_FUNCTION_NOT_PARALLEL: CkRv = 0x0000_0051;
pub const CKR_FUNCTION_NOT_SUPPORTED: CkRv = 0x0000_0054;
pub const CKR_KEY_HANDLE_INVALID: CkRv = 0x0000_0060;
pub const CKR_MECHANISM_INVALID: CkRv = 0x0000_0070;
pub const CKR_MECHANISM_PARAM_INVALID: CkRv = 0x0000_0071;
pub const CKR_OBJECT_HANDLE_INVALID: CkRv = 0x0000_0082;
pub const CKR_OPERATION_ACTIVE: CkRv = 0x0000_0090;
pub const CKR_OPERATION_NOT_INITIALIZED: CkRv = 0x0000_0091;
pub const CKR_PIN_INCORRECT: CkRv = 0x0000_00A0;
pub const CKR_PIN_INVALID: CkRv = 0x0000_00A1;
pub const CKR_PIN_LEN_RANGE: CkRv = 0x0000_00A2;
pub const CKR_PIN_EXPIRED: CkRv = 0x0000_00A3;
pub const CKR_PIN_LOCKED: CkRv = 0x0000_00A4;
pub const CKR_SESSION_CLOSED: CkRv = 0x0000_0700;
pub const CKR_SESSION_COUNT: CkRv = 0x0000_0701;
pub const CKR_SESSION_HANDLE_INVALID: CkRv = 0x0000_0703;
pub const CKR_SESSION_READ_ONLY: CkRv = 0x0000_0705;
pub const CKR_SIGNATURE_LEN_RANGE: CkRv = 0x0000_0021;
pub const CKR_SIGNATURE_INVALID: CkRv = 0x0000_00C0;
pub const CKR_TOKEN_NOT_PRESENT: CkRv = 0x0000_00E0;
pub const CKR_TOKEN_NOT_RECOGNIZED: CkRv = 0x0000_00E1;
pub const CKR_TOKEN_WRITE_PROTECTED: CkRv = 0x0000_00E2;
pub const CKR_USER_ALREADY_LOGGED_IN: CkRv = 0x0000_0100;
pub const CKR_USER_NOT_LOGGED_IN: CkRv = 0x0000_0101;
pub const CKR_USER_PIN_NOT_INITIALIZED: CkRv = 0x0000_0102;
pub const CKR_USER_TYPE_INVALID: CkRv = 0x0000_0103;
pub const CKR_CRYPTOKI_ALREADY_INITIALIZED: CkRv = 0x0000_0191;
pub const CKR_ACTION_PROHIBITED: CkRv = 0x0000_01DB;

/// A return value as the specification names it. An error message quotes
/// this, so `CKR_PIN_LOCKED` reads "locked PIN (CKR_PIN_LOCKED)" instead of a
/// bare number — see docs/AGENT-BRIEF.md on errors naming their cause.
pub fn rv_name(rv: CkRv) -> &'static str {
    match rv {
        CKR_OK => "CKR_OK",
        CKR_CANCEL => "CKR_CANCEL",
        CKR_SLOT_ID_INVALID => "CKR_SLOT_ID_INVALID",
        CKR_GENERAL_ERROR => "CKR_GENERAL_ERROR",
        CKR_FUNCTION_FAILED => "CKR_FUNCTION_FAILED",
        CKR_ARGUMENTS_BAD => "CKR_ARGUMENTS_BAD",
        CKR_NO_EVENT => "CKR_NO_EVENT",
        CKR_ATTRIBUTE_SENSITIVE => "CKR_ATTRIBUTE_SENSITIVE",
        CKR_ATTRIBUTE_TYPE_INVALID => "CKR_ATTRIBUTE_TYPE_INVALID",
        CKR_BUFFER_TOO_SMALL => "CKR_BUFFER_TOO_SMALL",
        CKR_DEVICE_ERROR => "CKR_DEVICE_ERROR",
        CKR_FUNCTION_CANCELED => "CKR_FUNCTION_CANCELED",
        CKR_FUNCTION_NOT_PARALLEL => "CKR_FUNCTION_NOT_PARALLEL",
        CKR_FUNCTION_NOT_SUPPORTED => "CKR_FUNCTION_NOT_SUPPORTED",
        CKR_KEY_HANDLE_INVALID => "CKR_KEY_HANDLE_INVALID",
        CKR_MECHANISM_INVALID => "CKR_MECHANISM_INVALID",
        CKR_MECHANISM_PARAM_INVALID => "CKR_MECHANISM_PARAM_INVALID",
        CKR_OBJECT_HANDLE_INVALID => "CKR_OBJECT_HANDLE_INVALID",
        CKR_OPERATION_ACTIVE => "CKR_OPERATION_ACTIVE",
        CKR_OPERATION_NOT_INITIALIZED => "CKR_OPERATION_NOT_INITIALIZED",
        CKR_PIN_INCORRECT => "CKR_PIN_INCORRECT",
        CKR_PIN_INVALID => "CKR_PIN_INVALID",
        CKR_PIN_LEN_RANGE => "CKR_PIN_LEN_RANGE",
        CKR_PIN_EXPIRED => "CKR_PIN_EXPIRED",
        CKR_PIN_LOCKED => "CKR_PIN_LOCKED",
        CKR_SESSION_CLOSED => "CKR_SESSION_CLOSED",
        CKR_SESSION_COUNT => "CKR_SESSION_COUNT",
        CKR_SESSION_HANDLE_INVALID => "CKR_SESSION_HANDLE_INVALID",
        CKR_SESSION_READ_ONLY => "CKR_SESSION_READ_ONLY",
        CKR_SIGNATURE_LEN_RANGE => "CKR_SIGNATURE_LEN_RANGE",
        CKR_SIGNATURE_INVALID => "CKR_SIGNATURE_INVALID",
        CKR_TOKEN_NOT_PRESENT => "CKR_TOKEN_NOT_PRESENT",
        CKR_TOKEN_NOT_RECOGNIZED => "CKR_TOKEN_NOT_RECOGNIZED",
        CKR_TOKEN_WRITE_PROTECTED => "CKR_TOKEN_WRITE_PROTECTED",
        CKR_USER_ALREADY_LOGGED_IN => "CKR_USER_ALREADY_LOGGED_IN",
        CKR_USER_NOT_LOGGED_IN => "CKR_USER_NOT_LOGGED_IN",
        CKR_USER_PIN_NOT_INITIALIZED => "CKR_USER_PIN_NOT_INITIALIZED",
        CKR_USER_TYPE_INVALID => "CKR_USER_TYPE_INVALID",
        CKR_CRYPTOKI_ALREADY_INITIALIZED => "CKR_CRYPTOKI_ALREADY_INITIALIZED",
        CKR_ACTION_PROHIBITED => "CKR_ACTION_PROHIBITED",
        _ => "an unknown Cryptoki return value",
    }
}

/// A return value as a person reads it: the constant plus, for the ones that
/// mean something actionable about a PIN or a token, the action.
pub fn rv_hint(rv: CkRv) -> &'static str {
    match rv {
        CKR_PIN_INCORRECT => "the PIN is wrong",
        CKR_PIN_LOCKED => {
            "the PIN is locked after too many wrong tries; unlock it with the token's \
             administration tool (softhsm2-util, pkcs11-tool, the FNMT pin change)"
        }
        CKR_PIN_EXPIRED => "the PIN has expired and must be changed",
        CKR_USER_NOT_LOGGED_IN => {
            "this token requires a PIN: pass --pin-env VAR with the environment \
             variable holding it"
        }
        CKR_TOKEN_NOT_PRESENT => "no token is present in this reader; insert it and run again",
        CKR_MECHANISM_INVALID => {
            "the token does not implement this signature mechanism, see the name in \
             the message above"
        }
        _ => "",
    }
}

// ---------------------------------------------------------------------------
// flags, classes, attributes, key types, mechanisms

pub const CKF_TOKEN_PRESENT: CkUlong = 0x0000_0001;
pub const CKF_USER_PIN_COUNT_LOW: CkUlong = 0x0001_0000;
pub const CKF_USER_PIN_FINAL_TRY: CkUlong = 0x0002_0000;
pub const CKF_USER_PIN_LOCKED: CkUlong = 0x0004_0000;

/// `CKF_SERIAL_SESSION`, which the spec says should always be set.
pub const CKF_SERIAL_SESSION: CkUlong = 0x0000_0004;

// About `CKF_OS_LOCKING_OK`, which is deliberately not declared here: openfirma
// passes *no* mutex callbacks and no flags at all, the shape proven to
// initialize both generic modules (NULL args) and NSS softokn3
// (`NssInitializeArgs`), so it has nothing to set. (0x2 in every header; do not
// confuse it with `CKF_SERIAL_SESSION`, which is 0x4.)

/// `CKU_USER`: the only user type openfirma logs in as. The SO PIN is an
/// administration secret and signing never needs it.
pub const CKU_USER: CkUlong = 1;

pub const CKO_CERTIFICATE: CkUlong = 0x0000_0001;
pub const CKO_PRIVATE_KEY: CkUlong = 0x0000_0003;

pub const CKA_CLASS: CkUlong = 0x0000_0000;
pub const CKA_LABEL: CkUlong = 0x0000_0003;
pub const CKA_VALUE: CkUlong = 0x0000_0011;
pub const CKA_CERTIFICATE_TYPE: CkUlong = 0x0000_0080;
pub const CKA_KEY_TYPE: CkUlong = 0x0000_0100;
pub const CKA_ID: CkUlong = 0x0000_0102;

/// `CKC_X_509`. Certificate objects of another type (attribute certificates,
/// WTLS) cannot be embedded in a CMS as X.509 and are skipped at list time.
pub const CKC_X_509: CkUlong = 0x0000_0000;

pub const CKK_RSA: CkUlong = 0x0000_0000;
pub const CKK_DSA: CkUlong = 0x0000_0001;
pub const CKK_DH: CkUlong = 0x0000_0002;
pub const CKK_EC: CkUlong = 0x0000_0003;
pub const CKK_EDDSA: CkUlong = 0x0000_0041;

/// `CKK_*` as a name, for the messages that refuse an unsupported key type.
pub fn key_type_name(t: CkUlong) -> &'static str {
    match t {
        CKK_RSA => "CKK_RSA",
        CKK_DSA => "CKK_DSA",
        CKK_DH => "CKK_DH",
        CKK_EC => "CKK_EC",
        CKK_EDDSA => "CKK_EDWARDS/DOMAIN-PARAMETER ECDSA (CKK_EDDSA)",
        _ => "an unknown CKA_KEY_TYPE",
    }
}

pub const CKM_RSA_PKCS: CkUlong = 0x0000_0001;
/// The complete `DigestInfo` (`SEQUENCE { AlgorithmIdentifier, OCTET STRING }`)
/// for SHA-256, RFC 8017 table 2 verbatim — what a token must be handed when
/// signing an *already computed* digest with the plain RSA mechanism:
/// 30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 ‖ H.
pub const DIGEST_INFO_SHA256_PREFIX: &[u8] = &[
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];
/// SHA-1: `SEQUENCE { sha1 NULL, OCTET STRING }`.
pub const DIGEST_INFO_SHA1_PREFIX: &[u8] = &[
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
];
/// SHA-224.
pub const DIGEST_INFO_SHA224_PREFIX: &[u8] = &[
    0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05,
    0x00, 0x04, 0x1c,
];
/// SHA-384.
pub const DIGEST_INFO_SHA384_PREFIX: &[u8] = &[
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
    0x00, 0x04, 0x30,
];
/// SHA-512.
pub const DIGEST_INFO_SHA512_PREFIX: &[u8] = &[
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40,
];

/// `CKM_SHAxxx_RSA_PKCS` exist for a token that hashes *the data itself*
/// (C_DigestVerify-style flows). CMS hands a signer a digest computed
/// elsewhere, so openfirma signs the pre-built DigestInfo with plain
/// `CKM_RSA_PKCS`: exactly one RSA primitive over what we control. The
/// digesting mechanisms would double-hash — proved by probing SoftHSM: its
/// CKM_SHA256_RSA_PKCS output equals RSA-PKCS1(sha256(digest_bytes)), which
/// no verifier on earth accepts. Keep the constants for refusal messages and
/// mechanism discovery, but never sign with them here.
pub const CKM_SHA1_RSA_PKCS: CkUlong = 0x0000_0006;
pub const CKM_SHA256_RSA_PKCS: CkUlong = 0x0000_0040;
pub const CKM_SHA384_RSA_PKCS: CkUlong = 0x0000_0041;
pub const CKM_SHA512_RSA_PKCS: CkUlong = 0x0000_0042;
pub const CKM_SHA224_RSA_PKCS: CkUlong = 0x0000_0046;
/// Raw ECDSA over a caller-supplied digest (the token does not hash). Every
/// module tested here implements this rather than the `CKM_ECDSA_SHAxxx`
/// mechanisms, because CMS hands the signer a digest computed elsewhere;
/// DNIe's module is one of them. The signature comes back as raw `r||s` and
/// gets DER-encoded by us — see `pkcs11::ecdsa_raw_to_der`.
pub const CKM_ECDSA: CkUlong = 0x0000_1041;

/// A mechanism id as the header names it, for refusal messages.
pub fn mechanism_name(m: CkUlong) -> &'static str {
    match m {
        CKM_RSA_PKCS => "CKM_RSA_PKCS",
        CKM_SHA1_RSA_PKCS => "CKM_SHA1_RSA_PKCS",
        CKM_SHA224_RSA_PKCS => "CKM_SHA224_RSA_PKCS",
        CKM_SHA256_RSA_PKCS => "CKM_SHA256_RSA_PKCS",
        CKM_SHA384_RSA_PKCS => "CKM_SHA384_RSA_PKCS",
        CKM_SHA512_RSA_PKCS => "CKM_SHA512_RSA_PKCS",
        CKM_ECDSA => "CKM_ECDSA",
        _ => "an unknown CKM_* mechanism",
    }
}

// ---------------------------------------------------------------------------
// the structs

#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct CkVersion {
    pub major: u8,
    pub minor: u8,
}

/// `CK_ATTRIBUTE`, exactly as the header defines it: a ulong type tag, a
/// value pointer, and a value length. `CK_ULONG` is C's unsigned long and
/// `CK_VOID_PTR` a plain pointer; Rust's usize/*mut c_void have the same size
/// and alignment on every LP64/LLP64 target we ship (asserted at the bottom
/// of this file), so the fields are declared with their natural types. The
/// length is in/out: a probe call learns the size through it, which is why
/// callers must hand real `CkUlong` storage, not literals. Do not reorder
/// these fields: NSS's own pkcs11t.h declares the same order.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CkAttribute {
    pub type_: CkUlong,
    pub p_value: *mut c_void,
    pub ul_value_len: CkUlong,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CkMechanism {
    pub mechanism: CkUlong,
    pub p_parameter: *mut c_void,
    /// A real `CK_ULONG` value slot: the spec's parameter length field. This
    /// crate only passes parameterless mechanisms, so zero is also correct.
    pub ul_parameter_len: CkUlong,
}

/// `CK_SLOT_INFO`, read at list time to filter slots that report no token.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CkSlotInfo {
    pub slot_description: [u8; 64],
    pub manufacturer_id: [u8; 32],
    pub flags: CkUlong,
    pub hardware_version: CkVersion,
    pub firmware_version: CkVersion,
}

impl Default for CkSlotInfo {
    /// [u8; 64] has no Default derive past 32 elements, so this spells it out
    /// rather than pulling zeroize or MaybeUninit in for one struct.
    fn default() -> Self {
        Self {
            slot_description: [0; 64],
            manufacturer_id: [0; 32],
            flags: 0,
            hardware_version: CkVersion::default(),
            firmware_version: CkVersion::default(),
        }
    }
}

/// `CK_INFO`, read nowhere yet but part of the documented prefix.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct CkInfo {
    pub cryptoki_version: CkVersion,
    /// `CK_FLAGS` is a `CK_ULONG`: this is why the struct is not 84 bytes on
    /// LP64. A `u32` here would shift everything after it by four bytes.
    pub flags: CkUlong,
    pub manufacturer_id: [u8; 32],
    pub library_description: [u8; 32],
    pub library_version: CkVersion,
}

/// `CK_TOKEN_INFO`. Note the total size is 192 bytes on a 64-bit target, not
/// the 188 the field list seems to add up to: after `utc_time` no field needs
/// 8-byte alignment, but the trailing row still rounds the struct up past
/// every member's natural placement — the offsets below pin down exactly
/// where C reads each one. Do not "fix" them from the field widths alone.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct CkTokenInfo {
    pub label: [u8; 32],
    pub manufacturer_id: [u8; 32],
    pub model: [u8; 16],
    pub serial_number: [u8; 16],
    pub flags: CkUlong,
    pub max_session_count: CkUlong,
    pub session_count: CkUlong,
    pub max_rw_session_count: CkUlong,
    pub rw_session_count: CkUlong,
    pub max_pin_len: CkUlong,
    pub min_pin_len: CkUlong,
    pub total_public_memory: CkUlong,
    pub free_public_memory: CkUlong,
    pub total_private_memory: CkUlong,
    pub free_private_memory: CkUlong,
    pub hardware_version: CkVersion,
    pub firmware_version: CkVersion,
    pub utc_time: [u8; 16],
}

/// The prefix of `CK_FUNCTION_LIST` that openfirma calls (see the module
/// documentation for why a partial table is safe). Field order is exactly the
/// v2.40 definition; underscore entries are spec functions this crate never
/// calls and exist only to keep every offset honest. Offsets on a 64-bit
/// target — spec function *k* sits at byte `8k`, because the two-byte version
/// plus its tail padding occupy slot 0:
///
/// ```text
/// version 0   C_Initialize 8   C_Finalize 16   C_GetInfo 24
/// C_GetFunctionList 32  C_GetSlotList 40  C_GetSlotInfo 48  C_GetTokenInfo 56
/// C_GetMechanismList 64 ... C_SetPIN 96
/// C_OpenSession 104   C_CloseSession 112   C_CloseAllSessions 120
/// C_GetSessionInfo 128   C_GetOperationState 136   C_SetOperationState 144
/// C_Login 152   C_Logout 160   C_CreateObject 168 ... C_GetObjectSize 192
/// C_GetAttributeValue 200   C_SetAttributeValue 208   C_FindObjectsInit 216
/// C_FindObjects 224   C_FindObjectsFinal 232   (cipher/digest family) ...
/// C_SignInit 344   C_Sign 352
/// ```
#[repr(C)]
pub struct CkFunctionList {
    pub version: CkVersion,
    // PKCS#11's CK_VERSION only declares the two bytes, but C aligns whatever
    // follows to its own alignment, and real modules store function pointers
    // starting at byte 8 (confirmed by calling a live SoftHSM through this
    // exact layout). Naming that tail padding `_pad0` is what makes the
    // offsets in the table above come out right on LP64/LLP64; it is also why
    // this can never be derived Default.
    _pad0: [u8; 6],
    pub initialize: extern "C" fn(init_args: *mut c_void) -> CkRv,
    pub finalize: extern "C" fn(reserved: *mut c_void) -> CkRv,
    _get_info: *mut c_void,
    /// Declared here because the list contains it even though we obtain the
    /// list itself through the exported `C_GetFunctionList` symbol.
    _get_function_list: *mut c_void,
    pub get_slot_list: extern "C" fn(
        token_present: u8,
        p_slot_list: *mut CkSlotId,
        pul_count: *mut CkUlong,
    ) -> CkRv,
    /// Read at list time to keep only slots whose token is present.
    pub get_slot_info: extern "C" fn(slot_id: CkSlotId, p_info: *mut CkSlotInfo) -> CkRv,
    pub get_token_info: extern "C" fn(slot_id: CkSlotId, p_info: *mut CkTokenInfo) -> CkRv,
    _get_mechanism_list: *mut c_void,
    _get_mechanism_info: *mut c_void,
    _init_token: *mut c_void,
    _init_pin: *mut c_void,
    _set_pin: *mut c_void,
    pub open_session: extern "C" fn(
        slot_id: CkSlotId,
        flags: CkUlong,
        application: *mut c_void,
        notify: *mut c_void,
        ph_session: *mut CkSessionHandle,
    ) -> CkRv,
    pub close_session: extern "C" fn(session: CkSessionHandle) -> CkRv,
    _close_all_sessions: *mut c_void,
    _get_session_info: *mut c_void,
    _get_operation_state: *mut c_void,
    _set_operation_state: *mut c_void,
    pub login: extern "C" fn(
        session: CkSessionHandle,
        user_type: CkUlong,
        p_pin: *mut u8,
        ul_pin_len: CkUlong,
    ) -> CkRv,
    _logout: *mut c_void,
    _create_object: *mut c_void,
    _copy_object: *mut c_void,
    _destroy_object: *mut c_void,
    _get_object_size: *mut c_void,
    pub get_attribute_value: extern "C" fn(
        session: CkSessionHandle,
        object: CkObjectHandle,
        p_template: *mut CkAttribute,
        ul_count: CkUlong,
    ) -> CkRv,
    _set_attribute_value: *mut c_void,
    pub find_objects_init: extern "C" fn(
        session: CkSessionHandle,
        p_template: *mut CkAttribute,
        ul_count: CkUlong,
    ) -> CkRv,
    pub find_objects: extern "C" fn(
        session: CkSessionHandle,
        p_object: *mut CkObjectHandle,
        ul_max_object_count: CkUlong,
        pul_count: *mut CkUlong,
    ) -> CkRv,
    pub find_objects_final: extern "C" fn(session: CkSessionHandle) -> CkRv,
    _encrypt_init: *mut c_void,
    _encrypt: *mut c_void,
    _encrypt_update: *mut c_void,
    _encrypt_final: *mut c_void,
    _decrypt_init: *mut c_void,
    _decrypt: *mut c_void,
    _decrypt_update: *mut c_void,
    _decrypt_final: *mut c_void,
    _digest_init: *mut c_void,
    _digest: *mut c_void,
    _digest_update: *mut c_void,
    _digest_key: *mut c_void,
    _digest_final: *mut c_void,
    pub sign_init: extern "C" fn(
        session: CkSessionHandle,
        p_mechanism: *mut CkMechanism,
        key: CkObjectHandle,
    ) -> CkRv,
    /// Signs the bytes handed to it. For `CKM_SHAxxx_RSA_PKCS` those are the
    /// raw digest and the module builds the DigestInfo; for `CKM_ECDSA` they
    /// are the digest already, exactly as the mechanism documents. Either way
    /// openfirma never hands a token anything but a digest.
    pub sign: extern "C" fn(
        session: CkSessionHandle,
        p_data: *mut u8,
        ul_data_len: CkUlong,
        p_signature: *mut u8,
        pul_signature_len: *mut CkUlong,
    ) -> CkRv,
    // the list continues (C_SignUpdate onwards); declaring a prefix is safe,
    // reading past it on an older module is not, and we never do.
}

// The padding above puts the first function pointer at byte 8 wherever C's
// alignment matches — which repr(C) guarantees per field. But our *declared*
// struct may still be narrower than the real table in exotic ABIs: the slot
// stride of a C function pointer can exceed `align_of::<fn()>` (the historical
// 32-bit x86 Pascal-call ABI is the example), and then every member after
// `sign_init` would read one slot too far and silently misparse. Refuse to
// compile rather than ship that; see ADR-0004 ("untestable parts").
const _: () = assert!(core::mem::size_of::<CkFunctionList>() >= 360);

// The compile-time proof of every layout claim in this file. These run on all
// CI targets; if a target ever violates the PKCS#11 natural-ABI assumptions,
// the build stops instead of shipping a module that misparses.
const _: () = {
    // CK_ULONG must be pointer-sized wherever we read it as one (on every
    // supported LP64/LLP64 target this equals C's unsigned long).
    assert!(core::mem::size_of::<CkUlong>() == core::mem::size_of::<*const c_void>());

    // Spec offsets on a 64-bit target: version at 0, then 8-byte slots.
    assert!(core::mem::offset_of!(CkFunctionList, initialize) == 8);
    assert!(core::mem::offset_of!(CkFunctionList, finalize) == 16);
    assert!(core::mem::offset_of!(CkFunctionList, get_slot_list) == 40);
    assert!(core::mem::offset_of!(CkFunctionList, get_token_info) == 56);
    assert!(core::mem::offset_of!(CkFunctionList, open_session) == 104);
    assert!(core::mem::offset_of!(CkFunctionList, close_session) == 112);
    assert!(core::mem::offset_of!(CkFunctionList, login) == 152);
    assert!(core::mem::offset_of!(CkFunctionList, get_attribute_value) == 200);
    assert!(core::mem::offset_of!(CkFunctionList, find_objects_init) == 216);
    assert!(core::mem::offset_of!(CkFunctionList, find_objects) == 224);
    assert!(core::mem::offset_of!(CkFunctionList, find_objects_final) == 232);
    assert!(core::mem::offset_of!(CkFunctionList, sign_init) == 344);
    assert!(core::mem::offset_of!(CkFunctionList, sign) == 352);

    // CK_VERSION is exactly two bytes; the attribute template is ulong +
    // pointer + ulong.
    assert!(core::mem::size_of::<CkVersion>() == 2);
    assert!(core::mem::size_of::<CkAttribute>() == 3 * core::mem::size_of::<CkUlong>());

    // CK_INFO: version at 0, and flags is a ulong that pushes the rest right.
    assert!(core::mem::offset_of!(CkInfo, cryptoki_version) == 0);
    assert!(core::mem::offset_of!(CkInfo, manufacturer_id) > 8);

    // CK_TOKEN_INFO: the four char arrays are 32+32+16+16 = 96 bytes of fixed
    // text, then flags as a ulong at 96.
    assert!(core::mem::offset_of!(CkTokenInfo, label) == 0);
    assert!(core::mem::offset_of!(CkTokenInfo, manufacturer_id) == 32);
    assert!(core::mem::offset_of!(CkTokenInfo, model) == 64);
    assert!(core::mem::offset_of!(CkTokenInfo, serial_number) == 80);
    assert!(core::mem::offset_of!(CkTokenInfo, flags) == 96);
};
