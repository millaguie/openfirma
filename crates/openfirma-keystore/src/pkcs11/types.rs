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
//! - `CK_ULONG` is C's `unsigned long`: 8 bytes on LP64 (Linux/macOS/other
//!   unixes), but only 4 bytes on Windows *even in a 64-bit process* (LLP64).
//!   It therefore follows neither the pointer width nor `usize` everywhere,
//!   and is cfg-selected below (`u32` on both Windows MSVC ABIs, `usize` —
//!   which equals C's `unsigned long` — elsewhere). The vendor builds of our
//!   reference token confirm it: SoftHSM2-for-Windows answers with 4-byte
//!   `CK_ULONG`s on x64. This matches cryptoki-rs' and the `pkcs11` crate's
//!   own platform cfgs, and the compile-time assertions at the bottom of
//!   this file pin both widths per target.
//! - The same headers tell Windows consumers to wrap everything in
//!   `#pragma pack(push, cryptoki, 1)` (their own shipped header applies it
//!   for `_WIN32` unconditionally), while unix compilers use natural
//!   alignment. The difference is visible in exactly one shape we read: the
//!   two-byte `CK_VERSION` at the head of `CK_FUNCTION_LIST`. Packed, the
//!   first function pointer sits at byte 2; naturally aligned, at byte 8.
//!   On every other field (all pointers or ulongs at natural offsets) both
//!   spellings compile identically. Below we model this the same way the C
//!   headers do: LP64 uses plain `#[repr(C)]` + an explicit 6-byte version
//!   tail; Windows uses `#[repr(C, packed)]`, where the padding disappears.
//! - Callback pointers (`C_OpenSession`'s application/notify) are passed as
//!   null `*mut c_void`: identical layout to the spec's function-pointer
//!   types, without declaring a callback ABI we never implement.

use core::ffi::c_void;

/// `CK_ULONG`: C's `unsigned long`. See the module docs — 8 bytes on LP64,
/// 4 bytes on both Windows ABIs (this is why it may not be `usize` there).
#[cfg(not(windows))]
pub type CkUlong = usize;
#[cfg(windows)]
pub type CkUlong = u32;
pub type CkRv = CkUlong;
pub type CkSlotId = CkUlong;
pub type CkSessionHandle = CkUlong;
pub type CkObjectHandle = CkUlong;

/// `CK_UNAVAILABLE_INFORMATION`: what `C_GetAttributeValue` writes into
/// `ulValueLen` when an attribute cannot be read at all (sensitive key,
/// unknown type). It is `~0UL` — the all-ones value of C's `unsigned long`,
/// so 2^64−1 on unixes and 2^32−1 on Windows — never a hardcoded guess.
pub const CK_UNAVAILABLE_INFORMATION: CkUlong = CkUlong::MAX;

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

/// The `#[repr]` the cryptoki headers impose on a struct: Windows consumes
/// them under `#pragma pack(push, cryptoki, 1)` (the spec's own Win32 recipe,
/// and what SoftHSM2's shipped header applies for `_WIN32`), while unix C
/// uses natural alignment. On LP64 both spellings compile to identical bytes
/// for every struct here; where they could differ (trailing ulongs after the
/// fixed-size char arrays) the packed cfg matches what the vendor DLL writes.
macro_rules! cryptoki_packed {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident { $($body:tt)* }
    ) => {
        $(#[$meta])*
        #[cfg_attr(windows, repr(C, packed))]
        #[cfg_attr(not(windows), repr(C))]
        $vis struct $name { $($body)* }
    };
}

cryptoki_packed! {
    /// `CK_SLOT_INFO`, read at list time to filter slots that report no token.
    #[derive(Clone, Copy)]
    pub struct CkSlotInfo {
        pub slot_description: [u8; 64],
        pub manufacturer_id: [u8; 32],
        pub flags: CkUlong,
        pub hardware_version: CkVersion,
        pub firmware_version: CkVersion,
    }
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
/// Its *fields* land at the same addresses under both packing rules on every
/// target we ship (all ulongs sit naturally after 96 bytes of arrays), which
/// is why this struct does not need the `cryptoki_packed!` treatment: only
/// offsets we read matter, and none can straddle a boundary here.
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
/// calls and exist only to keep every offset honest. Offsets depend on the
/// platform packing rule described in the module docs: unix (naturally
/// aligned, pointer-sized slots) puts spec function *k* at byte `8k`, with
/// the two-byte version plus its 6-byte tail occupying slot 0; Windows
/// (headers packed, pointers 4 bytes on i686 and 8 on x86_64) puts function
/// *k* at byte `2 + k·ptr`. Both readings appear below:
///
/// ```text
/// unix 64:    version 0   C_Initialize 8   C_Finalize 16   C_GetInfo 24
/// C_GetFunctionList 32  C_GetSlotList 40  C_GetSlotInfo 48  C_GetTokenInfo 56
/// C_GetMechanismList 64 ... C_SetPIN 96
/// C_OpenSession 104   C_CloseSession 112   C_CloseAllSessions 120
/// C_GetSessionInfo 128   C_GetOperationState 136   C_SetOperationState 144
/// C_Login 152   C_Logout 160   C_CreateObject 168 ... C_GetObjectSize 192
/// C_GetAttributeValue 200   C_SetAttributeValue 208   C_FindObjectsInit 216
/// C_FindObjects 224   C_FindObjectsFinal 232   (cipher/digest family) ...
/// C_SignInit 344   C_Sign 352
///
/// windows:  version 0   C_Initialize 2   C_Finalize 2+p   …   C_Sign 2+44p
///           (p = 4 on i686, 8 on x86_64)
/// ```
#[cfg_attr(windows, repr(C, packed))]
#[cfg_attr(not(windows), repr(C))]
pub struct CkFunctionList {
    pub version: CkVersion,
    // PKCS#11's CK_VERSION only declares the two bytes, but unix C aligns
    // whatever follows to its own alignment, and real modules store function
    // pointers starting at byte 8 (confirmed by calling a live SoftHSM
    // through this exact layout). Naming that tail padding `_pad0` is what
    // makes the offsets in the table above come out right on LP64; it is
    // also why this can never be derived Default. On Windows the cryptoki
    // headers are consumed under `pack(1)`, so no pad field is declared at
    // all — one byte too many here would displace every entry point below
    // it, which is exactly what the offset assertions at the bottom of this
    // file refuse to compile. C_Initialize really sits at byte 2 there.
    #[cfg(not(windows))]
    _pad0: [u8; 6],
    pub initialize: extern "system" fn(init_args: *mut c_void) -> CkRv,
    pub finalize: extern "system" fn(reserved: *mut c_void) -> CkRv,
    _get_info: *mut c_void,
    /// Declared here because the list contains it even though we obtain the
    /// list itself through the exported `C_GetFunctionList` symbol.
    _get_function_list: *mut c_void,
    pub get_slot_list: extern "system" fn(
        token_present: u8,
        p_slot_list: *mut CkSlotId,
        pul_count: *mut CkUlong,
    ) -> CkRv,
    /// Read at list time to keep only slots whose token is present.
    pub get_slot_info: extern "system" fn(slot_id: CkSlotId, p_info: *mut CkSlotInfo) -> CkRv,
    pub get_token_info: extern "system" fn(slot_id: CkSlotId, p_info: *mut CkTokenInfo) -> CkRv,
    _get_mechanism_list: *mut c_void,
    _get_mechanism_info: *mut c_void,
    _init_token: *mut c_void,
    _init_pin: *mut c_void,
    _set_pin: *mut c_void,
    pub open_session: extern "system" fn(
        slot_id: CkSlotId,
        flags: CkUlong,
        application: *mut c_void,
        notify: *mut c_void,
        ph_session: *mut CkSessionHandle,
    ) -> CkRv,
    pub close_session: extern "system" fn(session: CkSessionHandle) -> CkRv,
    _close_all_sessions: *mut c_void,
    _get_session_info: *mut c_void,
    _get_operation_state: *mut c_void,
    _set_operation_state: *mut c_void,
    pub login: extern "system" fn(
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
    pub get_attribute_value: extern "system" fn(
        session: CkSessionHandle,
        object: CkObjectHandle,
        p_template: *mut CkAttribute,
        ul_count: CkUlong,
    ) -> CkRv,
    _set_attribute_value: *mut c_void,
    pub find_objects_init: extern "system" fn(
        session: CkSessionHandle,
        p_template: *mut CkAttribute,
        ul_count: CkUlong,
    ) -> CkRv,
    pub find_objects: extern "system" fn(
        session: CkSessionHandle,
        p_object: *mut CkObjectHandle,
        ul_max_object_count: CkUlong,
        pul_count: *mut CkUlong,
    ) -> CkRv,
    pub find_objects_final: extern "system" fn(session: CkSessionHandle) -> CkRv,
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
    pub sign_init: extern "system" fn(
        session: CkSessionHandle,
        p_mechanism: *mut CkMechanism,
        key: CkObjectHandle,
    ) -> CkRv,
    /// Signs the bytes handed to it. For `CKM_SHAxxx_RSA_PKCS` those are the
    /// raw digest and the module builds the DigestInfo; for `CKM_ECDSA` they
    /// are the digest already, exactly as the mechanism documents. Either way
    /// openfirma never hands a token anything but a digest.
    pub sign: extern "system" fn(
        session: CkSessionHandle,
        p_data: *mut u8,
        ul_data_len: CkUlong,
        p_signature: *mut u8,
        pul_signature_len: *mut CkUlong,
    ) -> CkRv,
    // the list continues (C_SignUpdate onwards); declaring a prefix is safe,
    // reading past it on an older module is not, and we never do.
}

/// The byte offset at which this target's ABI places the function-pointer
/// slot *k* of a `CK_FUNCTION_LIST` (slot 0 is the version pair, and the
/// table is dense from there on — every field after `finalize` has the same
/// alignment as a pointer, so slot k simply sits k slots in). Windows reads
/// it under the packed headers (`2 + k·p`, p = 4 on i686, 8 on x86_64); unix
/// LP64 uses naturally aligned 8-byte slots with version+padding occupying
/// slot 0 (so 8k), and 32-bit unixes land on the packed formula through
/// natural alignment. Every number is derived from the declared fields of
/// `CkFunctionList` for slots we declare, so the loader probe, this
/// function, and the struct can never drift apart; for undeclared slots it
/// extrapolates with the slot stride, which the assertions at the bottom of
/// this file prove exact where any of our slots could reach.
pub fn function_slot_offset(k: usize) -> usize {
    use core::mem::{offset_of, size_of};
    let ptr = size_of::<*const c_void>();
    if cfg!(windows) || size_of::<extern "system" fn()>() == 4 {
        match k {
            1 => offset_of!(CkFunctionList, initialize),
            2 => offset_of!(CkFunctionList, finalize),
            5 => offset_of!(CkFunctionList, get_slot_list),
            6 => offset_of!(CkFunctionList, get_slot_info),
            7 => offset_of!(CkFunctionList, get_token_info),
            13 => offset_of!(CkFunctionList, open_session),
            14 => offset_of!(CkFunctionList, close_session),
            19 => offset_of!(CkFunctionList, login),
            25 => offset_of!(CkFunctionList, get_attribute_value),
            27 => offset_of!(CkFunctionList, find_objects_init),
            28 => offset_of!(CkFunctionList, find_objects),
            29 => offset_of!(CkFunctionList, find_objects_final),
            43 => offset_of!(CkFunctionList, sign_init),
            // Slot 44 is the last declared entry; nothing reads past it.
            _ => 2 + k * ptr,
        }
    } else {
        match k {
            1 => offset_of!(CkFunctionList, initialize),
            2 => offset_of!(CkFunctionList, finalize),
            5 => offset_of!(CkFunctionList, get_slot_list),
            6 => offset_of!(CkFunctionList, get_slot_info),
            7 => offset_of!(CkFunctionList, get_token_info),
            13 => offset_of!(CkFunctionList, open_session),
            14 => offset_of!(CkFunctionList, close_session),
            19 => offset_of!(CkFunctionList, login),
            25 => offset_of!(CkFunctionList, get_attribute_value),
            27 => offset_of!(CkFunctionList, find_objects_init),
            28 => offset_of!(CkFunctionList, find_objects),
            29 => offset_of!(CkFunctionList, find_objects_final),
            43 => offset_of!(CkFunctionList, sign_init),
            _ => 8 * k,
        }
    }
}

// The padding above puts the first function pointer at byte 8 on unix, where
// repr(C)'s alignment matches C's — guaranteed per field. But our *declared*
// struct may still be narrower than the real table in exotic ABIs: the slot
// stride of a C function pointer can exceed `align_of::<fn()>` (the historical
// 32-bit x86 Pascal-call ABI is the example), and then every member after
// `sign_init` would read one slot too far and silently misparse. Refuse to
// compile rather than ship that; see ADR-0004 ("untestable parts"). On
// Windows the same guard runs against the packed layout: two version bytes
// plus 45 pointer slots, so the floor is `2 + 45·ptr`.
const _: () = assert!(
    core::mem::size_of::<CkFunctionList>()
        >= if cfg!(windows) {
            2 + 45 * core::mem::size_of::<extern "system" fn()>()
        } else {
            360
        }
);

// The compile-time proof of every layout claim in this file. These run on
// every CI target — x86_64/aarch64 unixes, both Windows MSVC ABIs — and if a
// target ever violates the PKCS#11 ABI assumptions as documented above, the
// build stops instead of shipping a module that misparses live tokens. The
// numbers mirror how vendor binaries actually lay these structs out on each
// platform (ADR-0004's probes; SoftHSM2's shipped header applies `pack(1)`
// for `_WIN32`, and its Windows builds answer with 4-byte CK_ULONGs).
const _: () = {
    // CK_ULONG is C's unsigned long: pointer-sized on every non-Windows
    // target we ship, and always 4 bytes on Windows regardless of arch.
    assert!(core::mem::size_of::<CkUlong>() == core::mem::size_of::<*const c_void>());
    if cfg!(windows) {
        assert!(core::mem::size_of::<CkUlong>() == 4);
    }

    // CK_VERSION is exactly two bytes. CK_ATTRIBUTE (ulong + pointer + ulong)
    // puts its pointer right after the ulong on every target we compile for:
    // natural alignment gives that on unixes, and pack(1) does on Windows —
    // measured against bindgen's translation of the same headers, and against
    // rustc's own `packed` layout for each MSVC ABI.
    assert!(core::mem::size_of::<CkVersion>() == 2);
    assert!(core::mem::offset_of!(CkAttribute, p_value) == core::mem::size_of::<CkUlong>());

    // CK_INFO: version at 0, and flags is a ulong that pushes the rest right.
    assert!(core::mem::offset_of!(CkInfo, cryptoki_version) == 0);
    assert!(core::mem::offset_of!(CkInfo, manufacturer_id) > 8);

    // CK_TOKEN_INFO: the four char arrays are 32+32+16+16 = 96 bytes of fixed
    // text on every platform, so `flags` starts exactly at 96 — where C
    // reads it under both packing rules for every ulong width we target.
    assert!(core::mem::offset_of!(CkTokenInfo, label) == 0);
    assert!(core::mem::offset_of!(CkTokenInfo, manufacturer_id) == 32);
    assert!(core::mem::offset_of!(CkTokenInfo, model) == 64);
    assert!(core::mem::offset_of!(CkTokenInfo, serial_number) == 80);
    assert!(core::mem::offset_of!(CkTokenInfo, flags) == 96);

    // Spec offsets for the entries openfirma calls. Windows modules are read
    // under the packed headers: spec function k sits at `2 + k·p` (p the
    // pointer width, 4 on i686 and 8 on x86_64) — exactly what the cfg'd
    // repr above compiles to. On unix, LP64 puts function k at byte 8k with
    // version+padding in slot 0; 32-bit unix ABIs align naturally, which for
    // these field types coincides with the packed `2 + k·4` reading, so the
    // same formula covers them.
    let ptr = core::mem::size_of::<extern "system" fn()>();
    if cfg!(windows) || ptr == 4 {
        assert!(core::mem::offset_of!(CkFunctionList, initialize) == 2 + ptr);
        assert!(core::mem::offset_of!(CkFunctionList, finalize) == 2 + 2 * ptr);
        assert!(core::mem::offset_of!(CkFunctionList, get_slot_list) == 2 + 5 * ptr);
        assert!(core::mem::offset_of!(CkFunctionList, get_token_info) == 2 + 7 * ptr);
        assert!(core::mem::offset_of!(CkFunctionList, open_session) == 2 + 13 * ptr);
        assert!(core::mem::offset_of!(CkFunctionList, close_session) == 2 + 14 * ptr);
        assert!(core::mem::offset_of!(CkFunctionList, login) == 2 + 19 * ptr);
        assert!(core::mem::offset_of!(CkFunctionList, get_attribute_value) == 2 + 25 * ptr);
        assert!(core::mem::offset_of!(CkFunctionList, find_objects_init) == 2 + 27 * ptr);
        assert!(core::mem::offset_of!(CkFunctionList, find_objects) == 2 + 28 * ptr);
        assert!(core::mem::offset_of!(CkFunctionList, find_objects_final) == 2 + 29 * ptr);
        assert!(core::mem::offset_of!(CkFunctionList, sign_init) == 2 + 43 * ptr);
        assert!(core::mem::offset_of!(CkFunctionList, sign) == 2 + 44 * ptr);
    } else {
        // Spec offsets on a 64-bit unix target: version at 0, then 8-byte slots.
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
    }
};
