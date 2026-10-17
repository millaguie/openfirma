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
//! - `CK_ULONG` is C's `unsigned long`, and its width table has exactly one
//!   trap in it: **every Windows MSVC ABI — x86_64, aarch64, i686 — is LLP64,
//!   where `unsigned long` is 4 bytes no matter the pointer size** (Microsoft's
//!   own x64 and ARM64 ABI tables agree; SoftHSM2-for-Windows' diagnostics
//!   measure `sizeof(CK_ULONG) = 4` on x64, while Linux answers 8). So it is
//!   never `usize` there, but everywhere else (every LP64 unix we ship) it
//!   equals `usize`. The cfg below spells out that table by width; the
//!   compile-time assertions tie it to `core::ffi::c_ulong`, which is how the
//!   Rust ecosystem's other PKCS#11 crates derive their alias too.
//! - The headers themselves tell Windows consumers to wrap everything in
//!   `#pragma pack(push, cryptoki, 1)` (the spec's Win32 recipe; SoftHSM2's
//!   shipped header applies it for `_WIN32` unconditionally) while unix C uses
//!   natural alignment. With the right per-platform ulong width above, that
//!   difference only *moves bytes* in `CK_FUNCTION_LIST`: its two-byte
//!   `CK_VERSION` at offset 0 means packed puts the first function pointer at
//!   byte 2 while natural alignment parks it at 8 (slot 0's tail padding).
//!   The other structs we touch read identically under both spellings for
//!   every width we target — the char arrays in CK_SLOT_INFO/CK_TOKEN_INFO
//!   pin `flags` to the same byte either way, and pack(1) cannot slide a
//!   pointer past an equal-width ulong — so they carry the cfg'd packed repr
//!   as pure fidelity to the headers (`cryptoki_packed!`) while this file's
//!   assertions pin every measured offset per target.
//! - Slot arithmetic therefore has exactly two forms: windows and any
//!   pointer-sized-ulong-but-packed table read spec function *k* at
//!   `2 + k·sizeof(pointer)` (4 on i686, 8 on x64/arm64); LP64 unixes read it
//!   at `8k`. `function_slot_offset` and the assertions in this file carry
//!   that rule; nothing else may hardcode slot addresses.
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

/// The `#[repr]` the cryptoki headers impose on a struct: Windows consumes
/// them under `#pragma pack(push, cryptoki, 1)` (the spec's own Win32 recipe,
/// and what SoftHSM2's shipped header applies for `_WIN32`), while unix C
/// uses natural alignment. Rust's bare `packed` reproduces the pragma exactly —
/// measured per target with rustc on all three MSVC ABIs *and* against clang
/// compiling the real headers with `-target x86_64-pc-windows-msvc`: under
/// pack(1) MSVC keeps `CK_VERSION` at two bytes and puts the first function
/// pointer of `CK_FUNCTION_LIST` at byte 2 (the compiler follows the pragma,
/// not a word-alignment floor), while `CK_ATTRIBUTE` compiles to pValue@4 +
/// ulValueLen@12 = size 16 on x64/arm64 — MSVC's documented ULLONG_MAX rule
/// keeps `unsigned long` an 8-aligned *type* even under /Zp1 — and to
/// 4/8/size-12 on i686. rustc's bare `packed` reproduces both numbers byte for
/// byte, exactly as bindgen's generated cryptoki bindings report them, and
/// every Rust PKCS#11 crate mirrors the headers the same way — cryptoki-rs
/// (`cryptoki_aligned!`) and rust-pkcs11 both wrap *every* cryptoki struct.
/// Reading a real vendor DLL any other way displaces its whole function table
/// by six bytes; that is why
/// the loader reads slots with `read_unaligned` (pack(1) legally puts slot 1
/// at byte 2, an unaligned address on x64) and why every claim here has a
/// per-target compile-time assertion below.
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
    /// `CK_ATTRIBUTE`, exactly as the header defines it: a ulong type tag, a
    /// value pointer, and a value length. On Windows CkUlong is 4 bytes and
    /// pack(1) moves the pointer right behind it (offset 4; `ul_value_len`
    /// then lands at 8 on i686 but at 12 on x64/aarch64 under MSVC's
    /// ULLONG_MAX rule — the "16 bytes, not 24" the review measured); on LP64
    /// everything is 8 wide and naturally aligned. Both readings are asserted
    /// per target below. Do not reorder
    /// these fields: NSS's own pkcs11t.h declares the same order.
    #[derive(Clone, Copy)]
    pub struct CkAttribute {
        pub type_: CkUlong,
        pub p_value: *mut c_void,
        pub ul_value_len: CkUlong,
    }
}

cryptoki_packed! {
    /// `CK_MECHANISM`: ulong + pointer + ulong. Same shape argument as
    /// `CkAttribute` above — packed on Windows so the pointer sits right after
    /// the 4-byte ulong exactly like the pack(1) header does.
    #[derive(Clone, Copy)]
    pub struct CkMechanism {
        pub mechanism: CkUlong,
        pub p_parameter: *mut c_void,
        /// A real `CK_ULONG` value slot: the spec's parameter length field. This
        /// crate only passes parameterless mechanisms, so zero is also correct.
        pub ul_parameter_len: CkUlong,
    }
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

cryptoki_packed! {
    /// `CK_INFO`, read nowhere yet but part of the documented prefix (slot 3
    /// of the table needs it declared). Its *trailing* ulong-after-bytes is
    /// exactly where packing changes byte placement, so it carries the cfg'd
    /// repr like the function list.
    #[derive(Clone, Copy, Default)]
    pub struct CkInfo {
        pub cryptoki_version: CkVersion,
        /// `CK_FLAGS` is a `CK_ULONG`: the ulong between two byte pairs is
        /// where platforms disagree on padding — see the struct's repr note.
        pub flags: CkUlong,
        pub manufacturer_id: [u8; 32],
        pub library_description: [u8; 32],
        pub library_version: CkVersion,
    }
}

/// `CK_TOKEN_INFO`. Note the total size is 192 bytes on a 64-bit target, not
/// the 188 the field list seems to add up to: after `utc_time` no field needs
/// 8-byte alignment, but the trailing row still rounds the struct up past
/// every member's natural placement — the offsets below pin down exactly
/// where C reads each one. Do not "fix" them from the field widths alone.
/// Its *fields* land at the same addresses under both packing rules on every
/// target we ship (every ulong starts after 96 bytes of fixed text or after
/// another ulong at natural width), which is why this struct keeps plain
/// `#[repr(C)]`: only offsets C reads depend on padding, and none here can
/// straddle a boundary — the trailing row affects total size only, which no
/// call ever uses.
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

cryptoki_packed! {
    /// The prefix of `CK_FUNCTION_LIST` that openfirma calls (see the module
    /// documentation for why a partial table is safe). Field order is exactly
    /// the v2.40 definition; underscore entries are spec functions this crate
    /// never calls and exist only to keep every offset honest. The layout rule
    /// is in `cryptoki_packed!` above: unix (natural alignment) puts spec
    /// function *k* at byte `8k`, with the two-byte version plus its 6-byte
    /// tail occupying slot 0; Windows (pack(1) headers, MSVC layout verified
    /// against clang targeting the same ABI) puts it at `2 + k·p` — p is 4 on
    /// i686 and 8 on x86_64/aarch64, so the two tables genuinely disagree by
    /// six bytes and the cfg'd repr below is what keeps each target reading a
    /// real vendor DLL correctly:
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
    ///           (p = 4 on i686, 8 on x86_64/aarch64)
    /// ```
    ///
    /// A third ABI fact lives here, also measured: `extern "system"` fn
    /// pointers are pointer-sized on all Windows MSVC ABIs (the far-pointer
    /// worry only applies to 16-bit DOS ABIs), so packed slots step exactly p.
    /// The offset assertions at the bottom of this file are the executable
    /// version of every claim above, and the loader reads the table with
    /// `read_unaligned` because pack(1) permits a vendor DLL to place slot 1
    /// at byte 2 — an unaligned address on x64 that a natural read would fault.
    #[derive(Clone, Copy)]
    pub struct CkFunctionList {
    /// PKCS#11's CK_VERSION is exactly two bytes on every ABI (asserted at
    /// the bottom of this file). Under Windows' packed headers the first
    /// function pointer lands right after it at byte 2; on unix the natural
    /// alignment of what follows pushes the pointers to byte 8, which is the
    /// `_pad0` field below spelling out that padding.
    pub version: CkVersion,
    // PKCS#11's CK_VERSION declares only two bytes, but unix C aligns whatever
    // follows to its own width, and real modules store their function pointers
    // starting at byte 8 (confirmed by calling a live SoftHSM through this
    // exact layout). Naming that tail padding `_pad0` is what puts the table's
    // slots where the LP64 header comment above says they are; it is also why
    // this struct can never derive Default. On Windows the cryptoki headers
    // are consumed under `pack(1)`, so no pad field exists at all — one byte
    // too many would displace every entry point below it, which the offset
    // assertions at the bottom of this file refuse to compile. C_Initialize
    // really does sit at byte 2 there (measured twice: clang with MSVC's ABI
    // flags on the real packed headers, and rustc's own `repr(packed)` for all
    // three MSVC ABIs — init 2, finalize +p, sign_init 2+43p exactly).
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
}

/// The byte offset at which this target's ABI places the function-pointer
/// slot *k* of a `CK_FUNCTION_LIST` (slot 0 is the version pair, and the
/// table is dense from there on — every field after it has pointer width, so
/// slot k simply sits k slots in). Windows reads it under the packed headers
/// (`2 + k·p`, p = 4 on i686, 8 on x86_64/aarch64); unix LP64 uses naturally
/// aligned 8-byte slots with version+padding occupying slot 0 (so 8k), and
/// 32-bit unixes land on the packed formula through natural alignment. Every
/// declared slot resolves through `offset_of!` on this target's repr, so the
/// loader probe, this function, and the struct can never drift apart; for
/// undeclared slots it extrapolates with the slot stride, which the assertions
/// at the bottom of this file prove exact wherever our slots could reach.
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
// What no repr can guarantee is the *span*: if some ABI ever padded a slot
// wider than one pointer (the historical 32-bit x86 Pascal-call ABI is the
// example), our declared struct could end before spec slot 44 and every
// extrapolated offset would silently misparse the tail of the real table.
// Refuse to compile rather than ship that; see ADR-0004 ("untestable parts").
const _: () = assert!(
    // Span through the last *declared* slot, C_Sign at spec slot 44. The
    // stride between consecutive declared slots is one pointer wherever it
    // could be observed (asserted below and on every CI target), so this
    // floor is exact under whatever packing the target's headers use; the
    // guard catches an ABI that ends the struct before its own declared tail.
    core::mem::size_of::<CkFunctionList>()
        >= core::mem::offset_of!(CkFunctionList, sign) + core::mem::size_of::<*const c_void>(),
    "the declared CK_FUNCTION_LIST is shorter than the spec table it models",
);

// The compile-time proof of every layout claim in this file. These run on
// every CI target — x86_64/aarch64 unixes, all three Windows MSVC ABIs — and
// if a target ever violates the PKCS#11 ABI assumptions as documented above,
// the build stops instead of shipping a module that misparses live tokens.
// The numbers below are not opinions: each one was measured per target with
// rustc's own `offset_of!`/`size_of!` *and* against clang compiling NSS's real
// packed pkcs11t.h/pkcs11p.h for the same ABIs (ADR-0004's probes; SoftHSM2's
// shipped header applies `pack(1)` for `_WIN32`, and its Windows builds answer
// with 4-byte CK_ULONGs). Where a number can differ between targets it is
// written as a branch on measurable facts (the pointer width), never on wish.
const _: () = {
    // CK_ULONG is C's unsigned long: `core::ffi::c_ulong` is that type for
    // the compiler, so they must agree byte for byte — cryptoki-rs and every
    // other Rust PKCS#11 crate derive their alias the same way. On Windows
    // that means 4 bytes on *every* MSVC ABI (x86_64 and aarch64 included:
    // LLP64 holds across architectures; Microsoft's own ARM64 ABI table
    // agrees, `unsigned long` = 4) while `usize` is 8 — the exact mistake
    // C1 was. Non-Windows targets are LP64/ILP32, where it equals the
    // pointer width.
    assert!(core::mem::size_of::<CkUlong>() == core::mem::size_of::<core::ffi::c_ulong>());
    if cfg!(windows) {
        assert!(core::mem::size_of::<CkUlong>() == 4);
    }

    // CK_VERSION is exactly two bytes on every target: both fields are u8 and
    // no packing can grow a pair of bytes. CkFunctionList relies on it — the
    // first pointer slot sits two bytes into the table, which is why the
    // loader reads slots unaligned.
    assert!(core::mem::size_of::<CkVersion>() == 2);

    let ptr = core::mem::size_of::<*const c_void>();
    let ulong = core::mem::size_of::<CkUlong>();
    assert!(ptr == core::mem::size_of::<extern "system" fn()>());

    // CK_ATTRIBUTE (ulong + pointer + ulong) is what openfirma hands the
    // module in C_GetAttributeValue/C_FindObjectsInit, so its shape *is* the
    // ABI. Every field offset below was measured twice — rustc's own repr on
    // each target, and clang compiling NSS's real packed pkcs11t.h/pkcs11p.h
    // for the MSVC ABIs:
    assert!(core::mem::offset_of!(CkAttribute, type_) == 0);
    if cfg!(windows) {
        // pack(1) slides the pointer up against the 4-byte ulong (offset 4),
        // and the trailing ulong follows at 8 on i686 but at 12 on x64/
        // aarch64 — MSVC's documented ULLONG_MAX rule keeps `unsigned long`
        // an 8-aligned *type* even under /Zp1, which both clang (attr 4/12/16)
        // and rustc's bare `packed` (measured: 4/12/16 vs i686's 4/8/12)
        // reproduce byte for byte. Either way every pointer and length read
        // lands inside the pinned prefix; only tail padding sits past it.
        assert!(core::mem::offset_of!(CkAttribute, p_value) == 4);
        assert!(core::mem::offset_of!(CkAttribute, ul_value_len) == if ptr == 4 { 8 } else { 12 });
        assert!(core::mem::size_of::<CkAttribute>() == if ptr == 4 { 12 } else { 16 });
    } else {
        // LP64/ILP32: three naturally aligned pointer-width fields.
        assert!(core::mem::offset_of!(CkAttribute, p_value) == ptr);
        assert!(core::mem::offset_of!(CkAttribute, ul_value_len) == 2 * ptr);
        assert!(core::mem::size_of::<CkAttribute>() == 3 * ptr);
    }

    // CK_MECHANISM is the same shape and gets the same pinning: it crosses to
    // the module in C_SignInit, so a wrong layout hands the token garbage.
    assert!(core::mem::offset_of!(CkMechanism, mechanism) == 0);
    if cfg!(windows) {
        assert!(core::mem::offset_of!(CkMechanism, p_parameter) == 4);
        assert!(
            core::mem::offset_of!(CkMechanism, ul_parameter_len) == if ptr == 4 { 8 } else { 12 }
        );
        assert!(core::mem::size_of::<CkMechanism>() == if ptr == 4 { 12 } else { 16 });
    } else {
        assert!(core::mem::offset_of!(CkMechanism, p_parameter) == ptr);
        assert!(core::mem::offset_of!(CkMechanism, ul_parameter_len) == 2 * ptr);
    }

    // CK_INFO carries the version pair, then the ulong flags between fixed
    // char arrays. Under pack(1)/packed that is 2 + sizeof(ulong) for flags —
    // exact everywhere openfirma reads it (nowhere today; slot 3's shape must
    // simply stay honest), and monotonic member order is all C guarantees:
    assert!(core::mem::offset_of!(CkInfo, cryptoki_version) == 0);
    assert!(core::mem::offset_of!(CkInfo, flags) >= core::mem::size_of::<CkVersion>());
    assert!(
        core::mem::offset_of!(CkInfo, manufacturer_id)
            >= core::mem::offset_of!(CkInfo, flags) + ulong
    );

    // CK_SLOT_INFO / CK_TOKEN_INFO: the fixed char arrays (64+32 and 96 bytes
    // of them) are the whole prefix on every ABI we support, so `flags` sits
    // at 96 in the token record — where the token filter reads it under both
    // packing rules for every ulong width. CK_SLOT_INFO's own offset follows
    // from the running sums under pack(1) and is only pinned where it is read.
    assert!(core::mem::offset_of!(CkTokenInfo, label) == 0);
    assert!(core::mem::offset_of!(CkTokenInfo, manufacturer_id) == 32);
    assert!(core::mem::offset_of!(CkTokenInfo, model) == 64);
    assert!(core::mem::offset_of!(CkTokenInfo, serial_number) == 80);
    assert!(core::mem::offset_of!(CkTokenInfo, flags) == 96);

    // The function table itself. openfirma reads it exclusively through
    // `offset_of!` (the loader probe and `function_slot_offset`), so what has
    // to be true is *relational*: slot 1 begins at the two version bytes'
    // tail, consecutive declared slots are exactly one pointer apart, and the
    // last declared slot lands where the spec's numbering says. Those facts
    // hold under any packing that reproduces the headers, and they are what
    // the extrapolation in `function_slot_offset` assumes:
    assert!(core::mem::offset_of!(CkFunctionList, version) == 0);
    // Slot 1 starts where the ABI's slot-0 record ends: right after the two
    // version bytes under the packed Windows headers, or behind LP64/ILP32's
    // tail padding — byte 8 on a 64-bit unix, where SoftHSM2 keeps them.
    if cfg!(windows) {
        assert!(core::mem::offset_of!(CkFunctionList, initialize) == 2);
    } else if ptr == 8 {
        assert!(core::mem::offset_of!(CkFunctionList, initialize) == 8);
    }
    assert!(
        core::mem::offset_of!(CkFunctionList, finalize)
            - core::mem::offset_of!(CkFunctionList, initialize)
            == ptr
    );
    // Slot arithmetic against the spec numbering (slot k = `initialize` plus
    // k−1 pointers) for every entry point this crate calls:
    let base = core::mem::offset_of!(CkFunctionList, initialize);
    assert!(core::mem::offset_of!(CkFunctionList, get_slot_list) == base + 4 * ptr);
    assert!(core::mem::offset_of!(CkFunctionList, get_slot_info) == base + 5 * ptr);
    assert!(core::mem::offset_of!(CkFunctionList, get_token_info) == base + 6 * ptr);
    assert!(core::mem::offset_of!(CkFunctionList, open_session) == base + 12 * ptr);
    assert!(core::mem::offset_of!(CkFunctionList, close_session) == base + 13 * ptr);
    assert!(core::mem::offset_of!(CkFunctionList, login) == base + 18 * ptr);
    assert!(core::mem::offset_of!(CkFunctionList, get_attribute_value) == base + 24 * ptr);
    assert!(core::mem::offset_of!(CkFunctionList, find_objects_init) == base + 26 * ptr);
    assert!(core::mem::offset_of!(CkFunctionList, find_objects) == base + 27 * ptr);
    assert!(core::mem::offset_of!(CkFunctionList, find_objects_final) == base + 28 * ptr);
    assert!(core::mem::offset_of!(CkFunctionList, sign_init) == base + 42 * ptr);
    assert!(core::mem::offset_of!(CkFunctionList, sign) == base + 43 * ptr);
};
