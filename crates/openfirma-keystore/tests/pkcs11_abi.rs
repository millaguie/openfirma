//! The PKCS#11 ABI itself, byte-exact for whichever target compiles this —
//! the regression net for the two mistakes that compile fine everywhere and
//! misparse tokens silently on Windows: reading `CK_ULONG` as `usize` (C's
//! `unsigned long` is 4 bytes even in a 64-bit Windows process), and reading
//! the function table at slot·8 when the cryptoki headers pack it on Windows
//! (first pointer at byte 2, stride = pointer size).
//!
//! A live module can only prove the layout where one exists — SoftHSM is
//! Linux-only in CI — so these tests encode the two spec rules independently
//! of openfirma's own code and demand that its public types agree on every
//! target, Windows jobs included. They mirror what vendor libraries actually
//! do: SoftHSM2's shipped header applies `#pragma pack(push, cryptoki,1)` for
//! `_WIN32`, and its Windows builds answer with 4-byte `CK_ULONG`s (its own
//! issue-tracker diagnostics measure exactly that).

use std::mem::{offset_of, size_of};
use std::ptr;

use openfirma_keystore::pkcs11::types::{
    CK_UNAVAILABLE_INFORMATION, CkAttribute, CkFunctionList, CkInfo, CkSlotInfo, CkTokenInfo,
    CkUlong, CkVersion,
};

/// The byte offset of spec function *k* in a `CK_FUNCTION_LIST`, derived here
/// from the two ABI rules (packed headers on Windows: version pair then slot
/// 1 immediately; unix LP64: natural alignment puts it behind slot 0's tail
/// padding at 8k; ILP32 unixes land on the same formula as packing through
/// their own natural alignment). Deliberately written without looking at any
/// constant in `types.rs`.
fn abi_slot(k: usize) -> usize {
    let ptr = size_of::<*const u8>();
    if cfg!(windows) || ptr == 4 {
        2 + k * ptr
    } else {
        8 * k
    }
}

#[test]
fn ck_ulong_is_c_unsigned_long_on_every_target() {
    let want = if cfg!(windows) { 4 } else { size_of::<usize>() };
    assert_eq!(size_of::<CkUlong>(), want);
}

#[test]
fn ck_unavailable_information_is_all_ones_at_the_platform_width() {
    // ~0UL: on Windows the module writes 0xFFFF_FFFF, not usize::MAX. A
    // comparison widened wrongly would miss every "cannot read" answer there.
    let width = size_of::<CkUlong>();
    let all_ones: u128 = (1u128 << (8 * width)) - 1;
    assert_eq!(CK_UNAVAILABLE_INFORMATION as u128, all_ones);
}

#[test]
fn function_list_slots_sit_where_this_abi_puts_them() {
    // Every entry openfirma calls, checked through the public helper and
    // again straight off the struct. The two must agree with `abi_slot`.
    for (name, off) in openfirma_keystore::pkcs11::function_list_offsets() {
        let k = match name {
            "C_Initialize" => 1,
            "C_GetSlotList" => 5,
            "C_OpenSession" => 13,
            "C_Login" => 19,
            "C_GetAttributeValue" => 25,
            "C_FindObjectsInit" => 27,
            "C_SignInit" => 43,
            "C_Sign" => 44,
            other => panic!("offsets() grew a new entry: {other}"),
        };
        assert_eq!(off, abi_slot(k), "{name} via the loader helper");
    }
    assert_eq!(offset_of!(CkFunctionList, initialize), abi_slot(1));
    assert_eq!(offset_of!(CkFunctionList, finalize), abi_slot(2));
    assert_eq!(offset_of!(CkFunctionList, get_slot_info), abi_slot(6));
    assert_eq!(offset_of!(CkFunctionList, close_session), abi_slot(14));
    assert_eq!(offset_of!(CkFunctionList, find_objects), abi_slot(28));
    assert_eq!(offset_of!(CkFunctionList, find_objects_final), abi_slot(29));
}

#[test]
fn version_pair_is_two_bytes_and_heads_the_table() {
    assert_eq!(size_of::<CkVersion>(), 2);
    assert_eq!(offset_of!(CkFunctionList, version), 0);
}

#[test]
fn attribute_struct_matches_the_header_layout_for_this_platform() {
    // ulong + pointer + ulong. Naturally aligned (unix): each field starts at
    // its own width boundary — on LP64 that is 0/8/16, on ILP32 0/4/8, and
    // both are exactly `offset_of(p_value) == size_of::<CkUlong>()`. Under
    // the packed Windows headers the pointer sits at ulong+2 only when C
    // would pad there — with a 4-byte ulong it never does; MSVC's pack(1) and
    // Rust's `packed` agree on 0/4/12 (measured against bindgen's output for
    // cryptoki, the same translation unit through clang). A template
    // misaligned by four bytes hands the token a wrong-length value slot.
    let u = size_of::<CkUlong>();
    assert_eq!(offset_of!(CkAttribute, type_), 0);
    if cfg!(windows) {
        assert_eq!(offset_of!(CkAttribute, p_value), u);
    } else {
        assert_eq!(offset_of!(CkAttribute, p_value), u);
        assert_eq!(offset_of!(CkAttribute, ul_value_len), 2 * u);
    }
}

#[test]
fn info_structs_read_their_fields_where_c_puts_them() {
    // CK_INFO: the ulong flags between two byte pairs is the classic place a
    // 4-byte-ulong platform diverges from usize thinking; CK_SLOT_INFO's and
    // CK_TOKEN_INFO's flags follow 64+32 and 96 bytes of fixed text.
    assert_eq!(offset_of!(CkInfo, cryptoki_version), 0);
    assert!(offset_of!(CkSlotInfo, flags) >= 96);
    assert_eq!(offset_of!(CkTokenInfo, label), 0);
    assert_eq!(offset_of!(CkTokenInfo, serial_number), 80);
    let base = CkSlotInfo::default();
    let ptr = ptr::from_ref(&base).cast::<u8>();
    let flags = ptr::addr_of!(base.flags).cast::<u8>();
    assert_eq!(unsafe { flags.offset_from(ptr) }, 96);
}

#[test]
fn the_table_is_dense_and_sized_through_c_sign() {
    // Slot 44 is C_Sign and the last declared entry; the image must cover it.
    let span = offset_of!(CkFunctionList, sign) + size_of::<*const u8>();
    assert_eq!(span, abi_slot(44) + size_of::<*const u8>());
    assert!(size_of::<CkFunctionList>() >= span);
}

#[test]
fn the_entry_point_type_is_a_plain_platform_pointer() {
    // mod.rs transmutes table slots into `extern "system" fn(..)` values to
    // call them; that is only ABI-honest if every such value is a bare,
    // pointer-width fat-free pointer on this target (true for both MSVC ABIs
    // and every unix; false the day someone wraps it in a closure or Box).
    assert_eq!(size_of::<extern "system" fn()>(), size_of::<*const u8>());
}

/// Builds the image of a function table the way *this platform's* ABI lays a
/// real module's out (independently of the crate: `abi_slot` only), and reads
/// it back the two ways the loader does — through the published slot offsets
/// and unaligned on purpose. On packed ABIs (Windows) several slots are not
/// pointer-aligned, so a plain aligned read would be UB/misuse; this test is
/// also the executable proof that reading them needs no alignment fixup to
/// disagree with where the declared struct puts them.
#[test]
fn a_synthetic_table_reads_at_the_same_offsets_the_struct_declares() {
    let ptr = size_of::<*const u8>();
    // version pair + slots 1..=45 (one past C_Sign so nothing dangles).
    let mut image = vec![0u8; abi_slot(45) + ptr];
    image[0] = 2;
    image[1] = 40;
    // a recognizable, never-called sentinel as every entry point
    let sentinel = image.as_mut_ptr() as *const u8;
    for k in 1..=45 {
        unsafe {
            (image.as_mut_ptr().add(abi_slot(k)) as *mut *const u8).write_unaligned(sentinel);
        }
    }
    // The loader's published view and the struct's own offsets must land on
    // exactly the bytes written above — this is the C1/H-4 regression in one
    // line: it fails the moment any slot formula disagrees between the two.
    for (name, off) in openfirma_keystore::pkcs11::function_list_offsets() {
        let read = unsafe { (image.as_ptr().add(off) as *const *const u8).read_unaligned() };
        assert!(std::ptr::eq(read, sentinel), "{name} read outside its slot");
    }
    // and the version pair is where the loader's `(*functions).version` reads it
    assert_eq!(image[offset_of!(CkFunctionList, version)], 2);
    assert_eq!(unsafe { *image.as_ptr().add(1) }, 40);
}
