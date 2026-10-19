//! The PKCS#11 ABI itself, byte-exact for whichever target compiles this —
//! the regression net for the mistakes that compile fine everywhere and
//! misparse tokens silently on Windows: reading `CK_ULONG` as `usize` (C's
//! `unsigned long` is 4 bytes even in a 64-bit Windows process, on ARM64 too
//! — Microsoft's own ABI tables say so), and reading the function table at
//! slot·8 when the cryptoki headers pack it on Windows (first pointer at
//! byte 2, stride = pointer size).
//!
//! A live module can only prove the layout where one exists — SoftHSM is
//! Linux-only in CI — so these tests encode the width and packing rules
//! independently of openfirma's own code and demand that its public types
//! agree on every target, Windows jobs included.

use std::mem::{offset_of, size_of};
use std::ptr;

use openfirma_keystore::pkcs11::types::{
    CK_UNAVAILABLE_INFORMATION, CkAttribute, CkFunctionList, CkInfo, CkSlotInfo, CkTokenInfo,
    CkUlong, CkVersion,
};

/// The width C's `unsigned long` has on this target: 4 on every Windows MSVC
/// ABI (LLP64 holds for x86_64 and aarch64 alike), otherwise the LP64/ILP32
/// pointer width. Written from Microsoft's published type tables and the C
// standard minimums, not by peeking at `types.rs`.
const fn c_ulong_width() -> usize {
    if cfg!(windows) { 4 } else { size_of::<usize>() }
}

/// The byte offset of spec function *k* in a `CK_FUNCTION_LIST`, derived here
/// from the packing rules, not by peeking at `types.rs`: under the packed
/// cryptoki headers (all Windows MSVC ABIs) slot 1 — C_Initialize — sits
/// immediately behind the two version bytes at byte 2, and every following
/// spec slot one pointer-width after it: `2 + (k−1)·p`. Unix LP64 aligns
/// each 8-byte pointer behind slot 0's tail padding, so slot k lands at 8k
/// there. (A 32-bit unix *test* target would differ from both formulas —
/// nothing here runs it: the compile-time asserts in `types.rs` guard the
/// slots that file actually declares on such targets.)
fn abi_slot(k: usize) -> usize {
    let ptr = size_of::<*const u8>();
    if cfg!(windows) {
        2 + (k - 1) * ptr
    } else {
        8 * k
    }
}

#[test]
fn ck_ulong_is_c_unsigned_long_on_every_target() {
    assert_eq!(size_of::<CkUlong>(), c_ulong_width());
    // the one alias every Rust PKCS#11 crate must share with the C ABI:
    assert_eq!(
        core::mem::size_of::<CkUlong>(),
        core::mem::size_of::<core::ffi::c_ulong>(),
        "CK_ULONG must equal core::ffi::c_ulong byte for byte"
    );
    if cfg!(windows) {
        // the exact mistake C1 was: usize (8 on x64) standing in for a
        // 4-byte unsigned long. Windows is LLP64, so `unsigned long` is
        // always 4 bytes; the width divergence from usize holds everywhere
        // this crate can build for Windows except i686, where both are
        // 4 and only the first assert carries the rule.
        assert_eq!(size_of::<CkUlong>(), 4);
        if size_of::<usize>() > 4 {
            assert_ne!(size_of::<CkUlong>(), size_of::<usize>());
        }
    }
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
    // again straight off the struct. The two must agree with `abi_slot`: slot
    // 1 at byte 2 under Windows' packed cryptoki headers (measured against
    // clang on the real headers), or behind LP64's slot-0 tail padding, with
    // one pointer stride per spec index. That is all both this file and the
    // loader may ever assume.
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

/// Review M-1: the raw `C_GetSlotInfo` read (the one slot handled outside the
/// typed prefix) must address the table through the SAME ABI rule as every
/// other slot — `function_slot_offset`, exposed as `slot_byte_offset`. The old
/// loader used `add(6)`, i.e. `6·sizeof(pointer)`, which is 48 on LP64 Unix and
/// therefore "looked right" on every Linux dev box, but is wrong on Windows'
/// packed table (slot 6 at byte 42 on x64, 22 on i686) and read a garbage
/// pointer that was then transmuted to a function and called. This asserts the
/// rule directly, so the Windows CI jobs catch any regression even though no
/// live module exists there to exhibit it.
#[test]
fn every_slot_is_addressed_through_the_abi_rule_including_the_raw_one() {
    // slot 6 is the raw one; the assertion must hold on every target
    assert_eq!(
        openfirma_keystore::pkcs11::slot_byte_offset(6),
        abi_slot(6),
        "the raw C_GetSlotInfo read must use the packed/ABI offset, not 6·ptr"
    );
    // and the typed loader's own slots still agree, so the two paths cannot drift
    for k in [1usize, 5, 7, 13, 14, 19, 25, 27, 28, 29, 43, 44] {
        assert_eq!(
            openfirma_keystore::pkcs11::slot_byte_offset(k),
            abi_slot(k),
            "spec slot {k} must sit where this target's ABI puts it"
        );
    }
}

#[test]
fn version_pair_is_two_bytes_and_heads_the_table() {
    assert_eq!(size_of::<CkVersion>(), 2);
    assert_eq!(offset_of!(CkFunctionList, version), 0);
}

#[test]
fn attribute_struct_matches_the_header_layout_for_this_platform() {
    // ulong + pointer + ulong. On unixes natural alignment puts each field at
    // a pointer-width boundary; on Windows the pack(1) headers slide them:
    // pValue right behind the 4-byte ulong at offset 4, and ulValueLen after
    // it — at 8 on i686, at 12 on x64/aarch64 where MSVC keeps `unsigned
    // long` an 8-aligned type even under /Zp1 (measured per target against
    // clang compiling the real packed headers). What must hold for openfirma
    // everywhere: the pointer follows the ulong with no gap, and it is the
    // first field the module writes through.
    let u = size_of::<CkUlong>();
    assert_eq!(offset_of!(CkAttribute, type_), 0);
    if cfg!(windows) {
        assert_eq!(offset_of!(CkAttribute, p_value), 4);
        let ptr = size_of::<*const u8>();
        assert_eq!(
            offset_of!(CkAttribute, ul_value_len),
            if ptr == 4 { 8 } else { 12 }
        );
    } else {
        assert_eq!(offset_of!(CkAttribute, p_value), u);
        assert_eq!(offset_of!(CkAttribute, ul_value_len), 2 * u);
    }
}

#[test]
fn slot_and_token_info_read_their_flags_where_the_header_puts_them() {
    // CK_SLOT_INFO's flags and CK_TOKEN_INFO's ulong row follow fixed char
    // arrays (96 bytes each) that no ABI pads, so `flags` sits at 96 under
    // both packing rules on every target — the value the token filter reads.
    let mut slot = CkSlotInfo::default();
    let base = ptr::from_mut(&mut slot).cast::<u8>();
    let flags = ptr::addr_of!(slot.flags).cast::<u8>();
    assert_eq!(unsafe { flags.offset_from(base) }, 96);

    assert_eq!(offset_of!(CkTokenInfo, label), 0);
    assert_eq!(offset_of!(CkTokenInfo, manufacturer_id), 32);
    assert_eq!(offset_of!(CkTokenInfo, model), 64);
    assert_eq!(offset_of!(CkTokenInfo, serial_number), 80);
    assert_eq!(offset_of!(CkTokenInfo, flags), 96);

    // CK_INFO is never read; its only contract is monotonic member order.
    assert_eq!(offset_of!(CkInfo, cryptoki_version), 0);
}

#[test]
fn ck_info_follows_the_headers_field_order() {
    // The header, in order: `CK_VERSION cryptokiVersion; CK_UTF8CHAR
    // manufacturerID[32]; CK_FLAGS flags; CK_UTF8CHAR libraryDescription[32];
    // CK_VERSION libraryVersion;` — round 2, 04-N9: this struct had `flags`
    // second, which is no ABI's CK_INFO. Nothing reads it yet, so the order is
    // the contract; the offsets are what an implementation of C_GetInfo would
    // read, and each packing rule gives them exactly.
    let ulong = size_of::<CkUlong>();
    assert_eq!(offset_of!(CkInfo, cryptoki_version), 0);
    // the 32-byte array no ABI pads, right behind the version pair
    assert_eq!(offset_of!(CkInfo, manufacturer_id), 2);
    if cfg!(windows) {
        // pack(1): no padding anywhere, the same concatenation the
        // `CkAttribute` offsets above measure against the MSVC ABIs (a
        // 4-byte `unsigned long` does not hold an 8-byte alignment there).
        assert_eq!(offset_of!(CkInfo, flags), 34);
        assert_eq!(offset_of!(CkInfo, library_description), 38);
        assert_eq!(offset_of!(CkInfo, library_version), 70);
        assert_eq!(size_of::<CkInfo>(), 72);
    } else {
        // natural alignment: the ulong rounds its own offset up to its width,
        // and everything after it follows in declared order.
        let flags = (2 + 32usize).next_multiple_of(ulong);
        assert_eq!(offset_of!(CkInfo, flags), flags);
        assert_eq!(offset_of!(CkInfo, library_description), flags + ulong);
        assert_eq!(offset_of!(CkInfo, library_version), flags + ulong + 32);
        assert_eq!(
            size_of::<CkInfo>(),
            (flags + ulong + 32 + 2).next_multiple_of(ulong)
        );
    }
}

#[test]
fn ck_token_info_is_the_size_the_module_will_write_into_it() {
    // The buffer openfirma passes to `C_GetTokenInfo` is this struct, and the
    // module fills it as C lays it out: a short one is rejected (NSS says so)
    // and a long one silently reads whatever the module left. Round 2, N7
    // found the ADR claiming 192 here and the type's own comment claiming 188;
    // neither is a layout this target (or any other) produces.
    let ulong = size_of::<CkUlong>();
    // 32+32+16+16 bytes of text, eleven CK_ULONGs, then the two version pairs
    // and the 16-byte UTC string.
    let end = 96 + 11 * ulong + 2 + 2 + 16;
    let laid_out = if cfg!(windows) {
        // pack(1): alignment 1, so nothing rounds the tail
        end
    } else {
        // the ulongs' own alignment rounds the tail up (LP64: 204 -> 208)
        end.next_multiple_of(ulong)
    };
    assert_eq!(size_of::<CkTokenInfo>(), laid_out);
    assert_eq!(size_of::<CkTokenInfo>(), if ulong == 8 { 208 } else { 160 });
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
/// it back through the published slot offsets. On packed ABIs several slots
/// are not pointer-aligned, so the unaligned read is load-bearing; if the
/// loader's offsets ever disagree with where the written bytes sit, this
/// fails before a real token can.
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
    // exactly the bytes written above — the C1/H-4 regression in one line.
    for (name, off) in openfirma_keystore::pkcs11::function_list_offsets() {
        let read = unsafe { (image.as_ptr().add(off) as *const *const u8).read_unaligned() };
        assert!(ptr::eq(read, sentinel), "{name} read outside its slot");
    }
    // and the version pair is where the loader's `(*functions).version` reads it
    assert_eq!(image[offset_of!(CkFunctionList, version)], 2);
    assert_eq!(unsafe { *image.as_ptr().add(1) }, 40);
}
