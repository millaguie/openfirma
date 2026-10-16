// Two hand-built ELF carriers — headers and program tables written byte by
// byte, because the point of both is a *program header layout* no compiler
// produces and every hostile input might claim.
//
// `minimal_carrier_elf` is the honest shape: one R+X page carries the file
// header and program table (code that actually executes lives in there too —
// an R+X text segment is what every ELF "hello world" is), and the document
// follows at 0x1000, appended untouched with its offsets intact exactly the
// way a zip self-extractor appends its archive. Nothing past that boundary
// belongs to a mapped segment — which is precisely the claim `carrier_split`
// verifies before exempting a file from plain-file bounds.
//
// `fat_carrier_elf` is the same document behind a prepender that maps its own
// padding: a second PT_LOAD whose file extent crosses 0x1000. Bytes past the
// split of such a file are live memory of every process it starts, so the
// shape must be refused and no bound relaxed — the negative fixture for the
// one check that decides everything else about a carrier.
//
// An earlier generation of this fixture also *executed* itself: a hand-written
// `execve` stub re-ran the clone to run the reader inside its own container.
// It was deleted after proving impossible on the CI machine's kernel (see the
// comment in `hostile.rs::a_self_extracting_binary_reads_the_document_it_carries`);
// what remains is exactly the part data can prove, and hostile.rs says which
// claims live elsewhere because of it.

/// The honest carrier: image in page zero, document appended at 0x1000 with
/// its offsets untouched.
pub(crate) fn minimal_carrier_elf(doc: &[u8], _carrier_path: &[u8]) -> Vec<u8> {
    let mut elf = vec![0u8; 0x1000];
    write_header_page(&mut elf);
    // One PT_LOAD: the whole page, read and execute — a static text segment,
    // the same shape every toolchain emits. Its file extent ends at the page
    // boundary, so from 0x1000 on nothing is mapped: the entire document lies
    // past what any process from this image can reach.
    let ph = 64;
    elf[ph..ph + 4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    elf[ph + 4..ph + 8].copy_from_slice(&5u32.to_le_bytes()); // p_flags: R+X
    elf[ph + 8..ph + 16].copy_from_slice(&0u64.to_le_bytes()); // p_offset
    elf[ph + 16..ph + 24].copy_from_slice(&0x400000u64.to_le_bytes()); // p_vaddr
    elf[ph + 32..ph + 40].copy_from_slice(&0x1000u64.to_le_bytes()); // p_filesz
    elf[ph + 40..ph + 48].copy_from_slice(&0x1000u64.to_le_bytes()); // p_memsz
    elf[ph + 48..ph + 56].copy_from_slice(&0x1000u64.to_le_bytes()); // p_align
    let mut out = elf;
    out.extend_from_slice(doc);
    out
}

/// The refused carrier: the same one-page image, plus a second PT_LOAD whose
/// extent crosses the split. Whether *these* bytes run is irrelevant to the
/// check (and was the whole point of the deleted executed half): a program
/// header that maps past the boundary describes live memory, and live memory
/// is exactly what an exemption about unreachable bytes may never cover.
pub(crate) fn fat_carrier_elf(doc: &[u8], carrier_path: &[u8]) -> Vec<u8> {
    let mut out = minimal_carrier_elf(doc, carrier_path);
    let ph2 = 64 + 56;
    // There is room between the program table and whatever the document needs:
    // this record lives inside page zero, where a loader looks for it.
    out[ph2..ph2 + 4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    out[ph2 + 4..ph2 + 8].copy_from_slice(&5u32.to_le_bytes()); // p_flags: R+X
    out[ph2 + 8..ph2 + 16].copy_from_slice(&0x1000u64.to_le_bytes()); // p_offset: starts AT the split
    out[ph2 + 16..ph2 + 24].copy_from_slice(&0x401000u64.to_le_bytes()); // p_vaddr (congruent)
    // A page of payload declared into the image: whatever doc follows, this
    // segment alone ends past 0x1000, which is the whole refusal.
    out[ph2 + 32..ph2 + 40].copy_from_slice(&0x1000u64.to_le_bytes()); // p_filesz
    out[ph2 + 40..ph2 + 48].copy_from_slice(&0x1000u64.to_le_bytes()); // p_memsz
    out[ph2 + 48..ph2 + 56].copy_from_slice(&0x1000u64.to_le_bytes()); // p_align
    out[56..58].copy_from_slice(&2u16.to_le_bytes()); // e_phnum
    out
}

/// The identical ELF front end both builders share: magic, class, machine, the
/// header fields in their real offsets, one program-header entry to come.
/// Writing e_phnum at its own offset (56) rather than a neighbour's is not
/// ceremony — an earlier draft set section fields by accident and produced an
/// image the loader refused with "exec format error", which is exactly the
/// failure mode this whole fixture must never confuse with a *check* refusing
/// a shape.
fn write_header_page(elf: &mut [u8]) {
    assert_eq!(elf.len(), 0x1000);
    elf[0..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2; // ELFCLASS64
    elf[5] = 1; // ELFDATA2LSB
    elf[6] = 1; // EV_CURRENT
    elf[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    elf[18..20].copy_from_slice(&0x3eu16.to_le_bytes()); // EM_X86_64
    elf[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version
    elf[24..32].copy_from_slice(&0x400200u64.to_le_bytes()); // e_entry: inside the R+X page
    elf[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
    elf[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
    elf[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
    elf[56..58].copy_from_slice(&1u16.to_le_bytes()); // e_phnum: +1 in fat_carrier_elf
}
