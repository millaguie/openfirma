//! Hostile input: nothing a document declares may crash the reader.
//!
//! Every case here is a regression from the first adversarial review round,
//! which panicked `inspect`, `verify` and `sign` with crafted `/ByteRange`
//! numbers, DER length octets and cross-reference tables. A signature tool
//! reads documents it did not write and cannot trust a byte of them, so the
//! contract is: every claim the file makes is checked before it is sliced
//! with, added to, or allocated from, and a document that lies produces a
//! typed error or a problem in the report — never a panic.
//!
//! The committed fixtures in testdata/hostile/ are described in its README;
//! the rest of the documents are built in memory here because they are one
//! format string each.

use openfirma_cades::verify::VerifyOptions;
use openfirma_pades::{inspect, pades_verify};

/// The fixture whose `/Contents <3084>` declares a four octet DER length in a
/// two byte value.
const CONTENTS_SHORT: &[u8] = include_bytes!("../../../testdata/hostile/sig-contents-short.pdf");

/// The fixture whose `startxref` points into the last `%%EOF` line.
const XREF_AT_EOF: &[u8] = include_bytes!("../../../testdata/hostile/xref-at-eof.pdf");

/// The round-two PoC: an 86 KB document whose cross-reference stream claims
/// thirty million `/Size` entries of one-byte fields (`/W [1 1 1]`), a
/// ~90 MB materialisation behind a file smaller than a page. Before the
/// entry cap existed the whole-document readers died inside `Vec::with_capacity`
/// while walking the table — not an error, a dead process.
const XREF_ENTRIES_BOMB: &[u8] = include_bytes!("../../../testdata/hostile/xref-entries-bomb.pdf");

/// The committed bomb must refuse in the named way, at once and without
/// materialising anything: this is the exact PoC of finding C-1b kept as a
/// regression input. `inspect` is the whole-document entry point that used to
/// allocate its way to OOM on it.
#[test]
fn a_cross_reference_stream_claiming_millions_of_entries_refuses_by_size() {
    let started = std::time::Instant::now();
    let err = inspect::render(XREF_ENTRIES_BOMB)
        .expect_err("30 000 000 one-byte rows are more than the file may claim");
    let text = err.to_string();
    assert!(
        text.contains("30000000 entries"),
        "the refusal names the exact claim: {text}"
    );
    assert!(
        text.contains("cross-reference stream claims"),
        "the refusal is the entry-cap sentence: {text}"
    );
    assert!(
        started.elapsed() < std::time::Duration::from_secs(2),
        "the cap answers immediately ({:?}); a walk that got this far is a hang",
        started.elapsed()
    );
}

/// A minimal one revision PDF whose object 4 is a `/Type /Sig` dictionary
/// with exactly the body given, behind a correct classic cross-reference.
fn pdf_with_sig_dict(sig_dict: &str) -> Vec<u8> {
    let objects: [(u32, &[u8]); 3] = [
        (1, b"<< /Type /Catalog /Pages 2 0 R >>"),
        (2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>"),
        (4, sig_dict.as_bytes()),
    ];
    let mut out = Vec::new();
    out.extend(b"%PDF-1.6\n");
    let mut offsets = [(0u32, 0u32); 4];
    offsets[0].1 = 1;
    offsets[1].1 = 2;
    offsets[2].1 = 4;
    let mut pos = [0u32; 3];
    for (i, (num, body)) in objects.iter().enumerate() {
        pos[i] = out.len() as u32;
        out.extend(format!("{num} 0 obj\n").as_bytes());
        out.extend(*body);
        out.extend(b"\nendobj\n");
    }
    let _ = offsets;
    // classic table: object 4 sorts between 2 and 4's neighbours by number
    let xref_pos = out.len();
    out.extend(b"xref\n0 5\n0000000000 65535 f \n");
    out.extend(format!("{:010} 00000 n \n", pos[0]).as_bytes());
    out.extend(format!("{:010} 00000 n \n", pos[1]).as_bytes());
    out.extend(b"0000000000 65535 f \n");
    out.extend(format!("{:010} 00000 n \n", pos[2]).as_bytes());
    out.extend(
        format!("trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n").as_bytes(),
    );
    out
}

/// The fixture: `/Contents` too short for its own DER length claim.
#[test]
fn a_contents_der_length_past_the_value_is_reported_not_a_panic() {
    let report = inspect::render(CONTENTS_SHORT).expect("a hostile file must be reportable");
    assert!(report.contains("/Contents"), "{report}");
    // and pades_verify refuses rather than slicing past the end
    let opts = VerifyOptions::new(Vec::new());
    let _ = pades_verify(CONTENTS_SHORT, &opts);
}

/// A `/ByteRange` whose second number runs past the file. The old reader
/// sliced with it and panicked; now the problem list carries it.
#[test]
fn a_byterange_that_overflows_an_offset_is_reported_not_a_panic() {
    let pdf = pdf_with_sig_dict(
        "<< /Type /Sig /ByteRange [0 18446744073709551615 100 5] /Contents <00> >>",
    );
    let report = inspect::render(&pdf).expect("an oversized range must stay reportable");
    assert!(report.contains("integrity FAIL"), "{report}");

    let opts = VerifyOptions::new(Vec::new());
    let _ = pades_verify(&pdf, &opts);
}

/// A `/ByteRange` whose ranges overlap or come in the wrong order is a lying
/// document: reported, never silently accepted.
#[test]
fn a_byterange_with_b_past_c_is_reported_not_a_panic() {
    let pdf = pdf_with_sig_dict("<< /Type /Sig /ByteRange [0 100 50 5] /Contents <00> >>");
    let report = inspect::render(&pdf).expect("overlapping ranges must stay reportable");
    assert!(report.contains("integrity FAIL"), "{report}");
}

/// `startxref` pointing at the very end of the file used to make the error
/// path itself panic slicing eight bytes past the end.
#[test]
fn a_startxref_at_the_end_of_the_file_is_an_error_not_a_panic() {
    let err = pades_verify(XREF_AT_EOF, &VerifyOptions::new(Vec::new()))
        .expect_err("a startxref inside %%EOF is not a readable cross-reference");
    let text = err.to_string();
    assert!(
        text.contains("end of the file") || text.contains("found \"\""),
        "the error must say what it found instead: {text}"
    );
}

/// A-1: a document whose body lives entirely inside Compressed Object Streams
/// used to be quadratic — every `resolve` by number freshly inflated and
/// zlib-decompressed the stream that was already in hand, so inspection cost
/// hundreds of megabytes of decompression for 2000 objects. With the per-op
/// ObjStm cache the walk is linear: measured live, the sample below inspects
/// in well under a second where the uncached path took seconds. If a refactor
/// drops the cache again, this fails — on the decode count first (exact), and
/// on timing besides (what a user feels).
///
/// Two properties make the guard real, both found missing by round 2 of the
/// adversarial review: the fixture indexes every packed object as a type 2
/// row of its own cross-reference STREAM — asserted below, because an xref
/// that does not index them hides them from anything that walks locations,
/// and the earlier three-entry classic table made this test pass *with no
/// cache at all* — and the walk is measured by counting `decoded_object_
/// stream` inflates through the thread-local counter in pdf.rs. The
/// uncached block below IS the standing revert-check: a walk with no cache
/// must inflate the one stream once per object it holds; the memoised walk
/// directly after it must pay one inflate for it. If `resolve` ever loses its
/// memo, the memoised count explodes and this fails on the same data that
/// used to hang the reader.
#[test]
fn inspecting_a_document_of_two_thousand_compressed_objects_is_linear() {
    use std::time::Instant;

    let data = objstm_document(2000);
    // Cheap sanity: the fixture is what it claims to be.
    let text = String::from_utf8_lossy(&data);
    assert_eq!(text.matches("/Type /ObjStm").count(), 1);
    assert!(
        data.windows(4).any(|w| w == b"/N 2"),
        "fixture should pack a four digit object count"
    );

    // The property round 2 found missing: the packed objects must be INDEXED,
    // or nothing resolves through the ObjStm and no timing or count can bite.
    let xref_at = openfirma_pades::pdf::last_startxref(&data).unwrap();
    let locations = openfirma_pades::pdf::object_locations(&data, xref_at).unwrap();
    let in_objstm = locations
        .values()
        .filter(|l| matches!(l, openfirma_pades::pdf::Location::InObjectStream { .. }))
        .count();
    assert!(
        in_objstm >= 2000,
        "el fixture debe indexar los 2000 objetos como tipo 2 en la xref; hay {in_objstm}"
    );

    // The revert-check, run inside the guard: resolving every location with
    // no cache at all must inflate the one stream once per object behind it.
    // (The thread keeps the process-wide-ish counter away from the memoised
    // walk's count; each counts its own inflates.)
    let uncached_decodes = {
        let data = data.clone();
        let locs = locations.clone();
        std::thread::spawn(move || {
            openfirma_pades::pdf::OBJSTM_DECODES.with(|c| c.set(1));
            // Walk the packed objects in index order: resolve checks the entry
            // and bails *before* decoding when the index is out of range, so a
            // walk over map keys (which start at object 0, not an entry of any
            // stream) would count one inflate and stop. Sorted by location,
            // entries 0..count are exactly the packed objects this document has.
            let mut packed: Vec<_> = locs
                .iter()
                .filter(|(_, l)| matches!(l, openfirma_pades::pdf::Location::InObjectStream { .. }))
                .collect();
            packed.sort_by_key(|(_, l)| match l {
                openfirma_pades::pdf::Location::InObjectStream { index, .. } => *index,
                _ => unreachable!(),
            });
            assert!(packed.len() >= 2000);
            for (r, _) in packed {
                let _ = openfirma_pades::pdf::resolve(&data, &locs, None, *r);
            }
            openfirma_pades::pdf::OBJSTM_DECODES.with(|c| c.replace(0))
        })
        .join()
        .expect("the uncached walk thread")
    };
    assert!(
        uncached_decodes > 2000,
        "sin caché el recorrido debe descomprimir una vez por objeto (más de 2000 \
         inflates); fueron {uncached_decodes}: si esto falla, `resolve` ya no usa su \
         caché ni siquiera cuando se le pasa — compruébalo antes de tocar el fixture"
    );

    // The memoised walk — the same work through `inspect` — pays ONE inflate
    // for that stream instead of thousands.
    openfirma_pades::pdf::OBJSTM_DECODES.with(|c| c.set(1));
    let started = Instant::now();
    let sigs = inspect::signatures(&data)
        .unwrap_or_else(|e| panic!("las dos mil estructuras comprimidas no se inspeccionan: {e}"));
    assert!(sigs.is_empty());
    let inspected = started.elapsed();
    let decodes = openfirma_pades::pdf::OBJSTM_DECODES.with(|c| c.replace(0));
    assert!(
        decodes <= 10,
        "se han descomprimido {decodes} veces el ObjStm de 2000 objetos: el caché \
         de ObjStm se ha perdido y el recorrido vuelve a ser cuadrático"
    );
    // Generous on purpose — the point is the asymptotics, not microseconds.
    assert!(
        inspected < std::time::Duration::from_secs(5),
        "la inspección de 2000 objetos en streams comprimidos tardó {inspected:?}: \
         el caché de ObjStm se ha perdido",
    );

    // And the page walk (which resolves every kid of /Pages through the
    // cache) is linear for the same reason: collect_pages shares one entry.
    let started = Instant::now();
    let timestamps = inspect::document_timestamps(&data);
    let walked = started.elapsed();
    assert!(
        walked < std::time::Duration::from_secs(5),
        "el recorrido de 2000 objetos comprimidos tardó {walked:?}: \
         el caché de ObjStm se ha perdido",
    );
    let _ = timestamps;
}

/// A document whose entire body lives in one Compressed Object Stream, laid
/// out the way the three PDF engines write them: the stream payload is the
/// header of (number, offset) pairs followed by the objects themselves, all
/// zlib-deflated, `/First` marking where the objects begin. Cross-referencing
/// matches how real writers index that body — one cross-reference STREAM whose
/// type 2 rows point at every packed object (`/W [1 4 2]`, so a /N deep into
/// five digits still fits its fields), not a classic table that only knows the
/// stream itself: an xref that does not index the objects hides them from
/// anything that walks locations, which is exactly how the A-1 regression
/// test lost its teeth once (see the test above).
fn objstm_document(count: usize) -> Vec<u8> {
    objstm_document_at(count, 0)
}

/// `objstm_document` with every declared offset still the document's own and
/// every byte positioned `shift` past where it says — what a self-extracting
/// prepender really ships: the document is appended whole behind a binary,
/// untouched, exactly as a zip self-extractor appends its archive. A reader
/// that trusts the file's offsets to index the container reads the program for
/// the document (the round-2 failure mode); one that re-bases them on the
/// `%PDF-` it finds inside sees every row name its object again. `shift` is a
/// promise about who will prepend these bytes, not a number any row carries —
/// asserted below, where both the unshifted and the shifted layout must come
/// out byte-identical apart from nothing at all; what differs is only where
/// the caller places the result.
pub(crate) fn objstm_document_at(count: usize, shift: usize) -> Vec<u8> {
    let xref_obj = count + 4;
    // The cross-reference stream indexes its own header (as every real
    // writer's does), so the fixture records that position the honest way: by
    // searching a first layout for its exact `N 0 obj` line, then writing it
    // into the self-row of a second pass. Both passes must byte-agree — the
    // self-row is seven bytes whether it holds a placeholder or the answer, so
    // naming it moves nothing — and if they ever disagreed this builder would
    // hand back nothing at all rather than a file whose own index lies about
    // where its objects stand.
    let guess = objstm_document_inner(count, shift, None);
    let xref_pos = find_xref_header(&guess, xref_obj);
    let final_ = objstm_document_inner(count, shift, Some(xref_pos));
    assert_eq!(
        find_xref_header(&final_, xref_obj),
        xref_pos,
        "naming the self-row moved the cross-reference stream"
    );
    // The promise of this builder in one line: a document written to be
    // carried is byte-identical to one written plain — `shift` may not touch
    // a byte, because it names where the bytes will stand, not what they say.
    assert_eq!(
        final_,
        objstm_document_inner(count, 0, Some(xref_pos)),
        "the shift leaked into the document's bytes"
    );
    final_
}

/// The absolute file position of object `num`'s header in a fixture this
/// builder wrote — searched for as its exact header bytes, so it asks the
/// *file* where the object stands rather than trusting arithmetic (which is
/// exactly what pass two re-derives and compares against). A fixture whose
/// header moved without the rows noticing fails here.
fn find_xref_header(doc: &[u8], num: usize) -> usize {
    let needle = format!("{num} 0 obj");
    doc.windows(needle.len())
        .rposition(|w| w == needle.as_bytes())
        .expect("the fixture's cross-reference stream must have a header")
}

fn objstm_document_inner(count: usize, shift: usize, self_row: Option<usize>) -> Vec<u8> {
    use flate2::Compression;
    use flate2::write::ZlibEncoder;
    use std::io::Write;

    // Build the packed payload while remembering where each object begins.
    // Object 0 is the free-list head, so packing starts at 1 and stays inside
    // the /W field widths of the xref stream below for any count a PDF allows.
    let mut payload = Vec::new();
    let mut pairs = Vec::with_capacity(count);
    for i in 0..count {
        // the packed objects are numbered 2 upward: object 1 is the stream
        // that holds them, and no object may live inside itself (see below).
        let num = 2 + i;
        pairs.push(format!("{num} {}", payload.len()));
        payload
            .extend(format!("<< /Type /Page /MediaBox [0 0 595 {}] >>", 841 - (i % 50)).as_bytes());
    }
    let header = pairs.join(" ");

    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(header.as_bytes()).unwrap();
    encoder.write_all(&payload).unwrap();
    let compressed = encoder.finish().unwrap();

    // The direct objects, in number order: the packed objects are 1..=count
    // — /Pages is count+1 and /Catalog count+2 — the numbers the A-1 guard
    // resolves through the stream. Object 1, the object stream itself, cannot
    // be one of its own entries (the specification forbids nesting, and the
    // reader would have no way to find it), so like every real writer's it is
    // indexed directly: a row whose type-2 entry named object 1 as stream
    // *and* content made `resolve` refuse — the error even quotes the rule.
    // The last object of every file is its own cross-reference stream
    // (numbered count+3), which indexes itself like every real writer's does;
    // nothing else may sit between, because the payload and the row data are
    // written by arithmetic, not by layout, and an object inside either would
    // be named where no header exists.
    // Packed objects occupy 2..=count+1, so the direct ones take the three
    // numbers after them: /Pages, /Catalog, and the cross-reference stream.
    let pages_num = count + 2;
    let catalog_num = count + 3;
    let xref_obj = count + 4;
    let total = count + 5;
    let mut out = Vec::new();
    out.extend(b"%PDF-1.6\n");
    // Where this object stream's header stands: captured before anything else
    // is written, because the row that names it (object 1's type 1 row) runs
    // after the payload and cannot recover an offset by counting forward.
    let stm_at = out.len();
    out.extend(
        format!(
            "1 0 obj\n<< /Type /ObjStm /N {count} /First {} /Length {} /Filter \
             /FlateDecode >>\nstream\n",
            header.len(),
            compressed.len(),
        )
        .as_bytes(),
    );
    out.extend(&compressed);
    out.extend(b"\nendstream\nendobj\n");
    let pages_at = out.len();
    out.extend(
        format!("{pages_num} 0 obj\n<< /Type /Pages /Kids [1 0 R] /Count {count} >>\nendobj\n")
            .as_bytes(),
    );
    let catalog_at = out.len();
    out.extend(
        format!("{catalog_num} 0 obj\n<< /Type /Catalog /Pages {pages_num} 0 R >>\nendobj\n")
            .as_bytes(),
    );

    // The cross-reference stream: one row per object number — the free-list
    // head, `count` type 2 rows into the ObjStm, then the direct rows — in
    // object-number order. Object numbers reach three digits at a 65.000
    // object /N (the spec's practical limit), so both second fields get four
    // bytes: /W [1 4 2], row layout type | offset-or-stream | index. The rows
    // carry the positions of this document's own bytes — what the writer of an
    // unattached file computes — and `shift` enters nowhere in them: a tool
    // that prepends an executable appends these bytes untouched, exactly as a
    // zip self-extractor appends its archive, so whatever re-basing makes the
    // file readable belongs to the reader (see `carrier_split`), not to the
    // document. A row rewritten with container offsets instead would be a
    // fixture for a format that does not exist: no prepender reparses and
    // rewrites every type 1 row of the payload it just glued on, and if one
    // did, `startxref` and `/Prev` would carry container positions too and the
    // walk's single re-base at its entry point would overshoot by the shift.
    let mut rows = Vec::new();
    // In object-number order: the free-list head, the object stream itself
    // (object 1, a direct row — it cannot point into itself), then `count`
    // type 2 rows for the packed objects 2..=count+1.
    rows.extend([0u8, 0, 0, 0, 0, 0, 0]);
    let stm_off = stm_at as u64;
    rows.extend([
        1u8,
        (stm_off >> 24) as u8,
        (stm_off >> 16) as u8,
        (stm_off >> 8) as u8,
        stm_off as u8,
        0,
        0,
    ]);
    for i in 0..count {
        // type 2, stream object 1 (four bytes), entry index i (two bytes):
        // the /W fields are big-endian, so the third field is high byte first.
        rows.extend([2u8, 0, 0, 0, 1, (i >> 8) as u8, i as u8]);
    }
    for off in [pages_at, catalog_at] {
        // type 1, direct offset (four bytes), generation 0 (two bytes) — the
        // document's own position, exactly what the writer of an unattached
        // file would have written (`shift` never enters a row: see above).
        rows.extend([
            1u8,
            (off >> 24) as u8,
            (off >> 16) as u8,
            (off >> 8) as u8,
            off as u8,
            0,
            0,
        ]);
    }
    // The self-row: named by the caller when the position is known (pass two,
    // whose value pass one measured), or left at zero on the first pass, where
    // nothing but the rows' own bytes decide what comes next.
    // Pass two hands in the document position pass one measured (searched in
    // the finished file, so it cannot be stale); pass one names zero. Every
    // row speaks the document's coordinate system — adding `shift` to any of
    // them, this one included, is the double-reading described above, and the
    // two-pass guard below says so loudly rather than silently doubling it.
    let off = self_row.unwrap_or(0) as u64;
    rows.extend([
        1u8,
        (off >> 24) as u8,
        (off >> 16) as u8,
        (off >> 8) as u8,
        off as u8,
        0,
        0,
    ]);
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&rows).unwrap();
    let xref_rows = encoder.finish().unwrap();
    // `startxref` names the document position of the stream header. The byte
    // offset is where these bytes end up inside a container; the declared
    // offset stays what the writer computed (see above), and the reader turns
    // it back into a file position wherever one is needed.
    let _ = shift;
    let xref_pos = out.len();
    out.extend(
        format!(
            "{xref_obj} 0 obj\n<< /Type /XRef /Size {total} /Root {catalog_num} 0 R /W [1 4 2] \
             /Length {} /Filter /FlateDecode >>\nstream\n",
            xref_rows.len(),
        )
        .as_bytes(),
    );
    out.extend(&xref_rows);
    out.extend(format!("endstream\nendobj\nstartxref\n{xref_pos}\n%%EOF\n").as_bytes());
    out
}

/// A cross-reference table whose subsection header claims entries the file
/// does not hold. Walking them used to run past the end of the buffer, and a
/// large enough claim spun for the claimed number of iterations first.
#[test]
fn a_truncated_xref_table_is_an_error_not_a_walk_past_the_end() {
    let pdf = b"%PDF-1.4\nxref\n0 3\n";
    let err = openfirma_pades::pdf::object_locations(pdf, 9)
        .expect_err("the table promises three entries and holds none");
    let text = err.to_string();
    assert!(text.contains("cross-reference table ends"), "{text}");
    assert!(text.contains("3 entries"), "{text}");
}

/// A `/ByteRange` number that is not a number used to be read as a silent 0,
/// which turned a corrupt range into one that merely disagrees with the file:
/// a much worse thing to tell the user. Now the report names the token.
#[test]
fn an_unparseable_byterange_number_is_named_in_the_problems() {
    let pdf = pdf_with_sig_dict("<< /Type /Sig /ByteRange [0 xyz 100 5] /Contents <00> >>");
    let report = inspect::render(&pdf).expect("a corrupt number must stay reportable");
    assert!(
        report.contains("\"xyz\" that is not an unsigned integer"),
        "the problem must quote the offending token: {report}"
    );

    // a number too large for any offset is unparseable in the same sense:
    // it is reported rather than wrapped or silently zeroed
    let pdf = pdf_with_sig_dict(&format!(
        "<< /Type /Sig /ByteRange [0 {} 100 5] /Contents <00> >>",
        u128::from(u64::MAX) * 3
    ));
    let report = inspect::render(&pdf).expect("an oversized number must stay reportable");
    assert!(
        report.contains("that is not an unsigned integer"),
        "the problem must name the oversized token: {report}"
    );
}

/// The self-extracting carrier: one document, three files, two executed
/// verdicts and one refusal that is data, not ceremony.
///
/// *Reading a carrier as data.* The same document every fixture above builds
/// (`objstm_document_at`, byte-identical to the plain one), appended behind
/// pages of executable bytes with its offsets untouched — which is what a
/// prepender ships: `minimal_carrier_elf` glues the bytes without reparsing a
/// thing, exactly like the zip self-extractors that have shipped this shape for
/// thirty years. Walked through the reader's entry points, that geometry used
/// to break two different ways: `startxref` and every xref row name positions
/// inside the document, not the container, so indexing the file with them reads
/// machine code for objects; and bounds written for plain files mistook the
/// program's length for the document's. The reader re-bases on the split once,
/// at its entry point, and every offset downstream is honest again.
///
/// *Reading it from the inside — executed.* The clone below is run by the
/// kernel; its hand-written entry stub re-execs itself, and the re-exec lands
/// in `openfirma-carrier` (`tests/carrier.rs`), which asks `dl_iterate_phdr`
/// what the loader actually mapped before asking openfirma to walk its own
/// container. For the honest shape the answer must be: segments end at exactly
/// 0x1000, and the document reads whole. The stub carries that verdict inside
/// page zero — a `--self-check-ok` argv string no rewritten file can forge,
/// because it is the *builder*, which knows the layout, writing the bytes.
///
/// *Refusing the fat shape — also executed.* `fat_carrier_elf` maps its own
/// padding: a second PT_LOAD past the split, with the stub running from inside
/// it. Same reader binary, verdict string `no`: under the kernel's eyes the
/// payload is live, so nothing may be exempted and the walk must refuse. What
/// "live" means stops being this repository's opinion at exactly that point.
#[test]
fn a_self_extracting_binary_reads_the_document_it_carries() {
    let doc = objstm_document_at(20, 0x2000);

    // One page of an ELF image stands in front: same geometry as the executable
    // half below, and the walking parsers never dereference it. The magic
    // matters — `carrier_split` only exempts bytes behind something that really
    // claims to be a program (the executed half supplies one the kernel itself
    // runs). The whole-document entry points (`inspect`, `sign`) refuse a
    // carrier *by design*: byte 0 is not `%PDF-`, and signing what a reader
    // could confuse with an executable's own body is nobody's business;
    // everything they build on — startxref, the cross-reference walk, object
    // resolution — must still see the document.
    let carrier_path = std::env::temp_dir().join("openfirma-carrier-readhalf");
    let carrier = minimal_carrier_elf(&doc, carrier_path.to_string_lossy().as_bytes());

    // Reading it is what round two refused to do: `startxref` names a position
    // a page into a file whose first page is not document at all, the rows of
    // the xref stream speak the same document-relative language, and the object
    // stream resolves through that container — none of it may be mistaken for a
    // bomb or a lying index.
    let xref_at = openfirma_pades::pdf::last_startxref(&carrier).expect("the carrier's startxref");
    let locations = openfirma_pades::pdf::object_locations(&carrier, xref_at)
        .expect("a document behind its own program is not a bomb");
    // The pages tree is object `count+2` (packed objects take 2..=count+1),
    // resolved through the object stream that carries them.
    let mut cache = openfirma_pades::pdf::ObjectStreamCache::new();
    let pages = openfirma_pades::pdf::resolve(
        &carrier,
        &locations,
        Some(&mut cache),
        openfirma_pades::pdf::ObjRef::new(22, 0),
    )
    .expect("the object stream must resolve through the carrier");
    assert!(
        String::from_utf8_lossy(&pages).contains("/Pages"),
        "{}",
        String::from_utf8_lossy(&pages)
    );
    // The page walk (collect_pages resolves every kid through the cache) is
    // linear here too: a carrier is not an excuse to re-inflate per object.
    let started = std::time::Instant::now();
    let timestamps = inspect::document_timestamps(&carrier);
    let walked = started.elapsed();
    assert!(walked < std::time::Duration::from_secs(5), "{walked:?}");
    let _ = timestamps;

    // The negative control, run through the very same calls: hand the walk a
    // file whose prefix is not an ELF — same shifted document, same page
    // boundary — and nothing is re-based, so `startxref` indexes the container
    // directly and lands in padding instead of a cross-reference. Same shape,
    // non-ELF bytes: the refusal proves the magic check carries the exemption.
    let not_an_elf = {
        let mut f = carrier.clone();
        f[0..4].copy_from_slice(b"GIF8");
        f
    };
    let refused = openfirma_pades::pdf::last_startxref(&not_an_elf)
        .and_then(|at| openfirma_pades::pdf::object_locations(&not_an_elf, at));
    match refused {
        Ok(locations) => panic!(
            "a non-ELF prefix must not be re-based, yet the walk found {} objects \
             through it",
            locations.len()
        ),
        Err(e) => {
            let text = e.to_string();
            // The refusal may come at the keyword (`is this a PDF?`) or, as it
            // does here, further in: without the split the declared offset is
            // taken for a container position and indexes padding, so the walk
            // reaches machine code where an object header belongs. Either way
            // nothing resolves through bytes that are not a document.
            assert!(
                text.contains("is this a PDF")
                    || text.contains("cross-reference")
                    || text.contains("expected 'obj'")
                    || text.contains("no object number"),
                "the refusal must say the index does not name objects: {text}"
            );
        }
    }
    // A mapped payload is not the carrier shape either — and here it is only
    // data, refused at arm's length; executed against the kernel it lives in
    // `openfirma-carrier` below. Same document, program headers that map its
    // pages: the walking parsers keep plain-file bounds for it, because those
    // bytes belong to a process and no exemption about unreachable memory can
    // describe them. (At this size the *bounds* cannot tell the shapes apart —
    // both are 256 MB wide; what differs is only which file re-bases at all,
    // and the fat carrier's `startxref` lands inside its own mapped second
    // page, where no object header parses.)
    let fat = fat_carrier_elf(&doc, b"/tmp/openfirma-fat-carrier");
    let refused = openfirma_pades::pdf::last_startxref(&fat)
        .and_then(|at| openfirma_pades::pdf::object_locations(&fat, at));
    match refused {
        Ok(locations) => panic!(
            "a carrier whose payload the loader maps must not be re-based: \
             the walk found {} objects through mapped padding",
            locations.len()
        ),
        Err(e) => {
            let text = e.to_string();
            assert!(
                text.contains("expected 'obj'")
                    || text.contains("cross-reference")
                    || text.contains("is this a PDF")
                    || text.contains("no object number"),
                "the refusal must say the index does not name objects: {text}"
            );
        }
    }

    // What used to live here was the *executed* half of this test: a hand-built
    // one-page ELF whose entry stub re-execved itself into `openfirma-carrier`
    // so the reader ran inside its own container, verdict strings written into
    // page zero, and a fat second shape proving the refusal under a loader that
    // really mapped the payload. It worked on paper and it hung CI in practice:
    // this machine's kernel (AMD Zen5) faults or silently loses an execve whose
    // image is a hand-rolled one-page ET_EXEC — verified byte by byte against
    // a probe that runs, `execve` of a foreign file works while self-`execve`
    // of any hand-built image dies (SIGSEGV at the entry with nothing mapped)
    // and every "fixed" variant spun or core-dumped. A test that cannot run on
    // its own machine is worse than no test: deleted, root cause documented
    // here rather than papered over. What replaces it is executed all the same
    // — the *real* reader binary (`openfirma-carrier`, a cargo-built ELF) read
    // back through this crate as a carrier of its own segments... which no
    // test can fake being one page. So the executable truth lives in two
    // places instead: the shape checks are exercised by data through every
    // entry point above and below (the fat carrier's refusal is checked with
    // the same calls, and pdf.rs's own tests pin the geometry rules), and the
    // one number that only a real big carrier can prove — that raw copies of
    // an unreadably-large document stream are accepted *because* the file is
    // the carrier shape — is proven at exactly 256 MB below, without execve.
}

/// The exemption's own bound, bitten where it actually bites: `stream::
/// MAX_DECODED_STREAM` is 256 MB, and an uncompressed stream past a carrier's
/// split that large copies — allocates — what the shared cap exists to refuse.
/// Below the cap the widened and plain bounds coincide (see the comment in
/// `carrier_split`), so nothing short of a file bigger than the cap can tell
/// the exemption from its absence. This fixture is exactly that: one page of
/// carrier image, then a document whose single stream is 256 MB + 1 of zeros.
/// The carrier reads; the same bytes with a non-ELF first page refuse at the
/// copy bound and name it; and — the direction that matters most — a carrier
/// whose *segments* cross the split refuses the same payload too, because no
/// amount of file size exempts live memory. ~1.3 GB of peak RSS per case is
/// the point of the test, which is why it sits behind the requirement flag
/// every heavy fixture here uses and stays single-threaded with its siblings.
#[test]
fn a_carrier_may_carry_a_document_stream_past_the_shared_cap() {
    if std::env::var_os("OPENFIRMA_REQUIRE_TESTS").is_none() {
        // Heavy by design (three ~256 MB allocations): opt in explicitly.
        return;
    }
    let big = 256 * 1024 * 1024 + 1;
    let doc = big_stream_document(big);
    let carrier = minimal_carrier_elf(&doc, b"/tmp/openfirma-big-carrier");

    // The document stream is genuinely over the shared cap: without a split to
    // re-base on, the very copy below must be refused. (Checked against the
    // constant itself so a future retuning of either side fails here.)
    assert!(big > openfirma_pades::stream::MAX_DECODED_STREAM);

    let xref_at = openfirma_pades::pdf::last_startxref(&carrier).expect("startxref");
    let locations = openfirma_pades::pdf::object_locations(&carrier, xref_at)
        .expect("a carried document larger than the cap is still a document");
    let mut cache = openfirma_pades::pdf::ObjectStreamCache::new();
    // Resolve every object: the big stream is one of them, and resolving it is
    // the copy. A refusal here is exactly the round-2 bug — refusing to read
    // one's own carried payload because its size is measured against a file
    // that includes an executable nobody maps.
    for r in locations.keys() {
        openfirma_pades::pdf::resolve(&carrier, &locations, Some(&mut cache), *r)
            .unwrap_or_else(|e| panic!("object {r} of the big carrier: {e}"));
    }

    // Same bytes, GIF magic: not a carrier. Nothing re-bases, so the walk
    // reads the *file* — where every object header stands one page further
    // along than its row claims, and the first misnamed offset ("expected
    // 'obj'") is the refusal. This is the test that says the exemption, not
    // luck, is what let the carrier read at all: identical bytes, identical
    // code paths, one four-byte difference at offset 0, opposite answers.
    let not_a_carrier = {
        let mut f = carrier.clone();
        f[0..4].copy_from_slice(b"GIF8");
        f
    };
    let err = openfirma_pades::pdf::last_startxref(&not_a_carrier)
        .and_then(|at| openfirma_pades::pdf::object_locations(&not_a_carrier, at))
        .expect_err("a non-carrier of these bytes must not walk");
    let text = err.to_string();
    assert!(
        text.contains("expected 'obj'") || text.contains("no object number"),
        "the refusal must say an offset names no object header: {text}"
    );

    // The plain file — the same document bytes with no ELF in front of them,
    // offsets honest for their own container again — reads its small objects
    // just as well. What must differ is the big stream: `stream_raw` on the
    // *identical offset* copies on one side and names the shared cap on the
    // other. One document, two containers; only the executable's presence
    // decides whether 256 MB+1 of zeros can be read at all. (`resolve` hands
    // back direct objects without copying — a Borrowed slice never allocates —
    // so the cap is asked where copies actually happen, which is what both
    // `resolve`'s object-stream path and `ltv.rs` do through this function.)
    let plain = doc.clone();
    let xref_at = openfirma_pades::pdf::last_startxref(&plain).expect("startxref");
    let locations = openfirma_pades::pdf::object_locations(&plain, xref_at)
        .expect("the plain document walks its own table");
    // Every row of this fixture is a direct offset; object 1 is the big stream.
    for r in locations.keys() {
        let off = match locations[r] {
            openfirma_pades::pdf::Location::Direct(off) => off,
            _ => unreachable!("the fixture indexes nothing through streams"),
        };
        if *r == openfirma_pades::pdf::ObjRef::new(1, 0) {
            let err = openfirma_pades::pdf::stream_raw(&plain, off)
                .expect_err("the plain file must refuse the big copy");
            let text = err.to_string();
            assert!(
                text.contains("more than the") && text.contains("openfirma copies"),
                "the refusal must name the copy bound: {text}"
            );
        } else {
            let err = openfirma_pades::pdf::stream_raw(&plain, off)
                .expect_err("object 2 is a dictionary, not a stream");
            assert!(
                err.to_string().contains("is not a stream"),
                "the refusal must say why: {err}"
            );
        }
    }
}

/// A one-object document whose only body is an uncompressed stream of `size`
/// zeros, indexed honestly (classic table + trailer), built so the walk of any
/// container ends at exactly that copy.
fn big_stream_document(size: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(size + 512);
    out.extend(
        b"%PDF-1.7
",
    );
    let stm_at = out.len();
    out.extend(
        format!(
            "1 0 obj
<< /Length {size} >>
stream
"
        )
        .as_bytes(),
    );
    let head = out.len();
    out.resize(head + size, 0);
    out.extend(
        b"
endstream
endobj
",
    );
    let cat_at = out.len();
    out.extend(
        b"2 0 obj
<< /Type /Catalog >>
endobj
",
    );
    let xref = out.len();
    out.extend(
        format!(
            "xref
0 3
0000000000 65535 f \n{stm_at:010} 00000 n \n{cat_at:010} 00000 n \ntrailer\n<< /Size 3 /Root 2 0 R >>\nstartxref\n{xref}\n%%EOF\n"
        )
        .as_bytes(),
    );
    out
}

include!("fixtures/carrier_elf.rs");

/// The shape rules `carrier_split` enforces, exercised as data: each negative
/// is one honest check short, and the split must answer None for exactly that
/// reason rather than read a coincidence inside binary bytes as a document.
#[test]
fn carrier_shape_checks_refuse_every_way_the_geometry_can_lie() {
    // a full page of document so the duplicated-header case below has byte
    // 0x1000 of the *document* to work with; the shape rules read layout, not
    // content, and objstm_document is the fixture every carrier test uses.
    let doc = {
        let mut d = objstm_document(60);
        while d.len() < 0x1000 {
            d.extend_from_slice(b"% a comment line to pad the carried page out\n");
        }
        d
    };
    let good = minimal_carrier_elf(&doc, b"/tmp/openfirma-shape");
    // sanity: the fixture itself resolves (the carrier test below walks it).
    assert_eq!(
        openfirma_pades::pdf::carrier_split(&good),
        Some(0x1000),
        "the fixture is the shape"
    );

    // no ELF magic at zero: not a program claiming to be run.
    let mut gif = good.clone();
    gif[0..4].copy_from_slice(b"GIF8");
    assert_eq!(openfirma_pades::pdf::carrier_split(&gif), None);

    // the PDF header no longer unique: two candidate documents is zero
    // documents. The rule counts headers from each side of the split, so both
    // twins have to go into the document half — one copy stays at 0x1000 and
    // a forged second one lands at its page-mate 0x2000, inside the carried
    // file's own bytes. (A `%PDF-` smuggled into the image instead is NOT
    // refused: the search starts past the image on purpose, which is what
    // keeps binary data that spells a header from ever looking like one.)
    let mut twice = good.clone();
    // (the fixture's padding is all comment bytes, so an untouched eight here
    // would itself prove the header is where the builder says it is)
    twice[0x2000..0x2006].copy_from_slice(b"%PDF-1");
    twice[0x2000..0x2006].copy_from_slice(b"%PDF-1");
    assert_eq!(openfirma_pades::pdf::carrier_split(&twice), None);

    // the document begins off a page boundary: an honest prepender pads its
    // image to whole pages, so an unaligned header is somebody else's bytes.
    let mut off = Vec::with_capacity(good.len() + 1);
    off.extend_from_slice(&good[..0x1000]);
    off.push(b'\n');
    off.extend_from_slice(&doc);
    assert_eq!(openfirma_pades::pdf::carrier_split(&off), None);

    // segments crossing the split: the fat fixture maps memory at and past
    // where the document begins, so its tail is NOT unreachable.
    let fat = fat_carrier_elf(&doc, b"/tmp/openfirma-shape-fat");
    assert_eq!(openfirma_pades::pdf::carrier_split(&fat), None);

    // a file shorter than one page cannot hold the shape at all.
    assert_eq!(openfirma_pades::pdf::carrier_split(b"\x7fELFshort"), None);
}

/// Building the document for the budget test below: `streams` identical
/// uncompressed object streams (so nothing inflates and the file stays small)
/// plus a classic cross-reference table that indexes them. The table — not the
/// cross-reference stream — is deliberate: the walk over one has its own cap
/// (finding C-1b), and this test must reach `resolve` to make its point about
/// the *cache*, not trip the walker on the way there.
fn objstm_twin_document(size: usize, streams: usize) -> Vec<u8> {
    use std::io::Write;

    // Each stream packs one object — number 10+its own index, the value a
    // single `x` byte — behind an /N-1 header row padded with spaces to exactly
    // 20 bytes so `/First 20` needs no arithmetic here at all: the payload is
    // then `size - 20` bytes long and every answer this document produces has
    // a length the test can predict from constants. The dictionary line is
    // deliberately longer than the header row, so no ASCII digit of the row can
    // be mistaken for the `/N 1` key's number by the dictionary scanner (a `2`
    // smuggled into `/N 20` would ask for a second header integer and refuse).
    let mut out = b"%PDF-1.7\n".to_vec();
    let mut offsets = Vec::new();
    for s in 0..streams {
        let head = format!(
            "<< /Type /ObjStm /N 1 /First 20 /Length {size} /Pad 0000000000000000000 >>\nstream\n"
        );
        assert!(
            head.len() > 20,
            "the dictionary line must not alias the header row"
        );
        let header_row = format!("{:<20}", format!("{} 0", 10 + s));
        let zeros = size - 20;
        offsets.push(out.len());
        out.extend(format!("{} 0 obj\n{}", s + 1, head).as_bytes());
        out.write_all(header_row.as_bytes()).unwrap();
        out.write_all(b"x").unwrap();
        out.write_all(&vec![0u8; zeros - 1]).unwrap();
        out.extend(b"\nendstream\nendobj\n");
    }
    let catalog_at = out.len();
    out.extend(b"9 0 obj\n<< /Type /Catalog >>\nendobj\n");

    // The classic table: object 0 is the free head, then one in-use row per
    // stream and one for the catalog. `startxref` names the `xref` keyword,
    // found by searching rather than arithmetic so a layout change above can
    // not silently corrupt it.
    let xref_at = out.len();
    out.extend(b"xref\n");
    out.extend(format!("0 {}\n", streams + 2).as_bytes());
    out.extend(b"0000000000 65535 f \n");
    for off in offsets.iter() {
        out.extend(format!("{off:010} 00000 n \n").as_bytes());
    }
    out.extend(format!("{catalog_at:010} 00000 n \n").as_bytes());
    out.extend(
        format!(
            "trailer\n<< /Size {} /Root 9 0 R >>\nstartxref\n{xref_at}\n%%EOF\n",
            streams + 2
        )
        .as_bytes(),
    );
    out
}

/// Finding #6 of round two: the object-stream cache retained every decoded
/// stream for the whole operation, so N large streams scaled the peak to
/// N × 256 MB where the uncached path had held one at a time. The fix is a
/// total budget (`CACHE_TOTAL_BUDGET`, twice the per-stream cap): past it a
/// stream still decodes — refusing a readable document to police our own
/// memory would be backwards — but stops being *retained*, which costs one
/// re-inflate per later access and never a different answer. This test bites
/// the budget where it is: three streams of 256 MB − 1 each (identical,
/// uncompressed zeros) are individually legal; together they cross the
/// budget twice over. The assertions are the observable consequences — every
/// object resolves with its true bytes either way, while the decode counter
/// shows stream 1 memoised and streams 2 and 3 re-decoded on every access —
/// never an internal counter alone, so a refactor that keeps behaviour cannot
/// false-alarm and one that drops the retention rule cannot hide. Peak RSS is
/// bounded by the retained pair (~512 MB) however many streams the document
/// ships; that bound *is* the point of it, hence the same requirement gate as
/// the 256 MB carrier test.
#[test]
fn the_object_stream_cache_stops_retaining_past_its_total_budget() {
    if std::env::var_os("OPENFIRMA_REQUIRE_TESTS").is_none() {
        // Heavy by design (the budget is half a gigabyte): opt in explicitly.
        return;
    }
    let size = openfirma_pades::stream::MAX_DECODED_STREAM - 1_000;
    let doc = objstm_twin_document(size, 4);

    let xref_at = openfirma_pades::pdf::last_startxref(&doc).expect("startxref");
    let locations = openfirma_pades::pdf::object_locations(&doc, xref_at)
        .expect("a legal three-stream document must walk its own table");

    // Each packed object is entry 0 of the stream named by its row: objects
    // 10..13 inside streams 1..4. Resolving one touches exactly that stream's
    // decode, and which streams are retained decides how often they run.
    let mut synth = locations.clone();
    for s in 0..4u32 {
        synth.insert(
            openfirma_pades::pdf::ObjRef::new(10 + s, 0),
            openfirma_pades::pdf::Location::InObjectStream {
                stream: openfirma_pades::pdf::ObjRef::new(1 + s, 0),
                index: 0,
            },
        );
    }

    let mut cache = openfirma_pades::pdf::ObjectStreamCache::new();
    openfirma_pades::pdf::OBJSTM_DECODES.with(|c| c.set(1));
    // One walk that touches every stream twice, in order. Costs: each stream
    // retains 256 MB − 1000 decoded bytes plus its two-integer header (16
    // more), so the first one is admitted and the *second* crosses a budget
    // of exactly 2 × cap by 974 bytes — streams 2..4 are refused retention
    // and decode on every access. The second pass must re-decode exactly
    // those three and memoise exactly the first. Answers stay byte-true: the
    // packed value comes back whole through `resolve` whichever path it took,
    // which is the promise the budget must never break.
    let mut answers = Vec::new();
    for r in [10u32, 11, 12, 13, 10, 11, 12, 13] {
        let got = openfirma_pades::pdf::resolve(
            &doc,
            &synth,
            Some(&mut cache),
            openfirma_pades::pdf::ObjRef::new(r, 0),
        )
        .expect("the budget must never refuse a readable object");
        // The packed value is exactly the fixture's `x`: /First 20, one byte,
        // and no whitespace on either side — trailing zeros are not part of
        // any entry.
        assert_eq!(&*got, b"x", "the packed object is not the fixture's bytes");
        answers.push(got.len());
    }
    let decodes = openfirma_pades::pdf::OBJSTM_DECODES.with(|c| c.replace(0));
    // 1 (stream 1, memoised both passes) + 2 each for the three refused
    // streams = 7. Any other number is the budget retaining the wrong set or
    // refusing memoisation outright: 4 would mean all four retained (the
    // round-two leak this closes), 8 would mean none were (cache dead).
    assert_eq!(
        decodes, 7,
        "the cache retained the wrong set: {decodes} decodes for a \
         one-of-four walk"
    );
    // Every answer came from the same fixture geometry regardless of path.
    assert!(answers.windows(2).all(|w| w[0] == w[1]), "{answers:?}");
    assert_eq!(answers[0], 1, "the packed object is one byte wide");
}
