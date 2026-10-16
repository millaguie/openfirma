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
//! The two committed fixtures in testdata/hostile/ are described in its
//! README; the rest of the documents are built in memory here because they
//! are one format string each.

use openfirma_cades::verify::VerifyOptions;
use openfirma_pades::{inspect, pades_verify};

/// The fixture whose `/Contents <3084>` declares a four octet DER length in a
/// two byte value.
const CONTENTS_SHORT: &[u8] = include_bytes!("../../../testdata/hostile/sig-contents-short.pdf");

/// The fixture whose `startxref` points into the last `%%EOF` line.
const XREF_AT_EOF: &[u8] = include_bytes!("../../../testdata/hostile/xref-at-eof.pdf");

/// A minimal one revision PDF whose object 4 is a `/Type /Sig` dictionary
/// with exactly the body given, behind a correct classic cross-reference.
fn pdf_with_sig_dict(sig_dict: &str) -> Vec<u8> {
    let objects: [(u32, &[u8]); 3] = [
        (1, b"<< /Type /Catalog /Pages 2 0 R >>"),
        (2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>"),
        (
            3,
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] >>",
        ),
    ];
    let mut out = Vec::from(&b"%PDF-1.4\n"[..]);
    let mut offsets = Vec::new();
    for (num, body) in objects {
        offsets.push(out.len());
        out.extend_from_slice(format!("{num} 0 obj\n").as_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(b"\nendobj\n");
    }
    offsets.push(out.len());
    out.extend_from_slice(b"4 0 obj\n");
    out.extend_from_slice(sig_dict.as_bytes());
    out.extend_from_slice(b"\nendobj\n");

    let xref_at = out.len();
    out.extend_from_slice(b"xref\n0 5\n0000000000 65535 f \n");
    for off in &offsets {
        out.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(b"trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n");
    out.extend_from_slice(format!("{xref_at}\n%%EOF\n").as_bytes());
    out
}

/// `/ByteRange [0 5000 100 873]`: the first range ends after the second one
/// starts, on a file far too short for either. Reading the `/Contents` the
/// ranges describe used to slice `5000..100` and panic.
#[test]
fn a_byterange_with_b_past_c_is_reported_not_a_panic() {
    let pdf = pdf_with_sig_dict("<< /Type /Sig /ByteRange [0 5000 100 873] /Contents <00> >>");

    let report = inspect::render(&pdf).expect("a lying /ByteRange must stay reportable");
    assert!(
        report.contains("the two ranges overlap or are in the wrong order"),
        "{report}"
    );
    assert!(report.contains("integrity FAIL"), "{report}");

    let err = pades_verify(&pdf, &VerifyOptions::new(Vec::new()))
        .expect_err("a document whose ranges do not describe it cannot verify");
    assert!(
        err.to_string().contains("/ByteRange"),
        "the verdict must name the claim that failed: {err}"
    );
}

/// `/ByteRange [0 100 <usize::MAX> 1]`: the second range ends at a sum no
/// offset can hold. The addition itself used to overflow and abort in debug
/// builds before any check could run.
#[test]
fn a_byterange_that_overflows_an_offset_is_reported_not_a_panic() {
    let pdf = pdf_with_sig_dict(&format!(
        "<< /Type /Sig /ByteRange [0 100 {} 1] /Contents <00> >>",
        usize::MAX
    ));

    let report = inspect::render(&pdf).expect("an overflowing /ByteRange must stay reportable");
    assert!(
        report.contains("overflows any file offset"),
        "the problem must name the overflow: {report}"
    );

    let err = pades_verify(&pdf, &VerifyOptions::new(Vec::new()))
        .expect_err("no file has segments that add up past usize");
    assert!(
        err.to_string().contains("/ByteRange"),
        "the verdict must name the claim that failed: {err}"
    );
}

/// The committed fixture: `/Contents <3084>`, a long form DER length claiming
/// four octets in a value that holds none. `contents_der` used to slice
/// `raw[2..6]` out of a two byte value and panic.
#[test]
fn a_contents_der_length_past_the_value_is_reported_not_a_panic() {
    let report = inspect::render(CONTENTS_SHORT).expect("a broken /Contents must stay reportable");
    assert!(
        report.contains("/Contents declares a 4 octet DER length"),
        "the problem must name the malformed length: {report}"
    );
    assert!(report.contains("no CMS could be read"), "{report}");
}

/// The committed fixture: `startxref` points into the final `%%EOF` line, so
/// the object header scan walks off the end of the file. The error message
/// for that case used to slice eight bytes past the end to show what it found
/// — the report of the panic was itself a panic.
#[test]
fn a_startxref_at_the_end_of_the_file_is_an_error_not_a_panic() {
    let err = inspect::render(XREF_AT_EOF).expect_err("there is no object where startxref points");
    let text = err.to_string();
    assert!(text.contains("expected 'obj'"), "{text}");
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
/// in well under a second where the uncached path took over fourteen. If a
/// refactor drops the cache again, this fails on timing.
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

    let started = Instant::now();
    let sigs = inspect::signatures(&data)
        .unwrap_or_else(|e| panic!("las dos mil estructuras comprimidas no se inspeccionan: {e}"));
    assert!(sigs.is_empty());
    let inspected = started.elapsed();
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
/// zlib-deflated, `/First` marking where the objects begin.
fn objstm_document(count: usize) -> Vec<u8> {
    use flate2::Compression;
    use flate2::write::ZlibEncoder;
    use std::io::Write;

    // Build the packed payload while remembering where each object begins.
    let mut payload = Vec::new();
    let mut pairs = Vec::with_capacity(count);
    for i in 0..count {
        pairs.push(format!("{i} {}", payload.len()));
        payload
            .extend(format!("<< /Type /Page /MediaBox [0 0 595 {}] >>", 841 - (i % 50)).as_bytes());
    }
    let header = pairs.join(" ");

    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(header.as_bytes()).unwrap();
    encoder.write_all(&payload).unwrap();
    let compressed = encoder.finish().unwrap();

    let mut out = Vec::new();
    out.extend(b"%PDF-1.6\n");
    let mut offsets = [0u32; 4];
    offsets[1] = out.len() as u32;
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

    offsets[2] = out.len() as u32;
    out.extend(
        format!("2 0 obj\n<< /Type /Pages /Kids [1 0 R] /Count {count} >>\nendobj\n").as_bytes(),
    );
    offsets[3] = out.len() as u32;
    out.extend(b"3 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");

    let xref_pos = out.len();
    out.extend(b"xref\n0 4\n0000000000 65535 f \n");
    for off in &offsets[1..] {
        out.extend(format!("{off:010} 00000 n \n").as_bytes());
    }
    out.extend(
        format!("trailer\n<< /Size 4 /Root 3 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n").as_bytes(),
    );
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
