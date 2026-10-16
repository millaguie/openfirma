//! The `/ByteRange` hole belongs to THIS dictionary's `/Contents` (adversarial
//! review M-3). `verify_one` used to accept any hole starting with `<` and
//! ending with `>`; it now resolves the signature dictionary's own /Contents
//! value in place and demands the hole sit on it byte for byte, requires the
//! /ByteRange array itself to sit inside the covered prefix, and refuses a
//! signature dictionary compressed into an object stream, where no file offset
//! for the placeholder could exist at all (which is why ISO 32000 forbids it).

use std::path::{Path, PathBuf};

use openfirma_cades::verify::VerifyOptions;
use openfirma_core::{CertificateHandle, SoftwareSigner};
use openfirma_pades::{PadesOptions, inspect, pades_sign, pades_verify, pdf};

const INPUT: &[u8] = include_bytes!("../../../testdata/inputs/simple.pdf");

fn certs_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/certs")
}

fn handle(name: &str) -> CertificateHandle {
    let pem = std::fs::read_to_string(certs_dir().join(name)).unwrap();
    CertificateHandle::from_pem(&pem).unwrap()
}

fn signer() -> Option<SoftwareSigner> {
    let dir = certs_dir();
    let (Ok(cert), Ok(key)) = (
        std::fs::read_to_string(dir.join("signer-rsa.crt")),
        std::fs::read_to_string(dir.join("signer-rsa.key")),
    ) else {
        return None;
    };
    Some(
        SoftwareSigner::from_pkcs8_pem(&cert, &key)
            .expect("the test key must load")
            .with_chain(vec![handle("intermediate.crt")]),
    )
}

fn anchors() -> VerifyOptions {
    VerifyOptions::new(vec![handle("intermediate.crt"), handle("ca.crt")])
}

fn require_or_skip(reason: &str) {
    if std::env::var("OPENFIRMA_REQUIRE_TESTS").is_ok() {
        panic!("cannot run the test: {reason}");
    }
    eprintln!("skipped, {reason}");
}

/// Our own B-B document, padded so the signature dictionary has slack. The
/// hole M-3 cares about is between `b` and `c`; every test here moves that
/// boundary by hand and demands the STRUCTURAL refusal — the one naming
/// /Contents — before any digest verdict.
#[test]
fn a_hole_wider_than_the_contents_value_is_refused() {
    let Some(signer) = signer() else {
        require_or_skip("test PKI missing, rerun tools/gen-testcert.sh");
        return;
    };
    let signed = pades_sign(
        INPUT,
        &signer,
        &PadesOptions {
            contents_reserved: 8192,
            ..Default::default()
        },
    )
    .expect("B-B failed");
    pades_verify(&signed, &anchors()).expect("the padded document verifies");

    let sig = inspect::signatures(&signed).unwrap().remove(0);
    // shrink the second boundary by one: [b..c) then runs PAST this
    // dictionary's /Contents value (whose last byte is the `>` at c-1), so the
    // claimed hole swallows a byte of whatever follows the value — exactly the
    // "hole covers more than the CMS" shape. The covered bytes shift too, so
    // no CMS could ever match this claim; what matters is which refusal comes
    // first and names the reason. (The old code reached for the digest with a
    // shrunk hole in third-party layouts whose final byte happened to be a `>`
    // from other syntax — the appearance check M-3 removed.)
    let mut attacked = signed.clone();
    let span = byte_range_span(&attacked, sig.object);
    rewrite_byterange(
        &mut attacked,
        span,
        sig.byte_range[1],
        sig.byte_range[2] - 1,
        sig.byte_range[3] + 1,
    );

    let error = pades_verify(&attacked, &anchors())
        .expect_err("a hole that is not exactly the /Contents value must refuse");
    let text = error.to_string();
    assert!(
        (text.contains("/Contents") && text.contains("hole")) || text.contains("messageDigest"),
        "the refusal either names the /Contents binding or, at worst before \
         M-3's fix existed, the digest: {text}"
    );
    // and specifically our NEW sentence fires, because the structural check
    // runs before hashing: a document whose hole is off its /Contents cannot
    // even reach the digest report.
    assert!(
        text.contains("is not this dictionary's /Contents value"),
        "the structural refusal fires first: {text}"
    );
}

/// Where `/ByteRange`'s ARRAY value sits, as absolute offsets into the file.
fn byte_range_span(pdf: &[u8], object: pdf::ObjRef) -> (usize, usize) {
    let xref = pdf::last_startxref(pdf).unwrap();
    let locations = pdf::object_locations(pdf, xref).unwrap();
    let offset = match locations[&object] {
        pdf::Location::Direct(offset) => offset,
        _ => panic!("our signer writes direct dictionaries"),
    };
    let body = pdf::object_body(pdf, offset).unwrap();
    let at = pdf::get_span(&pdf[body.clone()], "/ByteRange").expect("it is there");
    (body.start + at.start, body.start + at.end)
}

/// Rewrite the four numbers of the array keeping its exact byte length. The
/// writer pads each number field (first and last right-padded, middle ones
/// left-aligned inside a fixed pitch), so every value is re-emitted with its
/// ORIGINAL alignment — only the digits change, never the padding style.
fn rewrite_byterange(pdf: &mut [u8], span: (usize, usize), b: usize, c: usize, d: usize) {
    let text = String::from_utf8_lossy(&pdf[span.0..span.1]).to_string();
    let open = text.find('[').expect("an array");
    let close = text.rfind(']').expect("its end");
    let inner = &text[open + 1..close];
    // locate the four number tokens inside the array's own spacing
    let bytes = inner.as_bytes();
    let mut pitch: Vec<(usize, usize)> = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            pitch.push((start, i - start));
        } else {
            i += 1;
        }
    }
    assert_eq!(pitch.len(), 4, "four numbers: {text}");
    let values = [0usize, b, c, d];
    // rebuild the array with each number padded to its ORIGINAL field width:
    // a field is from this token's first digit up to just before the next one
    // (the last runs to the closing bracket). Alignment style per field: every
    // writer we accept pads numbers inside fixed-width slots, and keeping each
    // token left-aligned in its slot preserves total length exactly.
    let mut out = String::new();
    for (n, ((start, _len), value)) in pitch.iter().zip(values).enumerate() {
        let field_end = pitch.get(n + 1).map_or(inner.len(), |(next, _)| *next);
        let width = field_end - start;
        let digits = value.to_string();
        assert!(
            digits.len() <= width,
            "a value wider than its field: {text}"
        );
        out.push_str(&digits);
        out.extend(std::iter::repeat_n(' ', width - digits.len()));
    }
    let rebuilt = format!("[{out}]");
    assert_eq!(
        rebuilt.len(),
        close - open + 1,
        "same width: rebuilt {rebuilt}"
    );
    let at = span.0 + open;
    pdf[at..at + rebuilt.len()].copy_from_slice(rebuilt.as_bytes());
}

/// Legitimate variation in SIZE must keep binding: /Contents of generous
/// padding still ends exactly at `c` (guards the new span arithmetic against
/// off-by-one regressions across writers' paddings).
#[test]
fn padded_contents_sizes_keep_binding() {
    let Some(signer) = signer() else {
        require_or_skip("test PKI missing, rerun tools/gen-testcert.sh");
        return;
    };
    for reserved in [4096usize, 65_536] {
        let signed = pades_sign(
            INPUT,
            &signer,
            &PadesOptions {
                contents_reserved: reserved,
                ..Default::default()
            },
        )
        .expect("signing failed");
        pades_verify(&signed, &anchors())
            .unwrap_or_else(|e| panic!("reserved {reserved} must bind its hole: {e}"));
    }
}

/// A signature dictionary compressed into an object stream has no file offset
/// for its /Contents at all. Hand-built minimal PDF: an xref stream naming
/// object 9 — the only `/Type /Sig` — as entry 0 of object stream 3, claiming a
/// hole deep in the file. `verify` must refuse by naming the missing direct
/// object rather than slicing bytes by a claim no writer could honour.
#[test]
fn a_signature_dictionary_inside_an_object_stream_is_refused() {
    let crafted = pdf_with_sig_in_object_stream();
    let error = pades_verify(&crafted, &VerifyOptions::new(Vec::new()))
        .expect_err("a /Sig inside an object stream describes no hole in the file");
    assert!(
        error.to_string().contains("direct object"),
        "the refusal says the dictionary is not a direct object: {error}"
    );
}

/// Minimal PDF whose object 9 lives inside object stream 3 and claims
/// `/ByteRange [0 20 60 40]`. The dictionary is written TWICE: a direct decoy
/// the cross-reference never names (so `inspect` resolves object 9 only from
/// the stream), and the packed real one whose body ends EXACTLY at the decoded
/// stream's end — which is what an unterminated-dictionary error was telling
/// us before, since the last stored range has no following offset to stop at.
fn pdf_with_sig_in_object_stream() -> Vec<u8> {
    let num: u32 = 9;
    // packed form ends with a newline (see the note on `header` below)
    let entry = b"<< /ByteRange [0 20 60 40] /Filter /Adobe.PPKLite /Type /Sig >>\n";
    // direct decoy, formatted like a normal object but UNREFERENCED by the
    // cross-reference: `inspect` must never see it, proving what it found lives
    // inside the stream
    let decoy =
        b"9 0 obj\n<< /ByteRange [0 20 60 40] /Filter /Adobe.PPKLite /Type /Sig >>\nendobj\n";
    // one row per packed object — number, then a SPACE (never a newline: this
    // reader tokenises bare numbers, and `0\n<<` would glue the offset to the
    // dictionary's `<`), then EOL before the bodies begin at /First
    let header = format!("{num} 0 \n");

    let mut out = Vec::new();
    out.extend(b"%PDF-1.6\n");
    let mut positions: Vec<(u32, usize)> = Vec::new();
    for (num, body) in [
        (1u32, "<< /Type /Catalog /Pages 2 0 R >>".as_bytes()),
        (2, "<< /Type /Pages /Kids [] /Count 0 >>".as_bytes()),
    ] {
        positions.push((num, out.len()));
        out.extend(format!("{num} 0 obj\n").as_bytes());
        out.extend(body);
        out.extend(b"\nendobj\n");
    }
    // the unreferenced decoy between objects 2 and 3
    out.extend(decoy);
    // /First is exactly the header's length: everything after it is bodies
    let first_at = header.len();
    positions.push((3, out.len()));
    out.extend(
        format!(
            "3 0 obj\n<< /Type /ObjStm /N 1 /First {first_at} /Length {} >>\nstream\n",
            // the payload written below is `header` then `entry`: exactly that
            // many bytes of stream data, /Length at its word
            header.len() + entry.len()
        )
        .as_bytes(),
    );
    out.extend(header.as_bytes());
    out.extend(entry);
    out.extend(b"endstream\nendobj\n");

    // cross-reference stream: rows for objects 1..3 (type 1) and object 9
    // (type 2: living in stream 3, index 0). /Index names them non-continuously.
    let mut rows: Vec<u8> = Vec::new();
    rows.extend([0u8, 0, 0, 0, 0, 255]); // object 0: free (W [1 4 1]: gen byte 255)
    for (_, at) in &positions {
        rows.push(1);
        rows.extend((*at as u32).to_be_bytes());
        rows.push(0);
    }
    rows.push(2); // object 9: compressed, stream 3 index 0
    rows.extend(3u32.to_be_bytes());
    rows.push(0);
    let xref_at = out.len();
    out.extend(
        format!(
            "4 0 obj\n<< /Type /XRef /Size 10 /Index [0 4 9 1] /W [1 4 1] /Root 1 0 R /Length {} >>\nstream\n",
            rows.len()
        )
        .as_bytes(),
    );
    out.extend(&rows);
    out.extend(b"\nendstream\nendobj\n");
    out.extend(format!("startxref\n{xref_at}\n%%EOF\n").as_bytes());
    out
}
