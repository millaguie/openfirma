//! Round 2, finding N-3: the revision a document gets must be the same *kind*
//! of cross-reference as the one it already ends with.
//!
//! The writer always appended a classic table. A table whose `/Prev` points at
//! a cross-reference stream is legal and every reader we tested (qpdf, pdfsig,
//! our own) accepts it — but not the reader AutoFirma uses. iText follows
//! `/Prev` from a stream as a stream and from a table with `readXrefSection`,
//! which requires the keyword `xref`, so over a stream the chain stops: it
//! rebuilds the document and then refuses to sign it in append mode ("Append
//! mode requires a document without errors even if recovery was possible"), or
//! dies on a null page. That is the citizen's second signature lost: a Word
//! PDF, or anything Ghostscript or qpdf produced.
//!
//! The fixture is written here rather than committed, because no file in
//! `testdata/inputs` ends in a cross-reference stream and the shape is small
//! enough to spell out: five objects, the last of them the `/Type /XRef` stream
//! that describes the other four and itself.

use std::path::{Path, PathBuf};

use openfirma_cades::verify::VerifyOptions;
use openfirma_core::{CertificateHandle, SoftwareSigner};
use openfirma_pades::ltv::RevocationBytes;
use openfirma_pades::{PadesOptions, pades_sign, pades_verify, pdf};

fn certs_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/certs")
}

fn handle(name: &str) -> CertificateHandle {
    let pem = std::fs::read_to_string(certs_dir().join(name))
        .unwrap_or_else(|e| panic!("{name} is part of the test PKI but cannot be read: {e}"));
    CertificateHandle::from_pem(&pem).unwrap_or_else(|e| panic!("{name}: {e}"))
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

fn require_or_skip(reason: &str) {
    if std::env::var("OPENFIRMA_REQUIRE_TESTS").is_ok() {
        panic!("cannot run the test: {reason}");
    }
    eprintln!("skipped, {reason}");
}

/// A one-page document whose *only* cross-reference section is a stream: the
/// shape `qpdf --object-streams=generate` and Ghostscript write. Uncompressed
/// (no `/Filter`), so the rows can be read by eye, and `/W [1 4 2]` like every
/// producer uses.
fn xref_stream_pdf() -> Vec<u8> {
    let bodies: [&[u8]; 4] = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] >>",
        b"<< /ModDate (D:20000101000000Z) /Producer (author) >>",
    ];
    let mut out = Vec::from(&b"%PDF-1.5\n"[..]);
    let mut offsets = vec![0usize; bodies.len() + 1]; // object 0 is the free entry
    for (i, body) in bodies.iter().enumerate() {
        offsets[i + 1] = out.len();
        out.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(b"\nendobj\n");
    }

    // the stream object describes itself too, so it is number 5, offset known
    // only once everything before it is written
    let stream_at = out.len();
    offsets.push(stream_at);
    let mut rows = Vec::new();
    rows.extend_from_slice(&[0u8]); // type 0: free
    rows.extend_from_slice(&0u32.to_be_bytes());
    rows.extend_from_slice(&65535u16.to_be_bytes()); // the head of the free list
    for off in &offsets[1..] {
        rows.push(1u8); // type 1: in use at this offset
        rows.extend_from_slice(&u32::try_from(*off).unwrap().to_be_bytes());
        rows.extend_from_slice(&0u16.to_be_bytes());
    }
    out.extend_from_slice(
        format!(
            "5 0 obj\n<< /Type /XRef /Size 6 /W [1 4 2] /Index [0 6] /Root 1 0 R \
             /Info 4 0 R /Length {} >>\nstream\n",
            rows.len()
        )
        .as_bytes(),
    );
    out.extend_from_slice(&rows);
    out.extend_from_slice(b"\nendstream\nendobj\n");
    out.extend_from_slice(format!("startxref\n{stream_at}\n%%EOF\n").as_bytes());
    out
}

#[test]
fn a_revision_over_an_xref_stream_is_an_xref_stream() {
    let Some(signer) = signer() else {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    let input = xref_stream_pdf();
    let input_at = pdf::last_startxref(&input).expect("startxref");
    assert!(
        pdf::section_is_stream(&input, input_at),
        "the fixture must end in a cross-reference stream, or the test proves nothing"
    );

    let signed = pades_sign(&input, &signer, &PadesOptions::default()).expect("signing failed");
    assert!(
        signed.starts_with(&input),
        "an incremental update leaves the previous revision untouched"
    );

    let at = pdf::last_startxref(&signed).expect("startxref");
    assert!(
        pdf::section_is_stream(&signed, at),
        "a revision after a cross-reference stream must be one: a classic table would leave \
         AutoFirma's iText unable to follow /Prev, and it would refuse to co-sign the file"
    );
    // and it is a real trailer: the entries resolve, the catalog is reachable
    // and the signature verifies over the bytes it was made over
    let trailer = pdf::trailer(&signed, at).expect("the stream's dictionary is the trailer");
    assert_eq!(
        trailer.prev,
        Some(input_at),
        "the new section points back at the stream of the original"
    );
    let locations = pdf::object_locations(&signed, at).expect("the entries read back");
    assert!(
        locations.contains_key(&pdf::ObjRef::new(trailer.root.num, 0)),
        "the catalog the trailer names is in the cross-reference"
    );
    let tree = pdf::resolve(&signed, &locations, None, trailer.root).expect("the catalog resolves");
    assert!(
        tree.starts_with(b"<<"),
        "the catalog is a dictionary: {}",
        String::from_utf8_lossy(&tree)
    );
    let report = pades_verify(
        &signed,
        &VerifyOptions::new(vec![handle("intermediate.crt"), handle("ca.crt")]),
    )
    .expect("the signature over the xref-stream document must verify");
    assert_eq!(report.signatures.len(), 1);

    // the shape is transitive: the archive that follows is a stream as well,
    // because the section it follows is one
    let dir = certs_dir();
    let (Ok(ca_crl), Ok(ca)) = (
        std::fs::read(dir.join("ca.crl.der")),
        std::fs::read_to_string(dir.join("ca.crt")),
    ) else {
        require_or_skip("the test PKI has no CRLs, rerun tools/gen-testcert.sh");
        return;
    };
    let certs = vec![
        handle("signer-rsa.crt"),
        handle("intermediate.crt"),
        handle("ca.crt"),
    ];
    let archived =
        openfirma_pades::add_validation_data(&signed, &certs, &[RevocationBytes::Crl(ca_crl)])
            .expect("archiving failed");
    let at = pdf::last_startxref(&archived).expect("startxref");
    assert!(
        pdf::section_is_stream(&archived, at),
        "the archive's revision follows a stream, so it is one too"
    );
    assert!(archived.starts_with(&signed), "and it is incremental");
    let _ = ca;
}

/// The other direction, so the branch is a branch: a document that ends in a
/// classic table keeps getting one. This is what the golden diff measures
/// against AutoFirma, which writes tables for table files.
#[test]
fn a_revision_over_a_classic_table_is_still_a_table() {
    let Some(signer) = signer() else {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    let input = include_bytes!("../../../testdata/inputs/simple.pdf");
    assert!(!pdf::section_is_stream(
        input,
        pdf::last_startxref(input).expect("startxref")
    ));

    let signed = pades_sign(input, &signer, &PadesOptions::default()).expect("signing failed");
    let at = pdf::last_startxref(&signed).expect("startxref");
    assert!(
        !pdf::section_is_stream(&signed, at),
        "a classic table must stay a classic table: that is the golden diff's shape"
    );
    assert!(
        signed.windows(5).any(|w| w == b"xref\n"),
        "the table is there, spelled out"
    );
}
