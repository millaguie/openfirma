//! `format=AUTO` end to end, read off the BYTES that come out (finding 04-N2).
//!
//! `auto` is AutoFirma's "look at the document": PDF → PAdES, XML → XAdES,
//! anything else CAdES (`identifyFormatFromData`). openfirma resolved it and
//! then threw the resolution away — the request was rebuilt from the raw text
//! `"AUTO"`, whose table entry is CAdES — so a PDF or an XML came back as a
//! detached CMS while the answer, and the CLI's own success line, named the
//! resolved shape. Every assertion below decodes the payload's signature field
//! and looks at it: a wrong label over right bytes would still be this bug in
//! its other direction, and a test that read the label could not tell.

use std::path::{Path, PathBuf};

use openfirma_browser::dispatch::{KeySource, ResultKind, execute};

/// DER object-identifier encoding of sha256WithRSAEncryption
/// (1.2.840.113549.1.1.11) — what a CMS of this key announces.
const SHA256_RSA_OID: &[u8] = &[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
];

fn testdata() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata")
}

/// CI sets OPENFIRMA_REQUIRE_TESTS so a missing test PKI fails the build
/// instead of quietly skipping; only the keystore-scoped opt-out may relax it
/// (the same rule the browser suite's other files follow).
fn require_or_skip(reason: &str) {
    let required = std::env::var("OPENFIRMA_REQUIRE_TESTS").is_ok();
    let allowed = std::env::var("OPENFIRMA_ALLOW_NONKEYSTORE_SKIP").is_ok();
    if required && !allowed {
        panic!("cannot run the test: {reason}");
    }
    eprintln!("skipped, {reason}");
}

/// Percent-encode like `encodeURIComponent`, the shape a page's URI carries
/// (`fake_sede`'s `uri_body` mirrors the same rule).
fn enc(text: &str) -> String {
    let mut out = String::new();
    for b in text.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn url_safe(bytes: &[u8]) -> String {
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE, bytes)
}

/// The payload's second field, decoded: `base64URL(cert)|base64URL(signature)`
/// with the URL-safe alphabet folded back, exactly as a page's
/// `processSignResponse` reads it.
fn signature_bytes(payload: &[u8]) -> Vec<u8> {
    let folded: Vec<u8> = payload
        .iter()
        .map(|b| match b {
            b'-' => b'+',
            b'_' => b'/',
            other => *other,
        })
        .collect();
    let text = String::from_utf8(folded).expect("the wire payload is ASCII");
    let (_, sig) = text.split_once('|').expect("cert|signature");
    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, sig)
        .expect("the folded signature field is standard base64")
}

#[test]
fn auto_signs_each_shape_as_the_shape_its_bytes_ask_for() {
    let key = testdata().join("certs/signer-rsa.p12");
    let pdf = testdata().join("inputs/simple.pdf");
    let xml = testdata().join("inputs/simple.xml");
    let other = testdata().join("inputs/simple.txt");
    for needed in [&key, &pdf, &xml, &other] {
        if !needed.is_file() {
            require_or_skip(&format!("{} is missing", needed.display()));
            return;
        }
    }
    let ks = KeySource::P12 {
        path: &key,
        password: "openfirma",
    };

    // One call per document, through the real front door (`execute`: parse,
    // resolve, build the request, sign), returning the signed bytes and the
    // shape the answer claims.
    let case = |name: &str| -> (Vec<u8>, String) {
        let bytes = std::fs::read(testdata().join("inputs").join(name)).unwrap();
        let uri = openfirma_browser::uri::parse(&format!(
            "afirma://sign?dat={}&format=auto&algorithm=SHA256withRSA",
            enc(&url_safe(&bytes))
        ))
        .expect("the recorded shape parses");
        let result = execute(&uri, &ks).expect("auto signs");
        let ResultKind::Signature { format } = result.kind else {
            panic!("a sign call answers with a signature, not a certificate");
        };
        (signature_bytes(&result.payload), format)
    };

    // A PDF: PAdES is a signed PDF document, so the bytes ARE a PDF. Before the
    // fix this was a CMS DER of a few kilobytes and the label already said
    // PAdES — the one thing a reader of the answer could not tell.
    let (pdf_out, pdf_label) = case("simple.pdf");
    assert!(
        pdf_out.starts_with(b"%PDF-"),
        "a PDF asked as auto must come back a PDF, not a detached CMS: {} bytes, \
         starting {:02x?}",
        pdf_out.len(),
        &pdf_out[..4.min(pdf_out.len())]
    );
    assert_eq!(
        pdf_label, "PAdES",
        "the shape named and the shape signed come from one resolution"
    );

    // An XML: XAdES is XML markup (enveloped, see docs/xades.md), never a DER
    // structure.
    let (xml_out, xml_label) = case("simple.xml");
    assert_eq!(xml_label, "XAdES");
    assert!(
        xml_out.starts_with(b"<") && xml_out.windows(9).any(|w| w == b"Signature"),
        "an XML asked as auto must come back markup carrying a Signature element: \
         {} bytes, starting {:02x?}",
        xml_out.len(),
        &xml_out[..8.min(xml_out.len())]
    );

    // Anything else: CAdES, a CMS DER — the same shape as before the fix, which
    // is what pins that the resolution did not change the fallback.
    let (other_out, other_label) = case("simple.txt");
    assert_eq!(other_label, "CAdES");
    assert_eq!(
        other_out.first(),
        Some(&0x30),
        "a transparent file asked as auto stays CAdES: a CMS DER begins 0x30"
    );
    assert!(
        other_out
            .windows(SHA256_RSA_OID.len())
            .any(|w| w == SHA256_RSA_OID),
        "the fallback is the CAdES signature the key announces"
    );

    // And the three are in fact three different shapes, so no assertion above
    // can be satisfied by the same bytes.
    assert!(
        !(pdf_out.starts_with(b"%PDF-") && other_out.starts_with(b"%PDF-")),
        "the PDF and the transparent file are signed as different things"
    );
}
