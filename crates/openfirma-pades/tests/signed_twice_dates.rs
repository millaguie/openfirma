//! The second signature of a document: what a signing pass rewrites in the
//! *metadata*, and whether the revision gate can tell that from tampering.
//!
//! Round two's 02-N-4. The refusal this area produced read
//! "a stream object was rewritten after the signature; readers render its bytes
//! (page content, XObjects, embedded files)" — and it was said about the XMP metadata
//! packet, which nothing renders. Measured against AutoFirma 1.9.1 (`gs` writes a PDF
//! carrying XMP and an `/Info` dictionary, AutoFirma signs it twice), the second pass
//! moves three date fields and nothing else anywhere in the file: `/ModDate` in
//! `/Info`, `xmp:ModifyDate` and `xmp:MetadataDate` in the packet, one second
//! forward, `/Producer` byte for byte intact. Both objects kept their numbers, so no
//! fresh-dictionary rule ever looked at them, and the document the reference tool had
//! just produced was refused as tampering.
//!
//! Two things are pinned here. The shapes are licensed when ONLY dates moved
//! (`a_second_pass_that_only_moves_dates_verifies`), and they are still refused when
//! anything with meaning moved with them — a property whose value changed, a key
//! invented or dropped, an XMP element added, a date element holding a sentence. And
//! the finding's other half, the wording: a refusal says what the gate knows, and one
//! signature followed by two unclassified changes is one sentence, not two.
//!
//! The document itself lives in `common`, because the reference tool signing it twice
//! is pinned in `autofirma_cosign.rs` against the very same fixture.

use std::path::{Path, PathBuf};

use openfirma_cades::verify::VerifyOptions;
use openfirma_core::CertificateHandle;
use openfirma_core::signer::SoftwareSigner;
use openfirma_pades::{PadesOptions, pades_sign, pades_verify};

mod common;

use common::{
    CONTENT_OBJ as CONTENT, INFO_BODY_LATER, INFO_OBJ as INFO, METADATA_OBJ as METADATA,
    XMP_PACKET_LATER as PACKET_LATER, xmp_document,
};

fn certs_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/certs")
}

fn handle(name: &str) -> CertificateHandle {
    let pem = std::fs::read_to_string(certs_dir().join(name))
        .unwrap_or_else(|e| panic!("{name} is part of the test PKI but cannot be read: {e}"));
    CertificateHandle::from_pem(&pem).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn require_or_skip(reason: &str) {
    if std::env::var("OPENFIRMA_REQUIRE_TESTS").is_ok() {
        panic!("cannot run the test: {reason}");
    }
    eprintln!("skipped, {reason}");
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

// ---------------------------------------------------------------------------
// Writing a later revision by hand, because what a pass rewrites is the subject.

/// A dictionary and the payload it declares, in the `stream` form the gate reads:
/// `/Length` computed, because a wrong one is a different object.
fn stream_body(dict: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = dict.as_bytes().to_vec();
    out.extend_from_slice(b"\nstream\n");
    out.extend_from_slice(payload);
    out.extend_from_slice(b"\nendstream");
    out
}

fn metadata_body(payload: &[u8]) -> Vec<u8> {
    stream_body(
        &format!(
            "<< /Type /Metadata /Subtype /XML /Length {} >>",
            payload.len()
        ),
        payload,
    )
}

fn content_body(payload: &[u8]) -> Vec<u8> {
    stream_body(&format!("<< /Length {} >>", payload.len()), payload)
}

fn last_xref(pdf: &[u8]) -> usize {
    let tail = &pdf[pdf.len().saturating_sub(64)..];
    let at = tail
        .windows(b"startxref".len())
        .rposition(|w| w == b"startxref")
        .expect("a document ends with a startxref record");
    let text = std::str::from_utf8(&tail[at + b"startxref".len()..]).unwrap();
    text.trim_start()
        .bytes()
        .take_while(|b| b.is_ascii_digit())
        .map(char::from)
        .collect::<String>()
        .parse()
        .expect("the startxref holds an offset")
}

fn declared_size(pdf: &[u8]) -> u32 {
    let text = String::from_utf8_lossy(pdf);
    let at = text.rfind("/Size ").expect("documents declare /Size");
    text[at + 6..]
        .bytes()
        .skip_while(|b| b.is_ascii_whitespace())
        .take_while(|b| b.is_ascii_digit())
        .map(char::from)
        .collect::<String>()
        .parse()
        .expect("/Size holds a number")
}

/// Append one classic-xref revision redefining the given objects, with the file's
/// own `/Root` and `/Info` named in its trailer. This is a signing library's
/// incremental update with the signature taken out: the objects it re-stamps, and
/// nothing else.
fn append_pass(pdf: &[u8], rewritten: &[(u32, Vec<u8>)]) -> Vec<u8> {
    let mut out = pdf.to_vec();
    out.push(b'\n');
    let mut positions = Vec::with_capacity(rewritten.len());
    for (num, body) in rewritten {
        positions.push((*num, out.len()));
        out.extend_from_slice(format!("{num} 0 obj\n").as_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(b"\nendobj\n");
    }
    let mut xref = String::new();
    for (num, at) in &positions {
        xref.push_str(&format!("{num} 1\n{at:010} 00000 n \n"));
    }
    let xref_at = out.len();
    out.extend_from_slice(format!("xref\n{xref}").as_bytes());
    out.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R /Info 7 0 R /Prev {} >>\nstartxref\n{xref_at}\n%%EOF\n",
            declared_size(pdf),
            last_xref(pdf)
        )
        .as_bytes(),
    );
    out
}

/// The second pass as measured on the reference tool: both metadata objects
/// re-stamped, every property a reader is told left alone.
fn second_pass(pdf: &[u8]) -> Vec<u8> {
    append_pass(
        pdf,
        &[
            (METADATA, metadata_body(PACKET_LATER.as_bytes())),
            (INFO, INFO_BODY_LATER.as_bytes().to_vec()),
        ],
    )
}

fn signed_once() -> Option<Vec<u8>> {
    let signer = signer()?;
    pades_sign(&xmp_document(), &signer, &PadesOptions::default()).ok()
}

// ---------------------------------------------------------------------------

/// What the reference tool's own second signature was refused for, and what
/// verifies now: a pass that moved three dates and nothing else is plumbing, not
/// tampering. The `/Info` arrives re-serialised in iText's spelling, because that is
/// what the tool does and because the rule compares the values a reader is told.
#[test]
fn a_second_pass_that_only_moves_dates_verifies() {
    let Some(signed) = signed_once() else {
        require_or_skip("test PKI missing, rerun tools/gen-testcert.sh");
        return;
    };
    pades_verify(&signed, &anchors()).expect("the document verifies before the pass");

    let twice = second_pass(&signed);
    pades_verify(&twice, &anchors()).expect(
        "a pass that only refreshed /ModDate and the XMP dates is what every signing \
         library writes, and refusing it refused the document AutoFirma itself produced",
    );
}

/// The same pass with a property moved alongside the dates. `/Producer` is what a
/// reader is told wrote the file, so a rule that let it slide because a date also
/// moved would license rewriting the document's stated authorship — which is why the
/// rule asks WHICH VALUES differ.
#[test]
fn a_property_moved_with_the_dates_is_refused_and_named() {
    let Some(signed) = signed_once() else {
        require_or_skip("test PKI missing, rerun tools/gen-testcert.sh");
        return;
    };
    let rewritten = "<</Producer(Alguien con prisa)/Author(D:20261019101107+02'00')/CreationDate(D:20261019101106+02'00')\
         /ModDate(D:20261019101108+02'00')>>";
    let attacked = append_pass(
        &signed,
        &[
            (METADATA, metadata_body(PACKET_LATER.as_bytes())),
            (INFO, rewritten.as_bytes().to_vec()),
        ],
    );

    let text = pades_verify(&attacked, &anchors())
        .expect_err("the producer is not a date, and moving it is not plumbing")
        .to_string();
    assert!(
        text.contains("/Info"),
        "the refusal must name the dictionary the way a reader knows it: {text}"
    );
    assert!(
        text.contains("more than its dates"),
        "and say which part moved: {text}"
    );
}

/// A key invented is not a date refreshed: the rule keeps every key the covered
/// revision had, so an `/Info` that gained a `/Title` is off it — as is one that
/// lost a key, which is the other half of the same check.
#[test]
fn a_key_invented_while_stamping_the_date_is_refused() {
    let Some(signed) = signed_once() else {
        require_or_skip("test PKI missing, rerun tools/gen-testcert.sh");
        return;
    };
    let grown = "<</Producer(GPL Ghostscript 10.08.0)/Author(D:20261019101107+02'00')/CreationDate(D:20261019101106+02'00')\
         /ModDate(D:20261019101108+02'00')/Title(otra cosa)>>";
    let attacked = append_pass(&signed, &[(INFO, grown.as_bytes().to_vec())]);

    let text = pades_verify(&attacked, &anchors())
        .expect_err("nothing licenses inventing a key over a signature")
        .to_string();
    assert!(
        text.contains("/Info"),
        "the refusal names the properties dictionary: {text}"
    );

    // and the same rule from the other side: `/CreationDate` taken away
    let shrunk = "<</Producer(GPL Ghostscript 10.08.0)/Author(D:20261019101107+02'00')/ModDate(D:20261019101108+02'00')>>";
    let attacked = append_pass(&signed, &[(INFO, shrunk.as_bytes().to_vec())]);
    let text = pades_verify(&attacked, &anchors())
        .expect_err("a property removed is a reader told less, which is not a date")
        .to_string();
    assert!(text.contains("/Info"), "and it is named: {text}");
}

/// The key-name guard's own case, and the reason it sits beside the value-shape
/// guard: an `/Info` key that is not one of the two dates, holding a value that looks
/// exactly like a date, moving. The value here is a WELL-FORMED PDF date on purpose:
/// both sides pass the value-shape guard, so the only thing that can refuse this is
/// asking WHICH KEY differs — a property a reader is told has moved, in bytes that
/// look like nothing moved. Producers do carry extra keys in `/Info` (this fixture's
/// is one), so the dictionary is not hypothetical even if the value is.
#[test]
fn a_date_looking_property_under_a_key_that_is_not_a_date_may_not_move() {
    let Some(signed) = signed_once() else {
        require_or_skip("test PKI missing, rerun tools/gen-testcert.sh");
        return;
    };
    let moved = "<</Producer(GPL Ghostscript 10.08.0)/Author(D:20261019101108+02'00')\
         /CreationDate(D:20261019101106+02'00')/ModDate(D:20261019101107+02'00')>>";
    let attacked = append_pass(&signed, &[(INFO, moved.as_bytes().to_vec())]);

    let text = pades_verify(&attacked, &anchors())
        .expect_err("a property moved, whatever shape its bytes are in")
        .to_string();
    assert!(
        text.contains("more than its dates"),
        "the refusal says what moved: {text}"
    );
}

/// The XMP half, refused: a packet that GAINED an element is not a packet whose
/// dates were refreshed. This is the use the review thought the reference tool had
/// for the packet (a signing history), and it is why the rule is a masked byte
/// comparison rather than a scan for date-looking text: content cannot arrive
/// wearing a date's name.
#[test]
fn an_xmp_packet_that_gained_content_is_refused_and_named() {
    let Some(signed) = signed_once() else {
        require_or_skip("test PKI missing, rerun tools/gen-testcert.sh");
        return;
    };
    let grown = PACKET_LATER.replace(
        " </rdf:RDF>",
        "  <rdf:Description rdf:about=\"\">\n   <pdf:SignaturesHistory>dos</pdf:SignaturesHistory>\
         \n  </rdf:Description>\n </rdf:RDF>",
    );
    assert_ne!(grown, PACKET_LATER, "the fixture really adds an element");
    let attacked = append_pass(
        &signed,
        &[
            (METADATA, metadata_body(grown.as_bytes())),
            (INFO, INFO_BODY_LATER.as_bytes().to_vec()),
        ],
    );

    let text = pades_verify(&attacked, &anchors())
        .expect_err("an element added to the packet is content, not a date")
        .to_string();
    assert!(
        text.contains("/Metadata"),
        "the refusal must name the XMP packet: {text}"
    );
    assert!(
        !text.contains("readers render"),
        "and must not claim what readers draw of a packet nothing renders: {text}"
    );
}

/// A date element whose text is not a date is the same attack from the other
/// direction: the writer is telling the reader something through a field the rule
/// licenses. Only text that IS a date gets masked, which is what keeps the rule from
/// being "anything inside those three elements".
#[test]
fn an_xmp_date_element_holding_a_sentence_is_refused() {
    let Some(signed) = signed_once() else {
        require_or_skip("test PKI missing, rerun tools/gen-testcert.sh");
        return;
    };
    let lied = PACKET_LATER.replace(
        "<xmp:ModifyDate>2026-10-19T10:11:08+02:00</xmp:ModifyDate>",
        "<xmp:ModifyDate>PAGUESE UN MILLON</xmp:ModifyDate>",
    );
    assert_ne!(
        lied, PACKET_LATER,
        "the fixture really rewrites the element"
    );
    let attacked = append_pass(
        &signed,
        &[
            (METADATA, metadata_body(lied.as_bytes())),
            (INFO, INFO_BODY_LATER.as_bytes().to_vec()),
        ],
    );

    let text = pades_verify(&attacked, &anchors())
        .expect_err("a sentence inside a date element is content, not a date")
        .to_string();
    assert!(
        text.contains("/Metadata"),
        "the refusal names the packet it refused: {text}"
    );
}

/// `/ModDate` wearing a sentence: the same rule read from the `/Info` side, since a
/// value that is not a date fails it whatever key carries it.
#[test]
fn a_mod_date_that_is_not_a_date_is_refused() {
    let Some(signed) = signed_once() else {
        require_or_skip("test PKI missing, rerun tools/gen-testcert.sh");
        return;
    };
    let lied = "<</Producer(GPL Ghostscript 10.08.0)/Author(D:20261019101107+02'00')/CreationDate(D:20261019101106+02'00')\
         /ModDate(PAGUESE UN MILLON)>>";
    let attacked = append_pass(&signed, &[(INFO, lied.as_bytes().to_vec())]);

    let text = pades_verify(&attacked, &anchors())
        .expect_err("the rule licenses dates, and this is not one")
        .to_string();
    assert!(
        text.contains("/Info"),
        "the refusal names the properties dictionary: {text}"
    );
}

/// The finding's other half, the message. A signature followed by TWO unclassified
/// changes produced two refusals, each repeating the signature's own label, so the
/// reader counted signatures that were not there. One signature is one sentence with
/// the changes listed inside it — and the page's content is named as a stream, which
/// is the claim that used to be made about the XMP packet and is true here.
#[test]
fn one_signature_with_two_unclassified_changes_is_one_sentence() {
    let Some(signed) = signed_once() else {
        require_or_skip("test PKI missing, rerun tools/gen-testcert.sh");
        return;
    };
    let lied = "<</Producer(Alguien con prisa)/Author(D:20261019101107+02'00')/CreationDate(D:20261019101106+02'00')\
         /ModDate(D:20261019101108+02'00')>>";
    let attacked = append_pass(
        &signed,
        &[
            (
                CONTENT,
                content_body(b"BT /F1 24 Tf 72 700 Td (PAGUESE 1.000.000 EUR) Tj ET"),
            ),
            (INFO, lied.as_bytes().to_vec()),
        ],
    );

    let text = pades_verify(&attacked, &anchors())
        .expect_err("unsigned page content after a signature is the attack itself")
        .to_string();
    assert_eq!(
        text.matches("no archive may append").count(),
        1,
        "one signature, one refusal sentence, however many changes followed it: {text}"
    );
    assert!(
        text.contains("6 0 R") && text.contains("/Info"),
        "and both changes are named inside it: {text}"
    );
    assert!(
        text.contains("a stream object was rewritten"),
        "the content stream is described as the stream it is: {text}"
    );
}

// ---------------------------------------------------------------------------
// Round 7 part C, C-4a and C-4b: the date rules read on the two shapes the
// earlier tests did not cover — a PURE `/Info` (the one this crate's writer
// produces) and legal date spellings the rule used to refuse.

const INPUT: &[u8] = include_bytes!("../../../testdata/inputs/simple.pdf");

fn signed_input() -> Option<Vec<u8>> {
    let signer = signer()?;
    pades_sign(INPUT, &signer, &PadesOptions::default()).ok()
}

/// C-4a, hiding direction: our writer's `/Info` holds only date keys, and the
/// pure branch asked the KEYS and never the VALUES — so a later pass could put a
/// sentence (visible as the document's ModDate in `pdfinfo`), a reference, or an
/// empty dictionary there and be licensed as plumbing over bytes a signature
/// attested.
#[test]
fn a_pure_info_that_stops_carrying_dates_is_refused() {
    let Some(signed) = signed_input() else {
        require_or_skip("test PKI missing, rerun tools/gen-testcert.sh");
        return;
    };
    let xref = openfirma_pades::pdf::last_startxref(&signed).expect("startxref");
    let info = openfirma_pades::pdf::trailer(&signed, xref)
        .expect("the signed trailer parses")
        .info
        .expect("the writer stamps an /Info");

    let sentence = "<</ModDate(PAGUESE UN MILLON DE EUROS)>>";
    let attacked = append_pass(&signed, &[(info.num, sentence.as_bytes().to_vec())]);
    let text = pades_verify(&attacked, &anchors())
        .expect_err("a date key is not a licence to put a sentence in the properties")
        .to_string();
    assert!(
        text.contains("/Info"),
        "the refusal names the properties dictionary: {text}"
    );

    // the same key removed: the attested date disappears from every reader
    let attacked = append_pass(&signed, &[(info.num, b"<</>>".to_vec())]);
    let text = pades_verify(&attacked, &anchors())
        .expect_err("an empty dictionary is nobody's bookkeeping")
        .to_string();
    assert!(
        text.contains(&info.to_string()),
        "and the object it emptied is named here: {text}"
    );
}

/// C-4b, refusing direction: two spellings every reader prints as a date and the
/// rule used to call tampering — PDF 2.0's `D:YYYY-MM-DDTHH:mm:ss+HH:mm` and a
/// HEX string carrying UTF-16BE with a BOM (legal in any edition, ISO 32000-1
/// 7.9.2.2). Both here rewrite ONLY `/ModDate` on a mixed `/Info`, so the
/// acceptance is the dates-only shape working, not a loophole.
#[test]
fn legal_date_spellings_move_as_dates() {
    let Some(signed) = signed_once() else {
        require_or_skip("test PKI missing, rerun tools/gen-testcert.sh");
        return;
    };
    let iso = INFO_BODY_LATER.replace(
        "/ModDate(D:20261019101108+02'00')",
        "/ModDate(D:2026-10-19T10:12:00+02:00)",
    );
    let attacked = append_pass(&signed, &[(INFO, iso.into_bytes())]);
    pades_verify(&attacked, &anchors())
        .expect("a PDF 2.0 date is a date; refusing it called a clean file tampered");

    let utf16: String = {
        let text = "D:20261019101200+02'00'";
        let mut hex = String::from("FEFF");
        for unit in text.encode_utf16() {
            hex.push_str(&format!("{unit:04X}"));
        }
        hex
    };
    let hex_body = INFO_BODY_LATER.replace(
        "/ModDate(D:20261019101108+02'00')",
        &format!("/ModDate<{utf16}>"),
    );
    let attacked = append_pass(&signed, &[(INFO, hex_body.into_bytes())]);
    pades_verify(&attacked, &anchors())
        .expect("a UTF-16 hex string is a date spelling, not an escape");
}
