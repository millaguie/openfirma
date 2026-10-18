//! The incremental saving attack (finding C-1 of the review): a revision
//! appended after a signature that redefines what readers show. `verify`
//! classifies everything newer than each signature against the archive white-
//! list — new signatures, document time-stamps, /DSS validation data and the
//! plumbing a newer signature needs — and refuses anything else: page content
//! rewritten by an unsigned revision is something no signature attests to.

use std::path::{Path, PathBuf};

use openfirma_cades::verify::VerifyOptions;
use openfirma_core::{CertificateHandle, SoftwareSigner};
use openfirma_pades::ltv::RevocationBytes;
use openfirma_pades::{Appearance, PadesOptions, pades_sign, pades_verify, pdf};

const INPUT: &[u8] = include_bytes!("../../../testdata/inputs/simple.pdf");

/// The fixed width of a `/ByteRange` number in a hand-written signature: enough
/// digits for any test document, and the same width on both sides of the patch
/// so pointing the range at the pass moves no byte.
const PAD: &str = "0000000000";

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

fn crls() -> Option<Vec<RevocationBytes>> {
    let dir = certs_dir();
    let (Ok(intermediate), Ok(ca)) = (
        std::fs::read(dir.join("intermediate.crl.der")),
        std::fs::read(dir.join("ca.crl.der")),
    ) else {
        return None;
    };
    Some(vec![
        RevocationBytes::Crl(intermediate),
        RevocationBytes::Crl(ca),
    ])
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

/// The last `startxref <offset>` of the file, read from its trailer.
fn last_xref(pdf: &[u8]) -> usize {
    let tail = &pdf[pdf.len().saturating_sub(64)..];
    let at = tail
        .windows(b"startxref".len())
        .rposition(|w| w == b"startxref")
        .expect("a signed document ends with a startxref record");
    let text = std::str::from_utf8(&tail[at + b"startxref".len()..]).unwrap();
    text.trim_start()
        .bytes()
        .take_while(|b| b.is_ascii_digit())
        .map(char::from)
        .collect::<String>()
        .parse()
        .expect("the startxref holds an offset")
}

/// Append one classic-xref revision that redefines object `num` with the exact
/// bytes at `source_at` of `pdf` (the object's own stored body): a new object,
/// a one-row xref, and a trailer naming the previous section through /Prev —
/// what the review's attack script did. The padding differs from the original
/// writer's (different byte offsets), which is itself part of what the gate
/// must look through: identical *content* is not an attack.
/// A byte-identical copy of an object. The dictionary alone is NOT the object
/// when the object is a stream: a writer relocating a page's content stream
/// copies the data after `stream` too, and omitting it does not relocate the
/// content, it deletes it — which is a change, and one the gate refuses (as it
/// should: the page renders nothing).
fn append_copy(pdf: &[u8], num: u32, source_at: usize) -> Vec<u8> {
    let mut contents = Vec::new();
    let body = pdf::object_body(pdf, source_at).expect("the source offset holds an object");
    contents.extend_from_slice(&pdf[body]);
    if let Ok(payload) = pdf::stream_raw(pdf, source_at) {
        contents.extend_from_slice(b"\nstream\n");
        contents.extend_from_slice(&payload);
        contents.extend_from_slice(b"\nendstream");
    }
    let mut out = pdf.to_vec();
    out.push(b'\n');
    let object_at = out.len();
    out.extend_from_slice(format!("{num} 0 obj\n").as_bytes());
    out.extend_from_slice(&contents);
    out.extend_from_slice(b"\nendobj\n");
    let xref_at = out.len();
    let size = declared_size(pdf) + 1;
    out.extend_from_slice(format!("xref\n{num} 1\n{object_at:010} 00000 n \n").as_bytes());
    out.extend_from_slice(
        format!(
            "trailer\n<< /Size {size} /Root 1 0 R /Prev {} >>\nstartxref\n{xref_at}\n%%EOF\n",
            last_xref(pdf)
        )
        .as_bytes(),
    );
    out
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

fn object_at(pdf: &[u8], num: u32) -> usize {
    let needle = format!("{num} 0 obj");
    pdf.windows(needle.len())
        .position(|w| w == needle.as_bytes())
        .unwrap_or_else(|| panic!("object {num} is not a direct object of this document"))
}

/// The classic Incremental Saving Attack: sign an archived document, then
/// append an unsigned revision that replaces the page's content stream with
/// new text. Every crypto check still passes — each digest covers only the
/// signed prefix — so without the revision gate `verify` would green-light a
/// document whose visible content no signature ever attested to (what pdfsig
/// calls "not all of the document is signed"). This is the review's proof of
/// concept, rebuilt from our own fixtures so it stays fully synthetic.
#[test]
fn a_revision_rewriting_page_content_after_a_signature_is_refused() {
    let (Some(signer), Some(revocation)) = (signer(), crls()) else {
        require_or_skip("test PKI or CRLs missing, rerun tools/gen-testcert.sh");
        return;
    };
    // B-LT: the attack in the review ran against an archived document, and a
    // /DSS present forces the classifier to choose between its whitelist and
    // the rewritten payload.
    let signed = pades_sign(
        INPUT,
        &signer,
        &PadesOptions {
            revocation,
            ..PadesOptions::default()
        },
    )
    .expect("signing failed");
    pades_verify(&signed, &anchors()).expect("the clean archive verifies");

    let content = b"<< /Length 46 >>\nstream\nBT /F1 24 Tf 72 700 Td (PAGUESE 1.000.000 EUR) Tj ET\nendstream";
    let attacked = append_written(&signed, 5, content);

    let error = pades_verify(&attacked, &anchors())
        .expect_err("rewriting the page content after a signature is the attack itself");
    let text = error.to_string();
    assert!(
        text.contains("no archive may append"),
        "the refusal says what was violated: {text}"
    );
    assert!(
        text.contains("5 0 R"),
        "the refusal names the rewritten object: {text}"
    );
}

/// Round 2, N-5. A later revision could rewrite the covered signature
/// dictionary itself, licensed by the *type of the old body*
/// (`is_type(older, "/Sig")` in `classify_one`). On a document carrying two
/// signatures, the rewrite below turns the first one into an ordinary
/// dictionary: `inspect::signatures` stops enumerating it, the second signature
/// still verifies by its own numbers, and the verdict — which speaks about the
/// signatures it can see — reports one signature over a document that was
/// signed twice. A *new* signature is a new object, so a rewrite of a real one
/// has no shape to license.
#[test]
fn a_covered_signature_dictionary_cannot_be_rewritten() {
    let Some(signer) = signer() else {
        require_or_skip("test PKI missing, rerun tools/gen-testcert.sh");
        return;
    };
    let once = pades_sign(INPUT, &signer, &PadesOptions::default()).expect("signing failed");
    let twice =
        pades_sign(&once, &signer, &PadesOptions::default()).expect("second signing failed");
    pades_verify(&twice, &anchors()).expect("the clean two-signature document verifies");
    let sigs = openfirma_pades::inspect::signatures(&twice).expect("the syntax reads");
    assert_eq!(sigs.len(), 2, "the fixture is a document signed twice");
    let first = sigs[0].object;

    // the first signature's dictionary, replaced by something that is not one
    let attacked = append_written(&twice, first.num, b"<< /Nothing (aqui) >>");

    // what a reader sees: one signature, and it is not the one that vanished
    let after = openfirma_pades::inspect::signatures(&attacked).expect("the syntax reads");
    assert_eq!(
        after.len(),
        1,
        "the reader no longer finds the signature the first revision made"
    );
    assert_ne!(after[0].object, first);

    let error = pades_verify(&attacked, &anchors())
        .expect_err("a covered signature dictionary may not be rewritten");
    let text = error.to_string();
    assert!(
        text.contains("no archive may append"),
        "the refusal says what was violated: {text}"
    );
    assert!(
        text.contains(&format!("{} 0 R", first.num)),
        "and names the object whose signature disappeared: {text}"
    );
}

/// Append one revision defining object `num` with `body` verbatim.
fn append_written(pdf: &[u8], num: u32, body: &[u8]) -> Vec<u8> {
    let mut out = pdf.to_vec();
    out.push(b'\n');
    let object_at = out.len();
    out.extend_from_slice(format!("{num} 0 obj\n").as_bytes());
    out.extend_from_slice(body);
    out.extend_from_slice(b"\nendobj\n");
    let xref_at = out.len();
    let size = declared_size(pdf).max(num + 1);
    out.extend_from_slice(format!("xref\n{num} 1\n{object_at:010} 00000 n \n").as_bytes());
    out.extend_from_slice(
        format!(
            "trailer\n<< /Size {size} /Root 1 0 R /Prev {} >>\nstartxref\n{xref_at}\n%%EOF\n",
            last_xref(pdf)
        )
        .as_bytes(),
    );
    out
}

/// Append one revision that redefines exactly the numbers given, with a classic
/// cross-reference TABLE whose subsections are the runs of numbers the pass
/// writes — ISO 32000 lets one section carry several subsections. `append_written`
/// writes one number and `append_packed_pass` a contiguous run; a pass that
/// rewrites a covered object AND adds its own (which is what a fill is) needs
/// both in one revision, and they are almost never adjacent.
fn append_pieces(pdf: &[u8], objects: &[(u32, Vec<u8>)]) -> Vec<u8> {
    let mut out = pdf.to_vec();
    if !out.ends_with(b"\n") {
        out.push(b'\n');
    }
    let mut offsets: Vec<(u32, usize)> = Vec::new();
    for (num, body) in objects {
        offsets.push((*num, out.len()));
        out.extend_from_slice(format!("{num} 0 obj\n").as_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(b"\nendobj\n");
    }
    let xref_at = out.len();
    let mut xref = String::from("xref\n");
    let mut i = 0;
    while i < offsets.len() {
        let start = i;
        while i + 1 < offsets.len() && offsets[i + 1].0 == offsets[i].0 + 1 {
            i += 1;
        }
        xref.push_str(&format!("{} {}\n", offsets[start].0, i - start + 1));
        for (_, at) in &offsets[start..=i] {
            xref.push_str(&format!("{at:010} 00000 n \n"));
        }
        i += 1;
    }
    let size = offsets
        .last()
        .map(|(num, _)| num + 1)
        .unwrap_or(0)
        .max(declared_size(pdf));
    out.extend_from_slice(xref.as_bytes());
    out.extend_from_slice(
        format!(
            "trailer\n<< /Size {size} /Root 1 0 R /Prev {} >>\nstartxref\n{xref_at}\n%%EOF\n",
            last_xref(pdf)
        )
        .as_bytes(),
    );
    out
}

/// A byte-identical copy of a signed object is not a redefinition: an archiving
/// writer that relocates objects keeps the document verifiable. If this test
/// fails, the gate confuses bookkeeping with content changes — and every
/// real-world B-LT tool would trip it.
#[test]
fn an_identical_copy_of_a_signed_object_does_not_trip_the_gate() {
    let Some(signer) = signer() else {
        require_or_skip("test PKI missing, rerun tools/gen-testcert.sh");
        return;
    };
    let signed = pades_sign(INPUT, &signer, &PadesOptions::default()).expect("signing failed");
    let source = object_at(&signed, 5);
    let copied = append_copy(&signed, 5, source);
    pades_verify(&copied, &anchors()).expect("a copy that changes nothing still verifies");
}

/// A revision that adds nothing but a cross-reference section and a trailer: no
/// object is redefined, so the gate has nothing to classify — what a chain of
/// these measures is how many sections the reader is willing to walk.
fn append_trailer_only(pdf: &[u8]) -> Vec<u8> {
    let mut out = pdf.to_vec();
    out.push(b'\n');
    let xref_at = out.len();
    out.extend_from_slice(b"xref\n0 1\n0000000000 65535 f \n");
    out.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R /Prev {} >>\nstartxref\n{xref_at}\n%%EOF\n",
            declared_size(pdf),
            last_xref(pdf)
        )
        .as_bytes(),
    );
    out
}

/// The chain walk is guarded at 100 sections, and the guard is declared: a
/// document at the limit is read, the next section is refused. 100 signatures is
/// more than any real document carries, and the guard is what stops a file whose
/// `/Prev` points at itself — or at a section it already walked — from being
/// followed forever. This is the number made measured, so raising the limit
/// deliberately fails a test instead of silently changing what is readable.
///
/// Flagged by the round-5 reviewer as an unpinned guard ("los tests actuales no
/// lo fijan — ruido, no defecto").
#[test]
fn a_chain_at_the_revision_limit_is_read_and_one_past_it_is_refused() {
    let Some(signer) = signer() else {
        require_or_skip("test PKI missing, rerun tools/gen-testcert.sh");
        return;
    };
    let signed = pades_sign(INPUT, &signer, &PadesOptions::default()).expect("signing failed");
    // the document's own section and the signature's: two, so 98 more is 100
    let mut at_limit = signed;
    for _ in 0..98 {
        at_limit = append_trailer_only(&at_limit);
    }
    pades_verify(&at_limit, &anchors()).expect("100 sections are read");
    let over = append_trailer_only(&at_limit);
    let error = pades_verify(&over, &anchors()).expect_err("101 sections are refused");
    let text = format!("{error}");
    assert!(
        text.contains("more than 100 revisions"),
        "says why rather than misreading the file: {text}"
    );
}

/// Overwrite the FIRST `startxref <n> %%EOF` record of a document in place, so
/// the bytes stop being a record while every offset after them is untouched.
/// Readers do not need that record — the `/Prev` chain walks past it — which is
/// what makes this a real-world shape and not a fiction.
fn strip_first_record(pdf: &[u8]) -> Vec<u8> {
    let mut out = pdf.to_vec();
    let at = out
        .windows(9)
        .position(|window| window == b"startxref")
        .expect("a startxref record");
    let eof = at
        + 5
        + out[at + 5..]
            .windows(5)
            .position(|window| window == b"%%EOF")
            .expect("%%EOF");
    let end = if out[eof..].starts_with(b"\r\n") {
        eof + 2
    } else if eof < out.len() && matches!(out[eof], b'\n' | b'\r') {
        eof + 1
    } else {
        eof
    };
    out[at..end].fill(b'#');
    out
}

/// Attribution fails closed on a revision whose own closing record is missing.
/// The oldest section of a chain falls back to `end = the end of the FILE`, and
/// `revision_of` is a `rposition` over the newest-first list: in a document
/// whose oldest section has no honest record, EVERY offset resolves to that
/// section, so `same_pass` is vacuously true for every pair of objects and the
/// plumbing rules license whatever a later pass writes — "a font this pass
/// wrote and a signature of this pass names", for a pass that carries no
/// signature at all.
///
/// Flagged by the round-5 reviewer (`R5-A1`), whose own payload (filling a
/// `/F2` slot the covered bytes named) is refused by the covered-name rule
/// already; this test pins the collapse itself, on the one shape that survives
/// that rule — an inert font — where the only thing that can refuse it is
/// knowing WHICH pass wrote it.
#[test]
fn attribution_fails_closed_when_the_oldest_revision_has_no_closing_record() {
    let Some(signer) = signer() else {
        require_or_skip("test PKI missing, rerun tools/gen-testcert.sh");
        return;
    };
    // Two sections, the older one stripped of its record, so the chain has an
    // oldest section whose end is the fallback rather than its own boundary.
    let page = b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] \
                 /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>";
    let two_sections = append_written(INPUT, 6, page);
    let stripped = strip_first_record(&two_sections);
    let signed = pades_sign(&stripped, &signer, &PadesOptions::default()).expect("signing failed");
    // A font nobody names, written by a pass that carries no signature: an
    // addition nothing attests, and the pass that wrote it is not signed.
    let attacked = append_written(
        &signed,
        97,
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    );
    let error = pades_verify(&attacked, &anchors()).expect_err("a font nobody signed");
    let text = format!("{error}");
    assert!(text.contains("object 97 0 R"), "names the object: {text}");
}

/// A rewritten page-content PAYLOAD is a rewrite even when its dictionary does
/// not move an inch: `/Length 61` stays `61` while the 61 bytes a reader draws
/// are replaced. Measured before the fix — resolving an object answers with its
/// dictionary, so both sides looked like `<< /Length 61 >>`, the gate reported
/// ZERO redefinitions and `verify` called the document fine while a reader
/// showed the attacker's text under a signature that attests the original.
#[test]
fn a_rewritten_stream_payload_is_refused_even_when_its_dictionary_is_identical() {
    let Some(signer) = signer() else {
        require_or_skip("test PKI missing, rerun tools/gen-testcert.sh");
        return;
    };
    let signed = pades_sign(INPUT, &signer, &PadesOptions::default()).expect("signing failed");
    // same dictionary bytes, same /Length, different 61 bytes of content
    let mut payload = b"BT /F1 12 Tf 72 770 Td (PAID IN FULL to attacker) Tj ET".to_vec();
    payload.resize(61, b' ');
    let mut body = b"<< /Length 61 >>\nstream\n".to_vec();
    body.extend_from_slice(&payload);
    body.extend_from_slice(b"\nendstream");
    let rewritten = append_written(&signed, 5, &body);
    let error = pades_verify(&rewritten, &anchors()).expect_err("the payload was rewritten");
    let text = format!("{error}");
    assert!(text.contains("object 5 0 R"), "names the object: {text}");
    assert!(
        text.contains("a stream object was rewritten"),
        "names the stream, not a dictionary: {text}"
    );
}

/// A rewrite nothing can read is still a rewrite. When `redefinitions_after`
/// cannot resolve an object's new bytes it used to `continue` — the gate
/// declining to judge, in silence — and the covering state's bytes are gone
/// from every reader's view while `verify` reports a clean document. The
/// unreadable body here is an unterminated literal string in the page's
/// content stream, which is the shape a real writer's bug or a hostile
/// revision produces, and which the parser cannot read to the end of the file.
///
/// Flagged by the round-5 reviewer as a method note ("a resolve that fails in
/// this gate is SILENT; validate any ObjStm PoC with qpdf before trusting an
/// OK") after a malformed PoC of theirs looked like a hole. It is one.
#[test]
fn a_rewrite_whose_bytes_cannot_be_read_is_refused_not_skipped() {
    let Some(signer) = signer() else {
        require_or_skip("test PKI missing, rerun tools/gen-testcert.sh");
        return;
    };
    let signed = pades_sign(INPUT, &signer, &PadesOptions::default()).expect("signing failed");
    // The unterminated string runs to the end of the file, so the dictionary
    // never closes and nothing can resolve this object.
    let body = b"<< /Length 61 /X (oops\nstream\nPAID IN FULL\nendstream";
    let rewritten = append_written(&signed, 5, body);
    let error = pades_verify(&rewritten, &anchors()).expect_err("the object was rewritten");
    let text = format!("{error}");
    assert!(text.contains("object 5 0 R"), "names the object: {text}");
    assert!(
        text.contains("cannot be read"),
        "says the new bytes are unreadable rather than guessing a shape: {text}"
    );
}

/// The same attack with one more hop: a brand-new content stream plus a page
/// dictionary repointing `/Contents` at it. The page rewrite is off the white-
/// list whatever the new stream is, so this must refuse too.
#[test]
fn an_appended_revision_repointing_the_page_is_refused() {
    let Some(signer) = signer() else {
        require_or_skip("test PKI missing, rerun tools/gen-testcert.sh");
        return;
    };
    let signed = pades_sign(INPUT, &signer, &PadesOptions::default()).expect("signing failed");
    let content = b"<< /Length 46 >>\nstream\nBT /F1 24 Tf 72 700 Td (PAGUESE 1.000.000 EUR) Tj ET\nendstream";
    let mut pdf = append_written(&signed, 99, content);
    let page = b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> \
                /Contents 99 0 R /Annots [10 0 R] >>";
    pdf = append_written(&pdf, 3, page);
    let error = pades_verify(&pdf, &anchors())
        .expect_err("a revision repointing /Contents is the attack through a hop");
    assert!(
        error.to_string().contains("no archive may append"),
        "the refusal says what was violated: {error}"
    );
}

/// The positive control: appending validation data to a plain B-B document —
/// exactly what a later B-LT pass does — passes the gate. (ltv.rs covers the
/// full archive flow; this pins the whitelist's central case against a bare
/// signature with no other revisions around.)
#[test]
fn an_archive_appended_after_a_signature_passes_the_gate() {
    let (Some(signer), Some(revocation)) = (signer(), crls()) else {
        require_or_skip("test PKI missing, rerun tools/gen-testcert.sh");
        return;
    };
    let plain = pades_sign(INPUT, &signer, &PadesOptions::default()).expect("B-B failed");
    let archived = openfirma_pades::add_validation_data(
        &plain,
        &[handle("signer-rsa.crt"), handle("intermediate.crt")],
        &revocation,
    )
    .expect("the B-LT pass runs");
    pades_verify(&archived, &anchors())
        .expect("a /DSS appended after a signature is what archives are for");
}

/// The shape a writer that REWRITES the document to sign produces — iText,
/// behind AutoFirma's first signature: the signature lives in revision 1, and
/// the boundary its `/ByteRange` names is that revision's own `%%EOF` record.
/// Every later pass over such a document (another signature, an archive) is
/// classified against that boundary, and until the oldest revision got its own
/// record back instead of the file end, the pass was refused with "the
/// /ByteRange ends at 55424, which is not the end of any revision" — measured
/// on AutoFirma's own `testdata/golden/simple.autofirma.pdf`, 55424 bytes.
///
/// That fixture is AutoFirma's output: `tools/golden-diff.sh` makes it from a
/// JVM and the AutoFirma jar, neither of which this repository ships or CI has.
/// Rather than commit a signed PDF whose chain the next `gen-testcert.sh`
/// invalidates, the test says so and does nothing when it is not there.
#[test]
fn an_archive_over_a_document_autofirma_wrote_is_accepted() {
    let Some(revocation) = crls() else {
        require_or_skip("test PKI missing, rerun tools/gen-testcert.sh");
        return;
    };
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/golden/simple.autofirma.pdf");
    let Ok(auto) = std::fs::read(&fixture) else {
        eprintln!(
            "skipped, {} is not here: tools/golden-diff.sh writes it (needs autofirma.jar)",
            fixture.display()
        );
        return;
    };
    // The reference tool's own document verifies on its own, and it is ONE
    // revision: iText rewrote the file to sign it, which is the shape this test
    // exists for.
    pades_verify(&auto, &anchors()).expect("AutoFirma's own output verifies");
    let revs = openfirma_pades::revisions::revisions(&auto).expect("the fixture is readable");
    assert_eq!(revs.len(), 1, "AutoFirma rewrites the document to sign it");

    // A later pass over it is appended right where that first revision ends.
    let archived = openfirma_pades::add_validation_data(
        &auto,
        &[handle("signer-rsa.crt"), handle("intermediate.crt")],
        &revocation,
    )
    .expect("the B-LT pass runs over the reference tool's document");
    // The verdict first, because it is the thing a user sees: with the file end
    // standing where this revision's own record belongs, this is where the
    // archive was refused — "the /ByteRange ends at 55424, which is not the end
    // of any revision".
    pades_verify(&archived, &anchors())
        .expect("an archive appended to the reference tool's own signature is an archive");
    let revs = openfirma_pades::revisions::revisions(&archived).expect("readable");
    assert_eq!(revs.len(), 2);
    assert_eq!(
        revs[1].end,
        auto.len(),
        "the revision AutoFirma wrote ends at its own record, which is where the archive begins"
    );
}

/// The gate decides on what the merged state shows, not on who wrote a byte:
/// an appended revision that redefines a signed object with different bytes is
/// refused even when no reader would ever reach the new definition (nothing
/// references it). That is deliberate — "the file contains two definitions of
/// your page content stream" is not something a signature archive should let
/// pass on the argument that one of them looks unreachable, and reaching the
/// copy takes one more trivial revision which the refusal above already covers.
#[test]
fn a_second_definition_of_a_signed_object_is_refused_even_unreferenced() {
    let Some(signer) = signer() else {
        require_or_skip("test PKI missing, rerun tools/gen-testcert.sh");
        return;
    };
    let signed = pades_sign(INPUT, &signer, &PadesOptions::default()).expect("signing failed");
    // a different stream body stored as object 5 again, unreferenced by anyone
    let body = b"<< /Length 46 >>\nstream\nBT /F1 24 Tf 72 700 Td (PAGUESE 1.000.000 EUR) Tj ET\nendstream";
    let doubled = append_written(&signed, 5, body);
    let error = pades_verify(&doubled, &anchors())
        .expect_err("two definitions of a signed object is exactly the attack's raw material");
    assert!(
        error.to_string().contains("no archive may append"),
        "the refusal says what was violated: {error}"
    );
}

/// The shadow attack through a hanging `/DSS` (Kimi round 1, C-1). The
/// revisions gate seeds "this object is validation data" from the archive the
/// CATALOG's /DSS names. An earlier build seeded it from every object whose
/// /Type is /DSS, referenced or not, so an attacker appended one revision that
/// rewrote the page content stream AND added an unreferenced
/// `<< /Type /DSS /Certs [<content> 0 R] >>`: the rewritten content then
/// counted as validation data and `verify` said OK over a document whose text
/// a reader renders as something no signature covered. The hanging /DSS must
/// whitelist nothing.
#[test]
fn a_hanging_dss_dictionary_cannot_whitelist_a_rewritten_payload() {
    let Some(signer) = signer() else {
        require_or_skip("test PKI missing, rerun tools/gen-testcert.sh");
        return;
    };
    let signed = pades_sign(INPUT, &signer, &PadesOptions::default()).expect("signing failed");
    let content =
        b"<< /Length 46 >>\nstream\nBT /F1 24 Tf 72 700 Td (PAGUESE 1.000.000 EUR) Tj ET\nendstream";
    // one revision: rewrite object 5 (the page content) and add object 99, a
    // /Type /DSS nothing references but which points at the rewritten stream
    let dss = b"<< /Type /DSS /Certs [5 0 R] /CRLs [5 0 R] /OCSPs [5 0 R] >>";
    let attacked = append_two(&signed, &[(5, content), (99, dss.as_slice())]);
    let error = pades_verify(&attacked, &anchors())
        .expect_err("a hanging /DSS must not turn a content rewrite into validation data");
    let text = error.to_string();
    assert!(
        text.contains("no archive may append"),
        "the refusal says what was violated: {text}"
    );
    assert!(
        text.contains("5 0 R"),
        "the refusal names the rewritten content object: {text}"
    );
}

/// The same shadow attack with the payload rewriting ITSELF as a /Type /DSS
/// object instead of adding a separate hanging dictionary: classify_one used to
/// grant any object whose body says `/Type /DSS` a pass, so a content stream
/// that overwrote its own dictionary with that key walked through. Only an
/// ADDED /Type /DSS dictionary (a co-signature's inert archive) is licensed; a
/// REWRITE that claims it is not.
#[test]
fn a_rewritten_object_claiming_type_dss_is_still_refused() {
    let Some(signer) = signer() else {
        require_or_skip("test PKI missing, rerun tools/gen-testcert.sh");
        return;
    };
    let signed = pades_sign(INPUT, &signer, &PadesOptions::default()).expect("signing failed");
    let body = b"<< /Type /DSS /Length 46 >>\nstream\nBT /F1 24 Tf 72 700 Td (PAGUESE 1.000.000 EUR) Tj ET\nendstream";
    let attacked = append_written(&signed, 5, body);
    let error = pades_verify(&attacked, &anchors())
        .expect_err("a rewritten object that merely claims /Type /DSS is not validation data");
    assert!(
        error.to_string().contains("no archive may append"),
        "the refusal says what was violated: {error}"
    );
}

/// Round 2, C-1 again: the archive is the one the CATALOG names, but it may
/// only license the objects it names through the keys a validation-data reader
/// consumes (`/Certs`, `/CRLs`, `/OCSPs`, see `collect_archive_data`). The
/// seeded walk used to follow EVERY reference inside the archive dictionary, so
/// one revision that rewrote the page content stream and re-pointed the catalog
/// at a fresh `<< /Type /DSS /Foo [<content> 0 R] >>` turned the rewritten
/// payload into "validation data" — `verify` answered OK over text the reader
/// shows as something the signature never covered. A key no validator reads
/// licenses nothing.
#[test]
fn an_inert_key_of_the_catalog_archive_cannot_whitelist_a_rewritten_payload() {
    let Some(signer) = signer() else {
        require_or_skip("test PKI missing, rerun tools/gen-testcert.sh");
        return;
    };
    let signed = pades_sign(INPUT, &signer, &PadesOptions::default()).expect("signing failed");
    let content =
        b"<< /Length 46 >>\nstream\nBT /F1 24 Tf 72 700 Td (PAGUESE 1.000.000 EUR) Tj ET\nendstream";
    let catalog = b"<< /Type /Catalog /Pages 2 0 R /DSS 99 0 R >>";
    let dss = b"<< /Type /DSS /Foo [5 0 R] /Bar [4 0 R] >>";
    let attacked = append_two(
        &signed,
        &[(1, catalog.as_slice()), (5, content), (99, dss.as_slice())],
    );
    let error = pades_verify(&attacked, &anchors())
        .expect_err("a key no validation-data reader reads cannot license a content rewrite");
    let text = error.to_string();
    assert!(
        text.contains("no archive may append"),
        "the refusal says what was violated: {text}"
    );
    assert!(
        text.contains("5 0 R"),
        "the refusal names the rewritten content object: {text}"
    );
}

/// The same attack one hop away: the archive names the payload through an
/// object of its own (`/Foo [98 0 R]`, 98 being `<< /Jump [5 0 R] >>`, or a
/// free array). Following references found INSIDE a named object is what let
/// the payload in; the walk now stops at the taxed key, so the hop licenses
/// nothing — a rewritten object is not validation data for the sole reason that
/// something the archive points at points back at it.
#[test]
fn a_hop_through_a_free_object_cannot_whitelist_a_rewritten_payload() {
    let Some(signer) = signer() else {
        require_or_skip("test PKI missing, rerun tools/gen-testcert.sh");
        return;
    };
    let signed = pades_sign(INPUT, &signer, &PadesOptions::default()).expect("signing failed");
    let content =
        b"<< /Length 46 >>\nstream\nBT /F1 24 Tf 72 700 Td (PAGUESE 1.000.000 EUR) Tj ET\nendstream";
    let catalog = b"<< /Type /Catalog /Pages 2 0 R /DSS 99 0 R >>";
    let dss = b"<< /Type /DSS /Foo [98 0 R] >>";
    let hop = b"<< /Jump [5 0 R] >>";
    let attacked = append_two(
        &signed,
        &[
            (1, catalog.as_slice()),
            (5, content),
            (98, hop.as_slice()),
            (99, dss.as_slice()),
        ],
    );
    let error = pades_verify(&attacked, &anchors())
        .expect_err("a reference inside a named object is not the archive naming the payload");
    assert!(
        error.to_string().contains("5 0 R"),
        "the refusal names the rewritten content object: {error}"
    );
}

/// An object only a `/VRI` entry names is not licensed, deliberately: this gate
/// licenses what verification then checks, and openfirma's own `/DSS` validator
/// parses and verifies the top-level `/Certs`, `/CRLs` and `/OCSPs` arrays — it
/// reads the `/VRI` keys against those arrays and never parses per-entry data.
/// Licensing per-entry references would hand an attacker a key to name an
/// addition with that nothing verifies. The profile requires the top-level
/// arrays, so an archive pass that writes only `/VRI` entries is refused here;
/// if a real document turns up that does so, the fix is to make the validator
/// verify per-entry data first and license it afterwards, in that order.
#[test]
fn an_object_named_only_inside_a_vri_entry_is_not_validation_data() {
    let Some(signer) = signer() else {
        require_or_skip("test PKI missing, rerun tools/gen-testcert.sh");
        return;
    };
    let signed = pades_sign(INPUT, &signer, &PadesOptions::default()).expect("signing failed");
    let payload =
        b"<< /Length 46 >>\nstream\nBT /F1 24 Tf 72 700 Td (PAGUESE 1.000.000 EUR) Tj ET\nendstream";
    let catalog = b"<< /Type /Catalog /Pages 2 0 R /DSS 99 0 R >>";
    let dss = b"<< /Type /DSS /VRI << /ABCDEF0123456789ABCDEF0123456789ABCDEF01 << /Cert [98 0 R] >> >> >>";
    let attacked = append_two(
        &signed,
        &[(1, catalog.as_slice()), (99, dss.as_slice()), (98, payload)],
    );
    let error = pades_verify(&attacked, &anchors())
        .expect_err("a /VRI entry is not a key the validator reads data with");
    assert!(
        error.to_string().contains("98 0 R"),
        "the refusal names the unverified addition: {error}"
    );
}

/// The `/VRI` dictionary is licensed as archive bytes, and archive bytes are
/// still candidates: a covered page that already draws `/Xm1 97 0 R` makes 97 a
/// reference a reader resolves, so a brand-new `/Type /DSS` whose `/VRI` names it
/// is refused exactly as the object the page points at is refused when the
/// catalog calls it an archive (the shape of R3-C1, by this route). Measured
/// before the test existed: "object 97 0 R: a dictionary outside the archive
/// whitelist was rewritten". What makes the assertion load-bearing is that the
/// new rule adds the dictionary to the CANDIDATE set, not to the answer: the
/// fixpoint's pruning still governs it.
#[test]
fn a_vri_dictionary_the_covered_bytes_named_is_not_licensed() {
    let Some(signer) = signer() else {
        require_or_skip("test PKI missing, rerun tools/gen-testcert.sh");
        return;
    };
    let page = b"<< /Type /Page /Parent 2 0 R /MediaBox [ 0 0 595 842 ] \
                 /Resources << /Font << /F1 5 0 R >> /XObject << /Xm1 97 0 R >> >> \
                 /Contents 4 0 R >>";
    let drawing = b"/Xm1 Do";
    let plain = pades_sign(
        &append_two(INPUT, &[(3, page.as_slice()), (4, &stream_body(drawing))]),
        &signer,
        &PadesOptions::default(),
    )
    .expect("signing a page that draws an object the file does not have");
    pades_verify(&plain, &anchors()).expect("an empty /XObject slot is not an attack");

    let text = "BT /F1 24 Tf 72 700 Td (PAGUESE 9999 EUR) Tj ET";
    let form = format!(
        "<< /BBox [ 0 0 300 60 ] /FormType 1 /Length {} /Matrix [ 1 0 0 1 0 0 ] \
         /Resources << /Font << /F1 5 0 R >> >> /Subtype /Form /Type /XObject >>\n\
         stream\n{text}\nendstream",
        text.len()
    );
    let catalog = b"<< /Type /Catalog /Pages 2 0 R /DSS 99 0 R >>";
    let dss = b"<< /Type /DSS /VRI 97 0 R >>";
    let attacked = append_two(
        &plain,
        &[
            (1, catalog.as_slice()),
            (99, dss.as_slice()),
            (97, form.as_bytes()),
        ],
    );
    let error = pades_verify(&attacked, &anchors()).expect_err(
        "the covered bytes named 97, so carrying it as the /VRI dictionary is a change they see",
    );
    assert!(
        error.to_string().contains("97 0 R"),
        "the refusal names the object the page draws: {error}"
    );
}

/// A second pass that draws its own signature writes its own Helvetica and names
/// it in the appearance's `/Resources` — the shape the font rule licenses only
/// because ONE signature covers the font and the object that names it. Every
/// other co-signature the suite makes is invisible, so its appearance carries no
/// font and the pass's own two fonts go unnamed (inert, and licensed for that
/// reason); this is the shape that would break first if the rule were ever
/// tightened to "a font nothing names", which is a false refusal for every writer
/// of visible signatures. Measured: with that tightening, this test is the only
/// one in the suite that fails.
#[test]
fn a_second_pass_may_draw_its_own_signature_with_a_font_it_named() {
    let Some(signer) = signer() else {
        require_or_skip("test PKI missing, rerun tools/gen-testcert.sh");
        return;
    };
    let plain = pades_sign(INPUT, &signer, &PadesOptions::default()).expect("B-B failed");
    let visible = openfirma_pades::appearance::Appearance {
        page: 1,
        rect: [50.0, 700.0, 300.0, 760.0],
        label: None,
    };
    let twice = pades_sign(
        &plain,
        &signer,
        &PadesOptions {
            visible: Some(visible),
            ..PadesOptions::default()
        },
    )
    .expect("co-signing with a visible signature");
    // The pass really did write fonts of its own, and the second one is the
    // shape under test: if this stops holding, the test has stopped reaching the
    // rule and must be revisited rather than left looking green.
    let fonts = |pdf: &[u8]| {
        pdf.windows(b"/BaseFont /Helvetica".len())
            .filter(|window| *window == b"/BaseFont /Helvetica")
            .count()
    };
    assert!(
        fonts(&twice) > fonts(&plain),
        "the visible pass writes and names a Helvetica of its own"
    );
    pades_verify(&twice, &anchors())
        .expect("a pass may name the font it draws its own signature with");
}

/// A writer may store the `/VRI` dictionary as an object of its own — ISO 32000
/// 12.7.4.4 lets any value in the `/DSS` dictionary be an indirect reference,
/// ETSI EN 319 142 writers do exactly that, and `read_dss` resolves it — and the
/// dictionary is archive bytes like the rest. Round 3b measured the cost of not
/// saying so: this file was refused twice over, `96 0 R` (the dictionary) and
/// `98 0 R` (the certificate stream the taxed `/Certs` array had already
/// licensed) because the stream's namer sat outside the licensed set. Licensing
/// the dictionary puts that edge back inside it without licensing what an entry
/// names — the test above keeps that out.
#[test]
fn an_archive_that_stores_its_vri_dictionary_as_an_object_passes_the_gate() {
    let Some(signer) = signer() else {
        require_or_skip("test PKI missing, rerun tools/gen-testcert.sh");
        return;
    };
    let signed = pades_sign(INPUT, &signer, &PadesOptions::default()).expect("signing failed");
    let cert = handle("signer-rsa.crt");
    let stream = stream_body(cert.der());
    // The archive takes the catalog it was handed and adds /DSS to it, exactly
    // as a real archive pass does: the document's form stays where it was (a
    // revision that removes it changes what a reader shows, and is refused —
    // measured in `a_form_the_document_had_cannot_be_swapped_for_another`).
    let handed = last_catalog_body(&signed);
    let inner = handed
        .strip_suffix(">>")
        .expect("the catalog is a dictionary")
        .trim_end();
    let catalog = format!("{inner} /DSS 99 0 R >>");
    let dss = b"<< /Type /DSS /Certs 97 0 R /VRI 96 0 R >>";
    let array = b"[ 98 0 R ]";
    let vri = b"<< /ABCDEF0123456789ABCDEF0123456789ABCDEF01 << /Cert [ 98 0 R ] >> >>";
    let archived = append_two(
        &signed,
        &[
            (1, catalog.as_bytes()),
            (99, dss.as_slice()),
            (97, array.as_slice()),
            (96, vri.as_slice()),
            (98, stream.as_slice()),
        ],
    );
    pades_verify(&archived, &anchors())
        .expect("a writer may store the /VRI dictionary as an object of its own");
}

/// Round 4, C-1: a catalog's `/AcroForm` is not free to move.
///
/// A signing pass may INTRODUCE a form into a document that had none, and it
/// may GROW the form the document had with signature fields; it may not swap the
/// form for another dictionary, however it spells it (inline for a reference,
/// one reference for another). What a viewer draws an existing field's text with
/// comes out of that dictionary: the field's own `/DA` names an entry of the
/// form's `/DR`, and a viewer generates the appearance of a field that has none
/// of its own from exactly that.
///
/// Measured on this document at 200 dpi, with a gate that licensed the swap and
/// therefore verified both variants: the honest form's `/DR` names a serif face
/// and "IMPORTE TOTAL MIL" renders serif (13256 dark pixels under the field);
/// the same signed bytes with the catalog repointed at a covered dictionary
/// whose `/DR` names a sans face render sans (14799), and a `/DR` whose font
/// carries a `/Differences` remap changes the text OCR reads back. No covered
/// byte moved: the glyphs did.
#[test]
fn a_form_the_document_had_cannot_be_swapped_for_another_dictionary() {
    let Some(signer) = signer() else {
        require_or_skip("test PKI missing, rerun tools/gen-testcert.sh");
        return;
    };
    // The document handed to the signer carries a text field whose appearance a
    // viewer generates, the honest face its `/DA` names, a face with a remapping
    // `/Encoding`, and a dictionary shaped like a form whose `/DR` names that
    // one instead.
    let field = b"<< /Type /Annot /Subtype /Widget /FT /Tx /T (concepto) \
                  /V (IMPORTE TOTAL MIL) /DA (/Helv 0 Tf 0 g) \
                  /Rect [ 72 600 400 630 ] /F 4 /P 3 0 R >>";
    let page = b"<< /Type /Page /Parent 2 0 R /MediaBox [ 0 0 595 842 ] \
                 /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R \
                 /Annots [ 13 0 R ] >>";
    let honest = b"<< /Type /Font /Subtype /Type1 /BaseFont /Times-Roman >>";
    let remapped = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica \
                     /Encoding << /Type /Encoding /BaseEncoding /WinAnsiEncoding \
                     /Differences [ 65 /B 66 /C 67 /D 68 /E 69 /F 70 /G 71 /H \
                     72 /I 73 /J 74 /K 75 /L 76 /M 77 /N 78 /O 79 /P 80 /Q ] >> >>";
    let spare = b"<< /NeedAppearances true /DR << /Font << /Helv 10 0 R >> >> >>";
    let catalog = b"<< /Type /Catalog /Pages 2 0 R /AcroForm << /DA (/Helv 0 Tf 0 g) \
                    /DR << /Font << /Helv 12 0 R >> >> /Fields [ 13 0 R ] >> >>";
    let dressed = append_two(
        INPUT,
        &[
            (1, catalog.as_slice()),
            (3, page.as_slice()),
            (10, remapped.as_slice()),
            (11, spare.as_slice()),
            (12, honest.as_slice()),
            (13, field.as_slice()),
        ],
    );
    let signed = pades_sign(&dressed, &signer, &PadesOptions::default()).expect("signing failed");
    pades_verify(&signed, &anchors()).expect("the form the signer was handed is honest");

    let handed = last_catalog_body(&signed);
    let repointed = repointed_acroform(&handed, "11 0 R");
    let attacked = append_two(&signed, &[(1, repointed.as_bytes())]);
    let error = pades_verify(&attacked, &anchors()).expect_err(
        "a covered dictionary is not a licence to swap the font signed field text is drawn with",
    );
    let text = error.to_string();
    assert!(
        text.contains("no archive may append"),
        "the refusal says what was violated: {text}"
    );
    assert!(
        text.contains("1 0 R"),
        "the refusal names the catalog the form was swapped in: {text}"
    );
}

/// The same rule from the other side: an appended revision may not take the
/// document's form away, because a viewer that had a form and now has none draws
/// the fields differently — the ones whose appearance it generated stop being
/// generated — and an archive pass has no business doing that.
#[test]
fn a_revision_that_takes_the_documents_form_away_is_refused() {
    let Some(signer) = signer() else {
        require_or_skip("test PKI missing, rerun tools/gen-testcert.sh");
        return;
    };
    let signed = pades_sign(INPUT, &signer, &PadesOptions::default()).expect("signing failed");
    let handed = last_catalog_body(&signed);
    let stripped = repointed_acroform(&handed, "");
    let attacked = append_two(&signed, &[(1, stripped.as_bytes())]);
    let error = pades_verify(&attacked, &anchors())
        .expect_err("a revision that removes the form changes what a reader shows");
    let text = error.to_string();
    assert!(
        text.contains("1 0 R"),
        "the refusal names the catalog the form was taken from: {text}"
    );
}

/// Round 3, C-1 once more: licensing every brand-new `/Type /DSS` dictionary
/// let one dress as an archive while being something a page renders. A reader
/// resolves references from the LAST revision, so a document that names an
/// object it does not have — `/XObject << /Xm1 100 0 R >>` in the page, used by
/// the content stream's `/Xm1 Do` — shows that object the moment a later
/// revision defines it. One appended revision defining it as a form XObject
/// with a text of its own AND `/Type /DSS` in its dictionary put "PAGUESE 9999
/// EUR" on a page no signature covered, and verify answered OK.
#[test]
fn a_brand_new_object_the_page_points_at_cannot_dress_as_an_archive() {
    let Some(signer) = signer() else {
        require_or_skip("test PKI missing, rerun tools/gen-testcert.sh");
        return;
    };
    // The document handed to the signer already references object 100, which
    // does not exist: the viewer shows nothing there, and the signature covers
    // the reference, so no later revision may repoint it.
    let page = b"<< /Type /Page /Parent 2 0 R /MediaBox [ 0 0 595 842 ] \
                 /Resources << /Font << /F1 5 0 R >> /XObject << /Xm1 100 0 R >> >> \
                 /Contents 4 0 R >>";
    let body = b"BT /F1 12 Tf 72 770 Td (openfirma PAdES test document) Tj ET /Xm1 Do";
    let content = format!(
        "<< /Length {} >>\nstream\n{}\nendstream",
        body.len(),
        std::str::from_utf8(body).expect("ascii")
    );
    let dangling = append_two(INPUT, &[(3, page.as_slice()), (4, content.as_bytes())]);
    let signed = pades_sign(&dangling, &signer, &PadesOptions::default()).expect("signing failed");
    pades_verify(&signed, &anchors()).expect("a dangling reference is harmless on its own");

    let text = b"BT /F1 24 Tf 72 400 Td (PAGUESE 9999 EUR) Tj ET";
    let xobject = format!(
        "<< /Type /DSS /Subtype /Form /BBox [ 0 0 595 842 ] \
         /Resources << /Font << /F1 5 0 R >> >> /Length {} >>\nstream\n{}\nendstream",
        text.len(),
        std::str::from_utf8(text).expect("ascii")
    );
    let attacked = append_two(&signed, &[(100, xobject.as_bytes())]);
    let error = pades_verify(&attacked, &anchors())
        .expect_err("an object the page renders is not an archive, whatever its dictionary claims");
    let t = error.to_string();
    assert!(
        t.contains("no archive may append"),
        "the refusal says what was violated: {t}"
    );
    assert!(
        t.contains("100 0 R"),
        "the refusal names the rendered object: {t}"
    );
}

/// The same door by the page tree, and the one that makes the fixpoint ITERATE:
/// the covered bytes already name a `/Kids` entry that does not exist, the
/// catalog's `/DSS` is re-pointed at the page that fills it (an object a reader
/// RESOLVES, so not validation data), and the content stream that page draws
/// with claims `/Type /DSS` too. Dropping the page is what exposes the stream;
/// a single pass would license the stream and refuse only the page.
#[test]
fn a_dangling_page_tree_kid_filled_with_a_rendered_page_is_refused_whole() {
    let Some(signer) = signer() else {
        require_or_skip("test PKI missing, rerun tools/gen-testcert.sh");
        return;
    };
    // the page tree the signature covers already counts a kid it does not have
    let dangling = append_two(
        INPUT,
        &[(
            2,
            b"<< /Count 2 /Kids [ 3 0 R 100 0 R ] /Type /Pages >>".as_slice(),
        )],
    );
    let signed = pades_sign(&dangling, &signer, &PadesOptions::default()).expect("signing failed");
    pades_verify(&signed, &anchors()).expect("a dangling kid is harmless on its own");

    // the catalog of the signed file, to re-point its /DSS at the new page
    let body = last_catalog_body(&signed);
    let catalog = format!("<< /DSS 100 0 R {}", &body[2..]);

    let page = b"<< /Type /Page /Parent 2 0 R /MediaBox [ 0 0 595 842 ] \
                 /Resources << /Font << /F1 5 0 R >> >> /Contents 101 0 R >>";
    let text = b"BT /F1 24 Tf 72 400 Td (PAGUESE 9999 EUR) Tj ET";
    let content = format!(
        "<< /Type /DSS /Length {} >>\nstream\n{}\nendstream",
        text.len(),
        std::str::from_utf8(text).expect("ascii")
    );
    let attacked = append_two(
        &signed,
        &[
            (1, catalog.as_bytes()),
            (100, page.as_slice()),
            (101, content.as_bytes()),
        ],
    );
    let error = pades_verify(&attacked, &anchors())
        .expect_err("a page the tree resolves is not an archive, whatever the catalog says");
    let t = error.to_string();
    assert!(
        t.contains("no archive may append"),
        "the refusal says what was violated: {t}"
    );
    assert!(
        t.contains("100 0 R"),
        "the refusal names the resolved page: {t}"
    );
    // and the stream that page draws with, exposed only once the page is gone:
    // this is the assertion a single-pass rule fails
    assert!(
        t.contains("101 0 R"),
        "the refusal names the stream the page exposed: {t}"
    );
}

/// A LEGITIMATE archiving pass whose transport is the one
/// `qpdf --object-streams=generate`, iText's compressed save and an Acrobat
/// re-save write: the new dictionary lives inside an object stream, and the
/// revision is indexed by a cross-reference stream. The archive is the one
/// `hand_built_archive` builds — certificate stream 201 (direct: a stream cannot
/// live inside an object stream), the `/DSS` dictionary in the container, the
/// catalog rewritten so a reader resolves it through the newest section.
fn archive_in_object_stream(plain: &[u8], container: u32, dss: u32) -> Vec<u8> {
    /// One cross-reference entry: a direct object at an offset, or the `index`th
    /// object of the object stream `stream`.
    enum Row {
        AtOffset(usize),
        InStream(u32, u32),
    }
    const SECTION: u32 = 300;
    let mut out = plain.to_vec();
    out.push(b'\n');
    let mut direct: Vec<(u32, usize)> = Vec::new();

    let cert = handle("signer-rsa.crt");
    let at = out.len();
    out.extend_from_slice(b"201 0 obj\n");
    out.extend_from_slice(&stream_body(cert.der()));
    out.extend_from_slice(b"\nendobj\n");
    direct.push((201, at));

    let body = last_catalog_body(plain);
    let at = out.len();
    out.extend_from_slice(
        format!("1 0 obj\n<< /DSS {dss} 0 R {}\nendobj\n", &body[2..]).as_bytes(),
    );
    direct.push((1, at));

    let header = format!("{dss} 0 ").into_bytes();
    let mut content = header.clone();
    content.extend_from_slice(b"<< /Type /DSS /Certs [ 201 0 R ] /CRLs [ ] >>");
    let at = out.len();
    out.extend_from_slice(format!("{container} 0 obj\n").as_bytes());
    out.extend_from_slice(
        format!(
            "<< /Type /ObjStm /N 1 /First {} /Length {} >>",
            header.len(),
            content.len()
        )
        .as_bytes(),
    );
    out.extend_from_slice(b"\nstream\n");
    out.extend_from_slice(&content);
    out.extend_from_slice(b"\nendstream\nendobj\n");
    direct.push((container, at));

    let xref_at = out.len();
    direct.push((SECTION, xref_at));
    let mut rows: Vec<(u32, Row)> = direct
        .iter()
        .map(|(number, offset)| (*number, Row::AtOffset(*offset)))
        .collect();
    rows.push((dss, Row::InStream(container, 0)));
    rows.sort_by_key(|(number, _)| *number);

    let mut index = String::new();
    let mut stream = Vec::new();
    for (number, row) in &rows {
        index.push_str(&format!(" {number} 1"));
        match row {
            Row::AtOffset(offset) => {
                stream.push(1u8);
                stream.extend_from_slice(&(*offset as u32).to_be_bytes());
                stream.extend_from_slice(&0u16.to_be_bytes());
            }
            Row::InStream(container, at) => {
                stream.push(2u8);
                stream.extend_from_slice(&container.to_be_bytes());
                stream.extend_from_slice(&(*at as u16).to_be_bytes());
            }
        }
    }
    let size = rows.last().map(|(number, _)| number + 1).unwrap_or(1);
    let dict = format!(
        "<< /Type /XRef /Size {size} /Root 1 0 R /Prev {} /W [1 4 2] \
         /Index [{index} ] /Length {} >>",
        last_xref(plain),
        stream.len()
    );
    out.extend_from_slice(format!("{SECTION} 0 obj\n").as_bytes());
    out.extend_from_slice(dict.as_bytes());
    out.extend_from_slice(b"\nstream\n");
    out.extend_from_slice(&stream);
    out.extend_from_slice(b"\nendstream\nendobj\n");
    out.extend_from_slice(format!("startxref\n{xref_at}\n%%EOF\n").as_bytes());
    out
}

/// The same archive, packed the way an incremental writer that compresses its
/// save writes it. Round 3b measured this refused as "changes no archive may
/// append" over an object stream and a cross-reference stream — the two objects
/// that carry no content at all — while `qpdf --check` saw nothing wrong with
/// the file. Transport is not content: the objects INSIDE an object stream are
/// classified one by one from the resolved final state, and a cross-reference
/// section is the section.
#[test]
fn an_archive_packed_into_an_object_stream_passes_the_gate() {
    let Some(signer) = signer() else {
        require_or_skip("test PKI missing, rerun tools/gen-testcert.sh");
        return;
    };
    let plain = pades_sign(INPUT, &signer, &PadesOptions::default()).expect("B-B failed");
    let archived = archive_in_object_stream(&plain, 110, 100);
    pades_verify(&archived, &anchors())
        .expect("bounding certificates in an object stream is a legitimate save");
}

/// ... and transport is licensed on the fixpoint's premise too: a container is
/// reached through cross-reference entries that carry offsets, never through a
/// reference, so a brand-new container that some covered object DOES name is a
/// dangling slot being filled, not transport. Here the covered page names
/// `/Xm1 97 0 R` under `/XObject` and its content stream draws it; nothing in the
/// signature made 97 an object, and the appended revision makes it the container
/// its `/DSS` rides in.
#[test]
fn a_container_the_covered_bytes_named_is_not_transport() {
    let Some(signer) = signer() else {
        require_or_skip("test PKI missing, rerun tools/gen-testcert.sh");
        return;
    };
    let page = b"<< /Type /Page /Parent 2 0 R /MediaBox [ 0 0 595 842 ] \
                 /Resources << /Font << /F1 5 0 R >> /XObject << /Xm1 97 0 R >> >> \
                 /Contents 4 0 R >>";
    let drawing = b"/Xm1 Do";
    let plain = pades_sign(
        &append_two(INPUT, &[(3, page.as_slice()), (4, &stream_body(drawing))]),
        &signer,
        &PadesOptions::default(),
    )
    .expect("signing a page that draws an object the file does not have");
    pades_verify(&plain, &anchors()).expect("an empty /XObject slot is not an attack");

    let archived = archive_in_object_stream(&plain, 97, 100);
    let error = pades_verify(&archived, &anchors())
        .expect_err("the covered bytes named 97, so filling it is a change they see");
    assert!(
        error.to_string().contains("97 0 R"),
        "the refusal names the container that filled the slot: {error}"
    );
}

/// The catalog body of the LAST revision, which is the one a reader resolves.
fn last_catalog_body(pdf: &[u8]) -> String {
    let marker = b"\n1 0 obj\n";
    let at = pdf
        .windows(marker.len())
        .rposition(|window| window == marker)
        .expect("the file carries a catalog")
        + 1;
    let start = at + b"1 0 obj\n".len();
    let end = start
        + pdf[start..]
            .windows(b"endobj".len())
            .position(|window| window == b"endobj")
            .expect("the catalog ends");
    std::str::from_utf8(&pdf[start..end])
        .expect("the catalog is written as text")
        .trim()
        .to_string()
}

/// The catalog `catalog` with its `/AcroForm` value replaced by `value` — or,
/// with `value` empty, with the key taken out entirely — and the rest of the
/// dictionary untouched.
fn repointed_acroform(catalog: &str, value: &str) -> String {
    let after_key = catalog
        .find("/AcroForm")
        .expect("the catalog carries a form")
        + "/AcroForm".len();
    let (head, tail) = catalog.split_at(after_key);
    let tail = tail.trim_start();
    let bytes = tail.as_bytes();
    let (mut depth, mut at, mut cut) = (0usize, 0usize, None);
    while at < bytes.len() {
        if bytes[at] == b'<' && bytes.get(at + 1) == Some(&b'<') {
            depth += 1;
            at += 2;
            continue;
        }
        if bytes[at] == b'>' && bytes.get(at + 1) == Some(&b'>') {
            depth -= 1;
            at += 2;
            if depth == 0 {
                cut = Some(at);
                break;
            }
            continue;
        }
        at += 1;
    }
    let cut = cut.expect("the form value is a balanced dictionary");
    let rest = tail[cut..].trim_start();
    if value.is_empty() {
        format!("{} {rest}", head.trim_end_matches("/AcroForm").trim_end())
    } else {
        format!("{head} {value} {rest}")
    }
}

/// One `/Length`-sized stream object body.
fn stream_body(blob: &[u8]) -> Vec<u8> {
    let mut out = format!("<< /Length {} >>\nstream\n", blob.len()).into_bytes();
    out.extend_from_slice(blob);
    out.extend_from_slice(b"\nendstream");
    out
}

/// A legitimate archive pass built by hand over a B-B signature: brand-new
/// certificate and CRL streams, named by a brand-new `/DSS` the catalog points
/// at. `indirect` names `/Certs` and `/CRLs` through objects of their own
/// instead of inlining the arrays.
fn hand_built_archive(
    plain: &[u8],
    revocation: &[RevocationBytes],
    indirect: bool,
    trailer_extra: &str,
) -> Vec<u8> {
    let mut objects: Vec<(u32, Vec<u8>)> = Vec::new();
    let mut cert_refs = Vec::new();
    for (i, cert) in [handle("signer-rsa.crt"), handle("intermediate.crt")]
        .iter()
        .enumerate()
    {
        let number = 201 + i as u32;
        objects.push((number, stream_body(cert.der())));
        cert_refs.push(number);
    }
    let mut crl_refs = Vec::new();
    for (i, revocation) in revocation.iter().enumerate() {
        let RevocationBytes::Crl(der) = revocation else {
            continue;
        };
        let number = 211 + i as u32;
        objects.push((number, stream_body(der)));
        crl_refs.push(number);
    }
    let array = |refs: &[u32]| {
        let mut out = String::from("[");
        for number in refs {
            out.push_str(&format!(" {number} 0 R"));
        }
        out.push_str(" ]");
        out
    };
    let dss = if indirect {
        objects.push((101, array(&cert_refs).into_bytes()));
        objects.push((102, array(&crl_refs).into_bytes()));
        b"<< /Type /DSS /Certs 101 0 R /CRLs 102 0 R >>".to_vec()
    } else {
        format!(
            "<< /Type /DSS /Certs {} /CRLs {} >>",
            array(&cert_refs),
            array(&crl_refs)
        )
        .into_bytes()
    };
    objects.push((100, dss));
    let body = last_catalog_body(plain);
    objects.push((1, format!("<< /DSS 100 0 R {}", &body[2..]).into_bytes()));
    let as_refs: Vec<(u32, &[u8])> = objects
        .iter()
        .map(|(number, body)| (*number, body.as_slice()))
        .collect();
    append_two_with(plain, &as_refs, trailer_extra)
}

/// The reference tool regenerates the file identifier on every stamp. iText
/// 2.1.7, which is what AutoFirma 1.9.1 signs with, writes a brand-new `/ID`
/// array in the incremental update it appends for a second signature: measured
/// on a document AutoFirma signed twice through the `tools/golden` driver, both
/// signatures its own, openfirma refused to READ it — "revision 2 changes /ID,
/// which the newest revision already fixed to a different value" — so the
/// reference tool's own document could be neither verified nor co-signed, over
/// a key no verdict in this crate reads. What judges an appended revision is the
/// archive gate, and it still does.
#[test]
fn an_append_that_regenerates_the_file_id_is_still_read() {
    let (Some(signer), Some(revocation)) = (signer(), crls()) else {
        require_or_skip("test PKI missing, rerun tools/gen-testcert.sh");
        return;
    };
    // The document handed to the signer carries an /ID, as nearly every real
    // document does, and those bytes are what the signature covers.
    let identified = append_two_with(
        INPUT,
        &[(6, b"<< /Nota (identidad) >>".as_slice())],
        " /ID [<00112233> <00112233>]",
    );
    let plain = pades_sign(&identified, &signer, &PadesOptions::default()).expect("B-B failed");
    // The archive pass regenerates it, the way iText's own append does.
    let archived = hand_built_archive(&plain, &revocation, false, " /ID [<44556677> <44556677>]");
    pades_verify(&archived, &anchors()).expect(
        "an archive pass that regenerates the file identifier appends what an archive appends",
    );
}

/// A LEGITIMATE archive must not be refused for HOW it names its data. ISO 32000
/// lets a value be indirect almost anywhere, so a writer may build `/Certs` and
/// `/CRLs` as objects of their own. The same archive verified with the arrays
/// inline and failed with them indirect (`pdf: expected an array`), while the
/// gate was already licensing that shape — the reader refusing what the door had
/// accepted.
#[test]
fn an_archive_that_names_its_arrays_indirectly_is_read_too() {
    let (Some(signer), Some(revocation)) = (signer(), crls()) else {
        require_or_skip("test PKI missing, rerun tools/gen-testcert.sh");
        return;
    };
    let plain = pades_sign(INPUT, &signer, &PadesOptions::default()).expect("B-B failed");
    let archived = hand_built_archive(&plain, &revocation, true, "");
    pades_verify(&archived, &anchors())
        .expect("an archive that names its arrays indirectly is the same archive");
}

/// A number run that only LOOKS like a reference is not one, and must not cost a
/// legitimate archive its document. `refs_in` scanned raw bytes, so a body
/// carrying the text "201 0 R" made object 201 look like something a reader
/// resolves, and the certificate stream the archive wrote was dropped as a
/// rewritten object: a real archive, refused over digits in a string.
#[test]
fn a_string_that_looks_like_a_reference_is_not_one() {
    let (Some(signer), Some(revocation)) = (signer(), crls()) else {
        require_or_skip("test PKI missing, rerun tools/gen-testcert.sh");
        return;
    };
    let page = b"<< /Type /Page /Parent 2 0 R /MediaBox [ 0 0 595 842 ] \
                 /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R \
                 /PieceInfo << /Nota (ver el objeto 201 0 R de este documento) >> >>";
    let crafted = append_two(INPUT, &[(3, page.as_slice())]);
    let plain = pades_sign(&crafted, &signer, &PadesOptions::default()).expect("signing failed");
    let archived = hand_built_archive(&plain, &revocation, false, "");
    pades_verify(&archived, &anchors()).expect("a string that reads like a reference is not one");
}

/// And the other direction of the same scanner: a comment is a separator, so a
/// reference SPLIT by one still resolves for a reader — `100 % note` newline
/// `0 R`. It did not for the gate, so an appended object a page resolves through
/// such a reference was licensed, and its text rendered over bytes no signature
/// covered.
#[test]
fn a_reference_split_by_a_comment_is_still_a_reference() {
    let Some(signer) = signer() else {
        require_or_skip("test PKI missing, rerun tools/gen-testcert.sh");
        return;
    };
    let page = b"<< /Type /Page /Parent 2 0 R /MediaBox [ 0 0 595 842 ] \
                 /Resources << /Font << /F1 5 0 R >> /XObject << /Xm1 100 % nota\n0 R >> >> \
                 /Contents 4 0 R >>";
    let body = b"BT /F1 12 Tf 72 770 Td (openfirma PAdES test document) Tj ET /Xm1 Do";
    let content = format!(
        "<< /Length {} >>\nstream\n{}\nendstream",
        body.len(),
        std::str::from_utf8(body).expect("ascii")
    );
    let crafted = append_two(INPUT, &[(3, page.as_slice()), (4, content.as_bytes())]);
    let plain = pades_sign(&crafted, &signer, &PadesOptions::default()).expect("signing failed");
    pades_verify(&plain, &anchors()).expect("a comment-split reference is harmless on its own");

    let text = b"BT /F1 24 Tf 72 400 Td (PAGUESE 9999 EUR) Tj ET";
    let xobject = format!(
        "<< /Type /DSS /Subtype /Form /BBox [ 0 0 595 842 ] \
         /Resources << /Font << /F1 5 0 R >> >> /Length {} >>\nstream\n{}\nendstream",
        text.len(),
        std::str::from_utf8(text).expect("ascii")
    );
    let attacked = append_two(&plain, &[(100, xobject.as_bytes())]);
    let error = pades_verify(&attacked, &anchors())
        .expect_err("a reference a reader resolves is a reference, comment or not");
    let t = error.to_string();
    assert!(
        t.contains("100 0 R"),
        "the refusal names the rendered object: {t}"
    );
}

/// The same scanner, and the marker it truncates on: `stream` inside a string is
/// text, not a payload. A page carrying `/PieceInfo << /Nota (stream` newline
/// `inocente) >>` BEFORE its own `/XObject` entry made the body stop at the
/// string, so the reference the page holds to object 100 was never seen, and an
/// appended form XObject claiming `/Type /DSS` drew over bytes no signature
/// covered.
#[test]
fn a_string_that_mentions_stream_does_not_hide_a_reference() {
    let Some(signer) = signer() else {
        require_or_skip("test PKI missing, rerun tools/gen-testcert.sh");
        return;
    };
    let page = b"<< /Type /Page /Parent 2 0 R /MediaBox [ 0 0 595 842 ] \
                 /PieceInfo << /Nota (stream\ninocente) >> \
                 /Resources << /Font << /F1 5 0 R >> /XObject << /Xm1 100 0 R >> >> \
                 /Contents 4 0 R >>";
    let body = b"BT /F1 12 Tf 72 770 Td (openfirma PAdES test document) Tj ET /Xm1 Do";
    let content = format!(
        "<< /Length {} >>\nstream\n{}\nendstream",
        body.len(),
        std::str::from_utf8(body).expect("ascii")
    );
    let crafted = append_two(INPUT, &[(3, page.as_slice()), (4, content.as_bytes())]);
    let plain = pades_sign(&crafted, &signer, &PadesOptions::default()).expect("signing failed");
    pades_verify(&plain, &anchors()).expect("a string is harmless on its own");

    let text = b"BT /F1 24 Tf 72 400 Td (PAGUESE 9999 EUR) Tj ET";
    let xobject = format!(
        "<< /Type /DSS /Subtype /Form /BBox [ 0 0 595 842 ] \
         /Resources << /Font << /F1 5 0 R >> >> /Length {} >>\nstream\n{}\nendstream",
        text.len(),
        std::str::from_utf8(text).expect("ascii")
    );
    let attacked = append_two(&plain, &[(100, xobject.as_bytes())]);
    let error = pades_verify(&attacked, &anchors())
        .expect_err("a string that spells a payload marker hides nothing");
    assert!(
        error.to_string().contains("100 0 R"),
        "the refusal names the rendered object: {error}"
    );
}

/// The number of the first object whose resolved body, as the LAST revision
/// defines it, contains `needle`.
fn object_with(signed: &[u8], needle: &[u8]) -> u32 {
    let xref_at = pdf::last_startxref(signed).expect("the file has an xref");
    let locations = pdf::object_locations(signed, xref_at).expect("the xref reads");
    let mut cache = pdf::ObjectStreamCache::new();
    let mut found: Vec<u32> = Vec::new();
    for object in locations.keys() {
        if let Ok(body) = pdf::resolve(signed, &locations, Some(&mut cache), *object) {
            if body.windows(needle.len()).any(|window| window == needle) {
                found.push(object.num);
            }
        }
    }
    *found.first().expect("the needle is in the document")
}

/// A form XObject body drawing one line of text, the shape a widget's `/AP`
/// names.
fn appearance_body(text: &[u8]) -> Vec<u8> {
    format!(
        "<< /Type /XObject /Subtype /Form /FormType 1 /BBox [ 0 0 300 200 ] \
         /Resources << /Font << /F1 5 0 R >> >> /Length {} >>\nstream\n{}\nendstream",
        text.len(),
        std::str::from_utf8(text).expect("ascii")
    )
    .into_bytes()
}

/// What a reader draws has to be the bytes a signature covered, and the
/// signature's own widget was the exception that proved it: the plumbing rule
/// licensed any object carrying a real `/V`, so a later revision could give the
/// widget of signature 1 a visible rectangle and an `/AP` of its own. Measured
/// before the fix: `pdftotext` read the attacker's sentence and verify answered
/// OK, because the widget's value was still the real signature. Now the widget
/// is refused (only a rewrite touching nothing but `/V` is plumbing) and so is
/// the appearance nothing attested names.
#[test]
fn a_rewritten_signature_widget_may_not_draw() {
    let Some(signer) = signer() else {
        require_or_skip("test PKI missing, rerun tools/gen-testcert.sh");
        return;
    };
    let plain = pades_sign(INPUT, &signer, &PadesOptions::default()).expect("signing failed");
    let signature = object_with(&plain, b"/Type /Sig");
    let widget = object_with(&plain, b"/Subtype /Widget");
    let body = format!(
        "<< /Type /Annot /Subtype /Widget /FT /Sig /T (Signature1) /P 3 0 R \
         /Rect [ 50 50 350 250 ] /F 132 /V {signature} 0 R /AP << /N 100 0 R >> >>"
    );
    let attacked = append_two(
        &plain,
        &[
            (widget, body.as_bytes()),
            (
                100,
                appearance_body(b"BT /F1 18 Tf 10 100 Td (PAGUESE 9999 EUR) Tj ET").as_slice(),
            ),
        ],
    );
    let error = pades_verify(&attacked, &anchors())
        .expect_err("a widget the covered bytes already carried may not be redrawn");
    let message = error.to_string();
    assert!(
        message.contains(&format!("{widget} 0 R")),
        "the refusal names the redrawn widget: {message}"
    );
    assert!(
        message.contains("100 0 R"),
        "and the appearance nothing attests names: {message}"
    );
}

/// The same door without rewriting anything: the covered page already names a
/// `/Kids`-style annotation the file does not have, and the appended revision
/// fills it with a widget that reuses the signature already in the document —
/// real `/V`, its own rectangle and its own appearance. The value was attested
/// only by the bytes it was made over, and the widget is none of them (round 3:
/// this verified OK while `pdftotext` read the appended text).
#[test]
fn a_new_widget_cannot_reuse_an_earlier_signatures_value() {
    let Some(signer) = signer() else {
        require_or_skip("test PKI missing, rerun tools/gen-testcert.sh");
        return;
    };
    let page = b"<< /Type /Page /Parent 2 0 R /MediaBox [ 0 0 595 842 ] \
                 /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R \
                 /Annots [ 100 0 R ] >>";
    let crafted = append_two(INPUT, &[(3, page.as_slice())]);
    let plain = pades_sign(&crafted, &signer, &PadesOptions::default()).expect("signing failed");
    pades_verify(&plain, &anchors()).expect("a dangling annotation is harmless on its own");

    let signature = object_with(&plain, b"/Type /Sig");
    let body = format!(
        "<< /Type /Annot /Subtype /Widget /FT /Sig /T (SignatureLegal) /P 3 0 R \
         /Rect [ 50 50 350 250 ] /F 132 /V {signature} 0 R /AP << /N 101 0 R >> >>"
    );
    let attacked = append_two(
        &plain,
        &[
            (100, body.as_bytes()),
            (
                101,
                appearance_body(b"BT /F1 18 Tf 10 100 Td (PAGUESE 9999 EUR) Tj ET").as_slice(),
            ),
        ],
    );
    let error = pades_verify(&attacked, &anchors()).expect_err(
        "a widget of its own may not borrow the value of a signature that never covered it",
    );
    let message = error.to_string();
    assert!(
        message.contains("100 0 R"),
        "the refusal names the borrowed-value widget: {message}"
    );
}

/// The appearance a widget names renders, so it belongs to what the signature
/// that owns the widget covered — and a covered widget whose `/AP` named an
/// object that did not exist yet is how a later revision put text of its own on
/// the page.
///
/// The document here is crafted so the widget the page already names points its
/// `/V` at the signature the signer is about to write (the number the signer
/// picks is a function of the input's objects, so a probe signing tells it) and
/// its `/AP` at object 900, which nobody has written. Signing verifies; the one
/// appended form XObject then draws "PAGUESE 9999 EUR" where the widget's
/// rectangle is, and with only the byte-range coverage of `762c321` — whose
/// first range was read as a length, so no object before the signature's
/// `/Contents` ever counted as covered — the appended object was refused for
/// that accident. Reading the ranges for what they are and licensing the
/// appearance only when the attesting signature covers IT leaves the refusal in
/// place for the right reason.
#[test]
fn an_appearance_the_covered_widget_was_still_waiting_for_is_refused() {
    let Some(signer) = signer() else {
        require_or_skip("test PKI missing, rerun tools/gen-testcert.sh");
        return;
    };
    // the same shape twice: only the /V number changes, so the signer numbers
    // its own objects the same way both times
    let crafted = |vref: u32| {
        let page = b"<< /Type /Page /Parent 2 0 R /MediaBox [ 0 0 595 842 ] \
                     /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R \
                     /Annots [ 100 0 R ] >>";
        let widget = format!(
            "<< /Type /Annot /Subtype /Widget /FT /Sig /T (Signature1) /P 3 0 R \
             /Rect [ 50 50 350 250 ] /F 132 /AP << /N 900 0 R >> /V {vref} 0 R >>"
        );
        append_two(INPUT, &[(3, page.as_slice()), (100, widget.as_bytes())])
    };
    let probe = pades_sign(&crafted(9999), &signer, &PadesOptions::default()).expect("signing");
    let signature = object_with(&probe, b"/Type /Sig");
    let plain =
        pades_sign(&crafted(signature), &signer, &PadesOptions::default()).expect("signing");
    pades_verify(&plain, &anchors()).expect("the widget borrows the signature the signer writes");

    let attacked = append_two(
        &plain,
        &[(
            900,
            appearance_body(b"BT /F1 18 Tf 10 100 Td (PAGUESE 9999 EUR) Tj ET").as_slice(),
        )],
    );
    let error = pades_verify(&attacked, &anchors())
        .expect_err("the appearance was written after the bytes the signature covered");
    assert!(
        error.to_string().contains("900 0 R"),
        "the refusal names the appearance the covered widget was waiting for: {error}"
    );
}

/// The third way into the room the fixpoint closed, and the one a shape test
/// left open: a font dictionary. The page a signature covers already names
/// `/F2 97 0 R` in its `/Resources` and its content stream sets that font for a
/// headline; 97 does not exist, so a reader draws nothing there. A later revision
/// defines 97 as a Helvetica whose `/Encoding` carries a `/Differences` array
/// remapping every capital one letter up, and "PAGO UN CERO CERO" renders as
/// "QBHP VO DFSP DFSP". Not one covered byte changed — the glyphs did — and round
/// 3b measured `verify` answering OK over exactly this document, because the
/// plumbing branch licensed any brand-new `/Type /Font` whose `/BaseFont` was
/// Helvetica or ZapfDingbats without asking who pointed at it. A pass writes its
/// font and the object that names it in the same revision, so the signature that
/// covers the font's bytes covers its namer too; a slot the covered bytes left
/// dangling is not a place a pass put a font.
#[test]
fn a_font_slot_the_page_left_dangling_cannot_be_filled_with_a_remapping_font() {
    let Some(signer) = signer() else {
        require_or_skip("test PKI missing, rerun tools/gen-testcert.sh");
        return;
    };
    let page = b"<< /Type /Page /Parent 2 0 R /MediaBox [ 0 0 595 842 ] \
                 /Resources << /Font << /F1 5 0 R /F2 97 0 R >> >> /Contents 4 0 R >>";
    let headline = b"BT /F2 24 Tf 72 640 Td (PAGO UN CERO CERO) Tj ET";
    let plain = pades_sign(
        &append_two(INPUT, &[(3, page.as_slice()), (4, &stream_body(headline))]),
        &signer,
        &PadesOptions::default(),
    )
    .expect("signing a page whose /F2 slot is still empty");
    pades_verify(&plain, &anchors()).expect("an empty /F2 slot is not an attack");

    // every capital one letter up: A -> B, P -> Q, ...
    let differences = (65..90)
        .map(|code| format!("{code} /{}", char::from(code as u8 + 1)))
        .collect::<Vec<_>>()
        .join(" ");
    let font = format!(
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica \
         /Encoding << /Type /Encoding /BaseEncoding /WinAnsiEncoding \
         /Differences [ {differences} ] >> >>"
    );
    let attacked = append_two(&plain, &[(97, font.as_bytes())]);
    let error = pades_verify(&attacked, &anchors())
        .expect_err("the font re-maps the glyphs of text the signature signed");
    assert!(
        error.to_string().contains("97 0 R"),
        "the refusal names the font that filled the slot: {error}"
    );
}

/// Append one revision that (re)defines SEVERAL objects at once. The shadow
/// attack needs the rewrite and the hanging dictionary in a single update so
/// the covering signature sees both as its successors.
fn append_two(pdf: &[u8], objects: &[(u32, &[u8])]) -> Vec<u8> {
    append_two_with(pdf, objects, "")
}

/// The same, with `extra` written inside the appended trailer dictionary — how
/// a writer that regenerates `/ID` (iText does, on every stamp) or adds a
/// vendor key writes its trailer.
fn append_two_with(pdf: &[u8], objects: &[(u32, &[u8])], extra: &str) -> Vec<u8> {
    let mut out = pdf.to_vec();
    out.push(b'\n');
    let mut entries = Vec::new();
    for (num, body) in objects {
        let at = out.len();
        out.extend_from_slice(format!("{num} 0 obj\n").as_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(b"\nendobj\n");
        entries.push((*num, at));
    }
    let xref_at = out.len();
    let max_num = objects.iter().map(|(n, _)| *n).max().unwrap_or(0);
    let size = declared_size(pdf).max(max_num + 1);
    out.extend_from_slice(b"xref\n");
    // one subsection per object number: xref subsections need not be contiguous
    for (num, at) in &entries {
        out.extend_from_slice(format!("{num} 1\n{at:010} 00000 n \n").as_bytes());
    }
    let trailer = format!("/Size {size} /Root 1 0 R {extra} /Prev {}", last_xref(pdf));
    out.extend_from_slice(
        format!("trailer\n<< {trailer} >>\nstartxref\n{xref_at}\n%%EOF\n").as_bytes(),
    );
    out
}

/// Round 4 measured the fill-in of the previous test coming BACK when a second
/// signer co-signs the document: a routine flow, `sign` over an already signed
/// document. The licence was asked globally — "is there SOME signature in the
/// document whose /ByteRange covers this font and every namer of it?" — and a
/// signature made after the fill covers everything written before it, so the
/// font the fill wrote came back licensed by a signature that did not exist
/// when it was written. A signature attests what existed when it was made.
#[test]
fn a_later_signature_does_not_bless_a_font_an_earlier_pass_filled_in() {
    let Some(signer) = signer() else {
        require_or_skip("test PKI missing, rerun tools/gen-testcert.sh");
        return;
    };
    let page = b"<< /Type /Page /Parent 2 0 R /MediaBox [ 0 0 595 842 ] \
                 /Resources << /Font << /F1 5 0 R /F2 97 0 R >> >> /Contents 4 0 R >>";
    let headline = b"BT /F2 24 Tf 72 640 Td (PAGO UN CERO CERO) Tj ET";
    let plain = pades_sign(
        &append_two(INPUT, &[(3, page.as_slice()), (4, &stream_body(headline))]),
        &signer,
        &PadesOptions::default(),
    )
    .expect("signing a page whose /F2 slot is still empty");

    let differences = (65..90)
        .map(|code| format!("{code} /{}", char::from(code as u8 + 1)))
        .collect::<Vec<_>>()
        .join(" ");
    let font = format!(
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica \
         /Encoding << /Type /Encoding /BaseEncoding /WinAnsiEncoding \
         /Differences [ {differences} ] >> >>"
    );
    let filled = append_two(&plain, &[(97, font.as_bytes())]);

    // from here on it is a two-signer document: the fill happened between them
    let cosigned = pades_sign(&filled, &signer, &PadesOptions::default()).expect("co-signing");
    let error = pades_verify(&cosigned, &anchors())
        .expect_err("a signature made after the fill cannot license it");
    assert!(
        error.to_string().contains("97 0 R"),
        "the refusal names the font the earlier pass filled in: {error}"
    );
}

/// The object number the pass that wrote `pdf` gave its own `/Helvetica`: the
/// last one in the file, since every pass appends after the previous one.
fn last_helvetica(pdf: &[u8]) -> u32 {
    let text = String::from_utf8_lossy(pdf);
    let mut found = None;
    for (pos, _) in text.match_indices(" 0 obj") {
        let head = &text[..pos];
        let start = head
            .rfind(|c: char| !c.is_ascii_digit())
            .map_or(0, |p| p + 1);
        let Ok(number) = head[start..].trim_start().parse::<u32>() else {
            continue;
        };
        let end = text[pos..].find("endobj").map_or(text.len(), |e| pos + e);
        if text[pos..end].contains("/BaseFont /Helvetica") {
            found = Some(number);
        }
    }
    found.expect("the writer always writes a /Helvetica")
}

/// Round 4's A-4 one step further out: the name the signed bytes carried is in
/// the FORM, and the pass that fills it is also the pass that rewrites the form —
/// which is exactly what a signature pass does to add its field.
///
/// The text field below has no appearance of its own, so a viewer generates one
/// from its `/DA` and the form's `/DR`: the mechanism C-1 measured. The document
/// binds `/FZ` to a number nobody defines, so at the revision that signs it the
/// name resolves to nothing and the field's value draws with whatever the viewer
/// substitutes. The namer check that closed A-4 reads the FINAL state's namers,
/// and the pass's own body is the one namer a reader sees afterwards: the covered
/// name left the question with the body that carried it. What remains is the
/// state the signature was made over, where that name is there and points at
/// nothing — and a font that appears at its number changes what those covered
/// bytes render.
///
/// The number is the writer's to choose, so the fixture asks it: the same
/// document with the name aimed past the pass is signed and co-signed, and the
/// number its own `/Helvetica` came out with is what the second document's `/DR`
/// binds before it is signed. The writer's face is a plain Helvetica where an
/// attacker's carries a `/Differences` remap; that is the difference between the
/// two documents, not between the two rules.
#[test]
fn a_name_the_signed_bytes_already_carried_is_not_a_place_for_a_font() {
    let Some(signer) = signer() else {
        require_or_skip("test PKI missing, rerun tools/gen-testcert.sh");
        return;
    };
    let build = |fz: u32| {
        let field = b"<< /Type /Annot /Subtype /Widget /FT /Tx /T (concepto) \
                      /V (IMPORTE TOTAL MIL) /DA (/FZ 0 Tf 0 g) \
                      /Rect [ 72 600 400 630 ] /F 4 /P 3 0 R >>";
        let catalog = format!(
            "<< /Type /Catalog /Pages 2 0 R /AcroForm << /DA (/FZ 0 Tf 0 g) \
               /DR << /Font << /FZ {fz} 0 R >> >> /NeedAppearances true \
               /Fields [ 13 0 R ] >> >>"
        );
        let page = b"<< /Type /Page /Parent 2 0 R /MediaBox [ 0 0 595 842 ] \
                     /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R \
                     /Annots [ 13 0 R ] >>";
        append_two(
            INPUT,
            &[
                (1, catalog.as_bytes()),
                (3, page.as_slice()),
                (13, field.as_slice()),
            ],
        )
    };
    let sign_twice = |fz: u32| {
        let once = pades_sign(&build(fz), &signer, &PadesOptions::default())
            .expect("signing a form whose /DR binds a name to nothing");
        pades_sign(&once, &signer, &PadesOptions::default()).expect("co-signing")
    };

    // the control first: the same document, the name aimed past both passes
    let control = sign_twice(999_999);
    pades_verify(&control, &anchors())
        .expect("a name that points nowhere near the pass is not an attack");
    let claimed = last_helvetica(&control);

    // and now the name the co-signing pass itself will answer to
    let error = pades_verify(&sign_twice(claimed), &anchors()).expect_err(
        "a font that appears where the signed bytes had a name changes what they render",
    );
    let text = error.to_string();
    assert!(
        text.contains(&format!("{claimed} 0 R")),
        "the refusal names the font that filled the covered name: {text}"
    );
}

/// A pass that FILLS a signature field the signed bytes left empty is an
/// ordinary signature: it gives the field the value and the appearance the field
/// was waiting for, and nothing that says where that field is or whose it is
/// moves. A form's own box is what a form is for.
///
/// Measured against AutoFirma 1.9.1 first: on a two-field form signed twice with
/// the reference tool, the second pass adds `/V` and `/AP` to the second field
/// and leaves the first exactly where it was — and this gate refused the
/// document, naming that second field (`a form field value was rewritten`).
/// The writer of this crate produces the same shape when a caller names a field
/// the form already offers (`PadesOptions::field_name`), which is what makes
/// this fixture exact rather than a stand-in.
///
/// What stays refused is round 3's shape: a widget whose covered bytes DID carry
/// a value may not gain a rectangle and an appearance of its own.
#[test]
fn a_pass_that_fills_a_field_the_signed_bytes_left_empty_is_an_ordinary_signature() {
    let Some(signer) = signer() else {
        require_or_skip("test PKI missing, rerun tools/gen-testcert.sh");
        return;
    };
    // The form before anyone signs it: two boxes of its own, both in the
    // /AcroForm and both drawn on the page.
    let catalog = b"<< /Type /Catalog /Pages 2 0 R \
                    /AcroForm << /Fields [ 13 0 R 14 0 R ] /SigFlags 3 >> >>";
    let page = b"<< /Type /Page /Parent 2 0 R /MediaBox [ 0 0 595 842 ] \
                 /Annots [ 13 0 R 14 0 R ] >>";
    let field1 = b"<< /Type /Annot /Subtype /Widget /FT /Sig /T (Firma1) \
                   /Rect [ 72 600 400 660 ] /F 132 /P 3 0 R >>";
    let field2 = b"<< /Type /Annot /Subtype /Widget /FT /Sig /T (Firma2) \
                   /Rect [ 72 400 400 460 ] /F 132 /P 3 0 R >>";
    let form = append_two(
        INPUT,
        &[
            (1, catalog.as_slice()),
            (3, page.as_slice()),
            (13, field1.as_slice()),
            (14, field2.as_slice()),
        ],
    );

    let first = PadesOptions {
        field_name: Some("Firma1".into()),
        visible: Some(Appearance {
            page: 1,
            rect: [72.0, 600.0, 400.0, 660.0],
            label: None,
        }),
        ..PadesOptions::default()
    };
    let once = pades_sign(&form, &signer, &first).expect("the first signer fills Firma1");
    pades_verify(&once, &anchors()).expect("one signature in the form's own box verifies");

    let second = PadesOptions {
        field_name: Some("Firma2".into()),
        visible: Some(Appearance {
            page: 1,
            rect: [72.0, 400.0, 400.0, 460.0],
            label: None,
        }),
        ..PadesOptions::default()
    };
    let twice = pades_sign(&once, &signer, &second).expect("the second signer fills Firma2");

    let report = pades_verify(&twice, &anchors())
        .expect("a fill of a field the signed bytes left empty is an ordinary signature");
    assert_eq!(
        report.signatures.len(),
        2,
        "both boxes signed, both verified"
    );

    // The filled field is still the form's, with the value and the appearance
    // added to it; and it is the object the form named, not a new one.
    let at = pdf::last_startxref(&twice).unwrap();
    let locations = pdf::object_locations(&twice, at).unwrap();
    let filled = pdf::resolve(&twice, &locations, None, pdf::ObjRef::new(14, 0)).unwrap();
    let text = String::from_utf8_lossy(&filled);
    assert!(
        text.contains("/T (Firma2)") && text.contains("/Rect [ 72 400 400 460 ]"),
        "the field keeps the form's name and rectangle: {text}"
    );
    assert!(
        pdf::get(&filled, "/V").is_some() && pdf::get(&filled, "/AP").is_some(),
        "and gained the value and the appearance: {text}"
    );
}

/// Append a revision the way a COMPRESSED saver writes one — iText's own save,
/// `qpdf --object-streams=generate`, an Acrobat re-save, and the second
/// signature of the reference tool: the dictionaries go inside a
/// `/Type /ObjStm`, the streams and the cross-reference stream stay direct, and
/// the closing xref is a stream with a type 2 row for each packed object. The
/// packed objects and the direct ones must be contiguous numbers in increasing
/// order, ending at the last direct object's number, so the container and the
/// cross-reference stream take the two numbers after it and `/Index` is a
/// single range.
fn append_packed_pass(pdf: &[u8], packed: &[(u32, Vec<u8>)], direct: &[(u32, Vec<u8>)]) -> Vec<u8> {
    let first = packed.first().expect("a packed object").0;
    let last = direct.last().expect("a direct object").0;
    let container = last + 1;
    let xref_obj = last + 2;
    let size = xref_obj + 1;

    let mut header = String::new();
    let mut payload: Vec<u8> = Vec::new();
    for (num, body) in packed {
        header.push_str(&format!("{num} {} ", payload.len()));
        payload.extend_from_slice(body);
        payload.push(b'\n');
    }
    let first_len = header.len();
    let mut rows: Vec<(u32, u8, u32, u16)> = Vec::new();

    let mut out = pdf.to_vec();
    if !out.ends_with(b"\n") {
        out.push(b'\n');
    }
    let at = out.len();
    out.extend(
        format!(
            "{container} 0 obj\n<< /Type /ObjStm /N {} /First {first_len} /Length {} >>\nstream\n",
            packed.len(),
            header.len() + payload.len()
        )
        .as_bytes(),
    );
    out.extend_from_slice(header.as_bytes());
    out.extend_from_slice(&payload);
    out.extend_from_slice(b"\nendstream\nendobj\n");
    rows.push((container, 1, at as u32, 0));
    for (i, (num, _)) in packed.iter().enumerate() {
        rows.push((*num, 2, container, i as u16));
    }
    for (num, body) in direct {
        let at = out.len();
        out.extend(format!("{num} 0 obj\n").as_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(b"\nendobj\n");
        rows.push((*num, 1, at as u32, 0));
    }
    let xref_at = out.len();
    rows.push((xref_obj, 1, xref_at as u32, 0));
    rows.sort_by_key(|(num, ..)| *num);
    let mut bytes = Vec::new();
    for (_, kind, f2, f3) in &rows {
        bytes.push(*kind);
        bytes.extend(f2.to_be_bytes());
        bytes.extend(f3.to_be_bytes());
    }
    out.extend(
        format!(
            "{xref_obj} 0 obj\n<< /Type /XRef /Size {size} /Index [ {first} {} ] \
             /W [ 1 4 2 ] /Root 1 0 R /Prev {} /Length {} >>\nstream\n",
            rows.len(),
            last_xref(pdf),
            bytes.len()
        )
        .as_bytes(),
    );
    out.extend_from_slice(&bytes);
    out.extend_from_slice(b"\nendstream\nendobj\n");
    out.extend_from_slice(format!("startxref\n{xref_at}\n%%EOF\n").as_bytes());
    out
}

/// The signature dictionary a hand-written pass carries: a well-formed
/// `/Type /Sig` whose `/ByteRange` placeholder [`patch_byte_range`] fills. The
/// gate reads the range and the bytes it covers; a real CMS adds only the
/// cryptographic checks the other tests cover.
fn padded_signature() -> Vec<u8> {
    format!(
        "<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached \
         /ByteRange [ 0 {PAD} {PAD} {PAD} ] /Contents <{}> /M (D:20260101000000Z) >>",
        "a5".repeat(64)
    )
    .into_bytes()
}

/// Point a hand-written pass's `/ByteRange` at the pass itself: everything but
/// the `/Contents` hex, which is what a detached signature covers. Same width as
/// the placeholder, so no offset in the pass moves.
fn patch_byte_range(pass: &mut [u8]) {
    let hex = pass
        .windows(b"/Contents <".len())
        .rposition(|window| window == b"/Contents <")
        .expect("the signature's /Contents")
        + b"/Contents ".len();
    let contents_end = hex + 128 + 1; // 64 bytes of hex, then the closing >
    let patched = format!(
        "[ 0 {hex:010} {contents_end:010} {:010} ]",
        pass.len() - contents_end
    );
    let placeholder = format!("[ 0 {PAD} {PAD} {PAD} ]");
    let at = pass
        .windows(placeholder.len())
        .position(|window| window == placeholder.as_bytes())
        .expect("the /ByteRange placeholder");
    assert_eq!(
        placeholder.len(),
        patched.len(),
        "the patch keeps the layout"
    );
    pass[at..at + patched.len()].copy_from_slice(patched.as_bytes());
}

/// A pass that saves COMPRESSED — its field, its font and therefore its
/// appearance inside a `/Type /ObjStm`, which is how iText writes the second
/// signature of a form, and what the reference tool produced when it filled a
/// two-field form — must be judged on the bytes its CONTAINER holds. Read as
/// "an object with no span of its own", no packed object could ever satisfy the
/// attestation the plumbing rules ask for: measured on that document, the
/// filled field came back as "a form field value was rewritten" and each of the
/// objects beside it as "a dictionary outside the archive whitelist was
/// rewritten", while the same objects written directly are licensed by the
/// tests above.
///
/// The container is the honest reading, the one `revision_of` already takes for
/// the same reason: an object packed into an object stream has no bytes of its
/// own anywhere, the container is where its bytes and the entry that maps them
/// live, and a signature can only attest bytes that existed when it was made —
/// so an object reached through a covered container's cross-reference entries
/// is older than the signature that names it.
///
/// This test calls the gate directly: the plumbing rules are structural, and a
/// real CMS would only add the cryptographic checks the other tests cover. The
/// signature dictionary here is a well-formed `/Type /Sig` whose `/ByteRange`
/// covers the pass, which is exactly what the gate reads.
#[test]
fn a_pass_that_packs_its_plumbing_into_an_object_stream_is_judged_on_the_container() {
    use openfirma_pades::revisions::{Change, classify, redefinitions_after, revisions};

    let Some(signer) = signer() else {
        require_or_skip("test PKI missing, rerun tools/gen-testcert.sh");
        return;
    };
    // Revision 1 is a document this crate's own writer signed, so the judge is
    // a real signature with a real /ByteRange and a real coverage end.
    let signed = pades_sign(INPUT, &signer, &PadesOptions::default()).expect("signing");
    let coverage_end = coverage_end_of(&signed);

    // The pass, numbered 20 upward: the field it fills (20) and the font its
    // appearance draws with (21) are packed; the appearance (22), the signature
    // (23), the container (24) and the cross-reference stream (25) are direct.
    let field = b"<< /Type /Annot /Subtype /Widget /FT /Sig /T (Firma2) \
                  /Rect [ 72 400 400 460 ] /F 132 /P 3 0 R /V 23 0 R \
                  /AP << /N 22 0 R >> >>"
        .to_vec();
    let font = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica \
                 /Encoding /WinAnsiEncoding >>"
        .to_vec();
    let appearance = b"<< /Type /XObject /Subtype /Form /BBox [ 0 0 328 60 ] /Length 4 \
                       /Resources << /Font << /F1 21 0 R >> >> >>\nstream\nq Q\nendstream"
        .to_vec();
    // The /ByteRange numbers are written at a fixed width so the layout survives
    // the patch below: the covered bytes are everything but the /Contents hex.
    let signature = padded_signature();

    let mut pass = append_packed_pass(
        &signed,
        &[(20, field), (21, font)],
        &[(22, appearance), (23, signature)],
    );
    patch_byte_range(&mut pass);

    let revs = revisions(&pass).expect("the packed revision parses");
    let redefined = redefinitions_after(&pass, &revs, coverage_end).expect("redefinitions");
    let verdicts = classify(&pass, &redefined).expect("classify");
    for (object, change) in &verdicts {
        assert!(
            !matches!(change, Change::NotAllowed { .. }),
            "every object of the packed pass is plumbing or transport, {object} came back {change:?}"
        );
    }
    assert!(
        verdicts
            .iter()
            .any(|(object, change)| object.num == 20
                && matches!(change, Change::SignaturePlumbing(_))),
        "the packed field is licensed as plumbing: {:?}",
        verdicts
            .iter()
            .filter(|(object, _)| object.num == 20)
            .collect::<Vec<_>>()
    );
}

/// A visible fill draws through a CHAIN, not through one hop: the widget's
/// `/AP /N` is a form XObject whose own `/Resources /XObject` names what
/// actually paints. Measured against the reference tool — iText 2.1.7 writing
/// the second signature of a two-field form for AutoFirma 1.9.1 builds
/// `/AP /N → 22 0 R → 18/19 0 R` — so licensing only the direct `/AP /N`
/// refused the reference tool's own visible fill, the document AutoFirma signs
/// with itself in `tests/autofirma_cosign.rs`, while the objects that paint the
/// ink went unjudged.
///
/// Every hop the attesting signature's own pass wrote is plumbing, judged by the
/// rule the direct appearance has used since round 3. The safety does not weaken
/// per hop: an object is reached only through `same_pass` (the signature's own
/// bytes cover it), and the rule downstream still asks that the object be brand
/// new in that pass, so a hop that REWROTE a covered object is refused however
/// it was reached.
#[test]
fn a_visible_fill_is_judged_on_every_object_its_appearance_draws() {
    use openfirma_pades::revisions::{Change, classify, redefinitions_after, revisions};

    let Some(signer) = signer() else {
        require_or_skip("test PKI missing, rerun tools/gen-testcert.sh");
        return;
    };
    let signed = pades_sign(INPUT, &signer, &PadesOptions::default()).expect("signing");
    let coverage_end = coverage_end_of(&signed);

    // The pass, numbered 20 upward: the field it fills (20) and the font it
    // draws with (21) are packed; the appearance (22), the signature (23) and
    // the form XObject the appearance draws (24) are direct.
    let field = b"<< /Type /Annot /Subtype /Widget /FT /Sig /T (Firma2) \
                  /Rect [ 72 400 400 460 ] /F 132 /P 3 0 R /V 23 0 R \
                  /AP << /N 22 0 R >> >>"
        .to_vec();
    let font = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica \
                 /Encoding /WinAnsiEncoding >>"
        .to_vec();
    let nested = b"<< /Type /XObject /Subtype /Form /BBox [ 0 0 328 60 ] /Length 4 >>\n\
                   stream\nq Q\nendstream"
        .to_vec();
    let drawn = b"q /Fm0 Do Q";
    let mut appearance = Vec::new();
    appearance.extend_from_slice(
        format!(
            "<< /Type /XObject /Subtype /Form /BBox [ 0 0 328 60 ] /Length {} \
             /Resources << /Font << /F1 21 0 R >> /XObject << /Fm0 24 0 R >> >> >>\nstream\n",
            drawn.len()
        )
        .as_bytes(),
    );
    appearance.extend_from_slice(drawn);
    appearance.extend_from_slice(b"\nendstream");
    let signature = padded_signature();

    let mut pass = append_packed_pass(
        &signed,
        &[(20, field), (21, font)],
        &[(22, appearance), (23, signature), (24, nested)],
    );
    patch_byte_range(&mut pass);

    let revs = revisions(&pass).expect("the pass parses");
    let redefined = redefinitions_after(&pass, &revs, coverage_end).expect("redefinitions");
    let verdicts = classify(&pass, &redefined).expect("classify");
    for (object, change) in &verdicts {
        assert!(
            !matches!(change, Change::NotAllowed { .. }),
            "every object of the drawn fill is plumbing, {object} came back {change:?}"
        );
    }
    for number in [22, 24] {
        assert!(
            verdicts.iter().any(|(object, change)| object.num == number
                && matches!(change, Change::SignaturePlumbing(_))),
            "the object {number} the appearance draws is licensed as plumbing: {:?}",
            verdicts
                .iter()
                .filter(|(object, _)| object.num == number)
                .collect::<Vec<_>>()
        );
    }
}

/// The chain is closed through `same_pass` at every hop, and this is what that
/// buys: a widget whose appearance names a number that does not exist yet, and a
/// later pass that defines it, is the round-3 shape (a dangling reference filled
/// after the fact) reached one hop deeper. The later object is brand new in the
/// FINAL state and parses as a form XObject — everything the appearance rule
/// asks for — but the signature that owns the widget never covered its bytes, so
/// it is refused.
#[test]
fn a_hop_of_an_appearance_chain_written_by_a_later_pass_is_not_plumbing() {
    use openfirma_pades::revisions::{Change, classify, redefinitions_after, revisions};

    let Some(signer) = signer() else {
        require_or_skip("test PKI missing, rerun tools/gen-testcert.sh");
        return;
    };
    let signed = pades_sign(INPUT, &signer, &PadesOptions::default()).expect("signing");
    let coverage_end = coverage_end_of(&signed);

    // Object 30 is past the /Size this pass declares: nothing defines it until
    // the NEXT revision does, which is what makes it the attack and not a fill.
    let field = b"<< /Type /Annot /Subtype /Widget /FT /Sig /T (Firma2) \
                  /Rect [ 72 400 400 460 ] /F 132 /P 3 0 R /V 23 0 R \
                  /AP << /N 22 0 R >> >>"
        .to_vec();
    let font = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica \
                 /Encoding /WinAnsiEncoding >>"
        .to_vec();
    let appearance = b"<< /Type /XObject /Subtype /Form /BBox [ 0 0 328 60 ] /Length 4 \
                       /Resources << /XObject << /Fm0 30 0 R >> >> >>\nstream\nq Q\nendstream"
        .to_vec();
    let signature = padded_signature();

    let mut pass = append_packed_pass(
        &signed,
        &[(20, field), (21, font)],
        &[(22, appearance), (23, signature)],
    );
    patch_byte_range(&mut pass);

    let nested = b"<< /Type /XObject /Subtype /Form /BBox [ 0 0 328 60 ] /Length 11 >>\n\
                   stream\n(PAGO UNO)\nendstream"
        .to_vec();
    let document = append_written(&pass, 30, &nested);

    let revs = revisions(&document).expect("both passes parse");
    let redefined = redefinitions_after(&document, &revs, coverage_end).expect("redefinitions");
    let verdicts = classify(&document, &redefined).expect("classify");
    assert!(
        verdicts.iter().any(|(object, change)| object.num == 30
            && matches!(change, Change::NotAllowed { .. })),
        "a chain hop no signature covered is refused: {:?}",
        verdicts
            .iter()
            .filter(|(object, _)| object.num == 30)
            .collect::<Vec<_>>()
    );
}

/// A writer may re-stamp its own mark into a dictionary it leaves otherwise
/// alone: iText records the version that last wrote a document as a `/ITXT`
/// entry, and it re-serializes the dictionary around entries it did not change.
/// Measured with AutoFirma 1.9.1 co-signing a document THIS crate signed: the
/// covered `/Pages` node came back as
/// `<</Type/Pages/Kids[3 0 R]/Count 1/ITXT(2.1.7)>>` — every entry byte for byte
/// what it was, plus the marker. `/ITXT` is not a key of ISO 32000 and nothing
/// about the document renders differently because of it.
#[test]
fn a_writer_may_restamp_its_own_marker_into_a_dictionary_it_left_alone() {
    use openfirma_pades::revisions::{Change, classify, redefinitions_after, revisions};

    let Some(signer) = signer() else {
        require_or_skip("test PKI missing, rerun tools/gen-testcert.sh");
        return;
    };
    let signed = pades_sign(INPUT, &signer, &PadesOptions::default()).expect("signing");
    let coverage_end = coverage_end_of(&signed);

    // Object 2 of the input is the page tree node.
    let restamped = b"<</Type/Pages/Kids[3 0 R]/Count 1/ITXT(2.1.7)>>".to_vec();
    let document = append_written(&signed, 2, &restamped);

    let revs = revisions(&document).expect("the pass parses");
    let redefined = redefinitions_after(&document, &revs, coverage_end).expect("redefinitions");
    let verdicts = classify(&document, &redefined).expect("classify");
    assert!(
        verdicts
            .iter()
            .any(|(object, change)| object.num == 2 && matches!(change, Change::Bookkeeping(_))),
        "the page tree's own re-stamp is bookkeeping: {:?}",
        verdicts
            .iter()
            .filter(|(object, _)| object.num == 2)
            .collect::<Vec<_>>()
    );
    for (object, change) in &verdicts {
        assert!(
            !matches!(change, Change::NotAllowed { .. }),
            "{object} came back {change:?}"
        );
    }
}

/// The marker rule is narrow, and this is what "narrow" has to mean: whatever
/// else moves, the verdict moves with it. A `/Count` that no longer matches its
/// `/Kids`, a reordered dictionary, a value respelled — and a STREAM whose
/// dictionary merely gained the mark, because what a reader takes from a stream
/// is its dictionary AND the data it declares.
#[test]
fn a_restamped_dictionary_may_not_change_anything_else() {
    use openfirma_pades::revisions::{Change, classify, redefinitions_after, revisions};

    let Some(signer) = signer() else {
        require_or_skip("test PKI missing, rerun tools/gen-testcert.sh");
        return;
    };
    let signed = pades_sign(INPUT, &signer, &PadesOptions::default()).expect("signing");
    let coverage_end = coverage_end_of(&signed);

    let refused = |what: &str, number: u32, body: &[u8]| {
        let document = append_written(&signed, number, body);
        let revs = revisions(&document).expect("the pass parses");
        let redefined = redefinitions_after(&document, &revs, coverage_end).expect("redefinitions");
        let verdicts = classify(&document, &redefined).expect("classify");
        assert!(
            verdicts.iter().any(|(object, change)| object.num == number
                && matches!(change, Change::NotAllowed { .. })),
            "{what} is refused: {:?}",
            verdicts
                .iter()
                .filter(|(object, _)| object.num == number)
                .collect::<Vec<_>>()
        );
    };

    // Object 2 is the page tree node, object 5 the page content stream.
    refused(
        "a /Count that disagrees with /Kids",
        2,
        b"<</Type/Pages/Kids[3 0 R]/Count 2/ITXT(2.1.7)>>",
    );
    refused(
        "a reordered dictionary",
        2,
        b"<</Count 1/Kids[3 0 R]/Type/Pages/ITXT(2.1.7)>>",
    );
    refused(
        "a value respelled around its reference",
        2,
        b"<</Type/Pages/Kids[ 3 0 R ]/Count 1/ITXT(2.1.7)>>",
    );
    let payload = b"BT /F1 12 Tf 72 770 Td (the attacker's page) Tj ET\n";
    let mut stream =
        format!("<< /Length {} /ITXT (2.1.7) >>\nstream\n", payload.len()).into_bytes();
    stream.extend_from_slice(payload);
    stream.extend_from_slice(b"endstream");
    refused("a stream whose payload was replaced", 5, &stream);
}

/// The declared residual around a fill: a signature that takes up a field the
/// covered bytes left EMPTY may repaint that field. Its pre-drawn appearance is
/// the document author's, it is bytes the earlier signature attested, and
/// filling the field replaces it — which is what a form field IS: its `/AP` is
/// the presentation of its value. Measured: AutoFirma 1.9.1 does exactly this
/// when it signs a field of a pre-drawn form, and so does this crate's own
/// writer when a caller names a field the form already offers.
///
/// Not narrowed further, on purpose: requiring the covered field to carry no
/// `/AP` at all would refuse the reference tool's own flow (round 6, R6-A1).
/// Licensing the chain the FILLING pass writes is a different question, and it
/// is answered by `appearance_chain`.
#[test]
fn a_fill_may_repaint_the_pre_drawn_appearance_of_an_empty_signature_field() {
    use openfirma_pades::revisions::{Change, classify, redefinitions_after, revisions};

    let Some(signer) = signer() else {
        require_or_skip("test PKI missing, rerun tools/gen-testcert.sh");
        return;
    };

    // A form the covered bytes carry: one empty signature field (8) whose
    // pre-drawn appearance (9) is the author's ink.
    let field = b"<< /Type /Annot /Subtype /Widget /FT /Sig /T (Firma2) \
                   /Rect [ 72 400 400 460 ] /F 132 /P 3 0 R /AP << /N 9 0 R >> >>"
        .to_vec();
    let ink = b"<< /Type /XObject /Subtype /Form /BBox [ 0 0 328 60 ] /Length 30 >>\n\
                stream\nBT (PAGO UN CERO UNO) Tj ET\nendstream"
        .to_vec();
    let with_form = append_written(INPUT, 8, &field);
    let with_form = append_written(&with_form, 9, &ink);

    let signed = pades_sign(&with_form, &signer, &PadesOptions::default()).expect("signing");
    let coverage_end = coverage_end_of(&signed);

    // A later pass fills the field: /V and a fresh /AP, everything else the
    // bytes the signature covered. Its own objects go above every number the
    // document already declares.
    let ink_number = declared_size(&signed);
    let signature_number = ink_number + 1;
    let filled = format!(
        "<< /Type /Annot /Subtype /Widget /FT /Sig /T (Firma2) \
         /Rect [ 72 400 400 460 ] /F 132 /P 3 0 R /V {signature_number} 0 R \
         /AP << /N {ink_number} 0 R >> >>"
    )
    .into_bytes();
    let drawn = b"<< /Type /XObject /Subtype /Form /BBox [ 0 0 328 60 ] /Length 3 >>\n\
                  stream\nq Q\nendstream"
        .to_vec();
    let signature = padded_signature();

    let mut pass = append_pieces(
        &signed,
        &[
            (8, filled),
            (ink_number, drawn),
            (signature_number, signature),
        ],
    );
    patch_byte_range(&mut pass);

    let revs = revisions(&pass).expect("the pass parses");
    let redefined = redefinitions_after(&pass, &revs, coverage_end).expect("redefinitions");
    let verdicts = classify(&pass, &redefined).expect("classify");
    for (object, change) in &verdicts {
        assert!(
            !matches!(change, Change::NotAllowed { .. }),
            "the fill of an empty field is plumbing, {object} came back {change:?}"
        );
    }
    assert!(
        verdicts
            .iter()
            .any(|(object, change)| object.num == 8
                && matches!(change, Change::SignaturePlumbing(_))),
        "the field is the plumbing of the signature that filled it: {:?}",
        verdicts
            .iter()
            .filter(|(object, _)| object.num == 8)
            .collect::<Vec<_>>()
    );
}

/// The end of the first signature's `/ByteRange`: where the bytes it attests
/// stop, and therefore the state a later revision's changes are judged against.
fn coverage_end_of(signed: &[u8]) -> usize {
    let sigs = openfirma_pades::inspect::signatures(signed).expect("signatures");
    let range = sigs[0].byte_range;
    range[2] + range[3]
}

/// Append one revision whose classic cross-reference table marks object `num`
/// FREE, appending no object at all: the way an incremental update deletes an
/// object (ISO 32000-1 7.5.4). Every reader resolves `num 0 R` to nothing after
/// it, so whatever the object rendered is gone from the document.
fn append_free(pdf: &[u8], num: u32) -> Vec<u8> {
    let mut out = pdf.to_vec();
    if !out.ends_with(b"\n") {
        out.push(b'\n');
    }
    let xref_at = out.len();
    let size = declared_size(pdf).max(num + 1);
    out.extend_from_slice(format!("xref\n{num} 1\n0000000000 00000 f \n").as_bytes());
    out.extend_from_slice(
        format!(
            "trailer\n<< /Size {size} /Root 1 0 R /Prev {} >>\nstartxref\n{xref_at}\n%%EOF\n",
            last_xref(pdf)
        )
        .as_bytes(),
    );
    out
}

/// Append one revision redefining object `num` under a generation number of its
/// own: readers resolve the newest entry for a number, see a generation the
/// reference they hold does not match, and treat `num 0 R` as null. The other
/// spelling of the same deletion.
fn append_written_generation(pdf: &[u8], num: u32, generation: u16, body: &[u8]) -> Vec<u8> {
    let mut out = pdf.to_vec();
    if !out.ends_with(b"\n") {
        out.push(b'\n');
    }
    let object_at = out.len();
    out.extend_from_slice(format!("{num} {generation} obj\n").as_bytes());
    out.extend_from_slice(body);
    out.extend_from_slice(b"\nendobj\n");
    let xref_at = out.len();
    let size = declared_size(pdf).max(num + 1);
    out.extend_from_slice(
        format!("xref\n{num} 1\n{object_at:010} {generation:05} n \n").as_bytes(),
    );
    out.extend_from_slice(
        format!(
            "trailer\n<< /Size {size} /Root 1 0 R /Prev {} >>\nstartxref\n{xref_at}\n%%EOF\n",
            last_xref(pdf)
        )
        .as_bytes(),
    );
    out
}

/// Round 2, N-1: object 5 is the page's content stream — the bytes the
/// signature covers. A later revision that only marks the number free rewrites
/// no byte at all, so every digest and every signature still verifies, and the
/// gate used to answer OK. qpdf and Ghostscript render the file with the page
/// empty: the object is not there for any conforming reader.
#[test]
fn a_revision_that_frees_a_signed_object_is_refused() {
    let (Some(signer), Some(revocation)) = (signer(), crls()) else {
        require_or_skip("test PKI or CRLs missing, rerun tools/gen-testcert.sh");
        return;
    };
    let signed = pades_sign(
        INPUT,
        &signer,
        &PadesOptions {
            revocation,
            ..PadesOptions::default()
        },
    )
    .expect("signing failed");
    pades_verify(&signed, &anchors()).expect("the clean archive verifies");

    let deleted = append_free(&signed, 5);
    // the reader's own view first: the object is gone
    let at = pdf::last_startxref(&deleted).expect("the appended revision has an xref");
    let locations = pdf::object_locations(&deleted, at).expect("the xref reads");
    assert!(
        !locations.keys().any(|r| r.num == 5),
        "after a free entry, 5 0 R resolves to nothing for a reader"
    );

    let error = pades_verify(&deleted, &anchors()).expect_err(
        "a revision that deletes a covered object is not something a signature attests",
    );
    let text = error.to_string();
    assert!(
        text.contains("deleted"),
        "the refusal says what happened: {text}"
    );
    assert!(
        text.contains("5 0 R"),
        "the refusal names the deleted object: {text}"
    );
}

/// The same deletion spelled with a generation number instead of a free entry:
/// the page still holds `5 0 R`, and the newest definitions of object 5 belong
/// to generation 1, which that reference does not resolve to.
#[test]
fn a_signed_object_reused_under_another_generation_is_refused() {
    let (Some(signer), Some(revocation)) = (signer(), crls()) else {
        require_or_skip("test PKI or CRLs missing, rerun tools/gen-testcert.sh");
        return;
    };
    let signed = pades_sign(
        INPUT,
        &signer,
        &PadesOptions {
            revocation,
            ..PadesOptions::default()
        },
    )
    .expect("signing failed");
    pades_verify(&signed, &anchors()).expect("the clean archive verifies");

    let body = b"<< /Length 0 >>\nstream\n\nendstream";
    let reused = append_written_generation(&signed, 5, 1, body);
    let at = pdf::last_startxref(&reused).expect("the appended revision has an xref");
    let locations = pdf::object_locations(&reused, at).expect("the xref reads");
    assert!(
        !locations
            .get(&pdf::ObjRef::new(5, 0))
            .is_some_and(|_| locations.contains_key(&pdf::ObjRef::new(5, 0))),
        "5 0 R must not resolve once object 5 lives at generation 1"
    );
    assert!(
        locations.contains_key(&pdf::ObjRef::new(5, 1)),
        "the new generation is the one readers see"
    );

    let error = pades_verify(&reused, &anchors())
        .expect_err("reusing a signed object's number is a deletion of it, not a new object");
    let text = error.to_string();
    assert!(
        text.contains("5 0 R"),
        "the refusal names the object the reference no longer reaches: {text}"
    );
}

/// The one shape where a stream and a table describe the same section: a
/// hybrid-reference file marks the objects it puts in `/XRefStm` free in the
/// classic table, so that readers which know nothing of cross-reference streams
/// ignore them (ISO 32000-1 7.5.8.4). The stream wins, so this document is
/// unchanged and the gate may not read a deletion into it.
#[test]
fn a_hybrid_reference_revision_is_read_from_its_stream() {
    let (Some(signer), Some(revocation)) = (signer(), crls()) else {
        require_or_skip("test PKI or CRLs missing, rerun tools/gen-testcert.sh");
        return;
    };
    let signed = pades_sign(
        INPUT,
        &signer,
        &PadesOptions {
            revocation,
            ..PadesOptions::default()
        },
    )
    .expect("signing failed");
    pades_verify(&signed, &anchors()).expect("the clean archive verifies");

    // object 5, unchanged, in a cross-reference stream of our own (/W [1 2 1]:
    // type, offset, generation) that the classic table then marks free
    let offset = object_at(&signed, 5) as u32;
    let row = [1u8, (offset >> 8) as u8, offset as u8, 0u8];
    let mut out = signed.clone();
    if !out.ends_with(b"\n") {
        out.push(b'\n');
    }
    let stream_at = out.len();
    let size = declared_size(&signed) + 1;
    out.extend_from_slice(
        format!(
            "{size} 0 obj\n<< /Type /XRef /Size {} /W [1 2 1] /Index [5 1] /Root 1 0 R \
             /Length {} >>\nstream\n",
            size + 1,
            row.len()
        )
        .as_bytes(),
    );
    out.extend_from_slice(&row);
    out.extend_from_slice(b"\nendstream\nendobj\n");
    let xref_at = out.len();
    out.extend_from_slice(b"xref\n5 1\n0000000000 00000 f \n");
    out.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R /XRefStm {stream_at} /Prev {} >>\nstartxref\n\
             {xref_at}\n%%EOF\n",
            size + 1,
            last_xref(&signed)
        )
        .as_bytes(),
    );

    // the stream's entry is the one that counts
    let at = pdf::last_startxref(&out).expect("the hybrid revision has an xref");
    let locations = pdf::object_locations(&out, at).expect("the xref reads");
    assert!(
        locations.contains_key(&pdf::ObjRef::new(5, 0)),
        "the /XRefStm entry wins over the free entry the classic table carries for old readers"
    );
    pades_verify(&out, &anchors()).expect("an unchanged hybrid revision is not a modification");
}
