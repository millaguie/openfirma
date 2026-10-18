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
use openfirma_pades::{PadesOptions, pades_sign, pades_verify, pdf};

const INPUT: &[u8] = include_bytes!("../../../testdata/inputs/simple.pdf");

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
fn append_copy(pdf: &[u8], num: u32, source_at: usize) -> Vec<u8> {
    let body = pdf::object_body(pdf, source_at).expect("the source offset holds an object");
    let mut out = pdf.to_vec();
    out.push(b'\n');
    let object_at = out.len();
    out.extend_from_slice(format!("{num} 0 obj\n").as_bytes());
    out.extend_from_slice(&pdf[body]);
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

/// Append one revision that (re)defines SEVERAL objects at once. The shadow
/// attack needs the rewrite and the hanging dictionary in a single update so
/// the covering signature sees both as its successors.
fn append_two(pdf: &[u8], objects: &[(u32, &[u8])]) -> Vec<u8> {
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
    out.extend_from_slice(
        format!(
            "trailer\n<< /Size {size} /Root 1 0 R /Prev {} >>\nstartxref\n{xref_at}\n%%EOF\n",
            last_xref(pdf)
        )
        .as_bytes(),
    );
    out
}
