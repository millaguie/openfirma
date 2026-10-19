//! AutoFirma as the other signer of the same form, in both directions: the
//! reference tool signs `Firma1` and then `Firma2` over its own output — two
//! incremental updates, the second of which builds the appearance chain for
//! the field it fills — and, the other way round, AutoFirma co-signs a document
//! THIS crate signed.
//!
//! Measured with AutoFirma 1.9.1: before the appearance chain was closed, the
//! tool's own second signature was refused, naming objects 18, 19 and 21 —
//! every object iText wrote for the filled field's appearance: the `/AP /N`
//! form XObject, and the XObjects that form draws through its own
//! `/Resources`. Both directions verify now.
//!
//! The jar is not a CI dependency (tools/fetch-autofirma.sh fetches it, and CI
//! does not run the golden diff either), so a missing jar or JDK skips with a
//! message, exactly like the qpdf tests; a jar that is present but whose driver
//! will not compile or run is a hard failure. Nothing here is committed: the form
//! input is produced by `tools/gen-testpdf.py --two-fields`, the other two inputs
//! are `testdata/inputs/simple.pdf` and the XMP-and-`/Info` document of
//! `common::xmp_document`, and every signed document goes to a temporary directory.

use std::path::{Path, PathBuf};
use std::process::Command;

use openfirma_cades::verify::VerifyOptions;
use openfirma_core::cert::CertificateHandle;
use openfirma_core::signer::SoftwareSigner;
use openfirma_pades::{PadesOptions, pades_sign, pades_verify};

mod common;

use common::xmp_document;

const TWO_FIELDS: &[u8] = include_bytes!("../../../testdata/inputs/twofields.pdf");
const SIMPLE: &[u8] = include_bytes!("../../../testdata/inputs/simple.pdf");

fn certs_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/certs")
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn handle(name: &str) -> CertificateHandle {
    let pem = std::fs::read_to_string(certs_dir().join(name))
        .unwrap_or_else(|e| panic!("{name} is part of the test PKI but cannot be read: {e}"));
    CertificateHandle::from_pem(&pem).unwrap_or_else(|e| panic!("{name} cannot be parsed: {e}"))
}

/// The trust anchors for the test PKI: the intermediate and the root, the same
/// pair the other PAdES tests verify against.
fn anchors() -> VerifyOptions {
    VerifyOptions::new(vec![handle("intermediate.crt"), handle("ca.crt")])
}

/// CI sets OPENFIRMA_REQUIRE_TESTS so a missing test PKI fails the build instead
/// of quietly skipping. A missing jar or JDK is not that: the jar is fetched by
/// tools/fetch-autofirma.sh and is not a CI dependency, so it skips explicitly.
fn require_or_skip(reason: &str) {
    if std::env::var("OPENFIRMA_REQUIRE_TESTS").is_ok() {
        panic!("cannot run the test: {reason}");
    }
    eprintln!("skipped, {reason}");
}

fn tool(name: &str) -> bool {
    Command::new(name)
        .arg("-version")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// The jar, from $AUTOFIRMA_JAR or the tools/fetch-autofirma.sh location.
fn jar() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("AUTOFIRMA_JAR") {
        let p = PathBuf::from(path);
        if p.is_file() {
            return Some(p);
        }
    }
    let dir = std::env::var("AUTOFIRMA_DIR").unwrap_or_else(|_| "/tmp/autofirma-ref".into());
    let p = PathBuf::from(dir).join("autofirma.jar");
    p.is_file().then_some(p)
}

/// Compiles the golden driver next to the test binaries and returns the
/// classpath root. A driver that does not compile against the jar is a hard
/// failure: the material is there and unusable.
fn driver_dir(jar: &Path) -> PathBuf {
    let dir = repo_root().join("target/golden-driver-test");
    std::fs::create_dir_all(&dir).unwrap();
    let source = repo_root().join("tools/golden/AutofirmaGolden.java");
    let class = dir.join("AutofirmaGolden.class");
    let needs_compile = match (
        class.metadata().and_then(|m| m.modified()),
        source.metadata().and_then(|m| m.modified()),
    ) {
        (Ok(class_time), Ok(source_time)) => class_time < source_time,
        _ => true,
    };
    if needs_compile {
        let out = Command::new("javac")
            .args(["-nowarn", "-cp"])
            .arg(jar)
            .args(["-d"])
            .arg(&dir)
            .arg(&source)
            .output()
            .expect("javac disappeared mid test");
        assert!(
            out.status.success(),
            "the golden driver does not compile against the jar:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    dir
}

/// Have AutoFirma sign `input` into `output`. `field` names the form field to fill;
/// `None` leaves the choice to the tool, which is what its GUI does with a document
/// that has no fields — and what the two tests at the bottom of this file measured.
fn autofirma_sign(
    jar: &Path,
    driver: &Path,
    p12: &Path,
    input: &Path,
    output: &Path,
    field: Option<&str>,
) {
    let classpath = format!("{}:{}", jar.display(), driver.display());
    let mut cmd = Command::new("java");
    cmd.args([
        "-Djava.awt.headless=true",
        "-cp",
        &classpath,
        "AutofirmaGolden",
    ])
    .arg(p12)
    .arg("openfirma")
    .arg(input)
    .arg(output)
    .arg("SHA256withRSA");
    if let Some(field) = field {
        cmd.arg(format!("signatureField={field}"));
    }
    let out = cmd.output().expect("java disappeared mid test");
    assert!(
        out.status.success(),
        "the reference tool did not sign {}{}:\n{}{}",
        input.display(),
        match field {
            Some(name) => format!(" field {name}"),
            None => String::new(),
        },
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A directory of its own per test, so two tests never race over a file name,
/// plus the two-field input in it.
fn workspace(name: &str) -> (PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!("openfirma-pades-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let input = dir.join("twofields.pdf");
    std::fs::write(&input, TWO_FIELDS).unwrap();
    (dir, input)
}

/// The same, holding instead the document from `common::xmp_document` — an XMP
/// `/Metadata` packet and an `/Info` dictionary, which is what a producer like
/// Ghostscript hands a signing tool and therefore what every second signature meets.
fn xmp_workspace(name: &str) -> (PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!("openfirma-pades-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let input = dir.join("producer-output.pdf");
    std::fs::write(&input, xmp_document()).unwrap();
    (dir, input)
}

/// Everything driving the reference tool needs: the jar, the golden driver compiled
/// beside it, and the PKCS#12 these tests sign with. `None` when a piece is not on
/// this machine — a missing JDK or jar skips, since neither is a CI dependency, while
/// a missing test PKI fails hard under `OPENFIRMA_REQUIRE_TESTS`.
fn reference_tool() -> Option<(PathBuf, PathBuf, PathBuf)> {
    if !tool("java") || !tool("javac") {
        eprintln!("skipped, no JDK on this machine");
        return None;
    }
    let Some(jar) = jar() else {
        eprintln!("skipped, no autofirma.jar ($AUTOFIRMA_JAR or tools/fetch-autofirma.sh)");
        return None;
    };
    let p12 = certs_dir().join("signer-rsa.p12");
    if !p12.is_file() {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return None;
    }
    let driver = driver_dir(&jar);
    Some((jar, driver, p12))
}

fn load_signer() -> Option<SoftwareSigner> {
    let dir = certs_dir();
    let (Ok(cert), Ok(key)) = (
        std::fs::read_to_string(dir.join("signer-rsa.crt")),
        std::fs::read_to_string(dir.join("signer-rsa.key")),
    ) else {
        return None;
    };
    let signer = SoftwareSigner::from_pkcs8_pem(&cert, &key)
        .unwrap_or_else(|e| panic!("signer-rsa is present but unusable: {e}"));
    Some(signer.with_chain(vec![handle("intermediate.crt"), handle("ca.crt")]))
}

/// The reference tool's second signature over its own first, on a two-field
/// form. Its second pass fills a field the first left empty and writes the
/// appearance chain that draws the result; the gate has to read every object of
/// that chain as what the signature wrote, or it refuses the reference tool's
/// own document (it did: objects 18, 19 and 21).
#[test]
fn autofirma_signs_both_fields_and_its_own_second_signature_verifies() {
    let Some((jar, driver, p12)) = reference_tool() else {
        return;
    };

    let (dir, input) = workspace("cosign-both");
    let first = dir.join("firma1.pdf");
    let second = dir.join("firma1-firma2.pdf");
    autofirma_sign(&jar, &driver, &p12, &input, &first, Some("Firma1"));
    autofirma_sign(&jar, &driver, &p12, &first, &second, Some("Firma2"));

    let signed = std::fs::read(&second).expect("the reference tool's output is there");
    let report = pades_verify(&signed, &anchors())
        .expect("the reference tool's own two-field form verifies");
    assert_eq!(
        report.signatures.len(),
        2,
        "both of AutoFirma's signatures are read"
    );
}

/// The other direction: we sign `Firma1` of the form, the reference tool fills
/// `Firma2` over our output, and both signatures verify. This is the flow a
/// real user makes co-signing a document two offices share, and the one the
/// reimplementation owes the tool it replaces.
#[test]
fn autofirma_cosigns_a_document_openfirma_signed() {
    let Some((jar, driver, p12)) = reference_tool() else {
        return;
    };
    let Some(signer) = load_signer() else {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };

    let (dir, _input) = workspace("cosign-ours");
    let options = PadesOptions {
        field_name: Some("Firma1".into()),
        ..PadesOptions::default()
    };
    let ours = pades_sign(TWO_FIELDS, &signer, &options).expect("our signature");
    let our_path = dir.join("our-firma1.pdf");
    std::fs::write(&our_path, &ours).unwrap();

    let cosigned = dir.join("our-firma1-autofirma-firma2.pdf");
    autofirma_sign(&jar, &driver, &p12, &our_path, &cosigned, Some("Firma2"));

    let signed = std::fs::read(&cosigned).expect("the co-signed document is there");
    let report = pades_verify(&signed, &anchors())
        .expect("our signature and the reference tool's co-signature both verify");
    assert_eq!(
        report.signatures.len(),
        2,
        "our signature and AutoFirma's are both read"
    );
}

/// Round two's 02-N-4, with the reference tool making the document rather than a
/// hand-written pass standing in for it: a PDF carrying XMP and `/Info` — what
/// Ghostscript hands a signing tool, and what a citizen's document usually carries —
/// signed TWICE by the reference tool.
///
/// Measured on the tool's own output: its second pass moves `/ModDate`,
/// `xmp:ModifyDate` and `xmp:MetadataDate` one second and nothing else anywhere in the
/// file, and both objects keep their numbers. Before the two date rules in
/// `revisions.rs` this document came back as "a stream object was rewritten after the
/// signature; readers render its bytes" — said of the XMP packet, which nothing
/// renders — and the refusal was reported as tampering on the file the tool had just
/// produced. `signed_twice_dates.rs` pins the same shapes portably for CI; this is the
/// version where the shapes come from the tool itself.
#[test]
fn autofirma_signing_a_document_with_xmp_twice_verifies_both() {
    let Some((jar, driver, p12)) = reference_tool() else {
        return;
    };

    let (dir, input) = xmp_workspace("twice-xmp");
    let first = dir.join("once.pdf");
    let second = dir.join("twice.pdf");
    autofirma_sign(&jar, &driver, &p12, &input, &first, None);
    autofirma_sign(&jar, &driver, &p12, &first, &second, None);

    let signed = std::fs::read(&second).expect("the reference tool's output is there");
    let report = pades_verify(&signed, &anchors())
        .expect("the reference tool's second signature over a document with XMP verifies");
    assert_eq!(
        report.signatures.len(),
        2,
        "both of AutoFirma's signatures are read"
    );
}

/// The case round two called the most common, and the residual this gate still
/// refuses: the reference tool co-signing a document THIS crate signed with an
/// INVISIBLE signature, so the tool has to create its own field and widget.
///
/// The widget is fine — it carries its own `/V`, whose `/ByteRange` covers the widget's
/// bytes, which is what the whitelist asks. What is not fine is the rest of the page
/// dictionary: iText writes `/Resources<</Font<</F1 4 0 R>>>>` where our revision had
/// written `/Resources << /Font << /F1 4 0 R >> >>`, same meaning, different bytes, and
/// this gate compares bytes because the byte comparison is what stops a re-pointed
/// `/Contents` hiding a shadow. So the document is refused: R4-C2's named residual, in
/// its everyday shape.
///
/// This test asserts a REFUSAL on purpose, and asserts which reason the gate gives: the
/// structural comparison that would license the re-serialisation is unwritten work, and
/// whoever writes it should see this test go green as the signal — while re-justifying
/// the byte comparison's own tests in the same breath.
#[test]
fn autofirma_cosigning_our_invisible_signature_is_refused_for_the_right_reason() {
    let Some((jar, driver, p12)) = reference_tool() else {
        return;
    };
    let Some(signer) = load_signer() else {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };

    let (dir, _input) = workspace("cosign-invisible");
    // no field name: the invisible signature, which is what our writer makes when the
    // caller does not ask for a box, and what the reference tool then has to work around
    let ours = pades_sign(SIMPLE, &signer, &PadesOptions::default()).expect("our signature");
    let our_path = dir.join("our-invisible.pdf");
    std::fs::write(&our_path, &ours).unwrap();

    let cosigned = dir.join("our-invisible-autofirma.pdf");
    autofirma_sign(&jar, &driver, &p12, &our_path, &cosigned, None);

    let signed = std::fs::read(&cosigned).expect("the co-signed document is there");
    let text = pades_verify(&signed, &anchors())
        .expect_err("the residual still refuses this document")
        .to_string();
    assert!(
        text.contains("another key of the page"),
        "the refusal has to name what it actually could not read: {text}"
    );
    assert!(
        text.contains("gate reads bytes"),
        "and say that bytes are the limit of what it saw: {text}"
    );
    assert!(
        !text.contains("has to carry a signature value"),
        "and must not blame the widget, which is attested: {text}"
    );
}
