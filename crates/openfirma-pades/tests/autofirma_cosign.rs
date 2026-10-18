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
//! will not compile or run is a hard failure. Nothing here is committed: the
//! input is produced by `tools/gen-testpdf.py --two-fields` and the signed
//! documents go to a temporary directory.

use std::path::{Path, PathBuf};
use std::process::Command;

use openfirma_cades::verify::VerifyOptions;
use openfirma_core::cert::CertificateHandle;
use openfirma_core::signer::SoftwareSigner;
use openfirma_pades::{PadesOptions, pades_sign, pades_verify};

const TWO_FIELDS: &[u8] = include_bytes!("../../../testdata/inputs/twofields.pdf");

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

/// Have AutoFirma sign `input` into the field `field` and write `output`.
fn autofirma_sign(jar: &Path, driver: &Path, p12: &Path, input: &Path, output: &Path, field: &str) {
    let classpath = format!("{}:{}", jar.display(), driver.display());
    let out = Command::new("java")
        .args([
            "-Djava.awt.headless=true",
            "-cp",
            &classpath,
            "AutofirmaGolden",
        ])
        .arg(p12)
        .arg("openfirma")
        .arg(input)
        .arg(output)
        .args(["SHA256withRSA", &format!("signatureField={field}")])
        .output()
        .expect("java disappeared mid test");
    assert!(
        out.status.success(),
        "the reference tool did not sign {field} of {}:\n{}{}",
        input.display(),
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
    if !tool("java") || !tool("javac") {
        eprintln!("skipped, no JDK on this machine");
        return;
    }
    let Some(jar) = jar() else {
        eprintln!("skipped, no autofirma.jar ($AUTOFIRMA_JAR or tools/fetch-autofirma.sh)");
        return;
    };
    let p12 = certs_dir().join("signer-rsa.p12");
    if !p12.is_file() {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    }
    let driver = driver_dir(&jar);

    let (dir, input) = workspace("cosign-both");
    let first = dir.join("firma1.pdf");
    let second = dir.join("firma1-firma2.pdf");
    autofirma_sign(&jar, &driver, &p12, &input, &first, "Firma1");
    autofirma_sign(&jar, &driver, &p12, &first, &second, "Firma2");

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
    if !tool("java") || !tool("javac") {
        eprintln!("skipped, no JDK on this machine");
        return;
    }
    let Some(jar) = jar() else {
        eprintln!("skipped, no autofirma.jar ($AUTOFIRMA_JAR or tools/fetch-autofirma.sh)");
        return;
    };
    let p12 = certs_dir().join("signer-rsa.p12");
    if !p12.is_file() {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    }
    let Some(signer) = load_signer() else {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    let driver = driver_dir(&jar);

    let (dir, _input) = workspace("cosign-ours");
    let options = PadesOptions {
        field_name: Some("Firma1".into()),
        ..PadesOptions::default()
    };
    let ours = pades_sign(TWO_FIELDS, &signer, &options).expect("our signature");
    let our_path = dir.join("our-firma1.pdf");
    std::fs::write(&our_path, &ours).unwrap();

    let cosigned = dir.join("our-firma1-autofirma-firma2.pdf");
    autofirma_sign(&jar, &driver, &p12, &our_path, &cosigned, "Firma2");

    let signed = std::fs::read(&cosigned).expect("the co-signed document is there");
    let report = pades_verify(&signed, &anchors())
        .expect("our signature and the reference tool's co-signature both verify");
    assert_eq!(
        report.signatures.len(),
        2,
        "our signature and AutoFirma's are both read"
    );
}
