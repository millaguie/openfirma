//! AutoFirma itself as the verifier: the official jar's ValidateXMLSignature
//! (the validator behind the GUI's "validate signature") must accept what we
//! sign, and must refuse it once tampered with. This is the strongest
//! in-repo statement of the project's promise: the reference implementation
//! agrees with us, in the direction that matters (it reads OUR file).
//!
//! The jar is not a CI dependency: it is large, it is fetched by
//! tools/fetch-autofirma.sh, and CI does not run the golden diff either. So
//! a missing jar or java skips with a message, exactly like the qpdf tests
//! in openfirma-pades; a jar that is present but whose driver fails to
//! compile or run is a hard failure.

use std::path::{Path, PathBuf};
use std::process::Command;

use openfirma_core::cert::CertificateHandle;
use openfirma_core::signer::SoftwareSigner;
use openfirma_xades::{XadesOptions, xades_sign};

const INPUT: &[u8] = include_bytes!("../../../testdata/inputs/simple.xml");

fn certs_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/certs")
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn require_or_skip(reason: &str) {
    let required = std::env::var("OPENFIRMA_REQUIRE_TESTS").is_ok();
    let allowed = std::env::var("OPENFIRMA_ALLOW_SKIP").is_ok();
    if required && !allowed {
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

fn autofirma_verify(jar: &Path, driver: &Path, file: &Path) -> (bool, String) {
    let classpath = format!("{}:{}", jar.display(), driver.display());
    let out = Command::new("java")
        .args([
            "-Djava.awt.headless=true",
            "-cp",
            &classpath,
            "AutofirmaGolden",
            "--verify",
        ])
        .arg(file)
        .output()
        .expect("java disappeared mid test");
    let text =
        String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
    (out.status.success(), text)
}

fn load_signer(cert: &str, key: &str, chain: &[&str]) -> Option<SoftwareSigner> {
    let dir = certs_dir();
    let (Ok(cert_pem), Ok(key_pem)) = (
        std::fs::read_to_string(dir.join(cert)),
        std::fs::read_to_string(dir.join(key)),
    ) else {
        return None;
    };
    let signer = SoftwareSigner::from_pkcs8_pem(&cert_pem, &key_pem).unwrap_or_else(|e| {
        panic!("{cert} / {key} are present but unusable: {e}, rerun tools/gen-testcert.sh")
    });
    let handles = chain
        .iter()
        .map(|c| {
            let pem = std::fs::read_to_string(dir.join(c))
                .unwrap_or_else(|e| panic!("{c} cannot be read: {e}"));
            CertificateHandle::from_pem(&pem).unwrap_or_else(|e| panic!("{c}: {e}"))
        })
        .collect();
    Some(signer.with_chain(handles))
}

fn write_tmp(name: &str, bytes: &[u8]) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("openfirma-xades-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}

#[test]
fn autofirma_verifies_what_openfirma_signed() {
    if !tool("java") || !tool("javac") {
        // not a CI dependency, same category as qpdf in openfirma-pades
        eprintln!("skipped, no JDK on this machine");
        return;
    }
    let Some(jar) = jar() else {
        eprintln!("skipped, no autofirma.jar ($AUTOFIRMA_JAR or tools/fetch-autofirma.sh)");
        return;
    };
    let Some(signer) = load_signer(
        "signer-rsa.crt",
        "signer-rsa.key",
        &["intermediate.crt", "ca.crt"],
    ) else {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    let driver = driver_dir(&jar);

    let signed = xades_sign(INPUT, &signer, &XadesOptions::default()).expect("signing");
    let path = write_tmp("autofirma-verify.xml", &signed);
    let (ok, text) = autofirma_verify(&jar, &driver, &path);
    assert!(
        ok && text.contains("OK"),
        "AutoFirma's own validator rejected our XAdES-B-B signature:\n{text}"
    );
    std::fs::remove_file(&path).ok();
}

/// The ECDSA path has no AutoFirma golden (AutoFirma cannot sign it, see
/// docs/xades.md), but its validator can still read ours: JSR-105
/// verification of ecdsa-sha256 works even where their signing provider
/// refuses SunEC keys.
#[test]
fn autofirma_verifies_the_ecdsa_signature() {
    if !tool("java") || !tool("javac") {
        eprintln!("skipped, no JDK on this machine");
        return;
    }
    let Some(jar) = jar() else {
        eprintln!("skipped, no autofirma.jar ($AUTOFIRMA_JAR or tools/fetch-autofirma.sh)");
        return;
    };
    let Some(signer) = load_signer(
        "signer-ec.crt",
        "signer-ec.key",
        &["intermediate.crt", "ca.crt"],
    ) else {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    let driver = driver_dir(&jar);

    let signed = xades_sign(INPUT, &signer, &XadesOptions::default()).expect("signing");
    let path = write_tmp("autofirma-verify-ec.xml", &signed);
    let (ok, text) = autofirma_verify(&jar, &driver, &path);
    assert!(
        ok && text.contains("OK"),
        "AutoFirma's validator rejected our ECDSA signature:\n{text}"
    );
    std::fs::remove_file(&path).ok();
}

/// And it must refuse a signature whose content was touched: a validator
/// that says OK to everything proves nothing.
#[test]
fn autofirma_refuses_a_tampered_document() {
    if !tool("java") || !tool("javac") {
        eprintln!("skipped, no JDK on this machine");
        return;
    }
    let Some(jar) = jar() else {
        eprintln!("skipped, no autofirma.jar ($AUTOFIRMA_JAR or tools/fetch-autofirma.sh)");
        return;
    };
    let Some(signer) = load_signer(
        "signer-rsa.crt",
        "signer-rsa.key",
        &["intermediate.crt", "ca.crt"],
    ) else {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    let driver = driver_dir(&jar);

    let signed = xades_sign(INPUT, &signer, &XadesOptions::default()).expect("signing");
    let text = std::str::from_utf8(&signed).unwrap().to_string();
    let tampered = text.replacen("1234.56", "9999.99", 1);
    assert_ne!(tampered, text);
    let path = write_tmp("autofirma-verify-tampered.xml", tampered.as_bytes());

    let (ok, _) = autofirma_verify(&jar, &driver, &path);
    assert!(!ok, "AutoFirma accepted a tampered document");
    std::fs::remove_file(&path).ok();
}
