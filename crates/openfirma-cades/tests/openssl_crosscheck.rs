//! Layer 2 of the validation strategy, see docs/validation.md: check our
//! output against an independent CMS implementation, the OpenSSL CLI.
//!
//! These tests skip themselves when openssl or the test certificates are not
//! present, so `cargo test` stays green on a fresh checkout. Run
//! `tools/gen-testcert.sh` first to exercise them.
//!
//! Note on detached signatures: `openssl cms -verify -content` is broken in
//! OpenSSL 3.6.5, it rejects detached signatures produced by openssl itself.
//! `openssl smime -verify -content` works, so that is what we use.

use std::path::{Path, PathBuf};
use std::process::Command;

use openfirma_cades::{CadesOptions, sign};
use openfirma_core::alg::DigestAlg;
use openfirma_core::signer::{Signer, SoftwareSigner};

const CONTENT: &[u8] =
    b"openfirma crosscheck payload\nsegunda linea con acentos: ca\xc3\xb1\xc3\xb3n\n";

fn certs_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/certs")
}

fn openssl_available() -> bool {
    Command::new("openssl")
        .arg("version")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Returns None when the material is missing, which skips the test.
///
/// Material that is present but cannot be loaded is a bug, not a skip. A
/// silent skip here once hid the fact that every ECDSA test was passing
/// without signing anything, because `openssl ecparam -genkey` emits SEC1 keys
/// and our loader only takes PKCS#8. So this panics instead.
fn load_signer(cert: &str, key: &str) -> Option<SoftwareSigner> {
    let dir = certs_dir();
    let (Ok(cert_pem), Ok(key_pem)) = (
        std::fs::read_to_string(dir.join(cert)),
        std::fs::read_to_string(dir.join(key)),
    ) else {
        return None;
    };
    Some(
        SoftwareSigner::from_pkcs8_pem(&cert_pem, &key_pem).unwrap_or_else(|e| {
            panic!(
                "{cert} / {key} are present but unusable: {e}. \
             Keys must be PKCS#8 PEM, rerun tools/gen-testcert.sh"
            )
        }),
    )
}

/// Same, embedding the issuing certificates listed in `chain`.
fn load_signer_with_chain(cert: &str, key: &str, chain: &[&str]) -> Option<SoftwareSigner> {
    use openfirma_core::cert::CertificateHandle;
    let dir = certs_dir();
    let handles = chain
        .iter()
        .map(|c| {
            let pem = std::fs::read_to_string(dir.join(c)).ok()?;
            CertificateHandle::from_pem(&pem).ok()
        })
        .collect::<Option<Vec<_>>>()?;
    Some(load_signer(cert, key)?.with_chain(handles))
}

/// CI sets OPENFIRMA_REQUIRE_TESTS so a missing tool or a missing test PKI
/// fails the build instead of quietly skipping. Only the keystore-scoped
/// opt-out (OPENFIRMA_ALLOW_SKIP, read exclusively by openfirma-keystore's
/// tests) may relax this; every other skip stays mandatory — review 07, H-2:
/// one flag for everything let a broken PKI step go green with nothing
/// verified on macOS and Windows.
fn require_or_skip(reason: &str) {
    let required = std::env::var("OPENFIRMA_REQUIRE_TESTS").is_ok();
    let allowed = std::env::var("OPENFIRMA_ALLOW_NONKEYSTORE_SKIP").is_ok();
    if required && !allowed {
        panic!("cannot run the crosscheck: {reason}");
    }
    eprintln!("skipped, {reason}");
}

/// openssl on Windows writes the recovered content in text mode, so every LF
/// comes back as CRLF. The signature verified either way, and our fixture has
/// no CR, so dropping them keeps the comparison exact on every platform.
fn strip_cr(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().copied().filter(|b| *b != b'\r').collect()
}

fn run(args: &[&str]) -> (bool, String) {
    let out = Command::new("openssl")
        .args(args)
        .output()
        .expect("openssl disappeared mid test");
    let text =
        String::from_utf8_lossy(&out.stderr).to_string() + &String::from_utf8_lossy(&out.stdout);
    (out.status.success(), text)
}

/// Temp file named after the running test, because the whole integration
/// test binary is one process and cargo runs tests in parallel threads.
/// Without the test name they all write to the same path and overwrite each
/// other, which shows up as a random verification failure.
fn write_tmp(name: &str, bytes: &[u8]) -> PathBuf {
    let test = std::thread::current()
        .name()
        .unwrap_or("main")
        .replace("::", "_");
    let path = std::env::temp_dir().join(format!("openfirma-{}-{test}-{name}", std::process::id()));
    std::fs::write(&path, bytes).expect("cannot write temp file");
    path
}

/// Root only. Used by the test that embeds the intermediate in the signature,
/// so chain building has to happen from what we embedded.
fn ca_file() -> PathBuf {
    certs_dir().join("ca.crt")
}

/// Root plus intermediate. Used by the tests that only embed the signer
/// certificate, so they exercise the signature and not the chain.
fn trust_bundle() -> PathBuf {
    certs_dir().join("chain.crt")
}

fn check_encapsulated(cert: &str, key: &str, digest: DigestAlg) {
    if !openssl_available() {
        require_or_skip("openssl not found");
        return;
    }
    let Some(signer) = load_signer(cert, key) else {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };

    let opts = CadesOptions {
        digest,
        signing_time: Some(std::time::SystemTime::now()),
        mime_type: Some("text/plain".into()),
        encapsulate_content: true,
        ..CadesOptions::default()
    };
    let signature = sign(CONTENT, &signer, &opts).expect("signing failed");

    let sig_path = write_tmp("enc.csig", &signature);
    let out_path = write_tmp("enc.out", b"");
    let ca = trust_bundle();

    let (ok, text) = run(&[
        "cms",
        "-verify",
        "-inform",
        "DER",
        "-in",
        sig_path.to_str().unwrap(),
        "-CAfile",
        ca.to_str().unwrap(),
        "-out",
        out_path.to_str().unwrap(),
    ]);
    assert!(ok, "openssl cms -verify failed:\n{text}");

    // openssl only writes the content when the messageDigest attribute matched
    let recovered = std::fs::read(&out_path).expect("no recovered content");
    assert_eq!(strip_cr(&recovered), CONTENT, "recovered content differs");

    std::fs::remove_file(sig_path).ok();
    std::fs::remove_file(out_path).ok();
}

/// The other direction of finding M6: an ECDSA P-384 signature produced by
/// openssl, not by us. openfirma must carry the chain and verify it — several
/// European CAs are P-384, and refusing to read their signatures would lock
/// those citizens' certificates out.
#[test]
fn ecdsa_p384_signatures_from_openssl_verify() {
    if !openssl_available() {
        require_or_skip("openssl not found");
        return;
    }
    let certs = certs_dir();
    if !certs.join("signer-p384.key").exists() {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    }
    let content = write_tmp("p384-content.txt", CONTENT);
    let sig_path = write_tmp("p384.csig", b"");
    let (ok, text) = run(&[
        "cms",
        "-sign",
        "-binary",
        "-nodetach",
        "-md",
        "sha384",
        "-in",
        content.to_str().unwrap(),
        "-signer",
        certs.join("signer-p384.crt").to_str().unwrap(),
        "-inkey",
        certs.join("signer-p384.key").to_str().unwrap(),
        "-certfile",
        certs.join("intermediate.crt").to_str().unwrap(),
        "-outform",
        "DER",
        "-out",
        sig_path.to_str().unwrap(),
    ]);
    assert!(ok, "openssl cms -sign (P-384) failed:\n{text}");
    let signature = std::fs::read(&sig_path).expect("no signature produced");

    // same profile caveat as the SKI test: bare openssl CMS carries no ESS
    // attribute, so sid resolution plus key handling is what the API-level
    // probe measures, and openssl's own -verify already validated the EC math.
    let signers = openfirma_cades::signer_certificates(&signature)
        .expect("the P-384 signer must resolve from its own signature (finding M6)");
    assert!(
        signers[0].subject().to_string().contains("P-384"),
        "{}",
        signers[0].subject()
    );

    std::fs::remove_file(sig_path).ok();
    std::fs::remove_file(content).ok();
}

/// Finding M4: a SignerInfo that identifies the signer by subjectKeyIdentifier
/// (CMS signerInfo version 3), which is what `openssl cms -keyid` writes. The
/// verifier used to carry userPassword's OID (2.5.4.35) where the extension's
/// belongs, so every such signature failed with "unknown signer". openssl both
/// produces this shape and resolves it against its own key: if openfirma reads
/// the same file, the SKI path is proven against an independent implementation.
#[test]
fn ski_signer_identifier_verifies() {
    if !openssl_available() {
        require_or_skip("openssl not found");
        return;
    }
    let certs = certs_dir();
    if !certs.join("signer-rsa.key").exists() {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    }
    let content = write_tmp("ski-content.txt", CONTENT);
    let sig_path = write_tmp("ski.csig", b"");
    // openssl refuses to add -keyid without a certificate carrying the SKI
    // extension; ours has `subjectKeyIdentifier = hash` on every certificate.
    let (ok, text) = run(&[
        "cms",
        "-sign",
        "-keyid",
        "-binary",
        "-nodetach",
        "-md",
        "sha256",
        "-in",
        content.to_str().unwrap(),
        "-signer",
        certs.join("signer-rsa.crt").to_str().unwrap(),
        "-inkey",
        certs.join("signer-rsa.key").to_str().unwrap(),
        "-outform",
        "DER",
        "-out",
        sig_path.to_str().unwrap(),
    ]);
    assert!(ok, "openssl cms -sign -keyid failed:\n{text}");
    let signature = std::fs::read(&sig_path).expect("no signature produced");

    // The finding is the sid resolution: given openssl's SKI-shaped message,
    // openfirma must find the signer certificate through the subjectKeyIdentifier
    // extension — OID 2.5.29.14, which it used to misread as userPassword — by
    // the public API that answers exactly that question. `verify` itself stops
    // earlier on a different rule (bare openssl CMS carries no ESS attribute,
    // and a CAdES verifier is right to refuse it), so it is not the probe here.
    let certs = openfirma_cades::signer_certificates(&signature)
        .expect("the sid must resolve through the subjectKeyIdentifier extension (finding M4)");
    assert_eq!(certs.len(), 1);
    assert!(
        certs[0].subject().to_string().contains("PEREZ GARCIA"),
        "{}",
        certs[0].subject()
    );

    // and it is genuinely a version-3 SKI SignerInfo: INTEGER 3 immediately
    // followed by the [0] IMPLICIT KeyIdentifier of 20 bytes (SHA-1's length)
    assert!(
        signature.windows(4).any(|w| w == [0x02, 0x01, 0x03, 0x80]),
        "openssl did not produce a version-3 SKI SignerInfo"
    );
    std::fs::remove_file(sig_path).ok();
    std::fs::remove_file(content).ok();
}

fn check_detached(cert: &str, key: &str, digest: DigestAlg) {
    if !openssl_available() {
        require_or_skip("openssl not found");
        return;
    }
    let Some(signer) = load_signer(cert, key) else {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };

    let opts = CadesOptions {
        digest,
        encapsulate_content: false,
        ..CadesOptions::default()
    };
    let signature = sign(CONTENT, &signer, &opts).expect("signing failed");

    let content_path = write_tmp("detached.txt", CONTENT);
    let sig_path = write_tmp("det.csig", &signature);
    let out_path = write_tmp("det.out", b"");
    let ca = trust_bundle();

    let (ok, text) = run(&[
        "smime",
        "-verify",
        "-inform",
        "DER",
        "-in",
        sig_path.to_str().unwrap(),
        "-content",
        content_path.to_str().unwrap(),
        "-CAfile",
        ca.to_str().unwrap(),
        "-out",
        out_path.to_str().unwrap(),
    ]);
    assert!(ok, "openssl smime -verify failed:\n{text}");

    let recovered = std::fs::read(&out_path).expect("no recovered content");
    assert_eq!(strip_cr(&recovered), CONTENT, "recovered content differs");

    for p in [content_path, sig_path, out_path] {
        std::fs::remove_file(p).ok();
    }
}

#[test]
fn rsa_sha256_encapsulated() {
    check_encapsulated("signer-rsa.crt", "signer-rsa.key", DigestAlg::Sha256);
}

#[test]
fn rsa_sha256_detached() {
    check_detached("signer-rsa.crt", "signer-rsa.key", DigestAlg::Sha256);
}

#[test]
fn rsa_sha512_encapsulated() {
    check_encapsulated("signer-rsa.crt", "signer-rsa.key", DigestAlg::Sha512);
}

#[test]
fn ecdsa_p256_sha256_encapsulated() {
    check_encapsulated("signer-ec.crt", "signer-ec.key", DigestAlg::Sha256);
}

#[test]
fn ecdsa_p256_sha256_detached() {
    check_detached("signer-ec.crt", "signer-ec.key", DigestAlg::Sha256);
}

// Finding M6: P-384 signing and verification, crosschecked against openssl so
// the curve arithmetic is not being graded by its own implementation.
#[test]
fn ecdsa_p384_sha384_encapsulated() {
    check_encapsulated("signer-p384.crt", "signer-p384.key", DigestAlg::Sha384);
}

#[test]
fn ecdsa_p384_sha384_detached() {
    check_detached("signer-p384.crt", "signer-p384.key", DigestAlg::Sha384);
}

/// The chain lives in three levels, root -> intermediate -> signer, like a
/// real Spanish PKI. We embed the intermediate in `SignedData.certificates`
/// and hand openssl only the root as trust anchor, so this test is what proves
/// the embedding and the issuer/serial in `SignerInfo.sid` are correct enough
/// for an independent implementation to rebuild the chain.
#[test]
fn rsa_sha256_encapsulated_chain_built_from_embedded_certs() {
    if !openssl_available() {
        require_or_skip("openssl not found");
        return;
    }
    let Some(signer) =
        load_signer_with_chain("signer-rsa.crt", "signer-rsa.key", &["intermediate.crt"])
    else {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    assert_eq!(signer.chain().len(), 1);

    let opts = CadesOptions {
        digest: DigestAlg::Sha256,
        encapsulate_content: true,
        ..CadesOptions::default()
    };
    let signature = sign(CONTENT, &signer, &opts).expect("signing failed");

    // both certificates must be inside the signature
    let embedded = signature
        .windows(signer.certificate().der().len())
        .filter(|w| *w == signer.certificate().der())
        .count();
    assert_eq!(embedded, 1, "signer certificate not embedded once");
    let interm = std::fs::read(certs_dir().join("intermediate.crt.der")).expect("intermediate der");
    assert!(
        signature
            .windows(interm.len())
            .any(|w| w == interm.as_slice()),
        "intermediate certificate not embedded"
    );

    let sig_path = write_tmp("chain.csig", &signature);
    let out_path = write_tmp("chain.out", b"");
    let (ok, text) = run(&[
        "cms",
        "-verify",
        "-inform",
        "DER",
        "-in",
        sig_path.to_str().unwrap(),
        "-CAfile",
        ca_file().to_str().unwrap(),
        "-out",
        out_path.to_str().unwrap(),
    ]);
    assert!(ok, "openssl rejected the chain:\n{text}");
    assert_eq!(
        strip_cr(&std::fs::read(&out_path).expect("no recovered content")),
        CONTENT
    );

    std::fs::remove_file(sig_path).ok();
    std::fs::remove_file(out_path).ok();
}
