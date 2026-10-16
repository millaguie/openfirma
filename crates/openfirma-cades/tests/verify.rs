//! The in-repo verifier, tested against the synthetic PKI: sign, then verify,
//! then break one thing at a time and check that the right check fails.
//!
//! Layer 2 of docs/validation.md is the crosscheck with an independent
//! implementation; the last test here ties the two together by asserting that
//! OpenSSL agrees with `openfirma_cades::verify` on a good and on a tampered
//! file.
//!
//! Skips follow the rules of openssl_crosscheck.rs: missing material skips,
//! unless CI set OPENFIRMA_REQUIRE_TESTS, and material that is present but
//! unusable panics.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

use openfirma_cades::verify::{
    CHECK_CERTIFICATE_CHAIN, CHECK_CONTENT_TYPE, CHECK_MESSAGE_DIGEST, CHECK_SIGNATURE_VALUE,
    CHECK_SIGNER_CERTIFICATE, CHECK_SIGNING_CERTIFICATE_V2, CHECK_VALIDITY_DATES, VerifyOptions,
    verify,
};
use openfirma_cades::{CadesOptions, attributes, sign};
use openfirma_core::alg::DigestAlg;
use openfirma_core::cert::CertificateHandle;
use openfirma_core::signer::SoftwareSigner;

const CONTENT: &[u8] =
    b"openfirma verify payload\nsegunda linea con acentos: ca\xc3\xb1\xc3\xb3n\n";

fn certs_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/certs")
}

fn openssl_available() -> bool {
    Command::new("openssl")
        .arg("version")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Returns None when the material is missing, which skips the test. Present
/// but unloadable material is a bug and panics, see openssl_crosscheck.rs.
fn load_signer_with_chain(cert: &str, key: &str, chain: &[&str]) -> Option<SoftwareSigner> {
    let dir = certs_dir();
    let (Ok(cert_pem), Ok(key_pem)) = (
        std::fs::read_to_string(dir.join(cert)),
        std::fs::read_to_string(dir.join(key)),
    ) else {
        return None;
    };
    let signer = SoftwareSigner::from_pkcs8_pem(&cert_pem, &key_pem).unwrap_or_else(|e| {
        panic!(
            "{cert} / {key} are present but unusable: {e}. \
             Keys must be PKCS#8 PEM, rerun tools/gen-testcert.sh"
        )
    });
    let handles = chain
        .iter()
        .map(|c| {
            let pem = std::fs::read_to_string(dir.join(c)).unwrap_or_else(|e| {
                panic!("{c} is listed in the test PKI but cannot be read: {e}")
            });
            CertificateHandle::from_pem(&pem)
                .unwrap_or_else(|e| panic!("{c} is not a certificate: {e}"))
        })
        .collect();
    Some(signer.with_chain(handles))
}

/// The trust anchors, loaded from the test PKI.
fn anchors(names: &[&str]) -> Vec<CertificateHandle> {
    names
        .iter()
        .map(|n| {
            let pem = std::fs::read_to_string(certs_dir().join(n))
                .unwrap_or_else(|e| panic!("{n} cannot be read: {e}"));
            CertificateHandle::from_pem(&pem)
                .unwrap_or_else(|e| panic!("{n} is not a certificate: {e}"))
        })
        .collect()
}

/// CI sets OPENFIRMA_REQUIRE_TESTS so missing material fails the build instead
/// of quietly skipping.
fn require_or_skip(reason: &str) {
    let required = std::env::var("OPENFIRMA_REQUIRE_TESTS").is_ok();
    let allowed = std::env::var("OPENFIRMA_ALLOW_SKIP").is_ok();
    if required && !allowed {
        panic!("cannot run the test: {reason}");
    }
    eprintln!("skipped, {reason}");
}

/// Temp file named after the running test, because cargo runs the tests of
/// one binary in parallel threads.
fn write_tmp(name: &str, bytes: &[u8]) -> PathBuf {
    let test = std::thread::current()
        .name()
        .unwrap_or("main")
        .replace("::", "_");
    let path = std::env::temp_dir().join(format!("openfirma-{}-{test}-{name}", std::process::id()));
    std::fs::write(&path, bytes).expect("cannot write temp file");
    path
}

/// The span of the `signatureValue` OCTET STRING content inside a CMS DER.
/// Walks ContentInfo -> SignedData -> signerInfos -> the first SignerInfo and
/// takes its only top level OCTET STRING, which is the signature value: every
/// other field is an INTEGER, a SEQUENCE or a context tagged container.
fn signature_span(der: &[u8]) -> std::ops::Range<usize> {
    fn tlv(b: &[u8], at: usize) -> (u8, usize, usize) {
        let tag = b[at];
        assert_ne!(tag & 0x1f, 0x1f, "a multi byte tag was not expected");
        let first = b[at + 1];
        let (len, n) = if first < 0x80 {
            (first as usize, 1usize)
        } else {
            let n = (first & 0x7f) as usize;
            let mut v = 0usize;
            for x in &b[at + 2..at + 2 + n] {
                v = (v << 8) | *x as usize;
            }
            (v, n + 1)
        };
        (tag, at + 1 + n, at + 1 + n + len)
    }
    let (_, ci_start, _) = tlv(der, 0);
    let (_, _, after_oid) = tlv(der, ci_start); // contentType
    let (_, content_start, _) = tlv(der, after_oid); // [0] EXPLICIT
    let (_, sd_start, sd_end) = tlv(der, content_start); // SignedData
    let (_, _, mut p) = tlv(der, sd_start); // version
    let (_, _, p1) = tlv(der, p); // digestAlgorithms
    let (_, _, p2) = tlv(der, p1); // encapContentInfo
    p = p2;
    let mut infos = None;
    while p < sd_end {
        let (tag, s, e) = tlv(der, p);
        if tag == 0x31 {
            infos = Some((s, e));
        }
        p = e;
    }
    let (infos_start, _) = infos.expect("no signerInfos SET");
    let (_, si_start, si_end) = tlv(der, infos_start); // the first SignerInfo
    let mut q = si_start;
    while q < si_end {
        let (tag, cs, ce) = tlv(der, q);
        if tag == 0x04 {
            return cs..ce;
        }
        q = ce;
    }
    panic!("no signatureValue OCTET STRING in the SignerInfo");
}

/// Flips one bit inside the signature value. RSA PKCS#1 v1.5 verification is
/// all or nothing, so a single changed byte has to fail the check.
fn tamper_signature(der: &mut [u8]) {
    let span = signature_span(der);
    der[span.start + span.len() / 2] ^= 0x01;
}

fn default_opts() -> CadesOptions {
    CadesOptions {
        digest: DigestAlg::Sha256,
        ..CadesOptions::default()
    }
}

#[test]
fn encapsulated_cades_verifies_and_the_report_is_complete() {
    let Some(signer) =
        load_signer_with_chain("signer-rsa.crt", "signer-rsa.key", &["intermediate.crt"])
    else {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    let opts = CadesOptions {
        encapsulate_content: true,
        mime_type: Some("text/plain".into()),
        content_hint: Some("Texto plano".into()),
        ..default_opts()
    };
    let signature = sign(CONTENT, &signer, &opts).expect("signing failed");

    let reports = verify(&signature, None, &VerifyOptions::new(anchors(&["ca.crt"])))
        .expect("an untouched encapsulated signature must verify");
    assert_eq!(reports.len(), 1);
    let r = &reports[0];
    assert!(
        r.signer_subject.contains("PEREZ GARCIA"),
        "{}",
        r.signer_subject
    );
    assert_eq!(r.digest, DigestAlg::Sha256);
    assert_eq!(r.signature_alg, "RSA-PKCS1-v1_5 with SHA-256");
    assert_eq!(r.chain_subjects.len(), 2, "signer plus intermediate");
    assert!(
        r.chain_subjects[1].contains("Intermediate"),
        "{:?}",
        r.chain_subjects
    );
    assert!(r.trust_anchor.contains("Root CA"), "{}", r.trust_anchor);
    assert_eq!(
        r.passed,
        vec![
            CHECK_SIGNER_CERTIFICATE,
            CHECK_CONTENT_TYPE,
            CHECK_MESSAGE_DIGEST,
            CHECK_SIGNATURE_VALUE,
            CHECK_SIGNING_CERTIFICATE_V2,
            CHECK_CERTIFICATE_CHAIN,
            CHECK_VALIDITY_DATES,
        ]
    );
    assert!(
        r.attributes.signing_time.is_some(),
        "AutoFirma's advanced profile carries signingTime"
    );
    assert!(r.attributes.message_digest && r.attributes.signing_certificate_v2);
    assert_eq!(r.attributes.mime_type.as_deref(), Some("text/plain"));
    assert_eq!(r.attributes.content_hint.as_deref(), Some("Texto plano"));
    assert!(!r.attributes.signature_time_stamp_token);
    assert!(r.attributes.unsigned_attributes.is_empty());
}

/// RFC 5652 11.1: the `contentType` signed attribute must match
/// `encapContentInfo.eContentType`. Nothing else in the signature breaks when
/// the two disagree — the digest is still over the same bytes and the
/// signature still verifies — which is exactly why the comparison has to be
/// a check of its own.
#[test]
fn a_content_type_that_disagrees_with_econtenttype_fails() {
    let Some(signer) =
        load_signer_with_chain("signer-rsa.crt", "signer-rsa.key", &["intermediate.crt"])
    else {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    let opts = CadesOptions {
        encapsulate_content: true,
        ..default_opts()
    };
    let signature = sign(CONTENT, &signer, &opts).expect("signing failed");

    // the first id-data OID in the DER is encapContentInfo.eContentType;
    // one byte turns it into id-signedData while the signed attribute, which
    // the signature value covers, still says id-data
    let id_data: [u8; 11] = [
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01,
    ];
    let mut patched = signature.clone();
    let at = patched
        .windows(11)
        .position(|w| w == id_data)
        .expect("an encapsulated id-data signature carries eContentType");
    patched[at + 10] = 0x02;

    let err = verify(&patched, None, &VerifyOptions::new(anchors(&["ca.crt"])))
        .expect_err("a contentType that disagrees with eContentType must not verify")
        .to_string();
    assert!(err.contains("contentType check failed"), "{err}");
    assert!(err.contains("RFC 5652 11.1"), "{err}");

    // the untouched signature passes the check, and says so
    let reports = verify(&signature, None, &VerifyOptions::new(anchors(&["ca.crt"])))
        .expect("the untouched signature must still verify");
    assert!(reports[0].passed.contains(&CHECK_CONTENT_TYPE));
}

#[test]
fn detached_cades_verifies_with_the_content() {
    let Some(signer) =
        load_signer_with_chain("signer-rsa.crt", "signer-rsa.key", &["intermediate.crt"])
    else {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    let signature = sign(CONTENT, &signer, &default_opts()).expect("signing failed");
    let reports = verify(
        &signature,
        Some(CONTENT),
        &VerifyOptions::new(anchors(&["ca.crt"])),
    )
    .expect("an untouched detached signature must verify");
    assert_eq!(reports.len(), 1);
    assert!(reports[0].attributes.signing_time.is_some());
}

#[test]
fn detached_without_content_is_an_error() {
    let Some(signer) =
        load_signer_with_chain("signer-rsa.crt", "signer-rsa.key", &["intermediate.crt"])
    else {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    let signature = sign(CONTENT, &signer, &default_opts()).expect("signing failed");
    let err = verify(&signature, None, &VerifyOptions::new(anchors(&["ca.crt"])))
        .expect_err("a detached signature with no content cannot verify");
    assert!(err.to_string().contains(CHECK_MESSAGE_DIGEST), "{err}");
}

#[test]
fn ecdsa_p256_verifies() {
    let Some(signer) =
        load_signer_with_chain("signer-ec.crt", "signer-ec.key", &["intermediate.crt"])
    else {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    let opts = CadesOptions {
        encapsulate_content: true,
        ..default_opts()
    };
    let signature = sign(CONTENT, &signer, &opts).expect("signing failed");
    let reports = verify(&signature, None, &VerifyOptions::new(anchors(&["ca.crt"])))
        .expect("an ECDSA signature must verify");
    assert_eq!(reports[0].signature_alg, "ECDSA with SHA-256");
    assert!(reports[0].signer_subject.contains("LOPEZ MARTIN"));
}

#[test]
fn rsa_sha512_verifies() {
    let Some(signer) =
        load_signer_with_chain("signer-rsa.crt", "signer-rsa.key", &["intermediate.crt"])
    else {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    let opts = CadesOptions {
        digest: DigestAlg::Sha512,
        ..default_opts()
    };
    let signature = sign(CONTENT, &signer, &opts).expect("signing failed");
    let reports = verify(
        &signature,
        Some(CONTENT),
        &VerifyOptions::new(anchors(&["ca.crt"])),
    )
    .expect("a SHA-512 signature must verify");
    assert_eq!(reports[0].digest, DigestAlg::Sha512);
    assert_eq!(reports[0].signature_alg, "RSA-PKCS1-v1_5 with SHA-512");
}

/// The root embedded in the signature and also supplied as the anchor: the
/// chain reaches the anchor by certificate equality, not only by signature.
#[test]
fn an_embedded_root_reaches_the_anchor() {
    let Some(signer) = load_signer_with_chain(
        "signer-rsa.crt",
        "signer-rsa.key",
        &["intermediate.crt", "ca.crt"],
    ) else {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    let signature = sign(CONTENT, &signer, &default_opts()).expect("signing failed");
    let reports = verify(
        &signature,
        Some(CONTENT),
        &VerifyOptions::new(anchors(&["ca.crt"])),
    )
    .expect("the chain must reach the embedded root");
    assert!(reports[0].trust_anchor.contains("Root CA"));
}

#[test]
fn tampered_content_fails_the_message_digest_check() {
    let Some(signer) =
        load_signer_with_chain("signer-rsa.crt", "signer-rsa.key", &["intermediate.crt"])
    else {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    let signature = sign(CONTENT, &signer, &default_opts()).expect("signing failed");
    let mut tampered = CONTENT.to_vec();
    tampered[3] ^= 0x20;
    let err = verify(
        &signature,
        Some(&tampered),
        &VerifyOptions::new(anchors(&["ca.crt"])),
    )
    .expect_err("tampered content must not verify");
    let text = err.to_string();
    assert!(text.contains(CHECK_MESSAGE_DIGEST), "{text}");
    assert!(
        !text.contains(CHECK_SIGNATURE_VALUE),
        "the signature itself is intact: {text}"
    );
}

#[test]
fn a_tampered_signature_byte_fails_the_signature_check() {
    let Some(signer) =
        load_signer_with_chain("signer-rsa.crt", "signer-rsa.key", &["intermediate.crt"])
    else {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    let mut signature = sign(CONTENT, &signer, &default_opts()).expect("signing failed");
    tamper_signature(&mut signature);
    let err = verify(
        &signature,
        Some(CONTENT),
        &VerifyOptions::new(anchors(&["ca.crt"])),
    )
    .expect_err("a tampered signature value must not verify");
    assert!(err.to_string().contains(CHECK_SIGNATURE_VALUE), "{err}");
}

/// The trust anchor has to be the root of the chain. The TSA certificate is a
/// valid certificate of the same PKI, and accepting it would mean accepting
/// any certificate as an anchor.
#[test]
fn a_trust_anchor_outside_the_chain_fails_chain_building() {
    let Some(signer) =
        load_signer_with_chain("signer-rsa.crt", "signer-rsa.key", &["intermediate.crt"])
    else {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    let signature = sign(CONTENT, &signer, &default_opts()).expect("signing failed");
    let err = verify(
        &signature,
        Some(CONTENT),
        &VerifyOptions::new(anchors(&["tsa.crt"])),
    )
    .expect_err("an unrelated trust anchor must not be enough");
    let text = err.to_string();
    assert!(text.contains(CHECK_CERTIFICATE_CHAIN), "{text}");
    assert!(
        text.contains("Root CA"),
        "the error should name the issuer it could not reach: {text}"
    );
}

/// The signer alone in `certificates`, the root as the only anchor: the
/// intermediate is missing, so the chain cannot be built even though both ends
/// are present.
#[test]
fn a_missing_intermediate_fails_chain_building() {
    let Some(signer) = load_signer_with_chain("signer-rsa.crt", "signer-rsa.key", &[]) else {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    let signature = sign(CONTENT, &signer, &default_opts()).expect("signing failed");
    let err = verify(
        &signature,
        Some(CONTENT),
        &VerifyOptions::new(anchors(&["ca.crt"])),
    )
    .expect_err("a gap in the chain must not verify");
    let text = err.to_string();
    assert!(text.contains(CHECK_CERTIFICATE_CHAIN), "{text}");
    assert!(
        text.contains("Intermediate"),
        "the error should name the missing link: {text}"
    );
}

#[test]
fn a_validation_time_before_not_before_fails_the_date_check() {
    let Some(signer) =
        load_signer_with_chain("signer-rsa.crt", "signer-rsa.key", &["intermediate.crt"])
    else {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    let signature = sign(CONTENT, &signer, &default_opts()).expect("signing failed");
    // 2001-09-09, decades before the throwaway PKI was generated
    let year_2001 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
    let err = verify(
        &signature,
        Some(CONTENT),
        &VerifyOptions::new(anchors(&["ca.crt"])).at(year_2001),
    )
    .expect_err("the certificates were not valid in 2001");
    assert!(err.to_string().contains(CHECK_VALIDITY_DATES), "{err}");

    // a time inside the window, a day after the test PKI was generated, passes
    let tomorrow = SystemTime::now() + Duration::from_secs(86_400);
    verify(
        &signature,
        Some(CONTENT),
        &VerifyOptions::new(anchors(&["ca.crt"])).at(tomorrow),
    )
    .expect("a validation time one day later is inside the validity window");
}

#[test]
fn a_signature_without_signing_certificate_v2_is_rejected() {
    let Some(signer) =
        load_signer_with_chain("signer-rsa.crt", "signer-rsa.key", &["intermediate.crt"])
    else {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    let opts = CadesOptions {
        signing_certificate_v2: false,
        ..default_opts()
    };
    let signature = sign(CONTENT, &signer, &opts).expect("signing failed");
    let err = verify(
        &signature,
        Some(CONTENT),
        &VerifyOptions::new(anchors(&["ca.crt"])),
    )
    .expect_err("CAdES requires signingCertificateV2");
    assert!(
        err.to_string().contains(CHECK_SIGNING_CERTIFICATE_V2),
        "{err}"
    );
}

/// Unsigned attributes are outside the signature, so a token can be attached
/// after signing without invalidating anything. The verifier must report what
/// it sees there; verifying the token itself is B-T work, not this.
#[test]
fn unsigned_attributes_are_reported() {
    let Some(signer) =
        load_signer_with_chain("signer-rsa.crt", "signer-rsa.key", &["intermediate.crt"])
    else {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    let opts = CadesOptions {
        unsigned_attributes: vec![
            attributes::signature_time_stamp_token(b"not-a-real-token").expect("attribute"),
        ],
        ..default_opts()
    };
    let signature = sign(CONTENT, &signer, &opts).expect("signing failed");
    let reports = verify(
        &signature,
        Some(CONTENT),
        &VerifyOptions::new(anchors(&["ca.crt"])),
    )
    .expect("an unsigned attribute cannot break the signature");
    assert!(reports[0].attributes.signature_time_stamp_token);
    assert_eq!(reports[0].attributes.unsigned_attributes.len(), 1);
    assert_eq!(
        reports[0].attributes.unsigned_attributes[0],
        openfirma_core::oid::ID_SIGNATURE_TIME_STAMP_TOKEN
    );
}

/// Layer 2 applied to the verifier itself: OpenSSL must agree with
/// `openfirma_cades::verify` on a good file and on a tampered one. `smime`
/// rather than `cms` for the detached signature, see docs/validation.md.
#[test]
fn openssl_agrees_with_the_verifier_on_good_and_tampered_files() {
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
    let signature = sign(CONTENT, &signer, &default_opts()).expect("signing failed");

    let sig_path = write_tmp("agreement.csig", &signature);
    let content_path = write_tmp("agreement.txt", CONTENT);
    let out_path = write_tmp("agreement.out", b"");
    let ca = certs_dir().join("chain.crt");
    let run = |content: &Path| -> (bool, String) {
        let out = Command::new("openssl")
            .args([
                "smime",
                "-verify",
                "-inform",
                "DER",
                "-in",
                sig_path.to_str().unwrap(),
                "-content",
                content.to_str().unwrap(),
                "-CAfile",
                ca.to_str().unwrap(),
                "-out",
                out_path.to_str().unwrap(),
            ])
            .output()
            .expect("openssl disappeared mid test");
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stderr).to_string(),
        )
    };

    // the good file: both implementations accept it
    let ours = verify(
        &signature,
        Some(CONTENT),
        &VerifyOptions::new(anchors(&["ca.crt"])),
    );
    let (theirs, text) = run(&content_path);
    assert!(
        ours.is_ok(),
        "openfirma rejected the good file: {:?}",
        ours.err()
    );
    assert!(theirs, "openssl rejected the good file:\n{text}");

    // the tampered file: both implementations reject it
    let mut tampered = CONTENT.to_vec();
    tampered[3] ^= 0x20;
    let tampered_path = write_tmp("agreement-tampered.txt", &tampered);
    let ours = verify(
        &signature,
        Some(&tampered),
        &VerifyOptions::new(anchors(&["ca.crt"])),
    );
    let (theirs, _) = run(&tampered_path);
    let err = ours.expect_err("openfirma accepted the tampered file");
    assert!(
        err.to_string().contains(CHECK_MESSAGE_DIGEST),
        "and it must fail on the right check: {err}"
    );
    assert!(!theirs, "openssl accepted the tampered file");

    for p in [sig_path, content_path, out_path, tampered_path] {
        std::fs::remove_file(p).ok();
    }
}
