//! What an archive's revocation data is allowed to be old *about*.
//!
//! Round two's N10: a B-LT document carrying an ordinary CRL — one with a
//! `nextUpdate` a week out, which is what every CA issues — stopped verifying a
//! week later, because the archived datum was judged against the wall clock. A
//! level called "long term" cannot last one CRL period, and the archived data
//! then argues for the document being re-signed every week, which is not what
//! validation data is for.
//!
//! The rule: an archive's evidence is judged about the first time-stamp in the
//! document whose TSA signature verified. A seal fixes the bytes under it to a
//! moment, that moment follows the signing, and a datum that speaks for it
//! supports "this certificate was not revoked when the document was signed",
//! which is the claim B-LT makes. With no such seal the wall clock judges, as a
//! live check should — so the aged datum is still refused in a document that
//! cannot place itself in time, and an aged datum that predates every seal is
//! refused even in one that can: nothing says the signature is as old as that
//! datum claims, and `signingTime` is the signer's own unauthenticated word.
//!
//! openssl stamps the current time and cannot be talked out of it, so the seal
//! here is built with openfirma's own CMS writer (`content_type =
//! id-ct-TSTInfo`, the RFC 3161 2.2 shape) over a TSA certificate minted at run
//! time with a ten-year-past `notBefore`: without that certificate a stamp dated
//! in the past would be refused by the rule round two's N8 added — the honest
//! answer to a forged date — and this file would be testing the wrong refusal.
//! The revocation datum is assembled byte by byte for the same reason: openssl's
//! `ocsp` app only ever answers for the future.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use openfirma_cades::revocation::ocsp_issuer_hashes;
use openfirma_cades::verify::VerifyOptions;
use openfirma_cades::{CadesOptions, sign, tsp};
use openfirma_core::alg::DigestAlg;
use openfirma_core::cert::CertificateHandle;
use openfirma_core::oid::ID_CT_TST_INFO;
use openfirma_core::signer::{Signer as _, SoftwareSigner};
use openfirma_core::tlv;
use openfirma_pades::ltv::RevocationBytes;
use openfirma_pades::{PadesOptions, pades_sign, pades_verify};

/// The same fixture the other PAdES tests sign.
const INPUT: &[u8] = include_bytes!("../../../testdata/inputs/simple.pdf");

fn certs_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/certs")
}

/// CI sets OPENFIRMA_REQUIRE_TESTS so a missing tool or PKI fails the build
/// instead of quietly skipping; OPENFIRMA_ALLOW_NONKEYSTORE_SKIP is the only way
/// out and is what a job whose PKI step could not run sets (review 07, H-2).
fn require_or_skip(reason: &str) {
    if std::env::var("OPENFIRMA_REQUIRE_TESTS").is_ok()
        && std::env::var("OPENFIRMA_ALLOW_NONKEYSTORE_SKIP").is_err()
    {
        panic!("cannot run the test: {reason}");
    }
    eprintln!("skipped, {reason}");
}

fn load(name: &str) -> CertificateHandle {
    let pem = std::fs::read_to_string(certs_dir().join(name))
        .unwrap_or_else(|e| panic!("{name} cannot be read: {e}"));
    CertificateHandle::from_pem(&pem).expect("a test PKI certificate")
}

fn text(name: &str) -> String {
    std::fs::read_to_string(certs_dir().join(name)).expect("a test PKI file")
}

fn signer() -> Option<SoftwareSigner> {
    let s = SoftwareSigner::from_pkcs8_pem(&text("signer-rsa.crt"), &text("signer-rsa.key"))
        .expect("the test signer key is PKCS#8 PEM");
    Some(s.with_chain(vec![load("intermediate.crt"), load("ca.crt")]))
}

fn run(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .output()
        .is_ok_and(|o| o.status.success())
}

// ---------------------------------------------------------------------------
// DER helpers. The same small set the openfirma-cades tests use: the two crates
// cannot share test code without a published test-support crate, which is a
// bigger decision than this file needs.

fn der(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if body.len() < 0x80 {
        out.push(body.len() as u8);
    } else {
        let bytes = (body.len() as u32).to_be_bytes();
        let first = bytes.iter().position(|b| *b != 0).unwrap_or(3);
        out.push(0x80 | (4 - first) as u8);
        out.extend_from_slice(&bytes[first..]);
    }
    out.extend_from_slice(body);
    out
}

/// UTCTime, through the writer the CMS code itself uses.
fn utc(when: SystemTime) -> Vec<u8> {
    tlv::utc_time(when).expect("the instant is inside UTCTime's range")
}

/// GeneralizedTime for the same instant: the two-digit year of RFC 5280
/// 4.1.2.5.1 (`50..=99` is 19YY, `00..=49` is 20YY) expanded in front of what
/// `utc` wrote. Written this way on purpose — openfirma-core has no
/// GeneralizedTime writer, and a calendar hand-rolled inside a test is exactly
/// the kind of code that quietly makes a test assert the wrong date.
fn generalized(when: SystemTime) -> Vec<u8> {
    let short = utc(when);
    let text = std::str::from_utf8(&short[2..]).expect("UTCTime is ASCII digits");
    let (yy, rest) = text.split_at(2);
    let century = if yy.parse::<u8>().unwrap_or(0) >= 50 {
        "19"
    } else {
        "20"
    };
    der(0x18, format!("{century}{yy}{rest}").as_bytes())
}

/// `CCYYMMDDHHMMSSZ`, the form openssl's `-not_before` and `-not_after` want,
/// read out of the DER value above so the two spellings cannot disagree.
fn openssl_date(when: SystemTime) -> String {
    let value = generalized(when);
    String::from_utf8_lossy(&value[2..]).to_string()
}

fn sha256_with_rsa() -> Vec<u8> {
    let mut alg = der(
        0x06,
        &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B],
    );
    alg.extend_from_slice(&[0x05, 0x00]);
    der(0x30, &alg)
}

// ---------------------------------------------------------------------------
// The pieces of the document

/// A TSA certificate minted now, valid from ten years ago to a year ahead, so a
/// stamp dated in the past passes the rule that refuses a `genTime` outside the
/// TSA certificate's own validity (01-N8) instead of dying there.
fn mint_tsa_cert(scratch: &Path) -> Option<(CertificateHandle, String)> {
    let dir = certs_dir();
    let csr = scratch.join("tsa-old.csr");
    let ext = scratch.join("tsa-old.ext");
    let crt = scratch.join("tsa-old.crt");
    std::fs::write(
        &ext,
        "basicConstraints = critical, CA:FALSE\nkeyUsage = critical, digitalSignature, \
         nonRepudiation\nextendedKeyUsage = critical, timeStamping\nsubjectKeyIdentifier = \
         hash\n",
    )
    .unwrap();
    let now = SystemTime::now();
    if !run(
        "openssl",
        &[
            "req",
            "-new",
            "-key",
            dir.join("tsa.key").to_str()?,
            "-subj",
            "/CN=TSA de pruebas antigua",
            "-out",
            csr.to_str()?,
        ],
    ) {
        return None;
    }
    let minted = run(
        "openssl",
        &[
            "x509",
            "-req",
            "-in",
            csr.to_str()?,
            "-CA",
            dir.join("ca.crt").to_str()?,
            "-CAkey",
            dir.join("ca.key").to_str()?,
            "-CAcreateserial",
            "-CAserial",
            scratch.join("ca.srl").to_str()?,
            "-not_before",
            &openssl_date(now - Duration::from_secs(3_650 * 86_400)),
            "-not_after",
            &openssl_date(now + Duration::from_secs(365 * 86_400)),
            "-extfile",
            ext.to_str()?,
            "-out",
            crt.to_str()?,
        ],
    );
    if !minted {
        return None;
    }
    let pem = std::fs::read_to_string(&crt).ok()?;
    Some((CertificateHandle::from_pem(&pem).ok()?, pem))
}

fn tsa_signer(cert_pem: &str) -> SoftwareSigner {
    SoftwareSigner::from_pkcs8_pem(cert_pem, &text("tsa.key"))
        .expect("the test TSA key is PKCS#8 PEM")
        .with_chain(vec![load("intermediate.crt"), load("ca.crt")])
}

/// A seal dated `when`, over the bytes the document timestamp is asked to cover.
fn seal_provider(tsa: SoftwareSigner, when: SystemTime) -> openfirma_cades::TimestampFn {
    Arc::new(move |message: &[u8], digest: DigestAlg| {
        assert_eq!(
            digest,
            DigestAlg::Sha256,
            "this file writes its imprint as SHA-256"
        );
        let mut imprint_alg = der(
            0x06,
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
        );
        imprint_alg.extend_from_slice(&[0x05, 0x00]);
        let mut body = der(0x02, &[0x01]); // version 1
        body.extend_from_slice(&der(0x06, &[0x2A, 0x03, 0x04, 0x01])); // policy 1.2.3.4.1
        let mut imprint = der(0x30, &imprint_alg);
        imprint.extend_from_slice(&der(0x04, &DigestAlg::Sha256.digest(message)));
        body.extend_from_slice(&der(0x30, &imprint));
        body.extend_from_slice(&der(0x02, &[0x42, 0x43])); // serialNumber
        body.extend_from_slice(&generalized(when)); // genTime
        let tst_info = der(0x30, &body);
        let token = sign(
            &tst_info,
            &tsa,
            &CadesOptions {
                content_type: ID_CT_TST_INFO,
                encapsulate_content: true,
                ..CadesOptions::default()
            },
        )
        .expect("building the seal");
        Ok(vec![tsp::unsigned_attribute(&token)?])
    })
}

/// A "good" OCSP answer from the intermediate about the signer, speaking for
/// `[from, to)` and nothing else.
fn answer(
    intermediate: &CertificateHandle,
    issuer_key: &SoftwareSigner,
    subject: &CertificateHandle,
    from: SystemTime,
    to: SystemTime,
) -> Vec<u8> {
    let (name_hash, key_hash) =
        ocsp_issuer_hashes(intermediate, DigestAlg::Sha1).expect("the hashes");
    let mut cert_id = der(0x30, &der(0x06, &[0x2B, 0x0E, 0x03, 0x02, 0x1A])); // sha1
    cert_id.extend_from_slice(&der(0x04, &name_hash));
    cert_id.extend_from_slice(&der(0x04, &key_hash));
    cert_id.extend_from_slice(&der(0x02, subject.serial_number().as_bytes()));

    let mut single = der(0x30, &cert_id);
    single.extend_from_slice(&der(0x80, &[])); // good
    single.extend_from_slice(&utc(from)); // thisUpdate, UTCTime
    single.extend_from_slice(&der(0xA0, &generalized(to))); // nextUpdate [0] EXPLICIT

    let responder_id = der(0xA1, &intermediate.subject_der().expect("the subject"));
    let mut tbs_body = responder_id;
    tbs_body.extend_from_slice(&generalized(SystemTime::now())); // producedAt
    tbs_body.extend_from_slice(&der(0x30, &der(0x30, &single)));
    let tbs = der(0x30, &tbs_body);

    let signature = issuer_key
        .sign_prehash(DigestAlg::Sha256, &DigestAlg::Sha256.digest(&tbs))
        .expect("the intermediate signs its answer");
    let mut basic = tbs;
    basic.extend_from_slice(&sha256_with_rsa());
    let mut bits = vec![0x00];
    bits.extend_from_slice(&signature);
    basic.extend_from_slice(&der(0x03, &bits));

    let mut response_bytes = der(
        0x06,
        &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01],
    );
    response_bytes.extend_from_slice(&der(0x04, &der(0x30, &basic)));
    let mut body = der(0x0A, &[0x00]); // responseStatus, ENUMERATED successful
    body.extend_from_slice(&der(0xA0, &der(0x30, &response_bytes)));
    der(0x30, &body)
}

/// The document: B-B signature, B-LT archive carrying `datum` for the signer's
/// CA plus the fixture CRL for the root's link, and, when `seal` is set, a B-LTA
/// document time-stamp dated at `when`.
fn document(
    datum: Vec<u8>,
    seal: Option<openfirma_cades::TimestampFn>,
) -> Result<Vec<u8>, openfirma_core::Error> {
    let signer = signer().expect("test PKI");
    pades_sign(
        INPUT,
        &signer,
        &PadesOptions {
            revocation: vec![
                RevocationBytes::Ocsp(datum),
                RevocationBytes::Crl(
                    std::fs::read(certs_dir().join("ca.crl.der")).expect("the root's CRL"),
                ),
            ],
            document_timestamp: seal,
            ..PadesOptions::default()
        },
    )
}

fn verify(pdf: &[u8]) -> Result<openfirma_pades::DocumentReport, openfirma_core::Error> {
    pades_verify(pdf, &VerifyOptions::new(vec![load("ca.crt")]))
}

/// The seal's instant, in the past by a month: recent enough to be a document
/// anyone would archive, old enough that its CRL has long since aged out.
fn sealed_at() -> SystemTime {
    let rough = SystemTime::now() - Duration::from_secs(30 * 86_400);
    // whole seconds: RFC 3161's GeneralizedTime carries no fraction, so a seal
    // dated with a fraction comes back truncated to the second, and the equality
    // below would then be about a codec rather than about the rule
    UNIX_EPOCH
        + Duration::from_secs(
            rough
                .duration_since(UNIX_EPOCH)
                .expect("after the epoch")
                .as_secs(),
        )
}

/// A B-LT document whose revocation datum expired weeks ago still verifies,
/// because the document carries a verified seal from inside that datum's window:
/// the datum speaks for the moment the document was sealed, which is the moment
/// the level is about. Round two's N10 — before this rule, `verify` refused the
/// document with "the instant being asked about is outside that interval" a week
/// after signing, and a "long term" format lasted one CRL period.
#[test]
fn a_b_lt_document_outlives_the_window_of_its_archived_evidence() {
    let dir = certs_dir();
    if !dir.join("ca.key").exists() || !dir.join("tsa.key").exists() {
        require_or_skip("test PKI with keys missing, rerun tools/gen-testcert.sh");
        return;
    }
    let scratch = std::env::temp_dir().join(format!("openfirma-archived-{}", std::process::id()));
    std::fs::create_dir_all(&scratch).unwrap();
    let Some((_, tsa_pem)) = mint_tsa_cert(&scratch) else {
        require_or_skip("openssl could not mint the TSA certificate");
        return;
    };

    let when = sealed_at();
    let from = when - Duration::from_secs(3600);
    let to = when + Duration::from_secs(3600);
    let intermediate = load("intermediate.crt");
    let issuer_key =
        SoftwareSigner::from_pkcs8_pem(&text("intermediate.crt"), &text("intermediate.key"))
            .expect("the test intermediate key is PKCS#8 PEM");
    let subject = load("signer-rsa.crt");
    let datum = answer(&intermediate, &issuer_key, &subject, from, to);

    // the datum really has aged out: that is the whole point of the test, and
    // asserting it here stops the document passing because the dates drifted
    assert!(
        to < SystemTime::now(),
        "the fixture datum's window closed in the past"
    );

    let seal = seal_provider(tsa_signer(&tsa_pem), when);
    let signed = document(datum.clone(), Some(seal)).expect("a B-LTA document must be produced");

    let report = verify(&signed)
        .expect("an archived datum that covered the sealing moment must still verify today");
    assert!(
        report.document_timestamps[0].verified(),
        "the seal must be verified for the archive to be judged about it: {:?}",
        report.document_timestamps[0].problem
    );
    let dss = report.dss.expect("the document carries validation data");
    assert_eq!(
        dss.evidence_about, when,
        "the verdict must say which instant the archived evidence was judged about"
    );
    assert!(
        !dss.chains.is_empty(),
        "the chain rebuilds from the archive"
    );

    // and the same datum, in a document with no seal to place it, is refused: the
    // wall clock judges, and the window closed a month ago
    let unsealed = document(datum, None).expect("a B-LT document must be produced");
    let err = verify(&unsealed)
        .expect_err("without a seal nothing places the datum, so it must not pass")
        .to_string();
    assert!(
        err.contains("outside that interval"),
        "the refusal must say the window does not reach the instant: {err}"
    );

    std::fs::remove_dir_all(&scratch).ok();
}

/// A document re-sealed later is still judged about its FIRST seal: the archive's
/// data has to speak for the moment the document was first fixed, and the older
/// seal is the weaker, and so the safer, claim. Judging about the newest seal
/// instead would refuse every document whose owner re-sealed after the CRL aged
/// out — which is the same N10 failure one resealing step away — and would also
/// make the level depend on when somebody last clicked "refresh".
#[test]
fn an_archive_is_judged_about_its_first_seal_not_its_last() {
    let dir = certs_dir();
    if !dir.join("ca.key").exists() || !dir.join("tsa.key").exists() {
        require_or_skip("test PKI with keys missing, rerun tools/gen-testcert.sh");
        return;
    }
    let scratch = std::env::temp_dir().join(format!("openfirma-firstseal-{}", std::process::id()));
    std::fs::create_dir_all(&scratch).unwrap();
    let Some((_, tsa_pem)) = mint_tsa_cert(&scratch) else {
        require_or_skip("openssl could not mint the TSA certificate");
        return;
    };

    let first = sealed_at();
    let intermediate = load("intermediate.crt");
    let issuer_key =
        SoftwareSigner::from_pkcs8_pem(&text("intermediate.crt"), &text("intermediate.key"))
            .expect("the test intermediate key is PKCS#8 PEM");
    let datum = answer(
        &intermediate,
        &issuer_key,
        &load("signer-rsa.crt"),
        first - Duration::from_secs(3600),
        first + Duration::from_secs(3600),
    );

    let seal = seal_provider(tsa_signer(&tsa_pem), first);
    let signed = document(datum, Some(seal)).expect("a B-LTA document must be produced");
    // and a second seal, a month later, over everything including the first
    let second = seal_provider(
        tsa_signer(&tsa_pem),
        first + Duration::from_secs(30 * 86_400),
    );
    let resealed =
        openfirma_pades::ltv::add_document_timestamp(&signed, &second, DigestAlg::Sha256, 8192)
            .expect("resealing an archive is allowed");

    let report = verify(&resealed).expect("the first seal is the instant the archive is about");
    assert_eq!(
        report.document_timestamps.len(),
        2,
        "both seals are readable"
    );
    let dss = report.dss.expect("the document carries validation data");
    assert_eq!(
        dss.evidence_about, first,
        "the verdict is about the first seal, not the one added a month later"
    );

    std::fs::remove_dir_all(&scratch).ok();
}

/// An old datum does not become evidence just because the document has a seal: it
/// has to reach the sealed moment. A CRL or OCSP answer from before it proves
/// nothing about a signing that could have happened after it, so a document whose
/// validation data predates every seal in it is refused — the shape that a relaxed
/// "old data is fine in an archive" rule would have let through.
#[test]
fn evidence_that_predates_the_seal_is_still_refused() {
    let dir = certs_dir();
    if !dir.join("ca.key").exists() || !dir.join("tsa.key").exists() {
        require_or_skip("test PKI with keys missing, rerun tools/gen-testcert.sh");
        return;
    }
    let scratch = std::env::temp_dir().join(format!("openfirma-predated-{}", std::process::id()));
    std::fs::create_dir_all(&scratch).unwrap();
    let Some((_, tsa_pem)) = mint_tsa_cert(&scratch) else {
        require_or_skip("openssl could not mint the TSA certificate");
        return;
    };

    let when = sealed_at();
    let from = when - Duration::from_secs(60 * 86_400);
    let to = when - Duration::from_secs(59 * 86_400);
    let intermediate = load("intermediate.crt");
    let issuer_key =
        SoftwareSigner::from_pkcs8_pem(&text("intermediate.crt"), &text("intermediate.key"))
            .expect("the test intermediate key is PKCS#8 PEM");
    let subject = load("signer-rsa.crt");
    let stale = answer(&intermediate, &issuer_key, &subject, from, to);

    let seal = seal_provider(tsa_signer(&tsa_pem), when);
    let signed = document(stale, Some(seal)).expect("a B-LTA document must be produced");
    let err = verify(&signed)
        .expect_err("validation data from before the seal says nothing about the signing")
        .to_string();
    assert!(
        err.contains("outside that interval"),
        "the refusal must name the window and the instant: {err}"
    );

    std::fs::remove_dir_all(&scratch).ok();
}
