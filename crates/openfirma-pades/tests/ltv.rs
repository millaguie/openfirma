//! PAdES B-LT and B-LTA: the validation data archive and the document
//! time-stamp, checked here against openssl, qpdf and poppler on top of
//! `openfirma verify`.
//!
//! The properties that matter, in the order the levels build on each other:
//!
//! - B-LT archives the chain and the revocation data in a `/DSS` the catalog
//!   points at, indexed per signature under `/VRI` by the SHA-1 of the
//!   complete `/Contents` string, exactly the key ETSI EN 319 142-1 names
//!   and the European Commission's DSS validator recomputes;
//! - adding the archive does not disturb the signature: every earlier
//!   signature still verifies, and poppler still calls it valid;
//! - B-LTA appends the document time-stamp after the `/DSS`, its token
//!   imprinting the whole document before it, and `openssl ts` verifies that
//!   token independently;
//! - a CRL signed by the wrong CA is refused by the verifier, and a token
//!   that imprints the wrong bytes is refused at embed time.
//!
//! Skips follow the rules of openssl_crosscheck.rs: missing material skips,
//! unless CI set OPENFIRMA_REQUIRE_TESTS, and material that is present but
//! unusable panics. The OCSP variant is the one exception: some openssl
//! builds cannot answer an OCSP request offline, so its material is optional
//! and its test skips without failing CI. The CRL path is the mandatory one.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

use openfirma_cades::tsp;
use openfirma_cades::verify::VerifyOptions;
use openfirma_core::alg::DigestAlg;
use openfirma_core::cert::CertificateHandle;
use openfirma_core::signer::{Signer, SoftwareSigner};
use openfirma_core::{oid, tlv};
use openfirma_pades::ltv::{RevocationBytes, read_dss, vri_key};
use openfirma_pades::{PadesOptions, inspect, pades_sign, pades_verify};

/// The committed fixture, same document the other PAdES tests sign.
const INPUT: &[u8] = include_bytes!("../../../testdata/inputs/simple.pdf");

fn certs_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/certs")
}

fn require_or_skip(reason: &str) {
    let required = std::env::var("OPENFIRMA_REQUIRE_TESTS").is_ok();
    let allowed = std::env::var("OPENFIRMA_ALLOW_SKIP").is_ok();
    if required && !allowed {
        panic!("cannot run the test: {reason}");
    }
    eprintln!("skipped, {reason}");
}

fn openssl_available() -> bool {
    Command::new("openssl")
        .arg("version")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn qpdf_available() -> bool {
    Command::new("qpdf")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn pdfsig_available() -> bool {
    Command::new("pdfsig")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn run(program: &str, args: &[&str]) -> (bool, String) {
    let out = Command::new(program)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("{program} disappeared mid test: {e}"));
    let text =
        String::from_utf8_lossy(&out.stderr).to_string() + &String::from_utf8_lossy(&out.stdout);
    (out.status.success(), text)
}

/// Temp file named after the running test, because the whole integration test
/// binary is one process and cargo runs tests in parallel threads.
fn write_tmp(name: &str, bytes: &[u8]) -> PathBuf {
    let test = std::thread::current()
        .name()
        .unwrap_or("main")
        .replace("::", "_");
    let path = std::env::temp_dir().join(format!("openfirma-{}-{test}-{name}", std::process::id()));
    std::fs::write(&path, bytes).expect("cannot write temp file");
    path
}

/// Returns None when the material is missing, which skips the test. Present
/// but unloadable material panics, see openssl_crosscheck.rs.
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
    Some(signer.with_chain(cert_handles(chain)))
}

fn cert_handles(names: &[&str]) -> Vec<CertificateHandle> {
    names
        .iter()
        .map(|n| {
            let pem = std::fs::read_to_string(certs_dir().join(n)).unwrap_or_else(|e| {
                panic!("{n} is listed in the test PKI but cannot be read: {e}")
            });
            CertificateHandle::from_pem(&pem).unwrap_or_else(|e| panic!("{n}: {e}"))
        })
        .collect()
}

fn anchors() -> VerifyOptions {
    VerifyOptions::new(cert_handles(&["ca.crt"]))
}

/// The two CRLs of the test PKI: the intermediate's, which covers the
/// signing certificates, and the root's, which covers the intermediate. One
/// datum per CA of the chain, as B-LT requires.
fn crls() -> Option<Vec<RevocationBytes>> {
    let (Ok(int), Ok(ca)) = (
        std::fs::read(certs_dir().join("intermediate.crl.der")),
        std::fs::read(certs_dir().join("ca.crl.der")),
    ) else {
        return None;
    };
    Some(vec![RevocationBytes::Crl(int), RevocationBytes::Crl(ca)])
}

fn rsa_signer() -> Option<SoftwareSigner> {
    load_signer_with_chain("signer-rsa.crt", "signer-rsa.key", &["intermediate.crt"])
}

fn ec_signer() -> Option<SoftwareSigner> {
    load_signer_with_chain("signer-ec.crt", "signer-ec.key", &["intermediate.crt"])
}

/// A `TimestampFn` that answers every query with `openssl ts -reply` and the
/// synthetic TSA of the test PKI, offline, and captures each
/// (message, response) pair so the test can hand them back to openssl.
type Captures = Arc<Mutex<Vec<(Vec<u8>, Vec<u8>)>>>;

fn tsa_provider(captures: Captures) -> openfirma_cades::TimestampFn {
    Arc::new(move |message: &[u8], digest| {
        let query = tsp::request(digest, message, 0x0102_0304)?;
        let q = write_tmp("lta.tsq", &query);
        let r = write_tmp("lta.tsr", b"");
        let dir = certs_dir();
        let (ok, text) = run(
            "openssl",
            &[
                "ts",
                "-reply",
                "-queryfile",
                q.to_str().unwrap(),
                "-out",
                r.to_str().unwrap(),
                "-signer",
                dir.join("tsa.crt").to_str().unwrap(),
                "-inkey",
                dir.join("tsa.key").to_str().unwrap(),
                "-chain",
                dir.join("chain.crt").to_str().unwrap(),
            ],
        );
        assert!(ok, "openssl ts -reply failed:\n{text}");
        let response = std::fs::read(&r).expect("the TSA wrote no response");
        captures
            .lock()
            .unwrap()
            .push((message.to_vec(), response.clone()));
        let token = tsp::token_from_response(&response, digest, message, Some(&query))?;
        Ok(vec![tsp::unsigned_attribute(&token)?])
    })
}

/// The `/VRI` key of a signature, recomputed from the document bytes without
/// going through the library's own helper: SHA-1 over the complete decoded
/// `/Contents` string, padding included, in upper case hex.
fn expected_vri_key(pdf: &[u8], sig: &inspect::Signature) -> String {
    let [_, b, c, _] = sig.byte_range;
    let gap = &pdf[b..c];
    assert_eq!(
        gap.first(),
        Some(&b'<'),
        "the /Contents is not a hex string"
    );
    assert_eq!(gap.last(), Some(&b'>'));
    let raw = hex::decode(&gap[1..gap.len() - 1]).expect("/Contents is not valid hex");
    hex::encode_upper(DigestAlg::Sha1.digest(&raw))
}

fn covered(pdf: &[u8], r: [usize; 4]) -> Vec<u8> {
    let mut out = Vec::with_capacity(r[1] + r[3]);
    out.extend_from_slice(&pdf[r[0]..r[0] + r[1]]);
    out.extend_from_slice(&pdf[r[2]..r[2] + r[3]]);
    out
}

fn find(bytes: &[u8], needle: &[u8]) -> usize {
    bytes
        .windows(needle.len())
        .position(|w| w == needle)
        .unwrap_or_else(|| {
            panic!(
                "{} not found in the document",
                String::from_utf8_lossy(needle)
            )
        })
}

// ---------------------------------------------------------------------------
// B-LT

#[test]
fn b_lt_archives_the_chain_and_the_revocation_data() {
    let Some(signer) = rsa_signer() else {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    let Some(revocation) = crls() else {
        require_or_skip("the test PKI has no CRLs, rerun tools/gen-testcert.sh");
        return;
    };
    let opts = PadesOptions {
        revocation,
        ..PadesOptions::default()
    };
    let signed = pades_sign(INPUT, &signer, &opts).expect("B-LT signing failed");

    // three revisions: the document, the signature, the validation data
    assert_eq!(
        signed.windows(5).filter(|w| *w == b"%%EOF").count(),
        3,
        "B-LT is one incremental update after the signature"
    );
    assert!(signed.starts_with(INPUT), "the original must survive");

    let dss = read_dss(&signed)
        .expect("the /DSS must be readable")
        .expect("a B-LT document has a /DSS");
    // the signer certificate and the chain the signer carries: int and root
    // are not both in it — the signer's chain here is [intermediate], so the
    // archive holds signer + intermediate
    assert_eq!(dss.certs.len(), 2, "signer and intermediate");
    assert_eq!(dss.crls.len(), 2, "one CRL per CA of the chain");
    assert!(dss.ocsps.is_empty());

    // the archived bytes are byte identical with what was handed over
    let int_crl = std::fs::read(certs_dir().join("intermediate.crl.der")).unwrap();
    let ca_crl = std::fs::read(certs_dir().join("ca.crl.der")).unwrap();
    let archived: Vec<&[u8]> = dss.crls.iter().map(|(_, b)| b.as_slice()).collect();
    assert!(
        archived.contains(&int_crl.as_slice()),
        "the intermediate's CRL"
    );
    assert!(archived.contains(&ca_crl.as_slice()), "the root's CRL");

    // /VRI is keyed by the SHA-1 of the complete /Contents string, and the
    // key in the document is the one an independent recomputation produces
    let sigs = inspect::signatures(&signed).expect("the document has one signature");
    assert_eq!(sigs.len(), 1);
    let keys = dss.vri_keys().expect("the /VRI must be readable");
    assert_eq!(keys, vec![expected_vri_key(&signed, &sigs[0])]);
    assert_eq!(keys, vec![vri_key(&signed, &sigs[0]).unwrap()]);

    // and the verifier agrees the archive is sound: chains rebuild from it
    let report = pades_verify(&signed, &anchors()).expect("a B-LT document must verify");
    let dss_report = report.dss.expect("the report carries the /DSS verdict");
    assert_eq!(dss_report.certificates, 2);
    assert_eq!(dss_report.crls.len(), 2);
    assert_eq!(dss_report.chains.len(), 1);
    assert!(dss_report.uncovered.is_empty());
    let chain = &dss_report.chains[0];
    assert_eq!(chain.signature, 1);
    assert!(
        chain.subjects[0].contains("PEREZ GARCIA"),
        "{:?}",
        chain.subjects
    );
    assert!(
        chain.subjects.last().unwrap().contains("Root CA"),
        "the chain rebuilt from the /DSS alone reaches the anchor: {:?}",
        chain.subjects
    );
}

#[test]
fn b_lt_on_a_cosigned_document_covers_both_signatures() {
    let (Some(rsa), Some(ec)) = (rsa_signer(), ec_signer()) else {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    let Some(revocation) = crls() else {
        require_or_skip("the test PKI has no CRLs, rerun tools/gen-testcert.sh");
        return;
    };
    let once = pades_sign(INPUT, &rsa, &PadesOptions::default()).expect("first signing failed");

    // the second signature archives its own chain plus the first signer's
    // certificate, so both chains rebuild from the /DSS alone
    let opts = PadesOptions {
        validation_certs: cert_handles(&["signer-rsa.crt"]),
        revocation,
        ..PadesOptions::default()
    };
    let twice = pades_sign(&once, &ec, &opts).expect("B-LT signing failed");
    assert!(twice.starts_with(&once), "the first revision must survive");

    let dss = read_dss(&twice)
        .expect("readable")
        .expect("the /DSS is there");
    // ec signer + intermediate + the rsa signer handed over in validation_certs
    assert_eq!(dss.certs.len(), 3);

    let sigs = inspect::signatures(&twice).expect("two signatures");
    assert_eq!(sigs.len(), 2);
    let mut keys = dss.vri_keys().expect("readable");
    keys.sort();
    let mut want: Vec<String> = sigs.iter().map(|s| expected_vri_key(&twice, s)).collect();
    want.sort();
    assert_eq!(keys, want, "/VRI carries one key per signature");

    let report = pades_verify(&twice, &anchors()).expect("both signatures must verify");
    assert_eq!(report.signatures.len(), 2);
    let dss_report = report.dss.expect("the /DSS verdict");
    assert_eq!(dss_report.chains.len(), 2, "both chains rebuild");
    assert!(dss_report.uncovered.is_empty());
}

#[test]
fn b_lt_accepts_an_ocsp_response_for_the_intermediate() {
    let Some(signer) = rsa_signer() else {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    let Ok(ocsp) = std::fs::read(certs_dir().join("signer-rsa.ocsp.der")) else {
        // optional material: some openssl builds cannot answer an OCSP
        // request offline, and gen-testcert.sh then leaves this out
        eprintln!("skipped, the test PKI has no OCSP response (openssl could not produce one)");
        return;
    };
    let Ok(ca_crl) = std::fs::read(certs_dir().join("ca.crl.der")) else {
        require_or_skip("the test PKI has no CRLs, rerun tools/gen-testcert.sh");
        return;
    };

    // the response is a real one: openssl's responder produced it for
    // signer-rsa against the intermediate, and it must parse as such
    let ids = openfirma_cades::revocation::parse_ocsp_response(&ocsp)
        .expect("the OCSP response openssl produced must parse");
    assert_eq!(ids.len(), 1);
    assert!(!ids[0].revoked, "the certificate is good");
    assert_eq!(ids[0].hash_algorithm, oid::ID_SHA1);
    assert_eq!(
        ids[0].serial,
        signer.certificate().serial_number().as_bytes(),
        "the response is about the signer certificate"
    );

    // one datum per CA takes any shape: the OCSP response covers the
    // intermediate (its CertID hashes are the intermediate's), the root's
    // CRL covers the root, and the archive is complete without a single
    // intermediate CRL
    let opts = PadesOptions {
        revocation: vec![
            RevocationBytes::Ocsp(ocsp.clone()),
            RevocationBytes::Crl(ca_crl),
        ],
        ..PadesOptions::default()
    };
    let signed = pades_sign(INPUT, &signer, &opts).expect("B-LT signing failed");

    let dss = read_dss(&signed)
        .expect("readable")
        .expect("the /DSS is there");
    assert_eq!(dss.ocsps.len(), 1);
    assert_eq!(dss.crls.len(), 1);
    // the response is archived byte for byte and indexed under /VRI
    assert_eq!(dss.ocsps[0].1, ocsp);
    assert!(
        signed.windows(7).any(|w| w == b"/OCSP ["),
        "the /VRI entry must reference the OCSP stream"
    );

    let report = pades_verify(&signed, &anchors())
        .expect("OCSP for the intermediate plus the root's CRL is a complete archive");
    let dss_report = report.dss.expect("the /DSS verdict");
    assert_eq!(dss_report.ocsps, 1);
    assert_eq!(dss_report.chains.len(), 1);
    assert!(dss_report.uncovered.is_empty());
}

#[test]
fn a_second_b_lt_pass_merges_the_archive() {
    let (Some(rsa), Some(ec), Some(revocation)) = (rsa_signer(), ec_signer(), crls()) else {
        require_or_skip("test PKI or CRLs missing, rerun tools/gen-testcert.sh");
        return;
    };
    let first = pades_sign(
        INPUT,
        &rsa,
        &PadesOptions {
            revocation: revocation.clone(),
            ..PadesOptions::default()
        },
    )
    .expect("first B-LT signing failed");

    // the second signer archives on top of an existing /DSS: its own
    // certificate is new, the intermediate and the first signer's certificate
    // are already there, and both CRLs are byte identical with the archived
    // ones, so nothing may be duplicated and the first /VRI key must survive
    let second = pades_sign(
        &first,
        &ec,
        &PadesOptions {
            validation_certs: cert_handles(&["signer-rsa.crt"]),
            revocation,
            ..PadesOptions::default()
        },
    )
    .expect("second B-LT signing failed");
    assert!(second.starts_with(&first));

    let dss = read_dss(&second)
        .expect("readable")
        .expect("the merged /DSS is there");
    assert_eq!(
        dss.certs.len(),
        3,
        "rsa + intermediate + ec, each archived exactly once"
    );
    assert_eq!(
        dss.crls.len(),
        2,
        "the identical CRLs must not be archived twice"
    );
    let mut keys = dss.vri_keys().expect("readable");
    keys.sort();
    let sigs = inspect::signatures(&second).expect("two signatures");
    let mut want: Vec<String> = sigs.iter().map(|s| expected_vri_key(&second, s)).collect();
    want.sort();
    assert_eq!(keys, want, "both signatures are indexed after the merge");

    let report = pades_verify(&second, &anchors()).expect("the merged archive must verify");
    let dss_report = report.dss.expect("the /DSS verdict");
    assert_eq!(dss_report.chains.len(), 2, "both chains rebuild");
    assert!(dss_report.uncovered.is_empty());
}

#[test]
fn a_signature_added_after_the_archive_is_reported_uncovered() {
    let Some(signer) = rsa_signer() else {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    let Some(revocation) = crls() else {
        require_or_skip("the test PKI has no CRLs, rerun tools/gen-testcert.sh");
        return;
    };
    let lt = pades_sign(
        INPUT,
        &signer,
        &PadesOptions {
            revocation,
            ..PadesOptions::default()
        },
    )
    .expect("B-LT signing failed");
    // a plain B-B signature afterwards: the archive predates it and does not
    // cover it, which is a fact worth reporting, not a failure
    let after = pades_sign(&lt, &signer, &PadesOptions::default()).expect("co-signing failed");
    assert!(
        read_dss(&after).expect("readable").is_some(),
        "the /DSS survives the later signature"
    );

    let report = pades_verify(&after, &anchors()).expect("both signatures still verify");
    assert_eq!(report.signatures.len(), 2);
    let dss = report.dss.expect("the /DSS verdict");
    assert_eq!(
        dss.chains.len(),
        1,
        "the archive covers the first signature"
    );
    assert_eq!(
        dss.uncovered,
        vec![2],
        "and reports the second as uncovered"
    );
}

// ---------------------------------------------------------------------------
// B-LTA

#[test]
fn b_lta_appends_the_document_timestamp_after_the_dss() {
    if !openssl_available() {
        require_or_skip("openssl not found");
        return;
    }
    let (Some(signer), Some(revocation)) = (rsa_signer(), crls()) else {
        require_or_skip("test PKI or CRLs missing, rerun tools/gen-testcert.sh");
        return;
    };
    let captures: Captures = Arc::new(Mutex::new(Vec::new()));
    let provider = tsa_provider(captures.clone());
    let opts = PadesOptions {
        timestamp: Some(provider.clone()),
        revocation,
        document_timestamp: Some(provider),
        ..PadesOptions::default()
    };
    let signed = pades_sign(INPUT, &signer, &opts).expect("B-LTA signing failed");

    // four revisions, in the order the specification names: document,
    // signature (with its B-T token), validation data, document time-stamp
    assert_eq!(signed.windows(5).filter(|w| *w == b"%%EOF").count(), 4);
    let sig_at = find(&signed, b"/SubFilter /ETSI.CAdES.detached");
    let dss_at = find(&signed, b"/Type /DSS");
    let dts_at = find(&signed, b"/Type /DocTimeStamp");
    assert!(
        sig_at < dss_at && dss_at < dts_at,
        "the order is part of the level: signature {sig_at}, /DSS {dss_at}, time-stamp {dts_at}"
    );
    assert!(signed.starts_with(INPUT));

    let stamps = inspect::document_timestamps(&signed).expect("readable");
    assert_eq!(stamps.len(), 1);
    let stamp = &stamps[0];
    assert!(
        stamp.problems.is_empty(),
        "the document time-stamp must be consistent: {:?}",
        stamp.problems
    );
    let [a, b, c, d] = stamp.byte_range;
    assert_eq!(a, 0);
    assert_eq!(c + d, signed.len(), "the stamp covers the whole document");
    assert!(dss_at < b, "the covered bytes include the /DSS");

    // our verifier: signatures, archive and stamp all pass together
    let report = pades_verify(&signed, &anchors()).expect("a B-LTA document must verify");
    assert_eq!(report.document_timestamps.len(), 1);
    assert!(
        report.signatures[0].reports[0]
            .attributes
            .signature_time_stamp_token,
        "B-LTA is B-T underneath: the signature carries its time-stamp token"
    );
    assert!(report.dss.is_some());

    // openssl, independently: the token embedded in the document verifies
    // against exactly the bytes its /ByteRange names
    let covered_bytes = covered(&signed, stamp.byte_range);
    let captured = captures.lock().unwrap();
    let (message, _) = captured
        .last()
        .expect("the provider was called for the document time-stamp");
    assert_eq!(
        message, &covered_bytes,
        "the provider was asked to stamp exactly the covered bytes"
    );
    let data = write_tmp("lta-covered.bin", &covered_bytes);
    let token = write_tmp("lta-token.der", &stamp.token);
    let dir = certs_dir();
    let (ok, text) = run(
        "openssl",
        &[
            "ts",
            "-verify",
            "-data",
            data.to_str().unwrap(),
            "-in",
            token.to_str().unwrap(),
            "-token_in",
            "-CAfile",
            dir.join("ca.crt").to_str().unwrap(),
            "-untrusted",
            dir.join("intermediate.crt").to_str().unwrap(),
        ],
    );
    assert!(
        ok,
        "openssl rejected the document time-stamp token:\n{text}"
    );

    if qpdf_available() {
        let path = write_tmp("lta.pdf", &signed);
        let (ok, text) = run("qpdf", &["--check", path.to_str().unwrap()]);
        assert!(ok, "qpdf found a problem in the B-LTA document:\n{text}");
        assert!(
            !text.contains("WARNING"),
            "qpdf warned about the B-LTA document:\n{text}"
        );
    }
    for p in [data, token] {
        std::fs::remove_file(p).ok();
    }
}

#[test]
fn a_document_timestamp_with_a_wrong_imprint_is_refused() {
    if !openssl_available() {
        require_or_skip("openssl not found");
        return;
    }
    let (Some(signer), Some(revocation)) = (rsa_signer(), crls()) else {
        require_or_skip("test PKI or CRLs missing, rerun tools/gen-testcert.sh");
        return;
    };
    // a provider that stamps something else entirely: the request goes out
    // over fixed bytes, so the token it brings back imprints those
    let provider: openfirma_cades::TimestampFn = Arc::new(move |_message: &[u8], digest| {
        let other = b"otros bytes que no son el documento";
        let query = tsp::request(digest, other, 0x2024)?;
        let q = write_tmp("wrong.tsq", &query);
        let r = write_tmp("wrong.tsr", b"");
        let dir = certs_dir();
        let (ok, text) = run(
            "openssl",
            &[
                "ts",
                "-reply",
                "-queryfile",
                q.to_str().unwrap(),
                "-out",
                r.to_str().unwrap(),
                "-signer",
                dir.join("tsa.crt").to_str().unwrap(),
                "-inkey",
                dir.join("tsa.key").to_str().unwrap(),
                "-chain",
                dir.join("chain.crt").to_str().unwrap(),
            ],
        );
        assert!(ok, "openssl ts -reply failed:\n{text}");
        let response = std::fs::read(&r).expect("the TSA wrote no response");
        let token = tsp::token_from_response(&response, digest, other, Some(&query))?;
        Ok(vec![tsp::unsigned_attribute(&token)?])
    });
    let opts = PadesOptions {
        revocation,
        document_timestamp: Some(provider),
        ..PadesOptions::default()
    };
    let err = pades_sign(INPUT, &signer, &opts)
        .expect_err("a token over other bytes must not be embeddable");
    let text = err.to_string();
    assert!(
        text.contains("imprints a different digest"),
        "the refusal must name the imprint: {text}"
    );
}

// ---------------------------------------------------------------------------
// the archive is only worth what its checks are worth

#[test]
fn verify_rejects_a_crl_signed_by_the_wrong_ca() {
    let Some(signer) = rsa_signer() else {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    let (Ok(ca_crl), Ok(ca_cert), Ok(ca_key), Ok(int_pem)) = (
        std::fs::read(certs_dir().join("ca.crl.der")),
        std::fs::read_to_string(certs_dir().join("ca.crt")),
        std::fs::read_to_string(certs_dir().join("ca.key")),
        std::fs::read_to_string(certs_dir().join("intermediate.crt")),
    ) else {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    let intermediate = CertificateHandle::from_pem(&int_pem).expect("intermediate.crt");
    let root = SoftwareSigner::from_pkcs8_pem(&ca_cert, &ca_key)
        .expect("the root key of the test PKI must load");

    // a well formed CRL that names the intermediate as its issuer but is
    // signed with the root's key: anyone can write a name, only the CA can
    // sign for it
    let now = std::time::SystemTime::now();
    let day = std::time::Duration::from_secs(86_400);
    let alg = tlv::sequence(&[tlv::oid(&oid::ID_SHA256_WITH_RSA).unwrap(), tlv::null()]);
    let tbs = tlv::sequence(&[
        alg.clone(),
        intermediate.subject_der().unwrap(),
        tlv::utc_time(now - day).unwrap(),
        tlv::utc_time(now + 30 * day).unwrap(),
    ]);
    let prehash = DigestAlg::Sha256.digest(&tbs);
    let signature = root.sign_prehash(DigestAlg::Sha256, &prehash).unwrap();
    let forged = tlv::sequence(&[
        tbs,
        alg,
        tlv::tlv(tlv::TAG_BIT_STRING, &[&[0u8][..], &signature].concat()),
    ]);

    let opts = PadesOptions {
        revocation: vec![RevocationBytes::Crl(forged), RevocationBytes::Crl(ca_crl)],
        ..PadesOptions::default()
    };
    // the writer archives what it is given; the verifier is the one that judges
    let signed = pades_sign(INPUT, &signer, &opts).expect("signing with the forged CRL failed");
    let err = pades_verify(&signed, &anchors())
        .expect_err("a CRL signed by the wrong CA must fail verification");
    let text = err.to_string();
    assert!(
        text.contains("signed by a different key"),
        "the refusal must name the cause: {text}"
    );
}

#[test]
fn openssl_verifies_the_crls_we_embed() {
    if !openssl_available() {
        require_or_skip("openssl not found");
        return;
    }
    let (Some(signer), Some(revocation)) = (rsa_signer(), crls()) else {
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
    .expect("B-LT signing failed");
    let dss = read_dss(&signed)
        .expect("readable")
        .expect("the /DSS is there");
    assert_eq!(dss.crls.len(), 2);

    // which embedded CRL belongs to which CA, decided by its issuer name
    let (int, ca) = (
        cert_handles(&["intermediate.crt"]).remove(0),
        cert_handles(&["ca.crt"]).remove(0),
    );
    let mut checked = 0;
    for (i, (_, der)) in dss.crls.iter().enumerate() {
        let issuer = openfirma_cades::revocation::crl_issuer_der(der).expect("a readable CRL");
        let (ca_file, wrong_file) = if issuer == int.subject_der().unwrap() {
            ("intermediate.crt", "ca.crt")
        } else if issuer == ca.subject_der().unwrap() {
            ("ca.crt", "intermediate.crt")
        } else {
            panic!("the embedded CRL {i} names an issuer that is not part of the test PKI");
        };
        let path = write_tmp(&format!("embedded-{i}.crl"), der);
        let (ok, text) = run(
            "openssl",
            &[
                "crl",
                "-inform",
                "DER",
                "-in",
                path.to_str().unwrap(),
                "-verify",
                "-CAfile",
                certs_dir().join(ca_file).to_str().unwrap(),
                "-noout",
            ],
        );
        assert!(ok, "openssl rejected the CRL we embedded:\n{text}");

        // and the check bites: under any other CA's certificate it must fail
        let (bad, _) = run(
            "openssl",
            &[
                "crl",
                "-inform",
                "DER",
                "-in",
                path.to_str().unwrap(),
                "-verify",
                "-CAfile",
                certs_dir().join(wrong_file).to_str().unwrap(),
                "-noout",
            ],
        );
        assert!(
            !bad,
            "openssl accepted the CRL under the wrong CA, so -verify proves nothing"
        );
        std::fs::remove_file(path).ok();
        checked += 1;
    }
    assert_eq!(checked, 2);
}

// ---------------------------------------------------------------------------
// the non-regression property: adding the long-term layers must not
// invalidate anything that was already signed

#[test]
fn pdfsig_still_validates_earlier_signatures_after_ltv() {
    if !pdfsig_available() {
        eprintln!("skipped, pdfsig (poppler-utils) not found");
        return;
    }
    if !openssl_available() {
        eprintln!("skipped, the B-LTA document needs openssl as its TSA");
        return;
    }
    let (Some(rsa), Some(ec), Some(revocation)) = (rsa_signer(), ec_signer(), crls()) else {
        require_or_skip("test PKI or CRLs missing, rerun tools/gen-testcert.sh");
        return;
    };
    let once = pades_sign(INPUT, &rsa, &PadesOptions::default()).expect("first signing failed");
    let captures: Captures = Arc::new(Mutex::new(Vec::new()));
    let provider = tsa_provider(captures);
    let twice = pades_sign(
        &once,
        &ec,
        &PadesOptions {
            timestamp: Some(provider.clone()),
            revocation,
            document_timestamp: Some(provider),
            ..PadesOptions::default()
        },
    )
    .expect("B-LTA signing failed");

    let path = write_tmp("ltv-cosigned.pdf", &twice);
    let (ok, text) = run("pdfsig", &[path.to_str().unwrap()]);
    std::fs::remove_file(path).ok();
    assert!(ok, "pdfsig failed to read the B-LTA document:\n{text}");

    // both signatures must still be valid: the first one is untouched bytes
    // from poppler's point of view, and the archive and the time-stamp are
    // revisions after it. The TSA is not trusted and poppler will say so;
    // that is the certificate verdict, not the signature verdict.
    let valid = text.matches("Signature is Valid").count();
    assert!(
        valid >= 2,
        "poppler must still call both signatures valid, found {valid} in:\n{text}"
    );
    assert!(
        !text.contains("Signature is Invalid"),
        "poppler reports an invalid signature:\n{text}"
    );
    assert!(
        !text.contains("MessageDigest Mismatch") && !text.contains("Digest Mismatch"),
        "poppler reports a digest problem:\n{text}"
    );
}

#[test]
fn qpdf_reads_the_b_lt_document() {
    if !qpdf_available() {
        eprintln!("skipped, qpdf not found");
        return;
    }
    let (Some(signer), Some(revocation)) = (rsa_signer(), crls()) else {
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
    .expect("B-LT signing failed");
    let path = write_tmp("lt.pdf", &signed);
    let (ok, text) = run("qpdf", &["--check", path.to_str().unwrap()]);
    std::fs::remove_file(path).ok();
    assert!(
        ok,
        "qpdf found a syntax problem in the B-LT document:\n{text}"
    );
    assert!(
        !text.contains("WARNING"),
        "qpdf warned about the B-LT document:\n{text}"
    );
}
