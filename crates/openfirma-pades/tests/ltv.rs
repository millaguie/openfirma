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
use openfirma_cades::verify::{AnchorPolicy, VerifyOptions};
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
        panic!("cannot run the test: {reason}");
    }
    eprintln!("skipped, {reason}");
}

/// A crosscheck TOOL unprovisioned on this platform, which is a different fact
/// from a missing test PKI (the one require_or_skip guards). The runner names
/// exactly WHICH tools it cannot have in OPENFIRMA_ALLOW_MISSING_TOOL (a
/// comma/space list), so an unlisted tool's absence still fails the job: on
/// Windows qpdf and poppler install from Chocolatey and their crosschecks run,
/// while xmlsec1 has no Windows package at all and only it is excused. Missing
/// material must still fail under REQUIRE_TESTS — review 07, H-2 forbids one
/// flag relaxing both.
fn tool_or_skip(tool: &str, reason: &str) {
    let required = std::env::var("OPENFIRMA_REQUIRE_TESTS").is_ok();
    let excused = std::env::var("OPENFIRMA_ALLOW_MISSING_TOOL")
        .is_ok_and(|list| list.split([',', ' ', ';']).any(|t| t.trim() == tool));
    if required && !excused {
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
    // `--version` is not a pdfsig argument: it treats it as a file name and
    // fails, which once made this probe answer false on machines that had
    // poppler installed and silently skipped the test forever. `-v` with no
    // file prints the usage and exits 0 — that is the probe. See the same
    // fix in tests/openssl_crosscheck.rs.
    Command::new("pdfsig")
        .arg("-v")
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

    // 06-C-1, the PAdES half: rebuilding the chain from the archive alone is
    // the same "who issued it" question the CMS verdict skips when no
    // authority is named. The document is still judged — every archived
    // certificate parses, every CRL and OCSP response verifies under its
    // issuer's key, the /VRI coverage is checked — and the chain nobody can
    // name is reported as not rebuilt instead of failing the whole document.
    let unanchored = VerifyOptions {
        trust_anchors: Vec::new(),
        anchors: AnchorPolicy::IntegrityWithoutAnchors,
        ..anchors()
    };
    let report = pades_verify(&signed, &unanchored)
        .expect("no anchor is needed for the checks that do not use one");
    assert_eq!(report.signatures[0].reports[0].trust_anchor, None);
    let dss_report = report.dss.expect("the /DSS verdict");
    assert!(dss_report.chains.is_empty(), "{:?}", dss_report.chains);
    // The response was issued by the intermediate, which IS archived, so it
    // was checked even without an anchor. The root's CRL names a CA that is
    // neither archived nor (here) an anchor, so nobody could check it: it is
    // counted as unchecked, never reported as a verified datum.
    assert_eq!(dss_report.ocsps, 1);
    assert!(dss_report.crls.is_empty(), "{:?}", dss_report.crls);
    assert_eq!(dss_report.unchecked, 1);
    assert!(
        dss_report.uncovered.is_empty(),
        "whether the /VRI covers every signature is not a chain question"
    );
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

/// A signer that waits for the clock's next second before every signature: two
/// passes through it can never share a whole-second timestamp, which is exactly
/// the timing CI's macOS runner produced and local runners never reproduced.
#[test]
fn co_signing_across_a_second_boundary_still_verifies() {
    let Some(signer) = rsa_signer() else {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    let Some(revocation) = crls() else {
        require_or_skip("the test PKI has no CRLs, rerun tools/gen-testcert.sh");
        return;
    };
    let signer = NextSecond { inner: signer };
    // B-LT, then a co-sign in a different second (the CI failure): the archive
    // pass must not refuse over the second signing's ModDate landing at a new
    // timestamp — and with the whole-second clock that never happened before,
    // because two timestamps also meant two fresh /Info copies under CI. The
    // rewrite rule in revisions.rs is what makes the shared-number shape (the
    // co-sign following the document's own /Info) safe across seconds.
    let lt = pades_sign(
        INPUT,
        &signer,
        &PadesOptions {
            revocation,
            ..PadesOptions::default()
        },
    )
    .expect("B-LT signing failed");
    let after = pades_sign(&lt, &signer, &PadesOptions::default()).expect("co-signing failed");
    let report = pades_verify(&after, &anchors()).expect("B-LT then co-sign must verify");
    assert_eq!(report.signatures.len(), 2);
    // and a third pass in yet another second: the rule is not one-edge luck.
    let three =
        pades_sign(&after, &signer, &PadesOptions::default()).expect("third signing failed");
    let report = pades_verify(&three, &anchors()).expect("three co-signs must verify");
    assert_eq!(report.signatures.len(), 3);
}

/// Wrapper signer: sleeps until the raw clock leaves its current second, so each
/// signature it makes carries a timestamp no earlier one shares.
struct NextSecond {
    inner: SoftwareSigner,
}

impl Signer for NextSecond {
    fn certificate(&self) -> &CertificateHandle {
        self.inner.certificate()
    }
    fn chain(&self) -> &[CertificateHandle] {
        self.inner.chain()
    }
    fn sign_prehash(
        &self,
        digest: openfirma_core::alg::DigestAlg,
        prehash: &[u8],
    ) -> openfirma_core::Result<Vec<u8>> {
        use std::time::{Duration, SystemTime, UNIX_EPOCH};
        let now = || {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
        };
        let at = now();
        while now() == at {
            std::thread::sleep(Duration::from_millis(30));
        }
        self.inner.sign_prehash(digest, prehash)
    }
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
        report.document_timestamps[0].verified(),
        "a genuine document time-stamp must come back VERIFIED (its TSA signature \
         checked against the anchors), not merely present: {:?}",
        report.document_timestamps[0].problem
    );
    assert!(
        report.document_timestamps[0].gen_time.is_some(),
        "a verified document time-stamp must expose the genTime B-LTA asserts"
    );
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

/// The A-2 false green, pinned: a document time-stamp whose TSA has nothing to
/// do with the trust anchors is reported as PRESENT but NOT VERIFIED, and the
/// report's `verified()` stays false. Before the fix, `verify` never ran the
/// TSA's signature check over a `/Type /DocTimeStamp`, so a self-signed
/// attacker seal looked exactly like a genuine one and the GUI printed "nivel
/// B-LTA" over zero cryptographic evidence. The seal here is cryptographically
/// sound in ITSELF (openssl produced a real token) but its TSA is a throwaway
/// self-signed authority, so only the binding to the anchors can refuse it.
#[test]
fn a_document_timestamp_from_an_unknown_tsa_is_not_reported_as_verified() {
    if !openssl_available() {
        require_or_skip("openssl not found");
        return;
    }
    let (Some(signer), Some(revocation)) = (rsa_signer(), crls()) else {
        require_or_skip("test PKI or CRLs missing, rerun tools/gen-testcert.sh");
        return;
    };
    // a throwaway TSA that no anchor vouches for: self-signed, its own chain
    let dir = std::env::temp_dir().join(format!("openfirma-rogue-tsa-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let key = dir.join("rogue.key");
    let crt = dir.join("rogue.crt");
    let (ok, text) = run(
        "openssl",
        &[
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            key.to_str().unwrap(),
            "-out",
            crt.to_str().unwrap(),
            "-days",
            "3650",
            "-subj",
            "/CN=Rogue TSA/O=Evil",
            "-addext",
            "extendedKeyUsage=critical,timeStamping",
        ],
    );
    assert!(ok, "generating the rogue TSA failed:\n{text}");

    let (kc, cc) = (key.clone(), crt.clone());
    // openssl's ts -reply needs a TSA section with a writable serial file, the
    // same recipe the other TSA tests use; without it openssl falls back to its
    // system config and dies looking for a certificate it does not have.
    let cnf = dir.join("rogue-tsa.cnf");
    std::fs::write(dir.join("tsaserial"), "4242\n").unwrap();
    std::fs::write(
        &cnf,
        format!(
            "[tsa]\ndefault_tsa = tsa_config1\n[tsa_config1]\nserial = {}\ncrypto_device = builtin\ndefault_policy = 1.2.3.4.1\ndigests = sha256\naccuracy = secs:1\nordering = no\ntsa_name = no\ness_cert_id_chain = no\ness_cert_id_alg = sha256\nsigner_digest = sha256\n",
            dir.join("tsaserial").display()
        ),
    )
    .unwrap();
    let provider: openfirma_cades::TimestampFn = Arc::new(move |message: &[u8], digest| {
        let query = tsp::request(digest, message, 0x0777)?;
        let q = write_tmp("rogue.tsq", &query);
        let r = write_tmp("rogue.tsr", b"");
        let (ok, text) = run(
            "openssl",
            &[
                "ts",
                "-reply",
                "-config",
                cnf.to_str().unwrap(),
                "-queryfile",
                q.to_str().unwrap(),
                "-out",
                r.to_str().unwrap(),
                "-signer",
                cc.to_str().unwrap(),
                "-inkey",
                kc.to_str().unwrap(),
            ],
        );
        assert!(ok, "openssl ts -reply with the rogue TSA failed:\n{text}");
        let response = std::fs::read(&r).expect("the TSA wrote no response");
        let token = tsp::token_from_response(&response, digest, message, Some(&query))?;
        Ok(vec![tsp::unsigned_attribute(&token)?])
    });
    let opts = PadesOptions {
        revocation,
        document_timestamp: Some(provider),
        ..PadesOptions::default()
    };
    let signed = pades_sign(INPUT, &signer, &opts)
        .expect("signing with a document time-stamp must succeed even for a rogue TSA");
    std::fs::remove_dir_all(&dir).ok();

    let report = pades_verify(&signed, &anchors())
        .expect("the document is still sound: the seal's failure is not the signature's");
    assert_eq!(report.document_timestamps.len(), 1);
    let dts = &report.document_timestamps[0];
    assert!(
        !dts.verified(),
        "a document time-stamp from an unknown TSA must NOT be reported verified"
    );
    assert!(
        dts.gen_time.is_none(),
        "an unverified seal must not expose a genTime a B-LTA level could assert"
    );
    assert!(
        dts.problem.as_deref().is_some_and(|p| !p.is_empty()),
        "an unverified seal must say why, never fail silently"
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

/// Same as [`write_tmp`] but for a file a tool will create: the name has to be
/// unique per test, not per test *and* content.
fn tmp_path(name: &str) -> PathBuf {
    let test = std::thread::current()
        .name()
        .unwrap_or("main")
        .replace("::", "_");
    std::env::temp_dir().join(format!("openfirma-{}-{test}-{name}", std::process::id()))
}

/// Round 2, N3, the CRL half. A CRL was accepted as soon as *some* certificate
/// in the archive (or an anchor) carried the name it claims as issuer and its
/// key verified the signature. So a self-signed impostor — the CA's subject
/// copied byte for byte, a key of its own, `cRLSign` inherited from the copied
/// extensions — signed an empty CRL, and the archive looked complete while the
/// real CRL, the one every conforming validator reads, revoked the signer.
///
/// The datum has to be bound to the certificate it speaks for: the CRL that
/// counts for a link of the chain must verify under that link's parent, the
/// chain certificate itself.
#[test]
fn a_crl_signed_by_an_impostor_copying_the_ca_name_is_not_a_datum() {
    if !openssl_available() {
        require_or_skip("openssl not found");
        return;
    }
    let Some(signer) = rsa_signer() else {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    let Ok(ca_crl) = std::fs::read(certs_dir().join("ca.crl.der")) else {
        require_or_skip("the test PKI has no CRLs, rerun tools/gen-testcert.sh");
        return;
    };
    let intermediate = cert_handles(&["intermediate.crt"]).remove(0);

    // the impostor: openssl copies the intermediate's subject into a new
    // certificate and re-signs it with a key of its own
    let key = tmp_path("impostor.key");
    let pubkey = tmp_path("impostor.pub");
    let cert = tmp_path("impostor.crt");
    let (ok, text) = run(
        "openssl",
        &[
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
            "-out",
            key.to_str().unwrap(),
        ],
    );
    assert!(ok, "openssl genpkey failed:\n{text}");
    let (ok, text) = run(
        "openssl",
        &[
            "pkey",
            "-in",
            key.to_str().unwrap(),
            "-pubout",
            "-out",
            pubkey.to_str().unwrap(),
        ],
    );
    assert!(ok, "openssl pkey failed:\n{text}");
    let (ok, text) = run(
        "openssl",
        &[
            "x509",
            "-in",
            certs_dir().join("intermediate.crt").to_str().unwrap(),
            "-force_pubkey",
            pubkey.to_str().unwrap(),
            "-signkey",
            key.to_str().unwrap(),
            "-set_serial",
            "7",
            "-out",
            cert.to_str().unwrap(),
        ],
    );
    assert!(ok, "openssl could not mint the impostor:\n{text}");
    let impostor_cert_pem =
        std::fs::read_to_string(&cert).expect("openssl wrote the impostor certificate");
    let impostor_key_pem = std::fs::read_to_string(&key).expect("openssl wrote the impostor key");
    let impostor = SoftwareSigner::from_pkcs8_pem(&impostor_cert_pem, &impostor_key_pem)
        .expect("the impostor key must load");
    let impostor_handle =
        CertificateHandle::from_pem(&impostor_cert_pem).expect("the impostor certificate parses");
    // the impostor wears the CA's name: that is the whole attack
    assert_eq!(
        impostor_handle.subject_der().unwrap(),
        intermediate.subject_der().unwrap(),
        "the impostor's subject must be the intermediate's byte for byte"
    );

    // an empty CRL naming the intermediate as its issuer, signed by the impostor
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
    let signature = impostor
        .sign_prehash(DigestAlg::Sha256, &prehash)
        .expect("the impostor signs with its own key");
    let forged = tlv::sequence(&[
        tbs,
        alg,
        tlv::tlv(tlv::TAG_BIT_STRING, &[&[0u8][..], &signature].concat()),
    ]);

    // it is a real statement of the impostor's, and nothing the CA said
    assert!(
        openfirma_cades::revocation::verify_crl(
            &forged,
            std::slice::from_ref(&impostor_handle),
            openfirma_cades::revocation::RevocationTime::at(now),
        )
        .is_ok(),
        "the impostor really signed this CRL: the archive has a readable datum"
    );
    assert!(
        openfirma_cades::revocation::verify_crl(
            &forged,
            std::slice::from_ref(&intermediate),
            openfirma_cades::revocation::RevocationTime::at(now),
        )
        .is_err(),
        "the CA whose name the CRL carries never signed it"
    );

    let opts = PadesOptions {
        validation_certs: vec![impostor_handle],
        revocation: vec![RevocationBytes::Crl(forged), RevocationBytes::Crl(ca_crl)],
        ..PadesOptions::default()
    };
    let signed =
        pades_sign(INPUT, &signer, &opts).expect("signing with the impostor material failed");
    let dss = read_dss(&signed)
        .expect("readable")
        .expect("the /DSS is there");
    assert_eq!(dss.crls.len(), 2, "both CRLs are archived");

    let err = pades_verify(&signed, &anchors()).expect_err(
        "a CRL signed by a certificate wearing the CA's name is not the CA's revocation state",
    );
    let text = err.to_string();
    assert!(
        text.contains("carries no revocation datum issued by")
            && text.contains("Test Intermediate CA"),
        "the refusal must name the link that has no datum, not the pool: {text}"
    );
}

/// Round 2, N4. A leaf certificate issued by the CA with **no** extendedKeyUsage
/// extension served as an OCSP responder for it: the reader treated the absence
/// as "any purpose" (the RFC 5280 reading for a leaf), so anyone holding a
/// certificate from the CA — a citizen's, an employee's — could answer for every
/// other certificate that CA ever issued. RFC 6960 4.2.2.2 requires
/// `id-kp-OCSPSigning` of a delegated responder, and requires the CA to have
/// issued that responder directly.
#[test]
fn an_ocsp_response_from_a_responder_without_the_signing_eku_is_not_a_datum() {
    if !openssl_available() {
        require_or_skip("openssl not found");
        return;
    }
    let Some(signer) = rsa_signer() else {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    let (Ok(ca_crl), Ok(int_pem)) = (
        std::fs::read(certs_dir().join("ca.crl.der")),
        std::fs::read_to_string(certs_dir().join("intermediate.crt")),
    ) else {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    let intermediate = CertificateHandle::from_pem(&int_pem).expect("intermediate.crt");
    let Ok(ca_pem) = std::fs::read_to_string(certs_dir().join("ca.crt")) else {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    let ca = CertificateHandle::from_pem(&ca_pem).expect("ca.crt");

    // a certificate issued directly by the intermediate, with no EKU at all:
    // digitalSignature and nothing else, which is what millions of ordinary
    // certificates look like
    let key = tmp_path("no-eku.key");
    let csr = tmp_path("no-eku.csr");
    let crt = tmp_path("no-eku.crt");
    let ext = write_tmp(
        "no-eku.ext",
        b"basicConstraints = critical, CA:FALSE\nkeyUsage = critical, digitalSignature\n",
    );
    let (ok, text) = run(
        "openssl",
        &[
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
            "-out",
            key.to_str().unwrap(),
        ],
    );
    assert!(ok, "openssl genpkey failed:\n{text}");
    let (ok, text) = run(
        "openssl",
        &[
            "req",
            "-new",
            "-key",
            key.to_str().unwrap(),
            "-subj",
            "/C=ES/O=openfirma test/OU=Test PKI/CN=openfirma No EKU Responder",
            "-out",
            csr.to_str().unwrap(),
        ],
    );
    assert!(ok, "openssl req failed:\n{text}");
    let (ok, text) = run(
        "openssl",
        &[
            "x509",
            "-req",
            "-in",
            csr.to_str().unwrap(),
            "-CA",
            certs_dir().join("intermediate.crt").to_str().unwrap(),
            "-CAkey",
            certs_dir().join("intermediate.key").to_str().unwrap(),
            "-set_serial",
            "4242",
            "-days",
            "3650",
            "-sha256",
            "-extfile",
            ext.to_str().unwrap(),
            "-out",
            crt.to_str().unwrap(),
        ],
    );
    assert!(
        ok,
        "openssl could not issue the no-EKU certificate:\n{text}"
    );

    let resp = tmp_path("no-eku.ocsp.der");
    let index = write_tmp(
        "no-eku.index",
        format!(
            "V\t491231235959Z\t\t{}\tunknown\t{}\n",
            hex::encode_upper(signer.certificate().serial_number().as_bytes()),
            "C=ES, O=openfirma test, OU=AC openfirma Usuarios, CN=PEREZ GARCIA, ANA"
        )
        .as_bytes(),
    );
    let request = tmp_path("no-eku.req");
    let (ok, text) = run(
        "openssl",
        &[
            "ocsp",
            "-reqout",
            request.to_str().unwrap(),
            "-issuer",
            certs_dir().join("intermediate.crt").to_str().unwrap(),
            "-cert",
            certs_dir().join("signer-rsa.crt").to_str().unwrap(),
            "-no_nonce",
        ],
    );
    assert!(ok, "openssl could not build the OCSP request:\n{text}");
    let (ok, text) = run(
        "openssl",
        &[
            "ocsp",
            "-index",
            index.to_str().unwrap(),
            "-CA",
            certs_dir().join("intermediate.crt").to_str().unwrap(),
            "-rsigner",
            crt.to_str().unwrap(),
            "-rkey",
            key.to_str().unwrap(),
            "-reqin",
            request.to_str().unwrap(),
            "-respout",
            resp.to_str().unwrap(),
            "-ndays",
            "3650",
        ],
    );
    assert!(ok, "openssl could not sign the OCSP response:\n{text}");
    let resp = std::fs::read(&resp).expect("openssl wrote the OCSP response");

    // a well formed "good" answer about the signer, from that leaf
    let ids = openfirma_cades::revocation::parse_ocsp_response(&resp)
        .expect("the response openssl produced must parse");
    assert_eq!(ids.len(), 1);
    assert!(!ids[0].revoked);
    assert_eq!(
        ids[0].serial,
        signer.certificate().serial_number().as_bytes(),
        "the answer is about the signer"
    );
    let status = openfirma_cades::read_ocsp_response(
        &resp,
        &[ca.clone(), intermediate.clone()],
        openfirma_cades::revocation::RevocationTime::at(std::time::SystemTime::now()),
    );
    assert!(
        !status.verified(),
        "a responder without id-kp-OCSPSigning is not a responder: {status:?}"
    );

    let opts = PadesOptions {
        revocation: vec![RevocationBytes::Ocsp(resp), RevocationBytes::Crl(ca_crl)],
        ..PadesOptions::default()
    };
    let signed =
        pades_sign(INPUT, &signer, &opts).expect("signing with the forged response failed");
    let err = pades_verify(&signed, &anchors()).expect_err(
        "an OCSP answer signed by a certificate of the CA without the OCSP signing EKU is not a datum",
    );
    let text = err.to_string();
    assert!(
        text.contains("OCSP response 1") && text.contains("not a revocation datum"),
        "the refusal must name the archived response: {text}"
    );
}

/// Round 2, N4, the second half of the delegation rule: the delegate had to
/// *chain* to the CA, not be issued by it. RFC 6960 4.2.2.2 authorizes a
/// responder the CA issues, and a certificate hanging from a sub-CA of that CA
/// is not one — the CA never authorized it, the sub-CA did.
#[test]
fn an_ocsp_responder_that_hangs_from_a_sub_ca_is_not_a_delegate() {
    if !openssl_available() {
        require_or_skip("openssl not found");
        return;
    }
    let Some(signer) = rsa_signer() else {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    let (Ok(ca_crl), Ok(int_pem), Ok(ca_pem)) = (
        std::fs::read(certs_dir().join("ca.crl.der")),
        std::fs::read_to_string(certs_dir().join("intermediate.crt")),
        std::fs::read_to_string(certs_dir().join("ca.crt")),
    ) else {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    let intermediate = CertificateHandle::from_pem(&int_pem).expect("intermediate.crt");
    let ca = CertificateHandle::from_pem(&ca_pem).expect("ca.crt");
    let int_crt = certs_dir().join("intermediate.crt");
    let int_key = certs_dir().join("intermediate.key");

    // a sub-CA under the intermediate, and a responder the sub-CA issues with
    // the OCSP signing EKU: a proper delegation, from the wrong CA
    let sub_key = tmp_path("sub-ca.key");
    let sub_csr = tmp_path("sub-ca.csr");
    let sub_crt = tmp_path("sub-ca.crt");
    let sub_ext = write_tmp(
        "sub-ca.ext",
        b"basicConstraints = critical, CA:TRUE, pathlen:0\nkeyUsage = critical, keyCertSign, cRLSign\n",
    );
    let r_key = tmp_path("sub-responder.key");
    let r_csr = tmp_path("sub-responder.csr");
    let r_crt = tmp_path("sub-responder.crt");
    let r_ext = write_tmp(
        "sub-responder.ext",
        b"basicConstraints = critical, CA:FALSE\nkeyUsage = critical, digitalSignature\nextendedKeyUsage = critical, OCSPSigning\n",
    );
    for (key, csr, subj) in [
        (
            &sub_key,
            &sub_csr,
            "/C=ES/O=openfirma test/OU=Test PKI/CN=openfirma Sub CA",
        ),
        (
            &r_key,
            &r_csr,
            "/C=ES/O=openfirma test/OU=Test PKI/CN=openfirma Sub CA Responder",
        ),
    ] {
        let (ok, text) = run(
            "openssl",
            &[
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
                key.to_str().unwrap(),
            ],
        );
        assert!(ok, "openssl genpkey failed:\n{text}");
        let (ok, text) = run(
            "openssl",
            &[
                "req",
                "-new",
                "-key",
                key.to_str().unwrap(),
                "-subj",
                subj,
                "-out",
                csr.to_str().unwrap(),
            ],
        );
        assert!(ok, "openssl req failed:\n{text}");
    }
    let (ok, text) = run(
        "openssl",
        &[
            "x509",
            "-req",
            "-in",
            sub_csr.to_str().unwrap(),
            "-CA",
            int_crt.to_str().unwrap(),
            "-CAkey",
            int_key.to_str().unwrap(),
            "-set_serial",
            "9001",
            "-days",
            "3650",
            "-sha256",
            "-extfile",
            sub_ext.to_str().unwrap(),
            "-out",
            sub_crt.to_str().unwrap(),
        ],
    );
    assert!(ok, "openssl could not issue the sub-CA:\n{text}");
    let (ok, text) = run(
        "openssl",
        &[
            "x509",
            "-req",
            "-in",
            r_csr.to_str().unwrap(),
            "-CA",
            sub_crt.to_str().unwrap(),
            "-CAkey",
            sub_key.to_str().unwrap(),
            "-set_serial",
            "9002",
            "-days",
            "3650",
            "-sha256",
            "-extfile",
            r_ext.to_str().unwrap(),
            "-out",
            r_crt.to_str().unwrap(),
        ],
    );
    assert!(ok, "openssl could not issue the responder:\n{text}");

    // an answer about the signer, signed by that responder, with its own chain
    // embedded in the response (`-rother`) so that nothing is missing to build
    // it: the delegation itself is what has to be refused
    let resp = tmp_path("sub-responder.ocsp.der");
    let index = write_tmp(
        "sub-responder.index",
        format!(
            "V\t491231235959Z\t\t{}\tunknown\t{}\n",
            hex::encode_upper(signer.certificate().serial_number().as_bytes()),
            "C=ES, O=openfirma test, OU=AC openfirma Usuarios, CN=PEREZ GARCIA, ANA"
        )
        .as_bytes(),
    );
    let request = tmp_path("sub-responder.req");
    let (ok, text) = run(
        "openssl",
        &[
            "ocsp",
            "-reqout",
            request.to_str().unwrap(),
            "-issuer",
            int_crt.to_str().unwrap(),
            "-cert",
            certs_dir().join("signer-rsa.crt").to_str().unwrap(),
            "-no_nonce",
        ],
    );
    assert!(ok, "openssl could not build the OCSP request:\n{text}");
    let (ok, text) = run(
        "openssl",
        &[
            "ocsp",
            "-index",
            index.to_str().unwrap(),
            "-CA",
            int_crt.to_str().unwrap(),
            "-rsigner",
            r_crt.to_str().unwrap(),
            "-rkey",
            r_key.to_str().unwrap(),
            "-rother",
            sub_crt.to_str().unwrap(),
            "-reqin",
            request.to_str().unwrap(),
            "-respout",
            resp.to_str().unwrap(),
            "-ndays",
            "3650",
        ],
    );
    assert!(ok, "openssl could not sign the OCSP response:\n{text}");
    let resp = std::fs::read(&resp).expect("openssl wrote the OCSP response");

    // the signature is the responder's, the delegation is the sub-CA's
    let status = openfirma_cades::read_ocsp_response(
        &resp,
        &[ca.clone(), intermediate.clone()],
        openfirma_cades::revocation::RevocationTime::at(std::time::SystemTime::now()),
    );
    assert!(
        status.signature_verified,
        "the responder really signed this answer: {status:?}"
    );
    assert!(
        !status.chains_to_issuer,
        "a responder the intermediate's sub-CA issued is not a delegate the \
         intermediate authorized: {status:?}"
    );

    let opts = PadesOptions {
        revocation: vec![RevocationBytes::Ocsp(resp), RevocationBytes::Crl(ca_crl)],
        ..PadesOptions::default()
    };
    let signed = pades_sign(INPUT, &signer, &opts).expect("signing failed");
    let err = pades_verify(&signed, &anchors())
        .expect_err("a delegation from a sub-CA is not a delegation from the CA");
    let text = err.to_string();
    assert!(
        text.contains("OCSP response 1") && text.contains("not a revocation datum"),
        "the refusal must name the archived response: {text}"
    );
}

/// Round 2, N5. An OCSP response only had to name the CA; the serial number it
/// answers about was read (for the "revoked" verdict) but never required to be
/// the child's. So the CA's ordinary public responder — which anyone can ask
/// about their own certificate — produced a genuine "good" answer about a
/// *different* certificate, and the archive counted it as though it covered
/// the signer.
#[test]
fn an_ocsp_response_about_another_certificate_is_not_a_datum() {
    if !openssl_available() {
        require_or_skip("openssl not found");
        return;
    }
    let Some(signer) = rsa_signer() else {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    let (Ok(ca_crl), Ok(good_ocsp), Ok(int_pem), Ok(ca_pem)) = (
        std::fs::read(certs_dir().join("ca.crl.der")),
        std::fs::read(certs_dir().join("signer-rsa.ocsp.der")),
        std::fs::read_to_string(certs_dir().join("intermediate.crt")),
        std::fs::read_to_string(certs_dir().join("ca.crt")),
    ) else {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    let intermediate = CertificateHandle::from_pem(&int_pem).expect("intermediate.crt");
    let ca = CertificateHandle::from_pem(&ca_pem).expect("ca.crt");

    // an authentic answer from the CA's own responder, about signer-ec
    let other_serial = cert_handles(&["signer-ec.crt"]).remove(0);
    let resp = tmp_path("other-serial.ocsp.der");
    let index = write_tmp(
        "other-serial.index",
        format!(
            "V\t491231235959Z\t\t{}\tunknown\t{}\n",
            hex::encode_upper(other_serial.serial_number().as_bytes()),
            "C=ES, O=DIRECCION GENERAL DE LA POLICIA, OU=DNIE, CN=LOPEZ MARTIN, JUAN"
        )
        .as_bytes(),
    );
    let request = tmp_path("other-serial.req");
    let (ok, text) = run(
        "openssl",
        &[
            "ocsp",
            "-reqout",
            request.to_str().unwrap(),
            "-issuer",
            certs_dir().join("intermediate.crt").to_str().unwrap(),
            "-cert",
            certs_dir().join("signer-ec.crt").to_str().unwrap(),
            "-no_nonce",
        ],
    );
    assert!(ok, "openssl could not build the OCSP request:\n{text}");
    let (ok, text) = run(
        "openssl",
        &[
            "ocsp",
            "-index",
            index.to_str().unwrap(),
            "-CA",
            certs_dir().join("intermediate.crt").to_str().unwrap(),
            "-rsigner",
            certs_dir().join("ocsp.crt").to_str().unwrap(),
            "-rkey",
            certs_dir().join("ocsp.key").to_str().unwrap(),
            "-reqin",
            request.to_str().unwrap(),
            "-respout",
            resp.to_str().unwrap(),
            "-ndays",
            "3650",
        ],
    );
    assert!(ok, "openssl could not sign the OCSP response:\n{text}");
    let resp = std::fs::read(&resp).expect("openssl wrote the OCSP response");

    // it IS a genuine datum of that CA: verified, and about another certificate
    let status = openfirma_cades::read_ocsp_response(
        &resp,
        &[ca.clone(), intermediate.clone()],
        openfirma_cades::revocation::RevocationTime::at(std::time::SystemTime::now()),
    );
    assert!(
        status.verified(),
        "the CA's own responder signed it, and it must be read as such: {status:?}"
    );
    let ids = openfirma_cades::revocation::parse_ocsp_response(&resp).expect("it parses");
    assert_eq!(ids.len(), 1);
    assert_ne!(
        ids[0].serial,
        signer.certificate().serial_number().as_bytes(),
        "the answer is about a different certificate of the same CA"
    );

    let opts = PadesOptions {
        revocation: vec![
            RevocationBytes::Ocsp(resp),
            RevocationBytes::Crl(ca_crl.clone()),
        ],
        ..PadesOptions::default()
    };
    let signed = pades_sign(INPUT, &signer, &opts).expect("signing failed");
    let err = pades_verify(&signed, &anchors())
        .expect_err("an answer about another certificate of the same CA does not cover the signer");
    let text = err.to_string();
    assert!(
        text.contains("carries no revocation datum issued by")
            && text.contains("Test Intermediate CA"),
        "the refusal must name the link that has no datum: {text}"
    );

    // and the same construction with the answer that does name the signer is a
    // datum for it: the rule binds an answer to a certificate, it does not
    // refuse OCSP
    let opts = PadesOptions {
        revocation: vec![
            RevocationBytes::Ocsp(good_ocsp),
            RevocationBytes::Crl(ca_crl),
        ],
        ..PadesOptions::default()
    };
    let signed = pades_sign(INPUT, &signer, &opts).expect("signing failed");
    pades_verify(&signed, &anchors()).expect("the answer about the signer itself covers it");
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
        tool_or_skip("pdfsig", "pdfsig not found, install poppler-utils");
        return;
    }
    if !openssl_available() {
        require_or_skip("the B-LTA document needs openssl as its TSA");
        return;
    }
    let (Some(rsa), Some(ec), Some(revocation)) = (rsa_signer(), ec_signer(), crls()) else {
        require_or_skip("test PKI or CRLs missing, rerun tools/gen-testcert.sh");
        return;
    };
    let once = pades_sign(INPUT, &rsa, &PadesOptions::default()).expect("first signing failed");
    let captures: Captures = Arc::new(Mutex::new(Vec::new()));
    let provider = tsa_provider(captures);
    // The cosigner's archive must carry the FIRST signer's certificate too:
    // /DSS validation data is document-wide, and an archive that omits the
    // other signer's chain is exactly what `ltv.rs`' own guard refuses. The
    // co-sign case at the top of this file hands it over through
    // validation_certs for the same reason (wave 1 finding).
    let twice = pades_sign(
        &once,
        &ec,
        &PadesOptions {
            timestamp: Some(provider.clone()),
            revocation,
            document_timestamp: Some(provider),
            validation_certs: cert_handles(&["signer-rsa.crt"]),
            ..PadesOptions::default()
        },
    )
    .expect("B-LTA signing failed");

    let path = write_tmp("ltv-cosigned.pdf", &twice);
    let (ok, text) = run("pdfsig", &[path.to_str().unwrap()]);
    std::fs::remove_file(path).ok();
    // pdfsig exits 1 on a document whose certificates it cannot chain: the
    // synthetic PKI is trusted by nobody, and poppler counts an untrusted
    // certificate as its own kind of failure. That is the certificate
    // verdict, not the signature one — which is exactly why the asserts
    // below read "Signature Validation" lines rather than the exit code. An
    // unreadable document still fails here: the difference between "exit 1 +
    // per-signature report" and "no report at all" is text.
    if !ok && !text.contains("Signature #") {
        panic!("pdfsig failed to read the B-LTA document:\n{text}");
    }

    // both signatures must still be valid: the first one is untouched bytes
    // from poppler's point of view, and the archive and the time-stamp are
    // revisions after it. The TSA is not trusted and poppler will say so;
    // that is the certificate verdict, not the signature verdict.
    let valid = text
        .matches("Signature Validation: Signature is Valid")
        .count();
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
        tool_or_skip("qpdf", "qpdf not found, install qpdf");
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
