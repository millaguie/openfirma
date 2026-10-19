//! What a time-stamp token is allowed to claim about *when* it was made, and
//! what its certificate is allowed to say about *what the key is for*.
//!
//! Round two's N8 named two gaps, both on the path a token takes through
//! `verify_token_signature`: a token with `genTime` 2010 signed by the current
//! TSA key verified, and a TSA certificate whose `extendedKeyUsage` is present
//! but non-critical was taken at its word. RFC 3161 2.3 asks the extension to be
//! critical; RFC 3161 2.2 puts the token's whole meaning in `genTime`, so a date
//! its own certificate cannot cover is a date nothing attests.
//!
//! The tokens here are built by openfirma's own CMS writer, because that is the
//! only way to put a chosen `genTime` inside a token that is genuinely signed:
//! `openssl ts -reply` stamps the clock and nothing else, and a token patched
//! afterwards fails for the wrong reason — its `messageDigest` stops matching,
//! so nothing reaches the rule under test. Passing `content_type =
//! id-ct-TSTInfo` to `sign` produces the shape RFC 3161 2.2 describes (SignedData
//! whose eContent holds the TSTInfo, `messageDigest` and `signingCertificateV2`
//! over it) with the `genTime` asked for. The first assertion in each test is
//! that the honest form verifies, which is what makes the refusals mean something.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use openfirma_cades::{CadesOptions, sign, tsp};
use openfirma_core::cert::CertificateHandle;
use openfirma_core::oid::ID_CT_TST_INFO;
use openfirma_core::signer::SoftwareSigner;

fn certs_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/certs")
}

fn openssl_available() -> bool {
    Command::new("openssl")
        .arg("version")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// CI sets OPENFIRMA_REQUIRE_TESTS so a missing tool or a missing test PKI
/// fails the build instead of quietly skipping. `OPENFIRMA_ALLOW_NONKEYSTORE_SKIP`
/// is the only way out of it, and it is what a job whose PKI step could not run
/// sets — review 07, H-2.
fn require_or_skip(reason: &str) {
    let required = std::env::var("OPENFIRMA_REQUIRE_TESTS").is_ok();
    let allowed = std::env::var("OPENFIRMA_ALLOW_NONKEYSTORE_SKIP").is_ok();
    if required && !allowed {
        panic!("cannot run the test: {reason}");
    }
    eprintln!("skipped, {reason}");
}

/// One DER value with a short-form length. Everything built here is well under
/// 128 bytes, and the assert is what keeps that from becoming a lie later.
fn der(tag: u8, body: &[u8]) -> Vec<u8> {
    assert!(
        body.len() < 0x80,
        "this helper writes short-form lengths only"
    );
    let mut out = vec![tag, body.len() as u8];
    out.extend_from_slice(body);
    out
}

/// `TSTInfo`, RFC 3161 2.4.2: version, policy, messageImprint, serialNumber,
/// genTime. The imprint is 32 zero bytes — `verify_token_signature` is called
/// here without a message to match, so nothing re-hashes it, while the
/// `messageDigest` covers these exact TSTInfo bytes.
fn tst_info(gen_time: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&der(0x02, &[0x01])); // version 1
    body.extend_from_slice(&der(0x06, &[0x2A, 0x03, 0x04, 0x01])); // policy 1.2.3.4.1
    let mut alg = der(
        0x06,
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
    );
    alg.extend_from_slice(&[0x05, 0x00]); // sha256 with NULL parameters
    let mut imprint = der(0x30, &alg);
    imprint.extend_from_slice(&der(0x04, &[0u8; 32]));
    body.extend_from_slice(&der(0x30, &imprint));
    body.extend_from_slice(&der(0x02, &[0x42, 0x43])); // serialNumber
    body.extend_from_slice(gen_time); // genTime, already a DER GeneralizedTime
    der(0x30, &body)
}

/// An instant as DER GeneralizedTime, the way `der` writes it and the way
/// RFC 3161 2.2 requires it. Hand-rolling the format was tried first and got
/// the epoch shift wrong, which is the kind of bug a test should not be used to
/// discover.
fn gen_time(when: SystemTime) -> Vec<u8> {
    use der::{Encode, asn1::GeneralizedTime};
    GeneralizedTime::from_system_time(when)
        .expect("the instant is inside GeneralizedTime's range")
        .to_der()
        .expect("a GeneralizedTime always encodes")
}

/// The same instant as `YYYY-MM-DD`, for asserting what a refusal quoted. Read
/// out of the DER value above, so the two cannot disagree about the date.
fn ymd(when: SystemTime) -> String {
    let value = gen_time(when);
    let text = std::str::from_utf8(&value[2..]).expect("GeneralizedTime is ASCII digits");
    format!("{}-{}-{}", &text[0..4], &text[4..6], &text[6..8])
}

/// An instant from seconds since the epoch, the way a test names a date.
fn at(secs: u64) -> SystemTime {
    UNIX_EPOCH + std::time::Duration::from_secs(secs)
}

/// A token as a TSA hands one over: SignedData whose eContent is the TSTInfo,
/// signed by `tsa`, with its chain embedded so a validator can walk it later.
fn tsa_token(tsa: &SoftwareSigner, when: SystemTime) -> Vec<u8> {
    sign(
        &tst_info(&gen_time(when)),
        tsa,
        &CadesOptions {
            content_type: ID_CT_TST_INFO,
            encapsulate_content: true,
            ..CadesOptions::default()
        },
    )
    .expect("building the token")
}

fn load(dir: &Path, name: &str) -> CertificateHandle {
    let pem = std::fs::read_to_string(dir.join(name))
        .unwrap_or_else(|e| panic!("{name} cannot be read: {e}"));
    CertificateHandle::from_pem(&pem).unwrap_or_else(|e| panic!("{name}: {e}"))
}

/// The TSA signer from a certificate PEM that may live outside the test PKI (a
/// minted one), always with the test PKI's key and chain behind it.
fn tsa_signer(cert_pem: &str) -> SoftwareSigner {
    let dir = certs_dir();
    let key_pem = std::fs::read_to_string(dir.join("tsa.key")).expect("the TSA key");
    SoftwareSigner::from_pkcs8_pem(cert_pem, &key_pem)
        .expect("the test TSA key is PKCS#8 PEM")
        .with_chain(
            ["intermediate.crt", "ca.crt"]
                .iter()
                .map(|n| load(&dir, n))
                .collect(),
        )
}

/// The midpoint of a certificate's validity: an instant the certificate
/// certainly covers, which the wall clock is not — the PKI is regenerated on a
/// different day than the run.
fn midpoint_of(cert: &CertificateHandle) -> SystemTime {
    let v = cert.parsed().tbs_certificate().validity();
    at((secs_of(v.not_before) + secs_of(v.not_after)) / 2)
}

/// Seconds since the epoch of anything that names an instant (the certificate's
/// times arrive as `der::asn1::Time`).
fn secs_of(t: impl Into<SystemTime>) -> u64 {
    let t: SystemTime = t.into();
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The instant the token asserts has to sit inside the validity of the
/// certificate that signed it. Both directions are refused: a stamp from 2010
/// under a certificate that only begins in 2026 — the reviewer's case, the same
/// TSA key and a certificate renewed later, claiming a date nothing covers — and
/// a stamp from 2035 under a certificate that ends in 2029.
#[test]
fn a_gen_time_outside_the_tsa_certificate_is_refused() {
    if !certs_dir().join("tsa.crt").exists() {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    }
    let dir = certs_dir();
    let tsa_cert = load(&dir, "tsa.crt");
    let ca = load(&dir, "ca.crt");
    let now = SystemTime::now();

    let tsa = tsa_signer(&std::fs::read_to_string(dir.join("tsa.crt")).unwrap());
    let token = tsa_token(&tsa, midpoint_of(&tsa_cert));
    tsp::verify_token_signature(&token, std::slice::from_ref(&ca), now)
        .expect("a token dated inside its certificate's validity must verify");

    // 2010-01-01 and 2035-01-01, both years outside this certificate
    for (label, when) in [
        ("back-dated", at(1_262_304_000)),
        ("forward-dated", at(2_051_222_400)),
    ] {
        let token = tsa_token(&tsa, when);
        let err = tsp::verify_token_signature(&token, std::slice::from_ref(&ca), now)
            .expect_err(&format!("a {label} token must not verify"))
            .to_string();
        assert!(
            err.contains("outside the validity"),
            "the refusal must say what is outside what: {err}"
        );
        assert!(
            err.contains(&ymd(when)),
            "the refusal must quote the date it refuses ({}, {}): {err}",
            ymd(when),
            label
        );
    }
}

/// RFC 3161 2.3, the sentence this verifier had not been reading: a time-stamp
/// authority's `extendedKeyUsage` "MUST be present, MUST contain the extended key
/// usage purpose id-kp-timeStamping, and MUST be marked as critical". Non-critical,
/// RFC 5280 lets a verifier ignore it, so a certificate that leaves it off is not
/// claiming to be a TSA in any way a validator has to honour.
///
/// `anyExtendedKeyUsage` beside `timeStamping` is refused by name, because that
/// entry says the key is good for any purpose — the reading round two's N4 closed
/// the door on. What is NOT refused is a second *named* purpose next to
/// `timeStamping`: RFC 3161 does not forbid it, and inventing a rule there would
/// refuse real TSA certificates for nothing.
#[test]
fn a_tsa_certificate_with_a_soft_extended_key_usage_is_not_a_tsa() {
    if !openssl_available() {
        require_or_skip("openssl not found");
        return;
    }
    let dir = certs_dir();
    if !dir.join("tsa.key").exists() || !dir.join("ca.key").exists() {
        require_or_skip("test PKI with keys missing, run tools/gen-testcert.sh");
        return;
    }
    // minted where nothing else looks: these are one extension flag each, and
    // near-identical TSA certificates committed to the repository would be the
    // wrong place to hold that.
    let scratch =
        std::env::temp_dir().join(format!("openfirma-tst-profile-{}", std::process::id()));
    std::fs::create_dir_all(&scratch).unwrap();
    let ca = load(&dir, "ca.crt");

    for (name, eku_line, expected) in [
        (
            "eku-noncritical",
            "extendedKeyUsage = timeStamping",
            "non-critical",
        ),
        (
            "eku-any",
            "extendedKeyUsage = critical, timeStamping, anyExtendedKeyUsage",
            "anyExtendedKeyUsage",
        ),
    ] {
        let (cert, pem) = match mint_tsa_cert(eku_line, name, &dir, &scratch) {
            Some(pair) => pair,
            None => {
                require_or_skip("openssl could not mint the certificate");
                return;
            }
        };
        // the clock taken AFTER the mint: `notBefore` is the second the
        // certificate was issued in, so judging under an instant captured before
        // that asks whether a certificate was valid before it existed. The macOS
        // leg caught it, where the openssl call finished one second later than
        // the Linux one and `now` was already history.
        let now = SystemTime::now();
        let tsa = tsa_signer(&pem);
        let token = tsa_token(&tsa, midpoint_of(&cert));
        let err = tsp::verify_token_signature(&token, std::slice::from_ref(&ca), now)
            .expect_err(&format!("`{eku_line}` must not produce a trusted token"))
            .to_string();
        assert!(
            err.contains(expected),
            "the refusal for `{eku_line}` must name {expected}: {err}"
        );
    }
    std::fs::remove_dir_all(&scratch).ok();
}

/// Issue a TSA certificate under the test CA with one chosen
/// `extendedKeyUsage` line, for the test TSA key.
fn mint_tsa_cert(
    eku_line: &str,
    name: &str,
    dir: &Path,
    scratch: &Path,
) -> Option<(CertificateHandle, String)> {
    let csr = scratch.join(format!("{name}.csr"));
    let ext = scratch.join(format!("{name}.ext"));
    let cert = scratch.join(format!("{name}.crt"));
    std::fs::write(
        &ext,
        format!(
            "basicConstraints = critical, CA:FALSE\nkeyUsage = critical, digitalSignature, \
             nonRepudiation\n{eku_line}\nsubjectKeyIdentifier = hash\n"
        ),
    )
    .unwrap();
    let run = |args: &[&str]| {
        Command::new("openssl")
            .args(args)
            .output()
            .is_ok_and(|o| o.status.success())
    };
    if !run(&[
        "req",
        "-new",
        "-key",
        dir.join("tsa.key").to_str()?,
        "-subj",
        "/CN=TSA de pruebas",
        "-out",
        csr.to_str()?,
    ]) {
        return None;
    }
    let minted = run(&[
        "x509",
        "-req",
        "-in",
        csr.to_str()?,
        "-CA",
        dir.join("ca.crt").to_str()?,
        "-CAkey",
        dir.join("ca.key").to_str()?,
        "-CAcreateserial",
        "-days",
        "400",
        "-extfile",
        ext.to_str()?,
        "-out",
        cert.to_str()?,
    ]);
    if !minted {
        return None;
    }
    let pem = std::fs::read_to_string(&cert).ok()?;
    Some((CertificateHandle::from_pem(&pem).ok()?, pem))
}
