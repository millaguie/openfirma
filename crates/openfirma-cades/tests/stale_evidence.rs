//! How long a revocation datum speaks, and for which instant.
//!
//! Round two's N6: `revocation.rs` computed a response's currency as
//! `thisUpdate <= at` when no `nextUpdate` was present, so an OCSP answer from
//! years ago that omits `nextUpdate` stayed current for ever — with N5's
//! wrong-certificate hole next to it, one old capture kept vouching for a
//! certificate indefinitely. The same shape exists on the CRL path: RFC 5280
//! 5.1.2.5 lets `nextUpdate` be absent, meaning the issuer would not say when the
//! next list comes, and that absence used to be read as "no limit".
//!
//! The rule now: a datum is evidence about the instant asked about when its
//! window reaches that instant (`thisUpdate <= about < nextUpdate`) or when it is
//! not older than the instant (`about <= thisUpdate`) — because a CRL lists every
//! revocation its issuer knew at `thisUpdate` and an OCSP answer is the state as
//! of that moment, so a list from 2023 that does not name the certificate proves
//! it was not revoked in 2022 either. A datum older than the instant and with no
//! `nextUpdate` to bound it is refused once it is past the 48 hours a validator
//! assumes for an answer that would not say how long it speaks. Nothing may speak from after the clock it is checked under, which the
//! code already refused and still does.
//!
//! openssl cannot produce either shape: `ocsp` and `ca -gencrl` both insist on
//! writing a `nextUpdate` in the future, and `-crldays` refuses a negative number.
//! So the two datums here are assembled byte by byte and signed by the test PKI's
//! own intermediate with `sign_prehash` — the same operation the CMS writer
//! performs on a signature value. They have to really verify: a tampered fixture
//! fails at the signature and the date rule below it is never reached, which would
//! make the test pass for the wrong reason.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use der::{Encode as _, asn1::GeneralizedTime, asn1::UtcTime};
use openfirma_cades::revocation::{self, RevocationTime};
use openfirma_core::alg::DigestAlg;
use openfirma_core::cert::CertificateHandle;
use openfirma_core::signer::{Signer as _, SoftwareSigner};

fn certs_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/certs")
}

/// CI sets OPENFIRMA_REQUIRE_TESTS so a missing test PKI fails the build instead
/// of quietly skipping. OPENFIRMA_ALLOW_NONKEYSTORE_SKIP is the only way out, and
/// it is what a job whose PKI step could not run sets (review 07, H-2).
fn require_or_skip(reason: &str) {
    if std::env::var("OPENFIRMA_REQUIRE_TESTS").is_ok()
        && std::env::var("OPENFIRMA_ALLOW_NONKEYSTORE_SKIP").is_err()
    {
        panic!("cannot run the test: {reason}");
    }
    eprintln!("skipped, {reason}");
}

/// The test PKI: the root, the intermediate, and a signer holding the
/// intermediate's key — which is what a CA answering for its own certificates
/// does.
fn pki() -> Option<(CertificateHandle, CertificateHandle, SoftwareSigner)> {
    let dir = certs_dir();
    if !dir.join("intermediate.key").exists() {
        return None;
    }
    let text = |name: &str| std::fs::read_to_string(dir.join(name)).expect("a test PKI file");
    let load = |name: &str| -> CertificateHandle {
        CertificateHandle::from_pem(&text(name)).expect("a test PKI certificate")
    };
    let intermediate = load("intermediate.crt");
    let ca = load("ca.crt");
    let signer =
        SoftwareSigner::from_pkcs8_pem(&text("intermediate.crt"), &text("intermediate.key"))
            .expect("the test intermediate key is PKCS#8 PEM");
    Some((ca, intermediate, signer))
}

/// One DER value. Content longer than 127 bytes gets the long form, because a
/// 2048-bit RSA signature is 256 of them.
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

/// `AlgorithmIdentifier` for `sha256WithRSAEncryption` (1.2.840.113549.1.1.11)
/// with NULL parameters, as both `tbsCertList` and `BasicOCSPResponse` spell it.
fn sha256_with_rsa() -> Vec<u8> {
    let mut alg = der(
        0x06,
        &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B],
    );
    alg.extend_from_slice(&[0x05, 0x00]);
    der(0x30, &alg)
}

fn utc(when: SystemTime) -> Vec<u8> {
    UtcTime::from_system_time(when)
        .expect("the instant is inside UTCTime's range")
        .to_der()
        .expect("a UTCTime always encodes")
}

/// `producedAt`, which RFC 6960 spells GeneralizedTime (the interval fields are
/// UTCTime, as openssl writes them).
fn generalized(when: SystemTime) -> Vec<u8> {
    GeneralizedTime::from_system_time(when)
        .expect("the instant is inside GeneralizedTime's range")
        .to_der()
        .expect("a GeneralizedTime always encodes")
}

/// `id-pkix-ocsp-thisUpdate`-adjacent arithmetic: the shapes here are years
/// apart, so days are enough and no calendar code is needed.
fn ago(days: u64) -> SystemTime {
    SystemTime::now() - Duration::from_secs(days * 86_400)
}

fn ahead(days: u64) -> SystemTime {
    SystemTime::now() + Duration::from_secs(days * 86_400)
}

/// A "good" OCSP response from the intermediate about one of its certificates,
/// with the chosen `thisUpdate` and NO `nextUpdate` at all: RFC 6960 2.2.4 says a
/// responder SHOULD send one, this is the responder that did not.
fn answer_without_next_update(
    intermediate: &CertificateHandle,
    signer: &SoftwareSigner,
    subject: &CertificateHandle,
    this_update: SystemTime,
) -> Vec<u8> {
    // CertID: the hashes of the issuing CA, then the serial it is about
    let (name_hash, key_hash) =
        revocation::ocsp_issuer_hashes(intermediate, DigestAlg::Sha1).expect("the hashes");
    let serial = subject.serial_number().as_bytes().to_vec();
    let mut cert_id = der(0x30, &der(0x06, &[0x2B, 0x0E, 0x03, 0x02, 0x1A])); // sha1
    cert_id.extend_from_slice(&der(0x04, &name_hash));
    cert_id.extend_from_slice(&der(0x04, &key_hash));
    cert_id.extend_from_slice(&der(0x02, &serial));

    let mut single = der(0x30, &cert_id);
    single.extend_from_slice(&der(0x80, &[])); // certStatus: good
    single.extend_from_slice(&utc(this_update));

    // responderID byName: the CA's own subject, since the CA answered itself.
    // producedAt is when the answer was written, which says nothing about how
    // long it speaks — `thisUpdate` is the field the rule reads.
    let responder_id = der(0xA1, &intermediate.subject_der().expect("the subject DER"));
    let mut tbs_body = responder_id;
    tbs_body.extend_from_slice(&generalized(SystemTime::now()));
    tbs_body.extend_from_slice(&der(0x30, &der(0x30, &single)));
    let tbs = der(0x30, &tbs_body);

    let signature = signer
        .sign_prehash(DigestAlg::Sha256, &DigestAlg::Sha256.digest(&tbs))
        .expect("the intermediate signs its own answer");
    let mut basic = tbs;
    basic.extend_from_slice(&sha256_with_rsa());
    let mut bits = vec![0x00];
    bits.extend_from_slice(&signature);
    basic.extend_from_slice(&der(0x03, &bits));

    // OCSPResponse: successful, with the BasicOCSPResponse as an OCTET STRING
    // under the `basicOCSPResponse` content type.
    let mut response_bytes = der(
        0x06,
        &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01],
    );
    response_bytes.extend_from_slice(&der(0x04, &der(0x30, &basic)));
    let mut body = der(0x0A, &[0x00]); // responseStatus is an ENUMERATED
    body.extend_from_slice(&der(0xA0, &der(0x30, &response_bytes)));
    der(0x30, &body)
}

/// An empty CRL from the intermediate with the chosen `thisUpdate` and NO
/// `nextUpdate`.
fn crl_without_next_update(
    intermediate: &CertificateHandle,
    signer: &SoftwareSigner,
    this_update: SystemTime,
) -> Vec<u8> {
    let mut tbs_body = der(0x02, &[0x01]); // version 1
    tbs_body.extend_from_slice(&sha256_with_rsa());
    tbs_body.extend_from_slice(&intermediate.subject_der().expect("the subject DER"));
    tbs_body.extend_from_slice(&utc(this_update));
    // no crlEntries and no extensions: the list an unrevoked chain gets
    let tbs = der(0x30, &tbs_body);
    let signature = signer
        .sign_prehash(DigestAlg::Sha256, &DigestAlg::Sha256.digest(&tbs))
        .expect("the intermediate signs its own list");
    let mut body = tbs;
    body.extend_from_slice(&sha256_with_rsa());
    let mut bits = vec![0x00];
    bits.extend_from_slice(&signature);
    body.extend_from_slice(&der(0x03, &bits));
    der(0x30, &body)
}

/// An OCSP answer that omits `nextUpdate` is current for the moment it was given,
/// useless for one years later, and still evidence for an instant inside its own
/// era. The middle case is the finding; the others are what keep the fix from
/// being a blanket refusal of undated answers.
#[test]
fn an_ocsp_answer_without_next_update_only_speaks_for_its_own_moment() {
    let Some((ca, intermediate, signer)) = pki() else {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    let subject = {
        let pem = std::fs::read_to_string(certs_dir().join("signer-rsa.crt")).unwrap();
        CertificateHandle::from_pem(&pem).unwrap()
    };
    let issuers = [ca.clone(), intermediate.clone()];
    let now = SystemTime::now();

    // (1) given a minute ago, asked about now: usable, even undated
    let fresh = answer_without_next_update(
        &intermediate,
        &signer,
        &subject,
        now - Duration::from_secs(60),
    );
    let status = revocation::read_ocsp_response(&fresh, &issuers, RevocationTime::at(now));
    assert!(
        status.verified(),
        "an answer given a minute ago is current even without nextUpdate: {:?}",
        status.problem
    );
    assert_eq!(
        status.next_update, None,
        "the fixture stopped being the shape this test is about"
    );

    // (2) the same answer three years later, asked about today: past any
    // assumption, so it is not evidence about today. This is N6.
    let old = answer_without_next_update(&intermediate, &signer, &subject, ago(3 * 365));
    let status = revocation::read_ocsp_response(&old, &issuers, RevocationTime::at(now));
    assert!(
        !status.current && !status.verified(),
        "an undated answer from years ago was still being taken as current: {:?}",
        status.problem
    );
    assert!(
        status.signature_verified && status.chains_to_issuer,
        "the datum must fail on its date and not on something else: {:?}",
        status.problem
    );
    let problem = status.problem.unwrap_or_default();
    assert!(
        problem.contains("no nextUpdate"),
        "the refusal must say what is missing: {problem}"
    );

    // (2b) and the bound is a bound, not a word: two months on the same answer is
    // still too old, which is what stops "assumed window" meaning "for ever"
    let stale = answer_without_next_update(&intermediate, &signer, &subject, ago(60));
    let status = revocation::read_ocsp_response(&stale, &issuers, RevocationTime::at(now));
    assert!(
        !status.verified(),
        "a two-month-old undated answer must not pass as current either"
    );

    // (3) asked about an instant two years BEFORE it was given — the shape of an
    // archive whose data is older than today — the same old answer is evidence:
    // it did not name the certificate back then, so it was not revoked back then.
    let status =
        revocation::read_ocsp_response(&old, &issuers, RevocationTime::archive(ago(5 * 365), now));
    assert!(
        status.verified(),
        "a three-year-old answer must still speak for an instant two years older: {:?}",
        status.problem
    );

    // (4) nothing speaks from after the clock it is checked under
    let future = answer_without_next_update(&intermediate, &signer, &subject, ahead(365));
    let status = revocation::read_ocsp_response(&future, &issuers, RevocationTime::at(now));
    assert!(
        !status.verified(),
        "an answer dated a year ahead must not be taken as current"
    );
    assert!(
        status
            .problem
            .unwrap_or_default()
            .contains("after the time it is being checked at"),
        "the refusal must name the future date as the reason"
    );
}

/// The same rule on the CRL path: RFC 5280 5.1.2.5 allows `nextUpdate` to be
/// absent, and an absent one used to mean the list never stopped speaking.
#[test]
fn a_crl_without_next_update_only_speaks_for_its_own_moment() {
    let Some((ca, intermediate, signer)) = pki() else {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    let issuers = [ca.clone(), intermediate.clone()];
    let now = SystemTime::now();

    let fresh = crl_without_next_update(&intermediate, &signer, now - Duration::from_secs(60));
    let report = revocation::verify_crl(&fresh, &issuers, RevocationTime::at(now))
        .expect("a list issued a minute ago is usable even when it names no nextUpdate");
    assert_eq!(report.next_update, None, "the fixture is not the shape");

    let old = crl_without_next_update(&intermediate, &signer, ago(3 * 365));
    // two months old is past the assumed window as well
    let stale = crl_without_next_update(&intermediate, &signer, ago(60));
    assert!(
        revocation::verify_crl(&stale, &issuers, RevocationTime::at(now)).is_err(),
        "a two-month-old undated list must not pass as current"
    );

    let err = revocation::verify_crl(&old, &issuers, RevocationTime::at(now))
        .expect_err("a list from years ago that named no nextUpdate must not pass as current")
        .to_string();
    assert!(
        err.contains("no nextUpdate"),
        "the refusal must say what is missing: {err}"
    );

    revocation::verify_crl(&old, &issuers, RevocationTime::archive(ago(5 * 365), now))
        .expect("a three-year-old list must still speak for an instant two years older");
}
