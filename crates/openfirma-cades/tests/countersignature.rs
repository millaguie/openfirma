//! Countersignatures (RFC 5652 6, `id-aa-countersign`) are signatures too.
//!
//! Round two's N12: the attribute was known by OID and counted into the report's
//! list of unsigned attributes, and the verdict went on to say "all 1
//! signature(s) verify" about a signature nobody had looked at. This file checks
//! what `verify` now does with one: it verifies it over the very bytes a
//! countersignature covers — the outer `signatureValue` — under the countersigner's
//! own certificate, and refuses when that claim does not hold up.
//!
//! Nothing in the toolchain produces countersignatures (AutoFirma does not: the
//! golden diff has none, and the ETSI levels use `signatureTimeStamp` instead), so
//! each shape is assembled here: the countersignature as DER, attached through
//! [`CadesOptions::unsigned_attributes`]. The outer signature is made twice, which
//! is sound because signing here is deterministic and the attribute is *unsigned*:
//! pass one reveals the `signatureValue`, pass two produces the same
//! `signatureValue` with the countersignature riding along, and the test asserts
//! the two agree rather than trusting that.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use der::Encode as _;
use openfirma_cades::verify::{self, VerifyOptions};
use openfirma_cades::{CadesOptions, sign};
use openfirma_core::alg::DigestAlg;
use openfirma_core::cert::CertificateHandle;
use openfirma_core::signer::{Signer as _, SoftwareSigner};
use openfirma_core::tlv::{self, Cursor};

const CONTENT: &[u8] = b"the document somebody countersigned\n";

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

/// Whether the test PKI is there: without it there is nobody to countersign with.
/// Its absence skips, unless CI asked for tests that cannot be skipped.
fn pki_present() -> bool {
    if certs_dir().join("signer-representative.key").exists() {
        return true;
    }
    require_or_skip("test PKI missing, run tools/gen-testcert.sh");
    false
}

fn text(name: &str) -> String {
    std::fs::read_to_string(certs_dir().join(name)).expect("a test PKI file")
}

fn load(name: &str) -> CertificateHandle {
    CertificateHandle::from_pem(&text(name)).expect("a test PKI certificate")
}

fn signer_rsa(extra: Vec<CertificateHandle>) -> SoftwareSigner {
    let mut chain = vec![load("intermediate.crt"), load("ca.crt")];
    chain.extend(extra);
    SoftwareSigner::from_pkcs8_pem(&text("signer-rsa.crt"), &text("signer-rsa.key"))
        .expect("the test signer key is PKCS#8 PEM")
        .with_chain(chain)
}

// ---------------------------------------------------------------------------
// DER, by hand

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

/// `1.2.840.113549.1.9.NN`, the CMS attribute tree: nine body bytes.
fn cms_attr_oid(nn: u8) -> Vec<u8> {
    der(0x06, &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, nn])
}

/// An `Attribute`: the type, then a SET holding exactly one value.
fn attribute(type_oid: &[u8], value: &[u8]) -> Vec<u8> {
    der(0x30, &[type_oid, &der(0x31, value)].concat())
}

/// An `AlgorithmIdentifier` for a bare OID, with or without NULL parameters:
/// digest algorithms go without, `sha256WithRSAEncryption` and friends want the
/// NULL, as RFC 3370 spells them.
fn algorithm(oid: &[u8], null_params: bool) -> Vec<u8> {
    let mut body = der(0x06, oid);
    if null_params {
        body.extend_from_slice(&[0x05, 0x00]);
    }
    der(0x30, &body)
}

const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
const OID_SHA512: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];
/// `sha512WithRSAEncryption` (1.2.840.113549.1.1.13).
const OID_SHA512_WITH_RSA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D];
/// `id-ecdsa-with-SHA256` (1.2.840.10045.4.3.2).
const OID_ECDSA_WITH_SHA256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];

// ---------------------------------------------------------------------------
// the pieces of a countersignature

/// Who countersigns, with the algorithms its key can actually be used with: the
/// test PKI's RSA certificates sign SHA-512, its P-256 certificate SHA-256. Which
/// is itself the point — a countersignature's digest is its own business, not the
/// digest of the signature underneath it.
struct Countersigner {
    signer: SoftwareSigner,
    cert: CertificateHandle,
    digest: DigestAlg,
    digest_ai: Vec<u8>,
    signature_ai: Vec<u8>,
}

fn countersigner(
    name: &str,
    digest: DigestAlg,
    digest_oid: &[u8],
    sig_oid: &[u8],
) -> Countersigner {
    Countersigner {
        signer: SoftwareSigner::from_pkcs8_pem(
            &text(&format!("{name}.crt")),
            &text(&format!("{name}.key")),
        )
        .expect("the test keys are PKCS#8 PEM"),
        cert: load(&format!("{name}.crt")),
        digest,
        digest_ai: algorithm(digest_oid, false),
        signature_ai: algorithm(sig_oid, true),
    }
}

/// A second natural person of the same PKI, RSA, counting with SHA-512 while the
/// signature underneath uses SHA-256.
fn representative() -> Countersigner {
    countersigner(
        "signer-representative",
        DigestAlg::Sha512,
        OID_SHA512,
        OID_SHA512_WITH_RSA,
    )
}

/// A P-256 countersigner, used where the point is that nobody can find its
/// certificate.
fn police() -> Countersigner {
    countersigner(
        "signer-ec",
        DigestAlg::Sha256,
        OID_SHA256,
        OID_ECDSA_WITH_SHA256,
    )
}

/// The 1024-bit certificate of the test PKI, for the case where the
/// countersignature is real and the key behind it is not acceptable.
fn weak() -> Countersigner {
    countersigner(
        "signer-weak",
        DigestAlg::Sha512,
        OID_SHA512,
        OID_SHA512_WITH_RSA,
    )
}

/// The instant pinned into `signingTime`, so both passes sign identical
/// authenticated attributes. Computed once per test and passed around, because a
/// second computed at the wrong moment would not match the one in the report.
fn pinned_time() -> SystemTime {
    let now = SystemTime::now();
    // whole seconds: the attribute is a UTCTime and would come back truncated
    UNIX_EPOCH + Duration::from_secs(now.duration_since(UNIX_EPOCH).unwrap().as_secs())
}

/// Build the `id-aa-countersign` attribute over whatever `digest_over` claims.
///
/// `digest_over` is what its messageDigest attribute claims — the verifier decides
/// whether that something is the signature the attribute is attached to. `corrupt`
/// flips one byte of the countersignature's own value, which leaves the digest
/// claim intact: the refusal that follows is then about the signature, not about
/// the binding.
fn countersign(
    who: &Countersigner,
    digest_over: &[u8],
    corrupt: bool,
    when: SystemTime,
) -> Vec<u8> {
    let mut attrs = Vec::new();
    // messageDigest then signingTime: the DER `SET OF` order, since the two OIDs
    // differ only in their last byte and 04 sorts before 05
    attrs.extend_from_slice(&attribute(
        &cms_attr_oid(4),
        &der(0x04, &who.digest.digest(digest_over)),
    ));
    attrs.extend_from_slice(&attribute(
        &cms_attr_oid(5),
        &tlv::utc_time(when).expect("in UTCTime's range"),
    ));

    // The countersignature is a SignerInfo of its own (RFC 5652 6): version 1 with
    // issuerAndSerialNumber, its digestAlgorithm, its signedAttrs, its
    // signatureAlgorithm, its signatureValue.
    let sid = der(
        0x30,
        &[
            who.cert.issuer().to_der().expect("the issuer DER"),
            der(0x02, who.cert.serial_number().as_bytes()),
        ]
        .concat(),
    );
    let mut body = der(0x02, &[0x01]);
    body.extend_from_slice(&sid);
    body.extend_from_slice(&who.digest_ai);
    body.extend_from_slice(&der(0xA0, &attrs));
    body.extend_from_slice(&who.signature_ai);
    let retagged = der(0x31, &attrs);
    let mut value = who
        .signer
        .sign_prehash(who.digest, &who.digest.digest(&retagged))
        .expect("the countersigner signs");
    if corrupt {
        let last = value.len() - 1;
        value[last] ^= 0x01;
    }
    body.extend_from_slice(&der(0x04, &value));
    attribute(&cms_attr_oid(6), &der(0x30, &body))
}

/// The first `SignerInfo`'s `signatureValue`, walked out of the CMS by hand:
/// ContentInfo → [0] SignedData → SignedData → version, digestAlgorithms,
/// encapContentInfo, [0] certificates, [1] crlList, signerInfos (a plain SET) →
/// SignerInfo → version, sid, digestAlgorithm, [0] signedAttrs,
/// signatureAlgorithm, signatureValue.
fn outer_signature_value(cms: &[u8]) -> Vec<u8> {
    let mut top = Cursor::new(cms);
    let content_info = top.expect(0x30, "ContentInfo").unwrap();
    let mut ci = Cursor::new(content_info.content);
    ci.value().unwrap(); // contentType
    let sd_wrapper = ci.value().unwrap(); // [0] EXPLICIT SignedData
    let mut sd = Cursor::new(sd_wrapper.content);
    let signed_data = sd.expect(0x30, "SignedData").unwrap();
    let mut s = Cursor::new(signed_data.content);
    s.value().unwrap(); // version
    s.value().unwrap(); // digestAlgorithms
    s.value().unwrap(); // encapContentInfo
    for tag in [0xA0, 0xA1] {
        if s.peek_tag() == Some(tag) {
            s.value().unwrap(); // certificates, then crlList: both OPTIONAL
        }
    }
    let signer_infos = s.expect(0x31, "signerInfos").unwrap();
    let mut sis = Cursor::new(signer_infos.content);
    let si = sis.expect(0x30, "SignerInfo").unwrap();
    let mut p = Cursor::new(si.content);
    p.value().unwrap(); // version
    p.value().unwrap(); // sid
    p.value().unwrap(); // digestAlgorithm
    if p.peek_tag() == Some(0xA0) {
        p.value().unwrap(); // signedAttrs
    }
    p.value().unwrap(); // signatureAlgorithm
    p.expect(0x04, "signatureValue").unwrap().content.to_vec()
}

/// Sign `CONTENT` detached and countersigned. The countersigner's certificate is
/// embedded in the signature when `embed` says so, which is what lets its chain be
/// built from what the signature carries.
fn countersigned(
    who: &Countersigner,
    embed: bool,
    digest_over: Option<Vec<u8>>,
    corrupt: bool,
    when: SystemTime,
) -> Vec<u8> {
    let first = sign(
        CONTENT,
        &signer_rsa(Vec::new()),
        &CadesOptions {
            signing_time: Some(when),
            ..Default::default()
        },
    )
    .expect("the first pass signs");
    let value = outer_signature_value(&first);
    let claim = digest_over.unwrap_or_else(|| value.clone());
    let attr = countersign(who, &claim, corrupt, when);

    let outer = signer_rsa(if embed {
        vec![who.cert.clone()]
    } else {
        Vec::new()
    });
    let second = sign(
        CONTENT,
        &outer,
        &CadesOptions {
            signing_time: Some(when),
            unsigned_attributes: vec![attr],
            ..Default::default()
        },
    )
    .expect("the second pass signs");
    assert_eq!(
        outer_signature_value(&second),
        value,
        "attaching an unsigned attribute must not change the signature it rides on; without \
         that, the countersignature built here would be over a value the document does not carry"
    );
    second
}

fn opts(ca: &CertificateHandle) -> VerifyOptions {
    VerifyOptions::new(vec![ca.clone()])
}

/// A countersignature that holds up: verified, reported with who and when, and
/// named among the checks that passed.
#[test]
fn a_countersignature_that_verifies_is_reported() {
    if !pki_present() {
        return;
    }
    let who = representative();
    let ca = load("ca.crt");
    let when = pinned_time();
    let doc = countersigned(&who, true, None, false, when);
    let reports = verify::verify(&doc, Some(CONTENT), &opts(&ca)).expect(
        "a countersignature over this signature's value, by a certificate of the same \
         trusted chain, must verify and not disturb the signature under it",
    );
    let report = &reports[0];
    assert_eq!(report.countersignatures.len(), 1);
    let cs = &report.countersignatures[0];
    assert!(
        cs.signer_subject.contains("representante"),
        "the report must say who countersigned: {}",
        cs.signer_subject
    );
    assert_ne!(
        report.signer_subject, cs.signer_subject,
        "and it must not be confused with the signer: {} vs {}",
        report.signer_subject, cs.signer_subject
    );
    assert_eq!(
        cs.digest,
        DigestAlg::Sha512,
        "a countersignature digests under its own algorithm"
    );
    assert_eq!(
        cs.signing_time,
        Some(when),
        "and reports the moment it claims"
    );
    assert!(
        !cs.chain_subjects.is_empty() && cs.trust_anchor.is_some(),
        "the countersigner has to stand on somebody the caller trusts: {cs:?}"
    );
    assert!(
        report.passed.contains(&verify::CHECK_COUNTERSIGNATURES),
        "the passed list must say the countersignature was checked: {:?}",
        report.passed
    );
}

/// A countersignature over the wrong thing — here over the content rather than the
/// signature value, the shape a confused or a dishonest producer makes — says
/// nothing about this signature and is refused.
#[test]
fn a_countersignature_over_anything_else_is_refused() {
    if !pki_present() {
        return;
    }
    let who = representative();
    let ca = load("ca.crt");
    let doc = countersigned(&who, true, Some(CONTENT.to_vec()), false, pinned_time());
    let err = verify::verify(&doc, Some(CONTENT), &opts(&ca))
        .expect_err("RFC 5652 6 gives a countersignature a digest over the signature value; over anything else it is not one")
        .to_string();
    assert!(
        err.contains("countersignature 1") && err.contains("countersigns a different signature"),
        "the refusal must name the countersignature and say what it countersigned: {err}"
    );
}

/// A countersignature whose digest claim is right but whose signature value is
/// not: somebody is signing as that countersigner without being them.
#[test]
fn a_countersignature_that_is_not_the_countersigners_is_refused() {
    if !pki_present() {
        return;
    }
    let who = representative();
    let ca = load("ca.crt");
    let doc = countersigned(&who, true, None, true, pinned_time());
    let err = verify::verify(&doc, Some(CONTENT), &opts(&ca))
        .expect_err("one flipped byte makes it somebody else's signature, or nobody's")
        .to_string();
    assert!(
        err.contains("countersignature 1"),
        "the refusal must name the countersignature: {err}"
    );
    assert!(
        !err.contains("countersigns a different signature"),
        "and must not blame the binding, which is intact: {err}"
    );
}

/// A countersignature by a certificate the signature does not carry cannot be
/// checked at all, and "we could not check it" is not a verdict to print under a
/// signature that reads "all signatures verify".
#[test]
fn a_countersignature_nobody_can_locate_is_refused() {
    if !pki_present() {
        return;
    }
    let who = police();
    let ca = load("ca.crt");
    let doc = countersigned(&who, false, None, false, pinned_time());
    let err = verify::verify(&doc, Some(CONTENT), &opts(&ca))
        .expect_err("a countersigner nobody can find must not pass as a countersignature")
        .to_string();
    assert!(
        err.contains("countersignature 1") && err.contains("no certificate"),
        "the refusal must say the countersigner's certificate is missing: {err}"
    );
}

/// The signature's own algorithm policy covers the countersignature too: a real
/// signature with a 1024-bit key is refused in a signature, and a countersignature
/// is a signature.
#[test]
fn a_countersignature_under_a_refused_key_is_refused() {
    if !pki_present() {
        return;
    }
    let who = weak();
    let ca = load("ca.crt");
    let doc = countersigned(&who, true, None, false, pinned_time());
    let err = verify::verify(&doc, Some(CONTENT), &opts(&ca))
        .expect_err("the countersigner's key is the weak one of the test PKI")
        .to_string();
    assert!(
        err.contains("countersignature 1"),
        "the refusal must name the countersignature: {err}"
    );
    assert!(
        err.contains("1024"),
        "and say what is wrong with the key: {err}"
    );
}
