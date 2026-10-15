//! Reading and checking revocation data: CRLs and OCSP responses.
//!
//! Long-term signature levels (PAdES B-LT, ETSI EN 319 142-1) archive this
//! data next to the signature so a validator years from now never has to
//! reach the network. Archiving is only worth something if the data can be
//! trusted on its own, and for a CRL that means: its signature verifies under
//! the public key of the CA whose name it carries as issuer. That is what
//! [`verify_crl`] establishes; a CRL from any other key is not a revocation
//! datum, it is a claim nobody made.
//!
//! OCSP responses are parsed only as far as their `CertID`s, which is what
//! associating a response with a certificate needs, and their `certStatus` is
//! read. Their own signature is *not* verified: that needs the responder's
//! certificate and the ESS signing-certificate matching of RFC 6960 4.2.2.2,
//! a chain of trust of its own. The CRL is the cryptographically checked
//! revocation path here; an archive that has to stand on its own should carry
//! CRLs. Deliberate limitation, recorded in docs/validation.md.

use std::time::SystemTime;

use const_oid::ObjectIdentifier;
use der::Decode;
use der::asn1::{GeneralizedTime, UtcTime};
use openfirma_core::alg::DigestAlg;
use openfirma_core::cert::CertificateHandle;
use openfirma_core::signer::verify_prehash;
use openfirma_core::{Error, Result, oid, tlv};

use crate::verify::{detail_of, digest_from_signature_oid, subject};

/// The RFC 6960 `responseStatus` values, for errors that name the refusal.
fn ocsp_status_name(code: u32) -> &'static str {
    match code {
        0 => "successful",
        1 => "malformedRequest",
        2 => "internalError",
        3 => "tryLater",
        5 => "signatureRequired",
        6 => "unauthorized",
        _ => "unknown status",
    }
}

/// What a verified CRL says.
#[derive(Clone, Debug)]
pub struct CrlReport {
    /// Subject of the CA that issued and signed the CRL.
    pub issuer: String,
    /// The issuer `Name` exactly as encoded, for byte level association with
    /// the certificates the CRL covers.
    pub issuer_der: Vec<u8>,
    pub this_update: SystemTime,
    pub next_update: Option<SystemTime>,
    /// Serial numbers the CRL revokes. An empty list is the normal case and a
    /// complete statement: nothing this CA issued is revoked.
    pub revoked_serials: Vec<Vec<u8>>,
}

/// One `CertID` of an OCSP response: which certificate a `SingleResponse`
/// speaks about, by the hashes RFC 6960 uses instead of names.
#[derive(Clone, Debug)]
pub struct OcspCertId {
    /// The hash algorithm the two hashes were taken with, SHA-1 in practice.
    pub hash_algorithm: ObjectIdentifier,
    pub issuer_name_hash: Vec<u8>,
    pub issuer_key_hash: Vec<u8>,
    /// Serial number of the certificate the response is about.
    pub serial: Vec<u8>,
    /// True when `certStatus` says `revoked`.
    pub revoked: bool,
}

/// Parses a DER `CertificateList` (RFC 5280), finds the CA that issued it
/// among `issuers`, and verifies its signature under that CA's public key.
///
/// `at` is the validation time: a CRL whose `nextUpdate` has passed says
/// nothing about the present and is refused, with the way out named.
pub fn verify_crl(der: &[u8], issuers: &[CertificateHandle], at: SystemTime) -> Result<CrlReport> {
    let mut outer = Cur::new(der);
    let list = outer.expect(tlv::TAG_SEQUENCE, "the CertificateList")?;
    if !outer.done() {
        return Err(trailing("after the CertificateList"));
    }

    let mut f = Cur::new(list.content);
    let tbs = f.expect(tlv::TAG_SEQUENCE, "tbsCertList")?;
    let mut t = Cur::new(tbs.content);
    // version is OPTIONAL and defaults to v1: an INTEGER up front is the
    // explicit version, anything else is already the signature algorithm
    if t.peek_tag() == Some(tlv::TAG_INTEGER) {
        let version = t.small_uint("the CRL version")?;
        if version > 1 {
            return Err(Error::Verification(format!(
                "CRL version {version} does not exist, versions are 1 and 2 (encoded 0 and 1)"
            )));
        }
    }
    let mut sig_alg = Cur::new(
        t.expect(tlv::TAG_SEQUENCE, "tbsCertList.signature")?
            .content,
    );
    let tbs_sig_oid = sig_alg.oid("the CRL signature algorithm")?;
    let issuer = t.expect(tlv::TAG_SEQUENCE, "tbsCertList.issuer")?;
    let this_update = time_value(&mut t, "thisUpdate")?;
    let next_update = match t.peek_tag() {
        Some(tlv::TAG_UTC_TIME) | Some(0x18) => Some(time_value(&mut t, "nextUpdate")?),
        _ => None,
    };
    let mut revoked_serials = Vec::new();
    if t.peek_tag() == Some(tlv::TAG_SEQUENCE) {
        let revoked_list = t.next()?;
        let mut rc = Cur::new(revoked_list.content);
        while !rc.done() {
            let entry = rc.expect(tlv::TAG_SEQUENCE, "a revokedCertificates entry")?;
            let mut e = Cur::new(entry.content);
            let serial = e.expect(tlv::TAG_INTEGER, "the revoked serial number")?;
            revoked_serials.push(serial.content.to_vec());
            // revocationDate and any entry extensions carry nothing we check
        }
    }
    // crlExtensions [0] is not interpreted

    let mut sa = Cur::new(f.expect(tlv::TAG_SEQUENCE, "signatureAlgorithm")?.content);
    let sig_oid = sa.oid("signatureAlgorithm")?;
    if sig_oid != tbs_sig_oid {
        return Err(Error::Verification(format!(
            "the CRL names {tbs_sig_oid} inside tbsCertList but {sig_oid} outside it"
        )));
    }
    let sig = f.expect(tlv::TAG_BIT_STRING, "signatureValue")?;
    let (unused, sig_bytes) = bit_string(&sig, "the CRL signature")?;
    if unused != 0 {
        return Err(Error::Verification(
            "the CRL signature BIT STRING has unused bits, which a signature never has".into(),
        ));
    }
    if !f.done() {
        return Err(trailing("in the CertificateList"));
    }

    let digest =
        digest_from_signature_oid(&sig_oid).map_err(|e| Error::Verification(detail_of(&e)))?;
    let prehash = digest.digest(tbs.whole);

    // The issuing CA is found by name and proved by key: a CRL that names a
    // CA but is signed by anyone else is exactly the attack this check stops.
    let mut candidates = 0usize;
    for cert in issuers {
        if cert.subject_der().ok().as_deref() != Some(issuer.whole) {
            continue;
        }
        candidates += 1;
        if verify_prehash(cert, digest, &prehash, sig_bytes).is_err() {
            continue;
        }
        if this_update > at {
            return Err(Error::Verification(format!(
                "the CRL was issued in the future (thisUpdate {}), which cannot be the \
                 revocation state at the validation time",
                fmt_time(this_update)
            )));
        }
        if let Some(next) = next_update {
            if at > next {
                return Err(Error::Verification(format!(
                    "the CRL expired at {}; it says nothing about the validation time. \
                     Fetch or regenerate a current one (for the test PKI: tools/gen-testcert.sh)",
                    fmt_time(next)
                )));
            }
        }
        return Ok(CrlReport {
            issuer: subject(cert),
            issuer_der: issuer.whole.to_vec(),
            this_update,
            next_update,
            revoked_serials,
        });
    }

    let issuer_name = name_string(issuer.whole);
    if candidates == 0 {
        Err(Error::Verification(format!(
            "the CRL claims to be issued by \"{issuer_name}\" but none of the {} certificate(s) \
             supplied carries that subject, so its signature cannot be checked and it is not a \
             revocation datum. Embed the issuing CA in the validation data or the trust anchors.",
            issuers.len()
        )))
    } else {
        Err(Error::Verification(format!(
            "the CRL claims to be issued by \"{issuer_name}\" and {candidates} certificate(s) \
             carry that subject, but none of their public keys verifies its signature: it was \
             signed by a different key"
        )))
    }
}

/// The issuer `Name` of a CRL, exactly as encoded, without verifying
/// anything. This is what the writer side associates a CRL with the
/// certificates of a chain by; the checking is [`verify_crl`]'s job.
pub fn crl_issuer_der(der: &[u8]) -> Result<Vec<u8>> {
    let mut outer = Cur::new(der);
    let list = outer.expect(tlv::TAG_SEQUENCE, "the CertificateList")?;
    let mut f = Cur::new(list.content);
    let tbs = f.expect(tlv::TAG_SEQUENCE, "tbsCertList")?;
    let mut t = Cur::new(tbs.content);
    if t.peek_tag() == Some(tlv::TAG_INTEGER) {
        let _version = t.next()?;
    }
    let _signature = t.expect(tlv::TAG_SEQUENCE, "tbsCertList.signature")?;
    let issuer = t.expect(tlv::TAG_SEQUENCE, "tbsCertList.issuer")?;
    Ok(issuer.whole.to_vec())
}

/// Parses a DER `OCSPResponse` (RFC 6960) as far as the `CertID`s of its
/// `SingleResponse`s, so each can be associated with the certificate it
/// speaks about.
///
/// A response whose `responseStatus` is not `successful` is refused: only a
/// successful answer is a statement about anything. The signature of the
/// `BasicOCSPResponse` is not verified, see the module documentation.
pub fn parse_ocsp_response(der: &[u8]) -> Result<Vec<OcspCertId>> {
    let mut outer = Cur::new(der);
    let resp = outer.expect(tlv::TAG_SEQUENCE, "the OCSPResponse")?;
    if !outer.done() {
        return Err(trailing("after the OCSPResponse"));
    }
    let mut r = Cur::new(resp.content);
    let status = r.expect(0x0a, "responseStatus")?; // ENUMERATED
    let code = enumerated(&status, "responseStatus")?;
    if code != 0 {
        return Err(Error::Verification(format!(
            "the OCSP responder answered \"{}\" (status {code}), not \"successful\"; only a \
             successful response is a revocation datum",
            ocsp_status_name(code)
        )));
    }
    if r.done() {
        return Err(Error::Verification(
            "the OCSP response is successful but carries no responseBytes".into(),
        ));
    }
    let bytes = r.expect(0xa0, "responseBytes")?;
    let mut rb = Cur::new(bytes.content);
    let seq = rb.expect(tlv::TAG_SEQUENCE, "ResponseBytes")?;
    let mut s = Cur::new(seq.content);
    let response_type = s.oid("ResponseBytes.responseType")?;
    if response_type != oid::ID_PKIX_OCSP_BASIC {
        return Err(Error::Verification(format!(
            "the OCSP responseBytes carry {response_type}, only a BasicOCSPResponse \
             ({}) can be read",
            oid::ID_PKIX_OCSP_BASIC
        )));
    }
    let basic_octets = s.expect(tlv::TAG_OCTET_STRING, "ResponseBytes.response")?;

    // BasicOCSPResponse ::= SEQUENCE { tbsResponseData, signatureAlgorithm,
    //                                  signature, certs [0] OPTIONAL }
    let mut b = Cur::new(basic_octets.content);
    let basic = b.expect(tlv::TAG_SEQUENCE, "the BasicOCSPResponse")?;
    let mut t = Cur::new(basic.content);
    let rd = t.expect(tlv::TAG_SEQUENCE, "tbsResponseData")?;
    let mut d = Cur::new(rd.content);
    // version [0] EXPLICIT DEFAULT v1
    if d.peek_tag() == Some(0xa0) {
        let _version = d.next()?;
    }
    // responderID: [1] byName or [2] byKey; not interpreted, see module docs
    let _responder_id = d.next()?;
    let _produced_at = d.expect(0x18, "producedAt")?; // GeneralizedTime
    let responses = d.expect(tlv::TAG_SEQUENCE, "the SingleResponse list")?;

    let mut out = Vec::new();
    let mut rs = Cur::new(responses.content);
    while !rs.done() {
        let single = rs.expect(tlv::TAG_SEQUENCE, "a SingleResponse")?;
        let mut sc = Cur::new(single.content);
        let cert_id = sc.expect(tlv::TAG_SEQUENCE, "SingleResponse.certID")?;
        let mut c = Cur::new(cert_id.content);
        let mut alg = Cur::new(c.expect(tlv::TAG_SEQUENCE, "CertID.hashAlgorithm")?.content);
        let hash_algorithm = alg.oid("CertID.hashAlgorithm")?;
        let issuer_name_hash = c
            .expect(tlv::TAG_OCTET_STRING, "CertID.issuerNameHash")?
            .content
            .to_vec();
        let issuer_key_hash = c
            .expect(tlv::TAG_OCTET_STRING, "CertID.issuerKeyHash")?
            .content
            .to_vec();
        let serial = c
            .expect(tlv::TAG_INTEGER, "CertID.serialNumber")?
            .content
            .to_vec();
        // certStatus ::= CHOICE { good [0] IMPLICIT NULL, revoked [1]
        // IMPLICIT RevokedInfo, unknown [2] IMPLICIT UnknownInfo } — good is
        // primitive and empty, which only a real responder's output teaches
        let cert_status = sc.next()?;
        match cert_status.tag {
            0x80 | 0xa1 => {}
            0x82 => {
                return Err(Error::Verification(format!(
                    "the OCSP response answers \"unknown\" for serial {}: the responder says \
                     nothing about that certificate, which is not a revocation datum",
                    hex::encode(&serial)
                )));
            }
            other => {
                return Err(Error::Verification(format!(
                    "certStatus has tag {other:#04x}, expected [0] good, [1] revoked or [2] unknown"
                )));
            }
        }
        out.push(OcspCertId {
            hash_algorithm,
            issuer_name_hash,
            issuer_key_hash,
            serial,
            revoked: cert_status.tag == 0xa1,
        });
    }
    if out.is_empty() {
        return Err(Error::Verification(
            "the OCSP response answers for no certificate at all".into(),
        ));
    }
    Ok(out)
}

/// The `issuerNameHash` and `issuerKeyHash` RFC 6960 4.1.1 computes for a
/// certificate: the digest of the **whole DER** of the subject `Name`, tag
/// and length included — this is what openssl's `X509_NAME_digest` hashes,
/// and what responders and clients agree on — and the digest of the subject
/// public key's bit string content without its unused-bits byte. Both under
/// the `CertID`'s hash algorithm. This is how an OCSP response is associated
/// with the CA that issued the certificate it speaks about.
pub fn ocsp_issuer_hashes(cert: &CertificateHandle, hash: DigestAlg) -> Result<(Vec<u8>, Vec<u8>)> {
    let name_der = cert.subject_der()?;
    let spki = cert.parsed().tbs_certificate().subject_public_key_info();
    let key = spki.subject_public_key.as_bytes().ok_or_else(|| {
        Error::Verification(
            "the certificate's public key BIT STRING is not octet aligned, so it has no \
             OCSP issuerKeyHash"
                .into(),
        )
    })?;
    Ok((hash.digest(&name_der), hash.digest(key)))
}

fn bit_string<'a>(t: &Tlv<'a>, what: &str) -> Result<(u8, &'a [u8])> {
    let unused = *t
        .content
        .first()
        .ok_or_else(|| Error::Verification(format!("{what} is an empty BIT STRING")))?;
    Ok((unused, &t.content[1..]))
}

fn enumerated(t: &Tlv<'_>, what: &str) -> Result<u32> {
    if t.content.len() > 4 || t.content.first().is_some_and(|b| *b & 0x80 != 0) {
        return Err(Error::Verification(format!(
            "{what} is negative or too large"
        )));
    }
    let mut v = 0u32;
    for b in t.content {
        v = (v << 8) | u32::from(*b);
    }
    Ok(v)
}

fn time_value(c: &mut Cur<'_>, what: &str) -> Result<SystemTime> {
    let t = c.next()?;
    match t.tag {
        tlv::TAG_UTC_TIME => UtcTime::from_der(t.whole)
            .map(|u| u.to_system_time())
            .map_err(|e| Error::Verification(format!("unreadable {what}: {e}"))),
        0x18 => GeneralizedTime::from_der(t.whole)
            .map(|g| g.to_system_time())
            .map_err(|e| Error::Verification(format!("unreadable {what}: {e}"))),
        other => Err(Error::Verification(format!(
            "{what} has tag {other:#04x}, expected UTCTime or GeneralizedTime"
        ))),
    }
}

/// A `Name` for error messages: the printable form when x509-cert can read
/// it, the hex of its DER when it cannot.
fn name_string(der: &[u8]) -> String {
    x509_cert::name::Name::from_der(der)
        .map(|n| n.to_string())
        .unwrap_or_else(|_| hex::encode(der))
}

fn fmt_time(t: SystemTime) -> String {
    match UtcTime::from_system_time(t) {
        Ok(u) => u.to_date_time().to_string(),
        Err(_) => format!("{t:?}"),
    }
}

fn trailing(where_: &str) -> Error {
    Error::Verification(format!("trailing bytes {where_}"))
}

// ---------------------------------------------------------------------------
// a cursor over DER, in the style of the ones in tsp.rs and verify.rs

struct Tlv<'a> {
    tag: u8,
    content: &'a [u8],
    /// Tag, length and content: the exact bytes of this value, which is what
    /// a signature is computed over.
    whole: &'a [u8],
}

struct Cur<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Cur<'a> {
    fn new(b: &'a [u8]) -> Self {
        Cur { b, i: 0 }
    }

    fn done(&self) -> bool {
        self.i >= self.b.len()
    }

    fn peek_tag(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn next(&mut self) -> Result<Tlv<'a>> {
        let start = self.i;
        let tag = *self
            .b
            .get(start)
            .ok_or_else(|| Error::Verification("the revocation data ends mid tag".into()))?;
        let (len, n) = read_len(&self.b[start + 1..])?;
        let content_start = start + 1 + n;
        let end = content_start.checked_add(len).ok_or_else(|| {
            Error::Verification("a DER length overflows the address space".into())
        })?;
        if end > self.b.len() {
            return Err(Error::Verification(format!(
                "a value with tag {tag:#04x} claims {len} bytes but only {} are left",
                self.b.len().saturating_sub(content_start)
            )));
        }
        self.i = end;
        Ok(Tlv {
            tag,
            content: &self.b[content_start..end],
            whole: &self.b[start..end],
        })
    }

    fn expect(&mut self, tag: u8, what: &str) -> Result<Tlv<'a>> {
        let t = self.next()?;
        if t.tag != tag {
            return Err(Error::Verification(format!(
                "expected {what} (tag {tag:#04x}), found tag {:#04x} — is this the right \
                 kind of DER? A CRL is a CertificateList, an OCSP response an OCSPResponse",
                t.tag
            )));
        }
        Ok(t)
    }

    fn oid(&mut self, what: &str) -> Result<ObjectIdentifier> {
        let t = self.expect(tlv::TAG_OID, what)?;
        ObjectIdentifier::from_bytes(t.content)
            .map_err(|e| Error::Verification(format!("{what} is not a readable OID: {e}")))
    }

    fn small_uint(&mut self, what: &str) -> Result<u32> {
        let t = self.expect(tlv::TAG_INTEGER, what)?;
        enumerated(&t, what)
    }
}

fn read_len(b: &[u8]) -> Result<(usize, usize)> {
    let first = *b
        .first()
        .ok_or_else(|| Error::Verification("the revocation data ends mid length".into()))?;
    if first < 0x80 {
        return Ok((first as usize, 1));
    }
    let n = (first & 0x7f) as usize;
    if n == 0 {
        return Err(Error::Verification(
            "indefinite length is BER, and this reads DER".into(),
        ));
    }
    if n > 8 || b.len() < 1 + n {
        return Err(Error::Verification(
            "a DER length that is overlong or runs past the input".into(),
        ));
    }
    let mut v = 0usize;
    for x in &b[1..=n] {
        v = (v << 8) | usize::from(*x);
    }
    Ok((v, n + 1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::Encode;
    use openfirma_core::signer::{Signer, SoftwareSigner};
    use std::path::{Path, PathBuf};
    use std::time::Duration;

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

    fn cert(name: &str) -> CertificateHandle {
        let pem = std::fs::read_to_string(certs_dir().join(name))
            .unwrap_or_else(|e| panic!("{name} is listed in the test PKI but cannot be read: {e}"));
        CertificateHandle::from_pem(&pem).unwrap_or_else(|e| panic!("{name}: {e}"))
    }

    #[test]
    fn a_crl_from_the_test_pki_verifies_under_its_ca() {
        let (Ok(int_crl), Ok(ca_crl)) = (
            std::fs::read(certs_dir().join("intermediate.crl.der")),
            std::fs::read(certs_dir().join("ca.crl.der")),
        ) else {
            require_or_skip("the test PKI has no CRLs, rerun tools/gen-testcert.sh");
            return;
        };
        let int = cert("intermediate.crt");
        let ca = cert("ca.crt");

        let report = verify_crl(&int_crl, &[int.clone(), ca.clone()], SystemTime::now())
            .expect("the intermediate's CRL must verify under the intermediate");
        assert!(report.issuer.contains("Intermediate"), "{}", report.issuer);
        assert!(
            report.revoked_serials.is_empty(),
            "an empty CRL revokes nothing"
        );

        let report = verify_crl(&ca_crl, &[int.clone(), ca.clone()], SystemTime::now())
            .expect("the root's CRL must verify under the root");
        assert!(report.issuer.contains("Root CA"), "{}", report.issuer);

        // and each CRL only verifies under its own CA: the issuer name is not
        // enough, the key has to match it
        let err = verify_crl(&int_crl, std::slice::from_ref(&ca), SystemTime::now()).unwrap_err();
        assert!(
            err.to_string().contains("none of the 1 certificate"),
            "{err}"
        );
        let err = verify_crl(&ca_crl, std::slice::from_ref(&int), SystemTime::now()).unwrap_err();
        assert!(
            err.to_string().contains("none of the 1 certificate"),
            "{err}"
        );
    }

    /// A CRL that names a real CA as its issuer but is signed by a different
    /// key must be refused: the name is data anyone can write, the signature
    /// is the only thing that makes it a statement by that CA.
    #[test]
    fn a_crl_signed_by_the_wrong_key_is_refused() {
        let Ok(int_pem) = std::fs::read_to_string(certs_dir().join("intermediate.crt")) else {
            require_or_skip("test PKI missing, run tools/gen-testcert.sh");
            return;
        };
        let (Ok(ca_cert_pem), Ok(ca_key_pem)) = (
            std::fs::read_to_string(certs_dir().join("ca.crt")),
            std::fs::read_to_string(certs_dir().join("ca.key")),
        ) else {
            require_or_skip("test PKI missing, run tools/gen-testcert.sh");
            return;
        };
        let int = CertificateHandle::from_pem(&int_pem).expect("intermediate.crt");
        let root_signer = SoftwareSigner::from_pkcs8_pem(&ca_cert_pem, &ca_key_pem)
            .expect("the root key of the test PKI must load");

        let fake = fake_crl_signed_by(&int, &root_signer);
        let err = verify_crl(&fake, std::slice::from_ref(&int), SystemTime::now())
            .expect_err("a CRL signed by the wrong key must not verify");
        let text = err.to_string();
        assert!(text.contains("signed by a different key"), "{text}");
    }

    /// A well formed CRL naming `issuer`'s subject, signed with `signer`'s
    /// key. When the two do not belong together this is a forged CRL.
    fn fake_crl_signed_by(issuer: &CertificateHandle, signer: &dyn Signer) -> Vec<u8> {
        let now = SystemTime::now();
        let alg = tlv::sequence(&[tlv::oid(&oid::ID_SHA256_WITH_RSA).unwrap(), tlv::null()]);
        let tbs = tlv::sequence(&[
            alg.clone(),
            issuer.subject_der().unwrap(),
            tlv::utc_time(now - Duration::from_secs(86_400)).unwrap(),
            tlv::utc_time(now + Duration::from_secs(30 * 86_400)).unwrap(),
        ]);
        let prehash = DigestAlg::Sha256.digest(&tbs);
        let signature = signer.sign_prehash(DigestAlg::Sha256, &prehash).unwrap();
        tlv::sequence(&[
            tbs,
            alg,
            tlv::tlv(tlv::TAG_BIT_STRING, &[&[0u8][..], &signature].concat()),
        ])
    }

    #[test]
    fn an_ocsp_response_is_read_down_to_its_cert_ids() {
        // good is [0] IMPLICIT NULL: tag 0x80, no content
        let synthetic = synthetic_ocsp_response(0, &[0x80, 0x00]);
        let ids = parse_ocsp_response(&synthetic).expect("a successful response must parse");
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0].hash_algorithm, oid::ID_SHA1);
        assert!(!ids[0].revoked);

        let refused = synthetic_ocsp_response(6, &[0xa0]);
        let err = parse_ocsp_response(&refused)
            .expect_err("an unauthorized response is not a revocation datum");
        assert!(err.to_string().contains("unauthorized"), "{err}");

        // revoked [1] IMPLICIT RevokedInfo { revocationTime GeneralizedTime }
        let rev_time = GeneralizedTime::from_system_time(SystemTime::now())
            .unwrap()
            .to_der()
            .unwrap();
        let revoked =
            synthetic_ocsp_response(0, &[&[0xa1, rev_time.len() as u8][..], &rev_time].concat());
        let ids = parse_ocsp_response(&revoked).expect("a revoked answer still parses");
        assert!(ids[0].revoked, "certStatus [1] means revoked");

        let unknown = synthetic_ocsp_response(0, &[0x82, 0x00]);
        assert!(
            parse_ocsp_response(&unknown).is_err(),
            "an \"unknown\" answer says nothing and must be refused"
        );
    }

    /// A minimal `OCSPResponse` with one `SingleResponse` whose `certStatus`
    /// is the raw choice bytes given. `status` is the `responseStatus`.
    /// No signature is computed: this parser deliberately does not check it.
    fn synthetic_ocsp_response(status: u8, cert_status: &[u8]) -> Vec<u8> {
        let now = SystemTime::now();
        let produced_at = GeneralizedTime::from_system_time(now)
            .unwrap()
            .to_der()
            .unwrap();
        let cert_id = tlv::sequence(&[
            tlv::sequence(&[tlv::oid(&oid::ID_SHA1).unwrap(), tlv::null()]),
            tlv::octet_string(&[1u8; 20]).unwrap(),
            tlv::octet_string(&[2u8; 20]).unwrap(),
            tlv::tlv(tlv::TAG_INTEGER, &[0x12, 0x34]),
        ]);
        let single = tlv::sequence(&[cert_id, cert_status.to_vec(), produced_at.clone()]);
        let responder_id = tlv::tlv(0xa2, &[3u8; 20]); // byKey
        let response_data = tlv::sequence(&[responder_id, produced_at, tlv::sequence(&[single])]);
        let basic = tlv::sequence(&[
            response_data,
            tlv::sequence(&[tlv::oid(&oid::ID_SHA256_WITH_RSA).unwrap(), tlv::null()]),
            tlv::tlv(tlv::TAG_BIT_STRING, &[0x00, 0x01, 0x02]),
        ]);
        let response_bytes = tlv::tlv(
            0xa0,
            &tlv::sequence(&[
                tlv::oid(&oid::ID_PKIX_OCSP_BASIC).unwrap(),
                tlv::octet_string(&basic).unwrap(),
            ]),
        );
        tlv::sequence(&[tlv::tlv(0x0a, &[status]), response_bytes])
    }

    #[test]
    fn the_issuer_hashes_are_the_rfc_6960_ones() {
        // RFC 6960 4.1.1: SHA-1 over the DER of the DN without its outer tag
        // and length, and over the public key bit string. Cross-checked
        // against `openssl ocsp -issuer ... -cert ... -reqout` output.
        let Ok(cert_pem) = std::fs::read_to_string(certs_dir().join("signer-rsa.crt")) else {
            require_or_skip("test PKI missing, run tools/gen-testcert.sh");
            return;
        };
        let Ok(int_pem) = std::fs::read_to_string(certs_dir().join("intermediate.crt")) else {
            require_or_skip("test PKI missing, run tools/gen-testcert.sh");
            return;
        };
        let c = CertificateHandle::from_pem(&cert_pem).expect("signer-rsa.crt");
        let int = CertificateHandle::from_pem(&int_pem).expect("intermediate.crt");
        let (name_hash, key_hash) = ocsp_issuer_hashes(&int, DigestAlg::Sha1).unwrap();
        assert_eq!(name_hash.len(), 20);
        assert_eq!(key_hash.len(), 20);

        // the request openssl writes for this certificate must carry the same
        // hashes, which is the independent confirmation
        let out = std::process::Command::new("openssl")
            .args([
                "ocsp",
                "-issuer",
                certs_dir().join("intermediate.crt").to_str().unwrap(),
                "-cert",
                certs_dir().join("signer-rsa.crt").to_str().unwrap(),
                "-reqout",
                "/dev/stdout",
            ])
            .output();
        let Ok(out) = out else {
            eprintln!("skipped, openssl not found");
            return;
        };
        if !out.status.success() {
            eprintln!(
                "skipped, openssl ocsp refused to build a request: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            return;
        }
        assert!(
            out.stdout.windows(20).any(|w| w == name_hash.as_slice()),
            "openssl's request does not carry our issuerNameHash"
        );
        assert!(
            out.stdout.windows(20).any(|w| w == key_hash.as_slice()),
            "openssl's request does not carry our issuerKeyHash"
        );
        let _ = c;
    }
}
