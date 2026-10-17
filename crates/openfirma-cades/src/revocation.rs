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

use crate::verify::{
    AlgorithmPolicy, CHECK_CERTIFICATE_CHAIN, check_algorithm_policy, check_key_strength,
    detail_of, digest_from_signature_oid, subject,
};

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

/// `id-kp-OCSPSigning` (RFC 6960 4.2.2.2): the extended key usage a respon-
/// der other than the CA itself must carry to speak for that CA.
const OID_EKU_OCSP_SIGNING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.9");

/// What reading an archived OCSP response establishes, part by part. Every
/// part is reported separately because the archive consumer must be able to
/// tell "nobody made this statement" from "the statement is genuine but its
/// interval ended": only [`OcspStatus::verified`] counts as a revocation da-
/// tum, but the reasons are what a user needs to hear.
#[derive(Clone, Debug)]
pub struct OcspStatus {
    /// The signature over `tbsResponseData` verifies under some certificate
    /// this response itself carries or the pool does.
    pub signature_verified: bool,
    /// That signer is the CA the CertIDs name, or a delegate that CA autho-
    /// rized with `id-kp-OCSPSigning` and that chains to it (RFC 6960
    /// 4.2.2.2). False also when the named CA is not in the pool at all.
    pub chains_to_issuer: bool,
    /// `at` falls inside `thisUpdate <= at < nextUpdate` (nextUpdate absent
    /// means no upper bound known to RFC 6960, which keeps the statement cu-
    /// rrent — same reading as a CRL without one).
    pub current: bool,
    /// `thisUpdate` of the first SingleResponse.
    pub this_update: SystemTime,
    /// `nextUpdate`, when present.
    pub next_update: Option<SystemTime>,
    /// The CertIDs, so /VRI-style association can proceed on a verified an-
    /// swer without parsing it twice.
    pub cert_ids: Vec<OcspCertId>,
    /// Why the response does not count; `None` exactly when [`Self::verified`]
    /// holds.
    pub problem: Option<String>,
}

impl OcspStatus {
    /// Whether this response may be counted as a revocation datum: every
    /// part above checked out for `at`.
    pub fn verified(&self) -> bool {
        self.problem.is_none()
    }
}

/// Reads AND verifies an OCSP response the way [`verify_crl`] does a CRL, so
/// archived validation data can be trusted on its own years after signing
/// (adversarial review A4). The signature is taken over the whole `tbsRes-
/// ponseData` TLV as encoded — RFC 6960 signs those bytes, not a re-encoded
/// model of them — under either the CA each CertID names by its hashes, or a
/// certificate that response embeds whose EKU names `id-kp-OCSPSigning` and
/// that chains to that CA. An absence of extendedKeyUsage means any purpose
/// (RFC 5280 4.2.1.12), so the CA's own certificate never carries the delega-
/// tion OID. A response signed by nobody in that set — even one whose crypto-
/// graphic signature is perfectly readable under a leaf key — makes no state-
/// ment and reports `signature_verified`/`chains_to_issuer` accordingly.
pub fn read_ocsp_response(der: &[u8], issuers: &[CertificateHandle], at: SystemTime) -> OcspStatus {
    match read_and_check(der, issuers, at) {
        Ok(status) => status,
        Err(e) => OcspStatus {
            signature_verified: false,
            chains_to_issuer: false,
            current: false,
            this_update: SystemTime::UNIX_EPOCH,
            next_update: None,
            cert_ids: Vec::new(),
            problem: Some(detail_of(&e)),
        },
    }
}

fn read_and_check(der: &[u8], issuers: &[CertificateHandle], at: SystemTime) -> Result<OcspStatus> {
    // ---- structure down to tbsResponseData, kept as whole TLV bytes -------
    let mut outer = der_cursor(der);
    let resp = outer.expect(tlv::TAG_SEQUENCE, "the OCSPResponse")?;
    if !outer.done() {
        return Err(trailing("after the OCSPResponse"));
    }
    let mut r = der_cursor(resp.content);
    let status = r.expect(0x0a, "responseStatus")?; // ENUMERATED
    let code = enumerated(&status, "responseStatus")?;
    if code != 0 {
        return Err(Error::Verification(format!(
            "the OCSP responder answered \"{}\" (status {code}), not \"successful\"",
            ocsp_status_name(code)
        )));
    }
    let bytes = r.expect(0xa0, "responseBytes")?;
    let mut rb = der_cursor(bytes.content);
    let seq = rb.expect(tlv::TAG_SEQUENCE, "ResponseBytes")?;
    let mut s = der_cursor(seq.content);
    let response_type = s.oid("ResponseBytes.responseType")?;
    if response_type != oid::ID_PKIX_OCSP_BASIC {
        return Err(Error::Verification(format!(
            "the OCSP responseBytes carry {response_type}, only a BasicOCSPResponse \
             ({}) can be read",
            oid::ID_PKIX_OCSP_BASIC
        )));
    }
    let basic_octets = s.expect(tlv::TAG_OCTET_STRING, "ResponseBytes.response")?;
    let mut b = der_cursor(basic_octets.content);
    let basic = b.expect(tlv::TAG_SEQUENCE, "the BasicOCSPResponse")?;
    let mut t = der_cursor(basic.content);
    let rd = t.expect(tlv::TAG_SEQUENCE, "tbsResponseData")?;
    let sa = t.expect(tlv::TAG_SEQUENCE, "BasicOCSPResponse.signatureAlgorithm")?;
    let sig = t.expect(tlv::TAG_BIT_STRING, "BasicOCSPResponse.signature")?;
    // optional [0] certs: whatever the responder embedded to prove who speaks
    let mut embedded: Vec<CertificateHandle> = Vec::new();
    if t.peek_tag() == Some(0xa0) {
        let certs = t.expect(0xa0, "BasicOCSPResponse.certs")?;
        // `[0] EXPLICIT Certificate` — one certificate wrapped in a SEQUENCE,
        // or RFC 6960's IMPLICIT SET OF reading: several bare certificates.
        // from_der on each element decides which shape the content has.
        let mut c = der_cursor(certs.content);
        let mut first = true;
        while !c.done() {
            let cert = c.expect(tlv::TAG_SEQUENCE, "an embedded certificate")?;
            match CertificateHandle::from_der(cert.whole) {
                Ok(handle) => embedded.push(handle),
                Err(first_err) => {
                    // the explicit wrapper: its content is one whole certificate
                    let mut inner = der_cursor(cert.content);
                    let mut recovered = false;
                    while !inner.done() {
                        let one = inner.expect(tlv::TAG_SEQUENCE, "an embedded certificate")?;
                        match CertificateHandle::from_der(one.whole) {
                            Ok(handle) => {
                                embedded.push(handle);
                                recovered = true;
                            }
                            Err(e) => {
                                // a SET OF reading where this element really is
                                // no certificate: only then is it an error, and
                                // only when nothing at all parsed before it
                                if !recovered && first {
                                    return Err(Error::Verification(format!(
                                        "the OCSP response's embedded certificates do not \
                                         parse: {first_err}; {e}"
                                    )));
                                }
                            }
                        }
                    }
                }
            }
            first = false;
        }
    }

    // ---- what the response says: responderID, interval, CertIDs ----------
    let mut d = der_cursor(rd.content);
    if d.peek_tag() == Some(0xa0) {
        let _version = d.value()?; // [0] EXPLICIT version
    }
    let responder_id = match d.peek_tag() {
        // [1] byName / [2] byKey: the constructed CHOICE alternatives, tag 0xA1
        // or 0xA2. A `[x] EXPLICIT Name` spelling wraps them in an outer SEQUENCE,
        // which is unwrapped below to reach the same choice anyway.
        Some(0xa1) | Some(0xa2) => d.value()?,
        _ => {
            let wrapped = d.expect(tlv::TAG_SEQUENCE, "responderID")?;
            match der_cursor(wrapped.content).peek_tag() {
                Some(0xa1) | Some(0xa2) => wrapped,
                _ => {
                    return Err(Error::Verification(
                        "responderID is neither byName [1] nor byKey [2]".into(),
                    ));
                }
            }
        }
    };
    let _produced_at = d.value()?; // GeneralizedTime: when, not what, was answered
    let responses = d.expect(tlv::TAG_SEQUENCE, "the SingleResponse list")?;

    let mut by_key_hash: Option<Vec<u8>> = None;
    // the constructed CHOICE alternatives are 0xA1/0xA2; inside one, byName's
    // content is a plain SEQUENCE Name (0x30) and byKey's an OCTET STRING.
    let (choice, inner_first) = match responder_id.content.first().copied() {
        Some(outer) if matches!(outer, 0xa1 | 0xa2) => {
            let inner = der_cursor(responder_id.content).value()?;
            (outer, inner)
        }
        _ => (responder_id.tag, der_cursor(responder_id.content).value()?),
    };
    match choice {
        // [1] byName: a Name. A delegate's responderID is its own subject, so
        // authority is judged from EKU and chain, not from this field.
        0xa1 => {}
        // [2] byKey: the SHA-1 of the responder's SubjectPublicKeyInfo
        // (RFC 6960 4.1.1), which names a specific certificate outright.
        0xa2 => by_key_hash = Some(inner_first.content.to_vec()),
        other => {
            return Err(Error::Verification(format!(
                "responderID has tag {other:#04x}, expected [1] byName or [2] byKey"
            )));
        }
    }

    let mut this_update = None;
    let mut next_update = None;
    let mut cert_ids: Vec<OcspCertId> = Vec::new();
    let mut rs = der_cursor(responses.content);
    while !rs.done() {
        let single = rs.expect(tlv::TAG_SEQUENCE, "a SingleResponse")?;
        let mut sc = der_cursor(single.content);
        let cert_id = sc.expect(tlv::TAG_SEQUENCE, "SingleResponse.certID")?;
        let mut c = der_cursor(cert_id.content);
        let mut alg = der_cursor(c.expect(tlv::TAG_SEQUENCE, "CertID.hashAlgorithm")?.content);
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
        let cert_status = sc.value()?;
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
        let this = time_value(&mut sc, "thisUpdate")?;
        // nextUpdate [0] EXPLICIT GeneralizedTime OPTIONAL — the parser that
        // read a bare UTCTime/GeneralizedTime here missed every real one: op-
        // enssl and friends wrap it in the context tag, so reading raw walked
        // past an answer's expiry entirely.
        let next = match sc.peek_tag() {
            Some(0xa0) => {
                let wrapped = sc.expect(0xa0, "nextUpdate")?;
                let mut inner = der_cursor(wrapped.content);
                Some(time_value(&mut inner, "nextUpdate")?)
            }
            Some(tlv::TAG_UTC_TIME) | Some(0x18) => Some(time_value(&mut sc, "nextUpdate")?),
            _ => None,
        };
        if this_update.is_none() {
            this_update = Some(this);
        } else if Some(this) != this_update {
            return Err(Error::Verification(
                "the SingleResponses of one response carry different thisUpdate values".into(),
            ));
        }
        match (next_update, next) {
            (None, _) => next_update = next,
            (Some(seen), Some(now)) if seen != now => {
                return Err(Error::Verification(
                    "the SingleResponses of one response carry different nextUpdate values".into(),
                ));
            }
            _ => {}
        }
        cert_ids.push(OcspCertId {
            hash_algorithm,
            issuer_name_hash,
            issuer_key_hash,
            serial,
            revoked: cert_status.tag == 0xa1,
        });
    }
    let this_update = this_update.ok_or_else(|| {
        Error::Verification("the OCSP response answers for no certificate at all".into())
    })?;

    // ---- signature over the very bytes of tbsResponseData -----------------
    let sig_oid = der_cursor(sa.content).oid("BasicOCSPResponse.signatureAlgorithm")?;
    let digest = digest_from_signature_oid(&sig_oid)?;
    let (unused, sig_bytes) = bit_string(&sig, "the OCSP response signature")?;
    if unused != 0 {
        return Err(Error::Verification(
            "the OCSP response signature's BIT STRING says a partial final byte".into(),
        ));
    }
    // The CertIDs hash the CA they name; the pool certificate matching those
    // hashes is who may speak (directly or by delegation). SHA-1 in practice.
    let mut named_cas: Vec<&CertificateHandle> = Vec::new();
    for id in &cert_ids {
        let alg = DigestAlg::from_oid(&id.hash_algorithm)
            .map_err(|e| Error::Verification(detail_of(&e)))?;
        // hashes over the WHOLE DER of the issuer Name and of its SubjectPublicKeyInfo —
        // ocsp_issuer_hashes takes exactly that, from_der on bare content bytes would
        // report a parse error as if the pool were wrong
        let found = issuers.iter().find(|ca| match ocsp_issuer_hashes(ca, alg) {
            Ok((name_hash, key_hash)) => {
                name_hash == id.issuer_name_hash && key_hash == id.issuer_key_hash
            }
            Err(_) => false,
        });
        if let Some(ca) = found {
            if !named_cas.iter().any(|other| other.der() == ca.der()) {
                named_cas.push(ca);
            }
        }
    }
    if named_cas.is_empty() {
        return Err(Error::Verification(
            "the CA the CertIDs name as issuer is not among the supplied certificates: the \
             response cannot be tied to any chain"
                .into(),
        ));
    }

    let pool: Vec<CertificateHandle> = embedded.iter().chain(issuers.iter()).cloned().collect();
    let mut signature_verified = false;
    let mut chains_to_issuer = false;
    for candidate in &pool {
        if verify_prehash(candidate, digest, &digest.digest(rd.whole), sig_bytes).is_err() {
            continue;
        }
        signature_verified = true;
        // byKey must name this certificate outright
        if let Some(hash) = &by_key_hash {
            let responder_key_hash = DigestAlg::Sha1.digest(&candidate.spki_der()?);
            if responder_key_hash.as_slice() != hash.as_slice() {
                continue;
            }
        }
        for ca in &named_cas {
            let authority = if candidate.der() == ca.der() {
                // the CA itself answered
                true
            } else {
                // a delegate: id-kp-OCSPSigning (or no EKU extension at all,
                // which RFC 5280 reads as any purpose) and chains to that CA
                let delegated = match eku_of(candidate) {
                    None => true,
                    Some(eku) => eku.contains(&OID_EKU_OCSP_SIGNING),
                };
                delegated && chain_certificates_ok(candidate, &embedded, &[(*ca).clone()], at)
            };
            if authority {
                chains_to_issuer = true;
                break;
            }
        }
        if chains_to_issuer {
            break;
        }
    }

    // ---- interval ----------------------------------------------------------
    let current = match next_update {
        Some(next) => this_update <= at && at < next,
        None => this_update <= at,
    };

    let problem: Option<String> = if !signature_verified {
        Some(
            "the OCSP response signature does not verify under any certificate it carries \
             or any supplied one"
                .to_string(),
        )
    } else if !chains_to_issuer {
        Some(
            "whoever signed the OCSP response is neither the CA the CertIDs name nor a dele- \
             gate that CA authorized with id-kp-OCSPSigning (RFC 6960 4.2.2.2)"
                .to_string(),
        )
    } else if !current {
        Some(match next_update {
            Some(next) => format!(
                "the OCSP answer speaks for [{}, {}) and the validation time is outside \
                 that interval",
                fmt_time(this_update),
                fmt_time(next)
            ),
            None => format!(
                "the OCSP answer's thisUpdate, {}, is after the validation time",
                fmt_time(this_update)
            ),
        })
    } else {
        None
    };

    Ok(OcspStatus {
        signature_verified,
        chains_to_issuer,
        current,
        this_update,
        next_update,
        cert_ids,
        problem,
    })
}

/// The extendedKeyUsage OIDs of a certificate, `None` when it carries no such
/// extension (which RFC 5280 reads as any purpose).
fn eku_of(cert: &CertificateHandle) -> Option<Vec<ObjectIdentifier>> {
    use der::Decode as _;
    use x509_cert::ext::pkix::ExtendedKeyUsage;
    // the extendedKeyUsage OID, RFC 5280 4.2.1.12
    const OID_EXTENDED_KEY_USAGE: &str = "2.5.29.37";
    let tbs = cert.parsed().tbs_certificate();
    for ext in tbs.extensions()? {
        if ext.extn_id.to_string() == OID_EXTENDED_KEY_USAGE {
            let Ok(eku) = ExtendedKeyUsage::from_der(ext.extn_value.as_bytes()) else {
                return Some(Vec::new());
            };
            return Some(eku.0.to_vec());
        }
    }
    None
}

fn chain_certificates_ok(
    signer: &CertificateHandle,
    embedded: &[CertificateHandle],
    anchors: &[CertificateHandle],
    at: SystemTime,
) -> bool {
    crate::verify::chain_certificates(signer, embedded, anchors, at).is_ok()
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
/// The CRL entry-less extensions whose presence a reader understands enough
/// to ignore safely when non-critical (RFC 5280 5.2): the issuing-distribution-
/// point family and the delta indicator are NOT in this list, because they
/// change what "this list covers" means, so critical ones are refused above.
const CRL_EXTENSIONS_UNDERSTOOD: &[ObjectIdentifier] = &[
    // authorityKeyIdentifier — names the issuer, which verify_crl matched by
    // name and key already; it carries no scope claim.
    ObjectIdentifier::new_unwrap("2.5.29.35"),
    // authInfoAccess — pointers to fetch things; nothing about state.
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.1"),
    // cRLNumber — a sequence number for the list, no scope claim either.
    ObjectIdentifier::new_unwrap("2.5.29.20"),
];

/// The `crlExtensions` of a parsed tbsCertList: every (OID, critical) pair in
/// `[0] crlExtensions`. A malformed block yields no extensions rather than an
/// error: its absence is not what this function's verdict rests on, and the
/// DER cursor has already bounds-checked its way to here.
fn crl_extensions(tbs_content: &[u8]) -> Vec<(ObjectIdentifier, bool)> {
    let mut out = Vec::new();
    let mut f = der_cursor(tbs_content);
    if f.peek_tag() == Some(tlv::TAG_INTEGER) {
        let _ = f.value(); // version
    }
    let _ = f.value(); // signature AlgorithmIdentifier
    let _ = f.value(); // issuer Name
    let _ = f.value(); // thisUpdate
    if matches!(f.peek_tag(), Some(tlv::TAG_UTC_TIME) | Some(0x18)) {
        let _ = f.value(); // nextUpdate
    }
    if f.peek_tag() == Some(tlv::TAG_SEQUENCE) {
        let _ = f.value(); // revokedCertificates
    }
    let Ok(exts) = f.expect(0xA0, "crlExtensions") else {
        return out;
    };
    let Ok(exts) = der_cursor(exts.content).expect(tlv::TAG_SEQUENCE, "the extensions SEQUENCE")
    else {
        return out;
    };
    let mut e = der_cursor(exts.content);
    while !e.done() {
        let Ok(one) = e.expect(tlv::TAG_SEQUENCE, "one CRL extension") else {
            break;
        };
        let mut o = der_cursor(one.content);
        let Ok(oid) = o.oid("the CRL extension OID") else {
            break;
        };
        let critical = match o.peek_tag() {
            Some(tlv::TAG_BOOLEAN) => match o.value() {
                Ok(v) => v.content.first().copied().unwrap_or(0) != 0,
                Err(_) => break,
            },
            _ => false, // absent means FALSE (RFC 5280 4.1.2.9)
        };
        out.push((oid, critical));
    }
    out
}

pub fn verify_crl(der: &[u8], issuers: &[CertificateHandle], at: SystemTime) -> Result<CrlReport> {
    let mut outer = der_cursor(der);
    let list = outer.expect(tlv::TAG_SEQUENCE, "the CertificateList")?;
    if !outer.done() {
        return Err(trailing("after the CertificateList"));
    }

    let mut f = der_cursor(list.content);
    let tbs = f.expect(tlv::TAG_SEQUENCE, "tbsCertList")?;
    let mut t = der_cursor(tbs.content);
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
    let mut sig_alg = der_cursor(
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
        let revoked_list = t.value()?;
        let mut rc = der_cursor(revoked_list.content);
        while !rc.done() {
            let entry = rc.expect(tlv::TAG_SEQUENCE, "a revokedCertificates entry")?;
            let mut e = der_cursor(entry.content);
            let serial = e.expect(tlv::TAG_INTEGER, "the revoked serial number")?;
            revoked_serials.push(serial.content.to_vec());
            // revocationDate and any entry extensions carry nothing we check
        }
    }
    // M8: crlExtensions is interpreted for the one thing that changes what
    // the bytes mean when nothing is said about it — a CRITICAL extension.
    // `deltaCRLIndicator` or `issuingDistributionPoint` marked critical make
    // this list something other than "the complete revocation state", and
    // reading it as complete turns an empty delta into "nothing revoked". A
    // non-critical extension says, by RFC 5280's own rule, that a reader may
    // ignore it, so only the critical ones are refused here. `authorityInfoAccess`
    // (id-pkix-...) is common and understood to carry nothing about revocation
    // state itself; `deltaCRLIndicator` and the DPD OIDs appear in errors by
    // their dotted form because this reader does not decode their content.
    for (oid, critical) in crl_extensions(tbs.content) {
        if critical && !CRL_EXTENSIONS_UNDERSTOOD.contains(&oid) {
            return Err(Error::Verification(format!(
                "the CRL marks extension {oid} critical; it says the list must be read \
                 with a meaning this reader does not implement (a delta or partitioned \
                 CRL is not the complete revocation state), and RFC 5280 4.2 forbids \
                 accepting one"
            )));
        }
    }

    let mut sa = der_cursor(f.expect(tlv::TAG_SEQUENCE, "signatureAlgorithm")?.content);
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
    // M5 again: an archived CRL nobody can any longer trust cryptographically
    // (SHA-1 signature, 1024-bit CA) is not long-term validation data, and a
    // B-LT archive exists precisely to be trusted years later. The CRL signs
    // with the issuer's key, so that certificate's strength is what counts.
    check_algorithm_policy(CHECK_CERTIFICATE_CHAIN, digest, &AlgorithmPolicy::default())?;
    let prehash = digest.digest(tbs.whole);

    // The issuing CA is found by name and proved by key: a CRL that names a
    // CA but is signed by anyone else is exactly the attack this check stops.
    let mut candidates = 0usize;
    let mut crl_sign_rejections = 0usize;
    for cert in issuers {
        if cert.subject_der().ok().as_deref() != Some(issuer.whole) {
            continue;
        }
        candidates += 1;
        if verify_prehash(cert, digest, &prehash, sig_bytes).is_err() {
            continue;
        }
        // M8: the certificate whose key verified the signature gets judged
        // for the role a CRL demands of it — `cRLSign` in its keyUsage when
        // keyUsage is present. A CA may delegate CRL signing to another
        // certificate of the same name, so one candidate without cRLSign
        // moves on instead of condemning the list; if none carries it, the
        // refusal below names cRLSign as the reason. The strength policy
        // applies to that key too: archived revocation data must outlive its
        // own crypto, which is what B-LT archives are for.
        if !cert.key_usage().is_none_or(|ku| ku.crl_sign()) {
            crl_sign_rejections += 1;
            continue;
        }
        check_key_strength(
            CHECK_CERTIFICATE_CHAIN,
            cert.key_info()
                .map_err(|e| Error::Verification(detail_of(&e)))?,
            &AlgorithmPolicy::default(),
        )?;
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
        // A CRL is only a revocation datum if its signer may sign CRLs: the
        // candidate whose key verified the signature but whose keyUsage says
        // it may not was rejected above without reaching this point.
        return Ok(CrlReport {
            issuer: subject(cert),
            issuer_der: issuer.whole.to_vec(),
            this_update,
            next_update,
            revoked_serials,
        });
    }

    let issuer_name = name_string(issuer.whole);
    if candidates > 0 && crl_sign_rejections == candidates {
        return Err(Error::Verification(format!(
            "the CRL's signature verifies under \"{issuer_name}\", but that certificate's \
             keyUsage does not grant cRLSign (RFC 5280 4.2.1.3): something with that name \
             signed this list without being allowed to, which is not a revocation datum"
        )));
    }
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
    let mut outer = der_cursor(der);
    let list = outer.expect(tlv::TAG_SEQUENCE, "the CertificateList")?;
    let mut f = der_cursor(list.content);
    let tbs = f.expect(tlv::TAG_SEQUENCE, "tbsCertList")?;
    let mut t = der_cursor(tbs.content);
    if t.peek_tag() == Some(tlv::TAG_INTEGER) {
        let _version = t.value()?;
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
    let mut outer = der_cursor(der);
    let resp = outer.expect(tlv::TAG_SEQUENCE, "the OCSPResponse")?;
    if !outer.done() {
        return Err(trailing("after the OCSPResponse"));
    }
    let mut r = der_cursor(resp.content);
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
    let mut rb = der_cursor(bytes.content);
    let seq = rb.expect(tlv::TAG_SEQUENCE, "ResponseBytes")?;
    let mut s = der_cursor(seq.content);
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
    let mut b = der_cursor(basic_octets.content);
    let basic = b.expect(tlv::TAG_SEQUENCE, "the BasicOCSPResponse")?;
    let mut t = der_cursor(basic.content);
    let rd = t.expect(tlv::TAG_SEQUENCE, "tbsResponseData")?;
    let mut d = der_cursor(rd.content);
    // version [0] EXPLICIT DEFAULT v1
    if d.peek_tag() == Some(0xa0) {
        let _version = d.value()?;
    }
    // responderID: [1] byName or [2] byKey; not interpreted, see module docs
    let _responder_id = d.value()?;
    let _produced_at = d.expect(0x18, "producedAt")?; // GeneralizedTime
    let responses = d.expect(tlv::TAG_SEQUENCE, "the SingleResponse list")?;

    let mut out = Vec::new();
    let mut rs = der_cursor(responses.content);
    while !rs.done() {
        let single = rs.expect(tlv::TAG_SEQUENCE, "a SingleResponse")?;
        let mut sc = der_cursor(single.content);
        let cert_id = sc.expect(tlv::TAG_SEQUENCE, "SingleResponse.certID")?;
        let mut c = der_cursor(cert_id.content);
        let mut alg = der_cursor(c.expect(tlv::TAG_SEQUENCE, "CertID.hashAlgorithm")?.content);
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
        let cert_status = sc.value()?;
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

/// `OCSPResponseStatus` and `CRLReason` are ENUMERATEDs; some producers write
/// them with the INTEGER tag, which DER reserves for 0x0A alone. The review
/// round fixed the reader to accept both, so keep accepting both: decode an
/// INTEGER through the strict shared helper and take anything else's content
/// as a small unsigned value.
fn enumerated(t: &Tlv<'_>, what: &str) -> Result<u32> {
    let bad = |v: u8| {
        Error::Verification(format!(
            "{what} is tag {v:#04x} carrying a value that is not a small non negative integer"
        ))
    };
    if t.tag == tlv::TAG_INTEGER {
        return tlv::Cursor::integer_u32(t, what).map_err(|_| bad(t.tag));
    }
    if t.content.len() > 4 || t.content.first().is_some_and(|b| *b & 0x80 != 0) {
        return Err(bad(t.tag));
    }
    let mut v = 0u32;
    for b in t.content {
        v = (v << 8) | u32::from(*b);
    }
    Ok(v)
}

fn time_value(c: &mut Cur<'_>, what: &str) -> Result<SystemTime> {
    let t = c.value()?;
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
// the shared DER cursor of `openfirma_core::tlv`, under the names this module
// already used. Revocation data comes from a CA or an OCSP responder, not
// from us: it is parsed strictly (NO_HIGH_TAG) but with the INTEGER readers
// that accept a BER-style zero pad, so a slightly loose responder is not a
// verification failure.

type Tlv<'a> = tlv::Value<'a>;
type Cur<'a> = tlv::Cursor<'a>;

fn der_cursor(bytes: &[u8]) -> Cur<'_> {
    tlv::Cursor::with_options(bytes, tlv::NO_HIGH_TAG)
}

/// A DER `UTCTime` or `GeneralizedTime` (tag and length included), read as the
/// instant it names; `None` for anything else. The OCSP regressions locate an
/// archived response's interval this way without re-parsing it.
pub fn parse_der_time(der: &[u8]) -> Option<SystemTime> {
    use der::Decode as _;
    match der.first()? {
        0x17 => UtcTime::from_der(der).ok().map(|t| t.to_system_time()),
        0x18 => GeneralizedTime::from_der(der)
            .ok()
            .map(|t| t.to_system_time()),
        _ => None,
    }
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
