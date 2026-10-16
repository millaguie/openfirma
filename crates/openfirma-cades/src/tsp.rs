//! RFC 3161 time-stamp requests and the tokens that come back.
//!
//! B-T is B-B plus one unsigned attribute, `signatureTimeStampToken`, holding a
//! token whose `messageImprint` is the digest of the signature value. The token
//! is what turns "someone signed this" into "someone signed this before this
//! time, according to a TSA", and it is unsigned on purpose: it is added after
//! the signature exists and cannot change it.
//!
//! This module builds the query and reads the answer. It does not know how the
//! answer arrived. Transport is the caller's problem, deliberately: a TSA is
//! reached over HTTPS in real life, and a TLS client in pure Rust is a
//! dependency decision of its own, not something a signature format should
//! smuggle in. Tests answer queries with `openssl ts -reply`, offline.

use std::time::SystemTime;

use openfirma_core::alg::DigestAlg;
use openfirma_core::cert::CertificateHandle;
use openfirma_core::{Error, Result, oid, tlv};

/// `id-ct-TSTInfo`, the content type a time-stamp token carries.
pub const OID_TST_INFO: &str = "1.2.840.113549.1.9.16.1.4";

/// A `TimeStampReq`, RFC 3161 2.4.1.
///
/// `certReq` is true so the TSA includes its certificate chain in the token,
/// which is what lets a validator check the token years later without having
/// to find the TSA certificate some other way.
pub fn request(digest: DigestAlg, message: &[u8], nonce: u64) -> Result<Vec<u8>> {
    let imprint = tlv::sequence(&[
        tlv::algorithm_identifier(&digest.algorithm_identifier()?)?,
        tlv::octet_string(&digest.digest(message))?,
    ]);
    Ok(tlv::sequence(&[
        tlv::integer_small(1),
        imprint,
        // a nonce binds the answer to this query, so a replayed token from
        // another signing run cannot be substituted
        tlv::tlv(tlv::TAG_INTEGER, &minimal_integer(nonce)),
        tlv::tlv(0x01, &[0xff]), // certReq TRUE
    ]))
}

/// Reads a `TimeStampResp`, checks it answers the question we asked, and
/// returns the token as a `ContentInfo`, ready to be embedded.
///
/// Two checks, both of which matter: the status must be granted, and the
/// token's `messageImprint` must be the digest of `message`. Embedding a token
/// that imprints something else would produce a signature whose timestamp
/// proves nothing about it.
pub fn token_from_response(response: &[u8], digest: DigestAlg, message: &[u8]) -> Result<Vec<u8>> {
    let mut outer = Cur::new(response).sequence()?;
    let mut status = outer.sequence()?;
    let code = status.number()?;
    if code != 0 && code != 1 {
        // 0 granted, 1 grantedWithMods; anything else is a refusal
        return Err(Error::Other(format!(
            "the TSA refused the request with PKIStatus {code}"
        )));
    }
    if outer.is_done() {
        return Err(Error::Other(
            "the TSA reported success but sent no token".into(),
        ));
    }

    // the token is a ContentInfo; keep its whole DER, that is what gets embedded
    // outer.i is relative to the TimeStampResp content, so the slice has to be
    // taken from outer.b, not from the whole response
    let token_start = outer.i;
    outer.sequence()?; // step over the token to find where it ends
    let token = &outer.b[token_start..outer.i];
    check_token(token, digest, message)?;
    Ok(token.to_vec())
}

/// Checks that `token`, a `ContentInfo` holding the TSA's `SignedData`,
/// imprints the digest of `message`.
pub fn check_token(token: &[u8], digest: DigestAlg, message: &[u8]) -> Result<()> {
    let mut ci = Cur::new(token).sequence()?;
    let content_type = ci.oid_string()?;
    if content_type != oid::ID_SIGNED_DATA.to_string() {
        return Err(Error::Other(format!(
            "a time-stamp token must be a SignedData, this ContentInfo is {content_type}"
        )));
    }
    // explicit(0) yields the SignedData TLV itself, so step into it
    let mut sd = Cur::new(ci.explicit(0)?).sequence()?;
    check_imprint(&mut sd, digest, message)
}

/// The token inside a `signature-time-stamp-token` unsigned attribute, with
/// its imprint checked against `message`.
///
/// This is how the token gets back out of what a [`crate::TimestampFn`]
/// returns: the closure hands over unsigned *attributes*, and a PDF document
/// time-stamp (B-LTA) embeds the bare token, so the attribute is unwrapped
/// here — under the same imprint check, because a token that imprints
/// something else must never be embedded no matter who produced it.
pub fn token_from_attribute(attr: &[u8], digest: DigestAlg, message: &[u8]) -> Result<Vec<u8>> {
    let mut outer = Cur::new(attr).sequence()?;
    let attr_type = outer.oid_string()?;
    if attr_type != oid::ID_SIGNATURE_TIME_STAMP_TOKEN.to_string() {
        return Err(Error::Other(format!(
            "the attribute is {attr_type}, not a signature-time-stamp-token \
             ({})",
            oid::ID_SIGNATURE_TIME_STAMP_TOKEN
        )));
    }
    let values = outer.expect(tlv::TAG_SET)?;
    // the token is the first value of the SET; slice its whole TLV out
    if values.first() != Some(&tlv::TAG_SEQUENCE) {
        return Err(Error::Other(
            "the time-stamp attribute value is not a ContentInfo SEQUENCE".into(),
        ));
    }
    let (len, n) = read_len(&values[1..])?;
    let end = 1 + n + len;
    if end > values.len() {
        return Err(Error::Other(
            "the time-stamp token runs past its attribute value".into(),
        ));
    }
    let token = &values[..end];
    check_token(token, digest, message)?;
    Ok(token.to_vec())
}

/// The outcome of verifying one time-stamp token: the instant it asserts, and
/// what made it verifiable or not.
#[derive(Clone, Debug)]
pub struct TokenStatus {
    /// `TSTInfo.genTime`, read out of the verified TSTInfo — never off a
    /// re-encoded copy of it.
    pub gen_time: SystemTime,
    /// Subject of the TSA certificate that signed the token.
    pub tsa_subject: String,
}

/// Verifies the TSA's own signature on `token`, and binds everything to the
/// TSTInfo inside it: `contentType = id-ct-TSTInfo`, the `messageDigest`
/// attribute equals the digest of the encapsulated TSTInfo bytes, the ESS
/// `signingCertificate`/`V2` (when the token carries one) names the TSA's own
/// certificate, and that certificate is a time-stamp authority — EKU
/// `id-kp-timeStamping`, RFC 3161 2.3 — chaining to one of `anchors`.
///
/// The binding is the whole point (docs/adversarial-review.md finding C2):
/// before it, only the signed attributes were verified, so rewriting the
/// TSTInfo — the `genTime`, the `messageImprint` — kept verifying, and one
/// genuine token could be laundered into a stamp for any signature at any
/// date. The chain walk itself is the CAdES verifier's (a TST *is* a CMS
/// SignedData); [`crate::verify`] runs in its TST mode over the very bytes of
/// this token, and the imprint of a real request is additionally matched when
/// `message` is `Some`.
///
/// Callers should *warn* rather than refuse on failure when they are signing:
/// a client does not know which TSAs to trust. The verdict side (verify) must
/// treat a token that fails here as unverified, never as evidence of B-T.
pub fn verify_token_signature(
    token: &[u8],
    anchors: &[CertificateHandle],
    at: SystemTime,
) -> Result<TokenStatus> {
    if anchors.is_empty() {
        return Err(Error::Other(
            "no TSA trust anchor was supplied, so the TSA's own signature on the token \
             cannot be verified"
                .into(),
        ));
    }

    // (1) content type: a TST is a SignedData...
    let mut ci = Cur::new(token).sequence()?;
    let content_type = ci.oid_string()?;
    if content_type != oid::ID_SIGNED_DATA.to_string() {
        return Err(Error::Other(format!(
            "a time-stamp token must be a SignedData, this ContentInfo is {content_type}"
        )));
    }
    let mut sd = Cur::new(ci.explicit(0)?).sequence()?;
    let _version = sd.number()?;
    let _digest_algs = sd.tlv()?;

    // (2) ...whose encapContentInfo carries an eContent that is one OCTET
    // STRING holding a TSTInfo. Keep the exact bytes: the messageDigest below
    // hashes them, and only them. RFC 3161 2.2: id-ct-TSTInfo, eContent MUST
    // be present.
    let mut eci = sd.sequence()?;
    let econtent_type = eci.oid_string()?;
    if econtent_type != OID_TST_INFO {
        return Err(Error::Other(format!(
            "the contentType of a time-stamp token must be id-ct-TSTInfo \
             ({OID_TST_INFO}), this SignedData carries {econtent_type}; anything else is not \
             a RFC 3161 token"
        )));
    }
    if eci.peek_tag() != Some(0xA0) {
        return Err(Error::Other(
            "the token's encapContentInfo carries no eContent, and RFC 3161 2.2 puts the \
             TSTInfo in it: a token without a TSTInfo stamps nothing"
                .into(),
        ));
    }

    // (2b) RFC 5652: encapContentInfo.eContent is `[0] EXPLICIT ANY` — a DER
    // OCTET STRING carrying the TSTInfo. A TSA may encode it constructed
    // (BouncyCastle and openssl both do, in definite form); what matters is
    // the concatenated content octets, which the messageDigest below hashes.
    let mut econtent_field = Cur::new(eci.explicit(0)?);
    let (e_tag, e_value) = econtent_field.tlv()?;
    if e_tag != tlv::TAG_OCTET_STRING {
        return Err(Error::Other(format!(
            "a time-stamp token's eContent is an OCTET STRING carrying the TSTInfo \
             (RFC 3161 2.2), this one carries tag {e_tag:#04x}"
        )));
    }
    let econtent = if e_tag & 0x20 == 0 {
        e_value.to_vec()
    } else {
        let mut joined = Vec::with_capacity(e_value.len());
        let mut parts = Cur::new(e_value);
        while !parts.is_done() {
            let (p_tag, p_value) = parts.tlv()?;
            if p_tag != tlv::TAG_OCTET_STRING || p_tag & 0x20 != 0 {
                return Err(Error::Other(format!(
                    "a constructed eContent holds a part with tag {p_tag:#04x}, expected \
                     primitive OCTET STRING segments"
                )));
            }
            joined.extend_from_slice(p_value);
        }
        joined
    };

    // (3) read the TSTInfo out of exactly those bytes
    let tst = parse_tst_info(&econtent)?;

    // (4) certificates and the single SignerInfo, kept as raw DER so the CMS
    // verifier can be pointed at the real token
    let mut certs: Vec<CertificateHandle> = Vec::new();
    let mut signer_infos: Vec<&[u8]> = Vec::new();
    while !sd.is_done() {
        let (tag, value) = sd.tlv()?;
        match tag {
            // [0] the certificate set, RFC 3161 asks the TSA to include its
            // chain because the query set certReq
            0xA0 => {
                let mut set = Cur::new(value);
                while !set.is_done() {
                    let (_, whole, _) = set.tlv_whole()?;
                    certs.push(CertificateHandle::from_der(whole).map_err(|e| {
                        Error::Other(format!("the token carries an unreadable certificate: {e}"))
                    })?);
                }
            }
            0xA1 => {} // CRLs: revocation of the TSA is a validator's layer
            tlv::TAG_SET => {
                let mut set = Cur::new(value);
                while !set.is_done() {
                    let (t, content) = set.tlv()?;
                    if t != tlv::TAG_SEQUENCE {
                        return Err(Error::Other(
                            "a SignerInfo in the token is not a SEQUENCE".into(),
                        ));
                    }
                    signer_infos.push(content);
                }
            }
            other => {
                return Err(Error::Other(format!(
                    "unexpected tag {other:#04x} in the token's SignedData"
                )));
            }
        }
    }
    if signer_infos.len() != 1 {
        return Err(Error::Other(format!(
            "a time-stamp token carries exactly one SignerInfo, this has {}",
            signer_infos.len()
        )));
    }

    // (5) the TST mode of the CMS verifier, run over these very bytes: it
    // checks messageDigest against eContent (binding every TSTInfo byte — and
    // any later rewrite of genTime or messageImprint fails right there), the
    // contentType attribute against id-ct-TSTInfo, the signature over the
    // re-tagged signed attributes, the ESS signer-certificate attribute, and
    // the chain to an anchor under the RFC 5280 issuer rules.
    crate::verify::verify(
        token,
        Some(&econtent),
        &crate::verify::VerifyOptions {
            trust_anchors: anchors.to_vec(),
            validation_time: at,
            ts_mode: true,
        },
    )
    .map_err(|e| Error::Other(format!("the time-stamp token does not verify: {e}")))?;

    // (6) the TSA's certificate is who RFC 3161 says it must be. The signer
    // is whichever embedded or anchor certificate the sid names — the same
    // lookup the CMS verifier made, redone here cheaply to judge its EKU.
    let mut f = Cur::new(signer_infos[0]);
    let _version = f.number()?;
    let (sid_tag, sid_value) = f.tlv()?;
    let mut dai = f.sequence()?;
    let digest_oid = parse_dotted_oid(&dai.oid_string()?)?;
    let digest = DigestAlg::from_oid(&digest_oid).map_err(|_| {
        Error::Other(format!(
            "the token's SignerInfo digests under {digest_oid}, which this code does not know"
        ))
    })?;
    let mut pool = certs.iter().chain(anchors.iter());
    let tsa_cert = match sid_tag {
        // issuerAndSerialNumber matches by issuer+serial...
        tlv::TAG_SEQUENCE => {
            use der::Encode as _;
            let mut s = Cur::new(sid_value);
            let (issuer_tag, issuer_whole, _) = s.tlv_whole()?;
            if issuer_tag != tlv::TAG_SEQUENCE {
                return Err(Error::Other(
                    "the token's issuerAndSerialNumber names no Name".into(),
                ));
            }
            let serial = s.expect(0x02)?;
            pool.find(|c| {
                c.issuer()
                    .to_der()
                    .map(|d| d == issuer_whole)
                    .unwrap_or(false)
                    && c.serial_number().as_bytes() == serial
            })
        }
        // ...a subjectKeyIdentifier [0] by subject key identifier
        0x80 => {
            pool.find(|c| crate::verify::subject_key_identifier(c).as_deref() == Some(sid_value))
        }
        other => {
            return Err(Error::Other(format!(
                "the token's sid has tag {other:#04x}, expected issuerAndSerialNumber or [0]"
            )));
        }
    }
    .ok_or_else(|| {
        Error::Other(
            "the token's SignerInfo names a signing certificate the token does not carry".into(),
        )
    })?;
    crate::verify::check_certificate_rules(tsa_cert, crate::verify::CertRole::TimeStamping)?;

    // (7) the digest algorithm of the SignerInfo is the one the TSTInfo's
    // messageImprint hashes under: two names for one operation, they may not
    // disagree.
    let imprint_digest =
        DigestAlg::from_oid(&parse_dotted_oid(&tst.imprint_alg)?).map_err(|_| {
            Error::Other(format!(
                "the token imprints under {}, which this code does not know",
                tst.imprint_alg
            ))
        })?;
    if imprint_digest != digest {
        return Err(Error::Other(format!(
            "the token's SignerInfo digests under {} but its messageImprint says {}",
            digest.name(),
            imprint_digest.name()
        )));
    }

    Ok(TokenStatus {
        gen_time: tst.gen_time,
        tsa_subject: crate::verify::subject(tsa_cert),
    })
}

/// What `verify_token_signature` reads out of a TSTInfo — the parts whose
/// bytes matter to the verdict beyond what the messageDigest binds.
struct TstInfo {
    gen_time: SystemTime,
    /// The OID of `messageImprint.hashAlgorithm`, cross-checked against the
    /// SignerInfo's digestAlgorithm.
    imprint_alg: String,
}

/// Parses `version`, `policy`, `messageImprint` and `genTime` out of TSTInfo
/// DER. `serialNumber` and the optional rest are stepped over, not read: the
/// messageDigest over the whole eContent binds every byte of them.
fn parse_tst_info(bytes: &[u8]) -> Result<TstInfo> {
    let mut cur = Cur::new(bytes);
    let mut tst = cur.sequence()?;
    let version = tst.number()?;
    if version != 1 {
        return Err(Error::Other(format!(
            "TSTInfo version is {version}, and RFC 3161 defines only version 1"
        )));
    }
    // TSTInfo.policy is an id-pkix-ocsp-nocheck... no: it is any
    // `OBJECT IDENTIFIER`, but the TSA may wrap nothing else — openssl emits a
    // plain OID; some TSAs tag it. A SEQUENCE here means the next field, not a
    // policy, so only read an OID when one is actually there.
    let _policy = if tst.peek_tag() == Some(0x06) {
        tst.oid_string()?
    } else {
        String::new()
    };
    let mut imprint = tst.sequence()?;
    // MessageImprint ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier,
    // hashedMessage OCTET STRING } — and an AlgorithmIdentifier is itself a
    // SEQUENCE of OID (plus optional parameters), which openssl writes as
    // such. Reading the bare OID here instead rejected every genuine token.
    let mut alg = imprint.sequence()?;
    let imprint_alg = alg.oid_string()?;
    let _hash = imprint.octets()?;
    let _serial = tst.tlv()?;
    let gen_time = {
        // GeneralizedTime (RFC 3161 requires it) or UTCTime of a legacy TSA;
        // der parses both to the same instant.
        use der::Decode as _;
        let (tag, whole, _) = tst.tlv_whole()?;
        match tag {
            0x18 => x509_cert::der::asn1::GeneralizedTime::from_der(whole)?.to_system_time(),
            0x17 => x509_cert::der::asn1::UtcTime::from_der(whole)?.to_system_time(),
            other => {
                return Err(Error::Other(format!(
                    "TSTInfo.genTime has tag {other:#04x}, expected a GeneralizedTime"
                )));
            }
        }
    };
    Ok(TstInfo {
        gen_time,
        imprint_alg,
    })
}

/// The OID of a `TimeStampReq.messageImprint.hashAlgorithm`, so the writer and
/// the reader of a token agree on one parse.
pub fn request_digest_algorithm(query: &[u8]) -> Result<DigestAlg> {
    let mut req = Cur::new(query).sequence()?;
    let _version = req.number()?;
    let mut imprint = req.sequence()?;
    let mut alg = imprint.sequence()?;
    let oid = parse_dotted_oid(&alg.oid_string()?)?;
    DigestAlg::from_oid(&oid)
        .map_err(|_| Error::Other("the time-stamp query names an unknown digest".into()))
}

/// The `messageImprint` of a `TimeStampReq`: what the TSA must answer for, and
/// what the writer side compares a token against.
pub fn request_imprint(query: &[u8]) -> Result<(DigestAlg, Vec<u8>)> {
    let mut req = Cur::new(query).sequence()?;
    let _version = req.number()?;
    let mut imprint = req.sequence()?;
    let mut alg = imprint.sequence()?;
    let oid = parse_dotted_oid(&alg.oid_string()?)?;
    let digest = DigestAlg::from_oid(&oid)
        .map_err(|_| Error::Other("the time-stamp query names an unknown digest".into()))?;
    Ok((digest, imprint.octets()?.to_vec()))
}

/// The digest algorithm and hashed message that a token's
/// `TSTInfo.messageImprint` carries, checked against nothing. This is what a
/// reader recomputes the covered bytes with; the writer side compares through
/// [`check_token`] instead.
pub fn token_imprint(token: &[u8]) -> Result<(DigestAlg, Vec<u8>)> {
    let mut ci = Cur::new(token).sequence()?;
    let content_type = ci.oid_string()?;
    if content_type != oid::ID_SIGNED_DATA.to_string() {
        return Err(Error::Other(format!(
            "a time-stamp token must be a SignedData, this ContentInfo is {content_type}"
        )));
    }
    let mut sd = Cur::new(ci.explicit(0)?).sequence()?;
    let _version = sd.tlv()?; // version
    let _digest_algs = sd.tlv()?; // digestAlgorithms
    let mut eci = sd.sequence()?; // encapContentInfo
    let _content_type = eci.oid_string()?;
    let econtent = eci.explicit(0)?;
    let octets = Cur::new(econtent).octets()?;
    let mut tst = Cur::new(octets).sequence()?;
    let _version = tst.number()?;
    let _policy = tst.oid_string()?;
    let mut imprint = tst.sequence()?;
    let mut alg = imprint.sequence()?;
    let alg_oid = alg.oid_string()?;
    let hashed = imprint.octets()?.to_vec();
    let digest_oid = parse_dotted_oid(&alg_oid)?;
    let digest = DigestAlg::from_oid(&digest_oid).map_err(|_| {
        Error::Other(format!(
            "the time-stamp token imprints a digest this code does not know: {alg_oid}"
        ))
    })?;
    Ok((digest, hashed))
}

/// Parses a dotted decimal OID string back into an `ObjectIdentifier`.
fn parse_dotted_oid(text: &str) -> Result<const_oid::ObjectIdentifier> {
    use std::str::FromStr;
    const_oid::ObjectIdentifier::from_str(text)
        .map_err(|e| Error::Other(format!("unreadable OID {text:?}: {e}")))
}

/// Finds `encapContentInfo`, unwraps the `TSTInfo` and compares its
/// `messageImprint` with what we asked to stamp.
fn check_imprint(sd: &mut Cur, digest: DigestAlg, message: &[u8]) -> Result<()> {
    let _version = sd.tlv()?; // version
    let _digest_algs = sd.tlv()?; // digestAlgorithms
    let mut eci = sd.sequence()?; // encapContentInfo
    let _content_type = eci.oid_string()?;
    let econtent = eci.explicit(0)?;
    let octets = Cur::new(econtent).octets()?;
    let mut tst = Cur::new(octets).sequence()?;
    let _version = tst.number()?;
    let _policy = tst.oid_string()?;
    let mut imprint = tst.sequence()?;
    let mut alg = imprint.sequence()?;
    let alg_oid = alg.oid_string()?;
    let hashed = imprint.octets()?.to_vec();

    let want = digest.digest(message);
    if alg_oid != digest.oid().to_string() || hashed != want.as_slice() {
        return Err(Error::Other(
            "the time-stamp token imprints a different digest than the signature value \
             it was requested for; refusing to embed it"
                .into(),
        ));
    }
    Ok(())
}

/// A DER INTEGER in minimal form: no leading zero bytes, and a zero byte in
/// front when the top bit would otherwise read as a sign. `tlv` encodes the
/// bytes it is given verbatim, and an INTEGER with leading zeros is not DER,
/// which a strict TSA or validator is entitled to reject.
fn minimal_integer(value: u64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let start = bytes
        .iter()
        .position(|b| *b != 0)
        .unwrap_or(bytes.len() - 1);
    let mut out = bytes[start..].to_vec();
    if out.is_empty() || out[0] & 0x80 != 0 {
        out.insert(0, 0);
    }
    out
}

/// The unsigned attribute that carries a token, RFC 5652 shape.
pub fn unsigned_attribute(token: &[u8]) -> Result<Vec<u8>> {
    let attr_type = tlv::oid(&oid::ID_SIGNATURE_TIME_STAMP_TOKEN)?;
    Ok(tlv::sequence(&[attr_type, tlv::tlv(tlv::TAG_SET, token)]))
}

// ---------------------------------------------------------------------------
// a cursor over DER, local to this module

struct Cur<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Cur<'a> {
    fn new(b: &'a [u8]) -> Self {
        Cur { b, i: 0 }
    }

    fn is_done(&self) -> bool {
        self.i >= self.b.len()
    }

    /// The tag of the next value without consuming it.
    fn peek_tag(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn tlv(&mut self) -> Result<(u8, &'a [u8])> {
        let (tag, _, value) = self.tlv_whole()?;
        Ok((tag, value))
    }

    /// The next value as (tag, whole TLV bytes, content bytes). The whole TLV
    /// is what a certificate has to be re-read from, because `from_der`
    /// rejects trailing data and the content alone is not a certificate.
    fn tlv_whole(&mut self) -> Result<(u8, &'a [u8], &'a [u8])> {
        let start = self.i;
        let tag = *self
            .b
            .get(self.i)
            .ok_or_else(|| Error::Other("the time-stamp DER ends mid tag".into()))?;
        self.i += 1;
        let (len, n) = read_len(&self.b[self.i..])?;
        self.i += n;
        let end = self
            .i
            .checked_add(len)
            .ok_or_else(|| Error::Other("an absurd length in the time-stamp DER".into()))?;
        if end > self.b.len() {
            return Err(Error::Other(
                "a time-stamp value runs past its container".into(),
            ));
        }
        let v = &self.b[self.i..end];
        let whole = &self.b[start..end];
        self.i = end;
        Ok((tag, whole, v))
    }

    fn expect(&mut self, tag: u8) -> Result<&'a [u8]> {
        let (t, v) = self.tlv()?;
        if t != tag {
            return Err(Error::Other(format!(
                "expected tag {tag:#04x} in the time-stamp, found {t:#04x}"
            )));
        }
        Ok(v)
    }

    fn sequence(&mut self) -> Result<Cur<'a>> {
        Ok(Cur::new(self.expect(0x30)?))
    }

    fn oid_string(&mut self) -> Result<String> {
        let v = self.expect(0x06)?;
        Ok(const_oid::ObjectIdentifier::from_bytes(v)
            .map_err(|e| Error::Other(format!("unreadable OID in the time-stamp: {e}")))?
            .to_string())
    }

    fn number(&mut self) -> Result<usize> {
        let v = self.expect(0x02)?;
        let mut n = 0usize;
        for b in v {
            n = (n << 8) | *b as usize;
        }
        Ok(n)
    }

    fn octets(&mut self) -> Result<&'a [u8]> {
        self.expect(0x04)
    }

    fn explicit(&mut self, n: u8) -> Result<&'a [u8]> {
        self.expect(0xa0 | n)
    }
}

fn read_len(b: &[u8]) -> Result<(usize, usize)> {
    let first = *b
        .first()
        .ok_or_else(|| Error::Other("the time-stamp DER ends mid length".into()))?;
    if first < 0x80 {
        return Ok((first as usize, 1));
    }
    let n = (first & 0x7f) as usize;
    if n == 0 || n > 4 {
        return Err(Error::Other(
            "an indefinite or overlong length in the time-stamp".into(),
        ));
    }
    let mut v = 0usize;
    for x in &b[1..=n] {
        v = (v << 8) | *x as usize;
    }
    Ok((v, n + 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_imprints_the_message_and_carries_a_nonce() {
        let req = request(DigestAlg::Sha256, b"the signature value", 0x0102).unwrap();
        // the imprint is sha256 of the message, not of anything else
        let hex = hex::encode(request_digest(&req));
        let want = hex::encode(DigestAlg::Sha256.digest(b"the signature value"));
        assert_eq!(hex, want);
        assert!(
            req.windows(2).any(|w| w == [0x02, 0x02]),
            "the nonce must travel"
        );
        assert!(
            req.windows(2).any(|w| w == [0x01, 0x01]),
            "certReq TRUE must travel"
        );
    }

    /// Pulls the hashedMessage out of a request, for the assertion above.
    fn request_digest(req: &[u8]) -> Vec<u8> {
        let mut outer = Cur::new(req).sequence().unwrap();
        let _version = outer.number().unwrap();
        let mut imprint = outer.sequence().unwrap();
        let _alg = imprint.sequence().unwrap();
        imprint.octets().unwrap().to_vec()
    }

    #[test]
    fn the_unsigned_attribute_wraps_the_token_in_a_set() {
        let attr = unsigned_attribute(b"\x30\x00").unwrap();
        assert_eq!(attr[0], 0x30);
        // the OID of id-signatureTimeStampToken, 1.2.840.113549.1.9.16.2.14
        assert!(
            attr.windows(10)
                .any(|w| { w == [0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09] }),
            "the attribute type must be the signatureTimeStamp OID"
        );
    }

    /// Without an anchor there is nothing the TSA's own signature could be
    /// trusted up to, and the check has to say that instead of passing a
    /// token nobody vouched for. The positive path runs against a real
    /// openssl-issued token in tests/tsp_crosscheck.rs.
    #[test]
    fn token_signature_verification_needs_an_anchor() {
        let err = verify_token_signature(b"\x30\x00", &[], SystemTime::now())
            .unwrap_err()
            .to_string();
        assert!(err.contains("no TSA trust anchor"), "{err}");
    }
}
