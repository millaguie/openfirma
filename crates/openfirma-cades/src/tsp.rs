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

/// A fresh nonce for a time-stamp query, RFC 3161 2.4.1: a randomly generated
/// integer the TSA echoes back so the answer is bound to this exact request.
/// Random, not a clock reading: two signings in the same nanosecond, or an
/// attacker who can guess the "random" value, defeat a timestamp made of time
/// (finding M7). The value stays below 2^63 so its DER INTEGER is always
/// positive with a leading zero byte at most.
pub fn random_nonce() -> Result<u64> {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes)
        .map_err(|e| Error::Other(format!("the operating system refused random bytes: {e}")))?;
    Ok(u64::from_be_bytes(bytes) >> 1)
}

/// The `nonce` of a `TimeStampReq`, when it carries one (RFC 3161 makes it
/// OPTIONAL). Used to check a token against the query that asked for it.
pub fn request_nonce(query: &[u8]) -> Result<Option<u64>> {
    let mut req = cur(query).sequence("the TimeStampReq")?;
    let _version = req.number("the INTEGER of the time-stamp")?;
    let _imprint = req.value()?;
    Ok(match req.peek_tag() {
        Some(tlv::TAG_INTEGER) => Some(req.u64("the TimeStampReq.nonce")?),
        _ => None,
    })
}

/// The `nonce` of a token's `TSTInfo`, when the TSA echoed one back. All the
/// structural checks that matter (that this is a SignedData whose eContent is
/// a primitive OCTET STRING holding a TSTInfo) are made here on the way; the
/// full parse with signature verification lives in
/// [`verify_token_signature`].
pub fn token_nonce(token: &[u8]) -> Result<Option<u64>> {
    let mut ci = cur(token).sequence("the ContentInfo")?;
    let content_type = ci.oid("the ContentInfo.contentType")?.to_string();
    if content_type != oid::ID_SIGNED_DATA.to_string() {
        return Err(Error::Other(format!(
            "a time-stamp token must be a SignedData, this ContentInfo is {content_type}"
        )));
    }
    let mut sd = cur(ci.explicit(0, "ContentInfo.content")?).sequence("the SignedData")?;
    let _version = sd.number("the INTEGER of the time-stamp")?;
    let _digest_algs = sd.value()?;
    let mut eci = sd.sequence("the encapContentInfo")?;
    let _ct = eci.oid("the encapContentInfo.contentType")?;
    if eci.peek_tag() != Some(0xA0) {
        return Err(Error::Other(
            "the token's encapContentInfo carries no eContent".into(),
        ));
    }
    // eContent is `[0] EXPLICIT OCTET STRING`: step into [0], read the OCTET
    // STRING, and its content is the TSTInfo itself. (An earlier draft here
    // took the OCTET STRING's content as a TLV to parse once more, which made
    // every genuine token answer "no nonce".)
    let mut field = cur(eci.explicit(0, "eContent")?);
    let v = field.value()?;
    // A constructed OCTET STRING is possible in the wild; this nonce helper
    // only reads the definite primitive form, and its callers treat `None` as
    // "nothing to compare", which verify_token_signature covers properly.
    if v.tag != tlv::TAG_OCTET_STRING || v.tag & 0x20 != 0 {
        return Ok(None);
    }
    let mut tst = cur(v.content).sequence("the TSTInfo")?;
    let _version = tst.number("the INTEGER of the time-stamp")?;
    // TSTInfo fields in order: policy is any OBJECT IDENTIFIER — a TSA names
    // its own, openssl's default config 1.2.3.4.1 and even encodes it in the
    // BER long form (0x81 ...), so this must accept every readable OID, not
    // only some prefix. parse_tst_info is permissive for exactly this reason;
    // a field that is not an OID means the policy was omitted and the next
    // field, messageImprint, begins.
    if tst.peek_tag() == Some(tlv::TAG_OID) {
        let _policy = tst.value()?;
    }
    let _imprint = tst.value()?;
    let _serial = tst.value()?;
    // GeneralizedTime or UTCTime, whatever tag: this helper only walks past
    // it. Reading it with a strict date reader here mispositioned the cursor
    // and every genuine token answered "no nonce".
    let _gen_time = tst.value()?;
    // ordering BOOLEAN and accuracy SEQUENCE sit between genTime and nonce,
    // both OPTIONAL; the field order in parse_tst_info is the reference. Step
    // over them by tag (a nonce is an INTEGER where ordering is a BOOLEAN and
    // accuracy a SEQUENCE), and read the nonce when one follows.
    loop {
        match tst.peek_tag() {
            Some(0x01) | Some(0x30) => {
                let _skipped = tst.value()?;
            }
            Some(tlv::TAG_INTEGER) => return Ok(Some(tst.u64("the TSTInfo.nonce")?)),
            _ => return Ok(None),
        }
    }
}

/// The nonce binding of RFC 3161 2.4.2: when the request carried a nonce, the
/// token MUST carry the same one. `None` on either side means "not sent", and
/// a token that answers a nonce-bearing query without echoing it back gets
/// refused here too (AutoFirma does exactly this in its TSTValidator).
pub fn check_nonce(request: Option<u64>, token: Option<u64>) -> Result<()> {
    match (request, token) {
        (Some(want), Some(got)) if want == got => Ok(()),
        (Some(want), Some(got)) => Err(Error::Other(format!(
            "the time-stamp token answers nonce {got}, this query asked for {want}: the \
             token does not belong to this request"
        ))),
        (Some(_want), None) => Err(Error::Other(
            "the time-stamp query carried a nonce and the TSA's token carries none, so the \
             token cannot be tied to this request (RFC 3161 2.4.2)"
                .into(),
        )),
        (None, _) => Ok(()),
    }
}

/// A `TimeStampReq`, RFC 3161 2.4.1.
///
/// `certReq` is true so the TSA includes its certificate chain in the token,
/// which is what lets a validator check the token years later without having
/// to find the TSA certificate some other way. Pass [`random_nonce`] as
/// `nonce`: a clock reading is guessable and defeats the binding (M7).
pub fn request(digest: DigestAlg, message: &[u8], nonce: u64) -> Result<Vec<u8>> {
    let imprint = tlv::sequence(&[
        tlv::algorithm_identifier(&digest.algorithm_identifier()?)?,
        tlv::octet_string(&digest.digest(message))?,
    ]);
    Ok(tlv::sequence(&[
        tlv::integer_small(1),
        imprint,
        // a nonce binds the answer to this query — checked on the way back by
        // token_from_response — so a replayed token from another signing run
        // cannot be substituted
        tlv::tlv(tlv::TAG_INTEGER, &minimal_integer(nonce)),
        tlv::tlv(0x01, &[0xff]), // certReq TRUE
    ]))
}

/// Reads a `TimeStampResp`, checks it answers the question we asked, and
/// returns the token as a `ContentInfo`, ready to be embedded.
///
/// Three checks, all of which matter: the status must be granted, the token's
/// `messageImprint` must be the digest of `message`, and — when the query that
/// produced this response carried a nonce (`request_nonce`) — the token must
/// echo it back (finding M7: without this the nonce was sent but never
/// compared, so the comment claiming it prevented substitution was a lie).
pub fn token_from_response(
    response: &[u8],
    digest: DigestAlg,
    message: &[u8],
    request: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let mut outer = cur(response).sequence("a TimeStampResp")?;
    let mut status = outer.sequence("the PKIStatusInfo")?;
    let code = status.small_uint("the PKIStatus")?;
    if code != 0 && code != 1 {
        // 0 granted, 1 grantedWithMods; anything else is a refusal
        return Err(Error::Other(format!(
            "the TSA refused the request with PKIStatus {code}"
        )));
    }
    if outer.done() {
        return Err(Error::Other(
            "the TSA reported success but sent no token".into(),
        ));
    }

    // the token is a ContentInfo; keep its whole DER, that is what gets embedded
    let token = outer.value()?.whole;
    check_token(token, digest, message)?;
    if let Some(query) = request {
        check_nonce(request_nonce(query)?, token_nonce(token)?)?;
    }
    Ok(token.to_vec())
}

/// Checks that `token`, a `ContentInfo` holding the TSA's `SignedData`,
/// imprints the digest of `message`.
pub fn check_token(token: &[u8], digest: DigestAlg, message: &[u8]) -> Result<()> {
    let mut ci = cur(token).sequence("the ContentInfo")?;
    let content_type = ci.oid("the ContentInfo.contentType")?.to_string();
    if content_type != oid::ID_SIGNED_DATA.to_string() {
        return Err(Error::Other(format!(
            "a time-stamp token must be a SignedData, this ContentInfo is {content_type}"
        )));
    }
    // explicit(0) yields the SignedData TLV itself, so step into it
    let mut sd = cur(ci.explicit(0, "ContentInfo.content")?).sequence("the SignedData")?;
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
    let mut outer = cur(attr).sequence("the attribute SEQUENCE")?;
    let attr_type = outer.oid("the attribute type")?.to_string();
    if attr_type != oid::ID_SIGNATURE_TIME_STAMP_TOKEN.to_string() {
        return Err(Error::Other(format!(
            "the attribute is {attr_type}, not a signature-time-stamp-token \
             ({})",
            oid::ID_SIGNATURE_TIME_STAMP_TOKEN
        )));
    }
    let values = outer.expect(tlv::TAG_SET, "the attribute values SET")?;
    // the token is the first value of the SET; slice its whole TLV out
    let token = cur(values.content).value()?.whole;
    if !token.starts_with(&[tlv::TAG_SEQUENCE]) {
        return Err(Error::Other(
            "the time-stamp attribute value is not a ContentInfo SEQUENCE".into(),
        ));
    }
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
    let mut ci = cur(token).sequence("the ContentInfo")?;
    let content_type = ci.oid("the ContentInfo.contentType")?.to_string();
    if content_type != oid::ID_SIGNED_DATA.to_string() {
        return Err(Error::Other(format!(
            "a time-stamp token must be a SignedData, this ContentInfo is {content_type}"
        )));
    }
    let mut sd = cur(ci.explicit(0, "ContentInfo.content")?).sequence("the SignedData")?;
    let _version = sd.number("the INTEGER of the time-stamp")?;
    let _digest_algs = sd.value()?;

    // (2) ...whose encapContentInfo carries an eContent that is one OCTET
    // STRING holding a TSTInfo. Keep the exact bytes: the messageDigest below
    // hashes them, and only them. RFC 3161 2.2: id-ct-TSTInfo, eContent MUST
    // be present.
    let mut eci = sd.sequence("the encapContentInfo")?;
    let econtent_type = eci.oid("the encapContentInfo.contentType")?.to_string();
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
    let mut econtent_field = cur(eci.explicit(0, "ContentInfo.content")?);
    let v = econtent_field.value()?;
    let (e_tag, e_value) = (v.tag, v.content);
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
        let mut parts = cur(e_value);
        while !parts.done() {
            let v = parts.value()?;
            let (p_tag, p_value) = (v.tag, v.content);
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
    while !sd.done() {
        let v = sd.value()?;
        let (tag, value) = (v.tag, v.content);
        match tag {
            // [0] the certificate set, RFC 3161 asks the TSA to include its
            // chain because the query set certReq
            0xA0 => {
                let mut set = cur(value);
                while !set.done() {
                    let whole = set.value()?.whole;
                    certs.push(CertificateHandle::from_der(whole).map_err(|e| {
                        Error::Other(format!("the token carries an unreadable certificate: {e}"))
                    })?);
                }
            }
            0xA1 => {} // CRLs: revocation of the TSA is a validator's layer
            tlv::TAG_SET => {
                let mut set = cur(value);
                while !set.done() {
                    let v = set.value()?;
                    let (t, content) = (v.tag, v.content);
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
            ..crate::verify::VerifyOptions::tst(anchors.to_vec(), at)
        },
    )
    .map_err(|e| Error::Other(format!("the time-stamp token does not verify: {e}")))?;

    // (6) the TSA's certificate is who RFC 3161 says it must be. The signer
    // is whichever embedded or anchor certificate the sid names — the same
    // lookup the CMS verifier made, redone here cheaply to judge its EKU.
    let mut f = cur(signer_infos[0]);
    let _version = f.number("the INTEGER of the time-stamp")?;
    let v = f.value()?;
    let (sid_tag, sid_value) = (v.tag, v.content);
    let mut dai = f.sequence("the SignerInfo.digestAlgorithm")?;
    let digest_oid = parse_dotted_oid(&dai.oid("the SignerInfo.digestAlgorithm")?.to_string())?;
    // Read to refuse a token digesting under an algorithm this code cannot
    // compute; the CMS verifier in step (5) digests under it for real. It is
    // kept separate from the imprint's algorithm on purpose — see step (7).
    let _digest = DigestAlg::from_oid(&digest_oid).map_err(|_| {
        Error::Other(format!(
            "the token's SignerInfo digests under {digest_oid}, which this code does not know"
        ))
    })?;
    let mut pool = certs.iter().chain(anchors.iter());
    let tsa_cert = match sid_tag {
        // issuerAndSerialNumber matches by issuer+serial...
        tlv::TAG_SEQUENCE => {
            use der::Encode as _;
            let mut s = cur(sid_value);
            let iv = s.value()?;
            let (issuer_tag, issuer_whole) = (iv.tag, iv.whole);
            if issuer_tag != tlv::TAG_SEQUENCE {
                return Err(Error::Other(
                    "the token's issuerAndSerialNumber names no Name".into(),
                ));
            }
            let serial = s.expect(0x02, "the serialNumber")?;
            pool.find(|c| {
                c.issuer()
                    .to_der()
                    .map(|d| d == issuer_whole)
                    .unwrap_or(false)
                    && c.serial_number().as_bytes() == serial.content
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

    // (6b) the instant the token asserts has to fall inside the validity of the
    // certificate that signed it. A TSA keeps its key across certificate
    // renewals, so a token can be perfectly signed by the right key and still
    // claim a moment when that key was not under this certificate: round two's
    // N8 measured a token with genTime 2010, signed by the current TSA key,
    // verifying — a stamp back-dated into a period its own certificate does not
    // cover is no evidence of when anything existed.
    let validity = tsa_cert.parsed().tbs_certificate().validity();
    let not_before = std::time::SystemTime::from(validity.not_before);
    let not_after = std::time::SystemTime::from(validity.not_after);
    if tst.gen_time < not_before || tst.gen_time > not_after {
        return Err(Error::Other(format!(
            "the token says it was stamped at {}, outside the validity of the TSA \
             certificate that signed it ({} to {}): a stamp dated beyond its own \
             certificate attests nothing",
            crate::verify::fmt_time(tst.gen_time),
            crate::verify::fmt_time(not_before),
            crate::verify::fmt_time(not_after)
        )));
    }

    // (7) the messageImprint must hash under an algorithm this code can
    // compute. It is deliberately NOT required to be the algorithm the
    // SignerInfo digests under: RFC 3161 never asks for that, and the two
    // disagree in the wild — AutoFirma asks every TSA for a SHA-512 imprint
    // (`TsaParams.java:24`) while plenty of TSAs sign their own SignedData
    // under SHA-256, and openssl's `ts -verify` accepts exactly that token.
    // Requiring equality reported every AutoFirma B-T stamp as unverified
    // (round two, N7). What binds a token to one signature is the imprint's
    // VALUE under its own algorithm, which `crate::verify` checks.
    let _imprint_digest =
        DigestAlg::from_oid(&parse_dotted_oid(&tst.imprint_alg)?).map_err(|_| {
            Error::Other(format!(
                "the token imprints under {}, which this code does not know",
                tst.imprint_alg
            ))
        })?;

    Ok(TokenStatus {
        gen_time: tst.gen_time,
        tsa_subject: crate::verify::subject(tsa_cert),
    })
}

/// What `verify_token_signature` reads out of a TSTInfo — the parts whose
/// bytes matter to the verdict beyond what the messageDigest binds.
struct TstInfo {
    gen_time: SystemTime,
    /// The OID of `messageImprint.hashAlgorithm`, refused when this code cannot
    /// compute it. Deliberately not compared with the SignerInfo's
    /// digestAlgorithm: RFC 3161 lets the requester choose the imprint's
    /// algorithm, and AutoFirma chooses one the TSA usually does not sign under.
    imprint_alg: String,
}

/// Parses `version`, `policy`, `messageImprint` and `genTime` out of TSTInfo
/// DER. `serialNumber` and the optional rest are stepped over, not read: the
/// messageDigest over the whole eContent binds every byte of them.
fn parse_tst_info(bytes: &[u8]) -> Result<TstInfo> {
    let mut cur = cur(bytes);
    let mut tst = cur.sequence("the TSTInfo")?;
    let version = tst.number("the INTEGER of the time-stamp")?;
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
        tst.oid("the TSTInfo.policy")?.to_string()
    } else {
        String::new()
    };
    let mut imprint = tst.sequence("the messageImprint")?;
    // MessageImprint ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier,
    // hashedMessage OCTET STRING } — and an AlgorithmIdentifier is itself a
    // SEQUENCE of OID (plus optional parameters), which openssl writes as
    // such. Reading the bare OID here instead rejected every genuine token.
    let mut alg = imprint.sequence("the MessageImprint.hashAlgorithm")?;
    let imprint_alg = alg.oid("the messageImprint.hashAlgorithm")?.to_string();
    let _hash = imprint.octets("an OCTET STRING of the time-stamp")?;
    let _serial = tst.value()?;
    let gen_time = {
        // GeneralizedTime (RFC 3161 requires it) or UTCTime of a legacy TSA;
        // der parses both to the same instant.
        use der::Decode as _;
        let gv = tst.value()?;
        let (tag, whole) = (gv.tag, gv.whole);
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
    let mut req = cur(query).sequence("the TimeStampReq")?;
    let _version = req.number("the INTEGER of the time-stamp")?;
    let mut imprint = req.sequence("the messageImprint")?;
    let mut alg = imprint.sequence("the MessageImprint.hashAlgorithm")?;
    let oid = parse_dotted_oid(&alg.oid("the messageImprint.hashAlgorithm")?.to_string())?;
    DigestAlg::from_oid(&oid)
        .map_err(|_| Error::Other("the time-stamp query names an unknown digest".into()))
}

/// The `messageImprint` of a `TimeStampReq`: what the TSA must answer for, and
/// what the writer side compares a token against.
pub fn request_imprint(query: &[u8]) -> Result<(DigestAlg, Vec<u8>)> {
    let mut req = cur(query).sequence("the TimeStampReq")?;
    let _version = req.number("the INTEGER of the time-stamp")?;
    let mut imprint = req.sequence("the messageImprint")?;
    let mut alg = imprint.sequence("the MessageImprint.hashAlgorithm")?;
    let oid = parse_dotted_oid(&alg.oid("the messageImprint.hashAlgorithm")?.to_string())?;
    let digest = DigestAlg::from_oid(&oid)
        .map_err(|_| Error::Other("the time-stamp query names an unknown digest".into()))?;
    Ok((
        digest,
        imprint
            .octets("an OCTET STRING of the time-stamp")?
            .to_vec(),
    ))
}

/// The digest algorithm and hashed message that a token's
/// `TSTInfo.messageImprint` carries, checked against nothing. This is what a
/// reader recomputes the covered bytes with; the writer side compares through
/// [`check_token`] instead.
pub fn token_imprint(token: &[u8]) -> Result<(DigestAlg, Vec<u8>)> {
    let mut ci = cur(token).sequence("the ContentInfo")?;
    let content_type = ci.oid("the ContentInfo.contentType")?.to_string();
    if content_type != oid::ID_SIGNED_DATA.to_string() {
        return Err(Error::Other(format!(
            "a time-stamp token must be a SignedData, this ContentInfo is {content_type}"
        )));
    }
    let mut sd = cur(ci.explicit(0, "ContentInfo.content")?).sequence("the SignedData")?;
    let _version = sd.value()?; // version
    let _digest_algs = sd.value()?; // digestAlgorithms
    let mut eci = sd.sequence("the encapContentInfo")?; // encapContentInfo
    let _content_type = eci.oid("the encapContentInfo.contentType")?.to_string();
    let econtent = eci.explicit(0, "ContentInfo.content")?;
    let octets = cur(econtent).octets("an OCTET STRING of the time-stamp")?;
    let mut tst = cur(octets).sequence("the TSTInfo")?;
    let _version = tst.number("the INTEGER of the time-stamp")?;
    let _policy = tst.oid("the TSTInfo.policy")?.to_string();
    let mut imprint = tst.sequence("the messageImprint")?;
    let mut alg = imprint.sequence("the MessageImprint.hashAlgorithm")?;
    let alg_oid = alg.oid("the messageImprint.hashAlgorithm")?.to_string();
    let hashed = imprint
        .octets("an OCTET STRING of the time-stamp")?
        .to_vec();
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
    let _version = sd.value()?; // version
    let _digest_algs = sd.value()?; // digestAlgorithms
    let mut eci = sd.sequence("the encapContentInfo")?; // encapContentInfo
    let _content_type = eci.oid("the encapContentInfo.contentType")?.to_string();
    let econtent = eci.explicit(0, "ContentInfo.content")?;
    let octets = cur(econtent).octets("an OCTET STRING of the time-stamp")?;
    let mut tst = cur(octets).sequence("the TSTInfo")?;
    let _version = tst.number("the INTEGER of the time-stamp")?;
    let _policy = tst.oid("the TSTInfo.policy")?.to_string();
    let mut imprint = tst.sequence("the messageImprint")?;
    let mut alg = imprint.sequence("the MessageImprint.hashAlgorithm")?;
    let alg_oid = alg.oid("the messageImprint.hashAlgorithm")?.to_string();
    let hashed = imprint
        .octets("an OCTET STRING of the time-stamp")?
        .to_vec();

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
// the shared DER cursor: `openfirma_core::tlv::Cursor`, imported under the
// short name every reader in this module already used. Three local cursors
// (here, verify.rs, revocation.rs) once read the same hostile bytes with
// three different rule sets; the one here panicked on `[30 84]`. There is
// now exactly one bounds-checked reader in the workspace.

type Cur<'a> = tlv::Cursor<'a>;

fn cur(bytes: &[u8]) -> Cur<'_> {
    Cur::with_options(bytes, tlv::NO_HIGH_TAG)
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
        let mut outer = cur(req).sequence("the request").unwrap();
        let _version = outer.small_uint("the version").unwrap() as usize;
        let mut imprint = outer.sequence("the request").unwrap();
        let _alg = imprint.sequence("the request").unwrap();
        imprint.octets("the hashedMessage").unwrap().to_vec()
    }

    /// Finding M7, part one: a nonce is generated from the operating system's
    /// random source, not off the clock, and it stays a positive INTEGER.
    #[test]
    fn a_generated_nonce_is_random_and_positive() {
        let a = random_nonce().unwrap();
        let b = random_nonce().unwrap();
        assert_ne!(a, b, "two draws must not agree");
        // the DER of every generated nonce is a positive minimal INTEGER:
        // the sign bit never set means at most a 9-byte encoding starting 00
        let req = request(DigestAlg::Sha256, b"x", a).unwrap();
        assert_eq!(request_nonce(&req).unwrap(), Some(a));
    }

    /// Finding M7, part two: RFC 3161 2.4.2 — when the query asked for a
    /// nonce, the token must answer it. Substituting a token from another
    /// request is exactly what this refuses.
    #[test]
    fn the_nonce_of_the_answer_is_checked_against_the_question() {
        assert!(check_nonce(Some(7), Some(7)).is_ok());
        assert!(check_nonce(None, None).is_ok());
        assert!(
            check_nonce(None, Some(7)).is_ok(),
            "no question, no promise"
        );
        let wrong = check_nonce(Some(7), Some(8)).unwrap_err();
        assert!(wrong.to_string().contains("nonce"), "{wrong}");
        let missing = check_nonce(Some(7), None).unwrap_err();
        assert!(missing.to_string().contains("nonce"), "{missing}");
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
