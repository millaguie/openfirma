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

use openfirma_core::alg::DigestAlg;
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

    fn tlv(&mut self) -> Result<(u8, &'a [u8])> {
        let tag = *self
            .b
            .get(self.i)
            .ok_or_else(|| Error::Other("the time-stamp DER ends mid tag".into()))?;
        self.i += 1;
        let (len, n) = read_len(&self.b[self.i..])?;
        self.i += n;
        let end = self.i + len;
        if end > self.b.len() {
            return Err(Error::Other(
                "a time-stamp value runs past its container".into(),
            ));
        }
        let v = &self.b[self.i..end];
        self.i = end;
        Ok((tag, v))
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
}
