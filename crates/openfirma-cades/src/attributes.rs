//! Signed and unsigned attributes for CMS based formats.
//!
//! Every attribute is built as its full DER encoding, `SEQUENCE { type OID,
//! values SET OF AttributeValue }`, because [`openfirma_core::tlv::set_of_content`]
//! needs the encoded form to order them the way X.690 requires.

use std::time::SystemTime;

use const_oid::ObjectIdentifier;
use der::Encode;
use der::asn1::{Ia5StringRef, OctetString, Utf8StringRef};
use openfirma_core::alg::DigestAlg;
use openfirma_core::cert::CertificateHandle;
use openfirma_core::oid;
use openfirma_core::tlv;
use openfirma_core::{Error, Result};

/// One attribute: `SEQUENCE { attrType OBJECT IDENTIFIER, attrValues SET OF ANY }`.
fn attribute(attr_type: &ObjectIdentifier, values: Vec<Vec<u8>>) -> Result<Vec<u8>> {
    Ok(tlv::sequence(&[tlv::oid(attr_type)?, tlv::set_of(values)]))
}

pub fn content_type(content_type: &ObjectIdentifier) -> Result<Vec<u8>> {
    attribute(&oid::ID_CONTENT_TYPE, vec![tlv::oid(content_type)?])
}

pub fn message_digest(digest: &[u8]) -> Result<Vec<u8>> {
    attribute(&oid::ID_MESSAGE_DIGEST, vec![tlv::octet_string(digest)?])
}

pub fn signing_time(t: SystemTime) -> Result<Vec<u8>> {
    attribute(&oid::ID_SIGNING_TIME, vec![tlv::utc_time(t)?])
}

/// ESS `contentHint`, RFC 3370.
///
/// ```text
/// ContentHints ::= SEQUENCE {
///     contentDescription UTF8String (SIZE (1..MAX)) OPTIONAL,
///     contentType        ContentType
/// }
/// ```
///
/// AutoFirma includes this by default in the advanced profile, with a human
/// readable description taken from its jmimemagic database and localized to
/// Spanish, "Texto plano" for text/plain. We do not ship that database, so the
/// description is supplied by the caller and omitted when empty, which is
/// legal because the field is OPTIONAL.
pub fn content_hint(description: &str, content_type: &ObjectIdentifier) -> Result<Vec<u8>> {
    let mut value = Vec::with_capacity(2);
    if !description.is_empty() {
        value.push(Utf8StringRef::new(description)?.to_der()?);
    }
    value.push(tlv::oid(content_type)?);
    attribute(&oid::ID_CONTENT_HINT, vec![tlv::sequence(&value)])
}

/// The ETSI `mime-type` attribute. AutoFirma emits it under
/// `0.4.0.1733.2.1`, see the note in [`openfirma_core::oid`].
pub fn mime_type(mime: &str) -> Result<Vec<u8>> {
    let value = Ia5StringRef::new(mime)
        .map_err(|e| Error::other(format!("mime type is not valid IA5String: {e}")))?
        .to_der()?;
    attribute(&oid::ID_AA_ETS_MIME_TYPE, vec![value])
}

/// `signingCertificateV2`, RFC 5035, as BouncyCastle and therefore AutoFirma
/// emit it:
///
/// ```text
/// SigningCertificateV2 ::= SEQUENCE {
///     certs    SEQUENCE OF ESSCertIDv2,
///     policies SEQUENCE OF PolicyInformation OPTIONAL
/// }
/// ESSCertIDv2 ::= SEQUENCE {
///     hashAlgorithm AlgorithmIdentifier DEFAULT {algorithm id-sha256},
///     certHash      Hash,
///     issuerSerial  IssuerSerial OPTIONAL
/// }
/// ```
///
/// The `hashAlgorithm` field is omitted for SHA-256 because that is the ASN.1
/// DEFAULT, and `issuerSerial` is omitted, both matching BouncyCastle.
pub fn signing_certificate_v2(
    cert: &CertificateHandle,
    digest: DigestAlg,
    include_issuer_serial: bool,
) -> Result<Vec<u8>> {
    let mut ess_cert_id = Vec::new();
    if digest != DigestAlg::Sha256 {
        ess_cert_id.push(tlv::algorithm_identifier(&digest.algorithm_identifier()?)?);
    }
    ess_cert_id.push(tlv::octet_string(&cert.fingerprint(digest))?);
    if include_issuer_serial {
        ess_cert_id.push(issuer_serial(cert)?);
    }

    // Three nested SEQUENCEs, and the outer one is easy to drop by mistake:
    // ESSCertIDv2, then certs SEQUENCE OF ESSCertIDv2, then the
    // SigningCertificateV2 wrapper the attribute value points at. AutoFirma
    // emits all three and only the golden diff showed us collapsing two.
    let ess_cert = tlv::sequence(&ess_cert_id);
    let certs = tlv::sequence(&[ess_cert]);
    let signing_certificate_v2 = tlv::sequence(&[certs]);
    attribute(
        &oid::ID_SIGNING_CERTIFICATE_V2,
        vec![signing_certificate_v2],
    )
}

/// `IssuerSerial ::= SEQUENCE { issuer GeneralNames, serialNumber CertificateSerialNumber }`
///
/// `GeneralNames` is a `SEQUENCE OF GeneralName` and the issuer is carried as
/// `directoryName [4] Name`, so the name gets wrapped twice.
fn issuer_serial(cert: &CertificateHandle) -> Result<Vec<u8>> {
    let name = cert.issuer().to_der()?;
    let general_name = tlv::explicit(4, &name);
    let general_names = tlv::sequence(&[general_name]);
    let serial = cert.serial_number().to_der()?;
    Ok(tlv::sequence(&[general_names, serial]))
}

/// Wraps a raw DER value as an OCTET STRING, the shape every unsigned
/// timestamp attribute needs.
pub fn raw_octet_string(bytes: &[u8]) -> Result<Vec<u8>> {
    Ok(OctetString::new(bytes.to_vec())?.to_der()?)
}

/// `signature-time-stamp-token`, RFC 5035, unsigned attribute carrying an RFC
/// 3161 `TimeStampToken`, which is itself a CMS `SignedData`.
pub fn signature_time_stamp_token(token_der: &[u8]) -> Result<Vec<u8>> {
    attribute(
        &oid::ID_SIGNATURE_TIME_STAMP_TOKEN,
        vec![raw_octet_string(token_der)?],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_digest_shape() {
        let attr = message_digest(&[0xaa; 32]).unwrap();
        // SEQUENCE { OID 1.2.840.113549.1.9.4, SET OF { OCTET STRING 32 } }
        assert_eq!(attr[0], tlv::TAG_SEQUENCE);
        assert_eq!(attr[2], tlv::TAG_OID);
        // SEQUENCE tag + length, OID tag + length, then the OID content
        let set_start = 4 + attr[3] as usize;
        assert_eq!(attr[set_start], tlv::TAG_SET);
        assert_eq!(attr[set_start + 2], tlv::TAG_OCTET_STRING);
        assert_eq!(attr[set_start + 3], 32);
    }

    #[test]
    fn signing_certificate_v2_omits_sha256_algorithm() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../testdata/certs/signer-rsa.crt.der"
        );
        let Ok(der) = std::fs::read(path) else {
            eprintln!("skipped, run tools/gen-testcert.sh first");
            return;
        };
        let cert = CertificateHandle::from_der(&der).unwrap();

        let sha256 = signing_certificate_v2(&cert, DigestAlg::Sha256, false).unwrap();
        let sha512 = signing_certificate_v2(&cert, DigestAlg::Sha512, false).unwrap();

        // SHA-256 is the ASN.1 DEFAULT so the AlgorithmIdentifier is absent,
        // and the cert hash is 32 bytes instead of 64
        assert!(sha512.len() > sha256.len());
        assert!(
            sha256
                .windows(2)
                .any(|w| w[0] == tlv::TAG_OCTET_STRING && w[1] == 32)
        );
        assert!(
            sha512
                .windows(2)
                .any(|w| w[0] == tlv::TAG_OCTET_STRING && w[1] == 64)
        );
    }
}
