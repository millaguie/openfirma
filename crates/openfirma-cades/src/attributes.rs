//! Signed and unsigned attributes for CMS based formats.
//!
//! Every attribute is built as its full DER encoding, `SEQUENCE { type OID,
//! values SET OF AttributeValue }`, because [`openfirma_core::tlv::set_of_content`]
//! needs the encoded form to order them the way X.690 requires.

use std::time::SystemTime;

use const_oid::ObjectIdentifier;
use der::Encode;
use der::asn1::Utf8StringRef;
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

/// ESS `contentHint`, RFC 2634 (ESS Content Hint Attribute).
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

/// The `mime-type` attribute: an UTF8String under one string (measured against
/// the jar: `new DERUTF8String(config.getMimeType())` in `CAdESUtils`, and the
/// value is the type itself, not a content-hint structure) identified by
/// [`openfirma_core::oid::ID_AA_ETS_MIME_TYPE`]. This used to encode IA5String,
/// which put a different tag on the same value than every other producer of
/// the attribute puts on it.
pub fn mime_type(mime: &str) -> Result<Vec<u8>> {
    let value = Utf8StringRef::new(mime)
        .map_err(|e| Error::other(format!("mime type is not valid UTF-8: {e}")))?
        .to_der()?;
    attribute(&oid::ID_AA_ETS_MIME_TYPE, vec![value])
}

/// `signaturePolicyIdentifier`, ETSI EN 319 122-1 6.4 (the AGE sede asks for
/// it as `policyIdentifier`):
///
/// ```text
/// SignaturePolicyIdentifier ::= SEQUENCE {
///     sigPolicyId         SigPolicyId,
///     sigPolicyHash       SigPolicyHash OPTIONAL,
///     sigPolicyQualifiers SEQUENCE SIZE (1..MAX) OF SigPolicyQualifierInfo OPTIONAL
/// }
/// ```
///
/// `policy_hash` is the `sigPolicyHash` to write. AutoFirma
/// (`CAdESUtils.getSigPolicyAttribute`) hashes the policy assertion text with
/// the named algorithm when it has one; given no assertion at all, its JSON
/// parser leaves the hash as the single byte `0x01` and it writes that over
/// the digest algorithm of the signature — measured against the jar's output:
/// `SEQUENCE { SEQUENCE { OID, NULL }, OCTET STRING 01 }`. When a caller does
/// have an assertion (a sede publishes one with its policy identifier), pass
/// its digest here. `signing_digest` is the digest the SignerInfo uses,
/// because that is the one AutoFirma names.
pub fn signature_policy_identifier(
    policy: &ObjectIdentifier,
    signing_digest: DigestAlg,
    policy_hash: &[u8],
) -> Result<Vec<u8>> {
    let hash = tlv::sequence(&[
        tlv::algorithm_identifier(&signing_digest.algorithm_identifier()?)?,
        tlv::octet_string(if policy_hash.is_empty() {
            &[0x01]
        } else {
            policy_hash
        })?,
    ]);
    let value = tlv::sequence(&[tlv::oid(policy)?, hash]);
    attribute(&oid::ID_SIGNATURE_POLICY_IDENTIFIER, vec![value])
}

/// `commitmentTypeIndication`, ETSI EN 319 122-1 6.5: the attribute is a
/// `SET OF CommitmentTypeIndication` and each indication is at least a type
/// OID (Spanish administration signs legal acts under `0.4.0.194112.1`; the
/// RFC 5035 proof types are `1.2.840.113549.1.9.16.6.n`). AutoFirma emits one value per indication, a
/// bare SEQUENCE around the type OID when it carries no qualifiers
/// (`CommitmentTypeIndicationsHelper`), so that is what this builds.
pub fn commitment_type_indication(commitment: &ObjectIdentifier) -> Result<Vec<u8>> {
    attribute(
        &oid::ID_COMMITMENT_TYPE_INDICATION,
        vec![tlv::sequence(&[tlv::oid(commitment)?])],
    )
}

/// The ESS signer-certificate attribute, [`openfirma_core::oid::ID_SIGNING_CERTIFICATE`]
/// (v1, RFC 5035 2) or [`openfirma_core::oid::ID_SIGNING_CERTIFICATE_V2`], as
/// BouncyCastle and therefore AutoFirma emit it:
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
/// AutoFirma chooses the version by digest (`CAdESParameters.load`): SHA-2
/// digests get V2, SHA-1 gets v1 with an ESSCertID — a certHash with no
/// `hashAlgorithm` (SHA-1 is implicit) plus the optional issuerSerial. The
/// golden diff proved it: AutoFirma's SHA-1 signature carries
/// `1.2.840.113549.1.9.16.2.12`, and emitting V2 with an explicit SHA-1 there
/// is how openfirma's output used to diverge on every SHA-1 file.
///
/// The `hashAlgorithm` field of a V2 is omitted for SHA-256 because that is
/// the ASN.1 DEFAULT, matching BouncyCastle.
///
/// `include_policies` copies the certificate's `certificatePolicies` into the
/// attribute's OPTIONAL `policies` — AutoFirma does it by default
/// (`doNotIncludePolicyOnSigningCertificate=false`, `getPolicyInformation`).
/// Every real signer certificate (FNMT, DNIe, sellos) carries the extension,
/// so omitting it is a structural difference against AutoFirma that only the
/// golden with a policy-bearing certificate can show.
pub fn signing_certificate(
    cert: &CertificateHandle,
    digest: DigestAlg,
    include_issuer_serial: bool,
    use_v2: bool,
    include_policies: bool,
) -> Result<Vec<u8>> {
    let mut ess_cert_id = Vec::new();
    // v1's ESSCertID has no hashAlgorithm field at all; its hash is SHA-1.
    if use_v2 && digest != DigestAlg::Sha256 {
        ess_cert_id.push(tlv::algorithm_identifier(&digest.algorithm_identifier()?)?);
    }
    let hash_digest = if use_v2 { digest } else { DigestAlg::Sha1 };
    ess_cert_id.push(tlv::octet_string(&cert.fingerprint(hash_digest))?);
    if include_issuer_serial {
        ess_cert_id.push(issuer_serial(cert)?);
    }

    // Three nested SEQUENCEs, and the outer one is easy to drop by mistake:
    // ESSCertID(v2), then certs SEQUENCE OF it, then the SigningCertificate
    // wrapper the attribute value points at. AutoFirma emits all three and
    // only the golden diff showed us collapsing two.
    let ess_cert = tlv::sequence(&ess_cert_id);
    let certs = tlv::sequence(&[ess_cert]);
    let mut value = vec![certs];
    if include_policies {
        let policies = certificate_policies(cert);
        if !policies.is_empty() {
            // ESSCertIDv2.policies is `[1] IMPLICIT SEQUENCE OF
            // PolicyInformation`. BouncyCastle — what AutoFirma signs through —
            // flattens the IMPLICIT wrapper away and writes each
            // PolicyInformation at the level of its parent, no tag of its own;
            // that is exactly what the golden dump shows (two SEQUENCEs beside
            // the certID one), so we copy them verbatim into the same slot
            // (finding M2). A wrapper — explicit SEQUENCE or [1] — was two
            // bytes and one level too deep.
            value.extend_from_slice(&policies);
        }
    }
    let signing_certificate = tlv::sequence(&value);
    attribute(
        if use_v2 {
            &oid::ID_SIGNING_CERTIFICATE_V2
        } else {
            &oid::ID_SIGNING_CERTIFICATE
        },
        vec![signing_certificate],
    )
}

/// The value of the `certificatePolicies` extension (2.5.29.32) as a list of
/// already-encoded `PolicyInformation` SEQUENCEs, or empty when the
/// certificate carries no such extension. The extension itself is
/// `SEQUENCE OF PolicyInformation`, so its content octets are exactly the
/// concatenation wanted.
fn certificate_policies(cert: &CertificateHandle) -> Vec<Vec<u8>> {
    let Some(extensions) = cert.parsed().tbs_certificate().extensions() else {
        return Vec::new();
    };
    let Some(ext) = extensions
        .iter()
        .find(|e| *e.extn_id == oid::ID_CERTIFICATE_POLICIES)
    else {
        return Vec::new();
    };
    // The wire encoding wraps the extension's DER in an OCTET STRING, but the
    // `x509-cert` model already unwrapped it when parsing (the same reason
    // verify.rs's subject_key_identifier calls OctetString::from_der on this
    // field for its own extensions): `extn_value` is the extension's own DER.
    // The policy SEQUENCEs are taken out of it byte for byte.
    let mut policies = Vec::new();
    let mut inner = crate::verify::der_cursor(ext.extn_value.as_bytes());
    while !inner.done() {
        match inner.expect(tlv::TAG_SEQUENCE, "a PolicyInformation") {
            Ok(p) => policies.push(p.whole.to_vec()),
            Err(_) => return Vec::new(),
        }
    }
    policies
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

/// `signature-time-stamp-token`, RFC 5035, unsigned attribute carrying an RFC
/// 3161 `TimeStampToken`, which is itself a CMS `SignedData`.
///
/// The attribute value is the token's own `ContentInfo` SEQUENCE: ETSI EN
/// 319 122-1 encodes the token as `ContentStamp-v1 ::= ContentInfo`, so there
/// is no OCTET STRING around it (an earlier version of this function wrapped
/// one, which produced an attribute no verifier reads as a token — finding
/// B5). It delegates to [`crate::tsp::unsigned_attribute`], the one encoder
/// of that shape, so the writer side and here cannot drift.
pub fn signature_time_stamp_token(token_der: &[u8]) -> Result<Vec<u8>> {
    crate::tsp::unsigned_attribute(token_der)
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
    fn signing_certificate_omits_sha256_algorithm() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../testdata/certs/signer-rsa.crt.der"
        );
        let Ok(der) = std::fs::read(path) else {
            eprintln!("skipped, run tools/gen-testcert.sh first");
            return;
        };
        let cert = CertificateHandle::from_der(&der).unwrap();

        let sha256 = signing_certificate(&cert, DigestAlg::Sha256, false, true, false).unwrap();
        let sha512 = signing_certificate(&cert, DigestAlg::Sha512, false, true, false).unwrap();

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

    /// Finding M1, the AutoFirma rule from `CAdESParameters.load`: SHA-1
    /// signs with the v1 `signingCertificate` (ESSCertID: no hashAlgorithm,
    /// SHA-1 hash implicit), SHA-2 digests with V2. The attribute OID, not
    /// just its shape, has to differ; AutoFirma's own SHA-1 golden shows
    /// 1.2.840.113549.1.9.16.2.12 and nothing else.
    #[test]
    fn sha1_signs_with_the_v1_signing_certificate() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../testdata/certs/signer-rsa.crt.der"
        );
        let Ok(der) = std::fs::read(path) else {
            eprintln!("skipped, run tools/gen-testcert.sh first");
            return;
        };
        let cert = CertificateHandle::from_der(&der).unwrap();

        // DER encodings of the two attribute type OIDs, whole TLVs. Both live
        // under 1.2.840.113549.1.9.16.2 and differ only in their last byte:
        // .12 (0x0c) for v1, .47 (0x2f) for V2.
        const V1_OID: [u8; 13] = [
            0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x0c,
        ]; // 1.2.840.113549.1.9.16.2.12
        const V2_OID: [u8; 13] = [
            0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x2f,
        ]; // 1.2.840.113549.1.9.16.2.47

        let v1 = signing_certificate(&cert, DigestAlg::Sha1, true, false, false).unwrap();
        assert!(
            v1.windows(13).any(|w| w == V1_OID),
            "the v1 attribute must carry OID 1.2.840.113549.1.9.16.2.12: {}",
            hex::encode(&v1)
        );
        assert!(
            !v1.windows(13).any(|w| w == V2_OID),
            "a SHA-1 attribute must not be the V2 one"
        );
        // an ESSCertID is a SHA-1 hash with no AlgorithmIdentifier in front
        let dump = openfirma_core::der_dump(&v1).unwrap();
        assert!(dump.contains("OCTET STRING"), "{dump}");
        assert!(
            v1.windows(2)
                .any(|w| w[0] == tlv::TAG_OCTET_STRING && w[1] == 20),
            "the v1 certHash must be 20 bytes of SHA-1"
        );
        // the hashAlgorithm AlgorithmIdentifier of SHA-1 (OID 1.3.14.3.2.26
        // plus NULL) appears nowhere inside a v1 ESSCertID
        assert!(
            !v1.windows(9)
                .any(|w| w == [0x30, 0x07, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a]),
            "a v1 ESSCertID carries no hashAlgorithm: {dump}"
        );

        // SHA-256 keeps V2, and without an explicit hashAlgorithm
        let v2 = signing_certificate(&cert, DigestAlg::Sha256, true, true, false).unwrap();
        assert!(v2.windows(13).any(|w| w == V2_OID), "SHA-256 must emit V2");
        assert!(
            !v2.windows(9)
                .any(|w| w == [0x30, 0x07, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a]),
            "SHA-256 is the DEFAULT and must not name hashAlgorithm"
        );
    }

    /// Finding M2: with a certificate that declares certificatePolicies, the
    /// attribute's OPTIONAL policies field carries exactly the certificate's
    /// PolicyInformation SEQUENCEs — AutoFirma's `getPolicyInformation`, on
    /// by default. Needs the policy-bearing test certificate; without it the
    /// test skips under the usual rule.
    #[test]
    fn signing_certificate_carries_the_certificates_policies() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/certs");
        let (Ok(der), Ok(policies)) = (
            std::fs::read(format!("{dir}/signer-policy.crt.der")),
            std::fs::read_to_string(format!("{dir}/signer-policy.policies.txt")),
        ) else {
            eprintln!("skipped, run tools/gen-testcert.sh first");
            return;
        };
        let cert = CertificateHandle::from_der(&der).unwrap();
        let attr = signing_certificate(&cert, DigestAlg::Sha256, true, true, true).unwrap();
        let dump = openfirma_core::der_dump(&attr).unwrap();
        for oid in policies.lines().filter(|l| !l.is_empty()) {
            assert!(dump.contains(oid), "policy {oid} missing from:\n{dump}");
        }

        // and with the option off, no policies field at all
        let without = signing_certificate(&cert, DigestAlg::Sha256, true, true, false).unwrap();
        let dump = openfirma_core::der_dump(&without).unwrap();
        for oid in policies.lines().filter(|l| !l.is_empty()) {
            assert!(!dump.contains(oid), "policy {oid} leaked:\n{dump}");
        }
    }
}
