//! Object identifiers used by the signature formats.
//!
//! Every OID here is either taken from the standard that defines it, or from
//! the constants AutoFirma emits, in which case the AutoFirma symbol name is
//! quoted in the comment so a golden file diff can be traced back to a
//! decision. See NOTICE.md for why upstream behaviour is the reference.

use const_oid::ObjectIdentifier;

// RFC 5652, CMS content types
pub const ID_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
pub const ID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
pub const ID_ENVELOPED_DATA: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.3");

// RFC 5652, signed and unsigned attributes
pub const ID_CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
pub const ID_MESSAGE_DIGEST: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
pub const ID_SIGNING_TIME: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.5");
pub const ID_COUNTER_SIGNATURE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.6");

// ESS attributes (RFC 2634, OID arc assigned through the S/MIME certificate
// attributes of RFC 5755's lineage; RFC 3370 only lists them in its CMS
// appendix). The advanced profile signs with contentHint by default.
pub const ID_CONTENT_HINT: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.4");

// RFC 5035, ESS
/// `ESS_SIGNING_CERT` (`signingCertificate`, RFC 5035 2): the v1 attribute a
/// TSA includes in its token so the signer certificate is bound to it.
pub const ID_SIGNING_CERTIFICATE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.12");
/// `SIGNATURE_TIMESTAMP_TOKEN_OID` in AutoFirma, used for the CAdES B-T
/// signature timestamp.
pub const ID_SIGNATURE_TIME_STAMP_TOKEN: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.14");
pub const ID_SIGNATURE_POLICY_IDENTIFIER: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.15");
/// `id-aa-commitmentTypeIndication` (RFC 5035 / EN 319 122-1 6.5). The OID is
/// spelled here because no consumer of this crate has a reason to compute it;
/// AutoFirma emits exactly this one for its `commitmentTypeIndications`
/// extraParams (`PKCSObjectIdentifiers.id_aa_ets_commitmentTypeIndication`).
pub const ID_COMMITMENT_TYPE_INDICATION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.16");
pub const ID_ATTRIBUTE_CERTIFICATE_REFERENCES: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.44");
pub const ID_REVOCATION_REFERENCES: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.45");
pub const ID_SIGNING_CERTIFICATE_V2: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.47");
/// `ARCHIVE_TIMESTAMP_V2_OID` in AutoFirma's CAdESMultiUtil.
pub const ID_ARCHIVE_TIME_STAMP_V2: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.48");

// RFC 3161, timestamping
pub const ID_CT_TST_INFO: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");

// RFC 6960, OCSP: the response type of a BasicOCSPResponse
pub const ID_PKIX_OCSP_BASIC: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.1");

// ETSI arcs
/// `CAdESAttributes.OID_id_aa_ets_mimeType`, TS 101 733 V2.1.1. AutoFirma
/// puts the MIME type of the signed data under this OID, not under the RFC
/// 5035 one, so we reproduce it.
pub const ID_AA_ETS_MIME_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("0.4.0.1733.2.1");
/// `ID_LONG_TERM_VALIDATION` in AutoFirma's signature format detector.
pub const ID_AA_ETS_CERTIFICATE_VALUES: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("0.4.0.1733.2.2");
/// `ID_ARCHIVE_TIME_STAMP_V3` in AutoFirma's signature format detector.
pub const ID_AA_ETS_ARCHIVE_TIME_STAMP_V3: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("0.4.0.1733.2.4");
/// `CAdESAttributes.OID_id_aa_ets_signerAttrV2`, EN 319 122-1 signer roles.
pub const ID_AA_ETS_SIGNER_ATTR_V2: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("0.4.0.19122.1.1");

// X.500 attribute types we need for display and for filters
pub const ID_COMMON_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");
pub const ID_SERIAL_NUMBER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.5");
pub const ID_ORGANIZATION_IDENTIFIER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.97");
pub const ID_PSEUDONYM: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.65");

// Digest algorithms
pub const ID_SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
pub const ID_SHA224: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.4");
pub const ID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
pub const ID_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
pub const ID_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");

// RSA
pub const ID_RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
pub const ID_RSASSA_PSS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");
pub const ID_SHA1_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.5");
pub const ID_SHA224_WITH_RSA: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.14");
pub const ID_SHA256_WITH_RSA: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
pub const ID_SHA384_WITH_RSA: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
pub const ID_SHA512_WITH_RSA: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");

// ESS signature policies (ETSI TS 102 918 / EN 319 122-1, and the policy
// identifiers real CAs publish in certificatePolicies)
/// The conservative policy of ETSI TS 119 312: SHA-1 is not accepted for any
/// new signature or new certificate (its own Appendix), and neither are RSA
/// keys below 2048 bits. openfirma's algorithm policy implements exactly this
/// profile, so the OID is what a report can name when it refuses.
pub const ID_ETSIG_POLICY_CONSERVATIVE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("0.4.0.194112.1.3");
/// The policy of Spanish administration (AGE) that its sede pages hand to
/// AutoFirma as `policyIdentifier`. Only here so a caller can name it without
/// a string literal; openfirma emits whatever OID the user asks for.
pub const ID_AGE_POLICY: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.724.1.3.1.1.2.1.9");

// X.509 extensions
/// `subjectKeyIdentifier` (RFC 5280 4.2.1.2): what a SignerInfo version 3
/// `sid` carries, and the extension this crate reads to resolve it. It used
/// to be spelled `2.5.4.35`, which is `userPassword` — an X.500 attribute
/// type from a different arc entirely; every signature whose sid named the
/// signer by SKI failed to resolve because of that one digit group.
pub const ID_SUBJECT_KEY_IDENTIFIER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");
/// `certificatePolicies` (RFC 5280 4.2.1.7): the extension whose
/// `PolicyInformation`s AutoFirma copies into the OPTIONAL `policies` field
/// of `signingCertificateV2`.
pub const ID_CERTIFICATE_POLICIES: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.32");

// Elliptic curve
pub const ID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
/// Only needed on the verification side: we never sign ECDSA with SHA-1 or
/// SHA-224, but a certificate in a chain may be signed with them.
pub const ID_ECDSA_WITH_SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.1");
pub const ID_ECDSA_WITH_SHA224: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.1");
pub const ID_ECDSA_WITH_SHA256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
pub const ID_ECDSA_WITH_SHA384: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
pub const ID_ECDSA_WITH_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4");
pub const ID_PRIME256V1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
pub const ID_SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
pub const ID_SECP521R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.35");
