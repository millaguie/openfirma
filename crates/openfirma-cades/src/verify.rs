//! Cryptographic verification of a CMS `SignedData`, RFC 5652 plus the CAdES
//! attribute checks of ETSI EN 319 122-1.
//!
//! The mirror image of [`crate::signed_data::sign`], and deliberately as close
//! to it as possible: the signature is verified over the `signedAttrs` content
//! bytes re-tagged from `[0] IMPLICIT` to `SET OF` with the exact same
//! [`openfirma_core::tlv`] call the signer uses, so the two cannot drift apart
//! in their reading of RFC 5652 5.4.
//!
//! What is checked, per `SignerInfo`:
//!
//! - the signer certificate the `sid` names is embedded in `certificates`,
//! - `messageDigest` equals the digest of the content,
//! - `signatureValue` verifies over the re-tagged signed attributes,
//! - `signingCertificateV2` hashes to the signer certificate, issuer and
//!   serial included when the attribute carries them,
//! - the chain climbs from the signer to one of the supplied trust anchors,
//!   every link's signature verified with the issuer's public key, and every
//!   certificate valid at the validation time.
//!
//! What is *not* checked, because it is layer 3/4 territory in
//! docs/validation.md: revocation (CRL/OCSP), key usage and other certificate
//! policies, RSASSA-PSS, attribute certificates, and the countersignature
//! tree. This verifier answers "is this a genuine signature by this
//! certificate, chained to this anchor", nothing more.

use std::time::SystemTime;

use const_oid::ObjectIdentifier;
use der::asn1::{GeneralizedTime, OctetString, UtcTime};
use der::{Decode, Encode};
use openfirma_core::alg::{DigestAlg, KeyAlgorithm, SignatureAlg};
use openfirma_core::cert::CertificateHandle;
use openfirma_core::signer::verify_prehash;
use openfirma_core::{Error, Result, oid, tlv};
use x509_cert::name::Name;

/// Name of the check that the `sid` resolves to an embedded certificate.
pub const CHECK_SIGNER_CERTIFICATE: &str = "signerCertificate";
/// Name of the check that the `contentType` signed attribute matches
/// `encapContentInfo.eContentType`, RFC 5652 11.1.
pub const CHECK_CONTENT_TYPE: &str = "contentType";
/// Name of the check that `messageDigest` equals the content's digest.
pub const CHECK_MESSAGE_DIGEST: &str = "messageDigest";
/// Name of the check that `signatureValue` verifies over the signed attrs.
pub const CHECK_SIGNATURE_VALUE: &str = "signatureValue";
/// Name of the check on the `signingCertificateV2` attribute.
pub const CHECK_SIGNING_CERTIFICATE_V2: &str = "signingCertificateV2";
/// Name of the check that the chain reaches a trust anchor.
pub const CHECK_CERTIFICATE_CHAIN: &str = "certificateChain";
/// Name of the check on the certificates' validity dates.
pub const CHECK_VALIDITY_DATES: &str = "validityDates";

/// No real PKI is deeper, and a chain that looks deeper is a loop or an attack.
const MAX_CHAIN_DEPTH: usize = 16;

/// What the verifier is handed besides the signature itself.
pub struct VerifyOptions {
    /// Roots (or any certificate the caller trusts) the signer's chain has to
    /// reach. At least one, or every verification fails.
    pub trust_anchors: Vec<CertificateHandle>,

    /// The instant the validity dates are judged against. A signature made
    /// yesterday verifies today by default; pass the claimed signing time to
    /// reproduce what a validator saw back then.
    pub validation_time: SystemTime,
}

impl VerifyOptions {
    /// Options that validate at the current time.
    pub fn new(trust_anchors: Vec<CertificateHandle>) -> Self {
        Self {
            trust_anchors,
            validation_time: SystemTime::now(),
        }
    }

    /// Builder for [`VerifyOptions::validation_time`].
    pub fn at(mut self, validation_time: SystemTime) -> Self {
        self.validation_time = validation_time;
        self
    }
}

/// The attribute set the signature carries, detected while verifying.
#[derive(Clone, Debug)]
pub struct Attributes {
    /// `contentType` signed attribute, when present.
    pub content_type: Option<ObjectIdentifier>,
    /// `signingTime` signed attribute, when present. PAdES leaves it out on
    /// purpose, the time lives in the PDF dictionary's `/M`.
    pub signing_time: Option<SystemTime>,
    /// Always true in a report: without `messageDigest` verification fails.
    pub message_digest: bool,
    /// Always true in a report: CAdES requires `signingCertificateV2`.
    pub signing_certificate_v2: bool,
    /// ESS `contentHint` description, when the attribute carries one.
    pub content_hint: Option<String>,
    /// The ETSI `mime-type` attribute, when present.
    pub mime_type: Option<String>,
    /// Signed attribute types this verifier does not interpret.
    pub other_signed: Vec<ObjectIdentifier>,
    /// Every unsigned attribute type, in the order they appear.
    pub unsigned_attributes: Vec<ObjectIdentifier>,
    /// Whether `signature-time-stamp-token` is among the unsigned attributes,
    /// which is what raises a signature to B-T.
    pub signature_time_stamp_token: bool,
}

/// The outcome of verifying one `SignerInfo`. One report per signer, and a
/// report only exists when every check passed: failures come back as an
/// [`Error::Verification`] naming the check.
#[derive(Clone, Debug)]
pub struct VerifyReport {
    /// Subject of the signer certificate, as an RFC 4514 style string.
    pub signer_subject: String,
    /// `SignerInfo.digestAlgorithm`.
    pub digest: DigestAlg,
    /// The signature algorithm, e.g. "RSA-PKCS1-v1_5 with SHA-256".
    pub signature_alg: String,
    /// Subjects from the signer upwards. The trust anchor itself is not part
    /// of this list unless it is also embedded in the signature.
    pub chain_subjects: Vec<String>,
    /// Subject of the trust anchor the chain reached.
    pub trust_anchor: String,
    /// What the signature carries besides the mandatory attributes.
    pub attributes: Attributes,
    /// The checks that passed, by their [`CHECK_SIGNER_CERTIFICATE`] style
    /// names, in the order they ran.
    pub passed: Vec<&'static str>,
}

/// Verifies every `SignerInfo` of a CMS `SignedData`.
///
/// `content` is the external content of a detached signature. When the
/// signature encapsulates its content, the encapsulated bytes are verified and
/// `content` is ignored; when it is detached and `content` is `None`,
/// verification fails on the `messageDigest` check.
///
/// `Ok` holds one [`VerifyReport`] per signer and only happens when all of
/// them pass. A failure names the signer (when there is more than one) and
/// the check that failed.
pub fn verify(
    der: &[u8],
    content: Option<&[u8]>,
    opts: &VerifyOptions,
) -> Result<Vec<VerifyReport>> {
    let signed_data = parse_signed_data(der)?;
    if signed_data.signer_infos.is_empty() {
        return Err(Error::Verification(
            "the SignedData carries no SignerInfo, so there is nothing to verify".into(),
        ));
    }

    let mut reports = Vec::with_capacity(signed_data.signer_infos.len());
    let mut failures = Vec::new();
    for (i, si) in signed_data.signer_infos.iter().enumerate() {
        match verify_signer_info(&signed_data, si, content, opts) {
            Ok(report) => reports.push(report),
            Err(e) => {
                let detail = detail_of(&e);
                if signed_data.signer_infos.len() == 1 {
                    failures.push(detail);
                } else {
                    failures.push(format!("signer {}: {detail}", i + 1));
                }
            }
        }
    }
    if !failures.is_empty() {
        return Err(Error::Verification(failures.join("; ")));
    }
    Ok(reports)
}

// ---------------------------------------------------------------------------
// the checks, in the order the report lists them

fn verify_signer_info(
    sd: &SignedData<'_>,
    si: &SignerInfo<'_>,
    external: Option<&[u8]>,
    opts: &VerifyOptions,
) -> Result<VerifyReport> {
    let mut passed = Vec::new();

    // (c) the signer certificate, located through the sid
    let cert = find_signer_cert(sd, &si.sid)?;
    passed.push(CHECK_SIGNER_CERTIFICATE);

    let attrs_content = si.signed_attrs.ok_or_else(|| {
        Error::Verification(
            "the SignerInfo carries no signedAttrs. A CAdES signature always has them, and the \
             bare RFC 5652 mode where the signature covers the content directly is not \
             implemented here"
                .into(),
        )
    })?;
    let attrs = parse_attributes(attrs_content)?;

    // the contentType attribute, when present, has to name the same type as
    // encapContentInfo: RFC 5652 11.1, repeated as a verification rule in
    // 5.6. A mismatch means the signed attributes describe a different
    // content than the one the messageDigest below is taken over.
    if let Some(claimed) = attrs.content_type {
        if claimed != sd.econtent_type {
            return Err(fail(
                CHECK_CONTENT_TYPE,
                format!(
                    "the signed attribute is {claimed} but encapContentInfo.eContentType \
                     is {}, and RFC 5652 11.1 requires the two to match",
                    sd.econtent_type
                ),
            ));
        }
        passed.push(CHECK_CONTENT_TYPE);
    }

    // (a) messageDigest equals the digest of the content
    let claimed = attrs.message_digest.ok_or_else(|| {
        fail(
            CHECK_MESSAGE_DIGEST,
            "the signed attributes carry no messageDigest attribute",
        )
    })?;
    let content = match (sd.econtent, external) {
        // encapsulated content wins: that is the content the signer digested
        (Some(inner), _) => inner,
        (None, Some(given)) => given,
        (None, None) => {
            return Err(fail(
                CHECK_MESSAGE_DIGEST,
                "the signature is detached, it carries no encapContentInfo, and no content \
                 was given to verify it against",
            ));
        }
    };
    let computed = si.digest_alg.digest(content);
    if claimed != computed.as_slice() {
        return Err(fail(
            CHECK_MESSAGE_DIGEST,
            format!(
                "the signed attribute is {} but the {} of the content is {}",
                hex::encode(claimed),
                si.digest_alg.name(),
                hex::encode(&computed)
            ),
        ));
    }
    passed.push(CHECK_MESSAGE_DIGEST);

    // (b) signatureValue over the signedAttrs re-tagged as SET OF, the exact
    // mirror of what signed_data::sign does before calling sign_prehash
    let key_alg = cert
        .key_algorithm()
        .map_err(|e| Error::Verification(detail_of(&e)))?;
    check_signature_algorithm(&si.signature_alg_oid, si.digest_alg, key_alg)?;
    let retagged = tlv::tlv(tlv::TAG_SET, attrs_content);
    let prehash = si.digest_alg.digest(&retagged);
    verify_prehash(cert, si.digest_alg, &prehash, si.signature)
        .map_err(|e| fail(CHECK_SIGNATURE_VALUE, detail_of(&e)))?;
    passed.push(CHECK_SIGNATURE_VALUE);

    // (d) signingCertificateV2 hashes to the signer certificate
    let v2 = attrs.signing_cert_v2.ok_or_else(|| {
        fail(
            CHECK_SIGNING_CERTIFICATE_V2,
            "the attribute is missing, and every CAdES profile requires it",
        )
    })?;
    check_signing_certificate_v2(&v2, cert)?;
    passed.push(CHECK_SIGNING_CERTIFICATE_V2);

    // (e) chain to a trust anchor, dates against the validation time
    let (chain_subjects, trust_anchor) = build_chain(
        cert,
        &sd.certificates,
        &opts.trust_anchors,
        opts.validation_time,
    )?;
    passed.push(CHECK_CERTIFICATE_CHAIN);
    passed.push(CHECK_VALIDITY_DATES);

    let signature_alg = match key_alg {
        KeyAlgorithm::Rsa => SignatureAlg::RsaPkcs1v15(si.digest_alg),
        KeyAlgorithm::EcPrimeField(_) => SignatureAlg::Ecdsa(si.digest_alg),
    };
    let unsigned_attributes = match si.unsigned_attrs {
        Some(content) => attribute_oids(content)?,
        None => Vec::new(),
    };
    let signature_time_stamp_token =
        unsigned_attributes.contains(&oid::ID_SIGNATURE_TIME_STAMP_TOKEN);

    Ok(VerifyReport {
        signer_subject: subject(cert),
        digest: si.digest_alg,
        signature_alg: signature_alg.to_string(),
        chain_subjects,
        trust_anchor,
        attributes: Attributes {
            content_type: attrs.content_type,
            signing_time: attrs.signing_time,
            message_digest: true,
            signing_certificate_v2: true,
            content_hint: attrs.content_hint,
            mime_type: attrs.mime_type,
            other_signed: attrs.other,
            unsigned_attributes,
            signature_time_stamp_token,
        },
        passed,
    })
}

fn find_signer_cert<'s>(
    sd: &'s SignedData<'_>,
    sid: &SignerId<'_>,
) -> Result<&'s CertificateHandle> {
    let found = match sid {
        SignerId::IssuerAndSerial { issuer, serial } => sd.certificates.iter().find(|c| {
            c.issuer().to_der().map(|d| d == *issuer).unwrap_or(false)
                && c.serial_number().as_bytes() == *serial
        }),
        SignerId::SubjectKeyIdentifier(ski) => sd
            .certificates
            .iter()
            .find(|c| subject_key_identifier(c).as_deref() == Some(*ski)),
    };
    found.ok_or_else(|| {
        let embedded: Vec<String> = sd.certificates.iter().map(subject).collect();
        let names = if embedded.is_empty() {
            "the signature embeds no certificate at all".to_string()
        } else {
            format!("the signature embeds {}", embedded.join(" | "))
        };
        fail(
            CHECK_SIGNER_CERTIFICATE,
            format!(
                "no certificate in SignedData.certificates matches the SignerInfo sid: {names}"
            ),
        )
    })
}

fn check_signature_algorithm(
    sig_oid: &ObjectIdentifier,
    digest_alg: DigestAlg,
    key: KeyAlgorithm,
) -> Result<()> {
    if *sig_oid == oid::ID_RSASSA_PSS {
        return Err(fail(
            CHECK_SIGNATURE_VALUE,
            "RSASSA-PSS signature verification is not implemented",
        ));
    }
    let implied = if *sig_oid == oid::ID_RSA_ENCRYPTION {
        // RFC 3370 3.1: rsaEncryption with the digest in digestAlgorithm,
        // which is what our own encoder and BouncyCastle emit
        if !matches!(key, KeyAlgorithm::Rsa) {
            return Err(fail(
                CHECK_SIGNATURE_VALUE,
                format!(
                    "signatureAlgorithm is rsaEncryption but the signer certificate carries a {} key",
                    key.name()
                ),
            ));
        }
        None
    } else if let Some(d) = rsa_pkcs1_digest(sig_oid) {
        if !matches!(key, KeyAlgorithm::Rsa) {
            return Err(fail(
                CHECK_SIGNATURE_VALUE,
                format!(
                    "signatureAlgorithm {sig_oid} is an RSA algorithm but the signer \
                     certificate carries a {} key",
                    key.name()
                ),
            ));
        }
        Some(d)
    } else if let Some(d) = ecdsa_digest(sig_oid) {
        if !matches!(key, KeyAlgorithm::EcPrimeField(_)) {
            return Err(fail(
                CHECK_SIGNATURE_VALUE,
                format!(
                    "signatureAlgorithm {sig_oid} is ECDSA but the signer certificate \
                     carries a {} key",
                    key.name()
                ),
            ));
        }
        Some(d)
    } else {
        return Err(fail(
            CHECK_SIGNATURE_VALUE,
            format!("unsupported signatureAlgorithm {sig_oid}"),
        ));
    };
    if let Some(d) = implied {
        if d != digest_alg {
            return Err(fail(
                CHECK_SIGNATURE_VALUE,
                format!(
                    "signatureAlgorithm says {} but digestAlgorithm says {}",
                    d.name(),
                    digest_alg.name()
                ),
            ));
        }
    }
    Ok(())
}

fn check_signing_certificate_v2(value: &Tlv<'_>, cert: &CertificateHandle) -> Result<()> {
    // value is the attribute value itself:
    // SigningCertificateV2 ::= SEQUENCE { certs, policies OPTIONAL },
    // certs ::= SEQUENCE OF ESSCertIDv2. Three nested SEQUENCEs, the same
    // three the encoder in attributes.rs builds.
    let wrapper = expect_tag(value, tlv::TAG_SEQUENCE, "SigningCertificateV2")?;
    let mut w = Cur::new(wrapper.content);
    let certs = w.expect(tlv::TAG_SEQUENCE, "SigningCertificateV2.certs")?;
    // the optional policies sequence is not interpreted

    let mut cs = Cur::new(certs.content);
    let ess = cs.expect(tlv::TAG_SEQUENCE, "an ESSCertIDv2")?;
    // RFC 5035: the first ESSCertIDv2 identifies the signer certificate;
    // anything after it references other certificates and is ignored here
    let mut e = Cur::new(ess.content);
    let first = e.next()?;
    let (hash_alg, cert_hash) = match first.tag {
        // an explicit hashAlgorithm, which our encoder only writes for
        // digests other than the ASN.1 DEFAULT
        tlv::TAG_SEQUENCE => {
            let mut ai = Cur::new(first.content);
            let h_oid = ai.oid("ESSCertIDv2.hashAlgorithm")?;
            let d = DigestAlg::from_oid(&h_oid).map_err(|_| {
                fail(
                    CHECK_SIGNING_CERTIFICATE_V2,
                    format!("hashAlgorithm {h_oid} is not supported"),
                )
            })?;
            (d, e.expect(tlv::TAG_OCTET_STRING, "ESSCertIDv2.certHash")?)
        }
        // absent hashAlgorithm means the DEFAULT, SHA-256
        tlv::TAG_OCTET_STRING => (DigestAlg::Sha256, first),
        other => {
            return Err(fail(
                CHECK_SIGNING_CERTIFICATE_V2,
                format!(
                    "ESSCertIDv2 starts with tag {other:#04x}, expected a hashAlgorithm or the certHash"
                ),
            ));
        }
    };

    let want = cert.fingerprint(hash_alg);
    if cert_hash.content != want.as_slice() {
        return Err(fail(
            CHECK_SIGNING_CERTIFICATE_V2,
            format!(
                "certHash is {} but the {} of the signer certificate is {}",
                hex::encode(cert_hash.content),
                hash_alg.name(),
                hex::encode(&want)
            ),
        ));
    }

    if !e.done() {
        // IssuerSerial ::= SEQUENCE { issuer GeneralNames, serialNumber INTEGER }
        let is = e.expect(tlv::TAG_SEQUENCE, "ESSCertIDv2.issuerSerial")?;
        if !e.done() {
            return Err(trailing("in ESSCertIDv2"));
        }
        let mut isc = Cur::new(is.content);
        let names = isc.expect(tlv::TAG_SEQUENCE, "IssuerSerial.issuer")?;
        let serial = isc.expect(tlv::TAG_INTEGER, "IssuerSerial.serialNumber")?;
        if !isc.done() {
            return Err(trailing("in IssuerSerial"));
        }
        let mut nc = Cur::new(names.content);
        let name = nc.expect(0xA4, "the directoryName GeneralName")?;
        if !nc.done() {
            return Err(trailing("in GeneralNames"));
        }
        let issuer_der = cert.issuer().to_der()?;
        if name.content != issuer_der.as_slice() {
            return Err(fail(
                CHECK_SIGNING_CERTIFICATE_V2,
                "issuerSerial names an issuer that is not the signer certificate's issuer",
            ));
        }
        if serial.content != cert.serial_number().as_bytes() {
            return Err(fail(
                CHECK_SIGNING_CERTIFICATE_V2,
                "issuerSerial carries a serial number that is not the signer certificate's",
            ));
        }
    }
    Ok(())
}

/// Walks from the signer certificate upwards. At each step the issuer is
/// looked for first among the trust anchors and then among the certificates
/// embedded in the signature, and every candidate has to verify the current
/// certificate's signature with its public key. Dates are checked on every
/// certificate that joins the chain, anchors included.
///
/// Returns the chain signer first, *excluding* the anchor, and the anchor it
/// stands on. The one case where the two overlap is a chain that already
/// contains the anchor as an embedded root, and the caller tells that apart
/// by comparing the last element with the anchor.
fn build_chain_refs<'c, 'a>(
    signer: &'c CertificateHandle,
    embedded: &'c [CertificateHandle],
    anchors: &'a [CertificateHandle],
    at: SystemTime,
) -> Result<(Vec<&'c CertificateHandle>, &'a CertificateHandle)> {
    if anchors.is_empty() {
        return Err(fail(
            CHECK_CERTIFICATE_CHAIN,
            "no trust anchors were supplied, so no chain can ever be accepted",
        ));
    }
    check_validity(signer, at)?;
    let mut chain: Vec<&'c CertificateHandle> = vec![signer];
    let mut visited: Vec<&[u8]> = vec![signer.der()];
    let mut current: &'c CertificateHandle = signer;

    for _ in 0..MAX_CHAIN_DEPTH {
        // the chain already stands on the anchor itself: an embedded root
        if let Some(anchor) = anchors.iter().find(|a| a.der() == current.der()) {
            return Ok((chain, anchor));
        }
        let issuer_der = current.issuer().to_der()?;
        let mut name_matches = 0usize;
        let mut signature_failures = 0usize;

        for anchor in anchors {
            if anchor.subject().to_der()? != issuer_der {
                continue;
            }
            name_matches += 1;
            match check_cert_signature(current, anchor) {
                Ok(()) => {
                    check_validity(anchor, at)?;
                    return Ok((chain, anchor));
                }
                Err(_) => signature_failures += 1,
            }
        }
        let mut advanced = None;
        for candidate in embedded {
            if candidate.der() == current.der() || candidate.subject().to_der()? != issuer_der {
                continue;
            }
            name_matches += 1;
            if check_cert_signature(current, candidate).is_err() {
                signature_failures += 1;
                continue;
            }
            check_validity(candidate, at)?;
            if visited.contains(&candidate.der()) {
                return Err(fail(
                    CHECK_CERTIFICATE_CHAIN,
                    format!("the chain loops back to \"{}\"", subject(candidate)),
                ));
            }
            advanced = Some(candidate);
            break;
        }
        let Some(next) = advanced else {
            let issuer_name = Name::from_der(&issuer_der)
                .map(|n| n.to_string())
                .unwrap_or_else(|_| hex::encode(&issuer_der));
            return Err(if signature_failures > 0 {
                fail(
                    CHECK_CERTIFICATE_CHAIN,
                    format!(
                        "\"{}\" names \"{issuer_name}\" as its issuer and {signature_failures} \
                         certificate(s) with that subject were found, but none of their public \
                         keys verifies the signature on it",
                        subject(current)
                    ),
                )
            } else {
                fail(
                    CHECK_CERTIFICATE_CHAIN,
                    format!(
                        "the chain stops at \"{}\": its issuer \"{issuer_name}\" is neither \
                         embedded in the signature nor one of the {} supplied trust anchors \
                         ({name_matches} certificate(s) even claim that subject)",
                        subject(current),
                        anchors.len()
                    ),
                )
            });
        };
        chain.push(next);
        visited.push(next.der());
        current = next;
    }
    Err(fail(
        CHECK_CERTIFICATE_CHAIN,
        format!("the chain is deeper than {MAX_CHAIN_DEPTH} levels, which no real PKI is"),
    ))
}

fn build_chain<'c>(
    signer: &'c CertificateHandle,
    embedded: &'c [CertificateHandle],
    anchors: &[CertificateHandle],
    at: SystemTime,
) -> Result<(Vec<String>, String)> {
    let (chain, anchor) = build_chain_refs(signer, embedded, anchors, at)?;
    // The report's chain_subjects excludes the anchor, except in the one
    // case where the chain already stands on the anchor itself (an embedded
    // root), and build_chain_refs returns exactly the elements for either
    // case; the anchor's subject travels separately as trust_anchor.
    Ok((chain.iter().map(|c| subject(c)).collect(), subject(anchor)))
}

/// Builds the certificate chain from `signer` up to one of the `anchors`
/// using **only** the certificates in `embedded`, verifying every link's
/// signature with the issuer's public key and every validity date against
/// `at`.
///
/// This is the entry point the PAdES `/DSS` check uses to prove that a chain
/// can be rebuilt from the archived validation data alone, without the
/// certificates a CMS happens to carry. The returned vector holds the signer
/// first and the trust anchor last.
pub fn chain_certificates(
    signer: &CertificateHandle,
    embedded: &[CertificateHandle],
    anchors: &[CertificateHandle],
    at: SystemTime,
) -> Result<Vec<CertificateHandle>> {
    let (chain, anchor) = build_chain_refs(signer, embedded, anchors, at)?;
    let mut out: Vec<CertificateHandle> = chain.iter().map(|c| (*c).clone()).collect();
    if out.last().map(|c| c.der() != anchor.der()).unwrap_or(true) {
        out.push(anchor.clone());
    }
    Ok(out)
}

/// The certificate each `SignerInfo` names through its `sid`, as embedded in
/// `SignedData.certificates`. One entry per `SignerInfo`, in order.
pub fn signer_certificates(der: &[u8]) -> Result<Vec<CertificateHandle>> {
    let sd = parse_signed_data(der)?;
    sd.signer_infos
        .iter()
        .map(|si| find_signer_cert(&sd, &si.sid).cloned())
        .collect()
}

fn check_validity(cert: &CertificateHandle, at: SystemTime) -> Result<()> {
    let validity = cert.parsed().tbs_certificate().validity();
    let not_before = SystemTime::from(validity.not_before);
    let not_after = SystemTime::from(validity.not_after);
    if at < not_before || at > not_after {
        return Err(fail(
            CHECK_VALIDITY_DATES,
            format!(
                "\"{}\" is not valid at {}: notBefore {}, notAfter {}",
                subject(cert),
                fmt_time(at),
                fmt_time(not_before),
                fmt_time(not_after)
            ),
        ));
    }
    Ok(())
}

/// Verifies the signature a certificate carries, under its issuer's key.
fn check_cert_signature(cert: &CertificateHandle, issuer: &CertificateHandle) -> Result<()> {
    let sig_oid = &cert.parsed().signature_algorithm().oid;
    let digest =
        digest_from_signature_oid(sig_oid).map_err(|e| Error::Verification(detail_of(&e)))?;
    let tbs = tbs_der(cert)?;
    let prehash = digest.digest(&tbs);
    let signature = cert.parsed().signature().as_bytes().ok_or_else(|| {
        Error::Verification("the certificate signature BIT STRING is not octet aligned".into())
    })?;
    verify_prehash(issuer, digest, &prehash, signature)
        .map_err(|e| Error::Verification(detail_of(&e)))
}

/// The `tbsCertificate` exactly as encoded, sliced out of the raw DER rather
/// than re-encoded, because the signature is over these bytes and only these.
fn tbs_der(cert: &CertificateHandle) -> Result<Vec<u8>> {
    let mut outer = Cur::new(cert.der());
    let seq = outer.expect(tlv::TAG_SEQUENCE, "the certificate")?;
    let mut inner = Cur::new(seq.content);
    let tbs = inner.expect(tlv::TAG_SEQUENCE, "tbsCertificate")?;
    Ok(tbs.whole.to_vec())
}

pub(crate) fn digest_from_signature_oid(o: &ObjectIdentifier) -> Result<DigestAlg> {
    if let Some(d) = rsa_pkcs1_digest(o).or_else(|| ecdsa_digest(o)) {
        return Ok(d);
    }
    Err(Error::other(format!(
        "unsupported certificate signature algorithm {o}"
    )))
}

fn rsa_pkcs1_digest(o: &ObjectIdentifier) -> Option<DigestAlg> {
    if *o == oid::ID_SHA1_WITH_RSA {
        Some(DigestAlg::Sha1)
    } else if *o == oid::ID_SHA224_WITH_RSA {
        Some(DigestAlg::Sha224)
    } else if *o == oid::ID_SHA256_WITH_RSA {
        Some(DigestAlg::Sha256)
    } else if *o == oid::ID_SHA384_WITH_RSA {
        Some(DigestAlg::Sha384)
    } else if *o == oid::ID_SHA512_WITH_RSA {
        Some(DigestAlg::Sha512)
    } else {
        None
    }
}

fn ecdsa_digest(o: &ObjectIdentifier) -> Option<DigestAlg> {
    if *o == oid::ID_ECDSA_WITH_SHA1 {
        Some(DigestAlg::Sha1)
    } else if *o == oid::ID_ECDSA_WITH_SHA224 {
        Some(DigestAlg::Sha224)
    } else if *o == oid::ID_ECDSA_WITH_SHA256 {
        Some(DigestAlg::Sha256)
    } else if *o == oid::ID_ECDSA_WITH_SHA384 {
        Some(DigestAlg::Sha384)
    } else if *o == oid::ID_ECDSA_WITH_SHA512 {
        Some(DigestAlg::Sha512)
    } else {
        None
    }
}

pub(crate) fn subject_key_identifier(cert: &CertificateHandle) -> Option<Vec<u8>> {
    let extensions = cert.parsed().tbs_certificate().extensions()?;
    let ext = extensions
        .iter()
        .find(|e| e.extn_id == oid::ID_SUBJECT_KEY_IDENTIFIER)?;
    // the extension value wraps the KeyIdentifier in one more OCTET STRING
    let inner = OctetString::from_der(ext.extn_value.as_bytes()).ok()?;
    Some(inner.as_bytes().to_vec())
}

pub(crate) fn subject(cert: &CertificateHandle) -> String {
    cert.subject().to_string()
}

fn fmt_time(t: SystemTime) -> String {
    match UtcTime::from_system_time(t) {
        Ok(u) => u.to_date_time().to_string(),
        // outside UTCTime's 1970..2049 window; the debug form still says when
        Err(_) => format!("{t:?}"),
    }
}

fn fail(check: &str, detail: impl std::fmt::Display) -> Error {
    Error::Verification(format!("{check} check failed: {detail}"))
}

/// The message of a verification error without the shared prefix, for
/// wrapping it under the name of the check that owns it.
pub(crate) fn detail_of(e: &Error) -> String {
    match e {
        Error::Verification(m) => m.clone(),
        other => other.to_string(),
    }
}

fn trailing(where_: &str) -> Error {
    Error::Verification(format!("trailing bytes {where_}"))
}

// ---------------------------------------------------------------------------
// parsing

struct SignedData<'a> {
    /// `encapContentInfo.eContentType`, what the `contentType` signed
    /// attribute has to match, RFC 5652 11.1.
    econtent_type: ObjectIdentifier,
    /// The content inside `encapContentInfo`, when the signature encapsulates.
    econtent: Option<&'a [u8]>,
    certificates: Vec<CertificateHandle>,
    signer_infos: Vec<SignerInfo<'a>>,
}

struct SignerInfo<'a> {
    sid: SignerId<'a>,
    digest_alg: DigestAlg,
    /// The content of the `[0] IMPLICIT` signedAttrs, the exact bytes that
    /// get re-tagged as `SET OF` for the signature check.
    signed_attrs: Option<&'a [u8]>,
    signature_alg_oid: ObjectIdentifier,
    signature: &'a [u8],
    unsigned_attrs: Option<&'a [u8]>,
}

enum SignerId<'a> {
    /// `issuer` is the whole Name TLV, `serial` the INTEGER content bytes.
    IssuerAndSerial {
        issuer: &'a [u8],
        serial: &'a [u8],
    },
    SubjectKeyIdentifier(&'a [u8]),
}

fn parse_signed_data(der: &[u8]) -> Result<SignedData<'_>> {
    let mut outer = Cur::new(der);
    let content_info = outer.expect(tlv::TAG_SEQUENCE, "the ContentInfo")?;
    if !outer.done() {
        return Err(trailing("after the ContentInfo"));
    }

    let mut ci = Cur::new(content_info.content);
    let content_type = ci.oid("ContentInfo.contentType")?;
    if content_type != oid::ID_SIGNED_DATA {
        return Err(Error::Verification(format!(
            "this is not a SignedData, its contentType is {content_type}"
        )));
    }
    let content = ci.expect(0xA0, "ContentInfo.content")?;
    if !ci.done() {
        return Err(trailing("in the ContentInfo"));
    }

    let mut sd_cur = Cur::new(content.content);
    let sd = sd_cur.expect(tlv::TAG_SEQUENCE, "the SignedData")?;
    if !sd_cur.done() {
        return Err(trailing("after the SignedData"));
    }

    let mut f = Cur::new(sd.content);
    let version = f.small_uint("SignedData.version")?;
    if !(1..=5).contains(&version) {
        return Err(Error::Verification(format!(
            "SignedData version {version} is not a version RFC 5652 defines"
        )));
    }
    let _digest_algorithms = f.expect(tlv::TAG_SET, "SignedData.digestAlgorithms")?;

    let mut eci = Cur::new(
        f.expect(tlv::TAG_SEQUENCE, "SignedData.encapContentInfo")?
            .content,
    );
    let econtent_type = eci.oid("encapContentInfo.eContentType")?;
    let mut econtent = None;
    if !eci.done() {
        let wrapper = eci.expect(0xA0, "encapContentInfo.eContent")?;
        if !eci.done() {
            return Err(trailing("in encapContentInfo"));
        }
        let mut w = Cur::new(wrapper.content);
        let octets = w.expect(tlv::TAG_OCTET_STRING, "the eContent")?;
        if !w.done() {
            return Err(Error::Verification(
                "the eContent is a chunked OCTET STRING, which is BER; this verifier reads DER"
                    .into(),
            ));
        }
        econtent = Some(octets.content);
    }

    let mut certificates = Vec::new();
    let mut signer_infos = Vec::new();
    while !f.done() {
        let item = f.next()?;
        match item.tag {
            0xA0 => {
                let mut certs = Cur::new(item.content);
                while !certs.done() {
                    let c = certs.next()?;
                    if c.tag != tlv::TAG_SEQUENCE {
                        return Err(Error::Verification(
                            "SignedData.certificates carries a choice that is not a plain X.509 \
                             certificate; attribute certificates are not supported"
                                .into(),
                        ));
                    }
                    certificates.push(CertificateHandle::from_der(c.whole)?);
                }
            }
            // CRLs are accepted and ignored: revocation is layer 3 territory
            0xA1 => {}
            tlv::TAG_SET => {
                let mut infos = Cur::new(item.content);
                while !infos.done() {
                    let si = infos.expect(tlv::TAG_SEQUENCE, "a SignerInfo")?;
                    signer_infos.push(parse_signer_info(si.content)?);
                }
            }
            other => {
                return Err(Error::Verification(format!(
                    "unexpected tag {other:#04x} in SignedData"
                )));
            }
        }
    }
    Ok(SignedData {
        econtent_type,
        econtent,
        certificates,
        signer_infos,
    })
}

fn parse_signer_info(content: &[u8]) -> Result<SignerInfo<'_>> {
    let mut f = Cur::new(content);
    let version = f.small_uint("SignerInfo.version")?;
    if version != 1 && version != 3 {
        return Err(Error::Verification(format!(
            "SignerInfo version {version}: only 1 (issuerAndSerialNumber) and 3 \
             (subjectKeyIdentifier) are supported"
        )));
    }
    let sid_item = f.next()?;
    let sid = match sid_item.tag {
        tlv::TAG_SEQUENCE => {
            let mut s = Cur::new(sid_item.content);
            let issuer = s.expect(tlv::TAG_SEQUENCE, "the sid issuerAndSerialNumber Name")?;
            let serial = s.expect(tlv::TAG_INTEGER, "the sid serialNumber")?;
            if !s.done() {
                return Err(trailing("in the sid"));
            }
            SignerId::IssuerAndSerial {
                issuer: issuer.whole,
                serial: serial.content,
            }
        }
        0x80 => SignerId::SubjectKeyIdentifier(sid_item.content),
        other => {
            return Err(Error::Verification(format!(
                "the SignerInfo sid has tag {other:#04x}, expected issuerAndSerialNumber or [0]"
            )));
        }
    };

    let mut dai = Cur::new(
        f.expect(tlv::TAG_SEQUENCE, "SignerInfo.digestAlgorithm")?
            .content,
    );
    let digest_oid = dai.oid("the digestAlgorithm")?;
    let digest_alg =
        DigestAlg::from_oid(&digest_oid).map_err(|e| Error::Verification(detail_of(&e)))?;

    let mut signed_attrs = None;
    if f.peek_tag() == Some(0xA0) {
        signed_attrs = Some(f.next()?.content);
    }

    let mut sai = Cur::new(
        f.expect(tlv::TAG_SEQUENCE, "SignerInfo.signatureAlgorithm")?
            .content,
    );
    let signature_alg_oid = sai.oid("the signatureAlgorithm")?;

    let signature = f
        .expect(tlv::TAG_OCTET_STRING, "SignerInfo.signatureValue")?
        .content;

    let mut unsigned_attrs = None;
    if f.peek_tag() == Some(0xA1) {
        unsigned_attrs = Some(f.next()?.content);
    }
    if !f.done() {
        return Err(trailing("in the SignerInfo"));
    }

    Ok(SignerInfo {
        sid,
        digest_alg,
        signed_attrs,
        signature_alg_oid,
        signature,
        unsigned_attrs,
    })
}

#[derive(Default)]
struct ParsedAttrs<'a> {
    content_type: Option<ObjectIdentifier>,
    signing_time: Option<SystemTime>,
    message_digest: Option<&'a [u8]>,
    /// The whole attribute value TLV, parsed later against the signer cert.
    signing_cert_v2: Option<Tlv<'a>>,
    content_hint: Option<String>,
    mime_type: Option<String>,
    other: Vec<ObjectIdentifier>,
}

fn parse_attributes(content: &[u8]) -> Result<ParsedAttrs<'_>> {
    let mut out = ParsedAttrs::default();
    let mut seen: Vec<ObjectIdentifier> = Vec::new();
    let mut cur = Cur::new(content);
    while !cur.done() {
        let attr = cur.expect(tlv::TAG_SEQUENCE, "an Attribute")?;
        let mut a = Cur::new(attr.content);
        let attr_type = a.oid("the Attribute type")?;
        let values = a.expect(tlv::TAG_SET, "the Attribute values")?;
        if !a.done() {
            return Err(trailing("in an Attribute"));
        }
        if seen.contains(&attr_type) {
            return Err(Error::Verification(format!(
                "the attributes carry {attr_type} twice, which RFC 5652 forbids"
            )));
        }
        seen.push(attr_type);

        let mut vs = Cur::new(values.content);
        match attr_type {
            t if t == oid::ID_CONTENT_TYPE => {
                let v = one_value(&mut vs, &attr_type)?;
                if v.tag != tlv::TAG_OID {
                    return Err(Error::Verification("contentType is not an OID".into()));
                }
                out.content_type = Some(ObjectIdentifier::from_bytes(v.content).map_err(|e| {
                    Error::Verification(format!("contentType is not a readable OID: {e}"))
                })?);
            }
            t if t == oid::ID_SIGNING_TIME => {
                let v = one_value(&mut vs, &attr_type)?;
                out.signing_time = Some(match v.tag {
                    tlv::TAG_UTC_TIME => UtcTime::from_der(v.whole)
                        .map_err(|e| Error::Verification(format!("unreadable signingTime: {e}")))?
                        .to_system_time(),
                    0x18 => GeneralizedTime::from_der(v.whole)
                        .map_err(|e| Error::Verification(format!("unreadable signingTime: {e}")))?
                        .to_system_time(),
                    other => {
                        return Err(Error::Verification(format!(
                            "signingTime has tag {other:#04x}, expected UTCTime or GeneralizedTime"
                        )));
                    }
                });
            }
            t if t == oid::ID_MESSAGE_DIGEST => {
                let v = one_value(&mut vs, &attr_type)?;
                if v.tag != tlv::TAG_OCTET_STRING {
                    return Err(Error::Verification(
                        "messageDigest is not an OCTET STRING".into(),
                    ));
                }
                out.message_digest = Some(v.content);
            }
            t if t == oid::ID_SIGNING_CERTIFICATE_V2 => {
                let v = one_value(&mut vs, &attr_type)?;
                out.signing_cert_v2 = Some(v);
            }
            t if t == oid::ID_CONTENT_HINT => {
                let v = one_value(&mut vs, &attr_type)?;
                let mut hint = Cur::new(expect_tag(&v, tlv::TAG_SEQUENCE, "contentHint")?.content);
                let mut description = String::new();
                while !hint.done() {
                    let part = hint.next()?;
                    match part.tag {
                        // the OPTIONAL contentDescription comes first
                        0x0C => description = String::from_utf8_lossy(part.content).into_owned(),
                        tlv::TAG_OID => {}
                        other => {
                            return Err(Error::Verification(format!(
                                "unexpected tag {other:#04x} in contentHint"
                            )));
                        }
                    }
                }
                out.content_hint = Some(description);
            }
            t if t == oid::ID_AA_ETS_MIME_TYPE => {
                let v = one_value(&mut vs, &attr_type)?;
                // IA5String per the ETSI ASN.1; be lenient with the encoding
                if !matches!(v.tag, 0x16 | 0x0C | 0x13) {
                    return Err(Error::Verification(format!(
                        "the mime-type attribute has tag {:#04x}, expected a string",
                        v.tag
                    )));
                }
                out.mime_type = Some(String::from_utf8_lossy(v.content).into_owned());
            }
            other => out.other.push(other),
        }
    }
    Ok(out)
}

/// The types of the attributes in a set, for the unsigned side where nothing
/// is interpreted beyond recognising the time-stamp token.
fn attribute_oids(content: &[u8]) -> Result<Vec<ObjectIdentifier>> {
    let mut out = Vec::new();
    let mut cur = Cur::new(content);
    while !cur.done() {
        let attr = cur.expect(tlv::TAG_SEQUENCE, "an Attribute")?;
        let mut a = Cur::new(attr.content);
        out.push(a.oid("the Attribute type")?);
    }
    Ok(out)
}

fn one_value<'a>(values: &mut Cur<'a>, attr_type: &ObjectIdentifier) -> Result<Tlv<'a>> {
    let v = values.next()?;
    if !values.done() {
        return Err(Error::Verification(format!(
            "attribute {attr_type} carries more than one value"
        )));
    }
    Ok(v)
}

fn expect_tag<'a>(v: &Tlv<'a>, tag: u8, what: &str) -> Result<Tlv<'a>> {
    if v.tag != tag {
        return Err(Error::Verification(format!(
            "expected {what} (tag {tag:#04x}), found tag {:#04x}",
            v.tag
        )));
    }
    Ok(*v)
}

// ---------------------------------------------------------------------------
// a cursor over DER, in the style of the one in tsp.rs

struct Tlv<'a> {
    tag: u8,
    content: &'a [u8],
    /// Tag, length and content: the exact bytes this value occupies.
    whole: &'a [u8],
}

// a Tlv is a plain borrowed view; copying it is cheaper than re-slicing
impl Copy for Tlv<'_> {}
impl Clone for Tlv<'_> {
    fn clone(&self) -> Self {
        *self
    }
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
            .ok_or_else(|| Error::Verification("the CMS ends mid tag".into()))?;
        if tag & 0x1F == 0x1F {
            return Err(Error::Verification(format!(
                "tag {tag:#04x} uses the multi octet form, which no CMS field needs"
            )));
        }
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
                "expected {what} (tag {tag:#04x}), found tag {:#04x}",
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
        if t.content.len() > 4 || t.content.first().is_some_and(|b| b & 0x80 != 0) {
            return Err(Error::Verification(format!(
                "{what} is negative or too large to be a version"
            )));
        }
        let mut v = 0u32;
        for b in t.content {
            v = (v << 8) | u32::from(*b);
        }
        Ok(v)
    }
}

fn read_len(b: &[u8]) -> Result<(usize, usize)> {
    let first = *b
        .first()
        .ok_or_else(|| Error::Verification("the CMS ends mid length".into()))?;
    if first < 0x80 {
        return Ok((first as usize, 1));
    }
    let n = (first & 0x7f) as usize;
    if n == 0 {
        return Err(Error::Verification(
            "indefinite length is BER, and this verifier reads DER".into(),
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
