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
//! docs/validation.md: revocation (CRL/OCSP), certificate policies, and the
//! countersignature tree. Chain construction itself follows RFC 5280: an
//! issuer is only ever accepted when `basicConstraints` says `cA = TRUE`, its
//! `keyUsage` (when present) allows `keyCertSign`, its `pathLenConstraint`
//! still leaves room, and no critical extension escapes interpretation. The
//! signer certificate must be allowed to sign (`digitalSignature` or
//! `nonRepudiation` when `keyUsage` is present). Without these rules any leaf
//! could issue a fake certificate at anyone's name and the chain would climb
//! over it — see docs/adversarial-review.md, finding C1.

use std::time::SystemTime;

use const_oid::ObjectIdentifier;
use der::asn1::{GeneralizedTime, OctetString, UtcTime};
use der::{Decode, Encode};
use openfirma_core::alg::{DigestAlg, KeyAlgorithm, KeyInfo, SignatureAlg};
use openfirma_core::cert::CertificateHandle;
use openfirma_core::signer::{RSA_MINIMUM_BITS, verify_prehash};
use openfirma_core::{Error, Result, oid, tlv};
use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage};
use x509_cert::name::Name;

/// `id-kp-timeStamping` (RFC 3161 2.3): the extended key usage a TSA's
/// certificate must carry for its tokens to mean anything.
pub const OID_EKU_TIME_STAMPING: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.8");

/// `basicConstraints` (RFC 5280 4.2.1.9). The same OID as
/// `const_oid::db::rfc5280::ID_CE_BASIC_CONSTRAINTS`, spelled out here in the
/// dotted form every other OID in this file uses.
const OID_BASIC_CONSTRAINTS: &str = "2.5.29.19";
/// `keyUsage` (RFC 5280 4.2.1.3).
const OID_KEY_USAGE: &str = "2.5.29.15";
/// `extendedKeyUsage` (RFC 5280 4.2.1.12).
const OID_EXTENDED_KEY_USAGE: &str = "2.5.29.37";
/// `nameConstraints` (RFC 5280 4.2.1.10).
const OID_NAME_CONSTRAINTS: &str = "2.5.29.30";

/// Extensions RFC 5280 defines and this verifier interprets, so a certificate
/// that marks any of them critical is still readable here. A critical
/// extension outside this list is one whose meaning we cannot know, and
/// RFC 5280 4.2 says the certificate must then be rejected.
const KNOWN_EXTENSIONS: &[ObjectIdentifier] = &[
    ObjectIdentifier::new_unwrap("2.5.29.14"), // subjectKeyIdentifier
    ObjectIdentifier::new_unwrap(OID_KEY_USAGE),
    ObjectIdentifier::new_unwrap("2.5.29.17"), // subjectAltName
    ObjectIdentifier::new_unwrap("2.5.29.18"), // issuerAltName
    ObjectIdentifier::new_unwrap(OID_BASIC_CONSTRAINTS),
    ObjectIdentifier::new_unwrap(OID_EXTENDED_KEY_USAGE),
    ObjectIdentifier::new_unwrap("2.5.29.31"), // cRLDistributionPoints
    oid::ID_CERTIFICATE_POLICIES,              // certificatePolicies
    ObjectIdentifier::new_unwrap("2.5.29.33"), // policyMappings
    ObjectIdentifier::new_unwrap("2.5.29.35"), // authorityKeyIdentifier
    ObjectIdentifier::new_unwrap("2.5.29.36"), // policyConstraints
    ObjectIdentifier::new_unwrap(OID_NAME_CONSTRAINTS),
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.1"), // authorityInfoAccess
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.5"), // ocspNoCheck
];

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
#[derive(Clone)]
pub struct VerifyOptions {
    /// Roots (or any certificate the caller trusts) the signer's chain has to
    /// reach. At least one, or every verification fails.
    pub trust_anchors: Vec<CertificateHandle>,

    /// The instant the validity dates are judged against. A signature made
    /// yesterday verifies today by default; pass the claimed signing time to
    /// reproduce what a validator saw back then.
    pub validation_time: SystemTime,

    /// Verify as a RFC 3161 time-stamp token (`tsp::verify_token_signature`
    /// runs the verifier in this mode). The CMS rules are shared on purpose,
    /// but a TST is not a CAdES signature and two profile rules differ: the
    /// ESS signer-certificate attribute is v1 or v2 or absent there (RFC 3161
    /// 2.4.2 says MUST include one, so v1 is accepted), and its content type
    /// is `id-ct-TSTInfo`, not `id-data`.
    pub ts_mode: bool,

    /// Which algorithms the verifier still accepts, see [`AlgorithmPolicy`].
    /// The default is the ETSI TS 119 312 conservative policy: verification
    /// of a signature is a security decision, and silently accepting SHA-1 or
    /// a 1024-bit RSA key is how a forged signature reaches a citizen as OK.
    pub algorithms: AlgorithmPolicy,

    /// Fail when `signingTime` falls outside the signer certificate's
    /// validity window (RFC 5652 11.3 expects the attribute to record when
    /// the signer produced the signature, which is inside its own
    /// certificate's life). Off by default: without a trusted time source, a
    /// `signingTime` outside validity is evidence of nothing on its own —
    /// the clock belongs to the signer — so it is a check callers opt into
    /// when their trust model has one. When on, signatures without the
    /// attribute are not judged (there is nothing to place in time).
    pub require_signing_time_in_validity: bool,
}

/// The minimum algorithm strengths a verifier accepts — finding M5. A
/// verifier that accepts anything tells a user "OK" about a signature that
/// any department with a budget could have forged; ETSI made that decision
/// for us (TS 119 312, conservative: no SHA-1 anywhere in new work, RSA at
/// least 2048). The OID of that policy is
/// [`openfirma_core::oid::ID_ETSIG_POLICY_CONSERVATIVE`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AlgorithmPolicy {
    /// ETSI TS 119 312 conservative (the default): SHA-1 is refused for the
    /// signature digest; RSA keys below 2048 bits are refused wherever they
    /// appear. Certificates *self-signed with* or *signed under* a refused
    /// algorithm fail like everything else, which is deliberate: in this
    /// policy an old root that only signs SHA-1 is not trusted material, and
    /// VALIDe agrees by refusing SHA-1 end-to-end (finding M5: silently OK
    /// was the bug).
    Conservative,
    /// Everything this implementation can read. For archives and for tools
    /// whose operator decides what to trust; a report under this policy must
    /// not be presented as "valid" by any frontend without saying the policy
    /// allowed algorithms ETSI refuses.
    All,
}

impl Default for AlgorithmPolicy {
    // derive(Default) would pick the first variant, and that is exactly this
    // one; the explicit impl states the intent.
    #[allow(clippy::derivable_impls)]
    fn default() -> Self {
        AlgorithmPolicy::Conservative
    }
}

impl Default for VerifyOptions {
    /// Trust anchors empty, which makes every verification fail: an option set
    /// with no anchor trusts nobody, inventing one here would be the unfounded
    /// success this project bans.
    fn default() -> Self {
        Self {
            trust_anchors: Vec::new(),
            validation_time: SystemTime::now(),
            ts_mode: false,
            algorithms: AlgorithmPolicy::default(),
            require_signing_time_in_validity: false,
        }
    }
}

impl VerifyOptions {
    /// Options that validate at the current time.
    pub fn new(trust_anchors: Vec<CertificateHandle>) -> Self {
        Self {
            trust_anchors,
            validation_time: SystemTime::now(),
            ts_mode: false,
            algorithms: AlgorithmPolicy::default(),
            require_signing_time_in_validity: false,
        }
    }

    /// A CAdES `VerifyOptions` with the checks of a RFC 3161 token instead of
    /// the CAdES profile ones — the one implementation behind both verdicts.
    pub fn tst(trust_anchors: Vec<CertificateHandle>, validation_time: SystemTime) -> Self {
        Self {
            trust_anchors,
            validation_time,
            ts_mode: true,
            algorithms: AlgorithmPolicy::default(),
            require_signing_time_in_validity: false,
        }
    }

    /// Builder for [`VerifyOptions::validation_time`].
    pub fn at(mut self, validation_time: SystemTime) -> Self {
        self.validation_time = validation_time;
        self
    }

    /// Builder for [`VerifyOptions::algorithms`].
    pub fn with_algorithm_policy(mut self, policy: AlgorithmPolicy) -> Self {
        self.algorithms = policy;
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
    /// Whether `signature-time-stamp-token` is among the unsigned attributes.
    /// Presence alone says nothing about the level; whether that token then
    /// verified is [`VerifyReport::timestamp`].
    pub signature_time_stamp_token: bool,
}

/// What the verifier found and concluded about one CAdES/ES time-stamp token
/// (`signatureTimeStampToken`).
///
/// The rule this type encodes (docs/adversarial-review.md A2): a level is
/// claimed only when its evidence was verified. A present-but-unverifiable
/// token is reported with the cause, never as if the check had passed.
#[derive(Clone, Debug, Default)]
pub struct TimestampTokenStatus {
    /// The tokens the signature carries, in attribute order. Empty means no
    /// time-stamp attribute at all.
    pub tokens: Vec<TimestampToken>,
}

/// One time-stamp token inside a signature, with the outcome of verifying it.
#[derive(Clone, Debug)]
pub struct TimestampToken {
    /// The unsigned attribute OID that carried the token.
    pub attribute: ObjectIdentifier,
    /// Whether the TSA's signature over the signed attributes verifies and
    /// those attributes digest the very TSTInfo this token carries (the whole
    /// set of checks in `tsp::verify_token_signature`).
    pub verified: bool,
    /// The token's `genTime`, only when `verified`. This is the assertion a
    /// B-T level is allowed to make.
    pub gen_time: Option<SystemTime>,
    /// What makes this token unverified, when it is: never empty then, and it
    /// names the check that failed and what to do about it.
    pub problem: Option<String>,
}

impl TimestampTokenStatus {
    /// No time-stamp attribute at all.
    pub fn absent() -> Self {
        TimestampTokenStatus::default()
    }

    /// Whether any token carried by the signature verified; that is what
    /// raises a signature to B-T.
    pub fn verified(&self) -> bool {
        self.tokens.iter().any(|t| t.verified)
    }

    /// The genTime of the first verified token, the time the level asserts.
    pub fn gen_time(&self) -> Option<SystemTime> {
        self.tokens.iter().find_map(|t| t.gen_time)
    }

    /// The combined cause when a token is present but none verified: what a
    /// verdict line shows instead of a level it cannot prove.
    pub fn problem(&self) -> Option<String> {
        let problems: Vec<&str> = self
            .tokens
            .iter()
            .filter(|t| !t.verified)
            .filter_map(|t| t.problem.as_deref())
            .collect();
        if problems.is_empty() {
            None
        } else {
            Some(problems.join("; "))
        }
    }
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
    /// The time-stamp tokens among the unsigned attributes and whether each
    /// one verified. A level (B-T) may rest on a `verified` token only; when
    /// a token is present and none verified, [`TimestampTokenStatus::problem`]
    /// says why, and no frontend may show the signature as timestamped.
    pub timestamp: TimestampTokenStatus,
}

/// The value of each unsigned attribute whose OID is `wanted`, whole-value
/// TLVs in attribute order. Unsigned attributes are `[1] IMPLICIT` over the
/// same `Attribute` SEQUENCE as the signed ones (RFC 5652 11.3, and
/// `signed_data::sign` writes them that way).
fn unsigned_values<'a>(content: &'a [u8], wanted: ObjectIdentifier) -> Result<Vec<Tlv<'a>>> {
    let mut out = Vec::new();
    let mut cur = der_cursor(content);
    while !cur.done() {
        let attr = cur.expect(tlv::TAG_SEQUENCE, "an unsigned Attribute")?;
        let mut a = der_cursor(attr.content);
        let attr_type = a.oid("the Attribute type")?;
        if attr_type == wanted {
            let values = a.expect(tlv::TAG_SET, "the Attribute values SET")?;
            let mut vs = der_cursor(values.content);
            while !vs.done() {
                out.push(vs.value()?);
            }
        }
    }
    Ok(out)
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
/// Whether `der` is shaped like a SignedData ContentInfo — the strictest
/// cheap look a caller can take before committing to `verify`. A PAdES verifier
/// uses it to refuse a `/Contents` that holds something else (a bare digest,
/// another object's value) as "that is not what I signed", naming the shape
/// mismatch instead of letting a half-read CMS fail on some unrelated check.
/// Only structure: no signatures are checked and no trust is consulted.
pub fn looks_like_signed_data(der: &[u8]) -> bool {
    parse_signed_data(der).is_ok()
}

pub fn verify(
    der: &[u8],
    content: Option<&[u8]>,
    opts: &VerifyOptions,
) -> Result<Vec<VerifyReport>> {
    let signed_data = match parse_signed_data(der) {
        Ok(sd) => sd,
        // the caller handed bytes that are not a CMS at all (the cursor's
        // codec complaints arrive as `Other`): say so as a verification
        // verdict — a verifier refusing its input — rather than letting the
        // UI explain a raw codec message on its own. A shape mismatch with a
        // readable contentType already arrives as `Verification` and passes
        // through untouched.
        Err(e @ Error::Other(_)) => {
            return Err(Error::Verification(format!(
                "these bytes are not a CMS signature: {e}"
            )));
        }
        Err(e) => return Err(e),
    };
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

    // The algorithm policy of M5 runs over every claim on the wire before
    // any crypto does: a SHA-1 signature digest or a sub-2048 RSA key under
    // `Conservative` is refused here, naming the check. The chain walk below
    // judges each certificate's own key through `check_certificate_rules`.
    check_algorithm_policy(CHECK_SIGNATURE_VALUE, si.digest_alg, &opts.algorithms)?;

    // (c) the signer certificate, located through the sid
    let cert = find_signer_cert(sd, &si.sid)?;
    check_key_strength(
        CHECK_SIGNATURE_VALUE,
        cert.key_info()
            .map_err(|e| fail(CHECK_SIGNER_CERTIFICATE, detail_of(&e)))?,
        &opts.algorithms,
    )?;
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

    // RFC 3161 2.4.2: a time-stamp token must carry the contentType signed
    // attribute and it must say id-ct-TSTInfo. The encapContentInfo check in
    // tsp::verify_token_signature reads the same name from the other place
    // where CMS records the type; both have to agree on what was stamped.
    if attrs.content_type.is_none() {
        // RFC 5652 11.1 names contentType mandatory in signedAttrs, and both
        // RFC 3161 2.4.2 (TST) and EN 319 122-1 (CAdES) repeat it. A CAdES
        // signature without it used to pass — finding B7.
        return Err(fail(
            CHECK_CONTENT_TYPE,
            if opts.ts_mode {
                "the token's signed attributes carry no contentType attribute, and RFC 3161 \
                 2.4.2 requires one naming id-ct-TSTInfo"
            } else {
                "the signed attributes carry no contentType attribute; RFC 5652 11.1 makes \
                 it mandatory inside a CMS signature, and without it nothing binds these \
                 attributes to the content type they claim to digest"
            },
        ));
    }

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
        // An encapsulated signature carries the very bytes the signer
        // digested, so they are what gets verified. But when the caller also
        // supplied content (a `--content` on the command line), silently
        // ignoring it would let a signature over one document pass as a
        // signature over another: the reviewer's a.txt/b.txt case. The two
        // must agree byte for byte, and if they do not, the verdict is a
        // refusal that names what happened.
        (Some(inner), Some(given)) => {
            if given != inner {
                return Err(fail(
                    CHECK_MESSAGE_DIGEST,
                    format!(
                        "the signature encapsulates {} bytes while the content supplied to \
                         verify against holds {}, and the two are not the same document; \
                         pass the file that was signed, or drop --content and let the \
                         encapsulated bytes speak for themselves",
                        inner.len(),
                        given.len()
                    ),
                ));
            }
            inner
        }
        // no external content: the encapsulated bytes are the signer's own
        (Some(inner), None) => inner,
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

    // (d) the ESS signer-certificate attribute hashes to the signer
    // certificate. A TST may carry the v1 `signingCertificate` instead (RFC
    // 3161 2.4.2: the TSA MUST include one, many TSAs still emit ESSCertID);
    // a CAdES signature must carry one too — but which of the two is defined
    // by the digest, exactly like AutoFirma's `CAdESParameters.load`: RFC
    // 5035 reserves V2 for SHA-2, so a SHA-1 CAdES (AutoFirma signs those,
    // so do all pre-2011 CAdES-BES files) legitimately names v1. Refusing v1
    // outright rejected every AutoFirma SHA-1 signature — finding M1. An
    // unknown digest in a v1 attribute still fails the hash comparison below.
    let (attr, is_v1) = match (attrs.signing_cert_v2, attrs.signing_cert) {
        (Some(v2), _) => (v2, false),
        (None, Some(v1)) if opts.ts_mode || si.digest_alg == DigestAlg::Sha1 => (v1, true),
        (None, Some(_)) => {
            return Err(fail(
                CHECK_SIGNING_CERTIFICATE_V2,
                "the signature carries the v1 signingCertificate but digests with \
                 something other than SHA-1; RFC 5035 requires signingCertificateV2 for \
                 SHA-2, and AutoFirma emits it accordingly",
            ));
        }
        (None, None) => {
            return Err(fail(
                CHECK_SIGNING_CERTIFICATE_V2,
                if opts.ts_mode {
                    "the token carries neither signingCertificate nor signingCertificateV2; \
                     RFC 3161 2.4.2 makes the TSA include one"
                } else {
                    "the attribute is missing, and every CAdES profile requires it"
                },
            ));
        }
    };
    check_signing_certificate_v2(&attr, cert, is_v1)?;
    passed.push(CHECK_SIGNING_CERTIFICATE_V2);

    // (e) chain to a trust anchor, dates against the validation time
    let (chain_subjects, trust_anchor) = build_chain(
        cert,
        &sd.certificates,
        &opts.trust_anchors,
        opts.validation_time,
        &opts.algorithms,
    )?;
    passed.push(CHECK_CERTIFICATE_CHAIN);
    passed.push(CHECK_VALIDITY_DATES);

    // B7: a caller with a trusted clock (a timestamped archive being audited,
    // say) can require the claimed signingTime to sit inside the signer
    // certificate's life. Off by default because without such a clock the
    // attribute is the signer's own claim and proves nothing on its own.
    if opts.require_signing_time_in_validity {
        if let Some(t) = attrs.signing_time {
            check_validity(cert, t).map_err(|e| {
                fail(
                    CHECK_VALIDITY_DATES,
                    format!(
                        "signingTime is outside the certificate's validity: {}",
                        detail_of(&e)
                    ),
                )
            })?;
        }
    }

    let signature_alg = match key_alg {
        KeyAlgorithm::Rsa => SignatureAlg::RsaPkcs1v15(si.digest_alg),
        KeyAlgorithm::EcPrimeField(_) => SignatureAlg::Ecdsa(si.digest_alg),
    };
    let signature_value_digest = {
        // The bytes a B-T token imprints for this signature, EN 319 122-1
        // (CAdES) and AutoFirma's own CMSTimestamper.java:227: the digest of the
        // `signature` field alone — the OCTET STRING content of `signatureValue`,
        // NOT the certificate. The signing side hashes the same thing
        // (`signed_data::sign` hands the provider `&signature_value`), so a
        // genuine stamp matches and one over anything else cannot.
        si.signature.to_vec()
    };
    let unsigned_attributes = match si.unsigned_attrs {
        Some(content) => attribute_oids(content)?,
        None => Vec::new(),
    };
    let signature_time_stamp_token =
        unsigned_attributes.contains(&oid::ID_SIGNATURE_TIME_STAMP_TOKEN);

    // The time-stamp tokens among the unsigned attributes, each verified
    // against the bytes of this very signature. A token is attached AFTER the
    // signature (that is what makes B-T possible without breaking it), so its
    // failures never invalidate the signature itself; but a level may only be
    // claimed on a verified token — presence proves nothing (finding A2).
    let mut timestamp = TimestampTokenStatus::absent();
    if let Some(content) = si.unsigned_attrs {
        for value in unsigned_values(content, oid::ID_SIGNATURE_TIME_STAMP_TOKEN)? {
            // The attribute value is the ContentInfo TLV itself; some
            // producers wrap it in an OCTET STRING instead (a BER habit), so
            // unwrap that first when present. `whole` is tag+length+content —
            // the whole ContentInfo — which is what the TSP parser expects;
            // `content` alone starts at the inner OID and it refused every
            // token with "expected the ContentInfo (tag 0x30), found tag 0x06".
            let mut token = value.whole;
            if token.first().copied() == Some(tlv::TAG_OCTET_STRING) {
                let mut c = der_cursor(token);
                token = c.value()?.content;
            }
            match crate::tsp::verify_token_signature(
                token,
                &opts.trust_anchors,
                opts.validation_time,
            ) {
                Ok(status) => {
                    // B-T's contract: the token imprints THIS signature value
                    // (EN 319 122-1 6.1), so its messageImprint must equal the
                    // digest of `signatureValue` under the token's own
                    // algorithm. The token already proved — by its verified
                    // messageDigest over its eContent — that this imprint is
                    // its real one; matching it here is what binds the stamp
                    // to this signature and not to another document's.
                    let bound = crate::tsp::token_imprint(token)
                        .and_then(|(alg, hash)| {
                            // The token imprints the DIGEST of this signature's
                            // value under its own algorithm; hashing here is
                            // what the signing side did (`signed_data::sign`
                            // hands the provider `&signature_value`), and what
                            // AutoFirma's CMSTimestamper.java:227 does too.
                            if alg == si.digest_alg && hash == alg.digest(&signature_value_digest) {
                                Ok(())
                            } else {
                                Err(Error::Other(format!(
                                    "the token's messageImprint is not the {} of this \
                                     signature value: it time-stamps a different signature \
                                     and says nothing about this one",
                                    si.digest_alg.name()
                                )))
                            }
                        })
                        .map(|()| status.gen_time);
                    match bound {
                        Ok(gen_time) => timestamp.tokens.push(TimestampToken {
                            attribute: oid::ID_SIGNATURE_TIME_STAMP_TOKEN,
                            verified: true,
                            gen_time: Some(gen_time),
                            problem: None,
                        }),
                        Err(e) => timestamp.tokens.push(TimestampToken {
                            attribute: oid::ID_SIGNATURE_TIME_STAMP_TOKEN,
                            verified: false,
                            gen_time: None,
                            problem: Some(detail_of(&e)),
                        }),
                    }
                }
                Err(e) => timestamp.tokens.push(TimestampToken {
                    attribute: oid::ID_SIGNATURE_TIME_STAMP_TOKEN,
                    verified: false,
                    gen_time: None,
                    problem: Some(detail_of(&e)),
                }),
            }
        }
    }

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
        timestamp,
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

fn check_signing_certificate_v2(
    value: &Tlv<'_>,
    cert: &CertificateHandle,
    is_v1: bool,
) -> Result<()> {
    // value is the attribute value itself:
    // SigningCertificateV2 ::= SEQUENCE { certs, policies OPTIONAL },
    // certs ::= SEQUENCE OF ESSCertIDv2. Three nested SEQUENCEs, the same
    // three the encoder in attributes.rs builds. A v1 SigningCertificate has
    // the identical shape with ESSCertID in place of ESSCertIDv2 — RFC 5035
    // defines v1 as `SigningCertificate ::= SEQUENCE { certs SEQUENCE OF
    // ESSCertID, policies ... }` — so one reader serves both, and `is_v1`
    // only decides what an absent hashAlgorithm means.
    let wrapper = expect_tag(value, tlv::TAG_SEQUENCE, "SigningCertificate")?;
    let mut w = der_cursor(wrapper.content);
    let certs = w.expect(tlv::TAG_SEQUENCE, "SigningCertificateV2.certs")?;
    // the optional policies sequence is not interpreted

    let mut cs = der_cursor(certs.content);
    let ess = cs.expect(tlv::TAG_SEQUENCE, "an ESSCertIDv2")?;
    // RFC 5035: the first ESSCertIDv2 identifies the signer certificate;
    // anything after it references other certificates and is ignored here
    let mut e = der_cursor(ess.content);
    let first = e.value()?;
    let (hash_alg, cert_hash) = match first.tag {
        // an explicit hashAlgorithm, which our encoder only writes for
        // digests other than the ASN.1 DEFAULT
        tlv::TAG_SEQUENCE => {
            let mut ai = der_cursor(first.content);
            let h_oid = ai.oid("ESSCertIDv2.hashAlgorithm")?;
            let d = DigestAlg::from_oid(&h_oid).map_err(|_| {
                fail(
                    CHECK_SIGNING_CERTIFICATE_V2,
                    format!("hashAlgorithm {h_oid} is not supported"),
                )
            })?;
            (d, e.expect(tlv::TAG_OCTET_STRING, "ESSCertIDv2.certHash")?)
        }
        // absent hashAlgorithm means the default: SHA-256 for a V2
        // (RFC 5035 3), SHA-1 for the v1 ESSCertID, whose implicit digest is
        // always SHA-1. A 32-byte hash with no algorithm inside a v1 would
        // be ambiguous DER; below a v1 refuses anything that does not match
        // its own SHA-1 of the certificate, which is what the compare does.
        tlv::TAG_OCTET_STRING if is_v1 => (DigestAlg::Sha1, first),
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
        let mut isc = der_cursor(is.content);
        let names = isc.expect(tlv::TAG_SEQUENCE, "IssuerSerial.issuer")?;
        let serial = isc.expect(tlv::TAG_INTEGER, "IssuerSerial.serialNumber")?;
        if !isc.done() {
            return Err(trailing("in IssuerSerial"));
        }
        let mut nc = der_cursor(names.content);
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

/// The role a certificate plays in the verification, which decides what RFC
/// 5280 requires of it. The rules run once per certificate that joins a chain
/// and once for each special certificate the verifier looks at on its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CertRole {
    /// The end entity that produced the signature: when `keyUsage` is present
    /// it must allow `digitalSignature` or `nonRepudiation`.
    Signer,
    /// An issuer above the signer (intermediate or anchor): `cA = TRUE`, and
    /// `keyCertSign` when `keyUsage` is present. A trust anchor that carries
    /// no `basicConstraints` at all is still accepted: RFC 5280 6.1.1(e)/(p)
    /// treats the trust anchor's properties as configuration data, and pre-v3
    /// roots exist in real PKIs. Anything else must say CA.
    Issuer {
        /// How many non-self-issued intermediate certificates sit below this
        /// one in the chain being built; `pathLenConstraint`, when present,
        /// must not be smaller. The end-entity signer is not an intermediate
        /// (RFC 5280 6.1.4 (l)/(m)).
        depth_below: usize,
    },
    /// A certificate that signs CRLs for some CA (a CRL issuer that is not
    /// itself an issuer of the chain): `cRLSign` when `keyUsage` is present.
    CrlIssuer,
    /// The TSA's signing certificate: `keyUsage` must allow a non-repudiation
    /// style signature and `extendedKeyUsage` must name `id-kp-timeStamping`.
    TimeStamping,
}

/// The RFC 5280 rules a certificate must satisfy for the role it plays. Every
/// failure names the extension and the rule that failed, so the user sees
/// which certificate is not fit for what it was asked to do.
pub fn check_certificate_rules(cert: &CertificateHandle, role: CertRole) -> Result<()> {
    let tbs = cert.parsed().tbs_certificate();
    // RFC 5280 4.1.2.9: an issuer certificate that is not v3 cannot carry
    // basicConstraints, so it can never issue. (v1 certificates have no
    // extensions at all and are refused here too.)
    let version = tbs.version() as u8;
    if matches!(role, CertRole::Issuer { .. }) && version < 2 {
        return Err(fail(
            CHECK_CERTIFICATE_CHAIN,
            format!(
                "\"{}\" is asked to be a CA but it is an X.509 v{version} certificate, and \
                 only v3 certificates can carry basicConstraints",
                subject(cert)
            ),
        ));
    }

    let mut saw_basic_constraints = false;
    for ext in tbs.extensions().into_iter().flatten() {
        let oid = ext.extn_id.to_string();
        // RFC 5280 4.2: a critical extension the verifier does not understand
        // condemns the certificate, whatever role it plays.
        if ext.critical && !KNOWN_EXTENSIONS.contains(&ext.extn_id) {
            return Err(fail(
                CHECK_CERTIFICATE_CHAIN,
                format!(
                    "\"{}\" marks extension {oid} critical and this verifier does not \
                     implement its meaning; RFC 5280 4.2 forbids accepting it",
                    subject(cert)
                ),
            ));
        }
        match oid.as_str() {
            OID_BASIC_CONSTRAINTS => {
                saw_basic_constraints = true;
                let bc = BasicConstraints::from_der(ext.extn_value.as_bytes()).map_err(|e| {
                    fail(
                        CHECK_CERTIFICATE_CHAIN,
                        format!(
                            "the basicConstraints of \"{}\" do not parse: {e}",
                            subject(cert)
                        ),
                    )
                })?;
                if let CertRole::Issuer { depth_below } = role {
                    if !bc.ca {
                        return Err(fail(
                            CHECK_CERTIFICATE_CHAIN,
                            format!(
                                "\"{}\" is asked to certify other certificates but its \
                                 basicConstraints says CA:FALSE; only a certificate with \
                                 cA = TRUE may issue another one (RFC 5280 4.2.1.9)",
                                subject(cert)
                            ),
                        ));
                    }
                    if let Some(limit) = bc.path_len_constraint {
                        // A pathLenConstraint of N allows at most N further
                        // certifications below this CA; `depth_below` counts the
                        // non-self-issued intermediates (never the end entity).
                        if depth_below > usize::from(limit) {
                            return Err(fail(
                                CHECK_CERTIFICATE_CHAIN,
                                format!(
                                    "\"{}\" carries pathLenConstraint {limit} but the chain \
                                     below it has {depth_below} intermediate certificate(s); \
                                     one certificate too many sit under this CA",
                                    subject(cert)
                                ),
                            ));
                        }
                    }
                }
                // A leaf that calls itself a CA is not signature fraud, so the
                // signer role does not refuse it; but the chain rules will make
                // any certificate issued *under* it prove itself.
            }
            OID_KEY_USAGE => {
                let ku = KeyUsage::from_der(ext.extn_value.as_bytes()).map_err(|e| {
                    fail(
                        CHECK_CERTIFICATE_CHAIN,
                        format!("the keyUsage of \"{}\" does not parse: {e}", subject(cert)),
                    )
                })?;
                match role {
                    CertRole::Signer => {
                        if !(ku.digital_signature() || ku.non_repudiation()) {
                            return Err(fail(
                                CHECK_CERTIFICATE_CHAIN,
                                format!(
                                    "\"{}\" signs but its keyUsage allows neither \
                                     digitalSignature nor nonRepudiation (RFC 5280 4.2.1.3)",
                                    subject(cert)
                                ),
                            ));
                        }
                    }
                    CertRole::Issuer { .. } => {
                        if !ku.key_cert_sign() {
                            return Err(fail(
                                CHECK_CERTIFICATE_CHAIN,
                                format!(
                                    "\"{}\" issues certificates but its keyUsage has no \
                                     keyCertSign (RFC 5280 4.2.1.3)",
                                    subject(cert)
                                ),
                            ));
                        }
                    }
                    CertRole::CrlIssuer => {
                        if !ku.crl_sign() {
                            return Err(fail(
                                CHECK_CERTIFICATE_CHAIN,
                                format!(
                                    "\"{}\" signs CRLs but its keyUsage has no cRLSign \
                                     (RFC 5280 4.2.1.3)",
                                    subject(cert)
                                ),
                            ));
                        }
                    }
                    CertRole::TimeStamping => {
                        if !(ku.digital_signature() || ku.non_repudiation()) {
                            return Err(fail(
                                CHECK_CERTIFICATE_CHAIN,
                                format!(
                                    "the TSA certificate \"{}\" has a keyUsage that allows no \
                                     signature at all (RFC 5280 4.2.1.3)",
                                    subject(cert)
                                ),
                            ));
                        }
                    }
                }
            }
            OID_EXTENDED_KEY_USAGE if role == CertRole::TimeStamping => {
                let eku = ExtendedKeyUsage::from_der(ext.extn_value.as_bytes()).map_err(|e| {
                    fail(
                        CHECK_CERTIFICATE_CHAIN,
                        format!(
                            "the extendedKeyUsage of \"{}\" does not parse: {e}",
                            subject(cert)
                        ),
                    )
                })?;
                if !eku.0.contains(&OID_EKU_TIME_STAMPING) {
                    return Err(fail(
                        CHECK_CERTIFICATE_CHAIN,
                        format!(
                            "the TSA certificate \"{}\" carries an extendedKeyUsage that does \
                             not name id-kp-timeStamping ({OID_EKU_TIME_STAMPING}); RFC 3161 \
                             2.3 requires it of every time-stamp authority",
                            subject(cert)
                        ),
                    ));
                }
            }
            _ => {}
        }
    }

    // A would-be issuer that carries no basicConstraints at all: a self-signed
    // trust anchor is exempt (its properties are the configuration that chose
    // it), everything else is not an authority.
    if matches!(role, CertRole::Issuer { .. }) && !saw_basic_constraints {
        return Err(fail(
            CHECK_CERTIFICATE_CHAIN,
            format!(
                "\"{}\" is asked to certify other certificates but carries no basicConstraints \
                 extension at all; without cA = TRUE it may not issue (RFC 5280 4.2.1.9)",
                subject(cert)
            ),
        ));
    }
    if role == CertRole::TimeStamping
        && !tbs
            .extensions()
            .into_iter()
            .flatten()
            .any(|e| e.extn_id.to_string() == OID_EXTENDED_KEY_USAGE)
    {
        return Err(fail(
            CHECK_CERTIFICATE_CHAIN,
            format!(
                "the TSA certificate \"{}\" carries no extendedKeyUsage at all; RFC 3161 2.3 \
                 requires id-kp-timeStamping ({OID_EKU_TIME_STAMPING}) of every time-stamp \
                 authority",
                subject(cert)
            ),
        ));
    }
    Ok(())
}

/// How many certificates below a candidate issuer its `pathLenConstraint`
/// bounds: RFC 5280 6.1.4 (l)/(m) counts the *non-self-issued intermediate*
/// certificates that follow in the path, so the end-entity signer never counts
/// and neither does a self-issued certificate (a CA that re-signs itself, as
/// rollover and cross-signed material does). `chain` is signer first, so the
/// first element is skipped. Round 2's finding N1: the walk handed the raw
/// chain length here, which counted the signer and so refused every chain
/// whose CA carries `pathlen:0` — the shape of AC FNMT Usuarios, AC
/// Representación, the FNMT sealing CAs and Firmaprofesional's intermediates,
/// i.e. every real Spanish citizen certificate and every FNMT time-stamp.
fn intermediates_below(chain: &[&CertificateHandle]) -> usize {
    chain
        .iter()
        .skip(1)
        .filter(|cert| match (cert.subject_der(), cert.issuer_der()) {
            (Ok(subject), Ok(issuer)) => subject != issuer,
            // a name this build cannot re-encode is not assumed self-issued:
            // it counts, which is the stricter direction
            _ => true,
        })
        .count()
}

/// Walks from the signer certificate upwards. At each step the issuer is
/// looked for first among the trust anchors and then among the certificates
/// embedded in the signature, and every candidate has to verify the current
/// certificate's signature with its public key *and* pass [`check_certificate_rules`]
/// as an issuer: `basicConstraints.cA = TRUE`, `keyCertSign` when present, a
/// `pathLenConstraint` that still fits. Dates are checked on every certificate
/// that joins the chain, anchors included. The signer itself is judged as a
/// Signer (it must be allowed to sign).
///
/// Returns the chain signer first, *including* the anchor when the chain
/// already carries it embedded, and the anchor it stands on.
fn build_chain_refs<'c, 'a>(
    signer: &'c CertificateHandle,
    embedded: &'c [CertificateHandle],
    anchors: &'a [CertificateHandle],
    at: SystemTime,
    policy: &AlgorithmPolicy,
) -> Result<(Vec<&'c CertificateHandle>, &'a CertificateHandle)> {
    if anchors.is_empty() {
        return Err(fail(
            CHECK_CERTIFICATE_CHAIN,
            "no trust anchors were supplied, so no chain can ever be accepted",
        ));
    }
    check_validity(signer, at)?;
    // the signer's own key was already judged with the signature-value check
    // by verify_signer_info; chain_certificates callers (PAdES /DSS) get it
    // here, where no signature value exists to judge it against
    check_key_strength(
        CHECK_CERTIFICATE_CHAIN,
        signer
            .key_info()
            .map_err(|e| fail(CHECK_CERTIFICATE_CHAIN, detail_of(&e)))?,
        policy,
    )?;
    check_certificate_rules(signer, CertRole::Signer)?;
    let mut chain: Vec<&'c CertificateHandle> = vec![signer];
    let mut visited: Vec<&[u8]> = vec![signer.der()];
    let mut current: &'c CertificateHandle = signer;

    for step in 0..MAX_CHAIN_DEPTH {
        // The chain stands on a certificate that is also one of the anchors.
        // Two shapes reach this point and they are not alike:
        //
        // * the signer alone, standing on itself as its own anchor — nobody
        //   above it vouches for anything, so the same rule as everywhere
        //   else decides: only something that may certify certificates (cA =
        //   TRUE and keyCertSign; a pre-v3 certificate never) may be its own
        //   authority. This is finding C1's self-anchored attack ("FIRMA
        //   VALIDA" for any leaf the user points at), and a real self-signed
        //   root passes it as what it is: a CA that signed itself.
        // * a middle link that merely equals an anchor of the pool (a cross-
        //   signed certificate the user chose to trust): its own signature
        //   was already checked by the walk one step below, exactly like any
        //   other accepted issuer, and RFC 5280's final constraint is about
        //   the *candidate issuer*, not about this terminal. Trusting it as
        //   an anchor is the user's decision, which the verifier implements
        //   without a second opinion — openssl's `-trusted` behaves the same.
        if let Some(anchor) = anchors.iter().find(|a| a.der() == current.der()) {
            if step > 0 {
                return Ok((chain, anchor));
            }
            check_certificate_rules(
                current,
                CertRole::Issuer {
                    depth_below: intermediates_below(&chain),
                },
            )?;
            return Ok((chain, anchor));
        }
        let issuer_der = current.issuer().to_der()?;
        let mut name_matches = 0usize;
        let mut signature_failures = 0usize;
        // certificates below `current` that its pathLenConstraint bounds: RFC
        // 5280 6.1.4 (l)/(m) counts the INTERMEDIATE certificates between it
        // and the end entity — never the end entity itself, and never a
        // self-issued certificate. Round 2, N1: counting the signer rejected
        // every chain whose CA carries `pathlen:0`, which is the shape of the
        // real Spanish CAs (AC FNMT Usuarios, AC Representación, the FNMT
        // sealing CAs, Firmaprofesional's intermediates), so `verify` refused
        // every citizen certificate from FNMT and every FNMT time-stamp.
        let depth_below = intermediates_below(&chain);

        for anchor in anchors {
            if anchor.subject().to_der()? != issuer_der {
                continue;
            }
            name_matches += 1;
            match check_cert_signature(current, anchor, policy) {
                Ok(()) => {
                    check_validity(anchor, at)?;
                    check_certificate_rules(anchor, CertRole::Issuer { depth_below })?;
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
            if check_cert_signature(current, candidate, policy).is_err() {
                signature_failures += 1;
                continue;
            }
            // an embedded certificate that equals a trust anchor is the
            // anchor: the user named it, no issuer rules to prove
            let stands_on_anchor = anchors.iter().any(|a| a.der() == candidate.der());
            if !stands_on_anchor {
                check_certificate_rules(candidate, CertRole::Issuer { depth_below })?;
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
    policy: &AlgorithmPolicy,
) -> Result<(Vec<String>, String)> {
    let (chain, anchor) = build_chain_refs(signer, embedded, anchors, at, policy)?;
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
    // the archived-validation-data check rebuilds a chain for archival, not
    // for a verdict, so it runs with the conservative policy — the strictest
    // one available — and its caller decides what to do with a refusal
    let (chain, anchor) = build_chain_refs(
        signer,
        embedded,
        anchors,
        at,
        &AlgorithmPolicy::Conservative,
    )?;
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

/// How many `SignerInfo`s a CMS holds — the library's own structure check
/// (the same parse [`verify`] iterates), not a byte heuristic. A front-end
/// rendering one line per signer needs exactly this number to know whether
/// `verify`'s joined failure carries "signer N: " labels at all; guessing it
/// from byte windows counts the OIDs every CMS carries and gets it wrong on
/// the first RSA signature. An unparseable CMS has no count, which callers
/// read as "do not split".
pub fn signer_count(der: &[u8]) -> Result<usize> {
    Ok(parse_signed_data(der)?.signer_infos.len())
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
fn check_cert_signature(
    cert: &CertificateHandle,
    issuer: &CertificateHandle,
    policy: &AlgorithmPolicy,
) -> Result<()> {
    let sig_oid = &cert.parsed().signature_algorithm().oid;
    let digest =
        digest_from_signature_oid(sig_oid).map_err(|e| Error::Verification(detail_of(&e)))?;
    // A CA that signs its issued certificates with SHA-1 is a weak link no
    // matter how good the leaf's own signature is — and in the conservative
    // policy an old root whose cross-signature is SHA-1 does not anchor
    // anything, which is what VALIDe does with it too. The issuer's key is
    // the one that signs, so it is the one whose strength gets judged.
    check_algorithm_policy(CHECK_CERTIFICATE_CHAIN, digest, policy)?;
    check_key_strength(
        CHECK_CERTIFICATE_CHAIN,
        issuer
            .key_info()
            .map_err(|e| Error::Verification(detail_of(&e)))?,
        policy,
    )?;
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
    let mut outer = der_cursor(cert.der());
    let seq = outer.expect(tlv::TAG_SEQUENCE, "the certificate")?;
    let mut inner = der_cursor(seq.content);
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

/// The M5 refusal of a digest the caller's [`AlgorithmPolicy`] does not
/// accept. The name of the check is the caller's because the same SHA-1 rule
/// guards the signature value, a certificate's own signature and a CRL's —
/// every one of them is "the thing that signs chose a broken algorithm".
pub(crate) fn check_algorithm_policy(
    check: &str,
    digest: DigestAlg,
    policy: &AlgorithmPolicy,
) -> Result<()> {
    if *policy == AlgorithmPolicy::Conservative && digest == DigestAlg::Sha1 {
        return Err(fail(
            check,
            format!(
                "SHA-1 is not accepted: the algorithm policy is the conservative one \
                 (ETSI TS 119 312, {}), which SHA-1 signatures and pre-SHA-256 \
                 certificate signatures cannot satisfy. A caller verifying an archive \
                 of old signatures opts out with AlgorithmPolicy::All and takes \
                 responsibility for what it shows as valid.",
                openfirma_core::oid::ID_ETSIG_POLICY_CONSERVATIVE
            ),
        ));
    }
    Ok(())
}

/// The M5 refusal of a key weaker than the caller's policy allows. Like the
/// digest rule it runs before any crypto: checking first is also cheaper when
/// refusing.
pub(crate) fn check_key_strength(
    check: &str,
    info: KeyInfo,
    policy: &AlgorithmPolicy,
) -> Result<()> {
    if *policy == AlgorithmPolicy::Conservative {
        // An RSA key whose modulus is below the floor cannot be trusted to
        // have signed anything at any date (factoring it, not forging a hash,
        // is the realistic attack), so there is no "old but valid" exception
        // for key size. EC curves this verifier accepts are all >= 256 bits.
        if let Some(bits) = info.modulus_bits {
            if bits < RSA_MINIMUM_BITS {
                return Err(fail(
                    check,
                    format!(
                        "an RSA key of {bits} bits is below the {} bits the conservative \
                         algorithm policy requires; no signature it produced is safe to \
                         believe at any signing time. AlgorithmPolicy::All opts out.",
                        RSA_MINIMUM_BITS
                    ),
                ));
            }
        }
    }
    Ok(())
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
    let mut outer = der_cursor(der);
    let content_info = outer.expect(tlv::TAG_SEQUENCE, "the ContentInfo")?;
    if !outer.done() {
        return Err(trailing("after the ContentInfo"));
    }

    let mut ci = der_cursor(content_info.content);
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

    let mut sd_cur = der_cursor(content.content);
    let sd = sd_cur.expect(tlv::TAG_SEQUENCE, "the SignedData")?;
    if !sd_cur.done() {
        return Err(trailing("after the SignedData"));
    }

    let mut f = der_cursor(sd.content);
    let version = f.small_uint("SignedData.version")?;
    if !(1..=5).contains(&version) {
        return Err(Error::Verification(format!(
            "SignedData version {version} is not a version RFC 5652 defines"
        )));
    }
    let _digest_algorithms = f.expect(tlv::TAG_SET, "SignedData.digestAlgorithms")?;

    let mut eci = der_cursor(
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
        let mut w = der_cursor(wrapper.content);
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
        let item = f.value()?;
        match item.tag {
            0xA0 => {
                let mut certs = der_cursor(item.content);
                while !certs.done() {
                    let c = certs.value()?;
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
                let mut infos = der_cursor(item.content);
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
    let mut f = der_cursor(content);
    let version = f.small_uint("SignerInfo.version")?;
    if version != 1 && version != 3 {
        return Err(Error::Verification(format!(
            "SignerInfo version {version}: only 1 (issuerAndSerialNumber) and 3 \
             (subjectKeyIdentifier) are supported"
        )));
    }
    let sid_item = f.value()?;
    let sid = match sid_item.tag {
        tlv::TAG_SEQUENCE => {
            let mut s = der_cursor(sid_item.content);
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

    let mut dai = der_cursor(
        f.expect(tlv::TAG_SEQUENCE, "SignerInfo.digestAlgorithm")?
            .content,
    );
    let digest_oid = dai.oid("the digestAlgorithm")?;
    let digest_alg =
        DigestAlg::from_oid(&digest_oid).map_err(|e| Error::Verification(detail_of(&e)))?;

    let mut signed_attrs = None;
    if f.peek_tag() == Some(0xA0) {
        signed_attrs = Some(f.value()?.content);
    }

    let mut sai = der_cursor(
        f.expect(tlv::TAG_SEQUENCE, "SignerInfo.signatureAlgorithm")?
            .content,
    );
    let signature_alg_oid = sai.oid("the signatureAlgorithm")?;

    let signature = f
        .expect(tlv::TAG_OCTET_STRING, "SignerInfo.signatureValue")?
        .content;

    let mut unsigned_attrs = None;
    if f.peek_tag() == Some(0xA1) {
        unsigned_attrs = Some(f.value()?.content);
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
    /// The v1 ESS `signingCertificate` (RFC 5035 2, ESSCertID). A CAdES
    /// signature must carry the V2; a RFC 3161 token may carry either.
    signing_cert: Option<Tlv<'a>>,
    content_hint: Option<String>,
    mime_type: Option<String>,
    other: Vec<ObjectIdentifier>,
}

fn parse_attributes(content: &[u8]) -> Result<ParsedAttrs<'_>> {
    let mut out = ParsedAttrs::default();
    let mut seen: Vec<ObjectIdentifier> = Vec::new();
    let mut cur = der_cursor(content);
    while !cur.done() {
        let attr = cur.expect(tlv::TAG_SEQUENCE, "an Attribute")?;
        let mut a = der_cursor(attr.content);
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

        let mut vs = der_cursor(values.content);
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
            t if t == oid::ID_SIGNING_CERTIFICATE => {
                // ESS signingCertificate (v1): RFC 3161 TSAs still emit it,
                // and ts_mode accepts it. `check_signing_certificate_v2`
                // reads the v1 ESSCertID shape by its hash length.
                let v = one_value(&mut vs, &attr_type)?;
                out.signing_cert = Some(v);
            }
            t if t == oid::ID_CONTENT_HINT => {
                let v = one_value(&mut vs, &attr_type)?;
                let mut hint =
                    der_cursor(expect_tag(&v, tlv::TAG_SEQUENCE, "contentHint")?.content);
                let mut description = String::new();
                while !hint.done() {
                    let part = hint.value()?;
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
    let mut cur = der_cursor(content);
    while !cur.done() {
        let attr = cur.expect(tlv::TAG_SEQUENCE, "an Attribute")?;
        let mut a = der_cursor(attr.content);
        out.push(a.oid("the Attribute type")?);
    }
    Ok(out)
}

fn one_value<'a>(values: &mut Cur<'a>, attr_type: &ObjectIdentifier) -> Result<Tlv<'a>> {
    let v = values.value()?;
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
// the shared DER cursor of `openfirma_core::tlv`, under the names this module
// already used. CMS DER must be strict DER, so every cursor here is built
// with NO_HIGH_TAG; a helper keeps that one line short.

pub(crate) type Tlv<'a> = tlv::Value<'a>;
type Cur<'a> = tlv::Cursor<'a>;

pub(crate) fn der_cursor(bytes: &[u8]) -> Cur<'_> {
    tlv::Cursor::with_options(bytes, tlv::NO_HIGH_TAG)
}
