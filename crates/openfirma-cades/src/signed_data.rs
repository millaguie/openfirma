//! CMS `SignedData` assembly, RFC 5652, plus the CAdES attribute set.
//!
//! The structures are built from encoded pieces with [`openfirma_core::tlv`]
//! rather than with derive macros, for two reasons. The signed attributes have
//! to be encoded twice under two different tags, `[0] IMPLICIT` in the
//! structure and `SET OF` for the signature, and `SET OF` ordering has to be
//! exact. See docs/adr/0001-hand-rolled-cms.md.

use std::time::SystemTime;

use const_oid::ObjectIdentifier;
use der::Encode;
use openfirma_core::alg::{DigestAlg, SignatureAlg};
use openfirma_core::cert::CertificateHandle;
use openfirma_core::signer::Signer;
use openfirma_core::tlv;
use openfirma_core::{Result, oid};

use crate::attributes;

/// Everything that shapes the output signature.
pub struct CadesOptions {
    pub digest: DigestAlg,

    /// `encapContentInfo.eContentType`, `id-data` for a plain file.
    pub content_type: ObjectIdentifier,

    /// When true the content travels inside the signature (AutoFirma's
    /// `mode=implicit`). When false the signature is detached and the content
    /// stays outside, which is AutoFirma's own default (`mode=explicit`: in
    /// @firma vocabulary explicit means "digest only") and what PAdES needs.
    pub encapsulate_content: bool,

    /// Adds the RFC 5652 `signingTime` attribute. AutoFirma includes it even
    /// for profiles where the timestamp comes from a TSA.
    pub signing_time: Option<SystemTime>,

    /// Adds the ETSI `mime-type` attribute when set.
    pub mime_type: Option<String>,

    /// Adds the ESS `contentHint` attribute with this description, or with
    /// AutoFirma's generic `"binary"` when `Some(String::new())`. AutoFirma
    /// includes it always unless asked not to (`includeContentHintAttribute=
    /// false`), so the default includes it; its Spanish per-type descriptions
    /// come from a jmimemagic database we do not ship, and the golden diff
    /// measures that. Set to `None` to leave the attribute out (what PAdES
    /// pins: docs/pades.md). The content type OID comes from `content_type`.
    pub content_hint: Option<String>,

    /// Adds the ESS signer-certificate attribute. Every ETSI baseline profile
    /// requires it; which one — V2 or the v1 `signingCertificate` — follows
    /// the digest, exactly like AutoFirma's `CAdESParameters.load`: SHA-1
    /// signs with v1 because RFC 5035 defines V2 for SHA-2.
    pub signing_certificate_v2: bool,

    /// Carry issuer and serial inside the signer-certificate attribute.
    pub include_issuer_serial: bool,

    /// Copy the signer certificate's `certificatePolicies` into the OPTIONAL
    /// `policies` field of the signer-certificate attribute. AutoFirma does
    /// it by default (`doNotIncludePolicyOnSigningCertificate=false`), and a
    /// real FNMT/DNIe/sello certificate always carries the extension, so this
    /// is a golden-visible difference with every certificate that signs in
    /// the real world. Nothing appears when the certificate has no policies.
    pub include_certificate_policies: bool,

    /// Adds ETSI `signaturePolicyIdentifier` (EN 319 122-1 6.4) naming this
    /// policy OID — the attribute a Spanish AGE sede asks for with its
    /// `policyIdentifier` extraParam (`2.16.724.1.3.1.1.2.1.9` and friends).
    /// AutoFirma, given only an identifier, writes `sigPolicyHash` as a
    /// DigestInfo of the signature's own digest algorithm over a placeholder
    /// byte (see [`crate::attributes::signature_policy_identifier`]). A sede
    /// that publishes an assertion for its policy passes its digest through
    /// [`Self::signature_policy_hash`] instead. `None` leaves the attribute
    /// out.
    pub signature_policy: Option<ObjectIdentifier>,

    /// The `sigPolicyHash` bytes to write with [`Self::signature_policy`]:
    /// normally the message imprint of the policy assertion text under the
    /// signature's digest algorithm. Empty keeps AutoFirma's placeholder.
    pub signature_policy_hash: Vec<u8>,

    /// Adds ETSI `commitmentTypeIndication` (EN 319 122-1 6.5) naming this
    /// commitment type — AutoFirma's `_commitmentTypeIndication` extraParam,
    /// `0.4.0.194112.1` for a legal act in Spanish administration. Multiple
    /// types are not supported on purpose: every real caller of the attribute
    /// names exactly one.
    pub commitment_type: Option<ObjectIdentifier>,

    /// Which algorithm strengths signing accepts at all — finding M5, the
    /// mirror of [`crate::verify::AlgorithmPolicy`] on the production side.
    /// The default ([`Conservative`](crate::verify::AlgorithmPolicy::Conservative))
    /// refuses to produce a SHA-1 signature or sign under an RSA key below
    /// [`openfirma_core::signer::RSA_MINIMUM_BITS`], so weak output cannot
    /// leave this program by accident — a sede's validator is not the place to
    /// discover it. A caller archiving legacy flows sets
    /// [`All`](crate::verify::AlgorithmPolicy::All) and owns what that means.
    pub algorithms: crate::verify::AlgorithmPolicy,

    /// Extra certificates to embed on top of the signer cert and its chain.
    pub extra_certificates: Vec<CertificateHandle>,

    /// Unsigned attributes, already DER encoded.
    pub unsigned_attributes: Vec<Vec<u8>>,

    /// Asked for the B-T level: called with the signature value once it exists,
    /// returning extra unsigned attributes to attach. A time-stamp token
    /// imprints the signature value, so it can only be requested after the
    /// value is computed, and being unsigned it cannot change it. The closure
    /// is where transport lives, which keeps this crate free of any network
    /// dependency.
    pub timestamp: Option<TimestampFn>,
}

/// Produces unsigned attributes for a signature value, typically by asking a
/// TSA for a token that imprints it.
// Arc rather than Box so options can be shared by reference: PAdES builds
// its CAdES options from a borrowed PadesOptions.
pub type TimestampFn =
    std::sync::Arc<dyn Fn(&[u8], DigestAlg) -> openfirma_core::Result<Vec<Vec<u8>>> + Send + Sync>;

/// The defaults reproduce AutoFirma's `advanced` profile, which is what it
/// uses unless told otherwise: detached content (`mode=explicit`),
/// `signingTime` present, the signer-certificate attribute carrying issuer
/// and serial, and `contentHint` present with AutoFirma's generic `"binary"`
/// description (its per-type Spanish descriptions are a jmimemagic lookup we
/// do not ship — measured against the golden in docs/validation.md).
impl Default for CadesOptions {
    fn default() -> Self {
        Self {
            digest: DigestAlg::Sha256,
            content_type: oid::ID_DATA,
            // AutoFirma's default mode is "explicit", and in @firma vocabulary
            // explicit means the signature carries only the digest, so the
            // content stays outside. "implicit" is the one that encapsulates.
            // The naming is the opposite of what it suggests, confirmed against
            // the golden output rather than the docs.
            encapsulate_content: false,
            signing_time: Some(SystemTime::now()),
            mime_type: None,
            content_hint: Some(AUTOFIRMA_DEFAULT_CONTENT_DESCRIPTION.to_string()),
            signing_certificate_v2: true,
            include_issuer_serial: true,
            include_certificate_policies: true,
            signature_policy: None,
            signature_policy_hash: Vec::new(),
            commitment_type: None,
            algorithms: crate::verify::AlgorithmPolicy::default(),
            extra_certificates: Vec::new(),
            unsigned_attributes: Vec::new(),
            timestamp: None,
        }
    }
}

/// `MimeHelper.DEFAULT_CONTENT_DESCRIPTION` in AutoFirma: the contentHint
/// description it writes when it cannot identify the data's type (which is
/// every file whose magic its jmimemagic database does not know), and so the
/// honest value for a client that ships no type database at all.
pub const AUTOFIRMA_DEFAULT_CONTENT_DESCRIPTION: &str = "binary";

/// Produces a complete CMS `ContentInfo` holding a `SignedData`.
///
/// This is the CAdES-B-B level. Higher levels add unsigned attributes on top
/// of it, see [`CadesOptions::unsigned_attributes`].
pub fn sign(content: &[u8], signer: &dyn Signer, opts: &CadesOptions) -> Result<Vec<u8>> {
    let digest_alg = opts.digest;
    // M5 on the production side: refuse weak output before any crypto runs.
    // The same helper the verifier uses, so both sides of the door quote the
    // same rule and the same error text. A signature this function refuses to
    // make is a signature no ETSI conservative validator would believe.
    crate::verify::check_algorithm_policy("signing", digest_alg, &opts.algorithms)?;
    crate::verify::check_key_strength(
        "signing",
        signer.certificate().key_info().map_err(|e| {
            openfirma_core::Error::other(format!(
                "the signer certificate carries no readable key: {e}"
            ))
        })?,
        &opts.algorithms,
    )?;
    let content_digest = digest_alg.digest(content);

    // Signed attributes. Order in the vector does not matter, set_of_content
    // sorts them the way X.690 requires.
    let mut signed_attrs: Vec<Vec<u8>> = Vec::new();
    signed_attrs.push(attributes::content_type(&opts.content_type)?);
    if let Some(t) = opts.signing_time {
        signed_attrs.push(attributes::signing_time(t)?);
    }
    signed_attrs.push(attributes::message_digest(&content_digest)?);
    if opts.signing_certificate_v2 {
        // AutoFirma's rule (CAdESParameters.load): V2 for SHA-2 digests, v1
        // for SHA-1. A SHA-1 signature that names V2 is a shape no other
        // producer of CAdES makes, and the verifier would then refuse every
        // real AutoFirma SHA-1 file — finding M1, fixed on both sides.
        let use_v2 = digest_alg != DigestAlg::Sha1;
        signed_attrs.push(attributes::signing_certificate(
            signer.certificate(),
            digest_alg,
            opts.include_issuer_serial,
            use_v2,
            opts.include_certificate_policies,
        )?);
    }
    if let Some(policy) = &opts.signature_policy {
        signed_attrs.push(attributes::signature_policy_identifier(
            policy,
            digest_alg,
            &opts.signature_policy_hash,
        )?);
    }
    if let Some(commitment) = &opts.commitment_type {
        signed_attrs.push(attributes::commitment_type_indication(commitment)?);
    }
    if let Some(mime) = &opts.mime_type {
        signed_attrs.push(attributes::mime_type(mime)?);
    }
    if let Some(description) = &opts.content_hint {
        // an empty description means AutoFirma's generic one, so the caller
        // never has to know the constant to match AutoFirma's shape
        let description = if description.is_empty() {
            AUTOFIRMA_DEFAULT_CONTENT_DESCRIPTION
        } else {
            description.as_str()
        };
        signed_attrs.push(attributes::content_hint(description, &opts.content_type)?);
    }

    let attrs_content = tlv::set_of_content(signed_attrs);

    // RFC 5652 5.4: the signature is computed over the DER of the attributes
    // encoded as a SET OF, with the [0] IMPLICIT tag replaced by 0x31.
    let to_sign = tlv::tlv(tlv::TAG_SET, &attrs_content);
    let prehash = digest_alg.digest(&to_sign);

    let signature_value = signer.sign_prehash(digest_alg, &prehash)?;
    let signature_alg = signer.signature_alg(digest_alg)?;

    let mut unsigned = opts.unsigned_attributes.clone();
    if let Some(stamp) = &opts.timestamp {
        unsigned.extend(stamp(&signature_value, digest_alg)?);
    }

    let signer_info = build_signer_info(
        signer,
        digest_alg,
        signature_alg,
        &attrs_content,
        &signature_value,
        &unsigned,
    )?;

    // RFC 5652 5.1: version is 3 when eContentType is anything but id-data
    // (and never less than what the signer infos need — ours are always
    // issuerAndSerialNumber, version 1 there). AutoFirma gets this through
    // BouncyCastle and so does every strict validator.
    let sd_version = if opts.content_type == oid::ID_DATA {
        1
    } else {
        3
    };
    let signed_data = tlv::sequence(&[
        tlv::integer_small(sd_version),
        tlv::set_of(vec![tlv::algorithm_identifier(
            &digest_alg.algorithm_identifier()?,
        )?]),
        build_encap_content_info(&opts.content_type, content, opts.encapsulate_content)?,
        build_certificates(signer, &opts.extra_certificates)?,
        tlv::set_of(vec![signer_info]),
    ]);

    Ok(tlv::sequence(&[
        tlv::oid(&oid::ID_SIGNED_DATA)?,
        tlv::explicit(0, &signed_data),
    ]))
}

fn build_signer_info(
    signer: &dyn Signer,
    digest_alg: DigestAlg,
    signature_alg: SignatureAlg,
    attrs_content: &[u8],
    signature_value: &[u8],
    unsigned_attrs: &[Vec<u8>],
) -> Result<Vec<u8>> {
    let cert = signer.certificate();
    let mut fields = Vec::with_capacity(7);

    // version 1 means sid is issuerAndSerialNumber
    fields.push(tlv::integer_small(1));
    fields.push(tlv::sequence(&[
        cert.issuer().to_der()?,
        cert.serial_number().to_der()?,
    ]));
    fields.push(tlv::algorithm_identifier(
        &digest_alg.algorithm_identifier()?,
    )?);
    if !attrs_content.is_empty() {
        fields.push(tlv::implicit_constructed(0, attrs_content));
    }
    fields.push(tlv::algorithm_identifier(
        &signature_alg.cms_algorithm_identifier()?,
    )?);
    fields.push(tlv::octet_string(signature_value)?);
    if !unsigned_attrs.is_empty() {
        let content = tlv::set_of_content(unsigned_attrs.to_vec());
        fields.push(tlv::implicit_constructed(1, &content));
    }

    Ok(tlv::sequence(&fields))
}

fn build_encap_content_info(
    content_type: &ObjectIdentifier,
    content: &[u8],
    encapsulate: bool,
) -> Result<Vec<u8>> {
    let mut fields = vec![tlv::oid(content_type)?];
    if encapsulate {
        fields.push(tlv::explicit(0, &tlv::octet_string(content)?));
    }
    Ok(tlv::sequence(&fields))
}

/// `[0] IMPLICIT` set of certificates.
///
/// `certificates` is a `SET OF CertificateChoices`, so DER requires the
/// elements ordered by their encoded bytes. Insertion order is not enough and
/// a strict validator will reject it, which is exactly what the golden diff
/// against AutoFirma showed: BouncyCastle sorts, we did not.
fn build_certificates(signer: &dyn Signer, extra: &[CertificateHandle]) -> Result<Vec<u8>> {
    let mut items: Vec<Vec<u8>> = Vec::with_capacity(extra.len() + signer.chain().len() + 1);
    for cert in std::iter::once(signer.certificate())
        .chain(signer.chain().iter())
        .chain(extra.iter())
    {
        // A SET OF must not repeat elements for a strict validator; chains
        // supplied by hand overlap with what a token's PKCS#12 already
        // carries more often than one would think.
        let der = cert.der().to_vec();
        if !items.contains(&der) {
            items.push(der);
        }
    }
    tlv::der_sort(&mut items);
    Ok(tlv::implicit_constructed(0, &items.concat()))
}
