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

    /// When true the content travels inside the signature, which is what
    /// AutoFirma does by default for a file. When false the signature is
    /// detached and the content stays outside, which is what PAdES needs.
    pub encapsulate_content: bool,

    /// Adds the RFC 5652 `signingTime` attribute. AutoFirma includes it even
    /// for profiles where the timestamp comes from a TSA.
    pub signing_time: Option<SystemTime>,

    /// Adds the ETSI `mime-type` attribute when set.
    pub mime_type: Option<String>,

    /// Adds the ESS `contentHint` attribute with this description. AutoFirma
    /// includes it by default in the advanced profile with a Spanish
    /// description from its jmimemagic database, which we do not ship, so it
    /// is opt in here. The content type OID comes from `content_type`.
    pub content_hint: Option<String>,

    /// Adds `signingCertificateV2`. Every ETSI baseline profile requires it.
    pub signing_certificate_v2: bool,

    /// Carry issuer and serial inside `signingCertificateV2`.
    pub include_issuer_serial: bool,

    /// Extra certificates to embed on top of the signer cert and its chain.
    pub extra_certificates: Vec<CertificateHandle>,

    /// Unsigned attributes, already DER encoded. Used for the B-T timestamp.
    pub unsigned_attributes: Vec<Vec<u8>>,
}

/// The defaults reproduce AutoFirma's `advanced` profile, which is what it
/// uses unless told otherwise: content encapsulated, `signingTime` present,
/// and `signingCertificateV2` carrying issuer and serial.
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
            content_hint: None,
            signing_certificate_v2: true,
            include_issuer_serial: true,
            extra_certificates: Vec::new(),
            unsigned_attributes: Vec::new(),
        }
    }
}

/// Produces a complete CMS `ContentInfo` holding a `SignedData`.
///
/// This is the CAdES-B-B level. Higher levels add unsigned attributes on top
/// of it, see [`CadesOptions::unsigned_attributes`].
pub fn sign(content: &[u8], signer: &dyn Signer, opts: &CadesOptions) -> Result<Vec<u8>> {
    let digest_alg = opts.digest;
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
        signed_attrs.push(attributes::signing_certificate_v2(
            signer.certificate(),
            digest_alg,
            opts.include_issuer_serial,
        )?);
    }
    if let Some(mime) = &opts.mime_type {
        signed_attrs.push(attributes::mime_type(mime)?);
    }
    if let Some(description) = &opts.content_hint {
        signed_attrs.push(attributes::content_hint(description, &opts.content_type)?);
    }

    let attrs_content = tlv::set_of_content(signed_attrs);

    // RFC 5652 5.4: the signature is computed over the DER of the attributes
    // encoded as a SET OF, with the [0] IMPLICIT tag replaced by 0x31.
    let to_sign = tlv::tlv(tlv::TAG_SET, &attrs_content);
    let prehash = digest_alg.digest(&to_sign);

    let signature_value = signer.sign_prehash(digest_alg, &prehash)?;
    let signature_alg = signer.signature_alg(digest_alg)?;

    let signer_info = build_signer_info(
        signer,
        digest_alg,
        signature_alg,
        &attrs_content,
        &signature_value,
        &opts.unsigned_attributes,
    )?;

    let signed_data = tlv::sequence(&[
        // version 1: eContentType is id-data, no attribute certificates and
        // no subject key identifier in the signer infos
        tlv::integer_small(1),
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
    items.push(signer.certificate().der().to_vec());
    for cert in signer.chain() {
        items.push(cert.der().to_vec());
    }
    for cert in extra {
        items.push(cert.der().to_vec());
    }
    tlv::der_sort(&mut items);
    Ok(tlv::implicit_constructed(0, &items.concat()))
}
