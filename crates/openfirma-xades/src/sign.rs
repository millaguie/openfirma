//! XAdES-B-B: an enveloped XML-DSig signature with the ETSI EN 319 132-1
//! baseline qualifying properties, built to match the measured AutoFirma 1.9
//! output byte for byte in structure. Everything about the layout here is
//! measured, not guessed; docs/xades.md is the record and the arbiter.

use std::time::SystemTime;

use base64::Engine;
use der::asn1::UintRef;
use der::{Decode, Sequence};
use openfirma_core::alg::{DigestAlg, EcCurve, KeyAlgorithm};
use openfirma_core::signer::Signer;
use openfirma_core::{Error, Result};

use crate::c14n;
use crate::xml;

pub const DS_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
pub const XADES_NS: &str = "http://uri.etsi.org/01903/v1.3.2#";
/// The Type of the SignedProperties reference uses the XAdES namespace
/// without a version, exactly like AutoFirma.
pub const SIGNED_PROPERTIES_TYPE: &str = "http://uri.etsi.org/01903#SignedProperties";
pub const C14N_URI: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
pub const ENVELOPED_URI: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
pub const XPATH_URI: &str = "http://www.w3.org/TR/1999/REC-xpath-19991116";
pub const XPATH_FILTER: &str = "not(ancestor-or-self::ds:Signature)";

/// The OID that AutoFirma's mime table assigns to `text/xml`, measured in its
/// `DataObjectFormat`.
pub const OID_TEXT_XML: &str = "1.2.840.10003.5.109.10";

pub struct XadesOptions {
    /// Digest of the signature algorithm (`ds:SignatureMethod`). AutoFirma's
    /// GUI signs with SHA256withRSA, so SHA-256 is the default.
    pub digest: DigestAlg,
    /// Digest of every `ds:Reference` and of the signing certificate in
    /// `CertDigest`. AutoFirma's `referencesDigestMethod` default is SHA-512,
    /// independent of the signature algorithm, and so is ours.
    pub reference_digest: DigestAlg,
    /// `xades:SigningTime`. Defaults to now, written as UTC: std Rust has no
    /// timezone database and AutoFirma writes local time with its offset, a
    /// deviation recorded in docs/xades.md.
    pub signing_time: Option<SystemTime>,
    /// `xades:MimeType` in `DataObjectFormat`. XML input is `text/xml` in
    /// AutoFirma unless overridden.
    pub mime_type: Option<String>,
    /// OID for the `DataObjectFormat`'s `ObjectIdentifier`, as a dotted
    /// string. Defaults to the table lookup for the mime type; when there is
    /// no known OID the whole `ObjectIdentifier` element is omitted, which is
    /// what AutoFirma does for an unrecognized mime type.
    pub content_type_oid: Option<String>,
}

impl Default for XadesOptions {
    fn default() -> Self {
        XadesOptions {
            digest: DigestAlg::Sha256,
            reference_digest: DigestAlg::Sha512,
            signing_time: None,
            mime_type: None,
            content_type_oid: None,
        }
    }
}

/// Signs an XML document with an enveloped XAdES-B-B signature.
///
/// The output is the input document with the `ds:Signature` spliced in as
/// the last child of the root element, the declaration normalized to
/// `<?xml version="1.0" encoding="UTF-8"?>` and everything outside the root
/// dropped: the measured AutoFirma serialization, see docs/xades.md.
pub fn xades_sign(input: &[u8], signer: &dyn Signer, opts: &XadesOptions) -> Result<Vec<u8>> {
    let doc = xml::parse(input).map_err(|e| {
        if !looks_like_xml(input) {
            Error::Xml(format!(
                "the input is not an XML document ({e}). Enveloped XAdES signs XML; \
                 for any other content sign it as CAdES with --format cades-b-b, which \
                 is also what AutoFirma's GUI offers for a file that is not XML"
            ))
        } else {
            e
        }
    })?;

    let key_alg = signer.key_algorithm()?;
    let sig_method_uri = signature_method_uri(key_alg, opts.digest)?;
    let digest_uri = digest_method_uri(opts.reference_digest);

    let sig_uuid = uuid_v4()?;
    let ref_uuid = uuid_v4()?;
    let sig_id = format!("Signature-{sig_uuid}");
    let ref_id = format!("Reference-{ref_uuid}");

    // AutoFirma references the root by its Id attribute when it has one and
    // signs the whole document (URI="") when it does not; the signature is
    // appended to the root either way. An empty Id is no identifier — the
    // Java signer checks `!ident.isEmpty()` before building `#{id}`, and a
    // URI="#" resolves nowhere an xmlsec1-based validator accepts.
    let root_id = doc.root.attr("Id").filter(|id| !id.is_empty());
    if let Some(id) = root_id {
        // `URI="#…"` is a same-document URI reference: an Id that is not an
        // NCName (a space, a `<`, a colon — the parser keeps attribute
        // values verbatim from any producer) would serialize an unencodable
        // fragment other validators resolve to no node at all. Refuse it as
        // clearly as AutoFirma's DOM layer would have.
        if !xml::is_valid_id(id) {
            return Err(Error::Xml(format!(
                "the root element's Id=\"{id}\" is not an NCName, so \
                 URI=\"#{id}\" could not resolve anywhere it is checked"
            )));
        }
        // A repeated Id is the classic XML signature wrapping pattern: two
        // elements answer `#id`, and a validator that resolves by any other
        // route than ours can end up checking one node's bytes against
        // another's digest. Refuse the document, the way DSS refuses
        // duplicated IDs.
        let mut seen = std::collections::HashSet::new();
        reject_duplicate_id(&doc.root, id, &mut seen)?;
    }
    let data_uri = match root_id {
        Some(id) => format!("#{id}"),
        None => String::new(),
    };

    // The data digest: C14N of the root subtree with every ds:Signature
    // subtree removed, which is the net effect of the enveloped transform
    // plus the XPath filter AutoFirma declares (docs/xades.md). Computed on
    // the input as it will appear in the output, signature excluded.
    let data_opts = c14n::Options {
        omit: Some((DS_NS.to_string(), "Signature".to_string())),
        ..Default::default()
    };
    // The root carries the Id we just validated, so URI="#id" resolves to it
    // — and nothing else in the document may carry it (the duplicate check
    // above guarantees that). Without an Id the reference is URI="", which
    // names the document; the enveloped transform then hands on the root
    // element, and so do the XPath filter and every validator: the node-set
    // that reaches the digest never contains a sibling of the root.
    //
    // Canonicalizing the whole DOCUMENT instead — which this line used to do,
    // on the reasoning that a root looks the same from either side — is what
    // broke it, because whole-document C14N also writes the document-level
    // processing instructions, and they are exactly what the transform chain
    // drops. Measured on inputs with a prolog PI, an epilog PI, or both (an
    // `xml-stylesheet` among them, and `testdata/inputs/pi-doc-level.xml`
    // carries that shape): `xmlsec1 --verify` reported `REFERENCE` failure on
    // our file every time, while AutoFirma's own signature over the same three
    // inputs verified OK — and its serializer had written no document-level PI
    // at all. So the root subtree is the target, here and in the output (see
    // `splice_into_document`), and a document-level PI is dropped rather than
    // signed.
    let data_c14n = c14n::root_element(&doc, &data_opts);
    let data_digest = opts.reference_digest.digest(&data_c14n);

    let cert = signer.certificate();
    let cert_digest = opts.reference_digest.digest(cert.der());

    let signing_time = opts.signing_time.unwrap_or_else(SystemTime::now);
    let mime_type = opts
        .mime_type
        .clone()
        .unwrap_or_else(|| "text/xml".to_string());
    let oid = match &opts.content_type_oid {
        Some(oid) => Some(oid.clone()),
        None => oid_for_mime(&mime_type).map(str::to_string),
    };

    // ---- the template fragments, built once ----
    //
    // Review 03, C-1: the SignedProperties and SignedInfo digests are NOT
    // taken over these strings canonicalized on their own. A validator reads
    // them hanging off the signed document's root (inside ds:Signature /
    // ds:Object) and canonicalizes with inclusive C14N 1.0, which re-emits
    // every namespace in scope — including what the document's own root
    // declares — and propagates the ancestors' xml:* attributes (§2.3/§2.4).
    // Canonicalizing a detached fragment misses exactly that context, so both
    // digests went wrong as soon as the root carried an xmlns or an xml:lang,
    // which is FacturaE and nearly all administrative XML. Instead: parse the
    // final file itself — the input's root with this ds:Signature spliced in,
    // exactly the bytes we ship — and canonicalize SignedProperties and
    // SignedInfo at the position each one occupies there. AutoFirma signs
    // exactly this way (Santuario on the DOM after appendChild), and its own
    // measured output proves it: recomputing ns-root.af.xml's digests in
    // place gets xmlns:fe onto both elements (docs/xades.md).

    let mut qp = String::new();
    qp.push_str(&format!(
        "<xades:QualifyingProperties xmlns:xades=\"{XADES_NS}\" \
         Id=\"{sig_id}-QualifyingProperties\" Target=\"#{sig_id}-Signature\" \
         xmlns:ds=\"{DS_NS}\">"
    ));
    let time_text = format_signing_time(signing_time)?;
    qp.push_str(&format!(
        "<xades:SignedProperties Id=\"{sig_id}-SignedProperties\">\
         <xades:SignedSignatureProperties>\
         <xades:SigningTime>{time_text}</xades:SigningTime>\
         <xades:SigningCertificateV2><xades:Cert><xades:CertDigest>\
         <ds:DigestMethod Algorithm=\"{digest_uri}\"/>\
         <ds:DigestValue>{}</ds:DigestValue>\
         </xades:CertDigest><xades:IssuerSerialV2/></xades:Cert></xades:SigningCertificateV2>\
         </xades:SignedSignatureProperties>",
        b64(&cert_digest),
    ));
    qp.push_str("<xades:SignedDataObjectProperties>");
    qp.push_str(&format!(
        "<xades:DataObjectFormat ObjectReference=\"#{ref_id}\">\
         <xades:Description/>"
    ));
    if let Some(oid) = &oid {
        // the leading urn:oid: and the OIDAsURN qualifier are what AutoFirma
        // writes; the value is escaped because a mime table is data
        qp.push_str(&format!(
            "<xades:ObjectIdentifier>\
             <xades:Identifier Qualifier=\"OIDAsURN\">urn:oid:{}</xades:Identifier>\
             <xades:Description/>\
             </xades:ObjectIdentifier>",
            c14n::escape_text(oid)
        ));
    }
    qp.push_str(&format!(
        "<xades:MimeType>{}</xades:MimeType><xades:Encoding/>\
         </xades:DataObjectFormat>",
        c14n::escape_text(&mime_type)
    ));
    qp.push_str("</xades:SignedDataObjectProperties></xades:SignedProperties>");
    qp.push_str("</xades:QualifyingProperties>");

    // ---- SignedInfo, as a closure of its two digest values ----

    let signed_info = |data_digest: &str, sp_digest: &str| {
        format!(
            "<ds:SignedInfo>\
             <ds:CanonicalizationMethod Algorithm=\"{C14N_URI}\"/>\
             <ds:SignatureMethod Algorithm=\"{sig_method_uri}\"/>\
             <ds:Reference Id=\"{ref_id}\" URI=\"{}\">\
             <ds:Transforms>\
             <ds:Transform Algorithm=\"{ENVELOPED_URI}\"/>\
             <ds:Transform Algorithm=\"{C14N_URI}\"/>\
             <ds:Transform Algorithm=\"{XPATH_URI}\">\
             <ds:XPath xmlns:ds=\"{DS_NS}\">{XPATH_FILTER}</ds:XPath>\
             </ds:Transform>\
             </ds:Transforms>\
             <ds:DigestMethod Algorithm=\"{digest_uri}\"/>\
             <ds:DigestValue>{data_digest}</ds:DigestValue>\
             </ds:Reference>\
             <ds:Reference Type=\"{SIGNED_PROPERTIES_TYPE}\" URI=\"#{sig_id}-SignedProperties\">\
             <ds:DigestMethod Algorithm=\"{digest_uri}\"/>\
             <ds:DigestValue>{sp_digest}</ds:DigestValue>\
             </ds:Reference>\
             </ds:SignedInfo>",
            c14n::escape_attr(&data_uri),
        )
    };

    let mut certs_b64 = String::new();
    certs_b64.push_str(&format!(
        "<ds:X509Certificate>{}</ds:X509Certificate>",
        b64(cert.der())
    ));
    for chain_cert in signer.chain() {
        certs_b64.push_str(&format!(
            "<ds:X509Certificate>{}</ds:X509Certificate>",
            b64(chain_cert.der())
        ));
    }
    // KeyValue for RSA only: AutoFirma omits it for EC keys because its own
    // validator does not accept Santuario's ECKeyValue (a FIXME in their
    // source), and we match the measured output (docs/xades.md)
    let key_value = match key_alg {
        KeyAlgorithm::Rsa => {
            let (modulus, exponent) = rsa_public_key_bytes(cert)?;
            format!(
                "<ds:KeyValue><ds:RSAKeyValue>\
                 <ds:Modulus>{}</ds:Modulus>\
                 <ds:Exponent>{}</ds:Exponent>\
                 </ds:RSAKeyValue></ds:KeyValue>",
                b64(&modulus),
                b64(&exponent)
            )
        }
        KeyAlgorithm::EcPrimeField(_) => String::new(),
    };
    let key_info = format!(
        "<ds:KeyInfo Id=\"{sig_id}-KeyInfo\">\
         <ds:X509Data>{certs_b64}</ds:X509Data>{key_value}\
         </ds:KeyInfo>"
    );

    // In baseline the KeyInfo exists but is not referenced from SignedInfo,
    // measured; the signature covers the data and the SignedProperties only.

    // The SignatureValue text runs through both digest computations as this
    // comment: it keeps the file well formed while nothing depends on it —
    // the SignedInfo canonicalization ends before ds:SignatureValue, the
    // SignedProperties subtree does not contain it, and the data reference
    // omits every ds:Signature subtree. The final bytes swap it for the real
    // value with no digest to recompute.
    let placeholder = "<!--signature-value-->";
    let pass = |signed_info: &str| {
        format!(
            "<ds:Signature xmlns:ds=\"{DS_NS}\" Id=\"{sig_id}-Signature\">\
             {signed_info}\
             <ds:SignatureValue Id=\"{sig_id}-SignatureValue\">{placeholder}</ds:SignatureValue>\
             {key_info}\
             <ds:Object>{qp}</ds:Object>\
             </ds:Signature>"
        )
    };

    // Pass one: SignedProperties canonicalized inside the final document,
    // with everything its ancestors put in scope — the document root's own
    // declarations first. A validator reparses our shipped bytes and reads
    // exactly this tree, so this is the form its digest will match.
    let sp_opts = c14n::Options::default();
    let pass1_bytes = splice_into_document(input, &doc, pass(&signed_info("", "")).as_bytes())?;
    let pass1_doc = xml::parse(&pass1_bytes).map_err(internal)?;
    let root_xml_attrs = c14n::extend_xml_attrs(&[], &pass1_doc.root);
    let (sp, sp_context) = subtree_in_context(
        &pass1_doc.root,
        XADES_NS,
        "SignedProperties",
        &format!("{sig_id}-Signature"),
        "internal error: no SignedProperties in the signed document",
    )?;
    let sp_c14n = c14n::subtree(sp, &sp_context, &root_xml_attrs, &sp_opts);
    let sp_digest = b64(&opts.reference_digest.digest(&sp_c14n));

    // Pass two: SignedInfo now carries its final digest values; canonicalize
    // it where it stands and sign that. The ds:XPath element keeps its
    // redundant xmlns:ds in the file, and C14N 1.0 suppresses it in the
    // canonical form (docs/xades.md, "Gotcha"); walking the real tree makes
    // both happen by themselves, exactly like Santuario on the final DOM.
    let pass2_bytes = splice_into_document(
        input,
        &doc,
        pass(&signed_info(&b64(&data_digest), &sp_digest)).as_bytes(),
    )?;
    let pass2_doc = xml::parse(&pass2_bytes).map_err(internal)?;
    let (si, si_context) = subtree_in_context(
        &pass2_doc.root,
        DS_NS,
        "SignedInfo",
        &format!("{sig_id}-Signature"),
        "internal error: no SignedInfo in the signed document",
    )?;
    let root_xml_attrs = c14n::extend_xml_attrs(&[], &pass2_doc.root);
    let si_c14n = c14n::subtree(si, &si_context, &root_xml_attrs, &sp_opts);

    let prehash = opts.digest.digest(&si_c14n);
    let raw_sig = signer.sign_prehash(opts.digest, &prehash)?;
    // AutoFirma checks the PKCS#1 it just produced against the certificate
    // public key (ETSI TS 119 102-1); so do we, before any conversion
    openfirma_core::signer::verify_prehash(cert, opts.digest, &prehash, &raw_sig)?;
    let sig_value = match key_alg {
        KeyAlgorithm::Rsa => raw_sig,
        KeyAlgorithm::EcPrimeField(curve) => ecdsa_der_to_p1363(&raw_sig, coord_len(curve))?,
    };

    // The bytes we ship: pass two with the placeholder comment replaced by
    // the signature value. No digest depends on it (see `placeholder`), so
    // the tree this string came from and the file a validator reads agree.
    let mut final_signature = pass(&signed_info(&b64(&data_digest), &sp_digest));
    let at = final_signature
        .find(placeholder)
        .expect("the template always carries the placeholder");
    final_signature.replace_range(at..at + placeholder.len(), &b64(&sig_value));

    splice_into_document(input, &doc, final_signature.as_bytes())
}

/// Our own output failing to parse is a bug, not user input; say so in the
/// same voice as the other internal errors of this module.
fn internal(e: openfirma_core::Error) -> openfirma_core::Error {
    Error::other(format!(
        "internal error: our own signed document does not parse: {e}"
    ))
}

/// Finds `ns:local` **inside the `ds:Signature` this call is writing** — the
/// one whose `Id` is `signature_id` — and returns it with the namespace axis of
/// its ancestors only: every declaration written on every element above it,
/// outermost first, inner bindings last. The target's own declarations are not
/// part of it: `c14n::subtree` merges them against this context, exactly like a
/// validator's inclusive C14N re-emits what the subtree root inherits and
/// prints its own over it.
///
/// The signature is selected by `Id` and not by name because a document that
/// already carries a signature has its own `ds:Signature`, `ds:SignedInfo` and
/// `xades:SignedProperties`, and the first ones in document order belong to the
/// *earlier* signature. Naming them was round 2's N-2: signing an already signed
/// document referenced and signed the previous signature's signed properties —
/// both digests came out equal across the two signatures — and xmlsec1 and
/// AutoFirma rejected the file. `signature_id` is the fresh UUID this call put
/// in the template, so it cannot match an element the document already had.
fn subtree_in_context<'e>(
    root: &'e xml::Element,
    ns: &str,
    local: &str,
    signature_id: &str,
    what: &str,
) -> Result<(&'e xml::Element, c14n::Axis)> {
    fn walk<'e>(
        el: &'e xml::Element,
        ns: &str,
        local: &str,
        axis: &mut c14n::Axis,
    ) -> Option<&'e xml::Element> {
        if el.namespace.as_deref() == Some(ns) && el.name.local == local {
            return Some(el);
        }
        let base = axis.len();
        // this element is an ancestor of anything below it: its declarations
        // join the context for the descent, and come back out when the
        // descent returns empty-handed
        axis.extend(el.ns_decls.iter().cloned());
        for child in &el.children {
            if let xml::Child::Element(inner) = child {
                if let Some(found) = walk(inner, ns, local, axis) {
                    return Some(found);
                }
            }
        }
        axis.truncate(base);
        None
    }

    /// Descend to the `ds:Signature` carrying `id`, collecting the declarations
    /// of its ancestors on the way; then look for `ns:local` inside it.
    fn descend<'e>(
        el: &'e xml::Element,
        id: &str,
        ns: &str,
        local: &str,
        axis: &mut c14n::Axis,
    ) -> Option<&'e xml::Element> {
        let is_the_signature = el.name.local == "Signature"
            && el
                .attributes
                .iter()
                .any(|a| a.name.local == "Id" && a.value == id);
        if is_the_signature {
            return walk(el, ns, local, axis);
        }
        let base = axis.len();
        axis.extend(el.ns_decls.iter().cloned());
        for child in &el.children {
            if let xml::Child::Element(inner) = child {
                if let Some(found) = descend(inner, id, ns, local, axis) {
                    return Some(found);
                }
            }
        }
        axis.truncate(base);
        None
    }

    let mut axis = c14n::Axis::new();
    let el = descend(root, signature_id, ns, local, &mut axis)
        .ok_or_else(|| Error::other(what.to_string()))?;
    Ok((el, axis))
}

/// The output file: the normalized declaration, then the input bytes of the
/// root element with the signature inserted before its end tag. Nothing
/// outside the root survives, which is what AutoFirma's serializer does: on
/// three inputs carrying a prolog PI, an epilog PI, or both (an
/// `xml-stylesheet` among them, `testdata/inputs/pi-doc-level.xml`), its
/// output contained none of them and no comment either — it writes the
/// declaration and the document element and stops. That is also the only
/// shape whose digests a validator can recompute: everything outside the root
/// is past the enveloped transform, so keeping a PI would put an unprotected
/// node inside a signed file. The reader still parses them (a document that
/// lies about its encoding is refused by what it declares, PI included); they
/// are simply not part of what gets signed or written.
fn splice_into_document(input: &[u8], doc: &xml::Document, signature: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() + signature.len() + 64);
    out.extend_from_slice(b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
    // And nothing else: the input's document-level processing instructions and
    // comments are not written. Measured against AutoFirma (`docs/xades.md`),
    // and not only for fidelity — the data reference is the root subtree, so a
    // PI kept here would sit inside a signed file covered by no digest. The
    // prolog/epilog vectors still exist on the parsed document (the encoding
    // check reads them); they just have no part in the output. DTDs cannot be
    // here at all: the reader refuses them.
    let root = &doc.root;
    if root.self_closing {
        // <root attrs/> becomes <root attrs><ds:Signature .../></root>: the
        // DOM appendChild that AutoFirma performs cannot keep the short form
        let open = &input[root.open_tag.0..root.open_tag.1];
        let trimmed = &open[..open.len() - 2]; // drop the "/>"
        let trimmed = trim_ascii_end(trimmed);
        out.extend_from_slice(trimmed);
        out.push(b'>');
        out.extend_from_slice(signature);
        out.extend_from_slice(b"</");
        out.extend_from_slice(root.name.to_string_with_prefix().as_bytes());
        out.push(b'>');
        return Ok(out);
    }
    let (close_start, close_end) = root.close_tag;
    out.extend_from_slice(&input[root.open_tag.0..close_start]);
    out.extend_from_slice(signature);
    out.extend_from_slice(&input[close_start..close_end]);
    Ok(out)
}

fn trim_ascii_end(bytes: &[u8]) -> &[u8] {
    let mut end = bytes.len();
    while end > 0 && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    &bytes[..end]
}

fn looks_like_xml(input: &[u8]) -> bool {
    let mut bytes = input;
    if let Some(rest) = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF][..]) {
        bytes = rest;
    }
    let first = bytes.iter().find(|b| !b.is_ascii_whitespace());
    first == Some(&b'<')
}

/// Refuse a document in which any element below `root` re-declares the Id
/// that `URI="#id"` resolves to. The walk sees every element, at every depth
/// and in every namespace — an attribute named exactly `Id` is what XML
/// digital signatures look up — because the wrapping attack hides the second
/// one wherever the resolver for the other validator happens not to look.
fn reject_duplicate_id(
    root: &xml::Element,
    id: &str,
    seen: &mut std::collections::HashSet<String>,
) -> Result<()> {
    for child in &root.children {
        let xml::Child::Element(el) = child else {
            continue;
        };
        if let Some(other) = el.attr("Id") {
            if other == id || !seen.insert(other.to_string()) {
                return Err(Error::Xml(format!(
                    "the document carries Id=\"{other}\" on more than one element, \
                     so a reference to it has no single target"
                )));
            }
        }
        reject_duplicate_id(el, id, seen)?;
    }
    Ok(())
}

/// The `ds:SignatureMethod` URI for a key and a digest, AutoFirma's table.
fn signature_method_uri(key: KeyAlgorithm, digest: DigestAlg) -> Result<&'static str> {
    Ok(match key {
        KeyAlgorithm::Rsa => match digest {
            DigestAlg::Sha1 => "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
            DigestAlg::Sha256 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            DigestAlg::Sha384 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
            DigestAlg::Sha512 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
            DigestAlg::Sha224 => {
                return Err(Error::UnsupportedCombination {
                    key: "RSA",
                    digest: "SHA-224",
                });
            }
        },
        KeyAlgorithm::EcPrimeField(_) => match digest {
            DigestAlg::Sha1 => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1",
            DigestAlg::Sha224 => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224",
            DigestAlg::Sha256 => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
            DigestAlg::Sha384 => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384",
            DigestAlg::Sha512 => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512",
        },
    })
}

/// The `ds:DigestMethod` URI. The javax.xml.crypto.dsig constants AutoFirma
/// uses are not uniform: SHA-256 and SHA-512 come from xmlenc, SHA-224 and
/// SHA-384 from xmldsig-more. Matched value for value.
fn digest_method_uri(digest: DigestAlg) -> &'static str {
    match digest {
        DigestAlg::Sha1 => "http://www.w3.org/2000/09/xmldsig#sha1",
        DigestAlg::Sha224 => "http://www.w3.org/2001/04/xmldsig-more#sha224",
        DigestAlg::Sha256 => "http://www.w3.org/2001/04/xmlenc#sha256",
        DigestAlg::Sha384 => "http://www.w3.org/2001/04/xmldsig-more#sha384",
        DigestAlg::Sha512 => "http://www.w3.org/2001/04/xmlenc#sha512",
    }
}

/// The OID AutoFirma's jmimemagic table assigns to a mime type. Only `text/xml`
/// is measured (docs/xades.md); anything else gets no ObjectIdentifier unless
/// the caller names one.
pub fn oid_for_mime(mime: &str) -> Option<&'static str> {
    match mime {
        "text/xml" => Some(OID_TEXT_XML),
        _ => None,
    }
}

/// `xs:dateTime`, second precision, UTC. AutoFirma writes local time with its
/// offset; we cannot without a timezone database, and the instant is the
/// same, so we write Z (docs/xades.md, deviation 1).
fn format_signing_time(t: SystemTime) -> Result<String> {
    let secs = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| Error::other("the signing time is before 1970 and cannot be written"))?
        .as_secs() as i64;
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    let rem = secs.rem_euclid(86_400);
    Ok(format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    ))
}

/// Days since the epoch to a proleptic Gregorian date, Howard Hinnant's
/// `civil_from_days`, the same conversion the CLI and openfirma-pades use.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (y + i64::from(m <= 2), m, d)
}

/// UUID version 4, formatted like `java.util.UUID.toString`, which is what
/// every AutoFirma Id is built from.
fn uuid_v4() -> Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes)
        .map_err(|e| Error::other(format!("the operating system refused random bytes: {e}")))?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    ))
}

/// XML-DSig carries ECDSA signatures as the raw `r || s` (IEEE P1363), while
/// the `Signer` trait returns the DER form CMS uses. This converts between
/// the two, left padding each half to the curve's coordinate length.
fn ecdsa_der_to_p1363(der_sig: &[u8], coord_len: usize) -> Result<Vec<u8>> {
    #[derive(Sequence)]
    struct EcdsaSigDer<'a> {
        r: UintRef<'a>,
        s: UintRef<'a>,
    }
    let parsed = EcdsaSigDer::from_der(der_sig)
        .map_err(|e| Error::Signing(format!("the ECDSA signature is not DER: {e}")))?;
    let (r, s) = (parsed.r.as_bytes(), parsed.s.as_bytes());
    if r.len() > coord_len || s.len() > coord_len {
        return Err(Error::Signing(
            "the ECDSA signature coordinates are larger than the curve".into(),
        ));
    }
    let mut out = vec![0u8; 2 * coord_len];
    out[coord_len - r.len()..coord_len].copy_from_slice(r);
    out[2 * coord_len - s.len()..].copy_from_slice(s);
    Ok(out)
}

/// Modulus and public exponent of the certificate's RSA key, minimal
/// big-endian, which is what Santuario writes into `ds:RSAKeyValue`.
fn rsa_public_key_bytes(cert: &openfirma_core::CertificateHandle) -> Result<(Vec<u8>, Vec<u8>)> {
    #[derive(Sequence)]
    struct RsaPublicKeyDer<'a> {
        modulus: UintRef<'a>,
        public_exponent: UintRef<'a>,
    }
    let spki_der = cert.spki_der()?;
    let spki = spki::SubjectPublicKeyInfoRef::from_der(&spki_der)
        .map_err(|e| Error::Certificate(format!("unreadable public key info: {e}")))?;
    let key = RsaPublicKeyDer::from_der(spki.subject_public_key.raw_bytes()).map_err(|e| {
        Error::Certificate(format!("the certificate carries no readable RSA key: {e}"))
    })?;
    Ok((
        key.modulus.as_bytes().to_vec(),
        key.public_exponent.as_bytes().to_vec(),
    ))
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Length of one ECDSA signature coordinate in the P1363 form.
fn coord_len(curve: EcCurve) -> usize {
    match curve {
        EcCurve::P256 => 32,
        EcCurve::P384 => 48,
        EcCurve::P521 => 66,
    }
}
