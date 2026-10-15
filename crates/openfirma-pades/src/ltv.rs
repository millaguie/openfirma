//! PAdES B-LT and B-LTA: long-term validation data and the document
//! time-stamp, ETSI EN 319 142-1.
//!
//! Both are revisions appended *after* the signature they protect, in the
//! order the specification names: B-B signature, then the `/DSS` validation
//! data (B-LT), then the document time-stamp (B-LTA). Appending is what keeps
//! the earlier signatures valid: their `/ByteRange` addresses absolute
//! offsets, and nothing here moves a byte of what exists
//! (docs/adr/0003-incremental-update.md).
//!
//! B-LT writes a `/DSS` dictionary into the catalog (ISO 32000-2 12.8.4.4):
//!
//! - `/VRI`, keyed by the upper case hex of the **SHA-1 of the complete
//!   `/Contents` string** of each signature — the decoded bytes including
//!   the zero padding, exactly what ETSI EN 319 142-1 5.4.2.2 a) prescribes
//!   and what the European Commission's DSS validator recomputes — with
//!   `/Cert`, `/CRL` and `/OCSP` arrays naming the streams that validate
//!   that one signature. The keys are written as names, because dictionary
//!   keys in PDF syntax are names and every conforming reader expects that.
//!   `/TU` is left out: the collection time of data the caller handed over
//!   is not something this library knows.
//! - `/Certs`, `/CRLs`, `/OCSPs`: every archived stream, one PDF stream
//!   object per DER blob, uncompressed.
//!
//! B-LTA adds one signature field whose value is a `/Type /DocTimeStamp`
//! dictionary, `/SubFilter /ETSI.RFC3161`, its `/Contents` an RFC 3161 token
//! over the whole document minus that hole — which, the revision order being
//! what it is, includes the signature and the `/DSS`.
//!
//! Nothing here touches the network. The validation data is exactly what the
//! caller supplies; where it came from is the caller's business.

use std::collections::BTreeMap;

use openfirma_cades::revocation::{self, OcspCertId};
use openfirma_cades::{TimestampFn, tsp};
use openfirma_core::alg::DigestAlg;
use openfirma_core::cert::CertificateHandle;
use openfirma_core::{Error, Result};

use crate::appearance;
use crate::inspect;
use crate::pdf::{self, Location, ObjRef};
use crate::sign::{
    BYTERANGE_WIDTH, build_field, existing_signature_fields, fill_hole, merged_annots, next_name,
    page_at,
};
use crate::update::{Object, Update};

/// Revocation data to archive in the `/DSS`, as the caller obtained it.
#[derive(Clone, Debug)]
pub enum RevocationBytes {
    /// A DER `CertificateList` (RFC 5280), archived under `/CRLs`.
    Crl(Vec<u8>),
    /// A DER `OCSPResponse` (RFC 6960), archived under `/OCSPs`.
    Ocsp(Vec<u8>),
}

/// The `/DSS` of a document, resolved: the bytes of every archived stream
/// and the `/VRI` dictionary as written.
#[derive(Clone, Debug, Default)]
pub struct Dss {
    /// Each certificate stream: its object and its DER.
    pub certs: Vec<(ObjRef, Vec<u8>)>,
    /// Each CRL stream: its object and its DER.
    pub crls: Vec<(ObjRef, Vec<u8>)>,
    /// Each OCSP response stream: its object and its DER.
    pub ocsps: Vec<(ObjRef, Vec<u8>)>,
    /// The `/VRI` dictionary, when the `/DSS` carries one.
    pub vri: Option<Vec<u8>>,
}

impl Dss {
    /// The `/VRI` keys, normalized to upper case without whitespace, which
    /// is the form the SHA-1 of a signature value is compared in.
    pub fn vri_keys(&self) -> Result<Vec<String>> {
        match &self.vri {
            Some(v) => vri_keys(v),
            None => Ok(Vec::new()),
        }
    }
}

/// Reads the catalog's `/DSS`, resolving every stream it names. `None` when
/// the document has no validation data, which is the B-B case.
pub fn read_dss(pdf: &[u8]) -> Result<Option<Dss>> {
    if !pdf.starts_with(b"%PDF-") {
        return Err(Error::Pdf("the input does not start with %PDF-".into()));
    }
    let xref_at = pdf::last_startxref(pdf)?;
    let trailer = pdf::trailer(pdf, xref_at)?;
    let offsets = pdf::object_locations(pdf, xref_at)?;
    let catalog = pdf::resolve(pdf, &offsets, trailer.root)?.to_vec();
    let Some(dss_bytes) = pdf::get(&catalog, "/DSS") else {
        return Ok(None);
    };
    let owned;
    let dict: &[u8] = match pdf::parse_ref(dss_bytes) {
        Some(r) => {
            owned = pdf::resolve(pdf, &offsets, r)?.into_owned();
            &owned
        }
        None => dss_bytes,
    };
    if !dict.starts_with(b"<<") {
        return Err(Error::Pdf("the catalog's /DSS is not a dictionary".into()));
    }
    Ok(Some(Dss {
        certs: stream_array(pdf, &offsets, dict, "/Certs")?,
        crls: stream_array(pdf, &offsets, dict, "/CRLs")?,
        ocsps: stream_array(pdf, &offsets, dict, "/OCSPs")?,
        vri: match pdf::get(dict, "/VRI") {
            Some(v) => Some(match pdf::parse_ref(v) {
                Some(r) => pdf::resolve(pdf, &offsets, r)?.into_owned(),
                None => pdf::trim_ws(v).to_vec(),
            }),
            None => None,
        },
    }))
}

fn stream_array(
    pdf: &[u8],
    offsets: &BTreeMap<ObjRef, Location>,
    dict: &[u8],
    key: &str,
) -> Result<Vec<(ObjRef, Vec<u8>)>> {
    let Some(array) = pdf::get(dict, key) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for r in pdf::array_refs(array)? {
        out.push((r, stream_bytes(pdf, offsets, r, key)?));
    }
    Ok(out)
}

fn stream_bytes(
    pdf: &[u8],
    offsets: &BTreeMap<ObjRef, Location>,
    r: ObjRef,
    key: &str,
) -> Result<Vec<u8>> {
    match offsets.get(&r).copied() {
        Some(Location::Direct(off)) => {
            let dict_span = pdf::object_body(pdf, off)?;
            let dict = &pdf[dict_span];
            let raw = pdf::stream_raw(pdf, off)?;
            crate::stream::decode(dict, &raw)
        }
        // a stream object cannot legally live inside an object stream, so a
        // cross-reference that says it does describes a damaged document
        Some(Location::InObjectStream { stream, .. }) => Err(Error::Pdf(format!(
            "the {key} entry {r} is listed inside object stream {stream}, but stream objects \
             cannot live in object streams: the document is damaged"
        ))),
        None => Err(Error::Pdf(format!(
            "the {key} entry {r} is not in the cross-reference"
        ))),
    }
}

/// Adds the B-LT validation data to a signed document as a further
/// incremental update: the `/DSS` dictionary in the catalog, one stream
/// object per certificate, CRL and OCSP response, and a `/VRI` entry per
/// signature value found in the document.
///
/// `certs` must hold the full chain of every signature the archive is for —
/// the signer's own chain plus anything else the caller wants archived;
/// `revocation` at least one datum per CA certificate of those chains, or
/// `openfirma verify` will report the archive as incomplete. Identical blobs
/// are archived once, and blobs the `/DSS` already carries are not
/// duplicated, so extending a document twice is safe.
pub fn add_validation_data(
    pdf: &[u8],
    certs: &[CertificateHandle],
    revocation: &[RevocationBytes],
) -> Result<Vec<u8>> {
    if !pdf.starts_with(b"%PDF-") {
        return Err(Error::Pdf("the input does not start with %PDF-".into()));
    }
    let xref_at = pdf::last_startxref(pdf)?;
    let trailer = pdf::trailer(pdf, xref_at)?;
    let offsets = pdf::object_locations(pdf, xref_at)?;
    let catalog = pdf::resolve(pdf, &offsets, trailer.root)?.to_vec();
    if !catalog.starts_with(b"<<") {
        return Err(Error::Pdf("the catalog is not a dictionary".into()));
    }

    let sigs = inspect::signatures(pdf)?;
    if sigs.is_empty() {
        return Err(Error::Pdf(
            "B-LT archives the validation data of the signatures of a document, and this \
             document has none: sign it first"
                .into(),
        ));
    }

    // Parse and associate the revocation data before anything is laid out: a
    // blob that cannot be parsed is not archive material, and finding that
    // out after the objects were allocated would mean either a broken
    // archive or a half written revision.
    let mut crls: Vec<(Vec<u8>, Vec<u8>)> = Vec::new(); // (DER, issuer Name DER)
    let mut ocsps: Vec<(Vec<u8>, Vec<OcspCertId>)> = Vec::new();
    for item in revocation {
        match item {
            RevocationBytes::Crl(der) => {
                let issuer = revocation::crl_issuer_der(der).map_err(|e| {
                    Error::Pdf(format!(
                        "a CRL given for the /DSS cannot be parsed: {e}. Pass the DER of an \
                         RFC 5280 CertificateList (a PEM file needs its base64 decoded)"
                    ))
                })?;
                crls.push((der.clone(), issuer));
            }
            RevocationBytes::Ocsp(der) => {
                let ids = revocation::parse_ocsp_response(der).map_err(|e| {
                    Error::Pdf(format!(
                        "an OCSP response given for the /DSS is not usable: {e}"
                    ))
                })?;
                ocsps.push((der.clone(), ids));
            }
        }
    }
    let certs = dedupe_certs(certs);
    let crls = dedupe_by_first(crls);
    let ocsps = dedupe_by_first(ocsps);

    let old = read_dss(pdf)?.unwrap_or_default();
    let old_keys = old.vri_keys()?;

    // what the /DSS already archives: reused by reference, never duplicated
    let mut ref_by_der: BTreeMap<Vec<u8>, ObjRef> = BTreeMap::new();
    for (r, bytes) in old
        .certs
        .iter()
        .chain(old.crls.iter())
        .chain(old.ocsps.iter())
    {
        ref_by_der.entry(bytes.clone()).or_insert(*r);
    }
    // the archived certificates join the pool the chains are walked through,
    // so extending a document that already carries a chain needs only the
    // new signer's certificates
    let mut pool: Vec<CertificateHandle> = certs.clone();
    for (_, bytes) in &old.certs {
        if let Ok(handle) = CertificateHandle::from_der(bytes) {
            if !pool.iter().any(|c| c.der() == handle.der()) {
                pool.push(handle);
            }
        }
    }

    let mut update = Update::new(xref_at, trailer.root, trailer.info, trailer.size);
    let mut next_num = update.next_object_number();
    let mut new_cert_refs: Vec<ObjRef> = Vec::new();
    for c in &certs {
        if let std::collections::btree_map::Entry::Vacant(e) = ref_by_der.entry(c.der().to_vec()) {
            let r = ObjRef::new(next_num, 0);
            next_num += 1;
            update.push(Object::new(r, stream_object(c.der())));
            e.insert(r);
            new_cert_refs.push(r);
        }
    }
    let mut new_crl_refs: Vec<ObjRef> = Vec::new();
    for (der, _) in &crls {
        if let std::collections::btree_map::Entry::Vacant(e) = ref_by_der.entry(der.clone()) {
            let r = ObjRef::new(next_num, 0);
            next_num += 1;
            update.push(Object::new(r, stream_object(der)));
            e.insert(r);
            new_crl_refs.push(r);
        }
    }
    let mut new_ocsp_refs: Vec<ObjRef> = Vec::new();
    for (der, _) in &ocsps {
        if let std::collections::btree_map::Entry::Vacant(e) = ref_by_der.entry(der.clone()) {
            let r = ObjRef::new(next_num, 0);
            next_num += 1;
            update.push(Object::new(r, stream_object(der)));
            e.insert(r);
            new_ocsp_refs.push(r);
        }
    }

    // One /VRI entry per signature of the document, keyed by the SHA-1 of
    // its complete /Contents string (ETSI EN 319 142-1 5.4.2.2 a): the
    // decoded bytes including the zero padding, not just the DER inside.
    // A signature whose key the /VRI already carries was archived by an
    // earlier B-LT and is left alone.
    let mut new_entries: Vec<(String, Vec<u8>)> = Vec::new();
    for (i, sig) in sigs.iter().enumerate() {
        let key = vri_key(pdf, sig).ok_or_else(|| {
            Error::Pdf(format!(
                "the /Contents of signature {} cannot be read, so its validation data \
                 cannot be indexed",
                i + 1
            ))
        })?;
        if old_keys.contains(&key) || new_entries.iter().any(|(k, _)| *k == key) {
            continue;
        }
        let signers = openfirma_cades::verify::signer_certificates(&sig.cms).map_err(|e| {
            Error::Pdf(format!(
                "the signer certificate of signature {} cannot be located in its CMS: {e}",
                i + 1
            ))
        })?;
        // normally one signer; a CMS may carry more, and the entry then
        // archives the union of their chains
        let mut chain: Vec<CertificateHandle> = Vec::new();
        for signer in &signers {
            let Some(root_of_chain) = pool.iter().find(|c| c.der() == signer.der()) else {
                return Err(Error::Pdf(format!(
                    "the validation data does not carry the certificate of the signer of \
                     signature {} (\"{}\"), so the /DSS cannot archive its chain. Pass the \
                     full chain in PadesOptions::validation_certs or in the signer's chain.",
                    i + 1,
                    signer.subject_cn().unwrap_or_else(|| "unknown".into())
                )));
            };
            for c in chain_walk(root_of_chain, &pool) {
                if !chain.iter().any(|have| have.der() == c.der()) {
                    chain.push(c);
                }
            }
        }
        let cert_refs: Vec<ObjRef> = chain
            .iter()
            .filter_map(|c| ref_by_der.get(c.der()).copied())
            .collect();
        let ca_subjects: Vec<Vec<u8>> = chain
            .iter()
            .skip(1)
            .filter_map(|c| c.subject_der().ok())
            .collect();
        let crl_refs: Vec<ObjRef> = crls
            .iter()
            .filter(|(_, issuer)| ca_subjects.iter().any(|s| s == issuer))
            .filter_map(|(der, _)| ref_by_der.get(der).copied())
            .collect();
        let ocsp_refs: Vec<ObjRef> = ocsps
            .iter()
            .filter(|(_, ids)| {
                ids.iter().any(|id| {
                    chain
                        .iter()
                        .skip(1)
                        .any(|ca| ocsp_id_names_ca(id, ca).unwrap_or(false))
                })
            })
            .filter_map(|(der, _)| ref_by_der.get(der).copied())
            .collect();

        let mut entry = Vec::from(&b"<<"[..]);
        if !crl_refs.is_empty() {
            entry.extend_from_slice(format!(" /CRL [{}] ", refs(&crl_refs)).as_bytes());
        }
        if !cert_refs.is_empty() {
            entry.extend_from_slice(format!("/Cert [{}] ", refs(&cert_refs)).as_bytes());
        }
        if !ocsp_refs.is_empty() {
            entry.extend_from_slice(format!("/OCSP [{}] ", refs(&ocsp_refs)).as_bytes());
        }
        entry.extend_from_slice(b">>");
        new_entries.push((key, entry));
    }

    // /VRI: the dictionary that was there, plus the new keys. Its keys are
    // hex strings rather than names, so pdf::set cannot splice into it; the
    // bytes are reassembled by hand, everything old kept verbatim.
    let vri: Vec<u8> = match &old.vri {
        Some(old_vri) if new_entries.is_empty() => old_vri.clone(),
        Some(old_vri) => {
            let t = pdf::trim_ws(old_vri);
            if !t.ends_with(b">>") {
                return Err(Error::Pdf("the existing /VRI is not a dictionary".into()));
            }
            let mut out = t[..t.len() - 2].to_vec();
            for (key, entry) in &new_entries {
                out.extend_from_slice(format!(" /{key} ").as_bytes());
                out.extend_from_slice(entry);
                out.push(b' ');
            }
            out.extend_from_slice(b">>");
            out
        }
        None => {
            let mut out = Vec::from(&b"<<"[..]);
            for (key, entry) in &new_entries {
                out.extend_from_slice(format!(" /{key} ").as_bytes());
                out.extend_from_slice(entry);
                out.push(b' ');
            }
            out.extend_from_slice(b">>");
            out
        }
    };

    let cert_refs = merge_refs(&old.certs, &new_cert_refs);
    let crl_refs = merge_refs(&old.crls, &new_crl_refs);
    let ocsp_refs = merge_refs(&old.ocsps, &new_ocsp_refs);

    let mut dss = Vec::from(&b"<<"[..]);
    if !crl_refs.is_empty() {
        dss.extend_from_slice(format!(" /CRLs [{}] ", refs(&crl_refs)).as_bytes());
    }
    if !cert_refs.is_empty() {
        dss.extend_from_slice(format!("/Certs [{}] ", refs(&cert_refs)).as_bytes());
    }
    if !ocsp_refs.is_empty() {
        dss.extend_from_slice(format!("/OCSPs [{}] ", refs(&ocsp_refs)).as_bytes());
    }
    dss.extend_from_slice(b"/Type /DSS /VRI ");
    dss.extend_from_slice(&vri);
    dss.extend_from_slice(b" >>");

    let dss_ref = ObjRef::new(next_num, 0);
    update.push(Object::new(dss_ref, dss));
    update.push(Object::new(
        trailer.root,
        pdf::set(&catalog, "/DSS", format!("{dss_ref}").as_bytes())?,
    ));

    let rendered = update.render(pdf.len())?;
    let mut out = Vec::with_capacity(pdf.len() + rendered.bytes.len());
    out.extend_from_slice(pdf);
    out.extend_from_slice(&rendered.bytes);
    Ok(out)
}

/// Adds the B-LTA document time-stamp to a document whose B-LT validation
/// data already exists: a new signature field appended to `/Fields`, its
/// `/Contents` an RFC 3161 token obtained through the same
/// [`TimestampFn`] mechanism as the B-T signature time-stamp, imprinted over
/// everything before the hole — the `/DSS` included, which is the whole
/// point of the order.
///
/// The token's imprint is checked before it is embedded, exactly like the
/// B-T path does: a token over any other bytes is refused.
pub fn add_document_timestamp(
    pdf: &[u8],
    timestamp: &TimestampFn,
    digest: DigestAlg,
    contents_reserved: usize,
) -> Result<Vec<u8>> {
    if !pdf.starts_with(b"%PDF-") {
        return Err(Error::Pdf("the input does not start with %PDF-".into()));
    }
    let xref_at = pdf::last_startxref(pdf)?;
    let trailer = pdf::trailer(pdf, xref_at)?;
    let offsets = pdf::object_locations(pdf, xref_at)?;
    let catalog = pdf::resolve(pdf, &offsets, trailer.root)?.to_vec();
    if !catalog.starts_with(b"<<") {
        return Err(Error::Pdf("the catalog is not a dictionary".into()));
    }

    if read_dss(pdf)?.is_none() {
        return Err(Error::Pdf(
            "the document time-stamp is the B-LTA layer: it goes over a document whose B-LT \
             validation data already exists, and this document has no /DSS. Add the \
             validation data first (PadesOptions::revocation, or add_validation_data)."
                .into(),
        ));
    }
    let existing = existing_signature_fields(pdf, &offsets, &catalog);
    if existing.refs.is_empty() {
        return Err(Error::Pdf(
            "the document time-stamp is added as a new signature field, and this document's \
             /AcroForm has no fields to append it to"
                .into(),
        ));
    }

    let mut update = Update::new(xref_at, trailer.root, trailer.info, trailer.size);
    let first_new = update.next_object_number();
    let appearance = ObjRef::new(first_new, 0);
    let dts = ObjRef::new(first_new + 1, 0);
    let field = ObjRef::new(first_new + 2, 0);

    let field_name = next_name("Timestamp", &existing.names);
    let page_ref = page_at(pdf, &offsets, &catalog, 1)?;
    let page = pdf::resolve(pdf, &offsets, page_ref)?.to_vec();
    if !page.starts_with(b"<<") {
        return Err(Error::Pdf(format!("page {page_ref} is not a dictionary")));
    }

    update.push(Object::new(appearance, appearance::blank()));
    update.push(Object::new(dts, build_dts_dict(contents_reserved)));
    update.push(Object::new(
        field,
        build_field(field_name, appearance, page_ref, dts, "[0 0 0 0]"),
    ));

    // /AcroForm keeps every byte it has except /Fields, which gains the new
    // field; it may sit inline in the catalog or be an indirect object, and
    // only the definition that actually changes is rewritten
    let Some(acro_value) = pdf::get(&catalog, "/AcroForm") else {
        return Err(Error::Pdf(
            "the catalog has no /AcroForm to append the time-stamp field to".into(),
        ));
    };
    let (acro_ref, acro_bytes) = match pdf::parse_ref(acro_value) {
        Some(r) => (Some(r), pdf::resolve(pdf, &offsets, r)?.into_owned()),
        None => (None, pdf::trim_ws(acro_value).to_vec()),
    };
    let Some(fields_value) = pdf::get(&acro_bytes, "/Fields") else {
        return Err(Error::Pdf("the /AcroForm has no /Fields".into()));
    };
    let mut fields = pdf::trim_ws(fields_value).to_vec();
    if !fields.ends_with(b"]") {
        return Err(Error::Pdf("the /AcroForm /Fields is not an array".into()));
    }
    fields.pop();
    fields.extend_from_slice(format!(" {field}]").as_bytes());
    let new_acro = pdf::set(&acro_bytes, "/Fields", &fields)?;
    match acro_ref {
        Some(r) => update.push(Object::new(r, new_acro)),
        None => update.push(Object::new(
            trailer.root,
            pdf::set(&catalog, "/AcroForm", &new_acro)?,
        )),
    }
    update.push(Object::new(
        page_ref,
        pdf::set(&page, "/Annots", &merged_annots(&page, field)?)?,
    ));

    let rendered = update.render(pdf.len())?;
    let dts_at = rendered.offsets[&dts];
    let mut out = Vec::with_capacity(pdf.len() + rendered.bytes.len());
    out.extend_from_slice(pdf);
    out.extend_from_slice(&rendered.bytes);

    fill_hole(&mut out, dts_at, "time-stamp token", &|covered| {
        let attrs = timestamp(covered, digest)?;
        let mut first_error = None;
        for attr in &attrs {
            match tsp::token_from_attribute(attr, digest, covered) {
                Ok(token) => return Ok(token),
                Err(e) => {
                    if first_error.is_none() {
                        first_error = Some(e);
                    }
                }
            }
        }
        Err(first_error.unwrap_or_else(|| {
            Error::Other(
                "the time-stamp provider returned no attribute at all, so there is no token \
                 to embed as the document time-stamp"
                    .into(),
            )
        }))
    })?;
    Ok(out)
}

/// The document time-stamp dictionary with both placeholders in it, the same
/// fixed width trick as the signature dictionary: `/ByteRange` ahead of
/// `/Contents`, so patching the ranges cannot move the hole they describe.
///
/// No `/M`: the time of a document time-stamp lives in its token, and in
/// nowhere else.
fn build_dts_dict(contents_reserved: usize) -> Vec<u8> {
    format!(
        "<< /ByteRange [0 {z} {z} {z}] /Contents <{zeros}> /Filter /Adobe.PPKLite \
         /SubFilter /ETSI.RFC3161 /Type /DocTimeStamp >>",
        z = " ".repeat(BYTERANGE_WIDTH),
        zeros = "0".repeat(contents_reserved * 2),
    )
    .into_bytes()
}

/// One archived blob as a PDF stream object body. Uncompressed on purpose:
/// the point of the archive is to be readable decades from now by whatever
/// reads it then, and DER is already dense. The end of line before
/// `endstream` is not part of the data and not counted in `/Length`, as
/// ISO 32000 7.3.8.1 requires.
fn stream_object(data: &[u8]) -> Vec<u8> {
    let mut body = format!("<< /Length {} >> stream\n", data.len()).into_bytes();
    body.extend_from_slice(data);
    body.extend_from_slice(b"\nendstream");
    body
}

/// Walks issuer to subject through `pool`, signer first. No signature is
/// verified here: this only decides which archived certificates belong to
/// one signature's `/VRI` entry; whether the chain *holds* is the
/// verifier's job, and it does check every link.
fn chain_walk(signer: &CertificateHandle, pool: &[CertificateHandle]) -> Vec<CertificateHandle> {
    let mut chain = vec![signer.clone()];
    let mut current = signer;
    for _ in 0..16 {
        let Ok(issuer_der) = current.issuer_der() else {
            break;
        };
        let Some(next) = pool.iter().find(|c| {
            c.der() != current.der()
                && !chain.iter().any(|seen| seen.der() == c.der())
                && c.subject_der().is_ok_and(|s| s == issuer_der)
        }) else {
            break;
        };
        chain.push(next.clone());
        current = next;
    }
    chain
}

/// Whether an OCSP `CertID` speaks about certificates issued by `ca`, by the
/// RFC 6960 hashes. An unsupported hash algorithm answers `false`, not an
/// error: the response is still archived, it just cannot be associated.
pub(crate) fn ocsp_id_names_ca(id: &OcspCertId, ca: &CertificateHandle) -> Result<bool> {
    let Ok(hash) = DigestAlg::from_oid(&id.hash_algorithm) else {
        return Ok(false);
    };
    let (name_hash, key_hash) = revocation::ocsp_issuer_hashes(ca, hash)?;
    Ok(id.issuer_name_hash == name_hash || id.issuer_key_hash == key_hash)
}

fn refs(list: &[ObjRef]) -> String {
    list.iter()
        .map(|r| r.to_string())
        .collect::<Vec<_>>()
        .join(" ")
}

fn merge_refs(old: &[(ObjRef, Vec<u8>)], new: &[ObjRef]) -> Vec<ObjRef> {
    let mut out: Vec<ObjRef> = old.iter().map(|(r, _)| *r).collect();
    out.extend_from_slice(new);
    out
}

fn dedupe_certs(certs: &[CertificateHandle]) -> Vec<CertificateHandle> {
    let mut out: Vec<CertificateHandle> = Vec::with_capacity(certs.len());
    for c in certs {
        if !out.iter().any(|o| o.der() == c.der()) {
            out.push(c.clone());
        }
    }
    out
}

fn dedupe_by_first<T>(items: Vec<(Vec<u8>, T)>) -> Vec<(Vec<u8>, T)> {
    let mut out: Vec<(Vec<u8>, T)> = Vec::with_capacity(items.len());
    for item in items {
        if !out.iter().any(|(b, _)| *b == item.0) {
            out.push(item);
        }
    }
    out
}

/// The `/VRI` key of one signature: the upper case hex SHA-1 of its
/// complete `/Contents` string, decoded and padding included. This is the
/// input ETSI EN 319 142-1 5.4.2.2 a) names — "the complete hexadecimal
/// string in the entry with the key Contents" — and the one the DSS
/// validator recomputes, so a validator looking for the signature's
/// validation data finds it under this key and no other.
pub fn vri_key(pdf: &[u8], sig: &inspect::Signature) -> Option<String> {
    let [_, b, c, _] = sig.byte_range;
    if c > pdf.len() || b >= c {
        return None;
    }
    let gap = &pdf[b..c];
    if gap.first() != Some(&b'<') || gap.last() != Some(&b'>') {
        return None;
    }
    let hex_bytes: Vec<u8> = gap[1..gap.len() - 1]
        .iter()
        .filter(|b| !b.is_ascii_whitespace())
        .copied()
        .collect();
    let raw = hex::decode(hex_bytes).ok()?;
    Some(hex::encode_upper(DigestAlg::Sha1.digest(&raw)))
}

/// The keys of a `/VRI` dictionary, normalized to upper case without
/// whitespace. Keys are names of hex characters, which is the only shape
/// PDF syntax allows for a dictionary key; a writer that read the ISO
/// wording literally may have written `<hex string>` keys instead, and both
/// forms are accepted here.
pub(crate) fn vri_keys(vri: &[u8]) -> Result<Vec<String>> {
    let v = pdf::trim_ws(vri);
    if !v.starts_with(b"<<") {
        return Err(Error::Pdf("the /VRI value is not a dictionary".into()));
    }
    let end = pdf::dict_end(v, 0)?;
    let mut out = Vec::new();
    let mut i = 2;
    while i < end {
        i = pdf::skip_ws(v, i);
        if i >= end || v[i] == b'>' {
            break;
        }
        let key: String = match v[i] {
            b'/' => {
                let key_end = pdf::name_end(v, i);
                String::from_utf8_lossy(&v[i + 1..key_end]).to_ascii_uppercase()
            }
            b'<' => {
                let close = v[i..end]
                    .iter()
                    .position(|b| *b == b'>')
                    .ok_or_else(|| Error::Pdf("a /VRI key is not terminated".into()))?;
                v[i + 1..i + close]
                    .iter()
                    .filter(|b| !b.is_ascii_whitespace())
                    .map(|b| (*b as char).to_ascii_uppercase())
                    .collect()
            }
            other => {
                return Err(Error::Pdf(format!(
                    "a /VRI key must be a name of hex characters or a hex string, found \
                     {:?} at offset {i}",
                    other as char
                )));
            }
        };
        let key_end = match v[i] {
            b'<' => {
                i + v[i..end]
                    .iter()
                    .position(|b| *b == b'>')
                    .ok_or_else(|| Error::Pdf("a /VRI key is not terminated".into()))?
                    + 1
            }
            _ => pdf::name_end(v, i),
        };
        out.push(key);
        i = pdf::value_end(v, key_end)?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stream_object_counts_exactly_its_data() {
        let body = stream_object(b"\x30\x03\x02\x01\x05");
        assert!(body.starts_with(b"<< /Length 5 >> stream\n"));
        assert!(body.ends_with(b"\nendstream"));
        // /Length counts the data only: not the newline before endstream
        let inner = &body[b"<< /Length 5 >> stream\n".len()..body.len() - b"\nendstream".len()];
        assert_eq!(inner, b"\x30\x03\x02\x01\x05");
    }

    #[test]
    fn vri_keys_reads_names_and_hex_strings() {
        let names = b"<< /1a2B3c << /Cert [5 0 R] >> /FF00 << /CRL [6 0 R] >> >>";
        assert_eq!(vri_keys(names).unwrap(), ["1A2B3C", "FF00"]);
        let strings = b"<< <1a2B3c> << /Cert [5 0 R] >> <FF00> << /CRL [6 0 R] >> >>";
        assert_eq!(vri_keys(strings).unwrap(), ["1A2B3C", "FF00"]);
        // whitespace inside a hex string is legal PDF and must not survive
        let split = b"<< <1a 2b\n3c> << /Cert [5 0 R] >> >>";
        assert_eq!(vri_keys(split).unwrap(), ["1A2B3C"]);
    }

    #[test]
    fn the_dts_dict_reserves_the_hole_it_patches() {
        let dict = build_dts_dict(64);
        let s = String::from_utf8(dict).unwrap();
        assert!(s.contains("/Type /DocTimeStamp"));
        assert!(s.contains("/SubFilter /ETSI.RFC3161"));
        // 64 bytes reserved -> 128 hex characters between the brackets
        assert!(s.contains(&format!("<{}>", "0".repeat(128))));
        // /ByteRange must sit ahead of /Contents, the patching invariant
        assert!(s.find("/ByteRange") < s.find("/Contents"));
    }
}
