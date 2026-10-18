//! PAdES-B-B: a detached CAdES inside a PDF signature dictionary, added to the
//! document as an incremental update. The long-term levels (B-LT validation
//! data, B-LTA document time-stamp) are further revisions appended by
//! `crate::ltv` after the signature this module writes exists.
//!
//! The signature covers the file except the value of `/Contents`, which is a
//! chicken and egg problem: the digest has to be computed over bytes that
//! include the offsets of the hole the digest goes into. It is solved the way
//! every implementation solves it, with placeholders of a fixed width so that
//! filling them in cannot move anything.
//!
//! 1. lay out the whole revision with `/ByteRange [0 0000000000 ...]` and
//!    `/Contents <000...>`
//! 2. the offsets are now known, so patch `/ByteRange` in place with numbers of
//!    exactly the same width
//! 3. digest the two ranges, build the CMS, hex encode it, zero pad it to the
//!    reserved width and write it into `/Contents`
//!
//! Step 3 changes nothing outside the hole, so the digest from step 2 stays
//! valid.

use std::collections::BTreeMap;
use std::time::SystemTime;

use openfirma_cades::{CadesOptions, sign as cades_sign};
use openfirma_core::alg::DigestAlg;
use openfirma_core::cert::CertificateHandle;
use openfirma_core::signer::Signer;
use openfirma_core::{Error, Result, oid};

use crate::appearance::{self, Appearance};
use crate::ltv::{self, RevocationBytes};
use crate::pdf::{self, Location, ObjRef};
use crate::update::{Object, Update};

/// Digits reserved for each number of `/ByteRange`. Ten covers files up to
/// 9999999999 bytes, and the width has to be fixed before the layout is known.
pub(crate) const BYTERANGE_WIDTH: usize = 10;

/// How much space to reserve for `/Contents` when the caller does not say.
///
/// The CMS is zero padded to fill it, so this is wasted space in the file, but
/// too small a reservation is a hard failure, and the shapes that need the
/// most room are the ones a signer cannot foresee: a long TSA chain in a B-T
/// token, or a certificate chain with a post-quantum key in it. 27000 is what
/// AutoFirma reserves through iText, so it is what openfirma reserves: a
/// document that fits AutoFirma fits us, and the golden diff sees the same
/// container on both sides. Raise it through [`PadesOptions::contents_reserved`]
/// or `--contents-reserved` for a signature that still does not fit.
pub const DEFAULT_CONTENTS_RESERVED: usize = 27000;

pub struct PadesOptions {
    pub digest: DigestAlg,

    /// Signing time, written to the signature dictionary's `/M`. There is no
    /// `signingTime` attribute in the CMS: `/M` is the only place the time
    /// lives, which is what AutoFirma does and what avoids two answers to one
    /// question.
    pub sign_time: SystemTime,

    /// Name of the AcroForm field. When the document already has a signature
    /// field with that name the signature is written INTO it, into the box the
    /// form drew; the field must be empty (a field that carries a value already
    /// is refused rather than overwritten), and a visible signature is drawn in
    /// the field's own rectangle. When the document has signature fields and no
    /// name is given, the next free `SignatureN` is used instead.
    pub field_name: Option<String>,

    /// Bytes reserved for `/Contents`.
    pub contents_reserved: usize,

    /// Where to draw the signature. `None`, the default, is an invisible
    /// signature, which is what AutoFirma produces when no position is given.
    pub visible: Option<Appearance>,

    /// Optional dictionary entries. AutoFirma leaves all three out unless the
    /// user asks for them, and so do we: their presence is what a validator
    /// uses to decide what was promised about the document.
    pub reason: Option<String>,
    pub location: Option<String>,
    pub contact_info: Option<String>,

    /// B-T: asked for a time-stamp token over the signature value. See
    /// [`openfirma_cades::TimestampFn`]; the transport is the caller's.
    pub timestamp: Option<openfirma_cades::TimestampFn>,

    /// B-LT: certificates to archive in the document's `/DSS` on top of the
    /// signer's own certificate and chain — a co-signer's chain, the TSA's,
    /// cross certificates. Nothing is ever fetched: what is archived is
    /// exactly what the caller hands over here and in
    /// [`PadesOptions::revocation`].
    pub validation_certs: Vec<CertificateHandle>,

    /// B-LT: revocation data to archive in the `/DSS`. For the archive to
    /// serve its purpose this needs at least one datum (a CRL, or an OCSP
    /// response) per CA certificate of the chain, and `openfirma verify`
    /// reports the archive as incomplete without it.
    pub revocation: Vec<RevocationBytes>,

    /// B-LTA: a document time-stamp appended after the validation data, as a
    /// new signature field whose `/Contents` is an RFC 3161 token over
    /// everything before it, the `/DSS` included. Same
    /// [`openfirma_cades::TimestampFn`] mechanism as B-T — the closure is
    /// called with the bytes the token must imprint — and the order is part
    /// of the level: signature, then validation data, then this stamp.
    /// Requires validation data in the same call or already in the document,
    /// because B-LTA is B-LT plus the document time-stamp.
    pub document_timestamp: Option<openfirma_cades::TimestampFn>,

    /// Sign a document certified with `/Perms /DocMDP` `/P 1` ("no changes to
    /// the document are permitted"). Without this, openfirma refuses: the new
    /// revision breaks the certification in every reader that honours it, and
    /// AutoFirma asks for the same explicit permission before doing it (its
    /// `allowSigningCertifiedPdfs` extraParam). With the flag set, the sign
    /// goes ahead and the broken certification is the author's decision, not
    /// ours. See docs/pades.md.
    pub allow_signing_certified: bool,
}

impl Default for PadesOptions {
    fn default() -> Self {
        Self {
            digest: DigestAlg::Sha256,
            sign_time: SystemTime::now(),
            field_name: None,
            contents_reserved: DEFAULT_CONTENTS_RESERVED,
            visible: None,
            reason: None,
            location: None,
            contact_info: None,
            timestamp: None,
            validation_certs: Vec::new(),
            revocation: Vec::new(),
            document_timestamp: None,
            allow_signing_certified: false,
        }
    }
}

/// What `/Perms /DocMDP` of a document permits (finding A-2). ISO 32000-1
/// 12.8.4.3; the certification dictionary sits under `/Reference`, whose value
/// may be one dictionary or an array of them when a document is certified and
/// then co-signed.
#[derive(Clone, Copy, Debug)]
pub struct DocMdp {
    /// The `/P` permission bit of the strictest (`/P 1`) certification found —
    /// ISO calls the whole thing out by the most restrictive entry.
    pub lowest_p: i64,
}

/// Reads `/Perms /DocMDP /Reference /TransformParams /P` from the catalog. A
/// catalog that has no `/Perms`, or one whose shape this cannot read, answers
/// `Ok(None)`: nothing is certified and signing is allowed. A value found and
/// refused to parse is an error — a certification openfirma cannot read is not
/// a licence to overwrite it (AutoFirma likewise fails closed).
pub fn docmdp_of(perms: &[u8]) -> Result<Option<DocMdp>> {
    let perms = pdf::trim_ws(perms);
    if !perms.starts_with(b"<<") {
        return Err(Error::Pdf(
            "the catalog's /Perms is not a dictionary".into(),
        ));
    }
    let Some(docmdp) = pdf::get(perms, "/DocMDP") else {
        return Ok(None);
    };
    let docmdp = pdf::trim_ws(docmdp);
    if !docmdp.starts_with(b"<<") {
        return Err(Error::Pdf(
            "the catalog's /Perms /DocMDP is not a dictionary".to_string(),
        ));
    }
    let Some(reference) = pdf::get(docmdp, "/Reference") else {
        // A certification with no /Reference has no TransformParams and no /P
        // to honour; ISO requires the pair, and AutoFirma treats the bare
        // /DocMDP as a P=1 certification. Fail closed the same way.
        return Ok(Some(DocMdp { lowest_p: 1 }));
    };
    let reference = pdf::trim_ws(reference);
    // one dictionary, or an array of them (certified then co-signed)
    let dicts: Vec<&[u8]> = if reference.starts_with(b"[") {
        let mut out = Vec::new();
        let mut i = 1;
        let end = pdf::trim_ws(reference).len().saturating_sub(1);
        while i < end {
            let j = pdf::skip_ws(reference, i);
            if j >= end || reference[j] == b']' {
                break;
            }
            if !reference[j..].starts_with(b"<<") {
                return Err(Error::Pdf(
                    "a /DocMDP /Reference array holds something that is not a dictionary"
                        .to_string(),
                ));
            }
            let stop = pdf::dict_end(reference, j)?;
            out.push(&reference[j..stop]);
            i = stop;
        }
        out
    } else if reference.starts_with(b"<<") {
        vec![reference]
    } else {
        return Err(Error::Pdf(
            "the /DocMDP /Reference is neither a dictionary nor an array of dictionaries"
                .to_string(),
        ));
    };
    let mut lowest: Option<i64> = None;
    for d in dicts {
        let Some(params) = pdf::get(d, "/TransformParams") else {
            // no TransformParams: nothing declares a permission, and every
            // conforming certification carries one. Fail closed as for an
            // absent /Reference.
            lowest = Some(1);
            continue;
        };
        let params = pdf::trim_ws(params);
        if !params.starts_with(b"<<") {
            return Err(Error::Pdf(
                "a /DocMDP /TransformParams is not a dictionary".to_string(),
            ));
        }
        let p = pdf::get(params, "/P")
            .and_then(|v| {
                std::str::from_utf8(pdf::trim_ws(v))
                    .ok()?
                    .trim()
                    .parse::<i64>()
                    .ok()
            })
            .unwrap_or(1);
        lowest = Some(lowest.map_or(p, |cur: i64| cur.min(p)));
    }
    Ok(lowest.map(|lowest_p| DocMdp { lowest_p }))
}

/// Adds a PAdES-B-B signature to `pdf` and returns the whole signed document.
pub fn sign(pdf: &[u8], signer: &dyn Signer, opts: &PadesOptions) -> Result<Vec<u8>> {
    if !pdf.starts_with(b"%PDF-") {
        return Err(Error::Pdf("the input does not start with %PDF-".into()));
    }

    let xref_at = pdf::last_startxref(pdf)?;
    // The trailer is read FIRST and refused there: C-2's whole point is that
    // an encrypted document must not get as far as being parsed further,
    // because every later step would slice streams that are ciphertext.
    let trailer = pdf::trailer(pdf, xref_at)?;
    let offsets = pdf::object_locations(pdf, xref_at)?;
    // One object-stream decode memo for the whole signing walk (finding A-1):
    // catalog, page tree, AcroForm and fields may all live in compressed
    // streams, and re-inflating one per object is what made reading hostile
    // documents CPU-quadratic.
    let mut cache = pdf::ObjectStreamCache::new();

    let mut catalog = pdf::resolve(pdf, &offsets, Some(&mut cache), trailer.root)?.to_vec();
    if !catalog.starts_with(b"<<") {
        return Err(Error::Pdf("the catalog is not a dictionary".into()));
    }

    let page_ref = match &opts.visible {
        Some(a) => page_at(pdf, &offsets, Some(&mut cache), &catalog, a.page)?,
        None => page_at(pdf, &offsets, Some(&mut cache), &catalog, 1)?,
    };
    let page = pdf::resolve(pdf, &offsets, Some(&mut cache), page_ref)?.to_vec();
    if !page.starts_with(b"<<") {
        return Err(Error::Pdf(format!("page {page_ref} is not a dictionary")));
    }
    // `/Info` may be indirect, and an incremental update must not rewrite it:
    // its old bytes are already covered by earlier revisions' /ByteRanges, so
    // the copy below is what gets spliced into the fresh definition.
    let info = match trailer.info {
        Some(r) => Some(pdf::resolve(pdf, &offsets, Some(&mut cache), r)?.to_vec()),
        None => None,
    };

    // A-2: a document certified with /Perms /DocMDP P=1 forbids every change,
    // this signature included; signing it breaks the certification in each
    // reader that honours it. AutoFirma asks for the same permission (its
    // allowSigningCertifiedPdfs) before touching one. /Perms may be indirect.
    if let Some(perms_value) = pdf::get(&catalog, "/Perms") {
        let perms_owned;
        let perms = match pdf::parse_ref(perms_value) {
            Some(r) => {
                perms_owned = pdf::resolve(pdf, &offsets, Some(&mut cache), r)?.into_owned();
                &perms_owned[..]
            }
            None => pdf::trim_ws(perms_value),
        };
        if let Some(mdp) = docmdp_of(perms)? {
            if mdp.lowest_p <= 1 && !opts.allow_signing_certified {
                return Err(Error::Pdf(format!(
                    "this document is certified with /Perms /DocMDP /P {} (no changes are \
                     permitted), and signing it would break that certification in every \
                     reader that honours it. If the author's rule must be overridden, pass \
                     allow_signing_certified (--allow-certified on the command line).",
                    mdp.lowest_p
                )));
            }
        }
    }

    // M-2: a PDF/A document (ISO 19005-1) requires xmp:ModifyDate in the
    // /Metadata XMP packet to equal /Info /ModDate, and openfirma does not
    // rewrite the XMP stream — AutoFirma likewise changes behaviour for PDF/A
    // sources. The simplest conforming choice (docs/pades.md): when a PDF/A
    // identity declaration exists, write no new /ModDate at all and leave the
    // /Info object exactly where it is — its bytes are already covered by the
    // earlier revisions' /ByteRanges. Detecting on the declaration rather than
    // trusting every /Metadata keeps every ordinary document (a plain XMP
    // stream, an OpenMetadata package) stamping dates as before.
    let metadata_ref = pdf::get(&catalog, "/Metadata").and_then(pdf::parse_ref);
    let pdfa = match metadata_ref {
        Some(m) => {
            let dict = pdf::resolve(pdf, &offsets, Some(&mut cache), m)?;
            // The key spells itself pdfaid:part in ISO 32000-2 and every
            // PDF/A packet; compared case-insensitively without its leading
            // slash because namespace prefixes are the XMP's business.
            pdf::items(&dict)
                .map(|items| {
                    items.iter().any(|(k, _)| {
                        let key = &dict[k.clone()];
                        key.len() > 1
                            && String::from_utf8_lossy(&key[1..]).to_ascii_lowercase()
                                == "pdfaid:part"
                    })
                })
                .unwrap_or(false)
        }
        None => false,
    };

    // A-1: the new trailer is a copy of the previous one — /ID included, which
    // ISO 32000-1 7.5.6 requires carried over and PDF/A and PDF 2.0 demand —
    // with this revision's /Size, /Root, /Info and /Prev written on top by
    // render().
    let previous_trailer = pdf::trailer_dict(pdf, xref_at)?;

    let (root, _, size) = trailer.mandatory()?;
    // Existing objects are rewritten under their own number and new ones start
    // here. B-1: /Size alone is not enough — a lying trailer whose /Size sits
    // below the real numbers would make every new object overwrite an existing
    // one (pages, fonts), so the highest number the cross-reference knows
    // bounds it too.
    let first_new = size.max(
        offsets
            .keys()
            .map(|r| r.num)
            .max()
            .map(|m| m.saturating_add(1))
            .unwrap_or(0),
    );
    // M-1: when the original has no /Info, this is the object number the fresh
    // dictionary gets and the trailer references — the old code wrote the
    // dictionary and left it orphaned. The numbering block below allocates from
    // first_new up to first_new + 5 (the five signature objects, plus the
    // catalog when an inline /AcroForm or a usage-rights rewrite forces it to
    // be written), so first_new + 6 is the number this revision really writes
    // — never one another object already took.
    let info_ref = trailer.info_for_revision(ObjRef::new(first_new + 6, 0));
    let mut update =
        Update::new_with_trailer(xref_at, root, Some(info_ref), size, &previous_trailer)?;
    let appearance = ObjRef::new(first_new, 0);
    let helv = ObjRef::new(first_new + 1, 0);
    let zadb = ObjRef::new(first_new + 2, 0);
    let sig = ObjRef::new(first_new + 3, 0);
    let field = ObjRef::new(first_new + 4, 0);

    // M-4: AutoFirma removes usage rights (pdfReader.removeUsageRights) before
    // signing: Adobe flags a signed document that still carries /Perms /UR3,
    // because the usage rights were granted to a state of the document this
    // new revision no longer is. The rest of /Perms (/DocMDP above, an older
    // /SigStamp) survives byte for byte — pdf::set replaces one key and touches
    // nothing else — and only when there is a /Perms to rewrite at all (the
    // catalog keeps its number, so an untouched catalog stays untouched).
    if let Some(perms_value) = pdf::get(&catalog, "/Perms") {
        let perms_ref = pdf::parse_ref(perms_value);
        let perms_owned = match perms_ref {
            Some(r) => pdf::resolve(pdf, &offsets, Some(&mut cache), r)?.into_owned(),
            None => pdf::trim_ws(perms_value).to_vec(),
        };
        if pdf::get(&perms_owned, "/UR3").is_some() || pdf::get(&perms_owned, "/UR").is_some() {
            let stripped = pdf::set(&pdf::set(&perms_owned, "/UR3", b"null")?, "/UR", b"null")?;
            match perms_ref {
                Some(r) => update.push(Object::new(r, stripped)),
                None => catalog = pdf::set(&catalog, "/Perms", &stripped)?,
            }
        }
    }

    let existing = existing_signature_fields(pdf, &offsets, Some(&mut cache), &catalog);
    let field_name = opts
        .field_name
        .clone()
        .unwrap_or_else(|| next_field_name(&existing.names));
    let acroform = acroform_of(pdf, &offsets, Some(&mut cache), &catalog)?;

    // A caller who NAMES a field the form already offers signs IN it. That is
    // what an empty signature field is for, and it is the flow the reference
    // tool has (its GUI asks which field to use, and its API takes
    // `signatureField`). The field is written back under its own number,
    // gaining the value — and, for a visible signature, the appearance — it was
    // waiting for, while its rectangle, its name and its page stay the bytes the
    // form had. Measured against AutoFirma 1.9.1: signing a two-field form twice
    // leaves the first field alone and fills the second by adding `/V` and `/AP`
    // to it. The revisions gate that guards our own output licenses exactly that
    // shape: a field whose covered bytes carried no `/V` may gain `/V` and `/AP`.
    //
    // Two shapes this refuses rather than guessing: a field that already
    // carries a value (filling it would replace the signature a reader shows
    // there) and a parent field with `/Kids` (the value goes on the parent and
    // the appearance on a widget child; openfirma signs a field whose own
    // dictionary is its widget, which is what a form that renders one carries).
    let target = opts.field_name.as_ref().and_then(|want| {
        existing
            .named
            .iter()
            .find(|(name, _)| name == want)
            .cloned()
    });
    let filling = match &target {
        None => None,
        Some((name, r)) => {
            let body = pdf::resolve(pdf, &offsets, Some(&mut cache), *r)?.into_owned();
            if pdf::get(&body, "/V").is_some() {
                return Err(Error::Pdf(format!(
                    "field {name:?} already carries a signature value: filling it would \
                     replace the signature a reader shows there"
                )));
            }
            if pdf::get(&body, "/Kids").is_some() {
                return Err(Error::Pdf(format!(
                    "field {name:?} is the parent of widget annotations (/Kids): openfirma \
                     signs a field whose own dictionary is its widget"
                )));
            }
            let rect = pdf::get(&body, "/Rect").and_then(rect_numbers);
            Some((*r, body, rect))
        }
    };

    let sig_dict = build_sig_dict(signer, opts)?;

    // Even an invisible signature needs an appearance entry, viewers look for
    // it, and a blank form XObject is how you say "draw nothing". A fill is the
    // exception: the field already has whatever appearance the form gave it,
    // and an invisible fill leaves that alone.
    let (rect, appearance_body) = match (&opts.visible, &filling) {
        (Some(a), None) => {
            appearance::check_rect(a.rect)?;
            let [llx, lly, urx, ury] = a.rect;
            let lines = appearance_lines(signer, opts);
            let rect = format!(
                "[{} {} {} {}]",
                appearance::num(llx),
                appearance::num(lly),
                appearance::num(urx),
                appearance::num(ury)
            );
            (
                rect,
                appearance::form_xobject(urx - llx, ury - lly, &lines, helv)?,
            )
        }
        // A visible fill draws in the FIELD's rectangle: that is the box the
        // form fixed and the one a reader maps the appearance onto, so the
        // caller's own rectangle plays no part.
        (Some(_), Some((_, _, Some([llx, lly, urx, ury])))) if urx > llx && ury > lly => {
            let lines = appearance_lines(signer, opts);
            (
                String::new(),
                appearance::form_xobject(urx - llx, ury - lly, &lines, helv)?,
            )
        }
        (_, Some(_)) => (String::new(), appearance::blank()),
        (None, None) => ("[0 0 0 0]".to_string(), appearance::blank()),
    };
    // An invisible fill draws nothing and needs no font of ours: the field
    // keeps the appearance the form gave it, and the objects that would only
    // say "blank" stay out of the revision.
    if filling.is_none() || opts.visible.is_some() {
        update.push(Object::new(appearance, appearance_body));
        update.push(Object::new(
            helv,
            // two of the standard 14 fonts, referenced and not embedded, which is
            // what iText puts in /DR for the field's default appearance
            "<< /BaseFont /Helvetica /Encoding /WinAnsiEncoding /Name /Helv \
             /Subtype /Type1 /Type /Font >>",
        ));
        update.push(Object::new(
            zadb,
            "<< /BaseFont /ZapfDingbats /Name /ZaDb /Subtype /Type1 /Type /Font >>",
        ));
    }
    update.push(Object::new(sig, sig_dict));
    match &filling {
        // The field the form had, back under its own number with the value it
        // was waiting for — and the appearance, when there is one to draw.
        Some((field_ref, body, _)) => {
            let mut filled = pdf::set(body, "/V", sig.to_string().as_bytes())?;
            if opts.visible.is_some() {
                filled = pdf::set(&filled, "/AP", format!("<< /N {appearance} >>").as_bytes())?;
            }
            update.push(Object::new(*field_ref, filled));
        }
        None => update.push(Object::new(
            field,
            build_field(field_name, appearance, page_ref, sig, &rect),
        )),
    }

    // The catalog and the page keep their numbers, so every reference to them
    // from the older revisions now resolves to these new definitions and the
    // page tree does not have to be rewritten at all.
    //
    // An /AcroForm that already exists is *spliced*, not rebuilt: /Fields
    // gains our field and /SigFlags is added when absent, and every other
    // byte of the dictionary survives — /NeedAppearances, /XFA (which the
    // forms the Spanish administration publishes carry), the author's own
    // /DR. Rebuilding it from the keys we know is exactly the silent
    // document alteration docs/adr/0003 exists to prevent. An indirect
    // /AcroForm stays indirect: only the object that changes is rewritten,
    // and the catalog is left alone entirely.
    match acroform {
        Some((acro_ref, acro_bytes)) => {
            // A fill does not grow /Fields: the field that is being signed is
            // in the form already. The dictionary is rewritten only if
            // /SigFlags was missing, and otherwise nothing about the form moves.
            let new_acro = if filling.is_some() {
                match pdf::get(&acro_bytes, "/SigFlags") {
                    Some(_) => None,
                    None => Some(pdf::set(&acro_bytes, "/SigFlags", b"3")?),
                }
            } else {
                let mut written = match pdf::get(&acro_bytes, "/Fields") {
                    Some(v) => pdf::set(&acro_bytes, "/Fields", &merged_fields(v, field)?)?,
                    None => pdf::set(&acro_bytes, "/Fields", format!("[{field}]").as_bytes())?,
                };
                if pdf::get(&written, "/SigFlags").is_none() {
                    written = pdf::set(&written, "/SigFlags", b"3")?;
                }
                Some(written)
            };
            if let Some(new_acro) = new_acro {
                match acro_ref {
                    Some(r) => update.push(Object::new(r, new_acro)),
                    None => update.push(Object::new(
                        trailer.root,
                        pdf::set(&catalog, "/AcroForm", &new_acro)?,
                    )),
                }
            }
        }
        None => {
            // no form at all: write the dictionary iText writes, which is
            // what the golden diff measures
            let mut fields = existing.refs;
            if !fields.contains(&field) {
                fields.push(field);
            }
            let form = build_acroform(&fields, helv, zadb);
            update.push(Object::new(
                trailer.root,
                pdf::set(&catalog, "/AcroForm", form.as_bytes())?,
            ));
        }
    }
    // A field the form already renders is in the page's /Annots already: it is
    // the widget annotation there, and a fill adds no second entry.
    if filling.is_none() {
        match merged_annots(pdf, &offsets, Some(&mut cache), &page, field)? {
            MergedAnnots::Inline(array) => {
                update.push(Object::new(page_ref, pdf::set(&page, "/Annots", &array)?))
            }
            // the page keeps pointing at "N G R"; only the array object it names
            // is rewritten, in the new revision, where the old one stays exactly
            // where the earlier /ByteRanges say it is
            MergedAnnots::Indirect(r, array) => update.push(Object::new(r, array)),
        }
    }

    // Recording that the document changed is what /ModDate is for — except
    // under PDF/A (M-2, see above), where the XMP copy of the date would be
    // left behind: no /Info dictionary is written at all then, and the trailer
    // keeps naming the one the original had. With M-1 fixed the alternative —
    // rewrite /Info without a new date — cannot be used for the case that
    // needs it most: a document with no /Info at all gets its first dictionary
    // in this revision, and an empty one would only add an orphan-looking key.
    let fresh_info = !pdfa;
    if fresh_info {
        let date = pdf_string(&pdf_date(opts.sign_time)?);
        let info_dict = match info {
            Some(old) if old.starts_with(b"<<") => pdf::set(&old, "/ModDate", &date)?,
            _ => {
                let mut d = Vec::from(&b"<< /ModDate "[..]);
                d.extend_from_slice(&date);
                d.extend_from_slice(b" >>");
                d
            }
        };
        update.push(Object::new(info_ref, info_dict));
    } else if trailer.info.is_none() {
        // A PDF/A document with no /Info: there is nothing to keep in sync, so
        // stamping a fresh dictionary would be the only date the XMP does not
        // carry. The trailer carries no /Info, which is exactly what the
        // original said.
        update.clear_info();
    }

    let rendered = update.render(pdf.len())?;
    let sig_at = rendered.offsets[&sig];
    let mut out = Vec::with_capacity(pdf.len() + rendered.bytes.len());
    out.extend_from_slice(pdf);
    out.extend_from_slice(&rendered.bytes);

    finish(&mut out, sig_at, signer, opts)?;

    // B-LT and B-LTA are further revisions on top of the signature, and the
    // order is part of the specification (ETSI EN 319 142-1): the signature
    // exists first, then the validation data that lets it be checked years
    // from now, then a document time-stamp over both. Each step is its own
    // incremental update, so the revision boundaries line up with the levels.
    if !opts.validation_certs.is_empty() || !opts.revocation.is_empty() {
        let mut certs = vec![signer.certificate().clone()];
        certs.extend_from_slice(signer.chain());
        certs.extend_from_slice(&opts.validation_certs);
        out = ltv::add_validation_data(&out, &certs, &opts.revocation)?;
    }
    if let Some(stamp) = &opts.document_timestamp {
        // add_document_timestamp refuses a document without /DSS, which is
        // the B-LTA rule: the archive stamp goes over validation data.
        out = ltv::add_document_timestamp(&out, stamp, opts.digest, opts.contents_reserved)?;
    }
    Ok(out)
}

/// The signature dictionary, with both placeholders still in it.
///
/// Keys go in alphabetical order, which is what iText writes and, more to the
/// point, what keeps `/ByteRange` ahead of `/Contents` in the file so that
/// patching the ranges cannot disturb the hole they describe.
fn build_sig_dict(signer: &dyn Signer, opts: &PadesOptions) -> Result<Vec<u8>> {
    let mut d = Vec::new();
    d.extend_from_slice(
        format!(
            "<< /ByteRange [0 {z} {z} {z}] /Contents <{zeros}> /Filter /Adobe.PPKLite",
            z = " ".repeat(BYTERANGE_WIDTH),
            zeros = "0".repeat(opts.contents_reserved * 2),
        )
        .as_bytes(),
    );
    push_entry(
        &mut d,
        "/M",
        pdf_string(&pdf_date(opts.sign_time)?).as_slice(),
    );
    if let Some(cn) = signer.certificate().subject_cn() {
        push_entry(&mut d, "/Name", pdf_string(&cn).as_slice());
    }
    if let Some(reason) = &opts.reason {
        push_entry(&mut d, "/Reason", pdf_string(reason).as_slice());
    }
    if let Some(location) = &opts.location {
        push_entry(&mut d, "/Location", pdf_string(location).as_slice());
    }
    if let Some(contact) = &opts.contact_info {
        push_entry(&mut d, "/ContactInfo", pdf_string(contact).as_slice());
    }
    d.extend_from_slice(b" /SubFilter /ETSI.CAdES.detached /Type /Sig >>");
    Ok(d)
}

fn push_entry(out: &mut Vec<u8>, key: &str, value: &[u8]) {
    out.extend_from_slice(format!(" {key} ").as_bytes());
    out.extend_from_slice(value);
}

fn build_acroform(fields: &[ObjRef], helv: ObjRef, zadb: ObjRef) -> String {
    let list: Vec<String> = fields.iter().map(|r| r.to_string()).collect();
    format!(
        "<< /DA (/Helv 0 Tf 0 g ) /DR << /Font << /Helv {helv} /ZaDb {zadb} >> >> \
         /Fields [{}] /SigFlags 3 >>",
        list.join(" ")
    )
}

/// The four numbers of a `/Rect`, which a fill needs to size its appearance to
/// the box the form fixed. Anything else about the value — a wrong count, a
/// token that is not a number — reads as "no usable rectangle", and the fill
/// then draws nothing rather than guessing.
fn rect_numbers(value: &[u8]) -> Option<[f64; 4]> {
    let inner = pdf::trim_ws(value).strip_prefix(b"[")?.strip_suffix(b"]")?;
    let mut out = [0f64; 4];
    let mut seen = 0;
    for token in inner.split(|b: &u8| b.is_ascii_whitespace()) {
        if token.is_empty() {
            continue;
        }
        if seen == 4 {
            return None;
        }
        out[seen] = std::str::from_utf8(token).ok()?.parse().ok()?;
        seen += 1;
    }
    (seen == 4).then_some(out)
}

/// `/F 132` is `Print | Locked`, `/Rect [0 0 0 0]` with a blank appearance is
/// an invisible signature, which is what AutoFirma writes when no position is
/// given.
pub(crate) fn build_field(
    name: String,
    appearance: ObjRef,
    page: ObjRef,
    sig: ObjRef,
    rect: &str,
) -> Vec<u8> {
    let mut d = Vec::new();
    d.extend_from_slice(
        format!(
            "<< /AP << /N {appearance} >> /DR << >> /F 132 /FT /Sig /P {page} \
         /Rect {rect} /Subtype /Widget /T "
        )
        .as_bytes(),
    );
    d.extend_from_slice(&pdf_string(&name));
    d.extend_from_slice(format!(" /Type /Annot /V {sig} >>").as_bytes());
    d
}

/// Where a page's `/Annots` ends up after our field is added: spliced into
/// the page dictionary itself, or written back under the number of the
/// indirect object it already was — the shape iText writes, and the shape the
/// page keeps pointing at. Turning an indirect array into an inline one would
/// work for readers but rewrite the page for no reason; keeping the reference
/// is the byte preservation of docs/adr/0003 at annotation level.
pub(crate) enum MergedAnnots {
    Inline(Vec<u8>),
    Indirect(ObjRef, Vec<u8>),
}

/// The page's `/Annots` with our field added, keeping the ones already there.
pub(crate) fn merged_annots(
    pdf: &[u8],
    offsets: &BTreeMap<ObjRef, Location>,
    cache: Option<&mut pdf::ObjectStreamCache>,
    page: &[u8],
    field: ObjRef,
) -> Result<MergedAnnots> {
    let Some(existing) = pdf::get(page, "/Annots") else {
        return Ok(MergedAnnots::Inline(format!("[{field}]").into_bytes()));
    };
    if let Some(r) = pdf::parse_ref(existing) {
        let resolved = pdf::resolve(pdf, offsets, cache, r)?;
        let array = pdf::trim_ws(&resolved);
        if !array.starts_with(b"[") || !array.ends_with(b"]") {
            return Err(Error::Pdf(format!(
                "object {r}, the page's indirect /Annots, is not an array"
            )));
        }
        return Ok(MergedAnnots::Indirect(r, append_to_array(array, field)?));
    }
    let array = pdf::trim_ws(existing);
    if !array.ends_with(b"]") {
        return Err(Error::Pdf("the page /Annots is not an array".into()));
    }
    Ok(MergedAnnots::Inline(append_to_array(array, field)?))
}

/// An array value with one more reference before the closing bracket,
/// keeping the author's bytes for everything already in it.
fn append_to_array(array: &[u8], field: ObjRef) -> Result<Vec<u8>> {
    let mut v = array.to_vec();
    v.pop(); // the ']'
    v.extend_from_slice(format!(" {field}]").as_bytes());
    Ok(v)
}

/// An existing `/AcroForm /Fields` with our field appended and duplicates
/// out. When the array holds neither a duplicate nor our field — the case
/// every real document is in — the author's bytes are kept and the reference
/// is inserted before the bracket. A rebuild from the parsed references only
/// happens for an array that lists the same field twice, because that cannot
/// be fixed by appending; it drops inline field dictionaries, which an array
/// with duplicate references is not a document to be careful with anyway.
pub(crate) fn merged_fields(existing: &[u8], field: ObjRef) -> Result<Vec<u8>> {
    let array = pdf::trim_ws(existing);
    if !array.starts_with(b"[") || !array.ends_with(b"]") {
        return Err(Error::Pdf("the /AcroForm /Fields is not an array".into()));
    }
    let refs = pdf::array_refs(array)?;
    let duplicated = refs.iter().enumerate().any(|(i, r)| refs[..i].contains(r));
    if !duplicated && !refs.contains(&field) {
        return append_to_array(array, field);
    }
    let mut out: Vec<ObjRef> = Vec::with_capacity(refs.len() + 1);
    for r in refs.into_iter().chain(std::iter::once(field)) {
        if !out.contains(&r) {
            out.push(r);
        }
    }
    let list: Vec<String> = out.iter().map(|r| r.to_string()).collect();
    Ok(format!("[{}]", list.join(" ")).into_bytes())
}

/// Patches `/ByteRange`, then signs the two ranges it describes and fills
/// `/Contents`. `sig_at` is the absolute offset of the signature dictionary
/// object in `out`.
fn finish(out: &mut [u8], sig_at: usize, signer: &dyn Signer, opts: &PadesOptions) -> Result<()> {
    fill_hole(out, sig_at, "CMS", &|covered| {
        cades_sign(covered, signer, &cades_options(opts))
    })
}

/// The placeholder mechanism both `/Contents` holes share, the signature's
/// and the document time-stamp's: patch `/ByteRange` with numbers of exactly
/// the reserved width, digest the two ranges, and fill the hole with the hex
/// of whatever `produce` makes from those bytes, zero padded.
///
/// `what` names the value in error messages ("CMS", "time-stamp token").
pub(crate) fn fill_hole(
    out: &mut [u8],
    dict_at: usize,
    what: &str,
    produce: &dyn Fn(&[u8]) -> Result<Vec<u8>>,
) -> Result<()> {
    let body = pdf::object_body(out, dict_at)?;
    let dict = &out[body.clone()];

    let contents_rel = pdf::get_span(dict, "/Contents")
        .ok_or_else(|| Error::Pdf("the signature dictionary lost its /Contents".into()))?;
    let contents_start = body.start + contents_rel.start;
    let contents_end = body.start + contents_rel.end;
    let total = out.len();
    if contents_end > total {
        return Err(Error::Pdf("/Contents runs past the end of the file".into()));
    }
    if out[contents_start] != b'<' || out[contents_end - 1] != b'>' {
        return Err(Error::Pdf(format!(
            "the /Contents placeholder at {contents_start}..{contents_end} is not a hex \
             string, so the ranges to sign cannot be located"
        )));
    }

    // step 2: the offsets are known, and writing them must not move anything
    let br_rel = pdf::get_span(dict, "/ByteRange")
        .ok_or_else(|| Error::Pdf("the signature dictionary lost its /ByteRange".into()))?;
    let br_start = body.start + br_rel.start;
    let br_end = body.start + br_rel.end;
    let replacement = format!(
        "[0 {:>w$} {:>w$} {:>w$}]",
        contents_start,
        contents_end,
        total - contents_end,
        w = BYTERANGE_WIDTH
    );
    if replacement.len() != br_end - br_start {
        return Err(Error::Pdf(format!(
            "the /ByteRange placeholder is {} bytes but the real value needs {}, which \
             would move every offset after it",
            br_end - br_start,
            replacement.len()
        )));
    }
    out[br_start..br_end].copy_from_slice(replacement.as_bytes());

    // step 3: digest the two ranges, which is the whole file minus the hole
    let mut covered = Vec::with_capacity(contents_start + total - contents_end);
    covered.extend_from_slice(&out[..contents_start]);
    covered.extend_from_slice(&out[contents_end..]);

    let value_der = produce(&covered)?;

    let hex_len = contents_end - contents_start - 2;
    if value_der.len() * 2 > hex_len {
        return Err(Error::Pdf(format!(
            "the {what} needs {} bytes but /Contents only reserves {}; raise the reserved \
             size (PadesOptions::contents_reserved)",
            value_der.len(),
            hex_len / 2
        )));
    }
    // lower case hex, zero padded to the reserved width, which is what iText
    // writes and what readers expect: the DER is parsed and the padding ignored
    let mut value = hex::encode(&value_der).into_bytes();
    value.resize(hex_len, b'0');
    out[contents_start + 1..contents_end - 1].copy_from_slice(&value);
    Ok(())
}

/// Detached CAdES-B-B, which is what PAdES-B-B is: no encapsulated content, no
/// `signingTime` and no `contentHint`. See docs/pades.md for the measurement
/// that established this against AutoFirma's own output.
fn cades_options(opts: &PadesOptions) -> CadesOptions {
    CadesOptions {
        digest: opts.digest,
        content_type: oid::ID_DATA,
        encapsulate_content: false,
        signing_time: None,
        mime_type: None,
        content_hint: None,
        signature_policy: None,
        signature_policy_hash: Vec::new(),
        commitment_type: None,
        // PAdES follows the same conservative rule as plain CAdES signing.
        algorithms: openfirma_cades::verify::AlgorithmPolicy::default(),
        include_certificate_policies: false,
        signing_certificate_v2: true,
        include_issuer_serial: true,
        extra_certificates: Vec::new(),
        unsigned_attributes: Vec::new(),
        timestamp: opts.timestamp.clone(),
    }
}

/// The `index`th page of the document, counting from 1.
pub(crate) fn page_at(
    pdf: &[u8],
    offsets: &BTreeMap<ObjRef, Location>,
    mut cache: Option<&mut pdf::ObjectStreamCache>,
    catalog: &[u8],
    index: usize,
) -> Result<ObjRef> {
    if index == 0 {
        return Err(Error::Pdf(
            "pages are counted from 1, there is no page 0".into(),
        ));
    }
    // M-5: the walk stops at the requested page — a visible signature on page
    // 1 of a million-page book must not enumerate a million references first —
    // and it remembers what it has seen, so a /Kids list that names the same
    // node twice cannot replay its whole subtree. The root's declared /Count
    // bounds the leaves an honest tree can hold; MAX_PAGES_WALKED bounds the
    // lie.
    let pages_ref = pdf::parse_ref(
        pdf::get(catalog, "/Pages")
            .ok_or_else(|| Error::Pdf("the catalog has no /Pages".into()))?,
    )
    .ok_or_else(|| Error::Pdf("/Pages is not an indirect reference".into()))?;
    let declared = {
        let body = pdf::resolve(pdf, offsets, cache.as_deref_mut(), pages_ref)?;
        pdf::get(&body, "/Count")
            .and_then(|v| std::str::from_utf8(pdf::trim_ws(v)).ok())
            .and_then(|s| s.trim().parse::<usize>().ok())
    };
    let limit = declared.map_or(MAX_PAGES_WALKED, |c| c.min(MAX_PAGES_WALKED));
    let mut walker = PageWalker::new(pdf, offsets, cache);
    let pages = walker.collect(pages_ref, index, limit)?;
    pages.get(index - 1).copied().ok_or_else(|| {
        // a truncated walk (it stopped at `index` leaves) can only miss when
        // the tree holds fewer leaves than asked, and then /Count is the
        // number of pages a viewer shows
        let shown = declared.unwrap_or(pages.len());
        Error::Pdf(format!(
            "the document has {shown} pages, so it has no page {index}"
        ))
    })
}

/// How many page leaves one walk may collect before the tree is refused. A
/// PDF object number space ends at u32::MAX and every leaf must be reachable
/// through a `/Kids` entry the file contains (at least three bytes each), so
/// this bounds memory by something a real document of readable size never
/// approaches while refusing the exponential-blowup shape outright.
const MAX_PAGES_WALKED: usize = 1 << 20;

/// The page-tree walk, with its visited set and its budget (finding M-5).
struct PageWalker<'a> {
    pdf: &'a [u8],
    offsets: &'a BTreeMap<ObjRef, Location>,
    cache: Option<&'a mut pdf::ObjectStreamCache>,
    visited: std::collections::HashSet<ObjRef>,
}

impl<'a> PageWalker<'a> {
    fn new(
        pdf: &'a [u8],
        offsets: &'a BTreeMap<ObjRef, Location>,
        cache: Option<&'a mut pdf::ObjectStreamCache>,
    ) -> Self {
        Self {
            pdf,
            offsets,
            cache,
            visited: std::collections::HashSet::new(),
        }
    }

    /// Leaves in document order, at most `stop` of them. A node already
    /// visited — `/Kids [N 0 R N 0 R]` listing the same child twice, a cycle
    /// dressed as a tree — is refused: iText's PageRefs marks nodes for
    /// exactly this reason, and replaying a repeated node is what turned a few
    /// KB of PDF into 2^depth references. `limit` bounds leaves by the root's
    /// declared `/Count` (capped at [`MAX_PAGES_WALKED`]).
    fn collect(&mut self, root: ObjRef, stop: usize, limit: usize) -> Result<Vec<ObjRef>> {
        let mut out = Vec::new();
        self.walk(root, &mut out, stop.min(limit), 0)?;
        Ok(out)
    }

    fn walk(&mut self, node: ObjRef, out: &mut Vec<ObjRef>, stop: usize, depth: u32) -> Result<()> {
        if out.len() >= stop {
            return Ok(());
        }
        if depth > 64 {
            return Err(Error::Pdf(
                "the page tree is deeper than 64 levels, /Kids is probably a loop".into(),
            ));
        }
        if !self.visited.insert(node) {
            return Err(Error::Pdf(format!(
                "the page tree reaches node {node} twice: /Kids repeats a child, and openfirma \
                 refuses to replay it — the pages a viewer shows cannot be derived from a tree \
                 that lists its own nodes more than once"
            )));
        }
        let body = pdf::resolve(self.pdf, self.offsets, self.cache.as_deref_mut(), node)?;
        let typed = pdf::get(&body, "/Type").map(|t| pdf::trim_ws(t) == b"/Page");
        if typed == Some(true) || (pdf::get(&body, "/MediaBox").is_some() && typed.is_none()) {
            out.push(node);
            return Ok(());
        }
        let Some(kids) = pdf::get(&body, "/Kids") else {
            return Err(Error::Pdf(format!(
                "node {node} is neither a page nor has /Kids"
            )));
        };
        for kid in pdf::array_refs(kids)? {
            // checked before descending: stopping only after the subtree was
            // walked would still materialise 2^depth visits for a doubled
            // /Kids tree even when page 1 is wanted
            if out.len() >= stop {
                return Ok(());
            }
            self.walk(kid, out, stop, depth + 1)?;
        }
        Ok(())
    }
}

/// The lines the visible appearance draws: an optional label, who signed, and
/// when.
fn appearance_lines(signer: &dyn Signer, opts: &PadesOptions) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    if let Some(label) = &opts.visible.as_ref().and_then(|a| a.label.clone()) {
        lines.push(label.clone());
    }
    if let Some(cn) = signer.certificate().subject_cn() {
        lines.push(cn);
    }
    if let Ok(date) = readable_date(opts.sign_time) {
        lines.push(date);
    }
    lines
}

/// `2026-10-15 13:36:00 UTC`, for drawing. The `/M` entry keeps the PDF form
/// `D:20261015133600Z`, which is what a validator reads and what nobody wants
/// to look at.
fn readable_date(t: SystemTime) -> Result<String> {
    let secs = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|e| Error::Pdf(format!("the signing time is before 1970: {e}")))?
        .as_secs() as i64;
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    let rem = secs.rem_euclid(86_400);
    Ok(format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    ))
}

/// The signature fields already in the document, so that a second signature is
/// added to `/Fields` instead of replacing the first one — and so that a caller
/// who NAMES a field the form already offers signs in it (`named`), which is
/// what the field is there for.
pub(crate) struct ExistingFields {
    pub refs: Vec<ObjRef>,
    pub names: Vec<String>,
    /// Name to object, in `/Fields` order, for the fields that carry a `/T`.
    pub named: Vec<(String, ObjRef)>,
}

/// The document's `/AcroForm` dictionary: its bytes, and the object it lives
/// under when it is an indirect object, which is how iText writes it. Both
/// halves matter to the caller: the bytes get spliced, and the number says
/// which object the splice has to be written back as.
/// The document's `/AcroForm` dictionary: its bytes, and the object it lives
/// under when it is an indirect object, which is how iText writes it. Both
/// halves matter to the caller: the bytes get spliced, and the number says
/// which object the splice has to be written back as. `Ok(None)` means the
/// document has no form at all, which lets the caller write a fresh one.
///
/// An indirect `/AcroForm` whose object cannot be resolved is an **error**,
/// not a `None` (finding B-5): `None` reads as "no AcroForm" and every caller
/// then replaces the catalog's whole `/AcroForm` — silently dropping `/XFA`
/// and everything else a damaged but real form held, which is precisely the
/// silent document alteration docs/adr/0003 forbids. Only a catalog without
/// the key at all may produce `None`.
pub(crate) fn acroform_of(
    pdf: &[u8],
    offsets: &BTreeMap<ObjRef, Location>,
    cache: Option<&mut pdf::ObjectStreamCache>,
    catalog: &[u8],
) -> Result<Option<(Option<ObjRef>, Vec<u8>)>> {
    let value = match pdf::get(catalog, "/AcroForm") {
        Some(v) => v,
        None => return Ok(None),
    };
    match pdf::parse_ref(value) {
        // an indirect /AcroForm may live in an object stream, so the bytes
        // are always owned here
        Some(r) => pdf::resolve(pdf, offsets, cache, r)
            .map(|b| Some((Some(r), b.into_owned())))
            .map_err(|e| {
                Error::Pdf(format!(
                    "the document's /AcroForm points at object {r}, which does not resolve \
                     ({e}); signing anyway would replace the whole form dictionary and lose \
                     what it held, so this is refused instead of guessed around"
                ))
            }),
        None => Ok(Some((None, pdf::trim_ws(value).to_vec()))),
    }
}

pub(crate) fn existing_signature_fields(
    pdf: &[u8],
    offsets: &BTreeMap<ObjRef, Location>,
    mut cache: Option<&mut pdf::ObjectStreamCache>,
    catalog: &[u8],
) -> ExistingFields {
    let empty = ExistingFields {
        refs: Vec::new(),
        names: Vec::new(),
        named: Vec::new(),
    };
    // A dangling indirect /AcroForm is refused by `acroform_of` itself (B-5);
    // here only the "no form at all" reading may fall through to an empty
    // list, and it always has.
    let Ok(Some((_, acro))) = acroform_of(pdf, offsets, cache.as_deref_mut(), catalog) else {
        return empty;
    };
    let Some(fields_bytes) = pdf::get(&acro, "/Fields") else {
        return empty;
    };
    let Ok(refs) = pdf::array_refs(fields_bytes) else {
        return empty;
    };
    let mut names = Vec::new();
    let mut named = Vec::new();
    for r in &refs {
        if let Ok(f) = pdf::resolve(pdf, offsets, cache.as_deref_mut(), *r) {
            if let Some(t) = pdf::get(&f, "/T") {
                let name = unquote(t);
                named.push((name.clone(), *r));
                names.push(name);
            }
        }
    }
    ExistingFields { refs, names, named }
}

fn next_field_name(taken: &[String]) -> String {
    next_name("Signature", taken)
}

/// The first free `<prefix>1`, `<prefix>2`, ... among the taken names. The
/// document time-stamp field is named `TimestampN` this way, so a co-signing
/// tool and a time-stamping tool do not fight over `SignatureN`.
pub(crate) fn next_name(prefix: &str, taken: &[String]) -> String {
    (1..)
        .map(|n| format!("{prefix}{n}"))
        .find(|candidate| !taken.contains(candidate))
        .unwrap_or_else(|| format!("{prefix}1"))
}

/// Renders `text` as a PDF literal string.
///
/// Characters that PDFDocEncoding can express go out as single bytes, which is
/// what covers accented Spanish names and matches what iText writes. Anything
/// beyond that needs UTF-16BE behind a byte order mark, as ISO 32000 7.9.2
/// prescribes. Escaping is byte level in both cases: the parentheses and
/// backslashes that terminate a literal string are the bytes 0x28, 0x29 and
/// 0x5c, including when they appear inside a UTF-16BE sequence.
fn pdf_string(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len() + 2);
    out.push(b'(');
    if text.chars().all(|c| (c as u32) < 0x100) {
        for c in text.chars() {
            push_escaped(&mut out, c as u8);
        }
    } else {
        out.push(0xfe);
        out.push(0xff);
        for unit in text.encode_utf16() {
            for b in unit.to_be_bytes() {
                push_escaped(&mut out, b);
            }
        }
    }
    out.push(b')');
    out
}

fn push_escaped(out: &mut Vec<u8>, b: u8) {
    match b {
        b'(' => out.extend_from_slice(b"\\("),
        b')' => out.extend_from_slice(b"\\)"),
        b'\\' => out.extend_from_slice(b"\\\\"),
        _ => out.push(b),
    }
}

/// Undoes [`pdf_string`] well enough to compare field names. Bytes that are not
/// behind a byte order mark were written as PDFDocEncoding, so they are decoded
/// one byte per character and not as UTF-8.
fn unquote(bytes: &[u8]) -> String {
    let b = pdf::trim_ws(bytes);
    let b = b
        .strip_prefix(b"(")
        .and_then(|x| x.strip_suffix(b")"))
        .unwrap_or(b);
    if b.starts_with(&[0xfe, 0xff]) {
        let units: Vec<u16> = b[2..]
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        return String::from_utf16_lossy(&units);
    }
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 1 < b.len() {
            out.push(b[i + 1]);
            i += 2;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    out.iter().map(|byte| *byte as char).collect()
}

/// `D:YYYYMMDDHHMMSSZ`, in UTC.
///
/// UTC rather than local time because a local offset needs a time zone
/// database and this crate has no dependency that is not pure Rust. The instant
/// is the same either way, and `Z` is one of the three offsets ISO 32000
/// allows. AutoFirma writes local time with an explicit offset.
fn pdf_date(t: SystemTime) -> Result<String> {
    let secs = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|e| Error::Pdf(format!("the signing time is before 1970: {e}")))?
        .as_secs() as i64;
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    let rem = secs.rem_euclid(86_400);
    Ok(format!(
        "D:{y:04}{m:02}{d:02}{:02}{:02}{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    ))
}

/// Days since 1970-01-01 to a proleptic Gregorian date. Howard Hinnant's
/// `civil_from_days`, which is public domain and exact over the whole range.
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

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    pub use crate::testkit::{build_pdf, mini_pdf, test_signer};

    #[test]
    fn dates_are_utc_and_zero_padded() {
        let t = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_760_000_000);
        assert_eq!(pdf_date(t).unwrap(), "D:20251009085320Z");
        assert_eq!(
            pdf_date(SystemTime::UNIX_EPOCH).unwrap(),
            "D:19700101000000Z"
        );
    }

    #[test]
    fn pdf_strings_escape_at_byte_level() {
        assert_eq!(pdf_string("a(b)c"), b"(a\\(b\\)c)".to_vec());
        assert_eq!(pdf_string("back\\slash"), b"(back\\\\slash)".to_vec());
        // an accented name stays single byte, PDFDocEncoding covers Latin-1
        assert_eq!(pdf_string("JOSÉ"), b"(JOS\xC9)".to_vec());
        // beyond Latin-1 it has to be UTF-16BE behind a byte order mark, and
        // the 0x29 in the middle of a sequence still needs escaping
        assert_eq!(
            pdf_string("日本語"),
            vec![b'(', 0xFE, 0xFF, b'e', 0xE5, b'g', b',', 0x8A, 0x9E, b')']
        );
    }

    #[test]
    fn unquote_round_trips() {
        for s in ["Signature1", "Firma (uno)", "JOSÉ ÁNGEL"] {
            assert_eq!(unquote(&pdf_string(s)), s, "{s} did not round trip");
        }
    }

    /// The fixture, so the visible appearance can be checked against a real
    /// page rather than a synthetic dictionary.
    const FIXTURE: &[u8] = include_bytes!("../../../testdata/inputs/simple.pdf");

    /// A regression: the rectangle used to be computed and then dropped, so a
    /// visible signature came out invisible while still drawing its
    /// appearance. Asserting on the bytes is the only way to catch that.
    #[test]
    fn a_visible_signature_writes_its_rectangle_and_draws() {
        let Some(signer) = test_signer() else {
            eprintln!("skipped, test PKI missing, run tools/gen-testcert.sh");
            return;
        };
        let opts = PadesOptions {
            visible: Some(Appearance {
                page: 1,
                rect: [60.0, 700.0, 320.0, 760.0],
                label: Some("Firmado digitalmente por".into()),
            }),
            ..PadesOptions::default()
        };
        let signed = sign(FIXTURE, &signer, &opts).expect("signing failed");

        assert!(
            signed.windows(22).any(|w| w == b"/Rect [60 700 320 760]"),
            "the field must carry the rectangle it was given"
        );
        // the appearance box is the rectangle moved to its own origin
        assert!(
            signed.windows(18).any(|w| w == b"/BBox [0 0 260 60]"),
            "the appearance must be the size of the rectangle"
        );
        let text = String::from_utf8_lossy(&signed);
        assert!(
            text.contains("(Firmado digitalmente por) Tj"),
            "the label must be drawn"
        );
        assert!(
            text.contains("(PEREZ GARCIA, ANA) Tj"),
            "the signer's name must be drawn"
        );
    }

    #[test]
    fn a_page_that_does_not_exist_is_an_error_not_a_panic() {
        let Some(signer) = test_signer() else {
            eprintln!("skipped, test PKI missing, run tools/gen-testcert.sh");
            return;
        };
        let opts = PadesOptions {
            visible: Some(Appearance {
                page: 7,
                rect: [10.0, 10.0, 100.0, 60.0],
                label: None,
            }),
            ..PadesOptions::default()
        };
        let err = sign(FIXTURE, &signer, &opts).unwrap_err().to_string();
        assert!(err.contains("no page 7"), "{err}");
    }

    /// The unreadable-path half of the AcroForm rule (finding B-5): an
    /// indirect `/AcroForm` whose object does not resolve must refuse the
    /// signature with its reason, never fall through to "no form" and replace
    /// a dictionary that may be holding `/XFA`. The catalog names object 9 as
    /// its AcroForm; object 9 is nowhere in the cross-reference.
    #[test]
    fn a_dangling_indirect_acroform_refuses_the_signing_instead_of_replacing_it() {
        let Some(signer) = test_signer() else {
            eprintln!("skipped, test PKI missing, run tools/gen-testcert.sh");
            return;
        };
        let pdf = mini_pdf("<< /Type /Catalog /Pages 2 0 R /AcroForm 9 0 R >>");
        let err = sign(&pdf, &signer, &PadesOptions::default())
            .expect_err("a dangling /AcroForm reference must stop the signing");
        let text = err.to_string();
        assert!(text.contains("/AcroForm"), "{text}");
        assert!(
            text.contains("9 0 R") || text.contains("does not resolve"),
            "the refusal must name the object: {text}"
        );
    }

    #[test]
    fn a_rectangle_with_no_area_is_refused() {
        let Some(signer) = test_signer() else {
            eprintln!("skipped, test PKI missing, run tools/gen-testcert.sh");
            return;
        };
        let opts = PadesOptions {
            visible: Some(Appearance {
                page: 1,
                rect: [100.0, 100.0, 100.0, 100.0],
                label: None,
            }),
            ..PadesOptions::default()
        };
        assert!(sign(FIXTURE, &signer, &opts).is_err());
    }

    /// The case that mattered in practice: adding a signature to a document
    /// whose catalog is compressed into an object stream, which is what iText
    /// writes and therefore what AutoFirma leaves behind. Without reading the
    /// cross-reference stream this fails at the first step.
    #[test]
    fn a_document_with_object_streams_can_be_signed() {
        let Some(signer) = test_signer() else {
            eprintln!("skipped, test PKI missing, run tools/gen-testcert.sh");
            return;
        };
        let doc = crate::pdf::tests::itext_style_document();
        let signed = sign(&doc, &signer, &PadesOptions::default())
            .expect("signing a document with object streams failed");

        assert!(
            signed.starts_with(&doc),
            "the compressed original must survive untouched"
        );

        // reading our own revision back has to find the catalog we rewrote,
        // which only works if the one we copied came out of the object stream
        let at = pdf::last_startxref(&signed).unwrap();
        let tr = pdf::trailer(&signed, at).unwrap();
        assert!(
            tr.prev.is_some(),
            "our revision must chain to the previous one"
        );
        let locs = pdf::object_locations(&signed, at).unwrap();
        let catalog = pdf::resolve(&signed, &locs, None, tr.root).unwrap();
        assert!(
            pdf::get(&catalog, "/AcroForm").is_some(),
            "the rewritten catalog must carry the signature field"
        );
        // the older revision still resolves its own compressed catalog
        let old_at = tr.prev.unwrap();
        let old_tr = pdf::trailer(&signed, old_at).unwrap();
        let old_locs = pdf::object_locations(&signed, old_at).unwrap();
        let old_catalog = pdf::resolve(&signed, &old_locs, None, old_tr.root).unwrap();
        assert!(
            pdf::get(&old_catalog, "/AcroForm").is_none(),
            "the revision we appended to had no signature in it"
        );
    }

    #[test]
    fn next_field_name_avoids_the_taken_ones() {
        assert_eq!(next_field_name(&[]), "Signature1");
        assert_eq!(
            next_field_name(&["Signature1".into(), "Signature2".into()]),
            "Signature3"
        );
    }

    /// The default reservation is iText's, which is what AutoFirma leaves in
    /// every document it signs: a signature that fits AutoFirma has to fit
    /// us, and a B-T token with a long TSA chain is the shape that used to
    /// not fit in 16384.
    #[test]
    fn the_default_reservation_matches_itext_and_lands_in_the_file() {
        assert_eq!(DEFAULT_CONTENTS_RESERVED, 27_000);
        assert_eq!(PadesOptions::default().contents_reserved, 27_000);
        let Some(signer) = test_signer() else {
            eprintln!("skipped, test PKI missing, run tools/gen-testcert.sh");
            return;
        };
        let signed = sign(FIXTURE, &signer, &PadesOptions::default()).expect("signing failed");
        let sig = &crate::inspect::signatures(&signed).expect("readable")[0];
        let [_, b, c, _] = sig.byte_range;
        assert_eq!(
            c - b,
            DEFAULT_CONTENTS_RESERVED * 2 + 2,
            "the hole is the reservation in hex, brackets included"
        );
    }

    /// An `/AcroForm` the document already has is spliced, not rebuilt:
    /// every key its author wrote survives into the new revision. The
    /// casualties of a rebuild are `/NeedAppearances` and `/XFA`, and XFA
    /// forms are what the Spanish administration publishes; dropping either
    /// changes how the document renders or what it says, which is exactly
    /// what docs/adr/0003 forbids.
    #[test]
    fn an_existing_acroform_keeps_its_other_keys() {
        const XFA_FORM: &[u8] = include_bytes!("../../../testdata/inputs/xfa-form.pdf");
        let Some(signer) = test_signer() else {
            eprintln!("skipped, test PKI missing, run tools/gen-testcert.sh");
            return;
        };
        let signed =
            sign(XFA_FORM, &signer, &PadesOptions::default()).expect("signing a form PDF failed");
        assert!(
            signed.starts_with(XFA_FORM),
            "the original revision must survive untouched"
        );

        let at = pdf::last_startxref(&signed).unwrap();
        let tr = pdf::trailer(&signed, at).unwrap();
        let locs = pdf::object_locations(&signed, at).unwrap();
        let catalog = pdf::resolve(&signed, &locs, None, tr.root).unwrap();
        let acro = pdf::get(&catalog, "/AcroForm").expect("the catalog lost its /AcroForm");
        for key in ["/NeedAppearances true", "/XFA 4 0 R"] {
            assert!(
                acro.windows(key.len()).any(|w| w == key.as_bytes()),
                "{key} must survive the splice, /AcroForm is now {:?}",
                String::from_utf8_lossy(acro)
            );
        }
        assert!(
            pdf::get(acro, "/SigFlags").is_some_and(|v| pdf::trim_ws(v) == b"3"),
            "/SigFlags 3 is added when absent"
        );
        // and the field list gained exactly our signature field
        let refs = pdf::array_refs(pdf::get(acro, "/Fields").unwrap()).unwrap();
        assert_eq!(refs.len(), 1, "the empty /Fields gains our field only");
        let field = pdf::resolve(&signed, &locs, None, refs[0]).unwrap();
        assert_eq!(
            pdf::get(&field, "/FT").map(pdf::trim_ws),
            Some(b"/Sig".as_slice())
        );
    }

    /// `/SigFlags` the author already wrote is kept: the splice adds it only
    /// when it is absent, it does not insist on its own value.
    #[test]
    fn an_existing_sigflags_value_is_kept() {
        let Some(signer) = test_signer() else {
            eprintln!("skipped, test PKI missing, run tools/gen-testcert.sh");
            return;
        };
        let doc = mini_pdf(
            "<< /Type /Catalog /Pages 2 0 R \
             /AcroForm << /Fields [] /NeedAppearances true /SigFlags 1 >> >>",
        );
        let signed = sign(&doc, &signer, &PadesOptions::default()).expect("signing failed");

        let at = pdf::last_startxref(&signed).unwrap();
        let tr = pdf::trailer(&signed, at).unwrap();
        let locs = pdf::object_locations(&signed, at).unwrap();
        let catalog = pdf::resolve(&signed, &locs, None, tr.root).unwrap();
        let acro = pdf::get(&catalog, "/AcroForm").expect("the catalog lost its /AcroForm");
        let text = String::from_utf8_lossy(acro);
        assert!(text.contains("/SigFlags 1"), "kept: {text}");
        assert!(!text.contains("/SigFlags 3"), "not overwritten: {text}");
        assert!(text.contains("/NeedAppearances true"), "{text}");
    }

    /// A minimal one page PDF with the catalog given verbatim, behind a
    /// correct classic cross-reference table.
    /// The array splice itself: the author's bytes are kept and the field
    /// appended, and only an array that lists a reference twice — which
    /// appending cannot fix — is rebuilt from its deduplicated references.
    #[test]
    fn merged_fields_keeps_the_authors_bytes_and_dedupes() {
        let field = ObjRef::new(9, 0);
        assert_eq!(
            merged_fields(b"[1 0 R 2 0 R]", field).unwrap(),
            b"[1 0 R 2 0 R 9 0 R]"
        );
        assert_eq!(
            merged_fields(b"[1 0 R 2 0 R 1 0 R]", field).unwrap(),
            b"[1 0 R 2 0 R 9 0 R]"
        );
        // our field already listed: no second copy of it
        assert_eq!(merged_fields(b"[9 0 R]", field).unwrap(), b"[9 0 R]");
        // an empty array gains exactly the field
        assert_eq!(merged_fields(b"[]", field).unwrap(), b"[ 9 0 R]");
        // and something that is not an array is refused
        assert!(merged_fields(b"9 0 R", field).is_err());
    }

    /// An indirect `/Annots` — the shape iText writes, so the shape every
    /// document AutoFirma signed has — is resolved, merged and written back
    /// under its own number: the page keeps its reference, the old array
    /// stays where the earlier revisions' `/ByteRange`s say it is, and the
    /// annotation it held survives next to our field.
    #[test]
    fn an_indirect_annots_array_stays_indirect() {
        const DOC: &[u8] = include_bytes!("../../../testdata/inputs/indirect-annots.pdf");
        let Some(signer) = test_signer() else {
            eprintln!("skipped, test PKI missing, run tools/gen-testcert.sh");
            return;
        };
        // before the fix this failed outright: "the page /Annots is not an
        // array", because the value was the reference, not the array
        let signed = sign(DOC, &signer, &PadesOptions::default())
            .expect("signing a document with an indirect /Annots failed");
        assert!(
            signed.starts_with(DOC),
            "the original revision must survive"
        );

        let at = pdf::last_startxref(&signed).unwrap();
        let locs = pdf::object_locations(&signed, at).unwrap();

        // the page still points at 4 0 R, it was not inlined
        let page = pdf::resolve(&signed, &locs, None, ObjRef::new(3, 0)).unwrap();
        assert_eq!(
            pdf::get(&page, "/Annots").map(pdf::trim_ws),
            Some(b"4 0 R".as_slice()),
            "the indirect form must be kept in the new revision"
        );

        // object 4, redefined in the new revision, holds both annotations
        let annots = pdf::resolve(&signed, &locs, None, ObjRef::new(4, 0)).unwrap();
        let refs = pdf::array_refs(&annots).unwrap();
        assert_eq!(refs.len(), 2, "the original annotation plus our field");
        // the annotation that was there is itself indirect, so the array
        // holds its reference and the /Subtype lives in its own object
        let link = pdf::resolve(&signed, &locs, None, refs[0]).unwrap();
        assert_eq!(
            pdf::get(&link, "/Subtype").map(pdf::trim_ws),
            Some(b"/Link".as_slice()),
            "the annotation that was there must survive: {:?}",
            String::from_utf8_lossy(&link)
        );
        let field = pdf::resolve(&signed, &locs, None, refs[1]).unwrap();
        assert_eq!(
            pdf::get(&field, "/FT").map(pdf::trim_ws),
            Some(b"/Sig".as_slice())
        );

        // and the whole document still verifies
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/certs");
        let ca = openfirma_core::cert::CertificateHandle::from_pem(
            &std::fs::read_to_string(dir.join("ca.crt")).expect("the test PKI has a ca.crt"),
        )
        .expect("ca.crt is a certificate");
        crate::verify::verify(
            &signed,
            &openfirma_cades::verify::VerifyOptions::new(vec![ca]),
        )
        .expect("the signed document must verify");
    }

    /// Signing a field the form already offers FILLS it: the rectangle, the name
    /// and the page stay the form's own bytes and the field gains the value and
    /// the appearance it was waiting for. This is the flow the reference tool
    /// has — `signatureField`, which its GUI drives — measured against AutoFirma
    /// 1.9.1 on a two-field form: the second signature lands in the second field
    /// and leaves the first exactly where it was.
    #[test]
    fn a_named_field_the_form_already_has_is_filled_not_duplicated() {
        let Some(signer) = test_signer() else {
            eprintln!("skipped, test PKI missing, run tools/gen-testcert.sh");
            return;
        };
        let doc = build_pdf(
            &[
                "<< /Type /Catalog /Pages 2 0 R \
                 /AcroForm << /Fields [ 4 0 R ] /SigFlags 3 >> >>",
                "<< /Type /Pages /Kids [ 3 0 R ] /Count 1 >>",
                "<< /Type /Page /Parent 2 0 R /MediaBox [ 0 0 595 842 ] /Annots [ 4 0 R ] >>",
                "<< /Type /Annot /Subtype /Widget /FT /Sig /T (Firma1) \
                 /Rect [ 72 600 400 660 ] /F 132 /P 3 0 R >>",
            ],
            "/Size 5 /Root 1 0 R",
        );
        let opts = PadesOptions {
            field_name: Some("Firma1".into()),
            visible: Some(Appearance {
                page: 1,
                rect: [72.0, 600.0, 400.0, 660.0],
                label: None,
            }),
            ..PadesOptions::default()
        };
        let signed = sign(&doc, &signer, &opts).expect("signing into the form's own field");

        let at = pdf::last_startxref(&signed).unwrap();
        let tr = pdf::trailer(&signed, at).unwrap();
        let locs = pdf::object_locations(&signed, at).unwrap();
        let field = pdf::resolve(&signed, &locs, None, ObjRef::new(4, 0)).unwrap();
        let text = String::from_utf8_lossy(&field);
        assert!(
            text.contains("/T (Firma1)") && text.contains("/Rect [ 72 600 400 660 ]"),
            "the name and the rectangle stay the form's bytes: {text}"
        );
        assert!(
            pdf::get(&field, "/V").is_some(),
            "the field gained the value: {text}"
        );
        let ap = pdf::get(&field, "/AP").expect("and a named appearance");
        let look = pdf::get(ap, "/N")
            .and_then(pdf::parse_ref)
            .expect("/N names the appearance");
        let appearance = pdf::resolve(&signed, &locs, None, look).unwrap();
        let drawn = String::from_utf8_lossy(&appearance);
        assert!(
            drawn.contains("/BBox [0 0 328 60]") && drawn.contains("/Font"),
            "the appearance is sized to the form's box and draws the signature, \
             where the blank one is [0 0 0 0] with no font: {drawn}"
        );
        let catalog = pdf::resolve(&signed, &locs, None, tr.root).unwrap();
        let acro = pdf::get(&catalog, "/AcroForm").expect("the catalog keeps its /AcroForm");
        assert_eq!(
            pdf::array_refs(pdf::get(acro, "/Fields").unwrap()).unwrap(),
            vec![ObjRef::new(4, 0)],
            "/Fields is still the author's: a fill adds no field"
        );
        let page = pdf::resolve(&signed, &locs, None, ObjRef::new(3, 0)).unwrap();
        assert_eq!(
            pdf::array_refs(pdf::get(&page, "/Annots").unwrap()).unwrap(),
            vec![ObjRef::new(4, 0)],
            "and the page keeps its one widget"
        );

        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/certs");
        let ca = openfirma_core::cert::CertificateHandle::from_pem(
            &std::fs::read_to_string(dir.join("ca.crt")).expect("the test PKI has a ca.crt"),
        )
        .expect("ca.crt is a certificate");
        crate::verify::verify(
            &signed,
            &openfirma_cades::verify::VerifyOptions::new(vec![ca]),
        )
        .expect("the filled document must verify");
    }

    /// Two fields a fill may NOT take over, and the refusal says which: one the
    /// form already signed (filling it would replace the signature a reader
    /// shows there) and a parent field whose value lives on the dictionary while
    /// its widgets are the children (openfirma signs a field whose own
    /// dictionary IS its widget, which is what a form that renders one has).
    #[test]
    fn naming_a_signed_field_or_a_parent_field_is_refused() {
        let Some(signer) = test_signer() else {
            eprintln!("skipped, test PKI missing, run tools/gen-testcert.sh");
            return;
        };
        let base = |field: &str| {
            build_pdf(
                &[
                    "<< /Type /Catalog /Pages 2 0 R \
                     /AcroForm << /Fields [ 4 0 R ] /SigFlags 3 >> >>",
                    "<< /Type /Pages /Kids [ 3 0 R ] /Count 1 >>",
                    "<< /Type /Page /Parent 2 0 R /MediaBox [ 0 0 595 842 ] /Annots [ 4 0 R ] >>",
                    field,
                ],
                "/Size 5 /Root 1 0 R",
            )
        };
        let signed_field = base(
            "<< /Type /Annot /Subtype /Widget /FT /Sig /T (Firma1) \
             /Rect [ 72 600 400 660 ] /F 132 /P 3 0 R /V 9 0 R >>",
        );
        let parent = base("<< /FT /Sig /T (Firma1) /Kids [ 9 0 R ] /Rect [ 72 600 400 660 ] >>");
        let opts = PadesOptions {
            field_name: Some("Firma1".into()),
            ..PadesOptions::default()
        };

        let taken = sign(&signed_field, &signer, &opts).expect_err("a signed field is not a place");
        assert!(
            taken.to_string().contains("already carries a signature"),
            "the refusal says why: {taken}"
        );
        let kids = sign(&parent, &signer, &opts).expect_err("/Kids is not a widget");
        assert!(
            kids.to_string().contains("/Kids"),
            "the refusal pushes the field: {kids}"
        );
    }
}
