//! PAdES-B-B: a detached CAdES inside a PDF signature dictionary, added to the
//! document as an incremental update.
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
use openfirma_core::signer::Signer;
use openfirma_core::{Error, Result, oid};

use crate::appearance::{self, Appearance};
use crate::pdf::{self, Location, ObjRef};
use crate::update::{Object, Update};

/// Digits reserved for each number of `/ByteRange`. Ten covers files up to
/// 9999999999 bytes, and the width has to be fixed before the layout is known.
const BYTERANGE_WIDTH: usize = 10;

/// How much space to reserve for `/Contents` when the caller does not say.
///
/// The CMS is zero padded to fill it, so this is wasted space in the file, but
/// too small a reservation is a hard failure. 16 KiB holds a chain of several
/// certificates with room to spare and leaves space for the timestamp token
/// that B-T will add later without changing the layout algorithm. AutoFirma,
/// through iText, reserves 27000.
pub const DEFAULT_CONTENTS_RESERVED: usize = 16384;

pub struct PadesOptions {
    pub digest: DigestAlg,

    /// Signing time, written to the signature dictionary's `/M`. There is no
    /// `signingTime` attribute in the CMS: `/M` is the only place the time
    /// lives, which is what AutoFirma does and what avoids two answers to one
    /// question.
    pub sign_time: SystemTime,

    /// Name of the AcroForm field. When the document already has signature
    /// fields, the next free `SignatureN` is used instead.
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
        }
    }
}

/// Adds a PAdES-B-B signature to `pdf` and returns the whole signed document.
pub fn sign(pdf: &[u8], signer: &dyn Signer, opts: &PadesOptions) -> Result<Vec<u8>> {
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

    let page_ref = match &opts.visible {
        Some(a) => page_at(pdf, &offsets, &catalog, a.page)?,
        None => page_at(pdf, &offsets, &catalog, 1)?,
    };
    let page = pdf::resolve(pdf, &offsets, page_ref)?.to_vec();
    if !page.starts_with(b"<<") {
        return Err(Error::Pdf(format!("page {page_ref} is not a dictionary")));
    }
    let info = match trailer.info {
        Some(r) => Some(pdf::resolve(pdf, &offsets, r)?.to_vec()),
        None => None,
    };

    let mut update = Update::new(xref_at, trailer.root, trailer.info, trailer.size);
    // existing objects are rewritten under their own number, new ones start here
    let first_new = update.next_object_number();
    let appearance = ObjRef::new(first_new, 0);
    let helv = ObjRef::new(first_new + 1, 0);
    let zadb = ObjRef::new(first_new + 2, 0);
    let sig = ObjRef::new(first_new + 3, 0);
    let field = ObjRef::new(first_new + 4, 0);
    let info_ref = trailer.info.unwrap_or(ObjRef::new(first_new + 5, 0));

    let existing = existing_signature_fields(pdf, &offsets, &catalog);
    let field_name = opts
        .field_name
        .clone()
        .unwrap_or_else(|| next_field_name(&existing.names));
    let mut fields = existing.refs;
    fields.push(field);

    let sig_dict = build_sig_dict(signer, opts)?;
    let acroform = build_acroform(&fields, helv, zadb);

    // Even an invisible signature needs an appearance entry, viewers look for
    // it, and a blank form XObject is how you say "draw nothing".
    let (rect, appearance_body) = match &opts.visible {
        Some(a) => {
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
        None => ("[0 0 0 0]".to_string(), appearance::blank()),
    };
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
    update.push(Object::new(sig, sig_dict));
    update.push(Object::new(
        field,
        build_field(field_name, appearance, page_ref, sig, &rect),
    ));

    // The catalog and the page keep their numbers, so every reference to them
    // from the older revisions now resolves to these new definitions and the
    // page tree does not have to be rewritten at all.
    update.push(Object::new(
        trailer.root,
        pdf::set(&catalog, "/AcroForm", acroform.as_bytes())?,
    ));
    update.push(Object::new(
        page_ref,
        pdf::set(&page, "/Annots", &merged_annots(&page, field)?)?,
    ));

    // Recording that the document changed is what /ModDate is for.
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

    let rendered = update.render(pdf.len())?;
    let sig_at = rendered.offsets[&sig];
    let mut out = Vec::with_capacity(pdf.len() + rendered.bytes.len());
    out.extend_from_slice(pdf);
    out.extend_from_slice(&rendered.bytes);

    finish(&mut out, sig_at, signer, opts)?;
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

/// `/F 132` is `Print | Locked`, `/Rect [0 0 0 0]` with a blank appearance is
/// an invisible signature, which is what AutoFirma writes when no position is
/// given.
fn build_field(name: String, appearance: ObjRef, page: ObjRef, sig: ObjRef, rect: &str) -> Vec<u8> {
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

/// The page's `/Annots` with our field added, keeping the ones already there.
fn merged_annots(page: &[u8], field: ObjRef) -> Result<Vec<u8>> {
    match pdf::get(page, "/Annots") {
        Some(existing) => {
            let mut v = pdf::trim_ws(existing).to_vec();
            if !v.ends_with(b"]") {
                return Err(Error::Pdf("the page /Annots is not an array".into()));
            }
            v.pop();
            v.extend_from_slice(format!(" {field}]").as_bytes());
            Ok(v)
        }
        None => Ok(format!("[{field}]").into_bytes()),
    }
}

/// Patches `/ByteRange`, then signs the two ranges it describes and fills
/// `/Contents`. `sig_at` is the absolute offset of the signature dictionary
/// object in `out`.
fn finish(out: &mut [u8], sig_at: usize, signer: &dyn Signer, opts: &PadesOptions) -> Result<()> {
    let body = pdf::object_body(out, sig_at)?;
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

    let cms = cades_sign(&covered, signer, &cades_options(opts))?;

    let hex_len = contents_end - contents_start - 2;
    if cms.len() * 2 > hex_len {
        return Err(Error::Pdf(format!(
            "the CMS needs {} bytes but /Contents only reserves {}; raise \
             PadesOptions::contents_reserved",
            cms.len(),
            hex_len / 2
        )));
    }
    // lower case hex, zero padded to the reserved width, which is what iText
    // writes and what readers expect: the DER is parsed and the padding ignored
    let mut value = hex::encode(&cms).into_bytes();
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
        signing_certificate_v2: true,
        include_issuer_serial: true,
        extra_certificates: Vec::new(),
        unsigned_attributes: Vec::new(),
    }
}

/// The `index`th page of the document, counting from 1.
fn page_at(
    pdf: &[u8],
    offsets: &BTreeMap<ObjRef, Location>,
    catalog: &[u8],
    index: usize,
) -> Result<ObjRef> {
    if index == 0 {
        return Err(Error::Pdf(
            "pages are counted from 1, there is no page 0".into(),
        ));
    }
    let pages_ref = pdf::parse_ref(
        pdf::get(catalog, "/Pages")
            .ok_or_else(|| Error::Pdf("the catalog has no /Pages".into()))?,
    )
    .ok_or_else(|| Error::Pdf("/Pages is not an indirect reference".into()))?;

    let mut pages = Vec::new();
    collect_pages(pdf, offsets, pages_ref, &mut pages, 0)?;
    pages.get(index - 1).copied().ok_or_else(|| {
        Error::Pdf(format!(
            "the document has {} pages, so it has no page {index}",
            pages.len()
        ))
    })
}

/// Walks the page tree in document order, which is the order viewers number
/// pages in and therefore the order a caller means by "page 3".
fn collect_pages(
    pdf: &[u8],
    offsets: &BTreeMap<ObjRef, Location>,
    node: ObjRef,
    out: &mut Vec<ObjRef>,
    depth: u32,
) -> Result<()> {
    if depth > 64 {
        return Err(Error::Pdf(
            "the page tree is deeper than 64 levels, /Kids is probably a loop".into(),
        ));
    }
    let body = pdf::resolve(pdf, offsets, node)?;
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
        collect_pages(pdf, offsets, kid, out, depth + 1)?;
    }
    Ok(())
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
/// added to `/Fields` instead of replacing the first one.
struct ExistingFields {
    refs: Vec<ObjRef>,
    names: Vec<String>,
}

fn existing_signature_fields(
    pdf: &[u8],
    offsets: &BTreeMap<ObjRef, Location>,
    catalog: &[u8],
) -> ExistingFields {
    let empty = ExistingFields {
        refs: Vec::new(),
        names: Vec::new(),
    };
    let Some(acro_bytes) = pdf::get(catalog, "/AcroForm") else {
        return empty;
    };
    // /AcroForm may be written inline or as an indirect reference, and an
    // indirect one may live in an object stream, so it is always owned here
    let owned: Vec<u8> = match pdf::parse_ref(acro_bytes) {
        Some(r) => match pdf::resolve(pdf, offsets, r) {
            Ok(b) => b.into_owned(),
            Err(_) => return empty,
        },
        None => acro_bytes.to_vec(),
    };
    let acro: &[u8] = &owned;
    let Some(fields_bytes) = pdf::get(acro, "/Fields") else {
        return empty;
    };
    let Ok(refs) = pdf::array_refs(fields_bytes) else {
        return empty;
    };
    let mut names = Vec::new();
    for r in &refs {
        if let Ok(f) = pdf::resolve(pdf, offsets, *r) {
            if let Some(t) = pdf::get(&f, "/T") {
                names.push(unquote(t));
            }
        }
    }
    ExistingFields { refs, names }
}

fn next_field_name(taken: &[String]) -> String {
    (1..)
        .map(|n| format!("Signature{n}"))
        .find(|candidate| !taken.contains(candidate))
        .unwrap_or_else(|| "Signature1".into())
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
mod tests {
    use super::*;

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

    /// The RSA signer from the throwaway PKI, or None when it has not been
    /// generated. Present but unloadable material panics rather than skipping,
    /// because a silent skip once hid that every ECDSA test was passing
    /// without signing anything.
    fn test_signer() -> Option<openfirma_core::signer::SoftwareSigner> {
        use openfirma_core::cert::CertificateHandle;
        use openfirma_core::signer::SoftwareSigner;
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/certs");
        let read = |name: &str| std::fs::read_to_string(dir.join(name));
        let (Ok(cert), Ok(key)) = (read("signer-rsa.crt"), read("signer-rsa.key")) else {
            return None;
        };
        let signer = SoftwareSigner::from_pkcs8_pem(&cert, &key).unwrap_or_else(|e| {
            panic!("the test PKI is present but unusable: {e}. Rerun tools/gen-testcert.sh")
        });
        let chain = ["intermediate.crt", "ca.crt"]
            .iter()
            .map(|c| {
                CertificateHandle::from_pem(&read(c).expect("the test PKI is incomplete"))
                    .expect("not a certificate")
            })
            .collect();
        Some(signer.with_chain(chain))
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
        let catalog = pdf::resolve(&signed, &locs, tr.root).unwrap();
        assert!(
            pdf::get(&catalog, "/AcroForm").is_some(),
            "the rewritten catalog must carry the signature field"
        );
        // the older revision still resolves its own compressed catalog
        let old_at = tr.prev.unwrap();
        let old_tr = pdf::trailer(&signed, old_at).unwrap();
        let old_locs = pdf::object_locations(&signed, old_at).unwrap();
        let old_catalog = pdf::resolve(&signed, &old_locs, old_tr.root).unwrap();
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
}
