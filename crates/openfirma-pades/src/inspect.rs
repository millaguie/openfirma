//! Looking at a signed PDF.
//!
//! `openfirma inspect` on a DER file prints a normalized tree, which is what
//! the golden diff runs on. On a PDF there is more to say than the CMS: where
//! the signature claims to cover, whether that claim holds, which of the
//! optional dictionary entries are present, and — since B-LTA — whether each
//! document time-stamp token imprints the bytes its own `/ByteRange` names.
//!
//! It walks the cross-reference rather than scanning for keywords, so it works
//! on a classic table, on a cross-reference stream and on a document whose
//! signature dictionary sits in an object stream.

use openfirma_core::{Error, Result, der_dump};

use crate::pdf::{self, ObjRef};

/// One signature found in a document.
pub struct Signature {
    /// The object holding the signature dictionary.
    pub object: ObjRef,
    /// The two ranges the signature claims to cover.
    pub byte_range: [usize; 4],
    /// The dictionary, as normalized lines for the interesting keys.
    pub dictionary: Vec<String>,
    /// The CMS in `/Contents`, without the zero padding.
    pub cms: Vec<u8>,
    /// What is wrong, if anything. Empty means the invariants hold.
    pub problems: Vec<String>,
}

impl Signature {
    /// True when the signature covers the file the way it claims to and its
    /// `messageDigest` is the digest of exactly those bytes.
    pub fn is_consistent(&self) -> bool {
        self.problems.is_empty()
    }
}

/// Every signature dictionary in the document, in object number order.
pub fn signatures(pdf: &[u8]) -> Result<Vec<Signature>> {
    if !pdf.starts_with(b"%PDF-") {
        return Err(Error::Pdf("the input does not start with %PDF-".into()));
    }
    let xref_at = pdf::last_startxref(pdf)?;
    let locations = pdf::object_locations(pdf, xref_at)?;

    // One decode memo for the whole scan: this loop resolves *every* object in
    // the cross-reference, so an unmemoised resolve would inflate each object
    // stream once per object it holds — quadratic CPU from 40 KB of input
    // (finding A-1). The document is read-only here, so no invalidation.
    let mut cache = pdf::ObjectStreamCache::new();
    let mut out = Vec::new();
    for object in locations.keys() {
        let Ok(body) = pdf::resolve(pdf, &locations, Some(&mut cache), *object) else {
            continue;
        };
        if pdf::get(&body, "/Type").map(|t| pdf::trim_ws(t) == b"/Sig") != Some(true) {
            continue;
        }
        out.push(read_signature(pdf, *object, &body)?);
    }
    out.sort_by_key(|s| (s.object.num, s.object.generation));
    Ok(out)
}

/// The `/ByteRange` of a signature or document time-stamp dictionary, and the
/// problems its numbers gave while being read. A number that is not a number
/// is read as 0 *and reported*: silently zeroing it used to turn a corrupt
/// range into a range that merely disagrees with the file, which is a much
/// worse thing to tell the user.
fn byte_range_of(dict: &[u8], object: ObjRef) -> Result<([usize; 4], Vec<String>)> {
    let Some(range_bytes) = pdf::get(dict, "/ByteRange") else {
        return Err(Error::Pdf(format!("signature {object} has no /ByteRange")));
    };
    let trimmed = pdf::trim_ws(range_bytes);
    let Some(inner) = trimmed.strip_prefix(b"[") else {
        return Err(Error::Pdf(format!(
            "signature {object} has a /ByteRange that is not an array"
        )));
    };
    let inner = inner.strip_suffix(b"]").unwrap_or(inner);
    let mut nums: Vec<usize> = Vec::with_capacity(4);
    let mut problems = Vec::new();
    for token in String::from_utf8_lossy(inner).split_whitespace() {
        match token.parse::<usize>() {
            Ok(n) => nums.push(n),
            Err(_) => {
                problems.push(format!(
                    "signature {object} has a /ByteRange number {token:?} that is not an \
                     unsigned integer; it is read as 0"
                ));
                nums.push(0);
            }
        }
    }
    if nums.len() != 4 {
        return Err(Error::Pdf(format!(
            "signature {object} has a /ByteRange with {} numbers, expected 4",
            nums.len()
        )));
    }
    Ok(([nums[0], nums[1], nums[2], nums[3]], problems))
}

/// The structural claims of a `/ByteRange`, shared by signatures and document
/// time-stamps: the ranges start at 0, end at a revision boundary, do not
/// overlap, and the hole between them is exactly the `/Contents` string.
///
/// The ranges have to end at a revision boundary, not necessarily at the end
/// of the file: a signature added by an incremental update covers the
/// document as it was when it was made, and later revisions are appended
/// after it. Only the newest one reaches the end of the file.
///
/// Every number here comes out of the document, so every offset is clamped or
/// checked instead of sliced with: a `/ByteRange` that names bytes the file
/// does not have is a problem to report, not a panic.
fn range_problems(pdf: &[u8], byte_range: [usize; 4]) -> Vec<String> {
    let [a, b, c, d] = byte_range;
    let mut problems = Vec::new();
    if a != 0 {
        problems.push(format!("the first range starts at {a}, not at 0"));
    }
    let ends = revision_ends(pdf);
    match c.checked_add(d) {
        Some(end) if ends.contains(&end) => {}
        Some(end) => problems.push(format!(
            "the ranges end at {end}, which is not the end of any of the {} revisions",
            ends.len()
        )),
        None => problems.push(format!(
            "the second range is {c} + {d}, which overflows any file offset"
        )),
    }
    if b >= c {
        problems.push("the two ranges overlap or are in the wrong order".into());
    }
    let gap = gap_slice(pdf, b, c);
    if gap.first() != Some(&b'<') || gap.last() != Some(&b'>') {
        problems.push("the gap between the ranges is not exactly the /Contents string".into());
    }
    problems
}

/// The bytes between the two ranges, the `/Contents` string, clamped into the
/// file. A `/ByteRange` whose numbers do not describe a slice of this file
/// yields an empty gap, which every caller already reports as a problem.
fn gap_slice(pdf: &[u8], b: usize, c: usize) -> &[u8] {
    let end = c.min(pdf.len());
    if b <= end { &pdf[b..end] } else { &[] }
}

/// The bytes a `/ByteRange` covers, tolerating ranges that run past the end
/// of the file so a damaged document stays reportable.
fn covered_bytes(pdf: &[u8], byte_range: [usize; 4]) -> Vec<u8> {
    let [a, b, c, d] = byte_range;
    let mut covered = Vec::with_capacity(b.min(pdf.len()).saturating_add(d.min(pdf.len())));
    // both ends are checked: a range may start past the file, end past it, or
    // name a sum that does not fit in an offset at all, and the digest of the
    // part that does exist still has to be computable for the report
    if let Some(end) = a.checked_add(b.min(pdf.len())) {
        if end <= pdf.len() {
            covered.extend_from_slice(&pdf[a..end]);
        }
    }
    if let Some(end) = c.checked_add(d) {
        if end <= pdf.len() {
            covered.extend_from_slice(&pdf[c..end]);
        }
    }
    covered
}

fn read_signature(pdf: &[u8], object: ObjRef, dict: &[u8]) -> Result<Signature> {
    let (byte_range, mut problems) = byte_range_of(dict, object)?;
    let [b, c] = [byte_range[1], byte_range[2]];
    problems.extend(range_problems(pdf, byte_range));

    let gap = gap_slice(pdf, b, c);
    let cms = if gap.first() == Some(&b'<') && gap.last() == Some(&b'>') {
        contents_der(gap, &mut problems)
    } else {
        Vec::new()
    };

    // the digest claim: messageDigest must equal the digest of the two ranges
    if cms.is_empty() {
        problems.push("no CMS could be read from /Contents".into());
    } else {
        let covered = covered_bytes(pdf, byte_range);
        let want = openfirma_core::DigestAlg::Sha256.digest(&covered);
        match message_digest(&cms) {
            Some(got) if got == want.as_slice() => {}
            Some(got) => problems.push(format!(
                "messageDigest {}... does not match sha256 of the ranges {}...",
                hex::encode(&got[..8.min(got.len())]),
                hex::encode(&want[..8]),
            )),
            None => problems.push("the CMS carries no messageDigest attribute".into()),
        }
    }

    let dictionary = dictionary_lines(dict);
    Ok(Signature {
        object,
        byte_range,
        dictionary,
        cms,
        problems,
    })
}

/// A document time-stamp dictionary (`/Type /DocTimeStamp`), the B-LTA
/// layer: an RFC 3161 token over the whole document before it, validation
/// data included.
pub struct DocTimeStamp {
    /// The object holding the dictionary.
    pub object: ObjRef,
    /// The two ranges the token claims to cover.
    pub byte_range: [usize; 4],
    /// The RFC 3161 token in `/Contents`, without the zero padding.
    pub token: Vec<u8>,
    /// The digest the token imprints under, when it parses.
    pub digest: Option<openfirma_core::alg::DigestAlg>,
    /// What is wrong, if anything. Empty means the claims hold.
    pub problems: Vec<String>,
}

impl DocTimeStamp {
    /// True when the token covers the bytes it claims to and imprints them.
    pub fn is_consistent(&self) -> bool {
        self.problems.is_empty()
    }
}

/// Every document time-stamp in the PDF, in object number order.
pub fn document_timestamps(pdf: &[u8]) -> Result<Vec<DocTimeStamp>> {
    if !pdf.starts_with(b"%PDF-") {
        return Err(Error::Pdf("the input does not start with %PDF-".into()));
    }
    let xref_at = pdf::last_startxref(pdf)?;
    let locations = pdf::object_locations(pdf, xref_at)?;

    // one ObjStm decode for the whole scan, not one per object (finding A-1)
    let mut cache = pdf::ObjectStreamCache::new();
    let mut out = Vec::new();
    for object in locations.keys() {
        let Ok(body) = pdf::resolve(pdf, &locations, Some(&mut cache), *object) else {
            continue;
        };
        if pdf::get(&body, "/Type").map(|t| pdf::trim_ws(t) == b"/DocTimeStamp") != Some(true) {
            continue;
        }
        out.push(read_document_timestamp(pdf, *object, &body)?);
    }
    out.sort_by_key(|t| (t.object.num, t.object.generation));
    Ok(out)
}

fn read_document_timestamp(pdf: &[u8], object: ObjRef, dict: &[u8]) -> Result<DocTimeStamp> {
    let (byte_range, mut problems) = byte_range_of(dict, object)?;
    let [b, c] = [byte_range[1], byte_range[2]];
    problems.extend(range_problems(pdf, byte_range));
    let mut digest = None;

    let gap = gap_slice(pdf, b, c);
    let token = if gap.first() == Some(&b'<') && gap.last() == Some(&b'>') {
        contents_der(gap, &mut problems)
    } else {
        Vec::new()
    };
    if token.is_empty() {
        if !problems.iter().any(|p| p.contains("/Contents")) {
            problems.push("no token could be read from /Contents".into());
        }
    } else {
        // the imprint claim: the token must hash the bytes its /ByteRange covers
        match openfirma_cades::tsp::token_imprint(&token) {
            Ok((alg, hashed)) => {
                digest = Some(alg);
                let want = alg.digest(&covered_bytes(pdf, byte_range));
                if want.as_slice() != hashed.as_slice() {
                    problems.push(format!(
                        "the token imprints {}... but the {} of the bytes its /ByteRange \
                         covers is {}...",
                        hex::encode(&hashed[..8.min(hashed.len())]),
                        alg.name(),
                        hex::encode(&want[..8]),
                    ));
                }
            }
            Err(e) => problems.push(format!(
                "/Contents does not hold a readable RFC 3161 token: {e}"
            )),
        }
    }

    Ok(DocTimeStamp {
        object,
        byte_range,
        token,
        digest,
        problems,
    })
}

/// The offset just past each revision, which is where the next revision's
/// appended bytes begin. A signature's ranges must end at one of these.
fn revision_ends(pdf: &[u8]) -> Vec<usize> {
    let mut ends = Vec::new();
    let mut from = 0;
    while let Some(p) = pdf[from..].windows(5).position(|w| w == b"%%EOF") {
        let mut e = from + p + 5;
        // exactly one end of line terminates %%EOF. Consuming more would eat
        // the newline that the next revision's appended bytes start with, and
        // then the boundary would sit one byte inside that revision.
        if pdf[e..].starts_with(b"\r\n") {
            e += 2;
        } else if e < pdf.len() && (pdf[e] == b'\n' || pdf[e] == b'\r') {
            e += 1;
        }
        ends.push(e);
        from = e;
    }
    ends
}

/// The CMS in a `/Contents` hex string, without the zero padding that fills
/// the reserved space. The length comes from the DER header rather than from
/// stripping zeros, because a signature value can legitimately end in a zero
/// byte.
fn contents_der(gap: &[u8], problems: &mut Vec<String>) -> Vec<u8> {
    let inner = &gap[1..gap.len().saturating_sub(1)];
    let raw = match hex::decode(inner) {
        Ok(r) => r,
        Err(e) => {
            problems.push(format!("/Contents is not valid hex: {e}"));
            return Vec::new();
        }
    };
    if raw.first() != Some(&0x30) {
        problems.push("/Contents does not hold a DER SEQUENCE".into());
        return Vec::new();
    }
    let n = (raw[1] & 0x7f) as usize;
    let total = if raw[1] & 0x80 == 0 {
        2 + n
    } else {
        // the long form length octets have to actually be inside the value:
        // both the count and the number they encode come out of the document
        let Some(len_end) = 2usize.checked_add(n).filter(|e| *e <= raw.len()) else {
            problems.push(format!(
                "/Contents declares a {n} octet DER length but only holds {} bytes",
                raw.len().saturating_sub(2)
            ));
            return Vec::new();
        };
        let mut v = 0usize;
        for b in &raw[2..len_end] {
            let Some(next) = v.checked_shl(8).and_then(|x| x.checked_add(*b as usize)) else {
                problems.push(format!(
                    "/Contents declares a DER length too large to be a file offset \
                     ({} length octets)",
                    len_end - 2
                ));
                return Vec::new();
            };
            v = next;
        }
        let Some(total) = len_end.checked_add(v) else {
            problems.push(format!(
                "/Contents declares a DER length too large to be a file offset \
                 ({} length octets)",
                len_end - 2
            ));
            return Vec::new();
        };
        total
    };
    if total > raw.len() {
        problems.push(format!(
            "/Contents declares a {total} byte DER but only holds {}",
            raw.len()
        ));
        return Vec::new();
    }
    raw[..total].to_vec()
}

/// The `messageDigest` signed attribute, located by its OID.
fn message_digest(der: &[u8]) -> Option<Vec<u8>> {
    let oid = [
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04,
    ];
    let at = der.windows(oid.len()).position(|w| w == oid)?;
    let rest = der.get(at + oid.len()..)?;
    let i = rest.iter().position(|b| *b == 0x04)?;
    let len = usize::from(*rest.get(i + 1)?);
    // the declared length is the document's claim, not a promise: slice with
    // get() so a truncated attribute reads as absent instead of panicking
    let start = i.checked_add(2)?;
    rest.get(start..start.checked_add(len)?).map(|v| v.to_vec())
}

/// The dictionary, reduced to the keys that carry meaning, in a fixed order.
fn dictionary_lines(dict: &[u8]) -> Vec<String> {
    const KEYS: [&str; 12] = [
        "/Type",
        "/Filter",
        "/SubFilter",
        "/ByteRange",
        "/M",
        "/Name",
        "/Reason",
        "/Location",
        "/ContactInfo",
        "/Cert",
        "/Prop_Build",
        "/DocMDP",
    ];
    let mut lines = Vec::new();
    for key in KEYS {
        match pdf::get(dict, key) {
            Some(v) => {
                let value = String::from_utf8_lossy(v).trim().to_string();
                lines.push(format!("{key} {value}"));
            }
            None => lines.push(format!("{key} (absent)")),
        }
    }
    lines
}

/// The whole report as text, one section per signature.
pub fn render(pdf: &[u8]) -> Result<String> {
    let signatures = signatures(pdf)?;
    if signatures.is_empty() {
        return Ok("no signature dictionaries found in this document\n".into());
    }
    let mut out = String::new();
    for (i, sig) in signatures.iter().enumerate() {
        out.push_str(&format!(
            "signature {} (object {} {}):\n",
            i + 1,
            sig.object.num,
            sig.object.generation
        ));
        for line in &sig.dictionary {
            out.push_str(&format!("  {line}\n"));
        }
        let [a, b, c, d] = sig.byte_range;
        out.push_str(&format!("  /ByteRange [{a} {b} {c} {d}]\n"));
        out.push_str(&format!("  /Contents <CMS {} bytes>\n", sig.cms.len()));
        if sig.is_consistent() {
            out.push_str(
                "  integrity: the ranges cover the file except /Contents, and \
                          messageDigest matches their digest\n",
            );
        } else {
            for p in &sig.problems {
                out.push_str(&format!("  integrity FAIL: {p}\n"));
            }
        }
        out.push_str("  cms:\n");
        match der_dump(&sig.cms) {
            Ok(dump) => {
                for line in dump.lines() {
                    out.push_str(&format!("    {line}\n"));
                }
            }
            Err(e) => out.push_str(&format!("    <not valid DER: {e}>\n")),
        }
        out.push('\n');
    }

    let timestamps = document_timestamps(pdf)?;
    for (i, t) in timestamps.iter().enumerate() {
        out.push_str(&format!(
            "document time-stamp {} (object {} {}):\n",
            i + 1,
            t.object.num,
            t.object.generation
        ));
        let [a, b, c, d] = t.byte_range;
        out.push_str(&format!("  /ByteRange [{a} {b} {c} {d}]\n"));
        out.push_str(&format!(
            "  /Contents <RFC 3161 token {} bytes>\n",
            t.token.len()
        ));
        if t.is_consistent() {
            out.push_str(&format!(
                "  integrity: the token imprints {} of the bytes its /ByteRange covers\n",
                t.digest.map(|alg| alg.name()).unwrap_or("the digest")
            ));
        } else {
            for p in &t.problems {
                out.push_str(&format!("  integrity FAIL: {p}\n"));
            }
        }
        out.push('\n');
    }

    if let Some(dss) = crate::ltv::read_dss(pdf)? {
        let keys = dss.vri_keys().unwrap_or_default();
        out.push_str(&format!(
            "validation data (/DSS): {} certificate(s), {} CRL(s), {} OCSP response(s), \
             {} /VRI key(s)\n",
            dss.certs.len(),
            dss.crls.len(),
            dss.ocsps.len(),
            keys.len(),
        ));
        out.push('\n');
    }
    Ok(out)
}
