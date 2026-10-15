//! Looking at a signed PDF.
//!
//! `openfirma inspect` on a DER file prints a normalized tree, which is what
//! the golden diff runs on. On a PDF there is more to say than the CMS: where
//! the signature claims to cover, whether that claim holds, and which of the
//! optional dictionary entries are present. This module produces that report.
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

    let mut out = Vec::new();
    for object in locations.keys() {
        let Ok(body) = pdf::resolve(pdf, &locations, *object) else {
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

fn read_signature(pdf: &[u8], object: ObjRef, dict: &[u8]) -> Result<Signature> {
    let mut problems = Vec::new();

    let Some(range_bytes) = pdf::get(dict, "/ByteRange") else {
        return Err(Error::Pdf(format!("signature {object} has no /ByteRange")));
    };
    let nums: Vec<usize> = String::from_utf8_lossy(range_bytes)
        .split(|c: char| !c.is_ascii_digit())
        .filter(|t| !t.is_empty())
        .map(|t| t.parse().unwrap_or(0))
        .collect();
    if nums.len() != 4 {
        return Err(Error::Pdf(format!(
            "signature {object} has a /ByteRange with {} numbers, expected 4",
            nums.len()
        )));
    }
    let byte_range = [nums[0], nums[1], nums[2], nums[3]];
    let [a, b, c, d] = byte_range;

    if a != 0 {
        problems.push(format!("the first range starts at {a}, not at 0"));
    }
    // The ranges have to end at a revision boundary, not necessarily at the
    // end of the file: a signature added by an incremental update covers the
    // document as it was when it was made, and later revisions are appended
    // after it. Only the newest signature reaches the end of the file.
    let ends = revision_ends(pdf);
    if !ends.contains(&(c + d)) {
        problems.push(format!(
            "the ranges end at {}, which is not the end of any of the {} revisions",
            c + d,
            ends.len()
        ));
    }
    if b >= c {
        problems.push("the two ranges overlap or are in the wrong order".into());
    }
    let gap = &pdf[b..c.min(pdf.len())];
    if gap.first() != Some(&b'<') || gap.last() != Some(&b'>') {
        problems.push("the gap between the ranges is not exactly the /Contents string".into());
    }

    let cms = contents_der(gap, &mut problems);

    // the digest claim: messageDigest must equal the digest of the two ranges
    if cms.is_empty() {
        problems.push("no CMS could be read from /Contents".into());
    } else {
        let mut covered = Vec::with_capacity(b + d);
        covered.extend_from_slice(&pdf[a..a + b.min(pdf.len())]);
        if c + d <= pdf.len() {
            covered.extend_from_slice(&pdf[c..c + d]);
        }
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
        let mut v = 0usize;
        for b in &raw[2..2 + n] {
            v = (v << 8) | *b as usize;
        }
        2 + n + v
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
    let rest = &der[at + oid.len()..];
    let i = rest.iter().position(|b| *b == 0x04)?;
    let len = *rest.get(i + 1)? as usize;
    Some(rest[i + 2..i + 2 + len].to_vec())
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
    Ok(out)
}
