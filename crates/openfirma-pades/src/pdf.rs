//! Reading just enough of a PDF to append a signature to it.
//!
//! This is not a PDF parser in the general sense. It does not decode content
//! streams, it does not interpret the page tree beyond following references,
//! and it does not read cross-reference streams yet. What it does is find the
//! last trailer, resolve the handful of objects an incremental update has to
//! touch, and cut dictionaries apart and back together at the byte level so
//! that everything we do not touch is reproduced exactly as the input had it.
//!
//! Working at the byte level is the point, not a shortcut. See
//! docs/adr/0003-incremental-update.md: every dictionary we re-serialize from a
//! parsed model is a chance to silently alter a legal document.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use openfirma_core::{Error, Result};

/// An indirect reference, the `N G R` triple.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ObjRef {
    pub num: u32,
    pub generation: u16,
}

impl ObjRef {
    pub fn new(num: u32, generation: u16) -> Self {
        Self { num, generation }
    }
}

impl std::fmt::Display for ObjRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {} R", self.num, self.generation)
    }
}

fn is_ws(b: u8) -> bool {
    matches!(b, 0x00 | b'\t' | b'\n' | 0x0c | b'\r' | b' ')
}

fn is_delim(b: u8) -> bool {
    matches!(
        b,
        b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
    )
}

fn at(data: &[u8], i: usize) -> u8 {
    data.get(i).copied().unwrap_or(0)
}

/// Skips whitespace and `%` comments, which may appear anywhere between tokens.
pub fn skip_ws(data: &[u8], mut i: usize) -> usize {
    loop {
        while i < data.len() && is_ws(data[i]) {
            i += 1;
        }
        if at(data, i) == b'%' {
            i = line_end(data, i);
        } else {
            return i;
        }
    }
}

fn line_end(data: &[u8], i: usize) -> usize {
    match data[i..].iter().position(|b| *b == b'\n') {
        Some(p) => i + p + 1,
        None => data.len(),
    }
}

/// End of a `/Name`, which runs to the next whitespace or delimiter. Names may
/// contain `#xx` escapes, which need no special handling here because `#` is
/// neither whitespace nor a delimiter.
pub(crate) fn name_end(data: &[u8], i: usize) -> usize {
    let mut j = i + 1;
    while j < data.len() && !is_ws(data[j]) && !is_delim(data[j]) {
        j += 1;
    }
    j
}

/// End of a `<hex string>`, which runs to the first `>`.
fn hex_end(data: &[u8], i: usize) -> Result<usize> {
    data[i..]
        .iter()
        .position(|b| *b == b'>')
        .map(|p| i + p + 1)
        .ok_or_else(|| Error::Pdf("unterminated hex string".into()))
}

/// End of a `(literal string)`, honouring backslash escapes and balanced
/// parentheses, which may be nested without escaping.
fn string_end(data: &[u8], i: usize) -> Result<usize> {
    let mut j = i + 1;
    let mut depth = 1usize;
    while j < data.len() {
        match data[j] {
            b'\\' => j += 2,
            b'(' => {
                depth += 1;
                j += 1;
            }
            b')' => {
                depth -= 1;
                j += 1;
                if depth == 0 {
                    return Ok(j);
                }
            }
            _ => j += 1,
        }
    }
    Err(Error::Pdf("unterminated literal string".into()))
}

/// End of a `<<dictionary>>`, tracking nested dictionaries. Strings and names
/// are skipped so that a `>>` inside one of them does not end the scan.
pub(crate) fn dict_end(data: &[u8], start: usize) -> Result<usize> {
    let mut i = start + 2;
    let mut depth = 1usize;
    while i < data.len() {
        match data[i] {
            b'<' if at(data, i + 1) == b'<' => {
                depth += 1;
                i += 2;
            }
            b'>' if at(data, i + 1) == b'>' => {
                depth -= 1;
                i += 2;
                if depth == 0 {
                    return Ok(i);
                }
            }
            b'<' => i = hex_end(data, i)?,
            b'(' => i = string_end(data, i)?,
            b'%' => i = line_end(data, i),
            b'/' => i = name_end(data, i),
            _ => i += 1,
        }
    }
    Err(Error::Pdf("unterminated dictionary".into()))
}

fn array_end(data: &[u8], start: usize) -> Result<usize> {
    let mut i = start + 1;
    let mut depth = 1usize;
    while i < data.len() {
        match data[i] {
            b'[' => {
                depth += 1;
                i += 1;
            }
            b']' => {
                depth -= 1;
                i += 1;
                if depth == 0 {
                    return Ok(i);
                }
            }
            b'<' if at(data, i + 1) == b'<' => i = dict_end(data, i)?,
            b'<' => i = hex_end(data, i)?,
            b'(' => i = string_end(data, i)?,
            b'%' => i = line_end(data, i),
            b'/' => i = name_end(data, i),
            _ => i += 1,
        }
    }
    Err(Error::Pdf("unterminated array".into()))
}

/// End of a bare token: a number, `true`, `false`, `null`, or the `R` of a
/// reference.
fn token_end(data: &[u8], i: usize) -> usize {
    let mut j = i;
    while j < data.len() && !is_ws(data[j]) && !is_delim(data[j]) {
        j += 1;
    }
    j
}

/// End of one complete value, whatever its type. An indirect reference is three
/// tokens that together form one value, and telling it apart from a plain
/// integer is what the lookahead here is for.
pub(crate) fn value_end(data: &[u8], start: usize) -> Result<usize> {
    let i = skip_ws(data, start);
    match at(data, i) {
        b'<' if at(data, i + 1) == b'<' => dict_end(data, i),
        b'<' => hex_end(data, i),
        b'(' => string_end(data, i),
        b'[' => array_end(data, i),
        b'/' => Ok(name_end(data, i)),
        0 if i >= data.len() => Err(Error::Pdf("value ends at the end of the file".into())),
        _ => {
            let first = token_end(data, i);
            match indirect_ref_end(data, i, first) {
                Some(end) => Ok(end),
                None => Ok(first),
            }
        }
    }
}

/// If `data[i..]` holds `N G R`, returns the offset just past the `R`.
fn indirect_ref_end(data: &[u8], i: usize, first_end: usize) -> Option<usize> {
    let num = std::str::from_utf8(&data[i..first_end]).ok()?;
    if num.is_empty() || !num.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let g_start = skip_ws(data, first_end);
    let g_end = token_end(data, g_start);
    let generation = std::str::from_utf8(&data[g_start..g_end]).ok()?;
    if generation.is_empty() || !generation.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let r_start = skip_ws(data, g_end);
    if at(data, r_start) != b'R' {
        return None;
    }
    let r_end = r_start + 1;
    // "R" must be a whole token, not the start of a longer word
    if r_end < data.len() && !is_ws(data[r_end]) && !is_delim(data[r_end]) {
        return None;
    }
    Some(r_end)
}

/// The key/value pairs of a dictionary, as absolute ranges into `dict`.
///
/// `dict` must be exactly the dictionary, starting at `<<` and ending at `>>`.
/// A key is only a key at depth zero: `/XYZ` inside `/Dest [3 0 R /XYZ ...]` is
/// an array element, and treating it as a key would corrupt the dictionary on
/// the next rewrite.
pub fn items(dict: &[u8]) -> Result<Vec<(Range<usize>, Range<usize>)>> {
    if !dict.starts_with(b"<<") {
        return Err(Error::Pdf("not a dictionary".into()));
    }
    let end = dict_end(dict, 0)?;
    let mut out = Vec::new();
    let mut i = 2;
    while i < end {
        i = skip_ws(dict, i);
        if i + 1 >= end || at(dict, i) == b'>' {
            break;
        }
        if at(dict, i) != b'/' {
            return Err(Error::Pdf(format!(
                "expected a name key at offset {i}, found {:?}",
                dict.get(i).map(|b| *b as char)
            )));
        }
        let key_end = name_end(dict, i);
        let key = i..key_end;
        let val_end = value_end(dict, key_end)?;
        // the value is what sits between the key and the next key, minus the
        // whitespace that separates them on both sides
        let mut v_start = key_end;
        while v_start < val_end && is_ws(dict[v_start]) {
            v_start += 1;
        }
        let mut v_end = val_end;
        while v_end > v_start && is_ws(dict[v_end - 1]) {
            v_end -= 1;
        }
        out.push((key, v_start..v_end));
        i = val_end;
    }
    Ok(out)
}

/// The raw bytes of `key`'s value, or `None` if the dictionary does not have it.
pub fn get<'a>(dict: &'a [u8], key: &str) -> Option<&'a [u8]> {
    let span = get_span(dict, key)?;
    Some(&dict[span])
}

pub fn get_span(dict: &[u8], key: &str) -> Option<Range<usize>> {
    for (k, v) in items(dict).ok()? {
        if &dict[k] == key.as_bytes() {
            return Some(v);
        }
    }
    None
}

/// Returns `dict` with `key` set to `value`, replacing it if it was there and
/// appending it before the closing `>>` if it was not. Every other byte of the
/// dictionary is left untouched.
pub fn set(dict: &[u8], key: &str, value: &[u8]) -> Result<Vec<u8>> {
    if !dict.ends_with(b">>") {
        return Err(Error::Pdf(format!(
            "cannot set {key}: the dictionary does not end with >>"
        )));
    }
    if let Some(span) = get_span(dict, key) {
        let mut out = Vec::with_capacity(dict.len());
        out.extend_from_slice(&dict[..span.start]);
        out.extend_from_slice(value);
        out.extend_from_slice(&dict[span.end..]);
        return Ok(out);
    }
    let cut = dict.len() - 2;
    let mut out = Vec::with_capacity(dict.len() + value.len() + key.len() + 2);
    out.extend_from_slice(&dict[..cut]);
    // keep the closing >> on its own only if the dictionary was already laid
    // out that way, otherwise stay on the same line
    let needs_space = cut > 0 && !is_ws(dict[cut - 1]);
    if needs_space {
        out.push(b' ');
    }
    out.extend_from_slice(key.as_bytes());
    out.push(b' ');
    out.extend_from_slice(value);
    out.push(b' ');
    out.extend_from_slice(&dict[cut..]);
    Ok(out)
}

/// Parses `N G R` into an [`ObjRef`].
pub fn parse_ref(bytes: &[u8]) -> Option<ObjRef> {
    let mut parts = bytes.split(|b| is_ws(*b)).filter(|p| !p.is_empty());
    let num = std::str::from_utf8(parts.next()?)
        .ok()?
        .parse::<u32>()
        .ok()?;
    let generation = std::str::from_utf8(parts.next()?)
        .ok()?
        .parse::<u32>()
        .ok()?;
    if parts.next()? != b"R" || parts.next().is_some() {
        return None;
    }
    Some(ObjRef {
        num,
        generation: generation.try_into().ok()?,
    })
}

/// Every indirect reference inside an array value.
pub fn array_refs(value: &[u8]) -> Result<Vec<ObjRef>> {
    let trimmed = trim_ws(value);
    if !trimmed.starts_with(b"[") {
        return Err(Error::Pdf("expected an array".into()));
    }
    let end = array_end(trimmed, 0)?;
    let mut out = Vec::new();
    let mut i = 1;
    while i < end.saturating_sub(1) {
        i = skip_ws(trimmed, i);
        if i + 1 >= end || at(trimmed, i) == b']' {
            break;
        }
        let v_end = value_end(trimmed, i)?;
        if let Some(r) = parse_ref(&trimmed[i..v_end]) {
            out.push(r);
        }
        i = v_end;
    }
    Ok(out)
}

pub fn trim_ws(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|b| !is_ws(*b)).unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|b| !is_ws(*b))
        .map(|p| p + 1)
        .unwrap_or(start);
    &bytes[start..end]
}

/// Where an object lives in the file.
///
/// A document written by a modern producer keeps most of its objects inside
/// compressed object streams, so "the offset of object N" is not always the
/// answer. A type 2 cross-reference entry names an object stream and an index
/// within it instead.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Location {
    /// At this byte offset, as `N G obj ... endobj`.
    Direct(usize),
    /// Inside the object stream `stream`, as its `index`th object.
    InObjectStream { stream: ObjRef, index: u32 },
}

/// The in-use objects of one cross-reference section.
type XrefEntries = Vec<(ObjRef, Location)>;

/// The object numbers one cross-reference section declares FREE (a classic
/// entry of type `f`, or a cross-reference stream row of type 0). A reader
/// resolves an indirect reference by looking up the newest section that names
/// the number: a free entry there means the number is not in use, and NO older
/// definition of it resolves any more (ISO 32000-1 7.5.4). Ignoring these was
/// round 2's N-1: an appended revision could mark a signed object free and
/// `verify` still answered OK, while qpdf, Ghostscript and Acrobat showed the
/// document without it.
type XrefFrees = Vec<u32>;

/// What the last trailer of a document says.
#[derive(Clone, Debug)]
pub struct Trailer {
    pub root: ObjRef,
    /// `/Size` as written by the file: `None` when the key is absent or not a
    /// number (finding B-1 — read as 0 it made new objects reuse existing
    /// numbers and silently overwrite pages).
    pub size: Option<u32>,
    pub info: Option<ObjRef>,
    /// `startxref` of the previous revision, when this is an incremental update.
    pub prev: Option<usize>,
    /// Offset of the `xref` keyword or xref stream object of this revision.
    pub at: usize,
    /// Trailer keys no earlier revision may change (ISO 32000-1 7.5.6): a
    /// trailer that adds one which an earlier revision already had, with a
    /// different value, changes the document without saying so in its new
    /// cross-reference section. `/Encrypt` is the one a signature must never
    /// smuggle past (finding C-2), because the new strings would not be
    /// encrypted.
    pub immutable: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl Trailer {
    /// Keys of a trailer that the revision appended on top must not change.
    /// `/Encrypt` and every future key in this family. `/Root`, `/Info`,
    /// `/Size` and `/Prev` are deliberately absent: those are exactly what an
    /// incremental update legitimately rewrites.
    ///
    /// `/ID` was in this list and is not any more. Refusing a trailer whose
    /// `/ID` differs from the newest one's was measured throwing away documents
    /// the reference tool itself writes: iText 2.1.7, which is what AutoFirma
    /// 1.9.1 signs with, regenerates the whole `/ID` array on the incremental
    /// update it appends for a second signature, so a document AutoFirma signed
    /// twice could not be read at all — not verified, not co-signed — with
    /// "revision 2 changes /ID". Nothing in this crate reads `/ID` (our own
    /// writer still carries it over byte for byte, which is what PDF/A and
    /// PDF 2.0 ask of a *writer*, finding A-1: `anonymous_comment` in the
    /// tests), and for the unencrypted documents this crate touches the
    /// identifier is an identity hint, not a rule a verdict rests on.
    fn immutable_keys(dict: &[u8]) -> Result<BTreeMap<Vec<u8>, Vec<u8>>> {
        const FIXED: [&str; 1] = ["/Encrypt"];
        let mut out = BTreeMap::new();
        for (k, v) in items(dict)? {
            let key = &dict[k];
            if FIXED.iter().any(|f| key == f.as_bytes()) {
                out.insert(key.to_vec(), dict[v].to_vec());
            }
        }
        Ok(out)
    }

    /// `/Root`, `/Info` and `/Size` of the trailer, and refuses a trailer with
    /// no readable `/Size` (finding B-1): every new object number derives from
    /// it, and inventing one that collides with an existing page is a silent
    /// document alteration. The error says what to run.
    pub fn mandatory(&self) -> Result<(ObjRef, Option<ObjRef>, u32)> {
        let size = self.size.ok_or_else(|| {
            Error::Pdf(
                "the trailer of this document has no readable /Size, so openfirma cannot know \
                 which object numbers are free; rewrite the file first with `qpdf --decrypt` \
                 (a repair pass fixes it even when the file is not encrypted)"
                    .to_string(),
            )
        })?;
        Ok((self.root, self.info, size))
    }

    /// The `/Info` reference of a new revision: the one it carries over, or,
    /// when the original had none, `new_info_ref` — the object the caller is
    /// about to write. A trailer that omits it would leave that dictionary
    /// orphaned (finding M-1).
    pub fn info_for_revision(&self, new_info_ref: ObjRef) -> ObjRef {
        self.info.unwrap_or(new_info_ref)
    }
}

/// Offset of the last `startxref` in the file, which is where the most recent
/// revision's cross-reference section begins.
///
/// Searched from the end because a linearized file has two, and a signed file
/// has one per revision. Only the last one describes the current state.
pub fn last_startxref(data: &[u8]) -> Result<usize> {
    let key = b"startxref";
    // Searched from the end (see the doc above), and only a whole keyword
    // counts: binary noise that merely contains the word names nothing, and
    // claiming an offset from it would bury the real cross-reference at the
    // back of the file. The token rule costs nothing on ordinary files, where
    // the keyword always sits on its own line between `endobj` and an offset.
    let pos = (0..data.len().saturating_sub(key.len()) + 1)
        .rev()
        .find(|at| {
            &data[*at..*at + key.len()] == key
                && (*at == 0 || is_ws(data[at - 1]) || is_delim(data[at - 1]))
                && data
                    .get(*at + key.len())
                    .is_none_or(|b| is_ws(*b) || is_delim(*b))
        })
        .ok_or_else(|| Error::Pdf("no startxref keyword, is this a PDF?".into()))?;
    let after = skip_ws(data, pos + key.len());
    let end = token_end(data, after);
    let text = std::str::from_utf8(&data[after..end])
        .map_err(|_| Error::Pdf("startxref offset is not ASCII".into()))?;
    text.parse::<usize>()
        .map_err(|_| Error::Pdf(format!("startxref offset is not a number: {text:?}")))
}

/// Reads the trailer dictionary of the revision whose cross-reference section
/// starts at `xref_at`.
/// Whether the cross-reference section starting at `xref_at` is a
/// cross-reference *stream* (an `N G obj << /Type /XRef …` at that offset)
/// rather than a classic table (the keyword `xref`).
///
/// The incremental writer needs it: a revision whose `/Prev` points at a
/// stream has to be a stream itself. iText — the reader inside AutoFirma —
/// follows `/Prev` from a stream as a stream and from a table with
/// `readXrefSection`, which requires the word `xref`, so a classic table over a
/// stream is a chain it refuses to walk: it rebuilds the file and will not
/// sign it in append mode (round 2, N-3).
pub fn section_is_stream(data: &[u8], xref_at: usize) -> bool {
    let i = skip_ws(data, xref_at);
    data.get(i..).is_some_and(|rest| !rest.starts_with(b"xref"))
}

pub fn trailer(data: &[u8], xref_at: usize) -> Result<Trailer> {
    // finding M-6: the offset comes from the file (a `startxref` number or a
    // `/Prev`), so it may point past the end. Checked where it is read, before
    // anything slices with it; `skip_ws` returns its argument unchanged past
    // the end, so every caller would otherwise index `data[i..]` at a position
    // one byte outside the buffer.
    if xref_at > data.len() {
        return Err(Error::Pdf(format!(
            "the cross-reference offset {xref_at} is past the end of a {} byte file",
            data.len()
        )));
    }
    let dict = trailer_dict(data, xref_at)?;
    // finding C-2 before anything else: an encrypted document must be refused
    // at the first thing a signing pass reads, not after it has parsed and
    // rewritten pieces of a file whose streams are ciphertext.
    if get(&dict, "/Encrypt").is_some() {
        return Err(Error::Pdf(
            "this PDF is encrypted: its trailer carries /Encrypt, and openfirma cannot sign \
             an encrypted document — the signature strings it writes (/T, /M, /Reason) would \
             not be encrypted while everything else stays ciphertext, and readers see a \
             broken file. Decrypt it first: `qpdf --input-password=<pass> --decrypt in.pdf \
             out.pdf` (drop --input-password when the user password is empty)"
                .into(),
        ));
    }
    let root_bytes =
        get(&dict, "/Root").ok_or_else(|| Error::Pdf("the trailer has no /Root".into()))?;
    let root = parse_ref(root_bytes)
        .ok_or_else(|| Error::Pdf("/Root is not an indirect reference".into()))?;
    // finding B-1: absent or unreadable is None, not 0. Callers that need a
    // number must go through Trailer::mandatory and refuse the document.
    let size = get(&dict, "/Size").and_then(|b| {
        std::str::from_utf8(trim_ws(b))
            .ok()?
            .trim()
            .parse::<u32>()
            .ok()
    });
    let info = get(&dict, "/Info").and_then(parse_ref);
    let prev = get(&dict, "/Prev").and_then(|b| {
        std::str::from_utf8(trim_ws(b))
            .ok()?
            .trim()
            .parse::<usize>()
            .ok()
    });
    // The encryption audit walks /Prev (finding C-2: a document encrypted from
    // its first revision carries /Encrypt in every trailer; one that a hostile
    // writer added only to an earlier revision is still the same reader-visible
    // lie, and ISO 32000-1 7.5.6 forbids changing /ID or /Encrypt across
    // revisions at all). A broken chain that never yields either key does not
    // refuse a document the newest trailer describes honestly.
    let mut immutable = Trailer::immutable_keys(&dict)?;
    let mut seen = std::collections::BTreeSet::new();
    seen.insert(xref_at);
    let mut cur = prev;
    for depth in 1..100 {
        let Some(at) = cur else { break };
        if at > data.len() || !seen.insert(at) {
            // a dead end or a repeated section is not evidence of encryption;
            // the bounds check also keeps this audit from slicing with an
            // offset that comes from the file (finding M-6, the /Prev half)
            break;
        }
        let Ok(dict) = trailer_dict(data, at) else {
            break;
        };
        let found = Trailer::immutable_keys(&dict)?;
        for (key, value) in found {
            if key == b"/Encrypt" {
                return Err(Error::Pdf(format!(
                    "this PDF is encrypted: revision {} of it carries /Encrypt in its \
                     trailer. openfirma cannot sign an encrypted document — the signature \
                     strings it writes would not be encrypted. Decrypt it first: `qpdf \
                     --input-password=<pass> --decrypt in.pdf out.pdf`",
                    depth + 1
                )));
            }
            if let Some(newer) = immutable.get(&key) {
                // nested on purpose: `&& newer != &value` in the if-let head
                // is a let-chain, stable only since 1.88 — this crate's floor
                // is 1.85 and CI's msrv job proves it (review 07, H-8).
                if newer != &value {
                    return Err(Error::Pdf(format!(
                        "revision {} changes {}, which the newest revision already fixed to a \
                         different value; a conforming incremental update may not",
                        depth + 1,
                        String::from_utf8_lossy(&key)
                    )));
                }
            }
            immutable.entry(key).or_insert(value);
        }
        cur = get(&dict, "/Prev").and_then(|b| {
            std::str::from_utf8(trim_ws(b))
                .ok()?
                .trim()
                .parse::<usize>()
                .ok()
        });
    }
    Ok(Trailer {
        root,
        size,
        info,
        prev,
        at: xref_at,
        immutable,
    })
}

/// The trailer dictionary of one revision as owned bytes: the classic table's
/// `trailer << … >>`, a bare dictionary, or an xref stream object's dictionary.
/// `trailer()` reads its fields from this; incremental writers carry it over
/// whole (finding A-1), which is what [`Update::carry_trailer`] does with it.
pub fn trailer_dict(data: &[u8], xref_at: usize) -> Result<Vec<u8>> {
    let i = skip_ws(data, xref_at);
    if data[i..].starts_with(b"xref") {
        // classic table: skip it, then read the trailer dictionary that follows
        let mut j = skip_ws(data, i + 4);
        loop {
            j = skip_ws(data, j);
            if data[j..].starts_with(b"trailer") {
                j = skip_ws(data, j + 7);
                break;
            }
            // a subsection header is two integers, then count entries of three
            // tokens each; walk them without assuming the 20 byte layout, which
            // broken writers get wrong
            let first_end = token_end(data, j);
            if first_end == j {
                return Err(Error::Pdf("malformed cross-reference table".into()));
            }
            let count_start = skip_ws(data, first_end);
            let count_end = token_end(data, count_start);
            let count = std::str::from_utf8(&data[count_start..count_end])
                .map_err(|_| Error::Pdf("subsection count is not ASCII".into()))?
                .trim()
                .parse::<usize>()
                .map_err(|_| Error::Pdf("subsection count is not a number".into()))?;
            let mut k = count_end;
            for _ in 0..count {
                // the count is the file's claim, and the file may end first;
                // without this an entry that reads no byte would spin the
                // claimed number of times, which a hostile count makes
                // unbounded
                if k >= data.len() {
                    return Err(Error::Pdf(format!(
                        "the cross-reference table ends before the {count} entries its \
                         subsection header claims"
                    )));
                }
                let before = k;
                k = skip_ws(data, k);
                // same rule as read_xref_table: a subsection that ends without
                // its mandatory end-of-line is followed straight by `trailer`,
                // not by another header — three more tokens would eat the
                // keyword and the trailer dictionary.
                if data[k..].starts_with(b"trailer") {
                    j = skip_ws(data, k + 7);
                    return Ok(data[j..dict_end(data, j)?].to_vec());
                }
                let a = token_end(data, k);
                k = skip_ws(data, a);
                let b = token_end(data, k);
                k = skip_ws(data, b);
                k = token_end(data, k); // n or f
                if k == before {
                    return Err(Error::Pdf(
                        "malformed cross-reference table: an entry does not advance".into(),
                    ));
                }
            }
            j = k;
        }
        let end = dict_end(data, j)?;
        Ok(data[j..end].to_vec())
    } else if data[i..].starts_with(b"<<") {
        // a bare dictionary, which no conforming writer produces but which is
        // cheap to accept
        let end = dict_end(data, i)?;
        Ok(data[i..end].to_vec())
    } else {
        // a cross-reference stream is an ordinary indirect object whose
        // dictionary doubles as the trailer. Reading that dictionary needs no
        // decompression, only locating objects through it does, which is why
        // trailer() succeeds on a document that object_offsets() refuses.
        let body = object_body(data, i)?;
        let dict = &data[body];
        if !dict.starts_with(b"<<") {
            return Err(Error::Pdf(format!(
                "startxref at {xref_at} points at neither an xref table nor a dictionary"
            )));
        }
        Ok(dict.to_vec())
    }
}

/// Every in-use object of the document, following `/Prev` through earlier
/// revisions.
///
/// Later revisions are walked first, and **the newest section that names an
/// object number decides it**: a newer in-use entry wins over an older
/// definition (with whichever generation it carries — a reference to the old
/// generation no longer resolves), and a newer FREE entry means the object is
/// gone, so no older definition of that number may be restored. Round 2's N-1
/// was the missing second half of that rule: the map only ever grew, so a
/// revision that marked a signed object free changed nothing for `verify` while
/// every conforming reader dropped the object and the content it held with it.
///
/// A hybrid-reference file is the one place a stream and a table describe the
/// same section: the classic table marks the hybrid objects free so old readers
/// ignore them, and `/XRefStm` carries their real entries. The stream is read
/// first for exactly that reason.
pub fn object_locations(data: &[u8], xref_at: usize) -> Result<BTreeMap<ObjRef, Location>> {
    let mut map = BTreeMap::new();
    // object numbers a newer section has already decided (in use or free)
    let mut decided: BTreeSet<u32> = BTreeSet::new();
    let mut cur = Some(xref_at);
    let mut revisions = 0;
    while let Some(at) = cur {
        revisions += 1;
        if revisions > 100 {
            return Err(Error::Pdf(
                "more than 100 revisions, /Prev is probably a loop".into(),
            ));
        }
        // finding M-6: every offset here comes from the file — startxref,
        // /XRefStm, /Prev — and one past the end used to index `data[i..]`
        // and panic. Checked where it enters the loop.
        if at > data.len() {
            return Err(Error::Pdf(format!(
                "the cross-reference offset {at} (revision {revisions}) is past the end of a \
                 {} byte file",
                data.len()
            )));
        }
        let i = skip_ws(data, at);
        let (entries, frees, dict) = if data[i..].starts_with(b"xref") {
            read_xref_table(data, i)?
        } else {
            read_xref_stream(data, i)?
        };
        // A hybrid reference file carries a classic table for old readers and
        // points at a cross-reference stream for the objects only it knows
        // about. The stream's entries come first: the classic table of such a
        // file marks those same numbers free on purpose.
        let mut stream: Option<(XrefEntries, XrefFrees)> = None;
        if let Some(stm) = get(&dict, "/XRefStm").and_then(parse_uint) {
            // A /XRefStm the reader cannot read is not "absent": it is a section
            // of this revision that says which objects are free, and skipping it
            // let a hybrid file hide a deletion with a row type the old reader
            // rejected (round 3's N3-2). /XRefStm is the file's claim, so the
            // offset is bounds-checked the same way as /Prev.
            if (stm as usize) > data.len() {
                return Err(Error::Pdf(format!(
                    "the /XRefStm offset {stm} is past the end of a {} byte file",
                    data.len()
                )));
            }
            let (extra, extra_frees, _) = read_xref_stream(data, stm as usize)?;
            stream = Some((extra, extra_frees));
        }
        if let Some((sentries, sfrees)) = stream {
            record_section(&mut map, &mut decided, sentries, sfrees)?;
        }
        record_section(&mut map, &mut decided, entries, frees)?;
        cur = get(&dict, "/Prev").and_then(parse_uint).map(|v| v as usize);
    }
    Ok(map)
}

/// Fold one cross-reference section into the map: the first decision about an
/// object number wins (sections are walked newest first), and a free entry is a
/// decision too — the numbers it lists may not be restored by an older section.
///
/// One section naming the same number TWICE is refused (round 3's N3-1). Both
/// list-building readers return in-use entries and frees separately, so a table
/// that says "6 free" and then "6 at the old offset" reached this function as one
/// free and one entry with no order left to honour; the gate kept the in-use one
/// and judged zero changes while qpdf and Ghostscript take the FIRST entry — the
/// free one — and render the document without the signed object. No legitimate
/// writer repeats a number in one section, and refusing costs nothing.
fn record_section(
    map: &mut BTreeMap<ObjRef, Location>,
    decided: &mut BTreeSet<u32>,
    entries: XrefEntries,
    frees: XrefFrees,
) -> Result<()> {
    let mut seen: BTreeSet<u32> = BTreeSet::new();
    for (r, _) in &entries {
        if !seen.insert(r.num) {
            return Err(Error::Pdf(format!(
                "a cross-reference section names object {} more than once: the order of \
                 the entries decides what readers see, and the sections the gate reads do \
                 not keep it",
                r.num
            )));
        }
    }
    for num in &frees {
        if !seen.insert(*num) {
            return Err(Error::Pdf(format!(
                "a cross-reference section names object {num} more than once: the order of \
                 the entries decides what readers see, and the sections the gate reads do \
                 not keep it"
            )));
        }
    }
    for (r, loc) in entries {
        if decided.insert(r.num) {
            map.insert(r, loc);
        }
    }
    for num in frees {
        decided.insert(num);
    }
    Ok(())
}

/// One classic cross-reference table: its in-use entries and its trailer.
///
/// Entries are walked by token rather than by assuming the 20 byte layout the
/// specification mandates, because a writer that gets the layout wrong still
/// produces a file that every reader accepts, and refusing to sign one is a
/// worse outcome than being lenient here.
fn read_xref_table(data: &[u8], i: usize) -> Result<(XrefEntries, XrefFrees, Vec<u8>)> {
    let mut entries = Vec::new();
    let mut frees = Vec::new();
    let mut j = skip_ws(data, i + 4);
    loop {
        j = skip_ws(data, j);
        if data[j..].starts_with(b"trailer") {
            let t = skip_ws(data, j + 7);
            let end = dict_end(data, t)?;
            return Ok((entries, frees, data[t..end].to_vec()));
        }
        let first_end = token_end(data, j);
        // A table that runs out of its own subsection headers before any
        // `trailer` keyword (a hostile or broken writer's truncated append)
        // would otherwise spin here forever: with no digits the header parse
        // reads nothing and `j` never moves. The loop always makes progress on
        // well-formed tables, where each header is followed by its entries.
        if first_end == j {
            return Err(Error::Pdf(
                "the cross-reference table ends without a trailer keyword".into(),
            ));
        }
        let count_start = skip_ws(data, first_end);
        let count_end = token_end(data, count_start);
        let first = parse_uint(&data[j..first_end])
            .ok_or_else(|| Error::Pdf("subsection start is not a number".into()))?;
        let count = parse_uint(&data[count_start..count_end])
            .ok_or_else(|| Error::Pdf("subsection count is not a number".into()))?;
        let mut k = count_end;
        for n in 0..count {
            // the entry count is the file's claim and the file may end first:
            // an entry reads three tokens, and past the end all three are
            // empty, which would spin the claimed number of times
            if k >= data.len() {
                return Err(Error::Pdf(format!(
                    "the cross-reference table ends after {n} of the {count} entries its \
                     subsection header claims"
                )));
            }
            k = skip_ws(data, k);
            // the standard's own spelling of a subsection start: object N on a
            // line of its own, where the previous table ended without an
            // end-of-line before `trailer` (every real writer emits one, and a
            // header parse that read "trailer" as a number would otherwise
            // refuse or misattribute the rest of the file)
            if data[k..].starts_with(b"trailer") {
                let t = skip_ws(data, k + 7);
                let end = dict_end(data, t)?;
                return Ok((entries, frees, data[t..end].to_vec()));
            }
            let off_end = token_end(data, k);
            let gen_start = skip_ws(data, off_end);
            let gen_end = token_end(data, gen_start);
            let type_start = skip_ws(data, gen_end);
            let kind = at(data, type_start);
            let offset = parse_uint(&data[k..off_end]).unwrap_or(0) as usize;
            let generation = parse_uint(&data[gen_start..gen_end]).unwrap_or(0) as u16;
            // the object number is the subsection start plus the entry index,
            // and both come out of the file: a pair that does not fit in an
            // object number is a broken table, not a wrapped one
            let Some(num) = first.checked_add(n) else {
                return Err(Error::Pdf(format!(
                    "the cross-reference subsection starting at {first} runs past the \
                     object number space at entry {n}"
                )));
            };
            // object 0 is always the head of the free list, never an object
            if num > 0 {
                if kind == b'n' {
                    entries.push((ObjRef::new(num, generation), Location::Direct(offset)));
                } else if kind == b'f' {
                    frees.push(num);
                }
            }
            k = type_start + 1;
        }
        j = k;
    }
}

/// The most cross-reference entries one revision may put in the table. A
/// stream's decoded bytes already bound its row count (`decoded.len()/row`),
/// but not what those rows are turned into: an 87 KB flate legitimately
/// inflates to 90 MB of `/W [1 1 1]` rows — under every stage cap, so the
/// decode side refuses nothing — and walking them into a
/// `Vec<(ObjRef, Location)>` plus the location map costs ~2 GB of RSS and
/// 47 s of CPU for a document that holds no objects at all (finding C-1's
/// second half: the stream cap closed the decode side of the bomb, this
/// closes the materialisation side). The bound is derived from the file, not
/// from a wish: every in-use entry names an object header (`"N G obj"` and
/// its separators) somewhere inside the *file*, so the file's own length
/// bounds how many entries can honestly exist. Eight bytes is the smallest
/// real object header (a one-digit number, a generation, `obj`, two line
/// breaks), with headroom on top of it for documents whose objects are denser
/// than that floor: an 87 KB attack file is refused at its 30-million claim,
/// while a document as large as the decoded-stream cap (`crate::stream::
/// MAX_DECODED_STREAM`) could index over six million real objects — no
/// conforming writer gets near that.
const MAX_XREF_ENTRIES_FACTOR: usize = 8;
fn max_xref_entries(data_len: usize) -> usize {
    (data_len / 8).max(4096) * MAX_XREF_ENTRIES_FACTOR
}

/// One cross-reference stream: the compressed form, whose dictionary doubles
/// as the trailer.
///
/// This is what iText writes, so without it a document AutoFirma has already
/// signed cannot be read, let alone signed again.
fn read_xref_stream(data: &[u8], obj_at: usize) -> Result<(XrefEntries, XrefFrees, Vec<u8>)> {
    let dict_span = object_body(data, obj_at)?;
    let dict = data[dict_span].to_vec();
    let is_xref = get(&dict, "/Type")
        .map(|t| trim_ws(t) == b"/XRef")
        .unwrap_or(false);
    if !is_xref {
        return Err(Error::Pdf(format!(
            "the object at {obj_at} is not a cross-reference stream"
        )));
    }
    let raw = stream_raw(data, obj_at)?;
    let decoded = crate::stream::decode(&dict, &raw)?;

    // /W gives the width in bytes of each of the three fields of an entry
    let widths = int_array(
        get(&dict, "/W")
            .ok_or_else(|| Error::Pdf("the cross-reference stream has no /W".into()))?,
    )?;
    if widths.len() != 3 {
        return Err(Error::Pdf(format!(
            "/W must have three entries, this has {}",
            widths.len()
        )));
    }
    let size = get(&dict, "/Size").and_then(parse_uint).unwrap_or(0);
    let index = match get(&dict, "/Index") {
        Some(v) => int_array(v)?,
        None => vec![0, size],
    };
    if index.len() % 2 != 0 {
        return Err(Error::Pdf("/Index must hold pairs of numbers".into()));
    }

    let row = widths.iter().map(|w| *w as usize).sum::<usize>();
    if row == 0 {
        return Err(Error::Pdf(
            "/W is all zeros, there is nothing to read".into(),
        ));
    }
    // The most entries this revision may put in the table, checked before
    // anything is materialised: `claimed` (the /Index pairs, or `/Size` when
    // there is no /Index) is what the loop below would turn into a `Vec`.
    let claimed: u64 = index.chunks_exact(2).map(|p| u64::from(p[1])).sum();
    if claimed as usize > max_xref_entries(data.len()) {
        return Err(Error::Pdf(format!(
            "the cross-reference stream claims {claimed} entries, past the {} a file of {} \
             bytes can hold: every in-use entry names an object header the file must contain, \
             and a table this many times larger than its own file is not a document",
            max_xref_entries(data.len()),
            data.len()
        )));
    }
    // finding M-6: the widths are the file's claim, and `widths[0] +
    // widths[1]` as u32 panicked on overflow in debug builds (u32::MAX + 1).
    // Computed in usize, which cannot overflow here on a 64 bit target. A
    // single field wider than the whole row is legal by the letter of the
    // specification — only `/W [0 0 0]` is not — and no conforming writer
    // produces one; the reader tolerates it because the row-bound check below
    // refuses every row before a field of such a width could be sliced, so
    // the hostile shape costs an error, not a panic.
    let starts = [
        0usize,
        widths[0] as usize,
        widths[0] as usize + widths[1] as usize,
    ];

    let mut entries = Vec::new();
    let mut frees = Vec::new();
    let mut pos = 0usize;
    for pair in index.chunks_exact(2) {
        let (first, count) = (pair[0], pair[1]);
        for n in 0..count {
            if pos + row > decoded.len() {
                return Err(Error::Pdf(
                    "the cross-reference stream is shorter than its /Index claims".into(),
                ));
            }
            // a zero width field is absent rather than zero, and the type then
            // defaults to 1, which is what the specification says
            let field = |k: usize| -> u64 {
                if widths[k] == 0 {
                    return if k == 0 { 1 } else { 0 };
                }
                let from = pos + starts[k];
                let mut v = 0u64;
                for b in &decoded[from..from + widths[k] as usize] {
                    v = (v << 8) | u64::from(*b);
                }
                v
            };
            let (kind, second, third) = (field(0), field(1), field(2));
            pos += row;
            let Some(num) = first.checked_add(n) else {
                return Err(Error::Pdf(format!(
                    "the /Index pair starting at {first} runs past the object number space"
                )));
            };
            if num == 0 {
                continue; // the head of the free list
            }
            match kind {
                0 => frees.push(num), // free: it hides every older definition
                1 => entries.push((
                    ObjRef::new(num, third as u16),
                    Location::Direct(second as usize),
                )),
                2 => entries.push((
                    ObjRef::new(num, 0),
                    Location::InObjectStream {
                        stream: ObjRef::new(second as u32, 0),
                        index: third as u32,
                    },
                )),
                // ISO 32000-1 Table 18: a type the reader does not know is a
                // reference to null — i.e. the object is not defined by this
                // revision. Treating it as an error let a hybrid /XRefStm smuggle
                // a "free" row past the gate by adding a third row of type 3
                // (round 3's N3-2). Null is a decision for the gate: it hides the
                // older definition, which is exactly what a deletion is.
                _ => frees.push(num),
            }
        }
    }
    Ok((entries, frees, dict))
}

/// The integers of an array value.
fn int_array(value: &[u8]) -> Result<Vec<u32>> {
    let v = trim_ws(value);
    if !v.starts_with(b"[") {
        return Err(Error::Pdf("expected an array of integers".into()));
    }
    let end = array_end(v, 0)?;
    let mut out = Vec::new();
    let mut i = 1;
    while i < end.saturating_sub(1) {
        i = skip_ws(v, i);
        if i + 1 >= end || at(v, i) == b']' {
            break;
        }
        let tok = token_end(v, i);
        out.push(parse_uint(&v[i..tok]).ok_or_else(|| {
            Error::Pdf("an array that should hold integers has something else in it".into())
        })?);
        i = tok;
    }
    Ok(out)
}

pub(crate) fn parse_uint(bytes: &[u8]) -> Option<u32> {
    std::str::from_utf8(trim_ws(bytes))
        .ok()?
        .trim()
        .parse::<u32>()
        .ok()
}

/// The body of the object at `offset`, without the `N G obj` header or the
/// `endobj` trailer. For a stream object this is its dictionary.
pub fn object_body(data: &[u8], offset: usize) -> Result<Range<usize>> {
    let mut i = offset;
    // "N G obj"
    let num_end = token_end(data, i);
    if num_end == i {
        return Err(Error::Pdf(format!("no object number at offset {offset}")));
    }
    i = skip_ws(data, num_end);
    let gen_end = token_end(data, i);
    i = skip_ws(data, gen_end);
    if !data[i..].starts_with(b"obj") {
        return Err(Error::Pdf(format!(
            "expected 'obj' at offset {i}, found {:?}",
            // the preview is clamped: an object header that runs into the end
            // of the file is exactly the case this error reports
            String::from_utf8_lossy(&data[i..(i + 8).min(data.len())])
        )));
    }
    let body_start = skip_ws(data, i + 3);
    let body_end = value_end(data, body_start)?;
    Ok(body_start..body_end)
}

/// The undecoded bytes of the stream belonging to the object at `offset`.
///
/// `/Length` is usually a direct integer, but it may be an indirect reference,
/// which cannot be followed here because the cross-reference is often what we
/// are in the middle of building. The fallback looks for an `endstream` that is
/// really the end, by requiring `endobj` to follow it, which compressed data
/// does not contain by accident often enough to matter.
pub fn stream_raw(data: &[u8], offset: usize) -> Result<Vec<u8>> {
    let dict_span = object_body(data, offset)?;
    let dict = &data[dict_span.clone()];
    let mut i = skip_ws(data, dict_span.end);
    if !data[i..].starts_with(b"stream") {
        return Err(Error::Pdf(format!(
            "the object at {offset} is not a stream"
        )));
    }
    i += 6;
    // the end of line after the keyword is not part of the data
    if data[i..].starts_with(b"\r\n") {
        i += 2;
    } else if at(data, i) == b'\n' || at(data, i) == b'\r' {
        i += 1;
    }

    if let Some(n) = get(dict, "/Length").and_then(parse_uint) {
        let n = n as usize;
        // i is inside the file, checked on the way here, so the subtraction
        // cannot wrap; the addition of a file-declared length could. Copying
        // is what this function does, so the copy is bounded by the same cap
        // decoding is: an uncompressed stream's payload *is* its decode, and
        // megabytes copied through here would slip past every other check
        // while allocating exactly what the cap exists to refuse.
        let cap = crate::stream::MAX_DECODED_STREAM;
        if n > data.len() - i {
            return Err(Error::Pdf(format!(
                "/Length {n} runs past the end of the file"
            )));
        }
        if n > cap {
            return Err(Error::Pdf(format!(
                "the stream declares {n} raw bytes, more than the {cap} openfirma copies \
                 from one stream: a structural stream this large is not a document"
            )));
        }
        return Ok(data[i..i + n].to_vec());
    }

    // unchanged from before the recovery function existed: /Length was already
    // tried above (that is how we got here), so the marker is all that is left
    match find_endstream(data, i) {
        Some(end) => Ok(data[i..end].to_vec()),
        None => Err(Error::Pdf(format!(
            "the stream at {offset} has an indirect /Length and no endstream to fall back on"
        ))),
    }
}

/// Every payload-end marker in one document — an `endstream` really followed by an
/// `endobj`, with the end-of-line before the keyword already stripped — found in
/// ONE pass and searched by position.
///
/// Round 3's N3-4 measured why this exists: `find_endstream` scanned from each
/// stream's start to the first marker that happened to follow, so a document
/// whose streams are missing their `endobj` (all readers tolerate it) cost a scan
/// to the signature's own appearance — near the end of the file — for every
/// stream, twice. A 723 KB file with 4000 such streams took 38 s and 1.2 GB; the
/// work was quadratic in the file and the copies quadratic in streams × document.
/// Building the positions once makes every lookup a binary search, and the copy
/// that follows is only as far as the stream's own marker, or its /Length.
pub struct EndstreamIndex {
    /// Every `endstream` in the document, payload end already stripped of the
    /// end-of-line before the keyword. This is what a recovering reader takes
    /// first — qpdf prints "attempting to recover stream length" and scans for the
    /// keyword, not for the `endobj` after it — and using it when `/Length` exists
    /// is what keeps a stream without its `endobj` from swallowing every later
    /// object (round 3's N3-4: 4000 such streams copied the rest of the file each,
    /// 1.2 GB of resident memory after the time fix).
    ends: Vec<usize>,
    /// The `endstream`s that ARE followed by an `endobj`: the strict reading used
    /// only when `/Length` cannot be trusted at all, where any marker might be
    /// compressed data that happens to spell the keyword.
    strict: Vec<usize>,
}

impl EndstreamIndex {
    pub fn build(data: &[u8]) -> Self {
        let mut ends = Vec::new();
        let mut strict = Vec::new();
        let mut from = 0usize;
        while let Some(p) = data[from..].windows(9).position(|w| w == b"endstream") {
            let candidate = from + p;
            let after = skip_ws(data, candidate + 9);
            let mut end = candidate;
            while end > 0 && (data[end - 1] == b'\n' || data[end - 1] == b'\r') {
                end -= 1;
            }
            ends.push(end);
            if data[after..].starts_with(b"endobj") {
                strict.push(end);
            }
            from = candidate + 9;
        }
        Self { ends, strict }
    }

    fn at_or_after(&self, i: usize) -> Option<usize> {
        let k = self.ends.partition_point(|end| *end < i);
        self.ends.get(k).copied()
    }

    fn strict_at_or_after(&self, i: usize) -> Option<usize> {
        let k = self.strict.partition_point(|end| *end < i);
        self.strict.get(k).copied()
    }
}

/// Where this stream's payload really ends: the byte before an `endstream` that
/// is really the end (an `endobj` follows it, which compressed data does not
/// contain by accident often enough to matter), with the single run of end-of-line
/// bytes before the keyword stripped. `None` when no such marker exists at all.
fn find_endstream(data: &[u8], i: usize) -> Option<usize> {
    EndstreamIndex::build(data).strict_at_or_after(i)
}

/// Whether these bytes are a stream object: a dictionary followed by the
/// `stream` keyword. The gate asks so that "I cannot read the payload" is never
/// mistaken for "this object is a bare dictionary" (round 7's C-1).
pub fn is_stream_object(data: &[u8], offset: usize) -> bool {
    match object_body(data, offset) {
        Ok(span) => {
            let i = skip_ws(data, span.end);
            data[i..].starts_with(b"stream")
        }
        Err(_) => false,
    }
}

/// The payload of a stream as the RECOVERING readers see it: what `/Length`
/// declares, or as far as the real `endstream` reaches when that is longer; and
/// when `/Length` cannot be believed at all — unparseable, or past the end of the
/// file — exactly where the marker says.
///
/// `/Length` is the specification's word and [`stream_raw`] rightly trusts it —
/// but qpdf, Ghostscript and poppler do not stop trusting a lying length: when
/// the bytes after the declared end are not an `endstream`, they scan to the real
/// one and re-render from there (measured on round 7's PoC, where qpdf says so out
/// loud: "attempting to recover stream length" / "recovered stream length: 97",
/// while pdftotext prints text no signature covered). A later pass that keeps a
/// lying stream's dictionary byte-identical and LENGTHENS the payload is therefore
/// not invisible: the extra bytes are exactly what those readers show. The
/// revision gate compares bodies through this function so such a rewrite is seen
/// as the stream rewrite it is; readers that honour `/Length` still hide the ink —
/// no verdict may depend on which side of that disagreement a reader sits on.
pub fn stream_payload_as_readers(data: &[u8], offset: usize) -> Result<Vec<u8>> {
    let dict_span = object_body(data, offset)?;
    let declared = get(&data[dict_span], "/Length").and_then(parse_uint);
    stream_payload_with_declared(data, offset, declared.map(|n| n as usize))
}

/// [`stream_payload_as_readers`] with the declared length already resolved — the
/// gate holds the cross-reference and can follow an INDIRECT `/Length`, which is
/// legal (ISO 32000-1 Table 4) and which [`stream_raw`] documents it cannot do
/// while the xref is itself being built. Round 7's C-1 is the shape: a covered
/// stream with an indirect `/Length` and no marker the reader can tie to an
/// `endobj`; resolving the length is the difference between "I cannot read this
/// stream" (which the gate must not mistake for a bare dictionary) and the payload
/// the recovering readers actually decode.
pub fn stream_payload_with_declared(
    data: &[u8],
    offset: usize,
    declared: Option<usize>,
) -> Result<Vec<u8>> {
    let index = EndstreamIndex::build(data);
    stream_payload_with_declared_indexed(data, offset, declared, &index)
}

/// [`stream_payload_with_declared`] with the document's marker index already
/// built — the gate reads every stream of both states, and builds one.
pub fn stream_payload_with_declared_indexed(
    data: &[u8],
    offset: usize,
    declared: Option<usize>,
    index: &EndstreamIndex,
) -> Result<Vec<u8>> {
    let dict_span = object_body(data, offset)?;
    let mut i = skip_ws(data, dict_span.end);
    if !data[i..].starts_with(b"stream") {
        return Err(Error::Pdf(format!(
            "the object at {offset} is not a stream"
        )));
    }
    // the same step past `stream` and its end-of-line that stream_raw takes
    i += 6;
    if data[i..].starts_with(b"\r\n") {
        i += 2;
    } else if at(data, i) == b'\n' || at(data, i) == b'\r' {
        i += 1;
    }
    // a length that runs past the end of the file is not trusted even by the
    // recovering readers (their scan stops at `endstream` anyway); everything
    // else stands until the marker reaches farther than it does
    let declared = declared.filter(|n| *n <= data.len() - i);
    // with a trusted length the FIRST marker is the one readers recover to; only
    // a stream whose length is unknowable leans on the strict reading
    let end = match declared {
        Some(_) => index.at_or_after(i),
        None => index.strict_at_or_after(i),
    };
    let stop = match (declared, end) {
        (Some(n), Some(e)) => (i + n).max(e),
        (Some(n), None) => i + n,
        (None, Some(e)) => e,
        (None, None) => {
            return Err(Error::Pdf(format!(
                "the stream at {offset} has no readable /Length and no endstream to fall back on"
            )));
        }
    };
    let span = stop - i;
    let cap = crate::stream::MAX_DECODED_STREAM;
    if span > cap {
        return Err(Error::Pdf(format!(
            "the stream declares a {span}-byte read, more than the {cap} openfirma copies \
             from one stream: a structural stream this large is not a document"
        )));
    }
    Ok(data[i..stop].to_vec())
}

/// A deterministic fingerprint of the payload a recovering reader would take —
/// length and SHA-256 of the bytes — for a stream whose payload is too large for
/// [`stream_payload_with_declared`] to copy.
///
/// The cap exists so one structural stream cannot make the gate allocate past
/// `MAX_DECODED_STREAM`; it does not exist to make big streams disappear. Round
/// 7's C-2 measured exactly that: a legal attachment of a few hundred megabytes
/// (an invoice's scan, a plan) was compared as ABSENCE, so a pass could rewrite it
/// wholesale behind an `/ITXT` mark and the gate called it bookkeeping. Hashing
/// costs the same order as the copy the cap refuses and allocates nothing, so a
/// rewrite of ANY byte changes the fingerprint; the same-length/same-bytes case
/// still compares equal, which is what every unchanged stream must do.
pub fn stream_payload_fingerprint(
    data: &[u8],
    offset: usize,
    declared: Option<usize>,
) -> Option<Vec<u8>> {
    let index = EndstreamIndex::build(data);
    stream_payload_fingerprint_indexed(data, offset, declared, &index)
}

/// [`stream_payload_fingerprint`] with the marker index already built.
pub fn stream_payload_fingerprint_indexed(
    data: &[u8],
    offset: usize,
    declared: Option<usize>,
    index: &EndstreamIndex,
) -> Option<Vec<u8>> {
    use sha2::{Digest, Sha256};

    let dict_span = object_body(data, offset).ok()?;
    let mut i = skip_ws(data, dict_span.end);
    if !data[i..].starts_with(b"stream") {
        return None;
    }
    i += 6;
    if data[i..].starts_with(b"\r\n") {
        i += 2;
    } else if at(data, i) == b'\n' || at(data, i) == b'\r' {
        i += 1;
    }
    let declared = declared.filter(|n| *n <= data.len() - i);
    let end = match declared {
        Some(_) => index.at_or_after(i),
        None => index.strict_at_or_after(i),
    };
    let stop = match (declared, end) {
        (Some(n), Some(e)) => (i + n).max(e),
        (Some(n), None) => i + n,
        (None, Some(e)) => e,
        (None, None) => return None,
    };
    let span = stop - i;
    if span <= crate::stream::MAX_DECODED_STREAM {
        // the copy path can judge this one; only the refused sizes need a digest
        return None;
    }
    let digest = hex::encode(Sha256::digest(&data[i..stop]));
    Some(format!("\x00openfirma stream fingerprint: {span} bytes {digest}").into_bytes())
}

thread_local! {
    /// Counts `decoded_object_stream` inflates while a test has armed the
    /// slot to a positive value (the A-1 regression guard in hostile.rs): the
    /// count distinguishes a memoised walk — one inflate per stream — from
    /// the quadratic pre-cache walk, one per object behind it. Un-armed
    /// threads never touch it, so parallel tests cannot clear each other's
    /// count.
    pub static OBJSTM_DECODES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// The decoded bytes of one object stream: dictionary included, because the
/// header offsets inside it (`/First`) are relative to the object's start.
/// This is the *inflate* — a hostile document can make it expensive, so every
/// caller goes through the per-document cache of [`resolve_with_cache`] and a
/// given stream is decoded at most once (finding A-1).
fn decoded_object_stream(
    data: &[u8],
    locations: &BTreeMap<ObjRef, Location>,
    stream: ObjRef,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let Some(Location::Direct(off)) = locations.get(&stream).copied() else {
        return Err(Error::Pdf(format!(
            "object stream {stream} is missing from the cross-reference, or is itself \
             inside another object stream, which the specification does not allow"
        )));
    };
    let dict_span = object_body(data, off)?;
    let dict = data[dict_span].to_vec();
    let raw = stream_raw(data, off)?;
    OBJSTM_DECODES.with(|c| {
        if c.get() > 0 {
            c.set(c.get() + 1);
        }
    });
    let decoded = crate::stream::decode(&dict, &raw)?;
    Ok((dict, decoded))
}

/// The header of an object stream: `(count, first)` and the 2N integers that
/// follow (`objnum offset` pairs). Validated exactly as far as it is trusted:
/// `/N` may not exceed the decoded length (a claim larger than the stream is
/// a lie that would allocate before reading anything), the numbers must all
/// be there, and nothing else is believed here — entry ranges are re-checked
/// per object by [`entry_range`] so a cached header never smuggles nonsense.
fn object_stream_header(dict: &[u8], decoded: Vec<u8>, stream: ObjRef) -> Result<ObjStmEntry> {
    // /N and /First belong to the dictionary, which the decode step did not
    // touch; `decoded` carries only the stream content, header numbers first.
    let count = get(dict, "/N")
        .and_then(parse_uint)
        .ok_or_else(|| Error::Pdf(format!("object stream {stream} has no /N")))?;
    let first = get(dict, "/First")
        .and_then(parse_uint)
        .ok_or_else(|| Error::Pdf("the object stream has no /First".into()))?
        as usize;
    if first > decoded.len() {
        return Err(Error::Pdf(
            "/First points past the end of the object stream".into(),
        ));
    }
    // /N is the file's claim, and every object needs at least two numbers in
    // the header inside the first /First bytes, so a claim bigger than the
    // stream is a lie: believed, it would allocate before reading anything.
    if count > decoded.len() as u32 {
        return Err(Error::Pdf(format!(
            "/N claims {count} objects but the decoded object stream is only {} bytes",
            decoded.len()
        )));
    }
    let count = count as usize;

    // the header is 2N integers: object number, then offset relative to /First
    let mut header = Vec::with_capacity(count * 2);
    let mut i = 0;
    while header.len() < count * 2 {
        i = skip_ws(&decoded, i);
        if i >= first {
            break;
        }
        let tok = token_end(&decoded, i);
        header.push(parse_uint(&decoded[i..tok]).ok_or_else(|| {
            Error::Pdf("the object stream header holds something that is not a number".into())
        })?);
        i = tok;
    }
    if header.len() < count * 2 {
        return Err(Error::Pdf(format!(
            "the object stream header holds {} numbers but /N {count} needs {}",
            header.len(),
            count * 2
        )));
    }
    Ok(ObjStmEntry {
        decoded,
        first,
        header,
    })
}

/// One object's byte range inside the stream, checked on every access — cached
/// or not. Offsets are the file's claim, so a sum that wraps is refused rather
/// than wrapped into a passing range test, and the `start > end` shape a lie
/// takes is refused too. Returns `(number, span)` of entry `index`.
fn entry_range(entry: &ObjStmEntry, index: usize) -> Result<(u32, std::ops::Range<usize>)> {
    let count = entry.header.len() / 2;
    let first = entry.first;
    let (Some(start), Some(end)) = (
        first.checked_add(entry.header[index * 2 + 1] as usize),
        if index + 1 < count {
            first.checked_add(entry.header[index * 2 + 3] as usize)
        } else {
            Some(entry.decoded.len())
        },
    ) else {
        return Err(Error::Pdf(format!(
            "object number {} of the stream has an offset too large to represent",
            entry.header[index * 2]
        )));
    };
    if start > end || end > entry.decoded.len() {
        return Err(Error::Pdf(format!(
            "object number {} of the stream has an impossible range {start}..{end}",
            entry.header[index * 2]
        )));
    }
    Ok((entry.header[index * 2], start..end))
}

/// What one object stream costs to read: its decoded bytes (needed for every
/// range check, and the dictionary `/N`//`/First` live at their start) plus
/// the header's 2N integers. An entire ObjStm entry is a few MB at worst; a
/// document's streams together are bounded by the same caps a single read of
/// the document pays anyway. The fields stay private and the struct itself is
/// only named through [`ObjectStreamCache`] — callers create one with `new`
/// and never look inside.
pub(crate) struct ObjStmEntry {
    decoded: Vec<u8>,
    /// /First, kept because entry ranges are re-validated per access and the
    /// dictionary is not at hand any more then.
    first: usize,
    header: Vec<u32>,
}

/// The decoded contents of every object stream one read has touched, keyed by
/// the stream's object number. A document is immutable while it is parsed —
/// nothing here writes to `data` — so a computed entry is valid for the whole
/// operation and there is no invalidation to get wrong; keeping decodes past
/// one parse would be a memory policy, not a correctness need, which is why
/// the cache travels with the caller's stack instead of globally. The entry
/// type stays private: an outside caller only ever passes this around.
///
/// Memory policy is still policy (finding A-1's own round-2 follow-up): three
/// ~60 MB object streams took the peak to 253 MB once every decode was kept,
/// and N large streams scaled it to N × the per-stream cap where the uncached
/// path held one at a time. So there is a total budget: past
/// `CACHE_TOTAL_BUDGET` a stream still decodes — refusing a readable document
/// to police our own memory would be backwards — but stops being retained,
/// which pays that one re-inflate per access and nothing else.
pub struct ObjectStreamCache {
    entries: std::collections::HashMap<ObjRef, std::sync::Arc<ObjStmEntry>>,
    /// Decoded bytes currently retained across all entries.
    retained: usize,
}

/// What one cache may hold at most: twice the per-stream decode cap, enough
/// for the biggest single stream plus a second one of ordinary size, while a
/// hostile document's peak stays bounded instead of scaling with its number
/// of streams (round-2 finding on A-1: 3 × 60 MB measured).
const CACHE_TOTAL_BUDGET: usize = 2 * crate::stream::MAX_DECODED_STREAM;

impl ObjectStreamCache {
    /// An empty cache for one document walk.
    pub fn new() -> Self {
        Self {
            entries: std::collections::HashMap::new(),
            retained: 0,
        }
    }

    /// Retain `entry` under its stream's number unless the total budget is
    /// spent; never eviction of what a later access needs (the document's own
    /// caps bound any single entry), only refusal to add past the budget. The
    /// cached and uncached paths answer identically either way (`resolve` runs
    /// the same checks on both), so refusing to retain costs a re-inflate and
    /// never a different answer.
    fn retain(&mut self, stream: ObjRef, entry: &std::sync::Arc<ObjStmEntry>) {
        let cost = entry.decoded.len() + 8 * entry.header.len();
        if self.retained.saturating_add(cost) > CACHE_TOTAL_BUDGET {
            return;
        }
        self.retained += cost;
        self.entries.insert(stream, entry.clone());
    }
}

impl Default for ObjectStreamCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Resolves a reference to the bytes of its value, whether it sits in the file
/// directly or compressed inside an object stream.
///
/// `cache` memoises the decode of each object stream (finding A-1): passing
/// one makes every ObjStm inflate **once per document walk instead of once
/// per object it holds** — without it, a 40 KB PDF with 2.000 objects behind
/// one ~24 MB stream costs 24,5 s of a single core, and /N up to 65.000
/// scales that to hours. `None` keeps the old uncached behaviour for one-shot
/// resolves (the entry checks run identically either way; only the inflate is
/// memoised, never a validation). Multi-object callers — `signatures()`, the
/// page-tree walk, the signer — create one cache per operation.
pub fn resolve<'a>(
    data: &'a [u8],
    locations: &BTreeMap<ObjRef, Location>,
    mut cache: Option<&mut ObjectStreamCache>,
    r: ObjRef,
) -> Result<Cow<'a, [u8]>> {
    let Some(loc) = locations.get(&r).copied() else {
        return Err(Error::Pdf(format!(
            "object {r} is not in the cross-reference"
        )));
    };
    match loc {
        Location::Direct(off) => {
            let span = object_body(data, off)?;
            Ok(Cow::Borrowed(&data[span]))
        }
        Location::InObjectStream { stream, index } => {
            // One *inflate* per (document, object stream): the first object
            // that needs the stream pays it, every later one clones the Arc
            // and runs its own range checks against the same caps the uncached
            // path applies — memoising means never skipping a check. The only
            // check the cached path *cannot* re-run here is whether the packed
            // object still sits where the classic-table scan put it: no such
            // second index exists for objects inside a stream (the /Index rows
            // name the stream and entry, not the bytes), so an object that
            // moved within its stream would resolve to stale bytes — which is
            // why `sign.rs` walks type 2 entries through `object_stream_bytes`
            // (a fresh decode every time) when hashing a document for signing.
            let entry = match cache.as_mut().and_then(|c| c.entries.get(&stream)) {
                Some(entry) => entry.clone(),
                None => {
                    let (dict, decoded) = decoded_object_stream(data, locations, stream)?;
                    let entry = std::sync::Arc::new(object_stream_header(&dict, decoded, stream)?);
                    if let Some(c) = cache.as_mut() {
                        c.retain(stream, &entry);
                    }
                    entry
                }
            };
            let count = entry.header.len() / 2;
            let Some(index_us) = usize::try_from(index).ok().filter(|i| *i < count) else {
                return Err(Error::Pdf(format!(
                    "object {r} is entry {index} of object stream {stream}, which only holds {count}"
                )));
            };
            let (num, range) = entry_range(&entry, index_us)?;
            if num != r.num {
                return Err(Error::Pdf(format!(
                    "object stream {stream} holds object {num} where {r} was expected"
                )));
            }
            Ok(Cow::Owned(trim_ws(&entry.decoded[range]).to_vec()))
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// The objects packed inside an object stream, as number and value bytes —
    /// the whole stream at once. An object stream holds the values only, with
    /// no `N G obj` wrapper, because their numbers are in the header instead.
    /// This is the one-shot reading every test cross-checks against: it walks
    /// [`object_stream_header`] + [`entry_range`] exactly like the cached
    /// resolve path does, so "cached agrees with fresh" is checkable by
    /// construction (finding A-1).
    pub(crate) fn object_stream_objects(
        dict: &[u8],
        decoded: &[u8],
    ) -> Result<Vec<(u32, Vec<u8>)>> {
        let entry = object_stream_header(dict, decoded.to_vec(), ObjRef::new(0, 0))?;
        let count = entry.header.len() / 2;
        let mut out = Vec::with_capacity(count);
        for n in 0..count {
            let (num, range) = entry_range(&entry, n)?;
            out.push((num, trim_ws(&entry.decoded[range]).to_vec()));
        }
        Ok(out)
    }

    fn keys(dict: &[u8]) -> Vec<String> {
        items(dict)
            .expect("the dictionary did not parse")
            .iter()
            .map(|(k, _)| String::from_utf8_lossy(&dict[k.clone()]).into_owned())
            .collect()
    }

    #[test]
    fn a_name_inside_an_array_is_not_a_key() {
        // /Dest carries /XYZ as data. Taking it for a key would truncate the
        // array the next time the dictionary is rewritten.
        let d = b"<< /Dest [3 0 R /XYZ null null null] /Type /Catalog >>";
        assert_eq!(keys(d), ["/Dest", "/Type"]);
        assert_eq!(
            get(d, "/Dest"),
            Some(b"[3 0 R /XYZ null null null]".as_slice())
        );
    }

    #[test]
    fn a_name_inside_a_nested_dictionary_is_not_a_key() {
        let d = b"<< /A << /B 1 >> /C 2 >>";
        assert_eq!(keys(d), ["/A", "/C"]);
        assert_eq!(get(d, "/A"), Some(b"<< /B 1 >>".as_slice()));
    }

    #[test]
    fn values_do_not_carry_the_separating_whitespace() {
        // the /Contents placeholder is found by its angle brackets, so a value
        // range that starts one byte early points at a space instead
        let d = b"<< /ByteRange [0 1 2 3] /Contents <00> >>";
        assert_eq!(get(d, "/Contents"), Some(b"<00>".as_slice()));
    }

    #[test]
    fn strings_cannot_end_a_dictionary_early() {
        let d = b"<< /S (a >> b) /H <303132> /N /XYZ >>";
        assert_eq!(get(d, "/S"), Some(b"(a >> b)".as_slice()));
        assert_eq!(get(d, "/H"), Some(b"<303132>".as_slice()));
        assert_eq!(get(d, "/N"), Some(b"/XYZ".as_slice()));
    }

    #[test]
    fn an_indirect_reference_is_one_value_not_three() {
        let d = b"<< /Pages 2 0 R /Count 1 >>";
        assert_eq!(get(d, "/Pages"), Some(b"2 0 R".as_slice()));
        assert_eq!(get(d, "/Count"), Some(b"1".as_slice()));
        assert_eq!(
            parse_ref(get(d, "/Pages").unwrap()),
            Some(ObjRef::new(2, 0))
        );
    }

    #[test]
    fn set_replaces_in_place_and_appends_otherwise() {
        let d = b"<< /A 1 /B 2 >>";
        assert_eq!(set(d, "/A", b"99").unwrap(), b"<< /A 99 /B 2 >>");
        assert_eq!(
            set(d, "/C", b"[3 0 R]").unwrap(),
            b"<< /A 1 /B 2 /C [3 0 R] >>"
        );
        // a value wider than the one it replaces shifts everything after it,
        // which is fine here but is why the signer uses fixed width placeholders
        assert_eq!(set(d, "/A", b"1000").unwrap(), b"<< /A 1000 /B 2 >>");
    }

    #[test]
    fn references_need_the_exact_shape() {
        assert_eq!(parse_ref(b"12 0 R"), Some(ObjRef::new(12, 0)));
        assert_eq!(parse_ref(b"12 0 r"), None);
        assert_eq!(parse_ref(b"12 0 Read"), None);
        assert_eq!(parse_ref(b"12"), None);
        assert_eq!(ObjRef::new(3, 1).to_string(), "3 1 R");
    }

    #[test]
    fn the_committed_fixture_reads_back() {
        let pdf = include_bytes!("../../../testdata/inputs/simple.pdf");
        // A cross-reference table records byte offsets, so a checkout that
        // turned LF into CRLF produces a document that is corrupt rather than
        // merely different. Saying so here beats a parse error downstream.
        assert!(
            !pdf.contains(&b'\r'),
            "the fixture was checked out with CRLF line endings, which moves every \
             offset in its cross-reference table. .gitattributes must mark *.pdf binary"
        );
        let at = last_startxref(pdf).unwrap();
        let tr = trailer(pdf, at).unwrap();
        assert_eq!(tr.root, ObjRef::new(1, 0));
        assert_eq!(tr.size, Some(6));
        assert!(tr.prev.is_none(), "the fixture is a single revision");

        let offs = object_locations(pdf, at).unwrap();
        assert_eq!(
            offs.len(),
            5,
            "objects 1..5, object 0 is the free list head"
        );

        let catalog = resolve(pdf, &offs, None, tr.root).unwrap();
        assert_eq!(get(&catalog, "/Type"), Some(b"/Catalog".as_slice()));
        let pages = parse_ref(get(&catalog, "/Pages").unwrap()).unwrap();
        let pages_body = resolve(pdf, &offs, None, pages).unwrap();
        let kids = array_refs(get(&pages_body, "/Kids").unwrap()).unwrap();
        assert_eq!(kids, [ObjRef::new(3, 0)]);

        let page = resolve(pdf, &offs, None, kids[0]).unwrap();
        assert_eq!(get(&page, "/MediaBox"), Some(b"[0 0 595 842]".as_slice()));
        assert!(
            get(&page, "/Annots").is_none(),
            "the unsigned fixture has none"
        );
    }

    #[test]
    fn the_object_header_error_message_survives_the_end_of_the_file() {
        // "obj" never arrives, and the eight byte preview of what did arrive
        // used to slice past the end of the buffer inside the error message
        let err = object_body(b"1 0 xy", 0).unwrap_err().to_string();
        assert!(err.contains("expected 'obj'"), "{err}");
        assert!(err.contains("found \"xy\""), "{err}");
        // the same scan with nothing left at all
        let err = object_body(b"1 0 ", 0).unwrap_err().to_string();
        assert!(err.contains("expected 'obj'"), "{err}");
    }

    #[test]
    fn an_object_stream_n_bigger_than_its_contents_is_refused() {
        // /N sizes an allocation before a single header number is read, and a
        // stream that claims more objects than it has bytes for is a lie:
        // believed, a large enough claim allocates gigabytes from sixteen
        // bytes of input. The refusal names the claim and the real size.
        let packed = deflate(b"1 0 2 4 <</A 1>>");
        let mut pdf = Vec::from(&b"%PDF-1.7\n"[..]);
        let objstm_at = pdf.len();
        pdf.extend_from_slice(
            format!(
                "7 0 obj\n<< /Type /ObjStm /N 100 /First 8 /Length {} \
                 /Filter /FlateDecode >>\nstream\n",
                packed.len()
            )
            .as_bytes(),
        );
        pdf.extend_from_slice(&packed);
        pdf.extend_from_slice(b"\nendstream\nendobj\n");

        let mut locations = BTreeMap::new();
        locations.insert(ObjRef::new(7, 0), Location::Direct(objstm_at));
        locations.insert(
            ObjRef::new(1, 0),
            Location::InObjectStream {
                stream: ObjRef::new(7, 0),
                index: 0,
            },
        );
        let err = resolve(
            &pdf,
            &locations,
            Some(&mut ObjectStreamCache::new()),
            ObjRef::new(1, 0),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("/N claims 100 objects"), "{err}");
        assert!(err.contains("only 16 bytes"), "{err}");
    }

    #[test]
    fn next_object_number_survives_the_top_of_the_range() {
        // /Size is the highest object number plus one; an object numbered
        // u32::MAX used to wrap that sum to zero and publish a /Size no
        // reader can use
        let mut update = crate::update::Update::new_with_trailer(
            0,
            ObjRef::new(1, 0),
            None,
            1,
            b"<< /Size 1 >>",
            false,
        )
        .unwrap();
        update.push(crate::update::Object::new(
            ObjRef::new(u32::MAX, 0),
            b"<< >>".to_vec(),
        ));
        assert_eq!(update.next_object_number(), u32::MAX);
    }

    /// A document shaped the way iText writes one: the catalog and the page
    /// tree compressed into an object stream, and a cross-reference stream
    /// instead of a table. That is what AutoFirma's own output looks like, so
    /// reading it is the difference between signing a fresh PDF and being able
    /// to add a signature to one that is already signed.
    pub(crate) fn itext_style_document() -> Vec<u8> {
        let values: [(u32, &[u8]); 3] = [
            (1, b"<< /Type /Catalog /Pages 2 0 R >>"),
            (2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>"),
            (
                3,
                b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] >>",
            ),
        ];
        // an object stream is a header of number and offset pairs, then the
        // values with no "N G obj" wrapper, because the numbers are up here
        let mut header = String::new();
        let mut bodies = Vec::new();
        for (num, body) in values {
            header.push_str(&format!("{num} {} ", bodies.len()));
            bodies.extend_from_slice(body);
            bodies.push(b' ');
        }
        let first = header.len();
        let mut packed = header.into_bytes();
        packed.extend_from_slice(&bodies);
        let packed = deflate(&packed);

        let mut out = Vec::from(&b"%PDF-1.7\n"[..]);
        let objstm_at = out.len();
        out.extend_from_slice(
            format!(
                "4 0 obj\n<< /Type /ObjStm /N 3 /First {first} /Length {} \
                 /Filter /FlateDecode >>\nstream\n",
                packed.len()
            )
            .as_bytes(),
        );
        out.extend_from_slice(&packed);
        out.extend_from_slice(b"\nendstream\nendobj\n");

        // /W [1 3 2]: one byte of type, three of offset or stream number, two
        // of generation or index inside the stream
        let xref_obj_at = out.len();
        let mut entries = Vec::new();
        entries.extend_from_slice(&xref_entry(0, 0, 0xffff));
        for i in 0..values.len() as u32 {
            entries.extend_from_slice(&xref_entry(2, 4, i as u16));
        }
        entries.extend_from_slice(&xref_entry(1, objstm_at as u32, 0));
        entries.extend_from_slice(&xref_entry(1, xref_obj_at as u32, 0));
        let entries = deflate(&entries);

        out.extend_from_slice(
            format!(
                "5 0 obj\n<< /Type /XRef /Size 6 /Root 1 0 R /W [1 3 2] /Length {} \
                 /Filter /FlateDecode >>\nstream\n",
                entries.len()
            )
            .as_bytes(),
        );
        out.extend_from_slice(&entries);
        out.extend_from_slice(
            format!("\nendstream\nendobj\nstartxref\n{xref_obj_at}\n%%EOF\n").as_bytes(),
        );
        out
    }

    fn xref_entry(kind: u8, second: u32, third: u16) -> Vec<u8> {
        let mut e = vec![kind];
        // /W [1 3 2]: three bytes of the u32, then both bytes of the u16
        e.extend_from_slice(&second.to_be_bytes()[1..]);
        e.extend_from_slice(&third.to_be_bytes());
        e
    }

    fn deflate(bytes: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(bytes).unwrap();
        enc.finish().unwrap()
    }

    /// The memo must answer exactly what the fresh decode answers: same
    /// bytes, and the same refusals. A cache that hides a validation is worse
    /// than no cache at all (finding A-1's design rule), and this test is the
    /// standing proof for `itext_style_document` end to end.
    #[test]
    fn the_object_stream_memo_answers_what_a_fresh_decode_answers() {
        let pdf = itext_style_document();
        let at = last_startxref(&pdf).unwrap();
        let locs = object_locations(&pdf, at).unwrap();
        let mut cache = ObjectStreamCache::new();
        for r in locs.keys() {
            let fresh = resolve(&pdf, &locs, None, *r).unwrap();
            let memoised = resolve(&pdf, &locs, Some(&mut cache), *r).unwrap();
            assert_eq!(fresh, memoised, "object {r} reads differently cached");
        }
        // and the whole-stream reading agrees object by object with it
        let (dict, decoded) = decoded_object_stream(&pdf, &locs, ObjRef::new(4, 0)).unwrap();
        let all = object_stream_objects(&dict, &decoded).unwrap();
        for (num, bytes) in &all {
            let r = ObjRef::new(*num, 0);
            assert_eq!(
                bytes,
                &resolve(&pdf, &locs, Some(&mut cache), r).unwrap()[..]
            );
        }
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn a_document_written_with_object_streams_is_readable() {
        let pdf = itext_style_document();
        let at = last_startxref(&pdf).unwrap();
        let tr = trailer(&pdf, at).unwrap();
        assert_eq!(tr.root, ObjRef::new(1, 0));
        assert_eq!(tr.size, Some(6));

        let locs = object_locations(&pdf, at).unwrap();
        assert_eq!(locs.len(), 5, "objects 1 to 5, object 0 is the free list");
        assert_eq!(
            locs[&ObjRef::new(1, 0)],
            Location::InObjectStream {
                stream: ObjRef::new(4, 0),
                index: 0
            },
            "the catalog is compressed, that is the whole point of an object stream"
        );
        assert!(matches!(locs[&ObjRef::new(4, 0)], Location::Direct(_)));

        let catalog = resolve(&pdf, &locs, None, tr.root).unwrap();
        assert_eq!(get(&catalog, "/Type"), Some(b"/Catalog".as_slice()));
        let pages = parse_ref(get(&catalog, "/Pages").unwrap()).unwrap();
        let pages_body = resolve(&pdf, &locs, None, pages).unwrap();
        assert_eq!(get(&pages_body, "/Count"), Some(b"1".as_slice()));
        let kids = array_refs(get(&pages_body, "/Kids").unwrap()).unwrap();
        assert_eq!(kids, [ObjRef::new(3, 0)]);
        let page = resolve(&pdf, &locs, None, kids[0]).unwrap();
        assert_eq!(
            get(&page, "/MediaBox"),
            Some(b"[0 0 595 842]".as_slice()),
            "an object taken from inside an object stream has no obj/endobj wrapper"
        );
    }

    // ---- what the recovery readers see in a stream payload (round 7, B-1) ----

    /// One direct object whose body is exactly `body`, at its real offset.
    fn one_stream(body: &str) -> (Vec<u8>, usize) {
        let mut pdf = b"%PDF-1.4\n".to_vec();
        let at = pdf.len();
        pdf.extend_from_slice(format!("1 0 obj\n{body}\nendobj\n").as_bytes());
        (pdf, at)
    }

    /// Every shape a lying or honest `/Length` takes, judged by what qpdf and
    /// Ghostscript end up reading. The gate compares through this function, so
    /// these are the boundaries of the B-1 fix: an exact length with the EOL a
    /// producer writes before `endstream` must read as exactly the payload (no
    /// false rewrite), and a length that stops short must read through to the
    /// marker (the ink those readers draw).
    #[test]
    fn the_payload_the_recovering_readers_see() {
        // exact /Length, producer's own EOL before the keyword: the EOL is not data
        let (pdf, at) = one_stream("<< /Length 5 >>\nstream\nHELLO\nendstream");
        assert_eq!(stream_payload_as_readers(&pdf, at).unwrap(), b"HELLO");

        // /Length stops at HELLO; readers recover through the space to `endstream`
        let (pdf, at) = one_stream("<< /Length 5 >>\nstream\nHELLO world\nendstream");
        assert_eq!(
            stream_payload_as_readers(&pdf, at).unwrap(),
            b"HELLO world",
            "a short /Length does not hide what the marker exposes"
        );

        // a fake `endstream`+`endobj` INSIDE the declared payload must not shrink
        // the read: the declared span is longer, and the max is what the gate uses
        let (pdf, at) =
            one_stream("<< /Length 26 >>\nstream\nHELLOendstreamendobjHELLO\nendstream");
        let seen = stream_payload_as_readers(&pdf, at).unwrap();
        assert!(
            seen.len() >= 26,
            "the declared span wins over an early marker, got {} bytes",
            seen.len()
        );

        // /Length past the end of the file: believed by nobody; the marker decides
        let (pdf, at) = one_stream("<< /Length 99999 >>\nstream\nHELLO world\nendstream");
        assert_eq!(stream_payload_as_readers(&pdf, at).unwrap(), b"HELLO world");

        // no /Length at all: the marker decides, exactly like stream_raw's fallback
        let (pdf, at) = one_stream("<< /Type /XObject >>\nstream\nHELLO world\nendstream");
        assert_eq!(stream_payload_as_readers(&pdf, at).unwrap(), b"HELLO world");

        // neither a trustworthy length nor a marker: not a payload anybody can read
        let (pdf, at) = one_stream("<< /Type /XObject >>\nstream\nHELLO");
        assert!(stream_payload_as_readers(&pdf, at).is_err());
    }

    // ---- round 3's xref findings: order is meaning, and silence is not absent ----

    /// A one-object PDF whose cross-reference SECTION is exactly `body` (what
    /// follows `xref\n`) and whose trailer is `trailer`.
    fn xref_with(body: &str, trailer: &str) -> Vec<u8> {
        let mut out = b"%PDF-1.4\n".to_vec();
        out.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
        let xref_at = out.len();
        out.extend_from_slice(b"xref\n");
        out.extend_from_slice(body.as_bytes());
        out.extend_from_slice(
            format!("trailer\n<< {trailer} /Size 7 /Root 1 0 R >>\nstartxref\n{xref_at}\n%%EOF\n")
                .as_bytes(),
        );
        out
    }

    /// Round 3's N3-1, classic table: the same number free and then in use in ONE
    /// section. qpdf and Ghostscript take the first entry (free) and drop the
    /// signed object; the gate's two-list reader kept the in-use one and judged
    /// zero changes. A section that repeats a number is now a read error.
    #[test]
    fn a_section_that_names_an_object_twice_is_refused() {
        // two subsections, both for object 6: the first frees it, the second
        // points at the old bytes — one section, one number, two decisions
        let pdf = xref_with("6 1\n0000000000 65535 f \n6 1\n0000000009 00000 n \n", "");
        let err = object_locations(&pdf, last_startxref(&pdf).unwrap())
            .expect_err("the order of two entries for one number is what readers obey")
            .to_string();
        assert!(err.contains("more than once"), "says why: {err}");
    }

    /// The same shape in a cross-reference STREAM: `/Index [6 1 6 1]` with a free
    /// row and then an in-use one.
    #[test]
    fn an_xref_stream_that_names_an_object_twice_is_refused() {
        let mut out = b"%PDF-1.5\n".to_vec();
        let stream_at = out.len();
        // two rows of /W [1 4 2]: type 0 (free) then type 1 (in use, offset 0)
        let rows: Vec<u8> = vec![0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        out.extend_from_slice(
            format!(
                "6 0 obj\n<< /Type /XRef /Size 7 /Root 1 0 R /W [1 4 2] /Index [6 1 6 1] /Length {} >>\nstream\n",
                rows.len()
            )
            .as_bytes(),
        );
        out.extend_from_slice(&rows);
        out.extend_from_slice(
            format!("\nendstream\nendobj\nstartxref\n{stream_at}\n%%EOF\n").as_bytes(),
        );
        let err = object_locations(&out, stream_at)
            .expect_err("a stream that repeats a number has the same order problem")
            .to_string();
        assert!(err.contains("more than once"), "says why: {err}");
    }

    /// Round 3's N3-2: a hybrid file's `/XRefStm` is a section of the revision,
    /// not a hint. One the reader cannot open is an error (it used to be skipped
    /// silently), and a row type the specification does not define is a null
    /// reference — a deletion the gate must see, not an error the caller can dodge.
    #[test]
    fn a_hybrid_xref_stm_is_never_silently_skipped() {
        // unreadable: the offset points at a plain stream with no /Type /XRef
        let mut out = b"%PDF-1.5\n".to_vec();
        let not_xref = out.len();
        out.extend_from_slice(b"3 0 obj\n<< /Length 1 >>\nstream\nX\nendstream\nendobj\n");
        let xref_at = out.len();
        out.extend_from_slice(
            format!(
                "xref\n1 1\n0000000009 00000 n \ntrailer\n<< /Size 4 /Root 1 0 R /XRefStm {not_xref} >>\nstartxref\n{xref_at}\n%%EOF\n"
            )
            .as_bytes(),
        );
        let err = object_locations(&out, xref_at)
            .expect_err("an unreadable XRefStm is a section the gate did not read")
            .to_string();
        assert!(
            err.contains("XRefStm") || err.contains("not a cross-reference stream"),
            "{err}"
        );

        // type 3 is a null reference: object 6 becomes a deletion, not a skip
        let mut out = b"%PDF-1.5\n".to_vec();
        let pairs_at = out.len();
        out.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
        let stream_at = out.len();
        // one row of /W [1 4 2] for number 6, type 3
        let rows: Vec<u8> = vec![3, 0, 0, 0, 0, 0, 0];
        out.extend_from_slice(
            format!(
                "7 0 obj\n<< /Type /XRef /Size 8 /Root 1 0 R /W [1 4 2] /Index [6 1] /Length {} >>\nstream\n",
                rows.len()
            )
            .as_bytes(),
        );
        out.extend_from_slice(&rows);
        out.extend_from_slice(b"\nendstream\nendobj\n");
        let xref_at = out.len();
        out.extend_from_slice(
            format!(
                "xref\n1 1\n0000000009 00000 n \ntrailer\n<< /Size 8 /Root 1 0 R /XRefStm {stream_at} >>\nstartxref\n{xref_at}\n%%EOF\n"
            )
            .as_bytes(),
        );
        let locs = object_locations(&out, xref_at).expect("a type-3 row is readable");
        assert!(
            !locs.contains_key(&ObjRef::new(6, 0)),
            "an unknown row type is a null reference; the number must not resolve"
        );
        let _ = pairs_at;
    }

    /// Round 3's N3-4, the memory half: a stream whose `endstream` is not followed
    /// by `endobj` (readers tolerate it; qpdf warns) and which carries a `/Length`
    /// is recovered to ITS OWN marker — readers scan for the FIRST `endstream`, not
    /// for the one with an `endobj` after it. Taking the strict marker made every
    /// such stream swallow the rest of the document up to the signature's
    /// appearance: 4000 streams, 1.2 GB, and a rewrite of any of them invisible.
    #[test]
    fn a_stream_with_a_length_stops_at_its_own_marker_not_a_later_one() {
        let mut pdf = b"%PDF-1.4\n".to_vec();
        let a = pdf.len();
        // object 1 has no endobj after its endstream: readers tolerate it, and the
        // strict marker would be object 2's, far past this stream's own data
        pdf.extend_from_slice(b"1 0 obj\n<< /Length 5 >>\nstream\nHELLO\nendstream\n2 0 obj\n");
        pdf.extend_from_slice(b"<< /Length 3 >>\nstream\nXYZ\nendstream\nendobj\n");
        assert_eq!(
            stream_payload_with_declared(&pdf, a, Some(5)).unwrap(),
            b"HELLO",
            "the next object is not this stream's payload"
        );
        assert_eq!(
            stream_payload_as_readers(&pdf, a).unwrap(),
            b"HELLO",
            "and the direct path agrees"
        );
    }
}
