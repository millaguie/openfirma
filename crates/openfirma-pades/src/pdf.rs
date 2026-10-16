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
use std::collections::BTreeMap;
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

/// What the last trailer of a document says.
#[derive(Clone, Debug)]
pub struct Trailer {
    pub root: ObjRef,
    pub size: u32,
    pub info: Option<ObjRef>,
    /// `startxref` of the previous revision, when this is an incremental update.
    pub prev: Option<usize>,
    /// Offset of the `xref` keyword or xref stream object of this revision.
    pub at: usize,
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
pub fn trailer(data: &[u8], xref_at: usize) -> Result<Trailer> {
    let dict = trailer_dict(data, xref_at)?;
    let root_bytes =
        get(&dict, "/Root").ok_or_else(|| Error::Pdf("the trailer has no /Root".into()))?;
    let root = parse_ref(root_bytes)
        .ok_or_else(|| Error::Pdf("/Root is not an indirect reference".into()))?;
    let size = get(&dict, "/Size")
        .and_then(|b| {
            std::str::from_utf8(trim_ws(b))
                .ok()?
                .trim()
                .parse::<u32>()
                .ok()
        })
        .unwrap_or(0);
    let info = get(&dict, "/Info").and_then(parse_ref);
    let prev = get(&dict, "/Prev").and_then(|b| {
        std::str::from_utf8(trim_ws(b))
            .ok()?
            .trim()
            .parse::<usize>()
            .ok()
    });
    Ok(Trailer {
        root,
        size,
        info,
        prev,
        at: xref_at,
    })
}

/// The trailer dictionary of one revision, as owned bytes.
fn trailer_dict(data: &[u8], xref_at: usize) -> Result<Vec<u8>> {
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
/// Later revisions are walked first, so `entry().or_insert()` keeps the newest
/// definition of an object that a previous revision also defined.
pub fn object_locations(data: &[u8], xref_at: usize) -> Result<BTreeMap<ObjRef, Location>> {
    let mut map = BTreeMap::new();
    let mut cur = Some(xref_at);
    let mut revisions = 0;
    while let Some(at) = cur {
        revisions += 1;
        if revisions > 100 {
            return Err(Error::Pdf(
                "more than 100 revisions, /Prev is probably a loop".into(),
            ));
        }
        let i = skip_ws(data, at);
        let (entries, dict) = if data[i..].starts_with(b"xref") {
            read_xref_table(data, i)?
        } else {
            read_xref_stream(data, i)?
        };
        for (r, loc) in entries {
            map.entry(r).or_insert(loc);
        }
        // A hybrid reference file carries a classic table for old readers and
        // points at a cross-reference stream for the objects only it knows
        // about. Both have to be read, or those objects look missing.
        if let Some(stm) = get(&dict, "/XRefStm").and_then(parse_uint) {
            if let Ok((extra, _)) = read_xref_stream(data, stm as usize) {
                for (r, loc) in extra {
                    map.entry(r).or_insert(loc);
                }
            }
        }
        cur = get(&dict, "/Prev").and_then(parse_uint).map(|v| v as usize);
    }
    Ok(map)
}

/// One classic cross-reference table: its in-use entries and its trailer.
///
/// Entries are walked by token rather than by assuming the 20 byte layout the
/// specification mandates, because a writer that gets the layout wrong still
/// produces a file that every reader accepts, and refusing to sign one is a
/// worse outcome than being lenient here.
fn read_xref_table(data: &[u8], i: usize) -> Result<(XrefEntries, Vec<u8>)> {
    let mut entries = Vec::new();
    let mut j = skip_ws(data, i + 4);
    loop {
        j = skip_ws(data, j);
        if data[j..].starts_with(b"trailer") {
            let t = skip_ws(data, j + 7);
            let end = dict_end(data, t)?;
            return Ok((entries, data[t..end].to_vec()));
        }
        let first_end = token_end(data, j);
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
            if kind == b'n' && num > 0 {
                entries.push((ObjRef::new(num, generation), Location::Direct(offset)));
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
fn read_xref_stream(data: &[u8], obj_at: usize) -> Result<(XrefEntries, Vec<u8>)> {
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
    let starts = [0, widths[0] as usize, (widths[0] + widths[1]) as usize];

    let mut entries = Vec::new();
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
                0 => {} // free, nothing to record
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
                other => {
                    return Err(Error::Pdf(format!(
                        "cross-reference entry type {other} does not exist, only 0, 1 and 2 do"
                    )));
                }
            }
        }
    }
    Ok((entries, dict))
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

fn parse_uint(bytes: &[u8]) -> Option<u32> {
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

    let mut from = i;
    while let Some(p) = data[from..].windows(9).position(|w| w == b"endstream") {
        let candidate = from + p;
        let after = skip_ws(data, candidate + 9);
        if data[after..].starts_with(b"endobj") {
            let mut end = candidate;
            // the end of line before the keyword is not part of the data either
            while end > i && (data[end - 1] == b'\n' || data[end - 1] == b'\r') {
                end -= 1;
            }
            return Ok(data[i..end].to_vec());
        }
        from = candidate + 9;
    }
    Err(Error::Pdf(format!(
        "the stream at {offset} has an indirect /Length and no endstream to fall back on"
    )))
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
        assert_eq!(tr.size, 6);
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
        let mut update = crate::update::Update::new(0, ObjRef::new(1, 0), None, 1);
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
        assert_eq!(tr.size, 6);

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
}
