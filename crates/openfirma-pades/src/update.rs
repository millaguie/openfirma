//! Writing the second revision: the objects, the cross-reference table and the
//! trailer that together make an incremental update.
//!
//! Everything here is appended after the untouched bytes of the input document,
//! which is the whole reason for doing it this way. See
//! docs/adr/0003-incremental-update.md.

use std::collections::BTreeMap;

use openfirma_core::{Error, Result};

use crate::pdf::{self, ObjRef};

/// One object to write. Objects that already exist in the document are written
/// under their original number and generation, which is how an incremental
/// update supersedes a definition: the new cross-reference entry wins, and
/// every `N G R` that the older revisions contain now resolves here.
pub struct Object {
    pub r: ObjRef,
    pub body: Vec<u8>,
}

impl Object {
    pub fn new(r: ObjRef, body: impl Into<Vec<u8>>) -> Self {
        Self {
            r,
            body: body.into(),
        }
    }
}

/// The bytes of a rendered revision and where each of its objects landed.
pub struct Rendered {
    pub bytes: Vec<u8>,
    pub offsets: BTreeMap<ObjRef, usize>,
}

pub struct Update {
    objects: Vec<Object>,
    prev_startxref: usize,
    root: ObjRef,
    info: Option<ObjRef>,
    size: u32,
    /// Whether the previous cross-reference section is a stream, in which case
    /// this revision must be one too: see [`crate::pdf::section_is_stream`] and
    /// round 2's finding N-3. A classic table whose `/Prev` points at a stream
    /// is a chain iText stops walking.
    xref_stream: bool,
    /// Keys the new trailer carries over verbatim from the previous one, in
    /// their original spelling and order (finding A-1). `/Prev`, `/Size`,
    /// `/Root` and the entries of a cross-reference stream are excluded; those
    /// belong to the revision being written, not to the one being copied.
    carry: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Update {
    /// Start from the previous revision's trailer dictionary (`dict`, exactly
    /// its `<< … >>` bytes). Every key it holds is carried into the new trailer
    /// verbatim except `/Prev`, `/Size`, `/Root`, `/Info` and the keys a
    /// cross-reference stream contributes, which describe the section being
    /// written rather than the document. ISO 32000-1 7.5.6 requires the
    /// appended trailer to hold all the entries of the previous one except
    /// `/Prev`; `/ID` in particular (finding A-1): PDF/A and PDF 2.0 require
    /// it, AutoFirma writes it, and dropping it is an interop failure that
    /// shows up only in validators.
    /// `xref_stream` says whether the previous cross-reference section is a
    /// stream, which the caller reads with [`pdf::section_is_stream`]; the
    /// revision written then has to be a stream as well, or the chain breaks
    /// for readers that walk it one kind at a time (round 2, N-3: AutoFirma's
    /// iText refuses to co-sign a document whose `/Prev` leaves a table for a
    /// stream).
    pub fn new_with_trailer(
        prev_startxref: usize,
        root: ObjRef,
        info: Option<ObjRef>,
        size: u32,
        previous_trailer: &[u8],
        xref_stream: bool,
    ) -> Result<Self> {
        let mut update = Self {
            objects: Vec::new(),
            prev_startxref,
            root,
            info,
            size,
            xref_stream,
            carry: Vec::new(),
        };
        update.carry_trailer(previous_trailer)?;
        Ok(update)
    }

    fn carry_trailer(&mut self, dict: &[u8]) -> Result<()> {
        // /Info is NOT carried below on purpose: every signing or archiving
        // revision rewrites that object (a new ModDate) and hands its own
        // reference to `new_with_trailer`, so carrying the old one would give
        // the trailer two /Info keys — qpdf warns and last-one-wins, which is
        // exactly the kind of ambiguity docs/adr/0003 exists to avoid. One
        // more than the keys below on purpose: if it ever carries /Info, this
        // count is wrong by construction.
        const NEW_REVISION: [&str; 11] = [
            "/Prev",
            "/Size",
            "/Root",
            "/Info",
            "/Type",
            "/W",
            "/Index",
            "/Filter",
            "/DecodeParms",
            "/Length",
            "/XRefStm",
        ];
        self.carry = Vec::new();
        for (k, v) in pdf::items(dict)? {
            let key = &dict[k.clone()];
            if NEW_REVISION.iter().any(|f| key == f.as_bytes()) {
                continue;
            }
            self.carry.push((key.to_vec(), dict[v].to_vec()));
        }
        Ok(())
    }

    pub fn push(&mut self, object: Object) {
        // saturating rather than checked: /Size is written as a number and an
        // object numbered u32::MAX simply leaves it at the top of the range.
        // A wrapping add here would publish a /Size of 0.
        self.size = self.size.max(object.r.num.saturating_add(1));
        self.objects.push(object);
    }

    /// Drop the `/Info` entry from the new trailer (the PDF/A case: the
    /// original had no `/Info` and a fresh dated one would be the only date
    /// its XMP does not carry).
    pub fn clear_info(&mut self) {
        self.info = None;
    }

    /// The highest object number plus one, which is where new objects start.
    pub fn next_object_number(&self) -> u32 {
        self.size
    }

    /// Renders the revision to append after `base_len` bytes, together with the
    /// absolute offset of every object in it. The signer needs those offsets to
    /// find its own placeholders again once the layout is fixed.
    ///
    /// Cross-reference offsets are absolute from the start of the file, so the
    /// length of what comes before has to be known here.
    pub fn render(&self, base_len: usize) -> Result<Rendered> {
        if self.objects.is_empty() {
            return Err(Error::Pdf(
                "an incremental update with no objects is pointless".into(),
            ));
        }
        let mut out = Vec::new();
        // start on a fresh line whatever the input ended with, so the first
        // object header cannot be glued onto the previous %%EOF
        out.push(b'\n');

        let mut offsets = BTreeMap::new();
        for o in &self.objects {
            offsets.insert(o.r, base_len + out.len());
            out.extend_from_slice(format!("{} {} obj\n", o.r.num, o.r.generation).as_bytes());
            out.extend_from_slice(&o.body);
            out.extend_from_slice(b"\nendobj\n");
        }

        let xref_at = base_len + out.len();
        if self.xref_stream {
            self.render_xref_stream(&mut out, xref_at, &offsets)?;
        } else {
            out.extend_from_slice(b"xref\n");
            for (first, run) in subsections(&offsets) {
                out.extend_from_slice(format!("{first} {}\n", run.len()).as_bytes());
                for (r, off) in run {
                    // exactly 20 bytes per entry, as ISO 32000 requires,
                    // counting the two character end of line that makes it 20
                    let line = format!("{off:010} {:05} n \n", r.generation);
                    debug_assert_eq!(line.len(), 20, "an xref entry must be 20 bytes");
                    out.extend_from_slice(line.as_bytes());
                }
            }

            // A-1: /Size, /Root, /Info, /Prev are what this revision sets for
            // itself; everything else the previous trailer held is copied
            // verbatim behind them. Order within a trailer dictionary carries
            // no meaning (ISO 32000 keys are unordered), so writing ours first
            // and the copied entries after cannot change how any reader
            // resolves them.
            out.extend_from_slice(b"trailer\n<< ");
            out.extend_from_slice(format!("/Size {}", self.size).as_bytes());
            out.extend_from_slice(format!(" /Root {}", self.root).as_bytes());
            if let Some(info) = self.info {
                out.extend_from_slice(format!(" /Info {info}").as_bytes());
            }
            out.extend_from_slice(format!(" /Prev {}", self.prev_startxref).as_bytes());
            for (key, value) in &self.carry {
                out.push(b' ');
                out.extend_from_slice(key);
                out.push(b' ');
                out.extend_from_slice(value);
            }
            out.extend_from_slice(b" >>\n");
        }
        out.extend_from_slice(b"startxref\n");
        out.extend_from_slice(format!("{xref_at}\n%%EOF\n").as_bytes());
        Ok(Rendered {
            bytes: out,
            offsets,
        })
    }

    /// The revision as a cross-reference *stream* (ISO 32000-1 7.5.8): the
    /// entries and the trailer in one object, which is what a revision after an
    /// xref stream must be. The stream object is numbered `/Size` — the first
    /// number past everything written so far — and the new `/Size` covers it.
    fn render_xref_stream(
        &self,
        out: &mut Vec<u8>,
        xref_at: usize,
        offsets: &BTreeMap<ObjRef, usize>,
    ) -> Result<()> {
        let stream_num = self.size;
        let mut entries: Vec<(u32, usize, u16)> = offsets
            .iter()
            .map(|(r, off)| (r.num, *off, r.generation))
            .collect();
        // the stream describes itself too, or a reader cannot find it
        entries.push((stream_num, xref_at, 0));
        entries.sort();

        let mut rows = Vec::with_capacity(entries.len() * 7);
        for (num, off, generation) in &entries {
            // /W [1 4 2]: one byte of type, four of offset, two of generation,
            // which is what every writer emits and every reader can parse. An
            // offset a 4 byte field cannot hold would silently truncate to a
            // wrong object, so it is refused.
            let off = u32::try_from(*off).map_err(|_| {
                Error::Pdf(format!(
                    "object {num} lands at byte {off}, past what the 4 byte cross-reference \
                     offsets of a stream can hold; the document is too large to update"
                ))
            })?;
            rows.push(1u8); // type 1: in use at that offset
            rows.extend_from_slice(&off.to_be_bytes());
            rows.extend_from_slice(&generation.to_be_bytes());
        }
        let compressed = deflate(&rows);
        let index: Vec<String> = runs(entries.iter().map(|(n, _, _)| *n))
            .into_iter()
            .map(|(first, count)| format!("{first} {count}"))
            .collect();

        out.extend_from_slice(format!("{stream_num} 0 obj\n<< /Type /XRef").as_bytes());
        out.extend_from_slice(
            format!(
                " /Size {} /W [1 4 2] /Index [{}]",
                stream_num.saturating_add(1),
                index.join(" ")
            )
            .as_bytes(),
        );
        out.extend_from_slice(format!(" /Root {}", self.root).as_bytes());
        if let Some(info) = self.info {
            out.extend_from_slice(format!(" /Info {info}").as_bytes());
        }
        out.extend_from_slice(format!(" /Prev {}", self.prev_startxref).as_bytes());
        for (key, value) in &self.carry {
            out.push(b' ');
            out.extend_from_slice(key);
            out.push(b' ');
            out.extend_from_slice(value);
        }
        out.extend_from_slice(
            format!(
                " /Length {} /Filter /FlateDecode >>\nstream\n",
                compressed.len()
            )
            .as_bytes(),
        );
        out.extend_from_slice(&compressed);
        out.extend_from_slice(b"\nendstream\nendobj\n");
        Ok(())
    }
}

/// Runs of consecutive object numbers, for a `/Index` array, which lists
/// `first count` pairs rather than one per object.
fn runs(nums: impl Iterator<Item = u32>) -> Vec<(u32, u32)> {
    let mut out: Vec<(u32, u32)> = Vec::new();
    for num in nums {
        match out.last_mut() {
            Some((first, count)) if *first + *count == num => *count += 1,
            _ => out.push((num, 1)),
        }
    }
    out
}

/// The Zlib stream of an xref stream's rows.
fn deflate(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(data).expect("writing into a Vec cannot fail");
    enc.finish().expect("writing into a Vec cannot fail")
}

/// Groups the offsets into runs of consecutive object numbers, because a
/// cross-reference table lists subsections rather than one entry per object.
fn subsections(offsets: &BTreeMap<ObjRef, usize>) -> Vec<(u32, Vec<(ObjRef, usize)>)> {
    let entries: Vec<(ObjRef, usize)> = offsets.iter().map(|(r, o)| (*r, *o)).collect();
    let mut out: Vec<(u32, Vec<(ObjRef, usize)>)> = Vec::new();
    for entry in entries {
        match out.last_mut() {
            Some((first, run)) if *first + run.len() as u32 == entry.0.num => run.push(entry),
            _ => out.push((entry.0.num, vec![entry])),
        }
    }
    out
}
