//! Writing the second revision: the objects, the cross-reference table and the
//! trailer that together make an incremental update.
//!
//! Everything here is appended after the untouched bytes of the input document,
//! which is the whole reason for doing it this way. See
//! docs/adr/0003-incremental-update.md.

use std::collections::BTreeMap;

use openfirma_core::{Error, Result};

use crate::pdf::ObjRef;

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
}

impl Update {
    /// `prev_startxref` is the `startxref` of the revision being appended to,
    /// and `size` its trailer's `/Size`.
    pub fn new(prev_startxref: usize, root: ObjRef, info: Option<ObjRef>, size: u32) -> Self {
        Self {
            objects: Vec::new(),
            prev_startxref,
            root,
            info,
            size,
        }
    }

    pub fn push(&mut self, object: Object) {
        // saturating rather than checked: /Size is written as a number and an
        // object numbered u32::MAX simply leaves it at the top of the range.
        // A wrapping add here would publish a /Size of 0.
        self.size = self.size.max(object.r.num.saturating_add(1));
        self.objects.push(object);
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
        out.extend_from_slice(b"xref\n");
        for (first, run) in subsections(&offsets) {
            out.extend_from_slice(format!("{first} {}\n", run.len()).as_bytes());
            for (_, off) in run {
                // exactly 20 bytes per entry, as ISO 32000 requires, counting
                // the two character end of line that makes it 20
                let line = format!("{off:010} 00000 n \n");
                debug_assert_eq!(line.len(), 20, "an xref entry must be 20 bytes");
                out.extend_from_slice(line.as_bytes());
            }
        }

        out.extend_from_slice(b"trailer\n<< ");
        out.extend_from_slice(format!("/Size {}", self.size).as_bytes());
        out.extend_from_slice(format!(" /Root {}", self.root).as_bytes());
        if let Some(info) = self.info {
            out.extend_from_slice(format!(" /Info {info}").as_bytes());
        }
        out.extend_from_slice(format!(" /Prev {} ", self.prev_startxref).as_bytes());
        out.extend_from_slice(b">>\nstartxref\n");
        out.extend_from_slice(format!("{xref_at}\n%%EOF\n").as_bytes());
        Ok(Rendered {
            bytes: out,
            offsets,
        })
    }
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
