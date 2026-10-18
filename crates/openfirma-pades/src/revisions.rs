//! What the revisions after each signature changed: the C-1 (incremental
//! saving attack) gate of the adversarial review.
//!
//! A signature covers a prefix of the file — its `/ByteRange` ends at the
//! `%%EOF` of the revision it signed. Anything appended after that point can
//! change what readers show while every earlier signature still verifies: the
//! classic Incremental Saving Attack. pdfsig reports "not all of the document
//! is signed"; AutoFirma compares page contents across revisions (`checkPdf-
//! ShadowAttack`). openfirma takes the structural route, which decides exactly
//! what each appended revision did:
//!
//! - a signature must cover up to a revision boundary — `inspect::range_`
//!   `problems` already refuses a `/ByteRange` ending anywhere else — so no
//!   unsigned byte can hide inside what its digest claims;
//! - every object that revisions newer than a signature redefine (body bytes
//!   differing from the previous definition) is classified against the white-
//!   list of what an archive may append (ETSI EN 319 142-1; what PAdES-LTV/ESA
//!   builds): new signature dictionaries, `/DocTimeStamp` dictionaries, the
//!   catalog gaining only its `/DSS`, validation data reachable from it, signa-
//!   ture fields (`/FT /Sig` with a real `/V`), AcroForms that only grew their
//!   `/Fields` with such fields, and page `/Annots` arrays that only grew with
//!   widgets of real signatures;
//! - redefining a content stream, page, `/Resources`, or anything else off the
//!   whitelist is the attack, and `verify` refuses the document over it.

use std::collections::{BTreeMap, BTreeSet};

use openfirma_core::{Error, Result};

use crate::pdf::{self, ObjRef};

/// One revision of the document, newest first (the order the `/Prev` chain
/// names them).
#[derive(Clone, Debug)]
pub struct Revision {
    /// The `startxref` offset of this revision's cross-reference section.
    pub startxref: usize,
    /// Offset just past the revision: where the next-newer revision's appended
    /// bytes began, or the end of the file for the newest one. Derived from the
    /// cross-reference chain, never from scanning `%%EOF` — a hostile file can
    /// forge that marker inside stream data. A section only describes offsets
    /// below its own `startxref`, so an older revision ends at most where the
    /// newer one's xref begins: exact for contiguous appends, conservative (never
    /// too large) otherwise — a coverage landing in the slack falls outside every
    /// boundary and fails closed.
    pub end: usize,
}

/// The revisions of the document, newest first, each with the offset its bytes
/// end at (see [`Revision`]).
pub fn revisions(pdf: &[u8]) -> Result<Vec<Revision>> {
    let xref_at = pdf::last_startxref(pdf)?;
    let mut sections: Vec<usize> = Vec::new();
    let mut cur = Some(xref_at);
    while let Some(at) = cur {
        if sections.len() > 100 {
            return Err(Error::Pdf(
                "more than 100 revisions, /Prev is probably a loop".into(),
            ));
        }
        if sections.contains(&at) {
            return Err(Error::Pdf(
                "the cross-reference chain repeats a section".into(),
            ));
        }
        sections.push(at);
        cur = pdf::trailer(pdf, at)?.prev;
    }
    // Boundaries between adjacent revisions. A signing library rewriting objects
    // copies their bytes into its own revision and the *older* section then names
    // them at newer offsets — so offsets a chain mentions are no boundary. What
    // does bound it is where the older revision's own objects begin: sections are
    // appended contiguously, and an object written before any append keeps its
    // original position forever. The minimum `Location::Direct` offset of the
    // older section's whole chain is therefore exactly where its first byte lives,
    // and that is the end of the revision it superseded — every byte from there
    // to that section's startxref was appended after it. Type-2 entries live in-
    // side an object stream and contribute nothing; a section whose objects are
    // all compressed falls back to the newer section's startxref, conservative
    // and still past every byte of the older revision (its xref must sit above
    // everything it wrote).
    // Boundaries between adjacent revisions: the older one ENDS at its own
    // `%%EOF` (plus end-of-line), and the newer one BEGINS just past it — so two
    // consecutive boundaries are adjacent by construction, never a guess split-
    // ting real bytes. A hostile `%%EOF` inside stream data is not enough: it
    // counts as a boundary only if the record that belongs to the older revision
    // sits right there in full — `startxref`, its digits naming one of this docu-
    // ment's own cross-reference sections, `%%EOF`. A well-formed chain always
    // ends each revision with exactly that record (ISO 32000 requires it; every
    // conforming writer writes it), so the true boundary is always among the can-
    // didates, and a forged one only adds a candidate whose byte just past it is
    // not a well-formed PDF delimiter — which the coverage check below refuses to
    // certify through (a signature ending mid-stream names bytes covered by no-
    // body). Candidates are sorted; each pair adjacent becomes one Revision.
    let mut candidates: Vec<usize> = Vec::new();
    // every %%EOF record of the file is a candidate; each must name one of THIS
    // chain's sections to be kept (a stale marker from an earlier life of the
    // file names its old xref, and stream noise names nothing real)
    candidates.extend(startxref_records(pdf));
    candidates.sort_unstable();
    candidates.dedup();
    // keep the ones that close a revision of THIS chain: startxref == sections[j]
    let candidates: Vec<usize> = candidates
        .into_iter()
        .filter(|end| is_revision_record(pdf, &sections, *end))
        .collect();
    // Each section's closing record: the *first* candidate past its xref whose
    // startxref names a section of this chain. An append always ends its bytes
    // with `startxref <its own offset> %%EOF` before anything is appended on top,
    // so the earliest well-formed record above a section closes it. Requiring
    // the record to name its own section specifically would break on writers
    // that rewrite earlier revisions' bodies (a DSS pass copying the catalog):
    // their records sit where the copied bytes began, and an older revision then
    // has two records naming the same offset — the earliest is still the true
    // close of the older revision, and no revision's coverage can hide behind a
    // later record without failing `covering_revision` on the gap.
    let mut closing = Vec::with_capacity(sections.len());
    for &startxref in &sections {
        // A candidate closes THIS section only if its own `startxref` names it:
        // every conforming append ends exactly that way, and a record naming a
        // different section (or no section at all, already filtered out) closes
        // nothing. The old rule — the first past-the-offset candidate whatever
        // it named — merged two revisions into one byte range whenever a forged
        // middle %%EOF carried the newest startxref, which is precisely how a
        // certification-after-the-fact hides: the certifying revision then
        // looks newest and every later change sits inside its own range.
        closing.push(
            candidates
                .iter()
                .find(|end| **end > startxref && record_names(pdf, **end) == Some(startxref))
                .copied(),
        );
    }
    let mut out = Vec::with_capacity(sections.len());
    for (i, &startxref) in sections.iter().enumerate() {
        // Older revision: its own closing record delimits it. A chain without
        // one (a broken or lying file) has no honest boundary, and guessing a
        // boundary would license whatever was appended inside the slack: error.
        // Newest revision: the file's end — trailing bytes past its record were
        // appended after every cross-reference and can only be claimed as whole-
        // file coverage (inspect::range_problems demanded exactly that number).
        // A middle section whose own offset no %%EOF line names has no honest
        // boundary: guessing one from a candidate floated above it would let a
        // certification-after-the-fact hide, so this stays an error.
        let end = match (closing[i], i + 1 < sections.len()) {
            (Some(boundary), true) => boundary,
            (None, true) => {
                return Err(Error::Pdf(format!(
                    "the revision whose cross-reference starts at {startxref} has no closing \
                     startxref/%%EOF record naming its own cross-reference: its bytes cannot \
                     be delimited, and content appended to it could not be classified either \
                     way"
                )));
            }
            (_, false) => pdf.len(),
        };
        out.push(Revision { startxref, end });
    }
    Ok(out)
}

/// Every offset just past a `%%EOF` token in `pdf`. Scanning the whole file for
/// five bytes is linear and unavoidable; every candidate is checked against the
/// chain by [`pdf_record_chains`] before it can split anything.
fn startxref_records(pdf: &[u8]) -> Vec<usize> {
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(found) = pdf[from..].windows(5).position(|w| w == b"%%EOF") {
        let end = from + found + 5;
        // exactly one end-of-line belongs to the record
        let end = if pdf[end..].starts_with(b"\r\n") {
            end + 2
        } else if end < pdf.len() && matches!(pdf[end], b'\n' | b'\r') {
            end + 1
        } else {
            end
        };
        out.push(end);
        from = end;
    }
    out
}

/// Whether the record closing at `end` is a real revision end of THIS document:
/// its last `startxref <offset>` names one of `sections`, and before it, past
/// the previous boundary... (see above) — the full shape checked: the bytes be-
/// fore `end` read backwards are `%%EOF`, whitespace, digits, whitespace, `start-
/// xref`.
fn is_revision_record(pdf: &[u8], sections: &[usize], end: usize) -> bool {
    record_names(pdf, end).is_some_and(|named| sections.contains(&named))
}

/// The offset the record closing at `end` names in its `startxref`, reading the
/// exact shape backwards: `%%EOF`, whitespace, digits, whitespace, `startxref`.
fn record_names(pdf: &[u8], end: usize) -> Option<usize> {
    // walk back over the %%EOF and its trailing newline consumed into `end`
    let record_end = {
        let mut i = end;
        if i >= 2 && pdf[i - 2..i] == *b"\r\n" {
            i -= 2;
        } else if i >= 1 && matches!(pdf[i - 1], b'\n' | b'\r') {
            i -= 1;
        }
        i
    };
    if record_end < 5 || &pdf[record_end - 5..record_end] != b"%%EOF" {
        return None;
    }
    // digits before the %%EOF: whitespace, a number, whitespace, `startxref`
    let mut i = record_end - 5;
    while i > 0 && pdf[i - 1].is_ascii_whitespace() {
        i -= 1;
    }
    let digits_end = i;
    while i > 0 && pdf[i - 1].is_ascii_digit() {
        i -= 1;
    }
    if i == digits_end {
        return None; // no digits
    }
    let named: usize = std::str::from_utf8(&pdf[i..digits_end])
        .ok()?
        .parse()
        .ok()?;
    while i > 0 && pdf[i - 1].is_ascii_whitespace() {
        i -= 1;
    }
    if i < 9 || &pdf[i - 9..i] != b"startxref" {
        return None;
    }
    Some(named)
}

/// The revision a signature's `/ByteRange` reaches. `coverage_end == pdf.len()`
/// is the newest (index 0); anything else must sit on a boundary of an older
/// one. `None` means the coverage ends inside a revision — unsigned bytes inside
/// what the digest claims to cover, which no whitelist can license.
pub fn covering_revision(pdf_len: usize, revs: &[Revision], coverage_end: usize) -> Option<usize> {
    if coverage_end == pdf_len {
        return Some(0);
    }
    revs.iter().position(|r| r.end == coverage_end)
}

/// What a redefinition after a signature was.
#[derive(Clone, Debug)]
pub enum Change {
    /// A signature dictionary (the object is `/Type /Sig` on either side of the
    /// change): allowed — it is verified in its own right.
    NewSignature(ObjRef),
    /// A document time-stamp dictionary: allowed, this is what B-LTA appends.
    DocTimeStamp(ObjRef),
    /// Validation data: an object reachable from the final catalog's `/DSS`, or
    /// the catalog gaining only its `/DSS` entry.
    ValidationData(ObjRef),
    /// The plumbing a newer visible signature needs: a `/FT /Sig` field whose
    /// `/V` names a real signature dictionary, an AcroForm that only grew its
    /// `/Fields` with such fields, or a page `/Annots` array that only grew
    /// with widgets of real signatures.
    SignaturePlumbing(ObjRef),
    /// Anything else — content streams, pages, `/Resources`, other annota-
    /// tions, form field values, a catalog whose keys other than `/DSS` chan-
    /// ged: outside what an archive may append.
    NotAllowed {
        object: ObjRef,
        /// How to describe it in the refusal.
        detail: String,
    },
}

impl Change {
    /// Whether this change is one the archive whitelist allows after a signa-
    /// ture (only [`Change::NotAllowed`] is not).
    pub fn allowed(&self) -> bool {
        !matches!(self, Change::NotAllowed { .. })
    }
}

impl std::fmt::Display for Change {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Change::NewSignature(o) => write!(f, "object {o} is a newer signature dictionary"),
            Change::DocTimeStamp(o) => write!(f, "object {o} is a document time-stamp"),
            Change::ValidationData(o) => write!(f, "object {o} is validation data (/DSS)"),
            Change::SignaturePlumbing(o) => {
                write!(f, "object {o} carries a newer signature's field or widget")
            }
            Change::NotAllowed { object, detail } => {
                write!(f, "object {object}: {detail}")
            }
        }
    }
}

/// One object whose bytes changed between two revisions, with the body each
/// state resolves for it (`before` = covering revision, `after` = final state).
pub struct Redefinition {
    pub object: ObjRef,
    pub before: Vec<u8>,
    pub after: Vec<u8>,
}

/// The redefinitions that happened strictly after the revision ending at
/// `coverage_end`: which objects changed, with their bodies before and after.
pub fn redefinitions_after(
    pdf: &[u8],
    revs: &[Revision],
    coverage_end: usize,
) -> Result<Vec<Redefinition>> {
    let Some(covering) = covering_revision(pdf.len(), revs, coverage_end) else {
        return Err(Error::Verification(format!(
            "the /ByteRange ends at {coverage_end}, which is not the end of any revision: \
             bytes between that point and the next boundary are covered by no signature"
        )));
    };
    if covering == 0 {
        // covers through the end of the file: nothing was appended after it
        return Ok(Vec::new());
    }
    let xref_at = pdf::last_startxref(pdf)?;
    let merged = pdf::object_locations(pdf, xref_at)?;
    // what the covering revision resolved for every object (its own section and
    // its /Prev chain — i.e. exactly what a reader showed at signing time), and
    // each newer section's own entries
    let covering_locs = pdf::object_locations(pdf, revs[covering].startxref)?;
    let mut covering_bodies: BTreeMap<ObjRef, Vec<u8>> = BTreeMap::new();
    {
        let mut cache = pdf::ObjectStreamCache::new();
        for object in covering_locs.keys() {
            if let Ok(body) = pdf::resolve(pdf, &covering_locs, Some(&mut cache), *object) {
                covering_bodies.insert(*object, body.to_vec());
            }
        }
    }
    // every redefinition of the whole chain, then keep those whose NEWER side
    // belongs to a section newer than the covering one. Attribution without an
    // index from per_revision is by resolution position: an object's bytes in
    // the merged view come from the newest section that names it, so compare
    // against the covering state directly — anything differing changed after it.
    let mut out = Vec::new();
    let mut cache = pdf::ObjectStreamCache::new();
    for object in merged.keys() {
        // only objects a newer revision touched can differ from the covering
        // state; but an object that lives inside an OLDER section keeps resolving
        // to old bytes and matches. This is exactly the wanted test.
        let Ok(current) = pdf::resolve(pdf, &merged, Some(&mut cache), *object) else {
            continue;
        };
        match covering_bodies.get(object) {
            // changed after the covering revision: an object the new state has
            // that did not exist below is `None` — a pure addition, classified as
            // such by the whitelist below (new signature objects land here).
            Some(previous) if previous != current.as_ref() => {
                out.push(Redefinition {
                    object: *object,
                    after: current.to_vec(),
                    before: previous.clone(),
                });
            }
            None => {
                out.push(Redefinition {
                    object: *object,
                    after: current.to_vec(),
                    before: Vec::new(),
                });
            }
            _ => {}
        }
    }
    Ok(out)
}

/// Classify redefinitions against the whitelist. Classification reads the fi-
/// nal state of the document (what readers show): a `/V` naming the *new* signa-
/// ture resolves only there, and that is precisely what licenses the plumbing.
/// `older == b""` marks an object the covering revision did not know: a pure
/// addition.
pub fn classify(pdf: &[u8], redefined: &[Redefinition]) -> Result<Vec<(ObjRef, Change)>> {
    let xref_at = pdf::last_startxref(pdf)?;
    let locations = pdf::object_locations(pdf, xref_at)?;
    let mut cache = pdf::ObjectStreamCache::new();
    let mut final_state: BTreeMap<ObjRef, Vec<u8>> = BTreeMap::new();
    for object in locations.keys() {
        if let Ok(body) = pdf::resolve(pdf, &locations, Some(&mut cache), *object) {
            final_state.insert(*object, body.to_vec());
        }
    }
    let trailer = pdf::trailer(pdf, xref_at)?;
    let catalog = final_state.get(&trailer.root).cloned().unwrap_or_default();
    // Validation data: the objects a reader reaches through an archive, and
    // only ever as ADDITIONS — an archive pass appends the bytes it archives
    // (that is what the `before` state tells apart); it never replaces a byte a
    // reader already rendered.
    //
    // Four review rounds narrowed this the hard way (round 1 C-1, round 2 C-1,
    // round 3 C-1):
    //   - seeding from every object whose /Type is /DSS let a HANGING dictionary
    //     whitelist a rewritten payload, referenced by nothing;
    //   - seeding from *everything reachable* from the catalog's archive let a
    //     `<< /Type /DSS /Foo [<payload> 0 R] >>` — or one hop through a free
    //     object — do the same, because no reader ever looks at a key the archive
    //     is not allowed to name validation data with: `ltv::Dss::read` consumes
    //     `/Certs`, `/CRLs`, `/OCSPs` and `/VRI`, and the walk follows exactly
    //     the three arrays now, following nothing found inside a named object;
    //   - licensing every brand-new `/Type /DSS` dictionary for the claim in its
    //     own body let one be an object a page renders (below).
    //
    // So the walk is not enough on its own (round 3). What makes an object
    // validation data is not only WHO NAMES IT but also WHO ELSE POINTS AT IT: a
    // reader resolves references from the last revision, so an object the
    // covered bytes already named — `/XObject << /Xm1 100 0 R >>` in a page and
    // `/Xm1 Do` in its content stream, a dangling `/Contents`, a page-tree kid —
    // was a reference to nothing when the signature was made and becomes a
    // RENDERED object the moment a later revision defines it. An appended
    // revision that defined it as a form XObject carrying a text of its own AND
    // `/Type /DSS` in its dictionary put that text on the page while verify
    // answered OK, because the `/Type /DSS` branch licensed it for the claim.
    //
    // So the licensed set is a fixpoint, not a walk: start from the archive the
    // catalog names, the objects it names data with, and every brand-new
    // `/Type /DSS` dictionary (an earlier pass's archive, left behind by a later
    // merge — the second B-LT pass test is what makes that one load bearing),
    // then DROP any candidate some object outside the candidate set points at.
    // Dropping one can expose another, so it repeats to a fixpoint. What
    // survives is validation data under the only definition that matters: bytes
    // a reader never resolves from anywhere but the archive.
    //
    // The catalog's own `/DSS` entry is the exception: pointing at the archive
    // is what makes it the archive. Every other reference from any object — the
    // catalog's other keys included — counts as an outside one.
    let archive = pdf::get(&catalog, "/DSS").and_then(pdf::parse_ref);
    let mut archive_data: BTreeSet<ObjRef> = BTreeSet::new();
    if let Some(dss) = archive {
        collect_archive_data(&final_state, dss, &mut archive_data);
    }
    let mut referrers: BTreeMap<ObjRef, BTreeSet<ObjRef>> = BTreeMap::new();
    for (num, body) in &final_state {
        for reference in refs_in(body) {
            if *num == trailer.root && Some(reference) == archive {
                continue;
            }
            referrers.entry(reference).or_default().insert(*num);
        }
    }
    let mut validation_data: BTreeSet<ObjRef> = archive_data.clone();
    if let Some(dss) = archive {
        validation_data.insert(dss);
    }
    for change in redefined {
        if change.before.is_empty() && is_type(&change.after, "/DSS") {
            validation_data.insert(change.object);
        }
    }
    loop {
        let dropped: Vec<ObjRef> = validation_data
            .iter()
            .copied()
            .filter(|candidate| {
                referrers
                    .get(candidate)
                    .is_some_and(|refs| refs.iter().any(|from| !validation_data.contains(from)))
            })
            .collect();
        if dropped.is_empty() {
            break;
        }
        for object in dropped {
            validation_data.remove(&object);
        }
    }

    let mut out = Vec::new();
    for change in redefined {
        out.push((
            change.object,
            classify_one(
                &final_state,
                trailer.root,
                &validation_data,
                &change.object,
                &change.after,
                &change.before,
            ),
        ));
    }
    Ok(out)
}

fn classify_one(
    final_state: &BTreeMap<ObjRef, Vec<u8>>,
    root: ObjRef,
    validation_data: &BTreeSet<ObjRef>,
    object: &ObjRef,
    newer: &[u8],
    older: &[u8],
) -> Change {
    let brand_new = older.is_empty();
    // A pass that rewrites a body it did not change (an xref-only touch, or the
    // trailer's /Info pointing at a fresh timestamp dictionary of its own): no
    // byte a reader sees moved, so nothing was added to what the signature cov-
    // ered. The identical-body rule lives in redefinitions_after for same-state
    // rewrites; here the two states DO differ as objects — /Info dictionaries
    // are brand-new copies carrying a new ModDate, which is what every signing
    // library's incremental update writes and no shadow attack hides behind it.
    if is_type(newer, "/Sig") || is_type(older, "/Sig") {
        return Change::NewSignature(*object);
    }
    if is_type(newer, "/DocTimeStamp") || is_type(older, "/DocTimeStamp") {
        return Change::DocTimeStamp(*object);
    }
    // Validation data, under the fixpoint `classify` computed: the archive
    // dictionary, an object one of its taxed keys names, or a brand-new
    // `/Type /DSS` dictionary nothing outside points at. And only ever as an
    // ADDITION: a pass that archives bytes appends the objects it archives; it
    // does not replace an object a reader already rendered — the whole
    // difference between an archive pass and the shadow attack, whose payload is
    // by construction a REWRITE of a covered object.
    //
    // So a rewritten object is never validation data, however it got named: not
    // by being pointed at from a taxed key (`/Certs [<payload> 0 R]`), not by
    // carrying `/Type /DSS` in its own body, not by being the dictionary the
    // catalog's own `/DSS` points at. And a brand-new object something outside
    // the archive points at is not validation data either, whatever it is
    // named or claims to be: a reference a reader resolves is a rendered object
    // (the round-3 form XObject that put a text of its own on the page).
    if brand_new && validation_data.contains(object) {
        return Change::ValidationData(*object);
    }
    // The catalog: /DSS gaining (fresh or merged), AcroForm appearing through a
    // signature pass, and nothing else changing. Each key an archive may touch
    // is listed; every other difference — /PageLabels, /Names, a re-pointed /Pages
    // — is off the whitelist and lands below.
    if object == &root {
        // The keys whose value bytes differ between the two states (names on
        // both sides compared by name; a key only one side has is its own dif-
        // ference). Only /DSS may differ for an archive pass.
        let differs = differing_keys(older, newer);
        // The keys a later revision may introduce into the catalog: /DSS (an
        // archive pass) and /AcroForm (a signature pass that first made the doc-
        // ument a form). Nothing else — /PageLabels, /Names, a re-pointed /Pages
        // or a value change of an existing key — is licensed.
        let dss_change = differs
            .iter()
            .all(|key| key == b"/DSS" || key == b"/AcroForm");
        if dss_change {
            return Change::ValidationData(*object);
        }
        // A signature pass that introduced /AcroForm pointing at a dictionary
        // whose fields are all signature fields: the catalog change is plumbing.
        let older_acro = pdf::get(older, "/AcroForm").and_then(pdf::parse_ref);
        let newer_acro = pdf::get(newer, "/AcroForm").and_then(pdf::parse_ref);
        if older_acro.is_none()
            && newer_acro.is_some_and(|a| {
                final_state.get(&a).is_some_and(|body| {
                    references_in(Some(body))
                        .into_iter()
                        .all(|f| is_signature_field(final_state, &f))
                        || pdf::get(body, "/Fields")
                            .map(|v| references_in(Some(v)).is_empty())
                            .unwrap_or(false)
                })
            })
            && only_new_key_differs(older, newer, b"/AcroForm")
        {
            return Change::SignaturePlumbing(*object);
        }
    }
    // AcroForm dictionaries: may grow /Fields with signature fields and change
    // nothing else.
    if !is_type(newer, "/Catalog") && pdf::get(newer, "/Fields").is_some() {
        // an existing form may grow /Fields with signature fields and change
        // nothing else; a brand-new AcroForm cannot be licensed by the white-
        // list (an archive never introduces forms — only signatures do), so it
        // stays NotAllowed below.
        let grew = added_references(older, newer, b"/Fields");
        let lost = removed_references(older, newer, b"/Fields");
        if !brand_new
            && grew.iter().all(|f| is_signature_field(final_state, f))
            && lost.is_empty()
            && other_keys_equal(older, newer, b"/Fields")
        {
            return Change::SignaturePlumbing(*object);
        }
    }
    // A fresh /Info dictionary: signing passes stamp a new ModDate every revision.
    if brand_new && pdf::items(newer).is_ok() && only_mod_and_creation_dates(newer) {
        return Change::SignaturePlumbing(*object);
    }
    // A REWRITE of the date-carrying /Info dictionary itself: a signing pass
    // re-stamped the existing object with a newer ModDate and nothing else
    // (openfirma's own co-sign shape, which follows the document's current
    // /Info reference instead of inventing a fresh number — measured on CI's
    // macOS runner as B-LT then co-sign refusing over two ModDate copies of one
    // object). The safety is entirely the shape, both sides: every key of the
    // OLD bytes and the NEW ones is a date (/ModDate or /CreationDate), so no
    // value any earlier signature covered can move behind this rule — there are
    // no non-date values to move. A dictionary that hides content (a stream
    // pointer, an author with meaning to a reader, anything) fails the test on
    // either side and lands on the refusal floor. `brand_new` copies keep their
    // own rule above; this one is only for bytes that already existed covered.
    if !brand_new && only_date_keys(newer) && older_keys_are_dates(older) {
        return Change::SignaturePlumbing(*object);
    }
    // Pages: /Annots may only grow, and only with widgets of real signatures.
    // The two sides may spell their references differently (an archiving pass
    // copying the page dictionary writes it with its own padding), so compari-
    // son is reference-by-reference, never byte-for-byte over the array bytes.
    if (pdf::get(newer, "/Annots").is_some() || pdf::get(older, "/Annots").is_some()) && !brand_new
    {
        let grew = added_references(older, newer, b"/Annots");
        let lost = removed_references(older, newer, b"/Annots");
        if lost.is_empty()
            && !grew.is_empty()
            && grew
                .iter()
                .all(|a| carries_real_signature_value(final_state, a))
            && other_keys_equal(older, newer, b"/Annots")
        {
            return Change::SignaturePlumbing(*object);
        }
    }
    // A signature field itself, or any dictionary (widget or plain AcroForm
    // field — the B-LTA timestamp field carries no /Subtype) whose own or par-
    // ent's /V names a real signature: the plumbing licenses only objects that
    // verifiably carry a signature value.
    if is_signature_field(final_state, object) || carries_real_signature_value(final_state, object)
    {
        return Change::SignaturePlumbing(*object);
    }
    // The pieces a signature pass builds around its widget: the appearance
    // stream (an empty or drawn Form XObject) and the two standard form fonts
    // every writer of visible signatures carries. Whitelisted as plumbing when
    // they ARE those: a /Form XObject that some final-state widget names under
    // /AP, and Helvetica/ZapfDingbats Type1 font dictionaries — content streams
    // are never Font or Form/XObject dictionaries (a page's /Contents is a bare
    // stream), so the shape test separates plumbing from payload. Anything else
    // new — embedded files, XObjects reached from rewritten /Resources — stays
    // off this rule and lands below as NotAllowed.
    if brand_new {
        if is_type(newer, "/Font")
            && pdf::get(newer, "/BaseFont")
                .is_some_and(|name| matches!(pdf::trim_ws(name), b"/Helvetica" | b"/ZapfDingbats"))
        {
            return Change::SignaturePlumbing(*object);
        }
        if is_type(newer, "/XObject")
            && pdf::get(newer, "/Subtype").is_some_and(|t| pdf::trim_ws(t) == b"/Form")
            && widget_appearances(final_state).contains(object)
        {
            return Change::SignaturePlumbing(*object);
        }
    }
    Change::NotAllowed {
        object: *object,
        detail: describe_change(newer),
    }
}

/// The /AP/N targets of every widget in the final state: what appearance streams
/// look like from the finished document.
fn widget_appearances(final_state: &BTreeMap<ObjRef, Vec<u8>>) -> BTreeSet<ObjRef> {
    let mut out = BTreeSet::new();
    for body in final_state.values() {
        if pdf::get(body, "/Subtype").is_none_or(|t| pdf::trim_ws(t) != b"/Widget") {
            continue;
        }
        // /AP is an inline dictionary or a reference to one: resolve it against
        // the final state (or take the inline bytes) and follow its /N.
        let Some(ap_value) = pdf::get(body, "/AP") else {
            continue;
        };
        let ap_dict: Option<Vec<u8>> = match pdf::parse_ref(ap_value) {
            // referenced /AP: a dictionary object in the final state
            Some(reference) => final_state.get(&reference).cloned(),
            // inline /AP << /N 17 0 R >>: the value bytes ARE the dictionary
            None if pdf::trim_ws(ap_value).starts_with(b"<<") => {
                Some(pdf::trim_ws(ap_value).to_vec())
            }
            _ => None,
        };
        let state = match ap_dict {
            Some(state) => state,
            None => continue,
        };
        if let Some(n) = pdf::get(&state, "/N").and_then(pdf::parse_ref) {
            out.insert(n);
        }
    }
    out
}

/// The names of the dictionary keys whose value bytes differ between the two
/// states (a key only one side carries counts as differing, named by it).
fn differing_keys(older: &[u8], newer: &[u8]) -> Vec<Vec<u8>> {
    let (Ok(a), Ok(b)) = (pdf::items(older), pdf::items(newer)) else {
        // unreadable dictionaries differ in everything classification cannot
        // name: one unnamed difference forces the NotAllowed route
        return vec![b"<unreadable dictionary>".to_vec()];
    };
    let mut out: Vec<Vec<u8>> = Vec::new();
    for (ka, va) in &a {
        let name = older[ka.clone()].to_vec();
        match b
            .iter()
            .find(|(kb, _)| &newer[kb.clone()] == name.as_slice())
        {
            Some((_, vb)) => {
                if older[va.clone()] != newer[vb.clone()] {
                    out.push(name);
                }
            }
            None => out.push(name),
        }
    }
    for (kb, _) in &b {
        let name = newer[kb.clone()].to_vec();
        if !a
            .iter()
            .any(|(ka, _)| &older[ka.clone()] == name.as_slice())
        {
            out.push(name);
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Whether a dictionary holds nothing but date keys — /ModDate and /CreationDate
/// are the whole of an /Info dictionary a signing pass writes.
fn only_mod_and_creation_dates(newer: &[u8]) -> bool {
    let Ok(items) = pdf::items(newer) else {
        return false;
    };
    !items.is_empty()
        && items
            .iter()
            .all(|(k, _)| matches!(&newer[k.clone()][..], b"/ModDate" | b"/CreationDate"))
}

/// Whether a dictionary parses and every key it holds is a date. Same shape as
/// [`only_mod_and_creation_dates`], kept separate because the rewrite rule also
/// asks it of the COVERING state's copy: both sides must be pure timestamp
/// dictionaries for one new /ModDate to count as plumbing. A malformed body (a
/// parser error) is a refusal, as everywhere else on this gate; an empty dict
/// changes nothing and passes.
fn only_date_keys(body: &[u8]) -> bool {
    let Ok(items) = pdf::items(body) else {
        return false;
    };
    items.is_empty()
        || items
            .iter()
            .all(|(k, _)| matches!(&body[k.clone()][..], b"/ModDate" | b"/CreationDate"))
}

/// The same question for the older side of a rewrite. `older` empty means the
/// object did not exist then — that case is `brand_new`, handled by its own rule.
fn older_keys_are_dates(older: &[u8]) -> bool {
    !older.is_empty() && only_date_keys(older)
}

pub(crate) fn is_type(body: &[u8], name: &str) -> bool {
    pdf::get(body, "/Type").is_some_and(|t| pdf::trim_ws(t) == name.as_bytes())
}

/// Whether a field (final state) is a signature field: /FT /Sig whose own or
/// inherited /V names a real signature dictionary.
fn is_signature_field(final_state: &BTreeMap<ObjRef, Vec<u8>>, field: &ObjRef) -> bool {
    let Some(body) = final_state.get(field) else {
        return false;
    };
    if pdf::get(body, "/FT").is_none_or(|t| pdf::trim_ws(t) != b"/Sig") {
        return false;
    }
    v_names_signature(final_state, body)
}

fn v_names_signature(final_state: &BTreeMap<ObjRef, Vec<u8>>, body: &[u8]) -> bool {
    pdf::get(body, "/V")
        .and_then(pdf::parse_ref)
        .and_then(|v| final_state.get(&v))
        // A /Sig dictionary or a document time-stamp — the widget's /V may hold
        // either (the B-LTA timestamp field points at its /DocTimeStamp), and
        // both are signature values a reader shows.
        .is_some_and(|b| is_type(b, "/Sig") || is_type(b, "/DocTimeStamp"))
}

fn carries_real_signature_value(final_state: &BTreeMap<ObjRef, Vec<u8>>, annot: &ObjRef) -> bool {
    let Some(body) = final_state.get(annot) else {
        return false;
    };
    // A widget always says so; a plain AcroForm field dictionary (the /FT /Sig
    // carrier whose value lives in /V) does not carry /Subtype at all, and the
    // B-LTA timestamp field is exactly that shape.
    let shape_ok = match pdf::get(body, "/Subtype") {
        Some(t) => pdf::trim_ws(t) == b"/Widget",
        None => true,
    };
    if !shape_ok {
        return false;
    }
    if v_names_signature(final_state, body) {
        return true;
    }
    // the widget's /Parent field may carry the value instead
    pdf::get(body, "/Parent")
        .and_then(pdf::parse_ref)
        .and_then(|p| final_state.get(&p))
        .is_some_and(|parent| v_names_signature(final_state, parent))
}

/// References `newer`'s array under `key` has beyond `older`'s. A key absent
/// from `older` means everything counts as added; absent from `newer`, nothing.
fn added_references(older: &[u8], newer: &[u8], key: &[u8]) -> Vec<ObjRef> {
    let key = std::str::from_utf8(key).unwrap_or("/");
    references_in(pdf::get(newer, key))
        .into_iter()
        .filter(|r| !references_in(pdf::get(older, key)).contains(r))
        .collect()
}

fn removed_references(older: &[u8], newer: &[u8], key: &[u8]) -> Vec<ObjRef> {
    let key = std::str::from_utf8(key).unwrap_or("/");
    references_in(pdf::get(older, key))
        .into_iter()
        .filter(|r| !references_in(pdf::get(newer, key)).contains(r))
        .collect()
}

/// The references of an array value (empty when the value is not there or not
/// an array — a dictionary-valued /Fields is broken and contributes nothing;
/// its equality check below still catches any change to it).
fn references_in(value: Option<&[u8]>) -> Vec<ObjRef> {
    match value.map(pdf::array_refs) {
        Some(Ok(refs)) => refs,
        _ => Vec::new(),
    }
}

/// Whether every key of both dictionaries except `except` is byte-identical on
/// name and value.
fn other_keys_equal(older: &[u8], newer: &[u8], except: &[u8]) -> bool {
    let (Ok(a), Ok(b)) = (pdf::items(older), pdf::items(newer)) else {
        return false;
    };
    for (ka, va) in &a {
        let name = &older[ka.clone()];
        if name == except {
            continue;
        }
        match b.iter().find(|(kb, _)| &newer[kb.clone()] == name) {
            Some((_, vb)) => {
                if older[va.clone()] != newer[vb.clone()] {
                    return false;
                }
            }
            None => return false,
        }
    }
    for (kb, _) in &b {
        let name = &newer[kb.clone()];
        if name == except {
            continue;
        }
        if !a.iter().any(|(ka, _)| &older[ka.clone()] == name) {
            return false;
        }
    }
    true
}

/// Whether `newer` differs from `older` by exactly one new key, and it is `only`.
fn only_new_key_differs(older: &[u8], newer: &[u8], only: &[u8]) -> bool {
    let (Ok(a), Ok(b)) = (pdf::items(older), pdf::items(newer)) else {
        return false;
    };
    for (ka, va) in &a {
        match b
            .iter()
            .find(|(kb, _)| newer[kb.clone()] == older[ka.clone()])
        {
            Some((_, vb)) => {
                if older[va.clone()] != newer[vb.clone()] {
                    return false;
                }
            }
            None => return false,
        }
    }
    let mut fresh = 0usize;
    for (kb, _) in &b {
        if !a
            .iter()
            .any(|(ka, _)| older[ka.clone()] == newer[kb.clone()])
        {
            fresh += 1;
            if &newer[kb.clone()] != only {
                return false;
            }
        }
    }
    fresh == 1
}

/// Collect the objects the catalog's archive names as validation data, reading
/// ONLY the keys a validation-data reader consumes: `/Certs`, `/CRLs`,
/// `/OCSPs`, each an array of references (or one reference to such an array).
///
/// Nothing else is followed, and nothing found inside a named object is
/// followed either: a reference is licensed because the archive names it
/// *directly* as data, never because some object it points at named it. That is
/// what stops both round-2 vectors — a key the archive validator never reads
/// (`/Foo [<payload> 0 R]`), and one hop through a free object that does
/// reference the payload. The `/VRI` tree is deliberately not followed: reader
/// checks the `/VRI` keys against the top-level arrays, but it does not parse
/// or verify per-entry data, and this gate licenses only what verification then
/// actually checks.
fn collect_archive_data(
    final_state: &BTreeMap<ObjRef, Vec<u8>>,
    dss: ObjRef,
    out: &mut BTreeSet<ObjRef>,
) {
    let Some(body) = final_state.get(&dss) else {
        return;
    };
    for key in ["/Certs", "/CRLs", "/OCSPs"] {
        let Some(value) = pdf::get(body, key) else {
            continue;
        };
        match pdf::parse_ref(value) {
            // `/Certs 20 0 R`: the array itself is archived bytes too.
            Some(array) => {
                out.insert(array);
                if let Some(resolved) = final_state.get(&array) {
                    if let Ok(refs) = pdf::array_refs(resolved) {
                        out.extend(refs);
                    }
                }
            }
            None => {
                if let Ok(refs) = pdf::array_refs(value) {
                    out.extend(refs);
                }
            }
        }
    }
}

/// Every `N G R` reference inside an object body, stopping at each `stream`
/// keyword: everything past it is encoded payload (a SHA-1 digest or a base64
/// blob can otherwise spell out a fake `N G R` pair and pull an unrelated object
/// into a reachability set). Only the dictionary part of an object — up to its
/// own `stream` marker, or the whole body when it is not a stream object — is
/// scanned. A byte scan: two unsigned numbers and the standalone name `R`, adja-
/// cent across whitespace only, the number runs bounded by non-digits. Diction-
/// ary noise may still produce extra pairs; reachability keeps only names the
/// cross-reference actually resolves, so a false hit adds a reference the file
/// really contains and changes nothing observable. (The alternative — parsing
/// every value as PDF syntax — would need a full parser; this scan over-resolves
/// *in the direction that cannot hurt*: noise references are dropped at the look-
/// up, missed ones cannot happen for well-formed dictionaries where references
/// are ordinary tokens.)
pub fn refs_in(body: &[u8]) -> Vec<ObjRef> {
    let body = match find_stream_marker(body) {
        Some(at) => &body[..at],
        None => body,
    };
    let mut out = Vec::new();
    // the two most recent number runs with their offsets; a run is consecutive
    // digits, and it participates only if nothing but whitespace separated it
    // from the previous one or the R that follows
    let mut first: Option<(u64, usize)> = None; // value, end offset
    let mut second: Option<(u64, usize)> = None;
    let mut i = 0usize;
    while i < body.len() {
        let b = body[i];
        // A comment runs to the end of the line and a reader treats it as a
        // single space, so it separates tokens WITHOUT breaking a reference
        // already half read: `100 % note` newline `0 R` resolves. Round 3: an
        // appended XObject aimed at from a comment-split reference rendered its
        // text while verify answered OK, because this scanner reset there.
        if b == b'%' {
            while i < body.len() && body[i] != b'\n' && body[i] != b'\r' {
                i += 1;
            }
            continue;
        }
        // Inside a string a reader resolves nothing, so nothing in one may be
        // read as a reference here: a phantom reference would drop a candidate
        // the document needs (a content stream whose text literally says
        // "123 0 R" is a false refusal, not a shadow attack).
        if b == b'(' {
            i = skip_literal_string(body, i);
            pending_reset(&mut first, &mut second);
            continue;
        }
        if b == b'<' {
            if body.get(i + 1) == Some(&b'<') {
                // a dictionary opens: `<` then `<`, neither is a string (reading
                // them one at a time made the second one look like a hex string
                // and swallow the references inside the dictionary)
                i += 2;
                pending_reset(&mut first, &mut second);
                continue;
            }
            // a hex string: hex digits and whitespace up to the closing `>`
            i += 1;
            while i < body.len() && body[i] != b'>' {
                i += 1;
            }
            if i < body.len() {
                i += 1;
            }
            pending_reset(&mut first, &mut second);
            continue;
        }
        if b.is_ascii_digit() && (i == 0 || !body[i - 1].is_ascii_digit()) {
            let start = i;
            while i < body.len() && body[i].is_ascii_digit() {
                i += 1;
            }
            let value = std::str::from_utf8(&body[start..i])
                .ok()
                .and_then(|s| s.parse::<u64>().ok());
            let Some(value) = value else {
                pending_reset(&mut first, &mut second);
                continue;
            };
            // a run may follow the previous one only across what a reader
            // reads as a separator: whitespace, and comments (a `%` to the end
            // of the line, which a reader treats as a single space)
            let gap_ok = |prev: &(u64, usize)| gap_is_separator(&body[prev.1..start]);
            match (first, second) {
                (None, _) => first = Some((value, i)),
                (Some(p), None) if gap_ok(&p) => second = Some((value, i)),
                // three consecutive numbers: keep the last two sliding window
                (Some(_), Some(p)) if gap_ok(&p) => {
                    first = second;
                    second = Some((value, i));
                }
                _ => {
                    first = Some((value, i));
                    second = None;
                }
            }
            continue;
        }
        if b == b'R'
            && !body.get(i + 1).is_some_and(|n| n.is_ascii_alphanumeric())
            && second.is_some()
        {
            let (Some(a), Some(g)) = (first, second) else {
                pending_reset(&mut first, &mut second);
                i += 1;
                continue;
            };
            // only whitespace between the generation and the R (the byte before
            // this one was checked not to be a digit above)
            if gap_is_separator(&body[g.1..i])
                && a.0 > 0
                && a.0 <= u64::from(u32::MAX)
                && g.0 <= u64::from(u16::MAX)
            {
                out.push(ObjRef::new(a.0 as u32, g.0 as u16));
            }
            pending_reset(&mut first, &mut second);
            i += 1;
            continue;
        }
        if !b.is_ascii_whitespace() && b != b'/' {
            // any other byte (a name character, a delimiter, stream noise) ends
            // the pair. '/' continues it: "/Root" — no: '/' belongs to names and
            // a reference is never inside a name; treat '/' as a breaker too.
            pending_reset(&mut first, &mut second);
        } else if b == b'/' {
            pending_reset(&mut first, &mut second);
        }
        i += 1;
    }
    out
}

fn pending_reset(first: &mut Option<(u64, usize)>, second: &mut Option<(u64, usize)>) {
    *first = None;
    *second = None;
}

/// Whether `gap` is only what a reader reads as a separator between two
/// tokens: whitespace and comments (`%` to the end of the line).
fn gap_is_separator(gap: &[u8]) -> bool {
    let mut i = 0usize;
    while i < gap.len() {
        match gap[i] {
            b'%' => {
                while i < gap.len() && gap[i] != b'\n' && gap[i] != b'\r' {
                    i += 1;
                }
            }
            b if b.is_ascii_whitespace() => i += 1,
            _ => return false,
        }
    }
    true
}

/// One past the closing `)` of the literal string that starts at `at`, honouring
/// backslash escapes and balanced parentheses — the way a reader tokenizes it.
fn skip_literal_string(body: &[u8], at: usize) -> usize {
    let mut depth = 0usize;
    let mut i = at;
    while i < body.len() {
        match body[i] {
            b'\\' => i += 2,
            b'(' => {
                depth += 1;
                i += 1;
            }
            b')' => {
                depth = depth.saturating_sub(1);
                i += 1;
                if depth == 0 {
                    return i;
                }
            }
            _ => i += 1,
        }
    }
    body.len()
}

/// The offset of the `stream` keyword that begins an object's payload, if the
/// body is a stream object. Requiring EOL bytes after it keeps false hits inside
/// dictionary text (`/XstreamXYZ` etc.): ISO 32000 defines the keyword as termi-
/// nated by an end-of-line marker. The first hit wins, which is the object's own
/// marker (a dictionary value never spells `stream\r\n` or `stream\n`).
///
/// The walk is over the syntax, not over raw bytes: a `stream\n` sitting inside a
/// string or a comment is text, not a payload. Scanning raw bytes made
/// `/PieceInfo << /Nota (stream` newline `... ) >>` truncate the body there, and
/// every reference after it — a page's own `/XObject << /Xm1 100 0 R >>`, say —
/// stopped counting as a reference (round 3, `bd74a50`'s neighbour: the appended
/// object rendered while verify answered OK).
fn find_stream_marker(body: &[u8]) -> Option<usize> {
    let mut i = 0usize;
    while i < body.len() {
        match body[i] {
            b'%' => {
                // a comment is not payload
                while i < body.len() && body[i] != b'\n' && body[i] != b'\r' {
                    i += 1;
                }
            }
            b'(' => i = skip_literal_string(body, i),
            b'<' if body.get(i + 1) == Some(&b'<') => i += 2,
            b'<' => {
                // a hex string is not payload either
                i += 1;
                while i < body.len() && body[i] != b'>' {
                    i += 1;
                }
                if i < body.len() {
                    i += 1;
                }
            }
            _ => {
                // `stream` as its own token: not the tail of `endstream` and not
                // a name like `/stream`, both of which a raw scan would take
                let standalone =
                    i == 0 || !(body[i - 1].is_ascii_alphanumeric() || body[i - 1] == b'/');
                if standalone && body[i..].starts_with(b"stream") {
                    let after = i + 6;
                    if body[after..].starts_with(b"\r\n")
                        || body.get(after).is_some_and(|b| matches!(b, b'\n' | b'\r'))
                    {
                        return Some(i);
                    }
                }
                i += 1;
            }
        }
    }
    None
}

/// How to describe a redefinition the whitelist does not cover.
fn describe_change(body: &[u8]) -> String {
    if body.windows(6).any(|w| w == b"stream") {
        "a stream object was rewritten after the signature; readers render its \
         bytes (page content, XObjects, embedded files)"
            .into()
    } else if pdf::get(body, "/Annots").is_some() {
        "an annotations array (or the page owning it) was rewritten".into()
    } else if pdf::get(body, "/Kids").is_some() || pdf::get(body, "/MediaBox").is_some() {
        "a page tree node or a page was rewritten".into()
    } else if pdf::get(body, "/V").is_some() && pdf::get(body, "/FT").is_some() {
        "a form field value was rewritten".into()
    } else if body.starts_with(b"<<") {
        "a dictionary outside the archive whitelist was rewritten".into()
    } else {
        "an object outside the archive whitelist was rewritten".into()
    }
}
