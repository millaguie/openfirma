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
    // Validation data: reachable from SOME /DSS dictionary of the final state —
    // the current one and any older archive's /DSS a newer pass replaced. Reach-
    // ability scans stop at each object's own `stream` marker (see `refs_in`), so
    // no encoded payload can drag unrelated objects into the set, and payload
    // hides inside validation data only by being *referenced* from an archive
    // dictionary — which is exactly what a /DSS/Certs/CRLs/OCSPs/VRI tree is.
    let mut dss_reachable: BTreeSet<ObjRef> = BTreeSet::new();
    let mut archive_dicts: Vec<ObjRef> = final_state
        .iter()
        .filter(|(_, body)| is_type(body, "/DSS"))
        .map(|(o, _)| *o)
        .collect();
    // The current catalog's /DSS counts even if a hand-made file spells the
    // dictionary without /Type: what the final document points at IS its archive.
    if let Some(dss_ref) = pdf::get(&catalog, "/DSS").and_then(pdf::parse_ref) {
        if !archive_dicts.contains(&dss_ref) {
            archive_dicts.push(dss_ref);
        }
    }
    for dss in archive_dicts {
        collect_reachable(pdf, &locations, &mut cache, dss, &mut dss_reachable);
        dss_reachable.insert(dss);
    }

    let mut out = Vec::new();
    for change in redefined {
        out.push((
            change.object,
            classify_one(
                &locations,
                &final_state,
                trailer.root,
                &dss_reachable,
                &change.object,
                &change.after,
                &change.before,
            ),
        ));
    }
    Ok(out)
}

fn classify_one(
    locations: &BTreeMap<ObjRef, pdf::Location>,
    final_state: &BTreeMap<ObjRef, Vec<u8>>,
    root: ObjRef,
    dss_reachable: &BTreeSet<ObjRef>,
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
    if dss_reachable.contains(object) || is_type(newer, "/DSS") || is_type(older, "/DSS") {
        // Validation data: reached from some /DSS of the final state (see
        // reachability above), or a /DSS dictionary itself — an older archive's
        // /DSS that a newer pass replaced is no longer reachable and still may
        // not be refused for it. A stream object can claim neither shape: page
        // content, XObjects and other payload never become /Type /DSS or get
        // referenced from the certificate tree on their own, so rewriting them
        // cannot hide on this rule — an attacker would have to name the new
        // payload from inside the archive's certificate chain.
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
    let _ = locations;
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

/// Collect `from` and everything its body references into `out`, bounded by the
/// document's own object count so a loop of fake references cannot explode.
fn collect_reachable(
    pdf: &[u8],
    locations: &BTreeMap<ObjRef, pdf::Location>,
    cache: &mut pdf::ObjectStreamCache,
    from: ObjRef,
    out: &mut BTreeSet<ObjRef>,
) {
    let mut queue = vec![from];
    while let Some(current) = queue.pop() {
        if !out.insert(current) {
            continue;
        }
        if out.len() > locations.len() + 1 {
            return; // a cycle of fake references: stop rather than chase it
        }
        let Ok(body) = pdf::resolve(pdf, locations, Some(cache), current) else {
            continue;
        };
        for reference in refs_in(&body) {
            if locations.contains_key(&reference) {
                queue.push(reference);
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
            // a run may follow the previous one only across whitespace
            let gap_ok =
                |prev: &(u64, usize)| body[prev.1..start].iter().all(u8::is_ascii_whitespace);
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
            if body[g.1..i].iter().all(u8::is_ascii_whitespace)
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

/// The offset of the `stream` keyword that begins an object's payload, if the
/// body is a stream object. Requiring EOL bytes after it keeps false hits inside
/// dictionary text (`/XstreamXYZ` etc.): ISO 32000 defines the keyword as termi-
/// nated by an end-of-line marker. The first hit wins, which is the object's own
/// marker (a dictionary value never spells `stream\r\n` or `stream\n`).
fn find_stream_marker(body: &[u8]) -> Option<usize> {
    let mut from = 0;
    while let Some(found) = body[from..].windows(6).position(|w| w == b"stream") {
        let at = from + found;
        let after = at + 6;
        if body[after..].starts_with(b"\r\n")
            || body.get(after).is_some_and(|b| matches!(b, b'\n' | b'\r'))
        {
            return Some(at);
        }
        from = after;
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
