//! Cryptographic verification of a signed PDF.
//!
//! `openfirma inspect` reports the structure of every signature dictionary and
//! checks the `/ByteRange` claim, but it verifies no crypto and no chain.
//! This module closes that gap: for **every** signature in the document, not
//! just the last one, it extracts the bytes `/ByteRange` covers and the CMS in
//! `/Contents`, and hands both to [`openfirma_cades::verify`]. A co-signed
//! document therefore only verifies when each of its signatures does, each
//! over its own revision.
//!
//! Since B-LT it also checks what the document archives for later: when the
//! catalog carries a `/DSS`, every certificate in it has to parse, every CRL
//! has to verify under the key of the CA it names, every OCSP response has to
//! be a successful answer from that CA (or a delegate it issued itself), and
//! for every signature the `/VRI` covers, the chain has to rebuild **from the
//! archived data alone** — with a revocation datum per link of that chain,
//! bound to the certificates of the link, and no certificate of the chain
//! revoked by the data archived for it. And since B-LTA, every
//! document time-stamp token has to imprint the bytes its own `/ByteRange`
//! covers.
//!
//! What is still *not* checked here, because it is layer 3/4 territory in
//! docs/validation.md: certificate policy (key usage, basic constraints,
//! qualification), the signature policy, the signature of an OCSP response
//! (only its structure and its `certStatus`, see
//! [`openfirma_cades::revocation`]), the signature of the time-stamp token
//! itself (that is `openssl ts -verify`'s job in the crosscheck suite), and
//! the "does the signature cover the latest revision" judgement a PDF viewer
//! makes.

use std::time::SystemTime;

use openfirma_cades::revocation::{self, CrlReport, OcspCertId, RevocationTime};
use openfirma_cades::verify::{AnchorPolicy, VerifyOptions};
use openfirma_core::alg::DigestAlg;
use openfirma_core::cert::CertificateHandle;
use openfirma_core::{Error, Result};

use crate::inspect;
use crate::ltv;
use crate::pdf;
use crate::pdf::ObjRef;

/// One signature dictionary of the document, with its CAdES reports. A
/// dictionary normally carries exactly one `SignerInfo`, but the CMS format
/// allows more and nothing here collapses them.
#[derive(Clone, Debug)]
pub struct SignatureReport {
    /// The object holding the signature dictionary.
    pub object: ObjRef,
    /// The two ranges the signature covers.
    pub byte_range: [usize; 4],
    /// One report per `SignerInfo` of the CMS in `/Contents`.
    pub reports: Vec<openfirma_cades::VerifyReport>,
}

/// One `/Type /DocTimeStamp` dictionary of the document (B-LTA).
#[derive(Clone, Debug)]
pub struct DocTimeStampReport {
    /// The object holding the dictionary.
    pub object: ObjRef,
    /// The two ranges its token covers.
    pub byte_range: [usize; 4],
    /// The digest the token imprints under.
    pub digest: DigestAlg,
    /// The RFC 3161 token in `/Contents`, without the zero padding.
    pub token: Vec<u8>,
    /// The token's `genTime`, only when the TSA's signature over it verified
    /// against the supplied anchors. `None` means the seal was NOT
    /// cryptographically confirmed, and no B-LTA level may be claimed from it.
    pub gen_time: Option<std::time::SystemTime>,
    /// What makes this document time-stamp unverified, when it is. Never empty
    /// when `gen_time` is `None`.
    pub problem: Option<String>,
}

impl DocTimeStampReport {
    /// Whether the document time-stamp's TSA signature was verified against a
    /// trust anchor. This — not the mere presence of a token — is what B-LTA
    /// may assert.
    pub fn verified(&self) -> bool {
        self.gen_time.is_some()
    }
}

/// One signature whose chain could be rebuilt from the `/DSS` alone.
#[derive(Clone, Debug)]
pub struct DssChain {
    /// The 1-based index of the signature, in the order `verify` reports them.
    pub signature: usize,
    /// Subjects from the signer upwards, the trust anchor last.
    pub subjects: Vec<String>,
    /// Subject of the trust anchor the chain reached.
    pub trust_anchor: String,
}

/// What the document's `/DSS` carries and what the checks made of it.
#[derive(Clone, Debug)]
pub struct DssReport {
    /// Certificates archived under `/Certs`.
    pub certificates: usize,
    /// One report per CRL archived under `/CRLs`, each signature verified.
    pub crls: Vec<CrlReport>,
    /// OCSP responses archived under `/OCSPs` that VERIFIED. Under
    /// [`AnchorPolicy::IntegrityWithoutAnchors`] a response whose responder CA
    /// could not be named is counted in [`Self::unchecked`] instead.
    pub ocsps: usize,
    /// Archived CRLs and OCSP responses whose signature NOBODY checked.
    ///
    /// Under the strict [`AnchorPolicy::Required`] this is always 0: an
    /// archived datum that cannot be verified is a refusal naming it. Under
    /// [`AnchorPolicy::IntegrityWithoutAnchors`] the caller named no authority,
    /// so a datum issued by a CA that is in neither the archive nor (there
    /// being none) the anchors cannot be judged at all — it is counted here
    /// instead of failing a document whose signatures are sound. Whatever this
    /// number is, the archive is NOT called coherent: no frontend may report
    /// these bytes as verified.
    pub unchecked: usize,
    /// The `/VRI` keys: the upper case hex SHA-1 of each archived signature
    /// value.
    pub vri_keys: Vec<String>,
    /// The chains rebuilt from the archived data, per covered signature.
    pub chains: Vec<DssChain>,
    /// 1-based indices of the signatures the `/VRI` does not cover, because
    /// the validation data predates them. They verify as signatures, they
    /// just are not archived.
    pub uncovered: Vec<usize>,
    /// The instant the archived datums' windows were judged about: the first
    /// time-stamp whose TSA signature verified, or `validation_time` when nothing
    /// in the document is pinned that way. A revocation statement is about a
    /// moment, and a verdict that does not say which moment knows less than it
    /// claims (round two's N10).
    pub evidence_about: SystemTime,
}

/// The verdict over a whole document.
#[derive(Clone, Debug)]
pub struct DocumentReport {
    /// One entry per `/Type /Sig` dictionary, in object number order.
    pub signatures: Vec<SignatureReport>,
    /// One entry per `/Type /DocTimeStamp` dictionary.
    pub document_timestamps: Vec<DocTimeStampReport>,
    /// The `/DSS` report, when the document carries validation data.
    pub dss: Option<DssReport>,
}

/// Verifies every signature in `pdf` against `opts`, plus its document
/// time-stamps and its `/DSS` validation data when it carries them.
///
/// `Ok` only happens when the document carries at least one signature and all
/// of it passes every check. Otherwise the error lists each failing part and
/// the check that failed it.
pub fn verify(pdf: &[u8], opts: &VerifyOptions) -> Result<DocumentReport> {
    let signatures = inspect::signatures(pdf)?;
    if signatures.is_empty() {
        return Err(Error::Verification(
            "the document carries no signature dictionary".into(),
        ));
    }

    let mut sig_reports = Vec::with_capacity(signatures.len());
    let mut failures = Vec::new();
    // A-2, the verification half: a document whose final catalog carries a
    // /Perms /DocMDP certification with /P 1 ("no changes permitted") may not
    // have ANY revision after the certifying one — every later change breaks
    // the certification. AutoFirma's validator marks those revisions KO;
    // openfirma adds the sentence to the failures it already reports. Checked
    // once for the whole document.
    if let Err(e) = certification_gate(pdf) {
        failures.push(unwrap(&e));
    }
    for (i, sig) in signatures.iter().enumerate() {
        let label = format!(
            "signature {} (object {} {})",
            i + 1,
            sig.object.num,
            sig.object.generation
        );
        match verify_one(pdf, sig, opts) {
            Ok(reports) => {
                // and the revisions gate: everything appended after this
                // signature's own revision has to be admissible archive data
                let problems = revision_gate_problems(pdf, sig.byte_range)?;
                if problems.is_empty() {
                    sig_reports.push(SignatureReport {
                        object: sig.object,
                        byte_range: sig.byte_range,
                        reports,
                    });
                } else {
                    // the same sentence the time-stamp gate uses: the attack
                    // IS a following revision that no archive may append, and
                    // naming it is what tells the user which layer refused.
                    // One sentence per signature, the changes listed inside it:
                    // repeating the label per change (round two's 02-N-4) made a
                    // document with two unclassified changes read as two
                    // refusals, and a reader counted signatures that were not
                    // there — the two changes here were `/Info` and the XMP
                    // packet of one signing pass.
                    failures.push(format!(
                        "{label} was followed by changes no archive may append: {}",
                        problems.join("; ")
                    ));
                }
            }
            Err(e) => failures.push(format!("{label}: {}", unwrap(&e))),
        }
    }

    let mut dts_reports = Vec::new();
    for (i, t) in inspect::document_timestamps(pdf)?.iter().enumerate() {
        let label = format!(
            "document time-stamp {} (object {} {})",
            i + 1,
            t.object.num,
            t.object.generation
        );
        if t.problems.is_empty() {
            // read_document_timestamp only leaves the digest unset when it
            // also left problems, so an empty problem list always has one
            let digest = t.digest.unwrap_or(DigestAlg::Sha256);
            // A timestamp that carries no problems still has to pass the
            // revisions gate: its token covers a revision, and what came after
            // it is only admissible if it is validation data or plumbing —
            // otherwise B-LTA would certify documents whose pages were swapped
            // after the stamp.
            let problems = revision_gate_problems(pdf, t.byte_range)?;
            if !problems.is_empty() {
                // one sentence per time-stamp, as above
                failures.push(format!(
                    "document time-stamp {} (object {} {}) was followed by changes no \
                     archive may append: {}",
                    i + 1,
                    t.object.num,
                    t.object.generation,
                    problems.join("; ")
                ));
            }
            if problems.is_empty() {
                // The token is a real RFC 3161 TST: verify the TSA's own
                // signature over it against the same anchors, exactly as the
                // B-T signature path does. Presence of a token proves nothing —
                // a self-signed attacker TSA's seal looked identical until now,
                // and the GUI printed "nivel B-LTA" over zero cryptographic
                // evidence (review A2: a level is claimed only when its evidence
                // was verified). A /Type /DocTimeStamp verifies against the
                // caller's trust anchors a fortiori: its own validity window
                // must contain the stamp, and the stamp cannot be checked
                // against nothing.
                match openfirma_cades::tsp::verify_token_signature(
                    &t.token,
                    &opts.trust_anchors,
                    opts.validation_time,
                ) {
                    Ok(status) => dts_reports.push(DocTimeStampReport {
                        object: t.object,
                        byte_range: t.byte_range,
                        digest,
                        token: t.token.clone(),
                        gen_time: Some(status.gen_time),
                        problem: None,
                    }),
                    Err(e) => {
                        // not a hard failure: like a B-T token that does not
                        // verify, the document is still sound — it just cannot
                        // claim B-LTA from this stamp, and the report says why
                        dts_reports.push(DocTimeStampReport {
                            object: t.object,
                            byte_range: t.byte_range,
                            digest,
                            token: t.token.clone(),
                            gen_time: None,
                            problem: Some(format!(
                                "the document time-stamp's TSA signature did not verify \
                                 ({e}), so this seal certifies nothing"
                            )),
                        });
                    }
                }
            }
        } else {
            for p in &t.problems {
                failures.push(format!("{label}: {p}"));
            }
        }
    }

    // The archived validation data is evidence about the past, and the past it
    // speaks for is the moment the document was first sealed by a TSA this
    // verifier trusted: see [`archived_instant`].
    let archived = archived_instant(&sig_reports, &dts_reports);
    let mut dss = None;
    match verify_dss(pdf, &signatures, opts, archived) {
        Ok(report) => dss = report,
        Err(e) => failures.push(format!("validation data (/DSS): {}", unwrap(&e))),
    }

    if !failures.is_empty() {
        return Err(Error::Verification(failures.join("; ")));
    }
    Ok(DocumentReport {
        signatures: sig_reports,
        document_timestamps: dts_reports,
        dss,
    })
}

/// The revisions gate (adversarial review C-1): the bytes a later pass appends
/// after a signature are limited to what an archive may append at all — new
/// signature objects, their plumbing in the field and form trees, validation
/// data under `/DSS`, and document time-stamps. Anything else that redefines
/// what this signature covered means the document changed underneath it, and
/// no verdict may rest on a document whose signed bytes are not the whole of
/// what it covers. Returns the refusals; empty means every later change is one
/// an archive is allowed to make.
fn revision_gate_problems(pdf: &[u8], byte_range: [usize; 4]) -> Result<Vec<String>> {
    let revisions = crate::revisions::revisions(pdf)?;
    let [_, _, c, d] = byte_range;
    // checked: the numbers come from the document, and a pair whose sum does
    // not fit in an offset describes no segment of any file. Inspect refused
    // one already; refusing again keeps this total.
    let coverage_end = match c.checked_add(d) {
        Some(end) => end,
        None => {
            return Err(Error::Verification(format!(
                "/ByteRange [{c} + {d}] overflows any file offset"
            )));
        }
    };
    let redefined = crate::revisions::redefinitions_after(pdf, &revisions, coverage_end)?;
    let classified = crate::revisions::classify(pdf, &redefined)?;
    Ok(classified
        .into_iter()
        .filter(|(_, change)| !change.allowed())
        .map(|(_, change)| change.to_string())
        .collect())
}

/// A-2, the verification half: a document whose FINAL catalog carries a
/// `/Perms /DocMDP` certification with `/P 1` ("no changes to the document
/// are permitted") and that has any revision after the one holding the
/// certifying dictionary is one every conforming reader shows as a broken
/// certification. AutoFirma's validator (`ValidatePdfSignature`) marks exactly
/// those revisions KO, and openfirma says so as a verification failure instead
/// of letting B-B signatures pass over an overwritten certification.
///
/// The certifying revision is where the `/Sig` the certification refers to
/// lives; when the pointer cannot be resolved at all, more than one revision
/// under a final P=1 certification is reported — fail closed on what readers
/// will flag. A single-revision certified document passes: nothing followed
/// the certification. `Err` is the refusal sentence; `Ok(())` reports nothing.
fn certification_gate(pdf: &[u8]) -> Result<()> {
    // A document whose newest revision is encrypted cannot be signed anyway
    // (C-2 refuses it upstream); reporting a certification sentence on top of
    // that error would bury the real cause. Silence here, loudly elsewhere.
    if trailer_is_encrypted(pdf) {
        return Ok(());
    }
    let at = pdf::last_startxref(pdf)?;
    let trailer = pdf::trailer(pdf, at)?;
    let locations = pdf::object_locations(pdf, at)?;
    let catalog = pdf::resolve(pdf, &locations, None, trailer.root)?;
    let Some(value) = pdf::get(&catalog, "/Perms") else {
        return Ok(());
    };
    let perms_owned = match pdf::parse_ref(value) {
        Some(r) => pdf::resolve(pdf, &locations, None, r)?.into_owned(),
        None => pdf::trim_ws(value).to_vec(),
    };
    if perms_owned.len() > crate::stream::MAX_DECODED_STREAM {
        return Err(Error::Verification(
            "the catalog's /Perms object is too large to read".into(),
        ));
    }
    let Some(mdp) = crate::sign::docmdp_of(&perms_owned)? else {
        return Ok(());
    };
    if mdp.lowest_p > 1 {
        // P=2 and above permit signing; only filling in form fields is limited.
        return Ok(());
    }
    // This gate runs on its own scan of the /Prev chain, not on wave 1's
    // `revisions()`: that one refuses a chain whose middle revision has no
    // honest closing record, and a forged certification lives in exactly such a
    // chain — the sentence must be issuable there too. A broken or looping
    // scan reports nothing: the other gates refuse that file for its own sake.
    let mut chain: Vec<usize> = Vec::new();
    let mut cur = Some(at);
    while let Some(x) = cur {
        if chain.len() > 100 || chain.contains(&x) || x > pdf.len() {
            return Ok(());
        }
        chain.push(x);
        cur = match pdf::trailer(pdf, x) {
            Ok(t) => t.prev,
            Err(_) => return Ok(()),
        };
    }
    if chain.len() == 1 {
        return Ok(());
    }
    // Both spellings of a certification (ISO 32000-1 12.8.4.3: an older one is
    // /Perms /DocMDP << … >> directly; PDF 2.0 multiple certifications put the
    // dictionaries into a /Reference array). Every dictionary is asked whether
    // it certifies with P=1, because any one of them being so constrained
    // binds the document.
    let mut dicts: Vec<Vec<u8>> =
        vec![pdf::trim_ws(pdf::get(&perms_owned, "/DocMDP").unwrap_or_default()).to_vec()];
    if let Some(reference) = pdf::get(&perms_owned, "/Reference") {
        let reference = pdf::trim_ws(reference);
        if reference.starts_with(b"<<") {
            dicts.push(reference.to_vec());
        } else if let Ok(items) = pdf::array_refs(reference) {
            for r in items {
                if let Ok(body) = pdf::resolve(pdf, &locations, None, r) {
                    dicts.push(body.into_owned());
                }
            }
        }
    }
    for d in dicts.iter().filter(|d| d.starts_with(b"<<")) {
        let Some(params_value) = pdf::get(d, "/TransformParams") else {
            continue;
        };
        let params = pdf::trim_ws(params_value);
        if !params.starts_with(b"<<") {
            continue;
        }
        let p = pdf::get(params, "/P")
            .and_then(|v| std::str::from_utf8(pdf::trim_ws(v)).ok())
            .and_then(|s| s.trim().parse::<i64>().ok())
            .unwrap_or(1);
        if p > 1 {
            continue;
        }
        // The certifying /Sig sits under the certification dictionary (/V in
        // the PDF 2.0 shape, or the older flat one; a bare /DocMDP without /V
        // falls through to the document-level sentence below).
        let v_ref = pdf::get(d, "/V").and_then(pdf::parse_ref);
        if let Some(v_ref) = v_ref {
            // Which revision wrote the certifying dictionary: an object of
            // revision *i* lies above that revision's own cross-reference and
            // below the one before it (`startxref` is the last offset the
            // revision wrote). `chain` is newest first, so the last entry an
            // object lies below is the index of its own revision — which is how
            // many revisions were appended after it. A certification the newest
            // revision itself wrote has nothing after it; a forged one naming an
            // OLDER signature object (certification-after-the-fact) resolves
            // through THIS xref to where that signature really stands, which is
            // what flags it. The merged cross-reference resolves every object to
            // its newest definition — an older revision re-INDEXING an object it
            // did not write leaves the bytes at their original offset — so this
            // placement never invents a revision for bytes that one never
            // touched.
            //
            // The comparison is the one that answers that question
            // (`offset < x` over a descending chain, so the last match is the
            // revision the object belongs to). Read as `offset <= x` it matched
            // at index 0 for every object in the file, which made this arm
            // unreachable: a resolvable `/V` was always reported as a
            // certification nothing followed, whatever the file held after it.
            let Some(pdf::Location::Direct(offset)) = locations.get(&v_ref).copied() else {
                continue;
            };
            match chain.iter().rposition(|x| offset < *x) {
                // The certifying signature lives in the newest revision: the
                // certification closes its own state and nothing followed it.
                Some(0) => return Ok(()),
                Some(i) => {
                    return Err(Error::Verification(format!(
                        "the document was certified with /Perms /DocMDP /P 1 (no changes \
                         permitted) by the signature at object {v_ref}, and {i} revision(s) \
                         were appended after that certification: every reader that honours \
                         it shows the certification as broken"
                    )));
                }
                None => {}
            }
        }
    }
    Err(Error::Verification(format!(
        "the final catalog certifies this document with /Perms /DocMDP /P 1 (no changes \
         permitted), and the document has {} revisions whose order the certification does \
         not explain: whatever was appended after the certification breaks it",
        chain.len()
    )))
}

/// Whether the newest trailer of `pdf` names an encryption dictionary. Read
/// with the most forgiving key scan there is (this module's own hole-aware
/// one), so a false "not encrypted" cannot silence the certification gate on
/// a file the C-2 refusal may or may not catch for its own reasons.
fn trailer_is_encrypted(pdf: &[u8]) -> bool {
    let Ok(at) = pdf::last_startxref(pdf) else {
        return false;
    };
    let Ok(dict) = crate::pdf::trailer_dict(pdf, at) else {
        return false;
    };
    key_spans(&dict)
        .into_iter()
        .any(|(name, _)| dict.get(name) == Some(b"/Encrypt".as_slice()))
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

/// Where every key of a dictionary sits in its raw bytes: name token plus
/// value, whole (`/Contents <hex>`, `/ByteRange [ … ]`).
///
/// `pdf::items` cannot be used here. A signed signature dictionary contains a
/// hole — the hex string in `/Contents` runs for tens of kilobytes and is
/// full of ASCII letters — and a tokenizer that walks the bytes with no other
/// idea of what is inside them can latch onto a `<` inside that hex, pair the
/// `>` that closes it with a name that comes after, and report a perfectly
/// ordinary dictionary as lying about where its own value sits. This scan
/// cannot: names only occur outside strings, so each value is skipped whole
/// by its own delimiter — strings by their markers, arrays to their `]`,
/// nested dictionaries recursively — before the next key is looked for. A
/// value that cannot be skipped whole stops the scan; whatever was found up
/// to there is returned.
pub(crate) fn key_spans(dict: &[u8]) -> Vec<(std::ops::Range<usize>, std::ops::Range<usize>)> {
    let mut out = Vec::new();
    if !dict.starts_with(b"<<") {
        return out;
    }
    let mut i = 2;
    loop {
        i = skip_ws(dict, i);
        if i >= dict.len() || dict[i] == b'>' {
            break; // the closing `>>`, or something that cannot be a key
        }
        if dict[i] != b'/' {
            break;
        }
        let name = name_end(dict, i);
        let value_start = skip_ws(dict, name);
        if value_start >= dict.len() {
            out.push((i..name, value_start..value_start));
            break; // a key with no value: the dictionary ends here
        }
        let value_end = match (dict[value_start], dict.get(value_start + 1)) {
            (b'<', Some(b'<')) => match nested_dict_end(dict, value_start) {
                Some(end) => end,
                None => break,
            },
            (b'<', _) => match hex_string_end(dict, value_start) {
                Some(end) => end,
                // not a hex string at all — a `<` in front of the next key,
                // say. Treat it as one token and let the loop see what follows.
                None => token_end(dict, value_start),
            },
            (b'(', _) => match literal_string_end(dict, value_start) {
                Some(end) => end,
                None => break,
            },
            (b'[', _) => match array_end(dict, value_start) {
                Some(end) => end,
                None => break,
            },
            _ => token_end(dict, value_start),
        };
        let mut v_end = value_end;
        while v_end > value_start && is_ws(dict[v_end - 1]) {
            v_end -= 1;
        }
        out.push((i..name, value_start..v_end));
        i = value_end;
    }
    out
}

/// The span of the key named `key` — without the leading slash — or `None`.
/// Matching is exact: `/Contents` is a prefix of `/ContentsSize`, and the two
/// can never be told apart by looking at where a token starts.
pub(crate) fn key_span(
    dict: &[u8],
    key: &str,
) -> Option<(std::ops::Range<usize>, std::ops::Range<usize>)> {
    let wanted = format!("/{key}");
    // The hole-aware scan below decides WHICH token is the key — a `/Contents`
    // that only appears inside the CMS hex can never be the one returned. Its
    // spans are then the ones every other reader of this crate measures them
    // at (`pdf::items`): matching what the signer itself measured when it
    // wrote the hole bounds, and refusing a shadow definition does not need a
    // second tokenizer, only the same eyes on both sides of the comparison.
    if !key_spans(dict)
        .into_iter()
        .any(|(name, _)| dict.get(name.clone()) == Some(wanted.as_bytes()))
    {
        return None;
    }
    let value = pdf::get_span(dict, &wanted)?;
    // the name is the token immediately before the value, separated by at
    // least one whitespace: walk back over the gap and take `/Name` whole
    let mut start = value.start;
    while start > 0 && matches!(dict[start - 1], b'\t' | b'\n' | 0x0c | b'\r' | b' ') {
        start -= 1;
    }
    let name = start - key.len() - 1..start;
    if dict.get(name.clone()) != Some(wanted.as_bytes()) {
        return None;
    }
    Some((name, value))
}

/// End of whitespace between tokens. (Comments are not skipped: a `%` that
/// would start one inside this scan is either hex, which cannot be one, or a
/// token boundary, where stopping the scan is the honest answer.)
fn skip_ws(data: &[u8], mut i: usize) -> usize {
    while i < data.len() && is_ws(data[i]) {
        i += 1;
    }
    i
}

/// End of the `/Name` that starts at `i`, the slash included.
fn name_end(data: &[u8], i: usize) -> usize {
    let mut j = i + 1;
    while j < data.len() && !is_ws(data[j]) && !is_delim(data[j]) {
        j += 1;
    }
    j
}

/// End of a hex string that starts with `<` at `i`, or `None` when something
/// that cannot be inside one turns up first. Real CMS tokens are strict
/// lower-case hex, so their closing `>` is always found; a stray `<` in front
/// of non-hex bytes is reported as not-a-string instead of swallowing the
/// rest of the dictionary.
fn hex_string_end(data: &[u8], i: usize) -> Option<usize> {
    let mut j = i + 1;
    while j < data.len() {
        match data[j] {
            b'>' => return Some(j + 1),
            b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F' | b'\t' | b'\n' | b'\r' | b' ' => j += 1,
            _ => return None,
        }
    }
    None
}

/// End of a literal string `( … )` with balanced escapes and nesting.
fn literal_string_end(data: &[u8], i: usize) -> Option<usize> {
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
                    return Some(j);
                }
            }
            _ => j += 1,
        }
    }
    None
}

/// End of an array value `[ … ]`: strings are skipped whole (their bytes may
/// look like a closing bracket) and the first `]` outside one closes it.
fn array_end(data: &[u8], i: usize) -> Option<usize> {
    let mut j = i + 1;
    while j < data.len() {
        match data[j] {
            b']' => return Some(j + 1),
            b'(' => j = literal_string_end(data, j)?,
            b'<' if j + 1 < data.len() && data[j + 1] == b'<' => j += 2,
            _ => j += 1,
        }
    }
    None
}

/// End of a nested dictionary that opens at `i`: one past its closing `>>`.
/// Located by scanning the nested keys with the same rules; if the close does
/// not follow cleanly, one past the last value understood.
fn nested_dict_end(data: &[u8], open: usize) -> Option<usize> {
    let inner = key_spans(&data[open..]);
    let last = inner.last()?;
    let i = skip_ws(data, open + last.1.end);
    if data.get(i..i + 2) == Some(b">>") {
        Some(i + 2)
    } else {
        Some(open + last.1.end)
    }
}

/// End of a plain token — a number, a reference, a keyword: it runs until the
/// next whitespace or delimiter.
fn token_end(data: &[u8], i: usize) -> usize {
    let mut j = i;
    while j < data.len() && !is_ws(data[j]) && !is_delim(data[j]) {
        j += 1;
    }
    j
}

fn verify_one(
    pdf: &[u8],
    sig: &inspect::Signature,
    opts: &VerifyOptions,
) -> Result<Vec<openfirma_cades::VerifyReport>> {
    let [a, b, c, d] = sig.byte_range;
    // The structural claim first: the ranges must be inside the file and the
    // hole between them must be exactly the /Contents hex string, otherwise
    // what is extracted below is not what the signer digested.
    if a != 0 {
        return Err(Error::Verification(format!(
            "the first /ByteRange segment starts at {a}, not at 0"
        )));
    }
    // checked: the numbers come out of the document, and a pair whose sum
    // does not fit in an offset describes no segment of any file
    let inside = c
        .checked_add(d)
        .is_some_and(|end| end <= pdf.len() && b <= c);
    if !inside {
        return Err(Error::Verification(format!(
            "/ByteRange [{a} {b} {c} {d}] does not describe two segments inside the {} byte file",
            pdf.len()
        )));
    }
    // The appearance of the hole (a hex string between the two segments) and
    // its ownership by THIS dictionary are checked together below, after the
    // dictionary has been located: a hole shaped like /Contents that belongs
    // to some other object is exactly what M-3 must refuse, so shape alone
    // cannot decide anything here. What must be true before locating any-
    // M-3, the binding between structure and bytes. The dictionary must be a
    // direct object of the file (an ISO 32000 rule with a hard reason: inside
    // an object stream there is no offset for its /Contents at all), and the
    // hole must be THIS dictionary's /Contents — not merely something shaped
    // like one. Checking only that `pdf[b..c]` starts with `<` and ends with
    // `>` let any second definition of a signature object, sitting in an older
    // still-reachable revision, claim someone else's bytes: the digest then
    // covers whatever lies in between while the dictionary shown to readers
    // says otherwise. What binds the claim is (a) being THE definition the
    // final cross-reference resolves — a shadow copy elsewhere is never the
    // one located here — and (b) this resolved dictionary carrying a /Contents
    // whose hex string IS the hole. The value span is taken from the raw
    // bytes with `pdf::get_span`, exactly as the signer measured it when it
    // wrote [b, c): whether that reading trimmed a space after the `>`, or one
    // token further in an unusual layout, is padding trivia both sides agree
    // on; whether the dictionary even has its own /Contents at those bytes is
    // the claim under test. The name span comes from the hole-aware scan
    // below, so a "/Contents" that only appears inside tens of kilobytes of
    // CMS hex can never be the key being checked.
    let locations = pdf::object_locations(pdf, pdf::last_startxref(pdf)?)?;
    let offset = match locations.get(&sig.object).copied() {
        Some(pdf::Location::Direct(off)) => off,
        _ => {
            return Err(Error::Verification(format!(
                "the signature dictionary ({} {}) is not a direct object of the file: its \
                 bytes do not sit at any offset the /ByteRange can name",
                sig.object.num, sig.object.generation
            )));
        }
    };
    // slice of the file this reader resolves object N to — exactly what
    // `inspect` digested and what the signer patched, span for span
    let body = pdf::object_body(pdf, offset)?;
    let raw = &pdf[body.clone()];
    let contents = key_span(raw, "Contents").ok_or_else(|| {
        Error::Verification(format!(
            "the signature dictionary ({} {}) carries no /Contents whose bytes the hole \
             could be",
            sig.object.num, sig.object.generation
        ))
    })?;
    if body.start + contents.1.start != b || body.start + contents.1.end != c {
        return Err(Error::Verification(format!(
            "the /ByteRange hole [{b}, {c}) is not this dictionary's /Contents value, which \
             sits at [{}, {}): what sits in the hole belongs to another object",
            body.start + contents.1.start,
            body.start + contents.1.end
        )));
    }
    if let Some((_, range)) = key_span(raw, "ByteRange") {
        let (first, last) = (body.start + range.start, body.start + range.end);
        if first >= c || last > b {
            // every byte of the array must fall inside [0, b): the second
            // segment resumes AT c, so a span reaching into or past the hole
            // would claim to have digested its own declaration.
            return Err(Error::Verification(format!(
                "the /ByteRange array of dictionary {} {} sits at [{first}, {last}), outside \
                 the bytes that signature covers",
                sig.object.num, sig.object.generation
            )));
        }
    }

    // The hole and the bytes `inspect` decoded from it are now bound to this
    // dictionary. Last carrier question: those bytes must BE a SignedData —
    // a `/Contents` that decodes to some other DER value (a bare digest, an
    // array) is not "the signature I could not verify", it is the wrong object
    // entirely, and saying so beats failing on whichever unrelated check an
    // honest parser happens to hit first.

    if sig.cms.is_empty() || !openfirma_cades::verify::looks_like_signed_data(&sig.cms) {
        return Err(Error::Verification(
            "the /Contents of this signature holds no SignedData: what fills the hole \
             belongs to another object"
                .into(),
        ));
    }

    let mut covered = Vec::with_capacity(b + d);
    covered.extend_from_slice(&pdf[a..a + b]);
    covered.extend_from_slice(&pdf[c..c + d]);
    openfirma_cades::verify::verify(&sig.cms, Some(&covered), opts)
}

/// The `/DSS` checks. Returns `None` for a document without validation data,
/// which is the B-B case and not an error.
fn verify_dss(
    pdf: &[u8],
    signatures: &[inspect::Signature],
    opts: &VerifyOptions,
    archived: Option<SystemTime>,
) -> Result<Option<DssReport>> {
    // One instant for the datums' own windows, another for everything that has to
    // be true today: see [`openfirma_cades::RevocationTime`].
    let revocation_time = match archived {
        Some(when) => RevocationTime::archive(when, opts.validation_time),
        None => RevocationTime::at(opts.validation_time),
    };
    let Some(dss) = ltv::read_dss(pdf)? else {
        return Ok(None);
    };

    // every archived certificate has to parse: an archive nobody can read is
    // worse than none, because a validator may trust its completeness
    let mut cert_handles: Vec<CertificateHandle> = Vec::with_capacity(dss.certs.len());
    for (i, (_, der)) in dss.certs.iter().enumerate() {
        match CertificateHandle::from_der(der) {
            Ok(handle) => cert_handles.push(handle),
            Err(e) => {
                return Err(fail_dss(&format!(
                    "certificate {} archived under /Certs does not parse: {e}",
                    i + 1
                )));
            }
        }
    }

    // every CRL: parse, signature under the naming CA's key, dates. The pool is
    // what makes the archive readable at all; WHICH chain certificate each CRL
    // may speak for is decided per link below, where the candidate is the one
    // certificate of the chain.
    let mut issuers = cert_handles.clone();
    issuers.extend_from_slice(&opts.trust_anchors);
    let mut crls: Vec<(Vec<u8>, CrlReport)> = Vec::with_capacity(dss.crls.len());
    let mut unchecked = 0usize;
    for (i, (_, der)) in dss.crls.iter().enumerate() {
        match revocation::verify_crl(der, &issuers, revocation_time) {
            Ok(report) => crls.push((der.clone(), report)),
            // 06-C-1: with no authority named, a datum that does not verify
            // against the archive alone is not a broken archive — it is a
            // datum nobody could check (its CA is not archived and the caller
            // named no anchor), and this mode never uses it: the per-link
            // revocation proof below is skipped too. Counted, never claimed.
            Err(_) if opts.anchors != AnchorPolicy::Required => unchecked += 1,
            Err(e) => {
                return Err(fail_dss(&format!(
                    "CRL {} archived under /CRLs is not a revocation datum: {}",
                    i + 1,
                    unwrap(&e)
                )));
            }
        }
    }

    // every OCSP response: verified as a revocation datum (signature, responder
    // authority, interval), and a successful answer, read down to its CertIDs.
    // An archived response is evidence years after signing with no network to
    // re-ask, so an unverifiable one is refused, not counted (A4).
    let mut ocsp_ids: Vec<OcspCertId> = Vec::new();
    let mut verified_ocsps = 0usize;
    for (i, (_, der)) in dss.ocsps.iter().enumerate() {
        let status = revocation::read_ocsp_response(der, &issuers, revocation_time);
        if !status.verified() {
            // 06-C-1: same rule as the CRLs above — no authority named means
            // an unverifiable datum is counted, not refused.
            if opts.anchors != AnchorPolicy::Required {
                unchecked += 1;
                continue;
            }
            return Err(fail_dss(&format!(
                "OCSP response {} archived under /OCSPs is not a revocation datum: {}",
                i + 1,
                status.problem.unwrap_or_else(|| "unverifiable".into())
            )));
        }
        // The CertIDs the checker accepted — not a fresh parse of the raw
        // response. `read_ocsp_response` drops the answers about CAs the signer
        // was not authorized for (round 4's N4-1); re-parsing here put every
        // SingleResponse back, so one "good" about the attacker's own CA laundered
        // a real-CA CertID about a revoked signer.
        verified_ocsps += 1;
        ocsp_ids.extend(status.cert_ids);
    }

    let vri_keys = dss
        .vri_keys()
        .map_err(|e| fail_dss(&format!("the /VRI dictionary cannot be read: {e}")))?;

    let mut chains = Vec::new();
    let mut uncovered = Vec::new();
    for (i, sig) in signatures.iter().enumerate() {
        // a signature whose /Contents or CMS cannot be read has already
        // failed above; the /DSS check adds nothing to that verdict
        let (Some(key), Ok(signers)) = (
            ltv::vri_key(pdf, sig),
            openfirma_cades::verify::signer_certificates(&sig.cms),
        ) else {
            continue;
        };
        if !vri_keys.contains(&key) {
            uncovered.push(i + 1);
            continue;
        }

        for signer in &signers {
            if !cert_handles.iter().any(|c| c.der() == signer.der()) {
                return Err(fail_dss(&format!(
                    "the /VRI claims to cover signature {} (key {key}) but the /Certs archive \
                     does not carry its signer certificate, so the chain cannot be rebuilt \
                     from the validation data alone",
                    i + 1
                )));
            }
            // 06-C-1: rebuilding the chain is the "who issued it" step, and a
            // caller who named no authority did not ask for it. What was judged
            // above (every archived certificate parses, every CRL and OCSP
            // response verifies) stays judged; the chain itself and the
            // per-link revocation proof need a named anchor, so they are
            // skipped here rather than failed, and no `DssChain` is reported
            // for a chain nobody built.
            if opts.anchors != AnchorPolicy::Required {
                continue;
            }
            let chain = openfirma_cades::verify::chain_certificates(
                signer,
                &cert_handles,
                &opts.trust_anchors,
                opts.validation_time,
            )
            .map_err(|e| {
                fail_dss(&format!(
                    "the chain of signature {} cannot be rebuilt from the /DSS contents \
                     alone: {}",
                    i + 1,
                    unwrap(&e)
                ))
            })?;

            // Every link of the chain needs revocation data about the child
            // from its parent, and the data has to be THAT parent's: the CRL
            // must verify under the chain certificate's own key, and an OCSP
            // response must name the child's serial number and the parent.
            //
            // Both halves were round 2 findings. N3: the CRL only had to verify
            // under *some* certificate of /Certs (or an anchor) carrying the
            // issuing CA's name, so a self-signed impostor with that name and a
            // key of its own signed an empty CRL and the archive looked
            // complete while every conforming validator saw the signer revoked.
            // N5: an authentic OCSP response about a different certificate of
            // the same CA counted for this one, which is an answer anyone can
            // ask that CA's public responder for.
            for pair in chain.windows(2) {
                let (child, parent) = (&pair[0], &pair[1]);
                let serial = child.serial_number().as_bytes().to_vec();
                let crl = crls.iter().find(|(der, _)| {
                    revocation::verify_crl(der, std::slice::from_ref(parent), revocation_time)
                        .is_ok()
                });
                let by_ocsp = ocsp_ids.iter().any(|id| {
                    id.serial == serial && ltv::ocsp_id_names_ca(id, parent).unwrap_or(false)
                });
                if crl.is_none() && !by_ocsp {
                    return Err(fail_dss(&format!(
                        "the archive carries no revocation datum issued by \"{}\" about \
                         \"{}\" (serial {}), a link of the chain of signature {}: a B-LT /DSS \
                         needs a CRL or an OCSP response from each CA about the certificate it \
                         issued, verifiable under that CA's own key",
                        parent.subject(),
                        child.subject(),
                        hex::encode(&serial),
                        i + 1
                    )));
                }
                if crl.is_some_and(|(_, r)| r.revoked_serials.contains(&serial)) {
                    return Err(fail_dss(&format!(
                        "the archived CRL issued by \"{}\" revokes \"{}\" (serial {}), a \
                         certificate of the chain of signature {}",
                        parent.subject(),
                        child.subject(),
                        hex::encode(&serial),
                        i + 1
                    )));
                }
                if ocsp_ids.iter().any(|id| {
                    id.revoked
                        && id.serial == serial
                        && ltv::ocsp_id_names_ca(id, parent).unwrap_or(false)
                }) {
                    return Err(fail_dss(&format!(
                        "an archived OCSP response answers \"revoked\" for \"{}\" (serial \
                         {}), a certificate of the chain of signature {}",
                        child.subject(),
                        hex::encode(&serial),
                        i + 1
                    )));
                }
            }

            let subjects: Vec<String> = chain.iter().map(|c| c.subject().to_string()).collect();
            let trust_anchor = subjects.last().cloned().unwrap_or_default();
            chains.push(DssChain {
                signature: i + 1,
                subjects,
                trust_anchor,
            });
        }
    }

    Ok(Some(DssReport {
        certificates: cert_handles.len(),
        crls: crls.into_iter().map(|(_, report)| report).collect(),
        // Responses that were checked, not responses that are present: the
        // field has said "successful" since it existed, and under the
        // no-anchor policy the two numbers differ.
        ocsps: verified_ocsps,
        unchecked,
        vri_keys,
        chains,
        uncovered,
        evidence_about: revocation_time.about,
    }))
}

/// The instant an archive's revocation evidence may be judged at: the earliest
/// time-stamp in the document whose TSA signature verified.
///
/// A seal fixes the bytes under it to a moment, and that moment is the closest
/// this verifier can place the signing: a CRL or OCSP answer archived with the
/// document speaks for it, whether or not it still speaks for today. Without
/// this the archived data of a B-LT document is judged against the wall clock,
/// and a perfectly ordinary CRL — one with a `nextUpdate` a week out, as every
/// CA issues — turns a signature that verified for decades into one that stops
/// verifying next Tuesday. Round two's N10 measured exactly that, and a level
/// whose name is "long term" cannot last one CRL period.
///
/// The earliest seal, not the latest, because it is the weaker claim: it is the
/// only instant this verifier can point at that certainly follows the signature.
/// Two limits follow from that and are named rather than papered over. An archive
/// whose validation data predates every seal in its own document still fails —
/// the data may be genuine, but nothing here says the signature is as old as the
/// data claims, and `signingTime` is the signer's own unauthenticated word. And
/// the chain's own validity dates are still judged at `validation_time`, so a
/// document whose CA certificate has since expired still fails too.
fn archived_instant(
    signatures: &[SignatureReport],
    timestamps: &[DocTimeStampReport],
) -> Option<SystemTime> {
    let from_signatures = signatures.iter().flat_map(|sig| {
        sig.reports
            .iter()
            .filter_map(|report| report.timestamp.gen_time())
    });
    let from_stamps = timestamps.iter().filter_map(|stamp| stamp.gen_time);
    from_signatures.chain(from_stamps).min()
}

fn fail_dss(detail: &str) -> Error {
    Error::Verification(detail.to_string())
}

/// The message of a verification error without the shared prefix, so the
/// per signature labels do not stack "verification:" twice.
fn unwrap(e: &Error) -> String {
    match e {
        Error::Verification(m) => m.clone(),
        other => other.to_string(),
    }
}
