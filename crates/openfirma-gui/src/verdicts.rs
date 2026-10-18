//! Verdicts: what the verifier's answer looks like as a sentence a person
//! reads, plus the rules that decide what each line says.
//!
//! The verdict is computed by the *same verifier* `openfirma verify` runs —
//! `openfirma_cades::verify` for detached/encapsulated CMS and
//! `openfirma_pades::verify` (`pades_verify`) for PDFs. What lives here is
//! the answer to three questions review 06 put to the old version:
//!
//! - A-5: a failure must be a VERDICT, not an error screen. The library
//!   reports all-or-nothing (a failed check returns `Err`); [`verdict_lines`]
//!   turns every outcome into one line per signature — valid, NOT valid with
//!   its reason in plain language, or "cannot tell" — and the technical text
//!   rides behind the details control of that line. The verify screen is
//!   therefore never a wall of DER for something that is really just "the
//!   document changed".
//! - A-4: a detached `.csig` verifies against its ORIGINAL document, which
//!   the caller hands in (found next to the `.csig`, or asked for).
//! - M-2/B-4: who signed is a name, never the DN; times say whose clock they
//!   come from.

use std::time::{SystemTime, UNIX_EPOCH};

use openfirma_cades::{VerifyOptions, VerifyReport};
use openfirma_core::Error;

use crate::strings::Tr;
use crate::wizard::{VerdictLine, VerdictList};

/// The validation time of the GUI's verify path: now. (`--at` is a
/// specialist's tool and stays in the CLI; the citizen's question — does this
/// signature hold today — is what this screen answers.)
pub fn now() -> SystemTime {
    SystemTime::now()
}

/// The mark [`verdict_lines`] returns when the reason is simply that no trust
/// anchor was supplied; the UI turns it into its ask-the-user screen.
pub const NO_ANCHORS_MARK: &str = "openfirma: no trust anchors were supplied";

/// Verify one file and render the verdict list. `content` is the ORIGINAL
/// document when `bytes` is a detached signature (found beside the `.csig`
/// or chosen by the user — review 06, A-4); `None` for an attached/PDF one,
/// where the covered bytes travel with the signature themselves. An empty
/// anchor list is not an error but the ask-the-anchor state, carried as
/// [`NO_ANCHORS_MARK`], because inventing anchors would be exactly the
/// unfounded success this project bans.
pub fn verdict_lines(
    bytes: &[u8],
    content: Option<&[u8]>,
    anchors: Vec<openfirma_core::CertificateHandle>,
    tr: &Tr,
) -> Result<VerdictList, openfirma_core::Error> {
    if anchors.is_empty() {
        return Err(Error::Verification(NO_ANCHORS_MARK.into()));
    }
    let opts = VerifyOptions {
        trust_anchors: anchors,
        validation_time: now(),
        ts_mode: false,
        ..VerifyOptions::default()
    };
    match openfirma_core::workflow::Format::detect(bytes) {
        openfirma_core::workflow::Format::Pdf => pdf_verdicts(bytes, &opts, tr),
        _ => cms_verdicts(bytes, content, &opts, tr),
    }
}

/// One CMS (detached, attached, or whatever `verify` is pointed at): one
/// line per SignerInfo. `verify` itself all-or-nothings — every failing
/// signer's check names its signer inside the one error string ("signer 2:
/// …" when there are several), so a broken signature can never hide a good
/// one: the per-signer failures are attributed back to their lines by that
/// label, and with one signer the single failure belongs to it.
fn cms_verdicts(
    bytes: &[u8],
    content: Option<&[u8]>,
    opts: &VerifyOptions,
    tr: &Tr,
) -> Result<VerdictList, openfirma_core::Error> {
    let detached = content.is_some();
    match openfirma_cades::verify(bytes, content, opts) {
        Ok(reports) => Ok(VerdictList {
            lines: reports.iter().map(|r| valid_line(r, tr)).collect(),
            notes: Vec::new(),
        }),
        Err(Error::Verification(msg)) => {
            // Not a CMS at all is a verdict about the FILE, not about each
            // signer (there was no signer to read).
            if msg.contains("not a CMS signature") || msg.contains("no SignerInfo") {
                return Ok(one_unknown(tr.reason_not_signature.clone(), msg));
            }
            let count = signer_count(bytes);
            let parts = split_per_signer(&msg, count);
            if parts.len() != count {
                // The failure is structural (before any signer was read):
                // one line about the file carries it.
                return Ok(one_unknown(plain_reason(&msg, tr), msg));
            }
            let lines = parts
                .into_iter()
                .map(|failure| invalid_line(failure.clone(), &failure, detached, tr))
                .collect();
            Ok(VerdictList {
                lines,
                notes: Vec::new(),
            })
        }
        Err(e) => Err(e),
    }
}

/// How many SignerInfos a CMS holds; it decides whether `verify`'s failure
/// text carries "signer N:" labels at all. The count comes from the library's
/// own structure check (openfirma-cades' parse — the same one `verify`
/// iterates), never from byte windows: every RSA CMS matches OID-byte probes
/// twice before a single signer exists, and a wrong count silently collapses
/// per-signer verdicts into one "?" line. An unparseable CMS counts zero, and
/// the caller's cross-check keeps any split collapsed to one honest line.
fn signer_count(bytes: &[u8]) -> usize {
    openfirma_cades::signer_count(bytes).unwrap_or(0)
}

/// Split `verify`'s joined failure into one message per signer. The library
/// joins with "; " and labels each part "signer N: " when there is more than
/// one signer (openfirma-cades verify.rs), so the count decides the shape:
/// `expected == 1` — no labels exist, the whole message names this one
/// signer; `expected > 1` — the parts are exactly the labelled ones. A
/// message whose labels disagree with the count (a future join format, a
/// hand-built CMS) would invent verdicts, so it collapses to nothing and the
/// caller renders one honest file-level line instead (it checks
/// `parts.len() != expected`).
fn split_per_signer(msg: &str, expected: usize) -> Vec<String> {
    if expected == 1 {
        return vec![msg.to_string()];
    }
    let mut parts = Vec::new();
    for (n, chunk) in split_cms_failures(msg).into_iter().enumerate() {
        // Every part carries its label ("signer N: ", numbered from 1, in
        // order) iff there is more than one signer; anything else means the
        // join did not say who it belongs to, which is a shape this code
        // must not guess at.
        let want = format!("signer {}: ", n + 1);
        if !chunk.starts_with(&want) {
            return Vec::new();
        }
        parts.push(chunk);
    }
    parts
}

/// Join-splitter for `openfirma_cades::verify`'s failures: cut at "; " that
/// opens a new part ("signer N: "), keeping quoted detail intact — the same
/// care `split_failures` gives pades' labels.
fn split_cms_failures(msg: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut rest = msg;
    loop {
        match next_join(rest, "signer ") {
            Some((head, tail)) => {
                parts.push(head.to_string());
                rest = tail;
            }
            None => {
                parts.push(rest.to_string());
                return parts;
            }
        }
    }
}

/// The head of `rest` up to the next "; " that opens with `opener`, and the
/// remainder starting at that opener. A "; " inside quoted detail (the
/// libraries quote technical text) is not a boundary.
fn next_join<'a>(rest: &'a str, opener: &str) -> Option<(&'a str, &'a str)> {
    let bytes = rest.as_bytes();
    let mut i = 0;
    while i + 2 <= bytes.len() {
        if bytes[i] == b';' && bytes[i + 1] == b' ' {
            let after = &rest[i + 2..];
            if after.starts_with(opener) {
                return Some((&rest[..i], after));
            }
        }
        i += 1;
    }
    None
}

/// The PDF verdicts (review 06, A-5): `pades_verify` all-or-nothings the
/// whole document, so a failing document gets its failures re-split on the
/// library's own per-part labels ("signature N (object X Y): …", the ones
/// main.rs prints and the pades crate writes) back onto one line per
/// signature; signatures whose label appears in no failure are VALID parts
/// of an otherwise failing document, and they keep their green line built
/// from a re-verify against just those bytes. A whole-file refusal (not even
/// a signature dictionary parsed) is one unknown verdict about the file.
fn pdf_verdicts(
    bytes: &[u8],
    opts: &VerifyOptions,
    tr: &Tr,
) -> Result<VerdictList, openfirma_core::Error> {
    match openfirma_pades::pades_verify(bytes, opts) {
        Ok(report) => Ok(pdf_list_from_report(&report, tr)),
        Err(Error::Verification(msg)) => {
            let signatures = openfirma_pades::inspect::signatures(bytes).unwrap_or_default();
            if signatures.is_empty() {
                return Ok(one_unknown(verdict_about_file(&msg, tr), msg));
            }
            let mut lines: Vec<Option<VerdictLine>> = vec![None; signatures.len()];
            let mut other_notes: Vec<String> = Vec::new();
            for chunk in split_failures(&msg) {
                // "signature N (object …): reason" — the label pades_verify
                // stamps on every per-signature failure.
                if let Some(rest) = chunk.strip_prefix("signature ")
                    && let Some(n) = rest
                        .split_whitespace()
                        .next()
                        .and_then(|w| w.parse::<usize>().ok())
                    && (1..=signatures.len()).contains(&n)
                    && lines[n - 1].is_none()
                {
                    let reason = after_colon(&chunk);
                    lines[n - 1] = Some(invalid_line(
                        reason.clone(),
                        &format!("{reason} ({chunk})"),
                        false,
                        tr,
                    ));
                    continue;
                }
                other_notes.push(chunk);
            }
            let mut list = VerdictList {
                lines: Vec::new(),
                notes: other_notes,
            };
            for (i, line) in lines.into_iter().enumerate() {
                match line {
                    Some(l) => list.lines.push(l),
                    None => {
                        // This signature's part passed; say so from its own
                        // report rather than from the document's silence.
                        match verify_one_pdf_signature(bytes, i, opts) {
                            Ok(r) => list.lines.push(valid_line(&r, tr)),
                            Err(e) => list.lines.push(unknown_line(
                                verdict_about_file(&e.to_string(), tr),
                                e.to_string(),
                                tr,
                            )),
                        }
                    }
                }
            }
            Ok(list)
        }
        Err(e) => Err(e),
    }
}

/// Re-verify exactly one signature dictionary of a failing document, for its
/// green line: `pades_verify` only answers Ok when EVERYTHING passed, so the
/// parts that passed carry no report unless they are asked for themselves.
/// The inspector hands over this dictionary's own CMS (the /Contents bytes,
/// zero padding removed) and its /ByteRange `[A, B, C, D]`: the covered bytes
/// are `[A, A+B) + [C, C+D)` — the two ranges around the /Contents placeholder
/// — which is what `verify` digested before ever naming a failure elsewhere
/// (the same reading `openfirma_pades::verify`'s own covered-bytes uses).
/// The CMS verifier runs with the very same
/// options and anchors, so this line says what it means: THIS signature was
/// checked on its own bytes and holds.
fn verify_one_pdf_signature(
    bytes: &[u8],
    i: usize,
    opts: &VerifyOptions,
) -> openfirma_core::Result<VerifyReport> {
    let sigs = openfirma_pades::inspect::signatures(bytes)?;
    let sig = sigs
        .get(i)
        .ok_or_else(|| Error::Other("signature index out of range".into()))?;
    if !sig.problems.is_empty() {
        return Err(Error::Verification(sig.problems.join("; ")));
    }
    let [a, b, c, d] = sig.byte_range;
    // Every bound measured against the file: a malformed /ByteRange says so
    // as this line's error instead of panicking in release arithmetic.
    if a > bytes.len() || b > bytes.len() - a || c > bytes.len() || d > bytes.len() - c || a + b > c
    {
        return Err(Error::Other(
            "the /ByteRange does not describe this document".into(),
        ));
    }
    let covered: Vec<u8> = bytes[a..a + b]
        .iter()
        .chain(bytes[c..c + d].iter())
        .copied()
        .collect();
    let mut reports = openfirma_cades::verify(&sig.cms, Some(&covered), opts)?;
    reports
        .pop()
        .ok_or_else(|| Error::Other("the signature dictionary's CMS carried no SignerInfo".into()))
}

/// Split pades_verify's joined failure on its own labels. Every part starts
/// with "signature N", "document time-stamp N" or "validation data"; "; " is
/// the joiner but also appears inside quoted technical detail, so splitting
/// happens only on a "; " that is followed by one of those openers.
fn split_failures(msg: &str) -> Vec<String> {
    const OPENERS: [&str; 3] = ["signature ", "document time-stamp ", "validation data ("];
    let mut parts = Vec::new();
    let mut rest = msg;
    loop {
        // The next cut is a "; " joiner followed by one of the library's
        // openers — searched from index 1 so the opener that OPENED this part
        // cannot cut it again, while inside-part "; " (a quoted detail like
        // `failed: "a; b" differs`, which continues with text, never an
        // opener) is passed over.
        let search_from = 2.min(rest.len());
        let mut cut = None;
        for open in OPENERS {
            let needle = format!("; {open}");
            if let Some(rel) = rest[search_from..].find(&needle) {
                let at = search_from + rel;
                if cut.is_none_or(|best| at < best) {
                    cut = Some(at);
                }
            }
        }
        match cut {
            Some(i) => {
                let head = rest[..i].trim_end_matches("; ").trim();
                if !head.is_empty() {
                    parts.push(head.to_string());
                }
                rest = &rest[i + 2..]; // the "; " joiner goes with the previous part
            }
            None => {
                let tail = rest.trim();
                if !tail.is_empty() {
                    parts.push(tail.to_string());
                }
                return parts;
            }
        }
    }
}

/// Everything after the first ": " of a labelled failure line, whole line
/// when it carries none.
fn after_colon(part: &str) -> String {
    match part.split_once(": ") {
        Some((_, rest)) => rest.to_string(),
        None => part.to_string(),
    }
}

/// Which sentence a document-level refusal earns in plain language.
fn verdict_about_file(msg: &str, tr: &Tr) -> String {
    if msg.contains("no signature dictionary") {
        return tr.verdict_unsigned.clone();
    }
    plain_reason(msg, tr)
}

fn pdf_list_from_report(report: &openfirma_pades::DocumentReport, tr: &Tr) -> VerdictList {
    let mut lines = Vec::new();
    for sig in &report.signatures {
        for r in &sig.reports {
            let mut line = valid_line(r, tr);
            line.technical.push(format!(
                "/ByteRange [{a} {b} {c} {d}]",
                a = sig.byte_range[0],
                b = sig.byte_range[1],
                c = sig.byte_range[2],
                d = sig.byte_range[3]
            ));
            lines.push(line);
        }
    }
    let mut notes = Vec::new();
    if !report.document_timestamps.is_empty() {
        let total = report.document_timestamps.len();
        let verified = report
            .document_timestamps
            .iter()
            .filter(|t| t.verified())
            .count();
        if verified == total {
            notes.push(format!(
                "El documento lleva {total} sello(s) de tiempo de documento (nivel B-LTA): la \
                 firma de la autoridad de sellado de cada uno se ha verificado, y cada sello \
                 certifica todos los bytes anteriores al momento del sellado."
            ));
        } else if verified == 0 {
            // A seal whose TSA signature did not verify is not a B-LTA level:
            // saying it were would be the exact false green this project bans
            // (review A2). Say what was seen, not what a level would claim.
            let why = report
                .document_timestamps
                .iter()
                .find_map(|t| t.problem.clone())
                .unwrap_or_else(|| "no se pudo comprobar".into());
            notes.push(format!(
                "El documento lleva {total} sello(s) de tiempo de documento, pero la firma de \
                 su autoridad de sellado NO se ha podido verificar ({why}). NO se afirma el \
                 nivel B-LTA: un sello sin verificar no certifica nada."
            ));
        } else {
            notes.push(format!(
                "El documento lleva {total} sello(s) de tiempo de documento, de los que \
                 {verified} tienen la firma de su autoridad verificada. NO se afirma el nivel \
                 B-LTA mientras alguno quede sin verificar."
            ));
        }
    }
    if let Some(dss) = &report.dss {
        notes.push(format!(
            "El documento guarda datos de validación ({} certificados, {} CRLs, {} respuestas \
             OCSP), todos legibles y cada CRL firmada por la autoridad que la emite.",
            dss.certificates,
            dss.crls.len(),
            dss.ocsps
        ));
        for chain in &dss.chains {
            notes.push(format!(
                "La cadena de la firma {} se reconstruye solo con los datos del documento: {}.",
                chain.signature,
                chain.subjects.join(" -> ")
            ));
        }
    }
    VerdictList { lines, notes }
}

/// The green line of a signature every check passed.
fn valid_line(r: &VerifyReport, tr: &Tr) -> VerdictLine {
    let stamped = r.timestamp.verified();
    VerdictLine {
        status: crate::wizard::VerdictStatus::Valid,
        signer: signer_display(&r.signer_subject).unwrap_or_default(),
        when: time_line(r.attributes.signing_time, stamped, tr),
        why_not: None,
        trust_anchor: Some(r.trust_anchor.clone()),
        technical: technical_of(r),
    }
}

/// The red line of one failing signer: plain reason in front, the library's
/// full sentence behind details (A-5). `detached` with a missing content is
/// folded into the digest reason by the caller handing us its own text.
fn invalid_line(reason: String, technical: &str, _detached: bool, tr: &Tr) -> VerdictLine {
    let why = plain_reason(&reason, tr);
    VerdictLine {
        status: crate::wizard::VerdictStatus::Invalid,
        signer: extract_labelled_signer(technical),
        when: String::new(),
        why_not: Some(why),
        trust_anchor: None,
        technical: vec![technical.to_string()],
    }
}

fn unknown_line(why: String, technical: String, _tr: &Tr) -> VerdictLine {
    VerdictLine {
        status: crate::wizard::VerdictStatus::Unknown,
        signer: String::new(),
        when: String::new(),
        why_not: Some(why),
        trust_anchor: None,
        technical: vec![technical],
    }
}

fn one_unknown(why: String, technical: String) -> VerdictList {
    VerdictList {
        lines: vec![VerdictLine {
            status: crate::wizard::VerdictStatus::Unknown,
            signer: String::new(),
            when: String::new(),
            why_not: Some(why),
            trust_anchor: None,
            technical: vec![technical],
        }],
        notes: Vec::new(),
    }
}

/// The plain-language reason a failure earns (A-5): matched on the check
/// names the library writes, never on punctuation. An unknown technical
/// string still yields "cannot tell why" plus its first clause — an error
/// screen never does.
fn plain_reason(technical: &str, tr: &Tr) -> String {
    let t = technical;
    if t.contains("messageDigest check failed") || t.contains("/ByteRange") {
        return tr.reason_digest.clone();
    }
    // "no trust anchors were supplied" reaches the verdict only through an
    // anchor-less pool that some other path produced; it reads as chain.
    if t.contains("certificateChain check failed")
        || t.contains("no trust anchors")
        || t.contains("does not reach a trust anchor")
        || t.contains("trust anchor")
    {
        return tr.reason_chain.clone();
    }
    if t.contains("validityDates check failed")
        || t.contains("expired")
        || t.contains("not yet valid")
    {
        return tr.reason_expired.clone();
    }
    if t.contains("signatureValue check failed") {
        return tr.reason_digest.clone();
    }
    // Not recognized: the reason stays honest about that.
    format!("{}: {}", tr.reason_generic_prefix, first_sentence(t))
}

/// The failure's first sentence, hard-capped so a DER dump never fills the
/// plain line — it is what rides behind details in full.
fn first_sentence(t: &str) -> String {
    let cut = t.find([';', '\n']).unwrap_or(t.len());
    let head = t[..cut].trim();
    if head.chars().count() > 160 {
        let mut s: String = head.chars().take(157).collect();
        s.push('…');
        s
    } else {
        head.to_string()
    }
}

/// A failed report names its signer nowhere (the signer lives in the DER);
/// the label the library added ("signer 2: …") is what we have to say — and
/// saying WHICH signature failed matters when a document carries several.
fn extract_labelled_signer(technical: &str) -> String {
    if let Some(rest) = technical.strip_prefix("signer ")
        && let Some(n) = rest.split(':').next()
    {
        return n.trim().to_string();
    }
    if let Some(rest) = technical.strip_prefix("signature ")
        && let Some(n) = rest.split_whitespace().next()
    {
        return format!("firma {n}");
    }
    String::new()
}

/// The technical block behind the details control.
fn technical_of(r: &VerifyReport) -> Vec<String> {
    let mut lines = vec![
        format!("digest: {}", r.digest.name()),
        format!("algoritmo de firma: {}", r.signature_alg),
        format!("sujeto (DN): {}", r.signer_subject),
        format!("cadena hasta la autoridad de confianza: {}", r.trust_anchor),
    ];
    for (i, s) in r.chain_subjects.iter().enumerate() {
        lines.push(format!("cadena {}: {s}", i + 1));
    }
    if let Some(t) = r.attributes.signing_time {
        lines.push(format!("signingTime: {}", fmt_utc(t)));
    }
    // A level string is only ever a level the verifier PROVED (finding A2):
    // an unverified token never contributes "B-T", and what failed travels in
    // the technical lines so no screen can paint it green.
    if r.timestamp.verified() {
        let stamp_time = r
            .timestamp
            .gen_time()
            .map(fmt_utc)
            .unwrap_or_else(|| "instante no reportado".into());
        lines.push(format!(
            "nivel: B-T (sellado de firma verificado, genTime {stamp_time})"
        ));
    } else if !r.timestamp.tokens.is_empty() {
        lines.push(format!(
            "nivel: B-B (hay sello de tiempo pero NO esta verificado: {})",
            r.timestamp.problem().unwrap_or_default()
        ));
    } else {
        lines.push("nivel: B-B".into());
    }
    lines.push(format!("comprobaciones superadas: {}", r.passed.join(", ")));
    lines
}

/// The "Cuándo" line (B-4): local time with the zone named, and — without a
/// TSA stamp standing behind it — whose clock it is. UTC printed bare looked
/// like wall-clock time; the machine's own zone is what a reader compares to.
fn time_line(t: Option<SystemTime>, stamped: bool, tr: &Tr) -> String {
    let Some(t) = t else { return String::new() };
    if stamped {
        fmt_local(t)
    } else {
        format!("{} ({})", fmt_local(t), tr.declared_time_note)
    }
}

/// A `SystemTime` in the machine's local wall clock, zone suffix included.
/// No tz dependency (the pure-Rust rule): the offset comes from libc's own
/// reading of /etc/localtime through std — which std does not expose — so it
/// is asked of the C library that owns the answer via `localtime_r`… no: this
/// crate links nothing. The honest zero-dependency answer is UTC with the
/// zone NAMED; a mislabelled local guess would be the exact failure B-4
/// reports, and pretending to know the offset without libc is a lie in the
/// other direction. The suffix therefore says UTC truthfully, and the note
/// about WHO declared the time carries the rest of the meaning.
fn fmt_local(t: SystemTime) -> String {
    let mut s = fmt_utc(t);
    if s.ends_with('Z') {
        s.pop();
        s.push_str(" UTC");
    }
    s
}

/// A `SystemTime` as the UTC ISO form. Same Hinnant calendar openfirma-pades
/// and the CLI use, so no two frontends can ever print different dates for
/// one instant.
fn fmt_utc(t: SystemTime) -> String {
    let secs = t
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    let z = (secs / 86_400) as i64;
    let rem = (secs % 86_400) as i64;
    let z2 = z + 719_468;
    let era = if z2 >= 0 { z2 } else { z2 - 146_096 } / 146_097;
    let doe = z2 - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let (y, m) = if m <= 2 { (y + 1, m) } else { (y, m) };
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02} UTC",
        rem / 3600,
        (rem % 3600) / 60,
    )
}

/// The friendly name from a verify report's RFC 4514 subject string (M-2):
/// the CN first — the FULL value, not `strip_prefix`'s DN dump that printed
/// the DNI number over the screen — then the organisation, then no name at
/// all. The rest of the DN stays in the details block, where it was already
/// available: `signer_display` answering `None` is the caller's "certificado
/// sin nombre" case, never a DN fallback.
pub fn signer_display(dn: &str) -> Option<String> {
    // Nameable means NON-EMPTY after unescaping: a CN that exists but carries
    // no text (`CN=,O=AYUNTAMIENTO…`) is no name, and the organisation signs
    // for itself then — AutoFirma's dialogs show the O in exactly that case.
    let value = |dn: &str, keys: [&str; 2]| -> Option<String> {
        attributes(dn)
            .into_iter()
            .find(|(k, _)| keys.iter().any(|key| k.eq_ignore_ascii_case(key)))
            .map(|(_, v)| unescape_4514(&v))
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };
    let named = |dn: &str| value(dn, ["CN", "2.5.4.3"]).or_else(|| value(dn, ["O", "2.5.4.10"]));
    named(dn).or_else(|| named(&repair_dn(dn)))
}

/// An RFC 4514 name as (key, raw value) pairs: attributes are `,`- or
/// `+`-separated, but a comma inside a quoted value belongs to the value
/// (RFC 4514 §2.4: quotes mean no backslashes needed), and a `\` always
/// escapes one character — every Spanish CN carries an escaped comma
/// (`APELLIDO1 APELLIDO2\, NOMBRE`). An attribute without `=` is skipped:
/// it is some other attribute's run-on tail, not a pair to name by.
fn attributes(dn: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let bytes = dn.as_bytes();
    let mut start = 0usize;
    let mut i = 0usize;
    let mut quoted = false;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'"' => {
                quoted = !quoted;
                i += 1;
            }
            b',' | b'+' if !quoted => {
                push_attribute(&mut out, &dn[start..i]);
                i += 1;
                start = i;
            }
            _ => i += 1,
        }
    }
    if start < bytes.len() {
        push_attribute(&mut out, &dn[start..]);
    }
    out
}

fn push_attribute(out: &mut Vec<(String, String)>, attr: &str) {
    // `=` inside a QUOTED value is part of the value (a rare CN spelling it
    // must not split on): find the first separator `=` outside quotes.
    let bytes = attr.as_bytes();
    let mut quoted = false;
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'"' => {
                quoted = !quoted;
                i += 1;
            }
            b'=' if !quoted => {
                out.push((attr[..i].trim().to_string(), attr[i + 1..].to_string()));
                return;
            }
            _ => i += 1,
        }
    }
}

/// Whether `v` holds an odd number of unescaped quotes — a writer that opened
/// `CN="NAME` and never closed it. Such a value swallowed its separator under
/// the strict reading, so the whole name parses shifted by one attribute.
fn quote_imbalance(v: &str) -> bool {
    let bytes = v.as_bytes();
    let mut i = 0;
    let mut odd = false;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'"' => {
                odd = !odd;
                i += 1;
            }
            _ => i += 1,
        }
    }
    odd
}

/// Repair an RFC 4514 name whose quoted values forgot to close: one closing
/// quote appended per unbalanced opening one. It invents no names — it joins
/// back the ones the string already contains, under its own separator rule.
fn repair_dn(dn: &str) -> String {
    if !quote_imbalance(dn) {
        return dn.to_string();
    }
    let mut out = String::with_capacity(dn.len() + 2);
    for (i, attr) in loose_attributes(dn).into_iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&attr);
        if quote_imbalance(&attr) {
            out.push('"');
        }
    }
    out
}

/// The same walk as [`attributes`] but returning whole attribute SLICES, the
/// escape-aware kind (a `\` before a comma means "part of my value"); quotes
/// are NOT honoured here — this is the view of a name whose quotes are broken.
fn loose_attributes(dn: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = dn.as_bytes();
    let mut start = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b',' => {
                out.push(dn[start..i].to_string());
                i += 1;
                start = i;
            }
            _ => i += 1,
        }
    }
    if start < bytes.len() {
        out.push(dn[start..].to_string());
    }
    out
}

/// Undo RFC 4514 escaping (`\,` `,` `\;` `\"` etc.) and surrounding quotes.
fn unescape_4514(v: &str) -> String {
    let v = v.trim();
    let out = if v.starts_with('"') && v.ends_with('"') && v.len() >= 2 {
        &v[1..v.len() - 1]
    } else {
        v
    };
    let mut s = String::with_capacity(out.len());
    let mut esc = false;
    for c in out.chars() {
        if esc {
            s.push(c);
            esc = false;
        } else if c == '\\' {
            esc = true;
        } else {
            s.push(c);
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_utc_formatter_matches_the_libraries_one() {
        // Known instants; the CLI's `fmt_system_time` and this calendar must
        // never disagree, so both are pinned to hand-checked values.
        assert_eq!(fmt_utc(UNIX_EPOCH), "1970-01-01 00:00 UTC");
        let t = UNIX_EPOCH + std::time::Duration::from_secs(1_792_071_360);
        assert!(fmt_utc(t).starts_with("2026-10-15 13:36"), "{}", fmt_utc(t));
    }

    #[test]
    fn the_signer_name_never_leaks_the_dni() {
        // M-2's exact failure: strip_prefix("CN=") returned the WHOLE rest of
        // the DN — SERIALNUMBER (the NIF) included. The new rule answers only
        // the name.
        let dn = "CN=PEREZ GARCIA\\, ANA,SERIALNUMBER=IDCES-12345678Z,OU=AC openfirma Usuarios,O=openfirma test,C=ES";
        assert_eq!(signer_display(dn).as_deref(), Some("PEREZ GARCIA, ANA"));
        // The DN as the report really spells it (CN= first):
        let dn2 = "CN=\"PÉREZ GÓMEZ, JOSÉ\",SERIALNUMBER=IDCES-99999999R,O=test,C=ES";
        assert_eq!(signer_display(dn2).as_deref(), Some("PÉREZ GÓMEZ, JOSÉ"));
        // Organisation only (sello de entidad without a CN):
        let dn3 = "CN=,O=AYUNTAMIENTO DE EJEMPLO,C=ES";
        assert_eq!(
            signer_display(dn3).as_deref(),
            Some("AYUNTAMIENTO DE EJEMPLO")
        );
        // Nothing nameable: no answer (the UI then says "unknown"), and never
        // a DN that would print the NIF.
        assert_eq!(signer_display("OU=people,C=ES"), None);
    }

    #[test]
    fn failures_split_back_onto_their_signers() {
        // The join format is verify.rs': "a; b" with no per-signer labels for
        // one signer. One failure therefore means one red line.
        assert_eq!(
            split_per_signer("messageDigest check failed: x", 1).len(),
            1
        );
        // A multi-signer CMS whose failure carries "signer N: " labels splits
        // into that many parts — and the count comes from the DER, not from
        // byte windows (an RSA CMS matches OID-byte probes repeatedly with a
        // single signer, which is how the old heuristic answered 2 for every
        // RSA signature and collapsed the split forever).
        let joined = "signer 1: digest mismatch; signer 2: chain stops at CN=AC";
        assert_eq!(split_per_signer(joined, 2).len(), 2);
        // A count that disagrees with the message's shape stays unsplit (the
        // caller renders one honest file-level line then).
        assert_eq!(split_per_signer("a; b", 3), Vec::<String>::new());
        // pades_verify's label split survives a quoted "; " inside detail.
        let joined = "signature 1 (object 5 0): messageDigest check failed: \"a; b\" differs; \
                      signature 2 (object 9 0): validityDates check failed: expired";
        let parts = split_failures(joined);
        assert_eq!(parts.len(), 2, "{parts:?}");
        assert!(parts[0].starts_with("signature 1"));
        assert!(parts[1].starts_with("signature 2"));
        // A part without a label at all (a document-level refusal) stays one.
        let one = split_failures("the document carries no signature dictionary");
        assert_eq!(one.len(), 1);
    }

    #[test]
    fn plain_reasons_answer_in_spanish() {
        let tr = Tr::es();
        assert!(plain_reason("signatureValue check failed: RSA verify", &tr).contains("cambió"));
        assert!(
            plain_reason("certificateChain check failed: stops at CN=AC", &tr)
                .contains("autoridad")
        );
        assert!(
            plain_reason("validityDates check failed: notAfter has passed", &tr)
                .contains("caducado")
        );
        // An unknown technical string still earns a sentence (A-5), never an
        // error screen.
        let odd = plain_reason("signerCertificate check failed: weird DER; extra", &tr);
        assert!(odd.starts_with("Motivo:"), "{odd}");
        assert!(!odd.contains("extra"), "the cap keeps it a sentence: {odd}");
    }

    #[test]
    fn no_anchors_is_the_distinguished_answer() {
        // An empty anchor list never reaches the verifier: it is this mark,
        // which the UI renders as its ask-the-user screen. A file that isn't
        // even a signature must not be blamed first for the anchors.
        let err = match verdict_lines(b"nada", None, Vec::new(), &Tr::es()) {
            Ok(_) => panic!("no anchors must never verify against nothing"),
            Err(e) => e,
        };
        match err {
            Error::Verification(m) => assert_eq!(m, NO_ANCHORS_MARK),
            other => panic!("expected the no-anchors mark, got {other:?}"),
        }
    }

    #[test]
    fn a_non_signature_file_is_a_verdict_not_an_error() {
        // A-5 through the real verifier: garbage bytes with real anchors get
        // ONE unknown verdict naming the file — the screen stays a verdict
        // list, it never falls to the error panel.
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/certs");
        let Ok(ca_pem) = std::fs::read_to_string(dir.join("ca.crt")) else {
            eprintln!("SKIP: testdata/certs/ca.crt is absent, run tools/gen-testcert.sh");
            if std::env::var_os("OPENFIRMA_REQUIRE_TESTS").is_some() {
                panic!("OPENFIRMA_REQUIRE_TESTS is set and the test PKI is missing");
            }
            return;
        };
        let anchors = vec![openfirma_core::CertificateHandle::from_pem(&ca_pem).unwrap()];
        let list = verdict_lines(b"not a signature", None, anchors, &Tr::es()).unwrap();
        assert_eq!(list.lines.len(), 1);
        use crate::wizard::VerdictStatus;
        assert!(matches!(list.lines[0].status, VerdictStatus::Unknown));
    }

    #[test]
    fn a_detached_csig_verifies_with_its_content() {
        // A-4 end to end through the GUI's own verdict path: sign detached,
        // verify WITHOUT content gets the red "document changed/missing"
        // verdict (messageDigest failing on absent content), and WITH the
        // original it is green — proving the window can check its own .csig.
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata");
        let (Ok(_), Ok(_)) = (
            std::fs::metadata(dir.join("certs/signer-rsa.p12")),
            std::fs::metadata(dir.join("certs/ca.crt")),
        ) else {
            eprintln!("SKIP: the test PKI is absent, run tools/gen-testcert.sh");
            if std::env::var_os("OPENFIRMA_REQUIRE_TESTS").is_some() {
                panic!("OPENFIRMA_REQUIRE_TESTS is set and the test PKI is missing");
            }
            return;
        };
        let key = crate::wizard::KeySource::P12 {
            path: dir.join("certs/signer-rsa.p12"),
            password: zeroize::Zeroizing::new("openfirma".into()),
            alias: None,
            display: "test".into(),
        };
        let signer = key.signer().unwrap();
        let doc = b"el documento firmado a parte";
        let sig = crate::signing::execute(
            "cades-b-b",
            doc,
            signer.as_ref(),
            openfirma_core::DigestAlg::Sha256,
            None,
            None,
        )
        .unwrap();
        let anchors: Vec<_> = ["ca.crt", "intermediate.crt"]
            .iter()
            .flat_map(|f| {
                std::fs::read_to_string(dir.join("certs").join(f))
                    .ok()
                    .and_then(|pem| openfirma_core::CertificateHandle::from_pem(&pem).ok())
                    .into_iter()
                    .collect::<Vec<_>>()
            })
            .collect();
        assert_eq!(anchors.len(), 2);
        let tr = Tr::es();
        let without = verdict_lines(&sig, None, anchors.clone(), &tr).unwrap();
        // The red status itself (A-5), not merely "not green": an
        // unsigned-content .csig fails its messageDigest, and that is a NOT
        // VALID line, never the "?" of an unsplit file-level guess. (The old
        // assertion only checked `!valid()`, which Unknown also passed — it
        // hid a broken signer count that made Invalid unreachable for every
        // RSA CMS.)
        assert_eq!(without.lines.len(), 1);
        use crate::wizard::VerdictStatus;
        assert_eq!(without.lines[0].status, VerdictStatus::Invalid);
        let with = verdict_lines(&sig, Some(doc), anchors, &tr).unwrap();
        assert_eq!(with.lines.len(), 1);
        assert!(with.lines[0].valid());
    }

    #[test]
    fn the_signer_count_is_the_librarys_own_parse() {
        // The count that decides whether failures split per signer comes
        // from openfirma-cades' structure check, so a signature's real
        // shape — not an OID byte-window — answers it (an RSA CMS matches
        // those probes twice before one signer exists).
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata");
        let Ok(container) = std::fs::read(dir.join("certs/signer-rsa.p12")) else {
            eprintln!("SKIP: the test PKI is absent, run tools/gen-testcert.sh");
            if std::env::var_os("OPENFIRMA_REQUIRE_TESTS").is_some() {
                panic!("OPENFIRMA_REQUIRE_TESTS is set and the test PKI is missing");
            }
            return;
        };
        let key = crate::wizard::KeySource::P12 {
            path: dir.join("certs/signer-rsa.p12"),
            password: zeroize::Zeroizing::new("openfirma".into()),
            alias: None,
            display: "test".into(),
        };
        let _ = container;
        let signer = key.signer().unwrap();
        let sig = crate::signing::execute(
            "cades-b-b",
            b"contar firmantes",
            signer.as_ref(),
            openfirma_core::DigestAlg::Sha256,
            None,
            None,
        )
        .unwrap();
        assert_eq!(signer_count(&sig), 1);
        // Garbage is not a CMS: zero, i.e. "do not split".
        assert_eq!(signer_count(b"nada"), 0);
    }

    /// Round 2 of the adversarial review: the window's wording for the MIXED
    /// document time-stamp case — a document whose seals did NOT all verify —
    /// had no test of its own while the library verdict it renders did. The
    /// mixed branch is the one that must not round up: one unverified seal
    /// means no B-LTA, and the sentence has to say how many and why instead of
    /// claiming the level, which is exactly the over-claim A-2 was about.
    #[test]
    fn a_mixed_document_timestamp_set_never_claims_b_lta() {
        let seal = |object: u32, verified: bool| openfirma_pades::verify::DocTimeStampReport {
            object: openfirma_pades::pdf::ObjRef::new(object, 0),
            byte_range: [0, 100, 200, 10],
            digest: openfirma_core::alg::DigestAlg::Sha256,
            token: Vec::new(),
            gen_time: verified.then_some(std::time::UNIX_EPOCH),
            problem: (!verified).then(|| "la cadena del sello no llega a un ancla".to_string()),
        };
        let report = openfirma_pades::DocumentReport {
            signatures: Vec::new(),
            document_timestamps: vec![seal(31, true), seal(41, false)],
            dss: None,
        };
        let list = pdf_list_from_report(&report, &Tr::es());
        let text = list.notes.join(" ");
        assert!(
            text.contains("de los que 1"),
            "the counts are named, not rounded: {text}"
        );
        assert!(
            text.contains("NO se afirma el nivel B-LTA"),
            "the level is refused, out loud: {text}"
        );
        assert!(
            !text.contains("(nivel B-LTA)"),
            "the mixed case may not claim the level: {text}"
        );
        // The other two branches stay distinguishable in the same sentence
        // space: every seal verified says so, and none verified says so too.
        let all = openfirma_pades::DocumentReport {
            signatures: Vec::new(),
            document_timestamps: vec![seal(31, true), seal(41, true)],
            dss: None,
        };
        let all_text = pdf_list_from_report(&all, &Tr::es()).notes.join(" ");
        assert!(
            all_text.contains("(nivel B-LTA)"),
            "two verified seals are the level: {all_text}"
        );
        let none = openfirma_pades::DocumentReport {
            signatures: Vec::new(),
            document_timestamps: vec![seal(31, false)],
            dss: None,
        };
        let none_text = pdf_list_from_report(&none, &Tr::es()).notes.join(" ");
        assert!(
            none_text.contains("NO se afirma el nivel B-LTA")
                && none_text.contains("la cadena del sello no llega a un ancla"),
            "an unverified seal says why: {none_text}"
        );
    }
}
