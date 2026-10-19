//! The wizard's state machine, deliberately free of any widget or window
//! type so it is testable headlessly (`egui_kittest` drives the rendering;
//! this module is tested as plain logic — and both assert the same rules).
//!
//! One principle from docs/adr/0006-gui-toolkit.md governs everything below: never a silent
//! success, never a lost result. The `Done` state keeps every byte of the
//! signature in memory until the user has seen where it was written *and* an
//! explicit save (or an explicit discard confirmed twice) releases it; the
//! window cannot be closed through it while unsaved (see `close_decision`).
//!
//! Review 06 A-1 moved the slow work (signing, TSA, card access) onto a
//! worker thread. The states here carry its shape — [`SignJob`]/[`LoadJob`]
//! are plain data so the *scheduling* rule ("exactly one job in flight, no
//! screen changes while one runs") is testable without any threads at all.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use openfirma_core::workflow::{Format, StoreSpec};
use zeroize::Zeroizing;

/// What a signable certificate came from and how to show it. `KeySource` is
/// the same three-way split `openfirma sign` takes (`--p12`, `--store`; a
/// bare cert+key pair is not a citizen's shape and stays CLI-only).
pub enum KeySource {
    P12 {
        path: PathBuf,
        password: Zeroizing<String>,
        alias: Option<String>,
        display: String,
    },
    /// `cert` rides boxed: a `StoreCertificate` embeds the parsed certificate
    /// inline (hundreds of bytes), and boxing it keeps this enum — carried by
    /// every picker row — the size of two pointers plus the display name.
    Store {
        store: Arc<dyn openfirma_keystore::SystemStore>,
        cert: Box<openfirma_keystore::StoreCertificate>,
        display: String,
    },
}

impl KeySource {
    pub fn display(&self) -> &str {
        match self {
            KeySource::P12 { display, .. } | KeySource::Store { display, .. } => display,
        }
    }

    /// A second owned copy of the same source (A-3: when the output collides
    /// and the save dialog answers with a new name, the signing job is rebuilt
    /// for that destination — the key must survive the first job's move into
    /// the worker). A store row copies its `Arc` only; a `.p12` row copies its
    /// path and its zeroizing password. Never a re-login.
    pub fn clone_box(&self) -> KeySource {
        match self {
            KeySource::P12 {
                path,
                password,
                alias,
                display,
            } => KeySource::P12 {
                path: path.clone(),
                password: password.clone(),
                alias: alias.clone(),
                display: display.clone(),
            },
            KeySource::Store {
                store,
                cert,
                display,
            } => KeySource::Store {
                store: store.clone(),
                cert: cert.clone(),
                display: display.clone(),
            },
        }
    }

    /// The signer the CLI builds for the same source — `load_p12` /
    /// `boxed_signer`, shared functions, not lookalikes.
    pub fn signer(&self) -> openfirma_core::Result<Box<dyn openfirma_core::Signer + 'static>> {
        match self {
            KeySource::P12 {
                path,
                password,
                alias,
                ..
            } => Ok(Box::new(crate::keystore_io::load_p12(
                path,
                password,
                alias.as_deref(),
            )?)),
            KeySource::Store { store, cert, .. } => Ok(openfirma_keystore::boxed_signer(
                store.clone(),
                (*(*cert)).clone(),
            )),
        }
    }
}

/// The certificate picker's content: what was found where. Errors from a
/// keystore that refused to open travel with it — an empty list with no
/// explanation is the silent failure this project bans.
#[derive(Default)]
pub struct CertCatalog {
    pub entries: Vec<CertificateChoice>,
    /// One line per store that failed to open, for the picker's honest
    /// "esto no funcionó" section.
    pub errors: Vec<String>,
}

/// One row of the picker. A `.p12` row waiting on its password holds the
/// path; every other row carries a thread-safe thunk (a `Send` closure, so
/// signing a picked certificate can happen off the UI thread — review 06,
/// A-1) that rebuilds the key source without re-opening anything. For store
/// entries the thunk keeps the opened `Arc<dyn SystemStore>`: the PIN was
/// spent once when the store opened and this session's catalog survives
/// documents, so no second login and no second PIN (finding A-6).
pub struct CertificateChoice {
    pub display: String,
    /// Which keystore it came from, or the .p12 file name.
    pub origin: String,
    /// The picker's extra lines (A-7): issuer, "válido hasta", and the flags
    /// ("solo autenticación…", "caducado") a person needs to tell two
    // certificates apart — the same fields AutoFirma's certificate dialog
    // shows before the mistake, not after it.
    pub issuer: Option<String>,
    /// The validity end date as `YYYY-MM-DD` (expired rows say so in `badges`).
    pub valid_until: Option<String>,
    /// Human flags a row wears: auth-only, expired — greyed but visible, never
    /// silently dropped (what a picker hides, a citizen cannot forgive).
    pub badges: Vec<String>,
    /// How to build the signer. `None` marks a `.p12` row that still needs
    /// its password typed first (the picker then shows one password field).
    pub source: Option<Arc<dyn Fn() -> KeySource + Send + Sync>>,
    /// A `.p12` awaiting its password, kept with the path so the field and
    /// the eventual `KeySource::P12` cannot disagree about which file they
    /// describe.
    pub pending_p12: Option<PathBuf>,
}

impl CertificateChoice {
    pub fn key(&self) -> Option<KeySource> {
        self.source.as_ref().map(|f| f())
    }

    /// A row that may be selected to sign with: a badge like "caducado" is
    /// shown to the user but AutoFirma's own default filters (finding A-5)
    /// still refuse it — an expired certificate produces a signature no
    /// validator will accept, and offering it silently would be worse than
    /// refusing it out loud. `badges` decides the greying.
    pub fn selectable(&self) -> bool {
        self.badges
            .iter()
            .all(|b| !b.contains("caducado") && !b.contains("expired"))
    }
}

/// The error panel's content: one plain sentence for the user plus the full
/// technical text behind "Ver detalles técnicos" — never the other way round.
#[derive(Clone, Debug)]
pub struct ErrorReport {
    /// One sentence in the interface language with what went wrong and, where
    /// a way out exists, what to run. Built by `crate::errors`.
    pub plain: String,
    /// The technical error exactly as the library reported it.
    pub technical: String,
}

/// What one signature's verdict says, in exactly three shapes (review 06,
/// A-5): green, red with a reason, and "cannot tell" with why. There is no
/// fourth shape; anything the verifier answers arrives as one of these.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerdictStatus {
    Valid,
    Invalid,
    /// Every check that could run passed or the failure was structural (not
    /// a CMS at all): the honest third answer "no se puede confirmar", never
    /// a green light and never an error screen.
    Unknown,
}

impl VerdictStatus {
    /// The line's leading word, for `Debug` output and for nothing else
    /// (M-7). This used to be a `glyph()` returning "✓"/"✗" and a claim that
    /// they were "in the one font every build carries" — the opposite of what
    /// the fonts have: egui's proportional and monospace families carry no
    /// U+2713/U+2717, so the window painted an empty box and the test harness
    /// hid it with `allow_missing_glyphs()`. A mark a reader sees as a box, and
    /// a screen reader announces as nothing, is worse than a word; the screen
    /// itself no longer draws a mark at all (its sentence says it).
    pub fn mark(&self) -> &'static str {
        match self {
            VerdictStatus::Valid => "válida",
            VerdictStatus::Invalid => "NO válida",
            VerdictStatus::Unknown => "sin confirmar",
        }
    }
}

/// One verdict line, status + sentence; `why_not` is the plain-language half
/// of an Invalid/Unknown line.
#[derive(Clone)]
pub struct VerdictLine {
    pub status: VerdictStatus,
    /// The failure's subject: the labelled signer ("2" from "signer 2: …") or
    /// "firma N" for a PDF signature dictionary; empty when nobody is named.
    pub signer: String,
    /// Human-readable time, or empty when the signature carries none. A time
    /// no TSA confirmed says whose clock it is (B-4).
    pub when: String,
    /// For red/unknown lines: the one-sentence reason in the interface
    /// language. Valid lines carry `None`.
    pub why_not: Option<String>,
    /// The trust anchor a valid chain reached, if any — shown first inside
    /// the details area so "¿en quién confía esto?" has an answer.
    pub trust_anchor: Option<String>,
    /// Technical detail for the details control (chain, byte ranges…).
    pub technical: Vec<String>,
}

impl VerdictLine {
    pub fn valid(&self) -> bool {
        self.status == VerdictStatus::Valid
    }
}

// Manual, sentence-shaped `Debug`s (not derives): a failed assert on a verdict
// must read as "NO válida firma 2 — el documento cambió", not as the technical
// DER dump riding behind every line. The full text stays available through the
// fields themselves.
impl core::fmt::Debug for VerdictLine {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{} {}{}{}",
            self.status.mark(),
            if self.signer.is_empty() {
                "?"
            } else {
                &self.signer
            },
            self.why_not
                .as_deref()
                .map(|w| format!(" — {w}"))
                .unwrap_or_default(),
            if self.technical.is_empty() {
                String::new()
            } else {
                format!(" ({} technical)", self.technical.len())
            }
        )
    }
}

/// The whole verify verdict list for one file. `Debug` reads as its lines do
/// (manual below), never a DER dump, because assert failures reach a human.
#[derive(Clone)]
pub struct VerdictList {
    pub lines: Vec<VerdictLine>,
    /// Document-level notes that are not a signature verdict (unsigned doc,
    /// validation data present…) as plain sentences.
    pub notes: Vec<String>,
    /// The DOCUMENT's own refusal, when the verifier answered `Err` for a
    /// reason that belongs to no single signature (06-N-3): a certification
    /// broken by what was signed after it, a document time-stamp followed by
    /// changes, unreadable validation data. It is the screen's first sentence
    /// — in the interface language, in red — and while it stands no line may
    /// read "Firma válida", however sound a signature is over its own bytes:
    /// the CLI already refuses these files with rc=1, and the window painted
    /// the same bytes green.
    pub document: Option<String>,
}

impl core::fmt::Debug for VerdictList {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_list().entries(self.lines.iter()).finish()
    }
}

/// One signing job, the owned form of everything the Picked screen decided:
/// the key, the effective choices, the document bytes, and where the answer
/// goes. It crosses to the worker thread whole (all fields owned), which is
/// what makes "the window freezes while signing" impossible by construction.
pub struct SignJob {
    pub key: KeySource,
    pub chosen_format: String,
    pub digest: openfirma_core::DigestAlg,
    /// The TSA url as the user typed it; empty means no time-stamp. Its
    /// provider is built (and refused) off the UI thread, inside the job.
    pub tsa_url: String,
    pub reason: Option<String>,
    pub content: Vec<u8>,
    pub path: PathBuf,
    pub out: PathBuf,
}

impl SignJob {
    /// A second owned copy of this job (A-3: the overwrite question rebuilds
    /// it onto a different destination). Cheap for store rows — the key is an
    /// `Arc`, no re-login; the document bytes are what they cost.
    pub fn clone_job(&self) -> SignJob {
        SignJob {
            key: self.key.clone_box(),
            chosen_format: self.chosen_format.clone(),
            digest: self.digest,
            tsa_url: self.tsa_url.clone(),
            reason: self.reason.clone(),
            content: self.content.clone(),
            path: self.path.clone(),
            out: self.out.clone(),
        }
    }
}

/// The result a signing worker sends back to the window. Owned bytes only:
/// it crosses an `std::mpsc` channel without borrowing anything the screen
/// holds.
pub enum SignOutcome {
    /// Written and synced at `output`; the Done screen shows this path.
    Done {
        signature: Vec<u8>,
        output: PathBuf,
        format_label: String,
        signer_display: String,
        /// 06-N-11 (review M-11): at least one time-stamp token was embedded
        /// WITHOUT its own signature being checked. This window has no TSA
        /// authority to check one against, so it says on screen what the
        /// terminal-only warning used to say alone: the stamp proves the time
        /// only if you trust who issued it.
        tsa_token_unchecked: bool,
    },
    /// A refusal worth a red line ("the password was wrong" is a retry
    /// reason, not a journey back to the drop zone): the Picked screen stays,
    /// its rows stay (M-4 keeps the picker where it was).
    Retryable { reason: ErrorReport },
    /// Anything else: the Failed screen, with this job's Picked screen as
    /// "Intentar de nuevo".
    Failed(ErrorReport),
}

/// The verify load a worker runs when an anchored document arrives (reading
/// the file and chaining certificates is instant locally, but a card-backed
/// anchor or a huge PDF must not stall a frame either).
pub struct LoadJob {
    pub path: PathBuf,
    pub bytes: Vec<u8>,
    /// The detached signature's original document, when one was found beside
    /// the `.csig` (A-4) — owned here so the worker needs no filesystem race.
    pub content: Option<Vec<u8>>,
    pub anchors: Vec<openfirma_core::CertificateHandle>,
}

/// What the window should do when its close button (or Alt-F4) fires. Three
/// answers, each with its own text (review 06 B-1: the old guard was dead
/// code wearing the wrong words — while a signature is being MADE the honest
/// question is "cancel it?", not "it isn't saved yet").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseDecision {
    /// Nothing is in flight or held unseen; close.
    Allow,
    /// A result nobody has seen stands behind the window (the Done state
    /// before its bytes were written — unreachable while the worker owns the
    /// bytes, kept honest for when a write path returns them).
    WarnUnsaved,
    /// The signing job is still running: closing now abandons a signature in
    /// progress. Say exactly that (B-1's wrong text was "not yet saved" over
    /// an already-written file).
    WarnBusy,
}

/// The close rule as a function (tested directly, not only through widgets),
/// given what the window currently holds: a job in flight (`busy`) and the
/// screen behind it.
pub fn close_decision(busy: bool, screen: &Screen) -> CloseDecision {
    if busy {
        return CloseDecision::WarnBusy;
    }
    match screen {
        Screen::Done { saved: false, .. } => CloseDecision::WarnUnsaved,
        _ => CloseDecision::Allow,
    }
}

/// The wizard's states, in the order of the happy path plus error/verify.
pub enum Screen {
    /// First screen: an empty drop zone.
    Idle,
    /// A file has been picked or dropped: its bytes are held, the format is
    /// detected and named, the certificate picker is open. `password_error`
    /// carries "contraseña incorrecta" under the field (M-4): a wrong
    /// password keeps this screen — rows, PIN-backed stores, all of it —
    /// exactly where it was.
    Picked {
        path: PathBuf,
        content: Vec<u8>,
        format: Format,
        chosen_format: String,
        catalog: CertCatalog,
        selected: Option<usize>,
        advanced: bool,
        /// TSA url from the advanced area; empty means B-B only.
        tsa_url: String,
        digest: openfirma_core::DigestAlg,
        reason: String,
        password_error: bool,
    },
    /// Signing in progress on a worker thread (A-1). The screen is shown with
    /// its spinner; every button the job could race is not rendered.
    Signing {
        /// The Picked screen parked while the worker holds the bytes — put
        /// back verbatim when the job answers, so nothing the user built is
        /// ever lost to a click.
        back: Box<Screen>,
    },
    /// A keystore is opening on the worker thread (06-N-10: loading a PKCS#11
    /// module and logging in is exactly the work A-1 put off the UI thread,
    /// and it used to run inside the frame — a card that takes seconds to
    /// answer froze the window). Same park shape as `Signing`, different
    /// sentence: the picker is untouched behind it.
    OpeningStore {
        /// The Picked screen parked while the store opens.
        back: Box<Screen>,
    },
    /// A signature is finished and held. This state cannot be left through
    /// the window's close button without an explicit decision; the bytes live
    /// here until they are saved for real or discarded on purpose.
    Done {
        path: PathBuf,
        output: PathBuf,
        content: Vec<u8>,
        signature: Vec<u8>,
        format_label: String,
        signer_display: String,
        saved: bool,
    },
    /// Verify mode: a file with signatures got its verdict lines.
    Verified {
        path: PathBuf,
        verdicts: VerdictList,
        /// Per-line "Ver detalles técnicos" open state (M-3: the old one was
        /// reset every frame and could never be read). One bool per line,
        /// indexed with the lines themselves.
        details_open: Vec<bool>,
    },
    /// A detached `.csig` whose original document the window needs before it
    /// can answer anything (A-4): found beside the signature automatically
    /// when the names agree; this screen asks when they do not.
    NeedsContent {
        signature_path: PathBuf,
        signature_bytes: Vec<u8>,
    },
    /// Any failure, from any state, with the plain/technical pair. It keeps
    /// whatever the user had (the picked file) so "Intentar de nuevo" can
    /// return to it instead of restarting from zero.
    Failed {
        error: ErrorReport,
        /// Where "Intentar de nuevo" goes; `None` means idle.
        back: Option<Box<Screen>>,
    },
}

impl Screen {
    pub fn is_done(&self) -> bool {
        matches!(self, Screen::Done { .. })
    }

    /// The Picked screen behind a Signing screen (the bytes the worker holds
    /// a copy of; the screen itself never mutates while it waits).
    pub fn signing_back(&self) -> Option<&Screen> {
        match self {
            Screen::Signing { back } => Some(back),
            Screen::OpeningStore { back } => Some(back),
            _ => None,
        }
    }

    /// Rebuild the screen "Intentar de nuevo" returns to. The expensive
    /// fields are owned and cloned; a Picked screen keeps its catalog rows —
    /// an opened store's PIN was spent once (A-6) and AutoFirma's retry keeps
    /// the card dialog open too; only the typed password is gone, which the
    /// user just got wrong anyway. A Done screen clones in full: its signature
    /// bytes *are* the result, and losing them would be the silent-loss
    /// failure this project bans (docs/adr/0006-gui-toolkit.md). Store rows
    /// keep working because their thunks are `Arc`-shared; a `.p12` row that
    /// had no password yet is dropped.
    pub fn restore(&self) -> Screen {
        match self {
            Screen::Idle | Screen::Signing { .. } | Screen::OpeningStore { .. } => Screen::Idle,
            Screen::Picked {
                path,
                content,
                format,
                chosen_format,
                catalog,
                advanced,
                tsa_url,
                digest,
                reason,
                ..
            } => Screen::Picked {
                path: path.clone(),
                content: content.clone(),
                format: *format,
                chosen_format: chosen_format.clone(),
                catalog: CertCatalog {
                    // rows backed by an opened store survive the retry (their
                    // Arcs are cheap and already logged in); pending .p12
                    // rows wait for their password again.
                    entries: catalog
                        .entries
                        .iter()
                        .filter(|e| e.source.is_some())
                        .map(|e| CertificateChoice {
                            display: e.display.clone(),
                            origin: e.origin.clone(),
                            issuer: e.issuer.clone(),
                            valid_until: e.valid_until.clone(),
                            badges: e.badges.clone(),
                            source: e.source.clone(),
                            pending_p12: None,
                        })
                        .collect(),
                    errors: Vec::new(),
                },
                selected: None,
                advanced: *advanced,
                tsa_url: tsa_url.clone(),
                digest: *digest,
                reason: reason.clone(),
                password_error: false,
            },
            Screen::Done {
                path,
                output,
                content,
                signature,
                format_label,
                signer_display,
                saved,
            } => Screen::Done {
                path: path.clone(),
                output: output.clone(),
                content: content.clone(),
                signature: signature.clone(),
                format_label: format_label.clone(),
                signer_display: signer_display.clone(),
                saved: *saved,
            },
            Screen::Verified { path, verdicts, .. } => Screen::Verified {
                path: path.clone(),
                verdicts: verdicts.clone(),
                details_open: vec![false; verdicts.lines.len()],
            },
            Screen::Failed { error, .. } => Screen::Failed {
                error: error.clone(),
                back: None,
            },
            Screen::NeedsContent {
                signature_path,
                signature_bytes,
            } => Screen::NeedsContent {
                signature_path: signature_path.clone(),
                signature_bytes: signature_bytes.clone(),
            },
        }
    }
}

/// CertificateChoice itself cannot derive Clone (the thunk is an Arc over a
/// closure), but cloning its fields is exact — the Arc makes it cheap and
/// thread-safe. `restore` inlines it; this is the rule's named home for tests.
pub fn shallow_clone(entries: &[CertificateChoice]) -> Vec<CertificateChoice> {
    entries
        .iter()
        .map(|e| CertificateChoice {
            display: e.display.clone(),
            origin: e.origin.clone(),
            issuer: e.issuer.clone(),
            valid_until: e.valid_until.clone(),
            badges: e.badges.clone(),
            source: e.source.clone(),
            pending_p12: e.pending_p12.clone(),
        })
        .collect()
}

/// The friendly name of the file for headings and buttons (never a raw path).
pub fn display_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

/// Formats the advanced-area TSA flag should expose for this kind of file and
/// chosen format. Review 06 M-11's fix: CAdES raises to B-T with a signature
/// time-stamp exactly like PAdES, so the field is offered for BOTH; XML (the
/// one shape whose dispatcher ignores a stamp) still shows nothing rather
/// than lie with an input that changes nothing.
pub fn tsa_available(chosen_format: &str) -> bool {
    matches!(
        chosen_format,
        "pades-b-b" | "pades-b-lt" | "pades-b-lta" | "cades-b-b"
    )
}

/// Whether the advanced TSA field is meaningful for this choice: a time-stamp
/// needs a URL; without one the level still signs at its own baseline.
pub fn effective_formats(format: Format, tsa_url: &str) -> Vec<(&'static str, bool)> {
    let have_tsa = !tsa_url.trim().is_empty();
    format
        .supported_formats()
        .iter()
        .map(|f| (*f, *f != "pades-b-lta" || have_tsa))
        .collect()
}

/// Where the signature file goes for the chosen format and input path: the
/// `workflow::Format::default_output` rule once more — one naming scheme per
/// frontend is a drift risk this avoids by calling the library.
pub fn output_path(format: Format, input: &Path) -> PathBuf {
    format.default_output(input)
}

/// The store descriptor a "add a keystore" line describes; an invalid
/// spelling returns the library's parse error, which says what to type.
pub fn parse_descriptor(text: &str) -> Result<StoreSpec, String> {
    StoreSpec::parse(text)
}

/// The worker channel payload the UI thread drains every frame. One type so
/// both slow paths (sign, verify) share one poll rule: at most one answer
/// per frame, never inside a UI closure.
pub enum WorkerReply {
    Sign(SignOutcome),
    Verify(Result<VerifiedAnswer, ErrorReport>),
    /// 06-N-10: an opened keystore, or the reason it refused, plus the PIN
    /// that worked so the cache keeps a PIN the store accepted.
    Store(OpenStoreOutcome),
}

/// What opening a keystore on the worker produced. The descriptor rides with
/// both arms: a failure is one line under that store's name in the picker,
/// never a screen of its own.
pub enum OpenStoreOutcome {
    /// The entries to add, and the PIN to remember — `Some` only when the
    /// store accepted it (a wrong PIN is never cached).
    Opened {
        descriptor: String,
        entries: Vec<crate::keystore_io::StoreEntry>,
        pin: Option<Zeroizing<String>>,
    },
    Failed {
        descriptor: String,
        report: ErrorReport,
    },
}

/// What the verify worker computed for the window. `Debug` is a sentence,
/// not a DER dump: assert failures on this type reach a human reading CI.
#[derive(Debug)]
pub struct VerifiedAnswer {
    pub path: PathBuf,
    pub verdicts: VerdictList,
}

/// The session-wide PIN cache (review 06 A-6: a card asked for its PIN per
/// document; AutoFirma logs in once and remembers the default store). Keyed
/// by descriptor so two different tokens never share a PIN; every stored copy
/// zeroes on drop like every other secret here. Sharing is an `Arc<Mutex<..>>`
/// because the picker builds key thunks that may need the PIN after the
/// screen moved on.
#[derive(Default, Clone)]
pub struct PinCache(Arc<Mutex<PinRows>>);

/// The rows behind the lock: (descriptor, PIN). Named so the type reads and
/// clippy stops counting its brackets.
type PinRows = Vec<(String, Zeroizing<String>)>;

impl PinCache {
    pub fn get(&self, descriptor: &str) -> Option<Zeroizing<String>> {
        self.0
            .lock()
            .ok()?
            .iter()
            .find(|(d, _)| d == descriptor)
            .map(|(_, p)| p.clone())
    }

    pub fn put(&self, descriptor: &str, pin: Zeroizing<String>) {
        if let Ok(mut guard) = self.0.lock() {
            guard.retain(|(d, _)| d != descriptor);
            guard.push((descriptor.to_string(), pin));
        }
    }
}

#[cfg(test)]
mod descriptor_tests {
    use super::parse_descriptor;

    #[test]
    fn the_form_parses_through_the_library_rule() {
        // The add-a-keystore field and `openfirma keystores list` parse the
        // same text with the same function, so a spelling accepted by one is
        // accepted by the other. An explicit nss database never depends on
        // this machine (a bare `nss` wants $HOME/.pki/nssdb, which a Windows
        // CI runner has no reason to hold); an empty pkcs11 module fails
        // everywhere with the same sentence telling what to type.
        assert_eq!(
            parse_descriptor("nss:sql:/tmp/opencode/keystores/nssdb")
                .unwrap()
                .descriptor(),
            "nss:sql:/tmp/opencode/keystores/nssdb"
        );
        assert!(parse_descriptor("pkcs11:").is_err());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closing_a_saved_or_idle_window_is_allowed() {
        assert_eq!(close_decision(false, &Screen::Idle), CloseDecision::Allow);
        let done = Screen::Done {
            path: PathBuf::from("doc.pdf"),
            output: PathBuf::from("doc.signed.pdf"),
            content: vec![1],
            signature: vec![2],
            format_label: "PAdES-B-B".into(),
            signer_display: "ANA".into(),
            saved: true,
        };
        assert_eq!(close_decision(false, &done), CloseDecision::Allow);
    }

    #[test]
    fn closing_over_an_unsaved_result_warns() {
        let done = Screen::Done {
            path: PathBuf::from("doc.pdf"),
            output: PathBuf::from("otro.pdf"),
            content: vec![1],
            signature: vec![2, 3],
            format_label: "CAdES-B-B".into(),
            signer_display: "ANA".into(),
            saved: false,
        };
        assert_eq!(close_decision(false, &done), CloseDecision::WarnUnsaved);
    }

    /// B-1's fix as a rule: the busy answer is its own variant with its own
    /// text; "a job in flight" outranks every screen because while a worker
    /// holds the bytes NO screen is authoritative.
    #[test]
    fn closing_mid_signing_warns_busy_over_anything() {
        assert_eq!(close_decision(true, &Screen::Idle), CloseDecision::WarnBusy);
        let done = Screen::Done {
            path: PathBuf::from("doc.pdf"),
            output: PathBuf::from("doc.signed.pdf"),
            content: vec![1],
            signature: vec![2],
            format_label: "PAdES-B-B".into(),
            signer_display: "ANA".into(),
            saved: true,
        };
        // even over a written result: what runs could still write somewhere.
        assert_eq!(close_decision(true, &done), CloseDecision::WarnBusy);
    }

    #[test]
    fn a_failure_remembers_where_it_came_from() {
        let back = Screen::Picked {
            path: PathBuf::from("doc.pdf"),
            content: b"%PDF-1.4".to_vec(),
            format: Format::Pdf,
            chosen_format: "pades-b-b".into(),
            catalog: CertCatalog::default(),
            selected: None,
            advanced: false,
            tsa_url: String::new(),
            digest: openfirma_core::DigestAlg::Sha256,
            reason: String::new(),
            password_error: false,
        };
        let failed = Screen::Failed {
            error: ErrorReport {
                plain: "x".into(),
                technical: "y".into(),
            },
            back: Some(Box::new(back)),
        };
        match &failed {
            Screen::Failed { back, .. } => match back.as_deref() {
                Some(Screen::Picked { path, .. }) => assert_eq!(path, Path::new("doc.pdf")),
                _ => panic!("back must be the Picked screen"),
            },
            _ => unreachable!(),
        }
    }

    /// A-6 through the state machine: restoring a Picked screen after a
    /// wrong password KEEPS its logged-in store rows; only the pending .p12
    /// (whose password was just typed wrong) drops out. AutoFirma's retry
    /// keeps the card dialog open too — re-opening a token per typo spends
    /// PIN tries on real cards.
    #[test]
    fn restoring_keeps_the_opened_stores() {
        let p12 = Arc::new(std::path::Path::new("cert.p12").to_path_buf());
        let thunk_p12 = Arc::clone(&p12);
        let store_row = CertificateChoice {
            display: "ANA".into(),
            origin: "pkcs11:/m.so".into(),
            issuer: None,
            valid_until: None,
            badges: Vec::new(),
            source: Some(Arc::new(move || KeySource::P12 {
                path: thunk_p12.as_ref().clone(),
                password: Zeroizing::new(String::new()),
                alias: None,
                display: "ANA".into(),
            })),
            pending_p12: None,
        };
        let pending_row = CertificateChoice {
            display: "otro.p12…".into(),
            origin: "otro.p12".into(),
            issuer: None,
            valid_until: None,
            badges: Vec::new(),
            source: None,
            pending_p12: Some(PathBuf::from("otro.p12")),
        };
        let picked = Screen::Picked {
            path: PathBuf::from("doc.pdf"),
            content: b"%PDF-1.4".to_vec(),
            format: Format::Pdf,
            chosen_format: "pades-b-b".into(),
            catalog: CertCatalog {
                entries: vec![store_row, pending_row],
                errors: Vec::new(),
            },
            selected: Some(0),
            advanced: false,
            tsa_url: String::new(),
            digest: openfirma_core::DigestAlg::Sha256,
            reason: String::new(),
            password_error: true,
        };
        match picked.restore() {
            Screen::Picked { catalog, .. } => {
                assert_eq!(catalog.entries.len(), 1, "the store row survives");
                assert_eq!(catalog.entries[0].display, "ANA");
                assert!(
                    !catalog.entries[0]
                        .badges
                        .iter()
                        .any(|b| b.contains("wrong"))
                );
            }
            _ => panic!("a Picked restores to a Picked"),
        }
    }

    /// The PIN cache keys per descriptor and zeroes between: one PIN per
    /// session per card (A-6), no shared secret across different tokens.
    #[test]
    fn the_pin_cache_remembers_per_descriptor() {
        let cache = PinCache::default();
        assert!(cache.get("pkcs11:/a.so").is_none());
        cache.put("pkcs11:/a.so", Zeroizing::new("1234".into()));
        cache.put("pkcs11:/b.so", Zeroizing::new("9999".into()));
        assert_eq!(
            cache.get("pkcs11:/a.so").map(|p| p.to_string()),
            Some("1234".to_string())
        );
        // a second PIN for the same card replaces, never joins.
        cache.put("pkcs11:/a.so", Zeroizing::new("4321".into()));
        assert_eq!(
            cache.get("pkcs11:/a.so").map(|p| p.to_string()),
            Some("4321".to_string())
        );
        assert_eq!(
            cache.get("pkcs11:/b.so").map(|p| p.to_string()),
            Some("9999".to_string())
        );
    }

    #[test]
    fn advanced_formats_depend_on_the_tsa_url() {
        let pdf = Format::Pdf;
        let no_tsa = effective_formats(pdf, "");
        assert_eq!(no_tsa.iter().filter(|(_, ok)| *ok).count(), 2); // lta greyed
        let with_tsa = effective_formats(pdf, "http://tsa.example/tsa");
        assert!(with_tsa.iter().all(|(_, ok)| *ok));
        // a txt document has exactly one shape and no TSA need
        assert_eq!(
            effective_formats(Format::Data, ""),
            vec![("cades-b-b", true)]
        );
    }

    /// M-11: the TSA field belongs to CAdES too (the dispatcher stamps it),
    /// and stays away from XAdES (whose dispatcher would ignore it).
    #[test]
    fn the_tsa_field_follows_what_the_dispatcher_honours() {
        assert!(tsa_available("cades-b-b"));
        assert!(tsa_available("pades-b-b"));
        assert!(!tsa_available("xades-b-b"));
    }

    #[test]
    fn the_output_path_is_the_libraries_rule() {
        // One naming scheme for both frontends, including its collision-free
        // shape (review 06, A-3): a dotted name keeps every extension.
        let p = output_path(Format::Pdf, Path::new("/a/contrato.pdf"));
        assert_eq!(p.file_name().unwrap(), "contrato.pdf.signed.pdf");
    }

    #[test]
    fn display_names_never_leak_directories() {
        assert_eq!(display_name(Path::new("/x/y/doc.pdf")), "doc.pdf");
        assert_eq!(display_name(Path::new("doc.txt")), "doc.txt");
    }
}
