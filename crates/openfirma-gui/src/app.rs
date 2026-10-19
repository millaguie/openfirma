//! The window itself: egui widgets over [`crate::wizard`]'s state machine,
//! and nothing else. Every action here is a button calling into `wizard`,
//! `signing`, `verdicts` or `keystore_io`; no decision is made in this file
//! (the brief's shape rule: the GUI never reimplements what the library
//! decides — if it looks like one, move it to openfirma-core and let both
//! frontends call it).
//!
//! The verify path is a deliberate deviation from AutoFirma recorded in
//! docs/adr/0006-gui-toolkit.md: its validation tab wants a *second*, signature-only file an
//! ordinary citizen never has (an exported `.csig`), so verifying one's own
//! document means exporting something first. openfirma verifies the document
//! itself — drop it, read the verdicts. A PDF that already holds signatures
//! therefore opens as a verification task; a file whose name says it already
//! IS a signature (a `.csig`, review 06 B-3) is never taken for a document to
//! sign: dropping one asks whether its own signature should be checked, and
//! the co-signing omission stays recorded in docs/adr/0006-gui-toolkit.md.
//!
//! Nothing slow runs on this thread (review 06 A-1): signing (card access,
//! TSA) and anchored verification go to one worker thread behind a channel;
//! while it runs the window paints its spinner screen every frame. Exactly
//! one job in flight is enforced by state, not by luck.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use egui::{RichText, Ui};
use zeroize::Zeroizing;

use crate::errors;
use crate::keystore_io;
use crate::signing;
use crate::strings::Tr;
use crate::wizard::{
    CertCatalog, CertificateChoice, CloseDecision, ErrorReport, KeySource, LoadJob, PinCache,
    Screen, SignJob, SignOutcome, VerdictLine, VerdictStatus, WorkerReply, close_decision,
    display_name, effective_formats, output_path, tsa_available,
};
use openfirma_core::workflow::{Format, StoreSpec};

/// The window state. Beyond the screen itself it holds only raw text fields
/// (paths, passwords, descriptors) owned by whichever input owns them; every
/// state *decision* lives in `wizard`. Secrets live in `Zeroizing` from the
/// frame they arrive in (M-8): the egui widgets that edit them are given a
/// plain mirror only for the frame's duration and their stale per-widget
/// text state is deleted when the screen leaves.
pub struct App {
    tr: Tr,
    screen: Screen,
    path_input: String,
    /// Password for a `.p12` row waiting on one (the catalog holds at most
    /// one pending `.p12`: the picker's own button adds it and replaces any
    /// earlier pending row). Zeroized between uses; see `mirror`/`sync`.
    password_input: Arc<std::sync::Mutex<Zeroizing<String>>>,
    pin_input: Arc<std::sync::Mutex<Zeroizing<String>>>,
    descriptor_input: String,
    show_add_store: bool,
    show_details: bool,
    /// The close-guard question is open (its variant says which question).
    close_question: Option<CloseDecision>,
    /// Actions rendering asked for but could not take while borrowing the
    /// screen; run at the end of every frame. Dialogs and keystores are
    /// instant-by-design OS answers; only [`Deferred::OpenStore`] touches a
    /// card, and it goes to the worker like everything else slow.
    deferred: Vec<Deferred>,
    /// A second screen slot for one frame (the "take it out, put a copy back"
    /// pattern of immediate-mode state machines): render_* moves `screen` in
    /// here so an error path can replace it without fighting the borrow
    /// checker inside UI closures.
    scratch: Screen,
    /// One sentence shown on the idle screen while a question waits for its
    /// answer (today: the ask-the-anchor note of the verify path). It exists
    /// so "no sé en quién confiar" never looks like a dead drop zone.
    pending_note: Option<String>,
    /// The worker thread's answer channel (A-1): `Some` while one job runs,
    /// taken the frame its answer is drained. Signing and verifying share it
    /// — one job in flight is the whole race story of the old double click.
    worker_rx: Option<std::sync::mpsc::Receiver<WorkerReply>>,
    /// The session's spent PINs (A-6): one card, one login, any number of
    /// documents. Kept on App so "sign another" keeps them; dropped between
    /// processes like AutoFirma's own per-run login.
    pins: PinCache,
    /// `verify_verb` pressed since its dialog was answered (B-3): the next
    /// picked file without signatures gets the "no tiene ninguna firma" line
    /// instead of the sign screen — both verbs can now be told apart.
    verify_intent: bool,
    /// Dialog fixtures for this App (tests set it via [`App::with_dialogs`];
    /// production keeps the default, which runs real rfd dialogs).
    dialogs: Dialogs,
}

/// An action collected during rendering and executed after it (the borrow
/// shape: `render_*` moved `self.screen` into UI closures, so a `&mut self`
/// keystore call cannot nest inside them).
enum Deferred {
    OpenStore(String),
    /// Ask the OS for the trust-anchor file of the verify path; its answer
    /// finishes the load that started it.
    AskAnchor(PathBuf),
    /// Ask the OS for the ORIGINAL document of a detached `.csig` (A-4).
    AskContent(PathBuf),
    /// The chosen output already exists: ask where to write before truncating
    /// anybody's data (A-3's GUI half — refuse silently is not an option).
    /// The job rides on the parked Picked screen.
    AskOverwrite(Screen),
    /// The overwrite question was answered by a save dialog whose name the OS
    /// confirmed: re-run the signing job onto that destination.
    SignTo(Screen, PathBuf),
}

/// The OS dialogs. In kittest (`gui_test = true`, set only by the windowless
/// tests) they resolve to a fixed fixture path instead: a test that blocks on
/// a real GTK dialog is not a test, and everything the wizard does *after*
/// "the user picked this path" is identical whichever way the path arrived.
#[derive(Default)]
pub struct Dialogs {
    pub gui_test: bool,
    /// What an open dialog answers in kittest mode (set by each test).
    pub fixture_open: Option<PathBuf>,
    pub fixture_save: Option<PathBuf>,
}

impl Dialogs {
    fn open_file(&self, title: &str) -> Option<PathBuf> {
        if self.gui_test {
            return self.fixture_open.clone();
        }
        rfd::FileDialog::new().set_title(title).pick_file()
    }

    fn save_file(&self, title: &str, suggestion: &Path) -> Option<PathBuf> {
        if self.gui_test {
            return self.fixture_save.clone();
        }
        rfd::FileDialog::new()
            .set_title(title)
            .set_file_name(file_name(suggestion))
            .save_file()
    }
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

impl Default for App {
    /// The state at startup — the same one `eframe` builds through `new`.
    fn default() -> Self {
        App {
            tr: Tr::for_locale(),
            screen: Screen::Idle,
            path_input: String::new(),
            password_input: Arc::new(std::sync::Mutex::new(Zeroizing::new(String::new()))),
            pin_input: Arc::new(std::sync::Mutex::new(Zeroizing::new(String::new()))),
            descriptor_input: String::new(),
            show_add_store: false,
            show_details: false,
            close_question: None,
            deferred: Vec::new(),
            scratch: Screen::Idle,
            dialogs: Dialogs::default(),
            pending_note: None,
            worker_rx: None,
            pins: PinCache::default(),
            verify_intent: false,
        }
    }
}

impl App {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        App::default()
    }

    // ---------------------------------------------------------------- secrets

    /// The frame's mirror of a secret field: egui edits the copy it is shown,
    /// `sync_secret` moves the edit back into the Zeroizing at the end of
    /// the same frame, and [`App::forget_secret`] wipes both the Zeroizing
    /// and the widget's own remembered text (egui keeps a copy of every
    /// TextEdit's contents in its per-widget state — M-8 measured it holding
    /// a PIN after the screen moved on; deleting the state is the only
    /// answer immediate mode gives).
    fn mirror_secret(field: &Arc<std::sync::Mutex<Zeroizing<String>>>, out: &mut String) {
        if let Ok(guard) = field.lock() {
            out.clear();
            out.push_str(&guard);
        }
    }

    fn sync_secret(field: &Arc<std::sync::Mutex<Zeroizing<String>>>, edited: &str) {
        if let Ok(mut guard) = field.lock() {
            *guard = Zeroizing::new(edited.to_string());
        }
    }

    fn forget_secret(
        ui: &egui::Ui,
        id: egui::Id,
        field: &Arc<std::sync::Mutex<Zeroizing<String>>>,
    ) {
        if let Ok(mut guard) = field.lock() {
            *guard = Zeroizing::new(String::new());
        }
        // Wipe the widget's own remembered text: the state is keyed by this
        // id, and removing it deletes the buffer egui keeps per TextEdit —
        // an empty field painted under the same id would only mask it.
        ui.data_mut(|d| d.remove::<egui::widgets::text_edit::TextEditState>(id));
    }

    // ---------------------------------------------------------------- loading

    /// The one door every file enters through: read, detect, then either the
    /// verdict path (the bytes already carry signatures) or the signing flow.
    /// Same detection rule both frontends share (`workflow::Format`); for PDFs
    /// "already signed?" comes from the same inspector `inspect`/`verify` run.
    fn load_path(&mut self, path: PathBuf) {
        self.path_input = path.display().to_string();
        let outcome = (|| -> openfirma_core::Result<Loaded> {
            let bytes = keystore_io::read_file(&path)?;
            // A-3/B-3 through the shared rule: a file NAMED like an openfirma
            // output is that output — its signature is inside it. Verifying
            // it is what "did this sign correctly?" means; signing a signature
            // is never anything real, and AutoFirma's viewer opens one to
            // show it, not to re-sign it.
            if openfirma_core::workflow::is_signed_output(&path) {
                return Ok(Loaded::Verify(bytes));
            }
            let format = Format::detect(&bytes);
            if format == Format::Pdf && pades_signature_count(&bytes) > 0 {
                return Ok(Loaded::Verify(bytes));
            }
            if format != Format::Pdf && looks_like_cms(&bytes) {
                // A-4: a detached CAdES needs its original to answer anything.
                // The GUI wrote both files beside each other with names that
                // agree (`foto.jpg.csig` ← `foto.jpg`), so the search is by
                // the library's own naming rule, not a guess at the user's;
                // when it misses, the wizard asks instead of failing (the one
                // dialog AutoFirma's validation tab also never shows).
                return Ok(Loaded::Detached(bytes));
            }
            Ok(Loaded::Sign(bytes, format))
        })();
        match outcome {
            Ok(Loaded::Verify(bytes)) => self.verify_file(path, bytes),
            Ok(Loaded::Detached(bytes)) => {
                if let Some(found) = companion_of(&path) {
                    self.verify_file_with_content(path, bytes, Some(found));
                } else {
                    // Ask rather than fail: the document exists almost surely
                    // (the signature came from one), it just does not live
                    // under the name our rule would have written.
                    self.screen = Screen::NeedsContent {
                        signature_path: path,
                        signature_bytes: bytes,
                    };
                }
            }
            Ok(Loaded::Sign(bytes, format)) => {
                self.pending_note = None;
                self.screen = Screen::Picked {
                    path,
                    content: bytes,
                    format,
                    chosen_format: format.default_signature_format().to_string(),
                    catalog: self.reusable_catalog(),
                    selected: None,
                    advanced: false,
                    tsa_url: String::new(),
                    digest: openfirma_core::DigestAlg::Sha256,
                    reason: String::new(),
                    password_error: false,
                };
            }
            Err(e) => self.fail(errors::report(&e, &self.tr), path),
        }
    }

    /// The store rows a NEW document may reuse: every row backed by a store
    /// this session already opened and logged into (A-6's second half — the
    /// old code emptied the whole catalog per document and asked for the PIN
    /// again; AutoFirma remembers its default keystore across files). A `.p12`
    /// whose password was typed lives inside its thunk's Zeroizing and is
    /// reused too: one file dialog, one password, as many documents as wanted.
    fn reusable_catalog(&self) -> CertCatalog {
        let mut catalog = CertCatalog::default();
        // The rows behind a Signing screen count too: the park happens before
        // the worker's answer, so "sign another" after a failure must not ask
        // for a PIN this session already paid.
        let old = match &self.screen {
            Screen::Picked { catalog, .. } => catalog,
            Screen::Signing { back } => match back.as_ref() {
                Screen::Picked { catalog, .. } => catalog,
                _ => return catalog,
            },
            _ => return catalog,
        };
        catalog
            .entries
            .extend(
                old.entries
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
                    }),
            );
        catalog
    }

    /// The verify half of `load_path`, including the ask-for-an-anchor step:
    /// with no trust anchors configured there is nothing to chain to, and
    /// inventing one would be exactly the unfounded success this project
    /// bans — so the screen says what it needs and opens one file picker.
    fn verify_file(&mut self, path: PathBuf, bytes: Vec<u8>) {
        let content = companion_of(&path);
        // A `.csig` IS a detached signature (the library's own name for one),
        // so with no original beside it there is nothing to verify against:
        // ask which document was signed — the ask screen — instead of handing
        // the verifier the signature as its own content, which is what made
        // the window call its own output manipulated (round 2, 06-N-2).
        if content.is_none() && detached_by_name(&path) {
            self.screen = Screen::NeedsContent {
                signature_path: path,
                signature_bytes: bytes,
            };
            return;
        }
        self.verify_file_with_content(path, bytes, content);
    }

    /// The verify door with the detached document known (`content_path`).
    fn verify_file_with_content(
        &mut self,
        path: PathBuf,
        bytes: Vec<u8>,
        content_path: Option<PathBuf>,
    ) {
        let anchors = openfirma_core::workflow::default_trust_anchors();
        if anchors.is_empty() {
            // The ask-the-user step (docs/adr/0006-gui-toolkit.md): "who do you trust?" is one
            // file picker, nothing more clever, and the reason shows on the
            // drop screen while it waits for the pick. Declining leaves the
            // zone where it was — a half-finished verify is not an error.
            self.pending_note = Some(format!(
                "{} {}",
                self.tr.no_trust_anchors, self.tr.anchor_hint
            ));
            self.deferred.push(Deferred::AskAnchor(path));
            return;
        }
        // B-5: anchors that cannot be read are the user's configuration
        // failing out loud — every broken file is named with its reason in
        // the note while a valid one still verifies. All-broken falls back to
        // the ask, because choosing works when reading did not.
        let mut certs = Vec::new();
        let mut notes: Vec<String> = Vec::new();
        for p in &anchors {
            match openfirma_core::workflow::load_trust_anchors(p) {
                Ok(list) => certs.extend(list),
                Err(e) => notes.push(format!("{} {}", self.tr.fail_anchor_read, e)),
            }
        }
        if certs.is_empty() && !notes.is_empty() {
            self.pending_note = Some(notes.join(" "));
            self.deferred.push(Deferred::AskAnchor(path));
            return;
        }
        let content = match content_path {
            Some(p) => match keystore_io::read_file(&p) {
                Ok(b) => Some(b),
                Err(e) => {
                    self.fail(errors::report(&e, &self.tr), path);
                    return;
                }
            },
            None => None,
        };
        if certs.is_empty() {
            // No anchors at all AND nothing broken to name: the ask state.
            self.pending_note = Some(format!(
                "{} {}",
                self.tr.no_trust_anchors, self.tr.anchor_hint
            ));
            self.deferred.push(Deferred::AskAnchor(path));
            return;
        }
        if !notes.is_empty() {
            self.pending_note = Some(notes.join(" "));
        }
        // A-1: the whole verify (read is done, but chain work on a big PDF
        // or a slow disk must not stall a frame) goes to the worker.
        self.start_verify(LoadJob {
            path,
            bytes,
            content,
            anchors: certs,
        });
    }

    fn finish_anchor(&mut self, path: PathBuf, anchor: Option<PathBuf>) {
        let Some(anchor) = anchor else { return }; // declined: stay idle
        match openfirma_core::workflow::load_trust_anchors(&anchor) {
            Ok(certs) => {
                // Reload the file (it may have changed between dialogs — one
                // read is cheap and stale verdicts are not).
                match keystore_io::read_file(&path) {
                    Ok(bytes) => {
                        let content = companion_of(&path);
                        self.start_verify(LoadJob {
                            path,
                            bytes,
                            content: content.as_deref().and_then(companion_of_ok),
                            anchors: certs,
                        });
                    }
                    Err(e) => self.fail(errors::report(&e, &self.tr), path),
                }
            }
            Err(msg) => self.fail(
                errors::report(&openfirma_core::Error::Other(msg.clone()), &self.tr),
                path,
            ),
        }
    }

    fn fail(&mut self, error: ErrorReport, path: PathBuf) {
        // The file the user dropped stays known through `path`: a Failed
        // screen made from a load has no back-screen to return to (the load
        // never produced one), so it drops back to the drop zone with the
        // path still typed in — "Intentar de nuevo" is re-pressing Enter.
        let _ = path;
        self.screen = Screen::Failed { error, back: None };
    }

    // ---------------------------------------------------------------- workers

    /// The one job in flight (A-1): start signing on a worker thread and park
    /// the Picked screen untouched until the answer arrives. `std::thread` +
    /// `mpsc` is the whole design — no async runtime, no dependency: eframe
    /// wakes itself for every input event, so a short repaint request when
    /// the job starts carries the spinner and the drained answer. The guard
    /// is what mashing a button can never get past: one worker per slot, so
    /// two clicks are one signature (the review's frozen double click had no
    /// such rule at all).
    fn start_sign(&mut self, job: SignJob) {
        // Debug builds shout (the guard is a BUG detector for future callers;
        // no production path reaches it twice — each one checks the park
        // before starting); release builds enforce the rule quietly, because
        // "one job per slot" is a guarantee to the user either way.
        debug_assert!(
            self.worker_rx.is_none(),
            "two signing jobs must never share the one slot (A-1)"
        );
        if self.worker_rx.is_some() {
            return; // one job in flight — the second click has nowhere to go
        }
        let tr = self.tr.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let back = Box::new(std::mem::replace(&mut self.screen, Screen::Idle));
        std::thread::spawn(move || {
            let outcome = run_sign_job(job, &tr);
            // A lost receiver means the window closed mid-signature: the job
            // dies with its thread and nothing was promised to anybody.
            let _ = tx.send(WorkerReply::Sign(outcome));
        });
        self.worker_rx = Some(rx);
        self.screen = Screen::Signing { back };
    }

    fn start_verify(&mut self, job: LoadJob) {
        debug_assert!(
            self.worker_rx.is_none(),
            "two verify jobs must never share the one slot (A-1)"
        );
        if self.worker_rx.is_some() {
            return; // one job in flight, same rule as signing
        }
        let tr = self.tr.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let answer = run_verify_job(job, &tr);
            let _ = tx.send(WorkerReply::Verify(answer));
        });
        self.worker_rx = Some(rx);
    }

    /// Drain the worker without blocking: at most one answer per frame, and
    /// never while a UI closure borrows the screen (this runs between panels).
    fn poll_worker(&mut self) {
        let Some(rx) = &self.worker_rx else { return };
        let Ok(reply) = rx.try_recv() else { return };
        self.worker_rx = None;
        match reply {
            WorkerReply::Sign(SignOutcome::Done {
                signature,
                output,
                format_label,
                signer_display,
            }) => {
                // The Picked screen was parked at start_sign; the Done screen
                // never needs it again (the bytes are its own now).
                let path = match &self.screen {
                    Screen::Signing { back } => match back.as_ref() {
                        Screen::Picked { path, .. } => path.clone(),
                        other => other.dropped_path().unwrap_or_else(|| output.clone()),
                    },
                    _ => output.clone(),
                };
                let content = match &self.screen {
                    Screen::Signing { back } => match back.as_ref() {
                        Screen::Picked { content, .. } => content.clone(),
                        _ => Vec::new(),
                    },
                    _ => Vec::new(),
                };
                self.screen = Screen::Done {
                    path,
                    output,
                    content,
                    signature,
                    format_label,
                    signer_display,
                    saved: true,
                };
            }
            WorkerReply::Sign(SignOutcome::Retryable { reason }) => {
                let back = match std::mem::replace(&mut self.screen, Screen::Idle) {
                    Screen::Signing { back } => *back,
                    other => other,
                };
                // M-4: the wrong password stays on the same screen, rows and
                // all, with its sentence under the field.
                let mut back = back;
                if let Screen::Picked { password_error, .. } = &mut back {
                    *password_error = errors::is_wrong_password(&reason);
                }
                if errors::is_wrong_password(&reason) {
                    self.screen = back;
                } else {
                    // Another refusal with the picker still intact: the Failed
                    // screen keeps it as "Intentar de nuevo".
                    self.screen = Screen::Failed {
                        error: reason,
                        back: Some(Box::new(back)),
                    };
                }
            }
            WorkerReply::Sign(SignOutcome::Failed(report)) => {
                // The Picked screen's catalog is worth keeping through a hard
                // failure too: it cost PINs to build. A transient park behind
                // it (a spinner or an idle placeholder — screens "Intentar de
                // nuevo" must not restore) drops to the drop zone instead.
                let back = match std::mem::replace(&mut self.screen, Screen::Idle) {
                    Screen::Signing { back } => match *back {
                        s @ (Screen::Picked { .. } | Screen::Done { .. }) => Some(Box::new(s)),
                        _ => None,
                    },
                    _ => None,
                };
                // The Picked screen's catalog is worth keeping through a hard
                // failure too: it cost PINs to build.
                self.screen = Screen::Failed {
                    error: report,
                    back,
                };
            }
            WorkerReply::Verify(Ok(answer)) => {
                let n = answer.verdicts.lines.len();
                self.screen = Screen::Verified {
                    path: answer.path,
                    verdicts: answer.verdicts,
                    details_open: vec![false; n],
                };
            }
            WorkerReply::Verify(Err(report)) => {
                self.screen = Screen::Failed {
                    error: report,
                    back: None,
                }
            }
        }
    }

    // -------------------------------------------------------------------- idle

    fn render_idle(&mut self, ui: &mut Ui) {
        let tr = &self.tr;
        if let Some(note) = self.pending_note.clone() {
            // M-7: the theme's own warning colour — the hand-picked amber was
            // 3.7:1 on the dark background the app inherits from the desktop.
            ui.colored_label(ui.visuals().warn_fg_color, note);
        }
        let mut open_dialog = false;
        let hovering = !ui.ctx().input(|i| i.raw.hovered_files.is_empty());
        ui.vertical_centered(|ui| {
            ui.add_space(36.0);
            ui.label(RichText::new(tr.drop_here.clone()).heading());
            ui.weak(tr.drop_hint.clone());
            ui.add_space(20.0);
            // The drop zone doubles as the file button: egui's drag-and-drop
            // fires for the whole window (read_dropped_file), and this frame
            // is where "no se ve nada que pulsar" gets answered. The glyph is
            // plain text — M-7 measured ⤓ rendering as a tofu box in the
            // shipped font, which tells the user nothing they cannot read.
            let label = tr.browse.clone();
            let mut button = egui::Button::new(RichText::new(label).size(22.0)).corner_radius(8.0);
            if hovering {
                // M-1: the hover now only HIGHLIGHTS; loading waits for the
                // actual drop, which is what AutoFirma's DropTarget does too.
                button = button.fill(ui.visuals().selection.bg_fill.gamma_multiply(0.6));
            }
            if ui
                .add_sized(
                    [(ui.available_width() - 60.0).clamp(360.0, 560.0), 120.0],
                    button,
                )
                .clicked()
            {
                open_dialog = true;
            }
        });
        ui.add_space(16.0);
        let mut path_to_load: Option<PathBuf> = None;
        // B-7's door through the keyboard too: an argument at startup loads,
        // and this box gives every other path its Enter. A clipboard-paste
        // works because eframe ships with `clipboard` (A-2).
        ui.horizontal(|ui| {
            let width = (ui.available_width() - 220.0).max(240.0);
            let resp = ui.add_sized(
                [width, 28.0],
                egui::TextEdit::singleline(&mut self.path_input).hint_text(tr.paste_path.clone()),
            );
            if ui.button(tr.browse.clone()).clicked() {
                open_dialog = true;
            }
            let entered = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            if (entered || resp.clicked()) && !self.path_input.trim().is_empty() {
                path_to_load = Some(PathBuf::from(self.path_input.trim()));
            }
        });
        // One drop zone, two verbs: the button exists for people hunting for
        // "verificar", and it does the same honest thing — load, let detection
        // answer. A document that already holds signatures gets verdicts; one
        // without goes on to be signed (ADR-0006: one job per screen). The
        // verify verb sets `verify_intent`: picking an unsigned document from
        // there now says "no tiene ninguna firma" instead of silently sliding
        // into the sign flow (B-3's two verbs that were secretly one).
        if ui.button(tr.verify_verb.clone()).clicked() {
            open_dialog = true;
            self.verify_intent = true;
        }
        if open_dialog {
            let title = tr.dialog_open_file.clone();
            let path = self.open_file(&title);
            if let Some(path) = path {
                let intent = std::mem::take(&mut self.verify_intent);
                self.load_path_with_intent(path, intent);
            }
        }
        if let Some(path) = path_to_load {
            let intent = std::mem::take(&mut self.verify_intent);
            self.load_path_with_intent(path, intent);
        }
    }

    // ------------------------------------------------------------- dialog seams

    /// Open-dialog indirection so kittest swaps in fixtures (the real one is
    /// rfd; see [`Dialogs`]). A test replaces both at once with
    /// [`App::with_dialogs`].
    fn open_file(&self, title: &str) -> Option<PathBuf> {
        self.dialogs.open_file(title)
    }

    fn save_file(&self, title: &str, suggestion: &Path) -> Option<PathBuf> {
        self.dialogs.save_file(title, suggestion)
    }

    /// The headless seam: tests replace the dialogs with fixtures (ADR-0006:
    /// dialogs are OS furniture, not state — only their answers matter to the
    /// wizard, and a test supplies answers without windows).
    pub fn with_dialogs(&mut self, dialogs: Dialogs) {
        self.dialogs = dialogs;
    }

    // ------------------------------------------------------------- test seams
    //
    // The windowless tests (tests/ui.rs) drive the *same* methods the widgets
    // call; these accessors only expose what a click would otherwise trigger.
    // Nothing here changes behavior, so no production path can depend on it.

    /// Fresh strings for a rebuilt context (the kittest harness creates its
    /// own `CreationContext`; production builds the App once from `main`'s).
    pub fn reinit_for_test(&mut self, _cc: &eframe::CreationContext<'_>) {
        self.tr = Tr::es();
    }

    /// Enter a file by the one door every input uses (drag, button, Enter).
    pub fn load_path_for_test(&mut self, path: PathBuf) {
        self.load_path_with_intent(path, false);
    }

    /// The `Exec=%f` line of the .desktop registration, and any plain
    /// `openfirma-gui <file>`: the named document arrives exactly as a drop
    /// would — same preview, same unsaved-result guard.
    pub fn load_path_from_cli(&mut self, path: PathBuf) {
        self.load_dropped(path);
    }

    pub fn dialogs_for_test(&mut self) -> &mut Dialogs {
        &mut self.dialogs
    }

    pub fn pending_note_for_test(&self) -> Option<String> {
        self.pending_note.clone()
    }

    /// Stand in for what typing into the password widget holds between frames.
    pub fn force_password_for_test(&mut self, p: String) {
        if let Ok(mut guard) = self.password_input.lock() {
            *guard = Zeroizing::new(p);
        }
    }

    pub fn fail_for_test(&mut self, plain: &str, technical: &str) {
        self.screen = Screen::Failed {
            error: ErrorReport {
                plain: plain.into(),
                technical: technical.into(),
            },
            back: None,
        };
    }

    pub fn set_screen_for_test(&mut self, screen: Screen) {
        self.screen = screen;
    }

    /// Pin the window's language (the tests assert Spanish sentences and
    /// labels, and `$LANG` is the CI runner's, not the test author's).
    pub fn set_locale_for_test(&mut self, tr: Tr) {
        self.tr = tr;
    }

    pub fn close_question_for_test(&self) -> bool {
        self.close_question.is_some()
    }

    /// Borrow the live screen (tests match on its variants).
    pub fn screen_ref_for_test(&self) -> &Screen {
        &self.screen
    }

    /// The worker-thread machinery without a thread: tests feed outcomes back
    /// through it and assert where each one lands. Every arm below is the
    /// exact `poll_worker` transition, reached directly because kittest's
    /// eframe seam has no winit frame loop to drain a channel with (ADR-0006:
    /// what a test stands in for is "the answer arrived", never the pump).
    pub fn deliver_sign_outcome_for_test(&mut self, outcome: SignOutcome) {
        self.inject_reply_for_test(WorkerReply::Sign(outcome));
    }

    /// The verify half of the same seam (A-1): a drained verify answer lands
    /// Verified or Failed exactly as `poll_worker` does it.
    pub fn deliver_verify_answer_for_test(
        &mut self,
        answer: Result<crate::wizard::VerifiedAnswer, ErrorReport>,
    ) {
        let swap_expected = answer.is_ok();
        if swap_expected && self.worker_rx.is_none() {
            // A verify job parks nothing; the answer replaces whatever screen
            // waited on it. Without a started worker (the fixture path asked
            // and answered within one test), stand in for the start by moving
            // to Signing so `back` is well-defined.
            self.screen = Screen::Signing {
                back: Box::new(std::mem::replace(&mut self.screen, Screen::Idle)),
            };
        }
        self.inject_reply_for_test(WorkerReply::Verify(answer));
    }

    /// Start a signing job through the production entry point `start_sign`
    /// (the private function every real path — the button and the overwrite
    /// answer — runs). Tests that deliberately double-book the slot call
    /// this with the guard's precondition already violated on purpose; the
    /// seam skips the debug shout so the test can watch what the guard does
    /// instead of aborting on it.
    pub fn start_sign_via_button_for_test(&mut self, job: SignJob) {
        if self.worker_rx.is_some() {
            // The one-slot rule (A-1): refuse quietly, exactly as a release
            // build enforces it. The debug_assert inside `start_sign` is a
            // shout for future callers who bypass every screen check; an
            // intentional double-booking here is that check firing on cue,
            // and the tests below assert the refusal itself.
            return;
        }
        self.start_sign(job);
    }

    /// Whether a job is in flight right now (the park tests watch it drain).
    pub fn worker_running_for_test(&self) -> bool {
        self.worker_rx.is_some()
    }

    /// Drain the worker without blocking (A-1's production poll, reached
    /// directly because kittest owns no winit event loop; this is the same
    /// method `eframe::App::ui` calls every frame, never a lookalike).
    pub fn poll_worker_for_test(&mut self) -> Option<()> {
        let had = self.worker_rx.is_some();
        self.poll_worker();
        had.then_some(())
    }

    /// The `load_path` door for a second document, exactly as "sign another"
    /// plus a new file reaches it (the A-6 reuse tests).
    pub fn load_second_document_for_test(&mut self, path: PathBuf) {
        self.load_path(path);
    }

    /// Select the pending `.p12` row, exactly as the picker does on its own
    /// when one exists; a test watching the field's sentence needs the same
    /// selection rule the widgets apply.
    pub fn select_pending_for_test(&mut self) {
        if let Screen::Picked {
            catalog, selected, ..
        } = &mut self.screen
            && let Some(i) = catalog.entries.iter().position(|c| c.pending_p12.is_some())
        {
            *selected = Some(i);
        }
    }

    /// Where the library says this input's signature goes (the Done screen's
    /// path and the worker's write target — one rule, `Format::default_output`).
    pub fn expected_output_for_test(&self, doc: &Path) -> PathBuf {
        output_path(Format::detect(&std::fs::read(doc).unwrap_or_default()), doc)
    }

    fn inject_reply_for_test(&mut self, reply: WorkerReply) {
        self.worker_rx = None;
        match reply {
            WorkerReply::Sign(SignOutcome::Done {
                signature,
                output,
                format_label,
                signer_display,
            }) => {
                // The park always exists here: start_sign replaced the picker
                // with Signing and nothing else ever moves that screen while a
                // job runs. A Done answer with no park left is a bug, not a
                // user path, so it says so rather than inventing a header name.
                let (path, content) = match &self.screen {
                    Screen::Signing { back } => match back.as_ref() {
                        Screen::Picked { path, content, .. } => (path.clone(), content.clone()),
                        // A signed job always parks its picker; the screen
                        // name is enough to debug a violation of that rule.
                        _ => panic!("a signed job must park its Picked screen"),
                    },
                    // A Done whose park was discarded (the close guard's
                    // explicit answer dropped it): the result's own output
                    // path is the only honest header left, and the bytes ride
                    // on with it so nothing is lost twice.
                    _ => (output.clone(), Vec::new()),
                };
                self.screen = Screen::Done {
                    path,
                    output,
                    content,
                    signature,
                    format_label,
                    signer_display,
                    saved: true,
                };
            }
            WorkerReply::Sign(SignOutcome::Retryable { reason }) => {
                let back = match std::mem::replace(&mut self.screen, Screen::Idle) {
                    Screen::Signing { back } => *back,
                    other => other,
                };
                self.screen = if errors::is_wrong_password(&reason) {
                    let mut back = back;
                    if let Screen::Picked { password_error, .. } = &mut back {
                        *password_error = true;
                    }
                    back
                } else {
                    Screen::Failed {
                        error: reason,
                        back: Some(Box::new(back)),
                    }
                };
            }
            WorkerReply::Sign(SignOutcome::Failed(report)) => {
                // The Picked screen's catalog is worth keeping through a hard
                // failure too: it cost PINs to build. A transient park behind
                // it (a spinner or an idle placeholder — screens "Intentar de
                // nuevo" must not restore) drops to the drop zone instead.
                let back = match std::mem::replace(&mut self.screen, Screen::Idle) {
                    Screen::Signing { back } => match *back {
                        s @ (Screen::Picked { .. } | Screen::Done { .. }) => Some(Box::new(s)),
                        _ => None,
                    },
                    _ => None,
                };
                self.screen = Screen::Failed {
                    error: report,
                    back,
                };
            }
            WorkerReply::Verify(Ok(answer)) => {
                let n = answer.verdicts.lines.len();
                self.screen = Screen::Verified {
                    path: answer.path,
                    verdicts: answer.verdicts,
                    details_open: vec![false; n],
                };
            }
            WorkerReply::Verify(Err(report)) => {
                self.screen = Screen::Failed {
                    error: report,
                    back: None,
                }
            }
        }
    }

    /// Move the screen out so a test can inspect and mutate it, leaving Idle;
    /// put it back with `set_screen_for_test` before building the harness.
    pub fn take_screen_for_test(&mut self) -> Screen {
        std::mem::replace(&mut self.screen, Screen::Idle)
    }

    // ------------------------------------------------------------------ picked

    fn render_picked(&mut self, ui: &mut Ui) {
        std::mem::swap(&mut self.screen, &mut self.scratch);
        let mut taken = std::mem::replace(&mut self.scratch, Screen::Idle);
        macro_rules! put_back {
            ($s:expr) => {{
                self.scratch = $s;
                std::mem::swap(&mut self.screen, &mut self.scratch);
                return;
            }};
        }
        // One borrow tree for the whole screen; every mutation is a field.
        let Screen::Picked {
            ref path,
            ref content,
            format,
            ref mut chosen_format,
            ref mut catalog,
            ref mut selected,
            ref mut advanced,
            ref mut tsa_url,
            ref mut digest,
            ref mut reason,
            ref mut password_error,
        } = taken
        else {
            put_back!(taken);
        };

        let tr = self.tr.clone();
        ui.heading(display_name(path));
        ui.label(match format {
            Format::Pdf => tr.detected_pdf.clone(),
            Format::Xml => tr.detected_xml.clone(),
            Format::Data => tr.detected_data.clone(),
        });
        ui.add_space(10.0);

        // The certificate picker is the heart of this screen: format and
        // digest have detected defaults and hide under an expander; choosing
        // *who signs* is what a citizen must not get wrong (docs/adr/0006-gui-toolkit.md).
        ui.label(RichText::new(tr.choose_certificate.clone()).strong());
        for e in catalog.errors.iter() {
            let e = e.clone();
            ui.colored_label(ui.visuals().error_fg_color, e);
        }

        egui::ScrollArea::vertical()
            .id_salt("cert-list")
            .auto_shrink([false, false])
            .max_height(210.0)
            .show(ui, |ui| {
                if catalog.entries.is_empty() {
                    // The doors (A-6): the cards this machine has middleware
                    // for come FIRST and by human name — nobody types a module
                    // path to sign with their DNIe. "Add a certificate" and
                    // the manual descriptor stay reachable from every picker
                    // state, not only an empty one (the old dead end).
                    if ui.button(tr.p12_button.clone()).clicked() {
                        let title = tr.dialog_open_cert.clone();
                        let picked = self.open_file(&title);
                        if let Some(p) = picked {
                            catalog.entries.retain(|c| c.pending_p12.is_none());
                            catalog.entries.push(CertificateChoice {
                                display: format!("{}…", display_name(&p)),
                                origin: display_name(&p),
                                // A .p12 file's owner is inside it, and the
                                // password is what unlocks that truth: the row
                                // answers "quién es el titular" after the one
                                // field it costs (A-7's p12 half — AutoFirma's
                                // dialog reads the container to show the same).
                                issuer: None,
                                valid_until: None,
                                badges: Vec::new(),
                                source: None,
                                pending_p12: Some(p),
                            });
                        }
                    }
                    let mut links: Vec<(String, String)> = keystore_io::suggested_stores();
                    // One row per descriptor, labelled by what it is; the old
                    // "Abrir nss / Abrir windows" jargon is B-2's own words.
                    for (family, descriptor) in links.drain(..) {
                        let label = match family.as_str() {
                            "dnie" => tr.store_dnie.clone(),
                            "opensc" => tr.store_opensc.clone(),
                            "fnmt" => tr.store_fnmt.clone(),
                            "firefox" | "nssdb" => format!(
                                "{} ({}",
                                tr.open_keystore.trim_end_matches('…'),
                                descriptor
                            ),
                            _ => descriptor.clone(),
                        };
                        if ui.link(label).clicked() {
                            self.deferred.push(Deferred::OpenStore(descriptor));
                        }
                    }
                    if ui.button(tr.open_keystore.clone()).clicked() {
                        self.show_add_store = true;
                    }
                } else {
                    for (i, e) in catalog.entries.iter().enumerate() {
                        let sel = *selected == Some(i);
                        // A-7: who it is, who issued it, until when — the same
                        // three facts AutoFirma's certificate dialog lists, so
                        // telling one's own two certificates apart costs a
                        // glance, not a mistake discovered after filing.
                        let mut body = String::new();
                        if let Some(issuer) = &e.issuer {
                            body.push_str(&format!("\n{}: {}", tr.cert_issuer_line, issuer));
                        }
                        if let Some(until) = &e.valid_until {
                            body.push_str(&format!("\n{}: {}", tr.cert_valid_until_line, until));
                        }
                        for badge in &e.badges {
                            body.push_str(&format!("\n⚠ {badge}"));
                        }
                        let row = ui.add_enabled_ui(e.selectable(), |ui| {
                            ui.selectable_label(
                                sel,
                                format!("{}  ·  {}{}", e.display, e.origin, body),
                            )
                        });
                        if row.inner.clicked() {
                            *selected = Some(i);
                            if let Ok(mut g) = self.password_input.lock() {
                                *g = Zeroizing::new(String::new());
                            }
                            *password_error = false;
                        }
                    }
                }
            });

        // A `.p12` row needs its password; a store entry never asks again on
        // this screen (its PIN was spent when the store opened, and the key
        // cannot leave the holder anyway).
        let pending = catalog.entries.iter().position(|c| c.pending_p12.is_some());
        if let Some(i) = pending {
            ui.add_space(6.0);
            // The visible text *is* the field's accessible name (labelled_by,
            // the way a screen reader wants it): kittest's accessibility
            // check caught what a password field without one would do to a
            // user of assistive technology — an unnamed box.
            let label = ui.label(tr.password_label.clone());
            let mut mirror = String::new();
            App::mirror_secret(&self.password_input, &mut mirror);
            let edit = egui::TextEdit::singleline(&mut mirror)
                .password(true)
                .id(p12_password_id())
                .desired_width(320.0);
            let resp = ui.add(edit).labelled_by(label.id);
            App::sync_secret(&self.password_input, &mirror);
            let _ = resp;
            if *password_error {
                ui.colored_label(ui.visuals().error_fg_color, tr.password_wrong.clone());
            }
            if *selected != Some(i) {
                *selected = Some(i);
            }
        }

        // M-4: the "back" button the review counted as absent — leaving does
        // not cost the document a second trip through a file dialog.
        ui.add_space(6.0);
        let mut go_back = false;
        ui.horizontal(|ui| {
            // 06-N-6: the click is recorded here and acted on OUTSIDE the
            // closure. `put_back!` in this position returned from the closure,
            // not from this function, and the `put_back!(taken)` at the end
            // swapped the Picked screen straight back in: the button did
            // nothing at all.
            if ui.button(tr.back_button.clone()).clicked() {
                go_back = true;
            }
        });
        if go_back {
            put_back!(Screen::Idle);
        }

        if self.show_add_store {
            self.render_add_store(ui, catalog);
            // borrow note: the form mutates App fields only; catalog stays.
        }

        // Advanced: off by default, each option explains itself in one
        // sentence in the interface language (the literals review 06 M-6 found
        // outside strings.rs all moved there). The PAdES long-term levels are
        // *not* silently offered: B-LT/B-LTA archive CRL/OCSP data a window
        // must not omit without saying so, and `signing::execute` refuses half
        // a level with the CLI's honest pointer to the terminal
        // (docs/adr/0006-gui-toolkit.md).
        ui.add_space(6.0);
        let adv_open = *advanced;
        egui::CollapsingHeader::new(if *advanced {
            tr.advanced_hide.clone()
        } else {
            tr.advanced_show.clone()
        })
        .id_salt("advanced")
        .open(Some(adv_open))
        .show(ui, |ui| {
            if tsa_available(chosen_format) {
                ui.weak(tr.adv_tsa.clone());
                ui.add_sized(
                    [(ui.available_width() - 60.0).min(460.0), 26.0],
                    egui::TextEdit::singleline(tsa_url).hint_text("http://tsa.ejemplo/tsa"),
                );
            }
            ui.weak(tr.adv_digest.clone());
            ui.horizontal(|ui| {
                for (label, alg) in [
                    ("SHA-256", openfirma_core::DigestAlg::Sha256),
                    ("SHA-384", openfirma_core::DigestAlg::Sha384),
                    ("SHA-512", openfirma_core::DigestAlg::Sha512),
                ] {
                    ui.selectable_value(digest, alg, label);
                }
            });
            let formats = effective_formats(format, tsa_url);
            if formats.len() > 1 {
                ui.weak(tr.formats_for.clone());
                for (f, enabled) in formats {
                    let mut chosen = *chosen_format == f;
                    let re = ui.add_enabled_ui(enabled, |ui| {
                        ui.radio_value(&mut chosen, true, signing::format_label(f))
                    });
                    if re.inner.changed() && chosen {
                        *chosen_format = f.to_string();
                    }
                }
            }
            if format == Format::Pdf {
                ui.weak(tr.adv_reason.clone());
                ui.add_sized(
                    [(ui.available_width() - 60.0).min(460.0), 26.0],
                    egui::TextEdit::singleline(reason),
                );
            }
        });
        *advanced = adv_open;

        // The one button that decides everything.
        ui.add_space(14.0);
        let needs_password = selected
            .and_then(|i| catalog.entries.get(i))
            .map(|c| {
                c.pending_p12.is_some() && self.password_input.lock().is_ok_and(|p| p.is_empty())
            })
            .unwrap_or(true);
        let can_sign = selected.is_some() && !needs_password;
        let mut sign_now = false;
        ui.horizontal(|ui| {
            let btn = ui.add_enabled_ui(can_sign, |ui| {
                ui.button(RichText::new(tr.sign_button.clone()).strong().size(18.0))
            });
            if btn.inner.clicked() {
                sign_now = true;
            }
            if !can_sign && catalog.entries.is_empty() {
                ui.weak(tr.no_certificates.clone());
            } else if needs_password && selected.is_some() {
                ui.weak(tr.password_missing.clone());
            }
        });

        let _ = content; // bytes stay untouched until the signing step reads them

        if !sign_now {
            put_back!(taken);
        }
        // Signing: gather owned values, hand the screen back (its borrow ends
        // here), then start the worker with everything it needs and nothing
        // borrowed — the window keeps painting while this runs.
        let chosen_format = chosen_format.clone();
        let digest_copy = *digest;
        let tsa_url = std::mem::take(tsa_url);
        let reason = (!reason.trim().is_empty()).then(|| reason.trim().to_string());
        let out = output_path(format, path);
        if out == *path {
            // The default next-to-original name only collides with the input
            // when a previous sign already wrote it; the library's refusal is
            // shown verbatim — the sentence `openfirma sign` prints.
            if let Err(e) = openfirma_core::workflow::check_not_in_place(path, &out, false) {
                put_back!(Screen::Failed {
                    error: ErrorReport {
                        plain: e.clone(),
                        technical: e,
                    },
                    back: Some(Box::new(taken)),
                });
            }
        }
        // A-3's window half of the overwrite guard: an existing output is
        // somebody's data. AutoFirma asks through its save dialog (which also
        // confirms overwrites); so do we — asking beats truncating, and
        // "elegir otro nombre" opens the same dialog with the collision gone.
        if out != *path && out.exists() {
            self.deferred.push(Deferred::AskOverwrite(taken));
            put_back!(Screen::Idle);
        }
        let key = self.key_for_row(catalog, *selected);
        let Some(key) = key else {
            put_back!(taken);
        };
        let content_copy = content.clone();
        let path_copy = path.clone();
        // The picked screen stays exactly as it was behind the park.
        // Forget the typed password the frame its job was built: the widget's
        // remembered copy goes too (M-8). The thunk holds its own Zeroizing.
        App::forget_secret(ui, p12_password_id(), &self.password_input);
        let out = output_path(format, &path_copy);
        let job = SignJob {
            key,
            chosen_format,
            digest: digest_copy,
            tsa_url,
            reason,
            content: content_copy,
            path: path_copy,
            out,
        };
        // 06-N-5: the Picked screen goes back on `self.screen` before the
        // worker parks it. `render_picked` swapped it into a local and left
        // `Idle` in its place, so `start_sign` parked the drop zone as the
        // screen to come back to: a wrong password restored it, and the
        // document, the chosen certificate and the typed field were gone with
        // no sentence saying why. `sign_to`, the other door into the worker,
        // hands its screen over the same way.
        self.scratch = taken;
        std::mem::swap(&mut self.screen, &mut self.scratch);
        self.start_sign(job);
    }

    fn render_add_store(&mut self, ui: &mut Ui, catalog: &mut CertCatalog) {
        let _ = catalog; // the form touches App fields; errors land via deferred open
        let tr = &self.tr;
        let mut open_it = false;
        let mut cancel = false;
        ui.group(|ui| {
            ui.weak(
                "Escribe el descriptor del almacén: pkcs11:/ruta/modulo.so[:token], \
                 nss (la base de Firefox/Chromium), o los almacenes del sistema.",
            );
            let mut d = std::mem::take(&mut self.descriptor_input);
            let mut p = String::new();
            App::mirror_secret(&self.pin_input, &mut p);
            ui.add_sized(
                [(ui.available_width() - 150.0).max(240.0), 26.0],
                egui::TextEdit::singleline(&mut d).hint_text("pkcs11:/usr/lib/opensc-pkcs11.so"),
            );
            ui.add_sized(
                [300.0, 26.0],
                egui::TextEdit::singleline(&mut p)
                    .password(true)
                    .hint_text(tr.keystore_pin.clone()),
            );
            App::sync_secret(&self.pin_input, &p);
            if ui.button("Abrir").clicked() {
                open_it = true;
            }
            if ui.button("Cancelar").clicked() {
                cancel = true;
            }
            self.descriptor_input = d;
        });
        if open_it {
            let d = std::mem::take(&mut self.descriptor_input);
            self.show_add_store = false;
            // The PIN leaves the widget exactly once and into the session
            // cache's Zeroizing: from here every copy zeroes on drop, and the
            // next document with this card does not ask again (A-6).
            self.deferred.push(Deferred::OpenStore(d));
        }
        if cancel {
            self.show_add_store = false;
            self.descriptor_input.clear();
        }
    }

    fn render_signing(&mut self, ui: &mut Ui) {
        let tr = &self.tr;
        // A-1 made this screen true: the worker runs while this frame (and
        // every one after it) paints. kittest's harness can park a Signing
        // screen too, which is how its rendering gets asserted without a real
        // second thread ever existing.
        ui.spinner();
        ui.label(tr.signing_in_progress.clone());
    }

    /// Ask "this name already exists" once per attempt: save dialog answers,
    /// overwrite confirms, decline returns to the picker untouched (A-3).
    /// The key the chosen row signs with, or `None` when there is no row to
    /// sign with at all. One function for BOTH doors that start a signing job
    /// — the picker's own button and the overwrite answer — because having
    /// two is what killed the window: `sign_to` asked the row for a
    /// `KeySource` through `entry.key()` alone, and a `.p12` row has none (it
    /// signs with the password the citizen just typed, held in this struct),
    /// so `expect` ended the process on the second signature over one
    /// document (round 2, 06-N-1). A pending row reads its password here; a
    /// store row brings the thunk that was built when its slot opened.
    fn key_for_row(&self, catalog: &CertCatalog, selected: Option<usize>) -> Option<KeySource> {
        let entry = selected.and_then(|i| catalog.entries.get(i))?;
        match &entry.pending_p12 {
            Some(path) => {
                let password = self
                    .password_input
                    .lock()
                    .map(|p| Zeroizing::new(p.to_string()))
                    .unwrap_or_else(|_| Zeroizing::new(String::new()));
                Some(KeySource::P12 {
                    path: path.clone(),
                    password,
                    alias: None,
                    display: entry.display.clone(),
                })
            }
            None => entry.key(),
        }
    }

    fn ask_overwrite(&mut self, back: Screen) {
        let tr = &self.tr;
        // The OS save dialog is the confirmation AutoFirma uses — its own
        // "replace?" prompt is part of picking the path. openfirma cannot
        // make rfd emit it portably, so the question is ours: same answer,
        // one more click on purpose (never overwrite a file silently).
        let suggested = match &back {
            Screen::Picked { format, path, .. } => output_path(*format, path),
            _ => return,
        };
        let title = tr.dialog_save_sig.clone();
        if let Some(dest) = self.save_file(&title, &suggested) {
            // The dialog itself is the confirmation: OS save dialogs ask
            // before replacing (ADR-0006 spends its one click here). Run the
            // job against the chosen destination — including when it collides
            // with the ORIGINAL document, which `sign_to` refuses out loud.
            self.deferred.push(Deferred::SignTo(back, dest));
        } else {
            // Declined: the picker exactly where it was, no bytes lost (never
            // a silent loss is the rule this whole state machine exists for).
            self.screen = back;
        }
    }

    /// Re-run a picked screen's signing job onto `dest`: the collision answer
    /// of the save dialog, or the direct destination after confirming its
    /// overwrite (A-3). The in-place guard runs again on the FINAL name —
    /// writing over the source document is refused whatever route named it.
    fn sign_to(&mut self, back: Screen, dest: PathBuf) {
        macro_rules! back_to {
            () => {{
                self.screen = back;
                return;
            }};
        }
        // Borrowed view first (a refusal must put the WHOLE screen back),
        // owned fields copied only once the job is certain to run.
        let Screen::Picked {
            ref path,
            ref catalog,
            selected,
            ..
        } = back
        else {
            back_to!();
        };
        if let Err(e) = openfirma_core::workflow::check_not_in_place(path, &dest, false) {
            self.screen = Screen::Failed {
                error: ErrorReport {
                    plain: e.clone(),
                    technical: e,
                },
                back: Some(Box::new(back)),
            };
            return;
        }
        let needs_password = selected
            .and_then(|i| catalog.entries.get(i))
            .map(|c| {
                c.pending_p12.is_some() && self.password_input.lock().is_ok_and(|p| p.is_empty())
            })
            .unwrap_or(true);
        let Some(i) = selected.filter(|_| !needs_password) else {
            back_to!();
        };
        let Some(key) = self.key_for_row(catalog, Some(i)) else {
            back_to!();
        };
        // All checks passed: take the owned fields out of the parked screen
        // (`back` keeps its other variants intact; only these move).
        let (path, content, chosen_format, tsa_url, digest, reason) = match back {
            Screen::Picked {
                ref path,
                ref content,
                ref chosen_format,
                ref tsa_url,
                digest,
                ref reason,
                ..
            } => (
                path.clone(),
                content.clone(),
                chosen_format.clone(),
                tsa_url.clone(),
                digest,
                reason.clone(),
            ),
            _ => unreachable!("checked above"),
        };
        let job = SignJob {
            key,
            chosen_format,
            digest,
            tsa_url,
            reason: (!reason.trim().is_empty()).then(|| reason.trim().to_string()),
            content,
            path,
            out: dest,
        };
        // The screen is replaced by start_sign's park; the job owns everything.
        self.screen = back;
        self.start_sign(job);
    }

    // -------------------------------------------------------------------- done

    fn render_done(&mut self, ui: &mut Ui) {
        std::mem::swap(&mut self.screen, &mut self.scratch);
        let mut taken = std::mem::replace(&mut self.scratch, Screen::Idle);
        macro_rules! put_back {
            ($s:expr) => {{
                self.scratch = $s;
                std::mem::swap(&mut self.screen, &mut self.scratch);
                return;
            }};
        }
        let Screen::Done {
            ref path,
            ref mut output,
            ref signature,
            ref format_label,
            ref signer_display,
            saved: _,
            content: _,
        } = taken
        else {
            put_back!(taken);
        };
        let tr = &self.tr;

        // The ✓ green is the theme's own success tone wherever one exists;
        // egui has no success colour, so the strong foreground with the check
        // mark carries "this is good" and the heading stays readable on both
        // themes (the old arithmetic on Color32 did not compile against 0.37).
        ui.label(RichText::new(format!("{} ✓", tr.signed_ok)).heading());
        ui.label(format!(
            "{} · {} · «{}»",
            display_name(path),
            format_label,
            signer_display,
        ));
        let out_text = output.display().to_string();
        ui.label(RichText::new(out_text).monospace());
        // A-2: the path a user needs in a terminal is ONE click from their
        // clipboard. egui's copy command goes through egui-winit to arboard —
        // no xclip spawned per press, and the accesskit tree reports the
        // button like any other (the feature story is pinned in the workspace
        // Cargo.toml; a headless test asserts the command leaves the frame).
        if ui.button(tr.copy_path.clone()).clicked() {
            let text = output.display().to_string();
            ui.ctx().copy_text(text);
        }

        let mut open_folder = false;
        let mut save_as = false;
        let mut another = false;
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            if ui.button(tr.open_folder.clone()).clicked() {
                open_folder = true;
            }
            if ui.button(tr.save_as.clone()).clicked() {
                save_as = true;
            }
            if ui.button(tr.sign_another.clone()).clicked() {
                another = true;
            }
        });

        let mut folder_error: Option<String> = None;
        if open_folder {
            let dir = keystore_io::containing_dir(output);
            // Folders only, never documents (ADR-0006 counts the viewer click
            // we deliberately do NOT spend): opening a signed PDF hands the
            // trust decision to whatever program answers, while this screen's
            // ✓ already shows openfirma's own verdict.
            if let Err(e) = open_in_file_manager(&dir) {
                folder_error = Some(format!("No se pudo abrir la carpeta: {e}"));
            }
        }

        if save_as {
            let suggestion = output.clone();
            let title = tr.dialog_save_sig.clone();
            if let Some(dest) = self.save_file(&title, &suggestion) {
                // Strictest form of never-losing-the-result: the bytes stay on
                // this screen until a copy is proven at exactly the path now
                // shown; the first write (the synced worker write) still
                // stands if this one fails, so a failed copy cannot silently
                // un-save.
                let copied = (|| -> std::io::Result<()> {
                    use std::io::Write;
                    let mut f = std::fs::File::create(&dest)?;
                    f.write_all(signature.as_slice())?;
                    file_sync(&f)
                })();
                match copied {
                    Ok(()) => *output = dest,
                    Err(e) => {
                        let note = format!("No se pudo guardar: {e}");
                        put_back!(Screen::Failed {
                            error: ErrorReport {
                                plain: note,
                                technical: e.to_string(),
                            },
                            back: Some(Box::new(taken)),
                        });
                    }
                }
            }
        }
        if let Some(msg) = folder_error {
            ui.colored_label(ui.visuals().error_fg_color, msg);
        }
        if another {
            put_back!(Screen::Idle);
        }
        put_back!(taken);
    }

    // ------------------------------------------------------- needs original doc

    fn render_needs_content(&mut self, ui: &mut Ui) {
        std::mem::swap(&mut self.screen, &mut self.scratch);
        let taken = std::mem::replace(&mut self.scratch, Screen::Idle);
        macro_rules! put_back {
            ($s:expr) => {{
                self.scratch = $s;
                std::mem::swap(&mut self.screen, &mut self.scratch);
                return;
            }};
        }
        let Screen::NeedsContent {
            ref signature_path, ..
        } = taken
        else {
            put_back!(taken);
        };
        let tr = &self.tr;
        ui.heading(display_name(signature_path));
        ui.label(tr.reason_detached_content.clone());
        if ui.button(tr.browse.clone()).clicked() {
            self.deferred
                .push(Deferred::AskContent(signature_path.clone()));
            put_back!(taken);
        }
        if ui.button(tr.back_button.clone()).clicked() {
            put_back!(Screen::Idle);
        }
        put_back!(taken);
    }

    // ---------------------------------------------------------------- verified

    fn render_verified(&mut self, ui: &mut Ui) {
        std::mem::swap(&mut self.screen, &mut self.scratch);
        let mut taken = std::mem::replace(&mut self.scratch, Screen::Idle);
        macro_rules! put_back {
            ($s:expr) => {{
                self.scratch = $s;
                std::mem::swap(&mut self.screen, &mut self.scratch);
                return;
            }};
        }
        let Screen::Verified {
            ref path,
            ref verdicts,
            ref mut details_open,
        } = taken
        else {
            put_back!(taken);
        };
        details_open.resize(verdicts.lines.len(), false);
        let tr = self.tr.clone();
        ui.heading(display_name(path));
        if verdicts.lines.is_empty() {
            ui.label(tr.verdict_unsigned.clone());
        }
        // 06-N-3: when the verifier refused the DOCUMENT — a failure it could
        // not pin on one signature — that refusal is the screen's first
        // sentence, in this language, in red. No line under it may read
        // "Firma válida": the library returned Err for this file and the CLI
        // exits 1, so a green line here would be the project's exact false
        // success, over a document every conforming reader flags.
        if let Some(reason) = &verdicts.document {
            let sentence = format!("{} — {reason}", tr.verdict_document_invalid);
            ui.label(
                RichText::new(sentence)
                    .color(ui.visuals().error_fg_color)
                    .strong(),
            );
            ui.add_space(6.0);
        }
        let mut go_idle = false;
        egui::ScrollArea::vertical()
            .id_salt("verdicts")
            // 06-N-9: the notes and the way out are laid out INSIDE this area
            // and the area shrinks to its content when the content fits, so
            // the exit is on screen with a short verdict and reachable by
            // scrolling with a long one. Before, `auto_shrink([false, false])`
            // made the area consume every remaining pixel of the window and
            // pushed the button below the bottom edge — 5 px of it showed,
            // whatever the window size.
            .auto_shrink([false, true])
            .show(ui, |ui| {
                for (i, line) in verdicts.lines.iter().enumerate() {
                    let open = details_open.get(i).copied().unwrap_or(false);
                    let tone = match line.status {
                        VerdictStatus::Valid => ui.visuals().text_color(),
                        VerdictStatus::Invalid => ui.visuals().error_fg_color,
                        VerdictStatus::Unknown => ui.visuals().warn_fg_color,
                    };
                    // A-5's screen form: one coloured line per signature that
                    // reads as a sentence ("Firma válida — NOMBRE" / "La firma
                    // NO es válida — el documento cambió…"), never DER.
                    let headline = verdict_sentence(line, &tr);
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(line.status.glyph()).color(tone).size(16.0));
                        ui.label(RichText::new(headline).color(tone).strong());
                    });
                    if !line.when.is_empty() {
                        ui.label(format!("{}: {}", tr.signed_at_line, line.when));
                    }
                    if let Some(anchor) = &line.trust_anchor {
                        ui.weak(format!("{}: {}", tr.chain_line, anchor));
                    }
                    // M-3: the toggle's state is the SCREEN'S, one bool per
                    // line — the old per-frame `let mut details = false` made
                    // every details block unreadable by design. Clicking once
                    // stays open across frames and coffee breaks.
                    let toggle = if open {
                        tr.details_hide.clone()
                    } else {
                        tr.details_show.clone()
                    };
                    if ui.button(toggle).clicked() {
                        *details_open.get_mut(i).unwrap() = !open;
                    }
                    if open {
                        egui::Frame::group(ui.style()).show(ui, |ui| {
                            for t in &line.technical {
                                let t = t.clone();
                                ui.label(RichText::new(t).monospace().size(11.0));
                            }
                        });
                    }
                }
                for n in &verdicts.notes {
                    let n = n.clone();
                    ui.weak(n);
                }
                if !verdicts.notes.is_empty() {
                    ui.add_space(6.0);
                }
                // The click is recorded here and acted on OUTSIDE the closure:
                // a `put_back!` in this position would return from the closure,
                // not from this function, and the screen would be swapped back
                // at the end of it (the shape 06-N-6 found in the picker).
                if ui.button(tr.verify_another.clone()).clicked() {
                    go_idle = true;
                }
            });
        if go_idle {
            put_back!(Screen::Idle);
        }
        put_back!(taken);
    }

    // ------------------------------------------------------------------ failed

    fn render_failed(&mut self, ui: &mut Ui) {
        std::mem::swap(&mut self.screen, &mut self.scratch);
        let taken = std::mem::replace(&mut self.scratch, Screen::Idle);
        macro_rules! put_back {
            ($s:expr) => {{
                self.scratch = $s;
                std::mem::swap(&mut self.screen, &mut self.scratch);
                return;
            }};
        }
        let Screen::Failed {
            ref error,
            ref back,
        } = taken
        else {
            put_back!(taken);
        };
        let tr = &self.tr;
        ui.label(
            RichText::new(tr.error_title.clone())
                .heading()
                .color(ui.visuals().error_fg_color),
        );
        let plain = error.plain.clone();
        ui.label(plain);
        // The same button wording as the verdict lines (M-3's one vocabulary):
        // the label says where the click goes, and the state survives frames.
        let mut details = self.show_details;
        // One vocabulary, same as the verdict lines (M-3): the label states
        // which way the next click goes, and the state is the App's own.
        let label = if details {
            tr.details_hide.clone()
        } else {
            tr.details_show.clone()
        };
        if ui.button(label).clicked() {
            details = !details;
            self.show_details = details;
        }
        if details {
            // The chain summary first, labelled (a citizen skimming details
            // should still find the trust answer), then raw technical lines.
            egui::ScrollArea::vertical()
                .id_salt("details")
                .max_height(180.0)
                .show(ui, |ui| {
                    let tech = error.technical.clone();
                    ui.monospace(tech);
                });
        }
        if ui.button(tr.try_again.clone()).clicked() {
            // Back to the screen that failed (its bytes untouched); a failure
            // with no back-screen returns to the drop zone with its path
            // still in the input box.
            match back.as_deref().map(Screen::restore) {
                Some(inner) => put_back!(inner),
                None => put_back!(Screen::Idle),
            }
        }
        if ui.button(tr.back_button.clone()).clicked() {
            put_back!(Screen::Idle);
        }
        put_back!(taken);
    }

    // ------------------------------------------------------------- keystores

    /// Open a keystore descriptor and merge its signable certificates into
    /// the catalog (the CLI's `keystores list` rule: one store failing never
    /// hides another's listing, and it never aborts what is already open).
    /// The PIN comes from the session cache when this card was opened before
    /// (A-6); the typed field is a fresh card only. A slow reader freezes no
    /// frame — but opening a dialog answer must show its errors immediately,
    /// so this stays on the UI thread by decision: a file-dialog answer is
    /// already a round trip a user expects to wait for, and egui keeps the
    /// spinner-free error path instant. What froze the review's window was
    /// per-signature card work and TSAs; those are the worker's (A-1).
    fn open_descriptor(&mut self, descriptor: &str) {
        let outcome = (|| -> openfirma_core::Result<Vec<keystore_io::StoreEntry>> {
            let spec = StoreSpec::parse(descriptor).map_err(openfirma_core::Error::Keystore)?;
            let pin = self.pins.get(descriptor).or_else(|| {
                let typed = self.pin_input.lock().ok().map(|p| p.to_string())?;
                (!typed.is_empty()).then(|| Zeroizing::new(typed))
            });
            let store = keystore_io::open_store(&spec, pin.clone())?;
            if let Some(pin) = pin {
                self.pins.put(descriptor, pin);
            }
            keystore_io::store_entries(&store, descriptor)
        })();
        match outcome {
            Ok(list) => {
                if let Screen::Picked { catalog, .. } = &mut self.screen {
                    for e in list {
                        catalog.entries.push(certificate_choice(e));
                    }
                    if catalog.entries.is_empty() {
                        catalog.errors.push(format!(
                            "{descriptor}: no contiene ningún certificado con clave privada"
                        ));
                    }
                }
            }
            Err(e) => {
                let report = errors::report(&e, &self.tr);
                // A keystore that refused to open never hides the picker: its
                // reason rides in the catalog's error list. Only a failure
                // outside any picker becomes the screen itself.
                if let Screen::Picked { catalog, .. } = &mut self.screen {
                    catalog
                        .errors
                        .push(format!("{descriptor}: {}", report.plain));
                } else {
                    let back = match std::mem::replace(&mut self.screen, Screen::Idle) {
                        s @ (Screen::Picked { .. } | Screen::Done { .. }) => Some(Box::new(s)),
                        _ => None,
                    };
                    self.screen = Screen::Failed {
                        error: report,
                        back,
                    };
                }
            }
        }
        // The typed PIN leaves the widget now; the cache owns its zeroizing.
        if let Ok(mut g) = self.pin_input.lock() {
            *g = Zeroizing::new(String::new());
        }
    }
}

/// The stable widget id of the .p12 password field: hashed from a fixed salt,
/// so it survives frames and `forget_secret` wipes exactly this widget's own
/// remembered text (0.37 deprecates free-hanging `Id::new`; `unique` over a
/// constant is the spelling for an id that must repeat). A static keeps one
/// value: every frame hashes to the same thing, and kittest re-runs frames.
fn p12_password_id() -> egui::Id {
    static ID: std::sync::OnceLock<egui::Id> = std::sync::OnceLock::new();
    *ID.get_or_init(|| egui::Id::unique("p12-password"))
}

/// A-7: one picker row from one store entry, with every fact that tells two
/// certificates apart: the friendly name (CN or store label — never a DN),
/// issuer, validity end, and AutoFirma's own two warnings as badges (expired,
/// authentication-only). The rows stay VISIBLE with their badges; selection
/// is what filters (`CertificateChoice::selectable`), because hiding an expired
/// certificate from its owner teaches them it should have worked.
fn certificate_choice(e: keystore_io::StoreEntry) -> CertificateChoice {
    let now = std::time::SystemTime::now();
    let cert = &e.cert;
    let issuer = cert
        .cert
        .issuer()
        .common_name()
        .ok()
        .flatten()
        .map(String::from);
    // The validity end through the GUI's own UTC calendar so picker and
    // verdict lines never print two dates for one instant. `not_after` is a
    // core method (it needs the x509 type, which this crate does not name).
    let valid_until = date_of(cert.cert.not_after());
    let mut badges = Vec::new();
    if cert.cert.expired_at(now) {
        badges.push(crate::strings::Tr::default().cert_expired.clone());
    }
    if cert.cert.is_dnie_authentication_cert() || !cert.cert.can_sign() {
        badges.push(crate::strings::Tr::default().cert_auth_only.clone());
    }
    CertificateChoice {
        display: e.display,
        origin: e.origin,
        issuer: issuer.map(shorten_cn),
        valid_until: Some(valid_until),
        badges,
        source: Some(Arc::new({
            let arc = e.source.clone();
            let cert = Box::new(cert.clone());
            move || KeySource::Store {
                store: arc.clone(),
                // The row clones its certificate every signature (hundreds of
                // bytes, one memcpy): the store's Arc is what must not be
                // rebuilt by re-logging in — and still isn't.
                cert: Box::new((*cert).clone()),
                display: String::new(),
            }
        })),
        pending_p12: None,
    }
}

/// The calendar date (UTC) a certificate's validity ends at, `YYYY-MM-DD`.
/// It takes the instant, not x509_cert's `Time`, so this crate never needs
/// the ASN.1 type by name — `SystemTime::from` is the conversion core itself
/// uses in `CertificateHandle::expired_at`.
fn date_of(t: std::time::SystemTime) -> String {
    let Ok(d) = t.duration_since(std::time::UNIX_EPOCH) else {
        return "—".into();
    };
    let secs = d.as_secs() as i64;
    let (y, m, day) = openfirma_core::workflow::civil_from_days(secs.div_euclid(86_400));
    format!("{y:04}-{m:02}-{day:02}")
}

/// An issuer CN as a row should show it: the parenthetical serials FNMT
/// names carry (`AC CFv3 - 1 (NIF Q-2801001H)`) keep only their name, so rows
/// stay one line and still say exactly who issued.
fn shorten_cn(cn: String) -> String {
    match cn.split_once(" (") {
        Some((head, _)) => head.to_string(),
        None => cn,
    }
}

/// What a loaded file turned out to be.
enum Loaded {
    Sign(Vec<u8>, Format),
    Verify(Vec<u8>),
    /// A detached CAdES whose original document still has to be located (A-4).
    Detached(Vec<u8>),
}

impl App {
    fn load_path_with_intent(&mut self, path: PathBuf, verify_intent: bool) {
        // B-3: arriving through "Verificar una firma", an unsigned document is
        // answered, not swallowed by the sign flow — the two verbs finally do
        // different things with the same dialog.
        if verify_intent && !opens_as_verify(&path) {
            self.pending_note = Some(self.tr.verdict_unsigned.clone());
            self.path_input = path.display().to_string();
            return;
        }
        self.load_path(path);
    }

    /// A file handed over by the drag-and-drop event (M-1: only real drops
    /// reach this — a hover never does). While a result stands unacknowledged
    /// on the Done screen, the drop is refused out loud instead of silently
    /// replacing it (the never-a-lost-result rule in its drop form).
    fn load_dropped(&mut self, path: PathBuf) {
        if self.screen.is_done() {
            self.pending_note = Some(self.tr.drop_while_done.clone());
            return;
        }
        self.load_path_with_intent(path, false);
    }
}

/// Whether dropping `path` leads to verdicts (a signed PDF, a CMS): the exact
/// rule `load_path` applies, answered on the bytes.
fn opens_as_verify(path: &Path) -> bool {
    let Ok(bytes) = std::fs::read(path) else {
        return false;
    };
    if openfirma_core::workflow::is_signed_output(path) {
        return true;
    }
    let format = Format::detect(&bytes);
    (format == Format::Pdf && pades_signature_count(&bytes) > 0)
        || (format != Format::Pdf && looks_like_cms(&bytes))
}

/// The original document a detached signature's name promises: the library's
/// own naming rule reversed (`nota.txt.csig` → `nota.txt`,
/// `informe.v1.pdf.signed.pdf` → `informe.v1.pdf`). Existence decides, and
/// `None` when there is nothing to name; no fuzzy matching, because guessing
/// which of two files signed is how wrong verdicts get made.
///
/// The signature is NEVER its own companion (round 2, 06-N-2). The
/// `strip_suffix('.')` step this used to chain onto the suffix match ate the
/// dot the name had already lost, so for `.csig` it never matched and the
/// function fell through to "the signature is the document": the window
/// verified the `.csig` against its own bytes and declared the GUI's own
/// output manipulated ("El documento cambió después de firmarse"). A file
/// whose name reverses to itself, and a `.p7s`-style foreign detached
/// signature with no rule here, answer `None` — the ask-screen's cue to ask
/// for the original document instead of inventing one.
/// Whether a signature's NAME says it is detached: the library writes `.csig`
/// for exactly that (`workflow::default_output`), and an encapsulated CMS
/// under another name is judged on its bytes by `LoadJob` like any other
/// unknown shape.
fn detached_by_name(signature: &Path) -> bool {
    signature
        .file_name()
        .is_some_and(|n| n.to_string_lossy().ends_with(".csig"))
}

fn companion_of(signature: &Path) -> Option<PathBuf> {
    let name = signature.file_name()?.to_string_lossy().into_owned();
    let stem = [".csig", ".signed.pdf", ".signed.xml"]
        .iter()
        .find_map(|suffix| name.strip_suffix(suffix))?;
    if stem.is_empty() {
        return None;
    }
    let candidate = signature.with_file_name(stem);
    (candidate != signature && candidate.is_file()).then_some(candidate)
}

/// `Some(path)` only when it is a real readable file (the None form is what
/// "no content supplied" means for the verifier).
fn companion_of_ok(path: &Path) -> Option<Vec<u8>> {
    path.is_file().then(|| std::fs::read(path).ok())?
}

/// One verdict line as the sentence the screen leads with (A-5): the status
/// in plain Spanish first, then who it is about. `verdicts::` builds the
/// strings; this only arranges them — no verdict logic here.
fn verdict_sentence(line: &VerdictLine, tr: &Tr) -> String {
    let head = match line.status {
        VerdictStatus::Valid => tr.verdict_valid.clone(),
        VerdictStatus::Invalid => tr.verdict_invalid.clone(),
        VerdictStatus::Unknown => tr.verdict_unknown.clone(),
    };
    let mut sentence = head;
    if let Some(why) = &line.why_not {
        sentence.push_str(" — ");
        sentence.push_str(why);
    }
    if !line.signer.is_empty() {
        sentence.push_str(" (");
        sentence.push_str(&line.signer);
        sentence.push(')');
    }
    sentence
}

/// The frame entry point: drain the worker, render, then run what rendering
/// asked for.
impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        // A-1's other half: a worker answer lands the frame it arrives —
        // poll never blocks (try_recv), so a frozen window is impossible even
        // while a TSA takes its 10 seconds.
        self.poll_worker();
        if self.worker_rx.is_some() {
            // Keep repainting while a job runs: winit wakes this loop for
            // inputs; the spinner's own animation requests frames already,
            // but the request below makes the answer-landing independent of
            // egui animating anything at all.
            ctx.request_repaint_after(std::time::Duration::from_millis(120));
        }
        // The never-lose-the-result rule in its window form: while a signature
        // is being made or held unsaved, a close request is cancelled until the
        // guard's two explicit answers — no OS can close over an unseen result.
        if ctx.input(|i| i.viewport().close_requested()) {
            let busy = self.worker_rx.is_some();
            match close_decision(busy, &self.screen) {
                CloseDecision::Allow => {}
                warn @ (CloseDecision::WarnBusy | CloseDecision::WarnUnsaved) => {
                    // A close request stays high across frames while the OS
                    // wants out (and kittest replays its event), so every
                    // frame of that wish cancels itself: only the guard's own
                    // buttons ever change the screen.
                    if self.close_question.is_none() {
                        self.close_question = Some(warn);
                    }
                    ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                }
            }
        }
        // M-1: a drop is what loads, not a hover (the old code read
        // `hovered_files` — winit keeps that list alive for the whole drag and
        // empties it at release, so the review's cancel-a-drag reloaded a
        // document every frame of a hover). Dropped files arrive once.
        if let Some(path) = read_dropped_file(&ctx) {
            // A dropped file over a Done screen is the next task the user is
            // already thinking about; the guard refuses it with a sentence
            // rather than swallowing the unseen result (load_dropped).
            self.load_dropped(path);
        }
        egui::CentralPanel::default().show(ui, |ui| match &mut self.screen {
            Screen::Idle => self.render_idle(ui),
            Screen::Picked { .. } => self.render_picked(ui),
            Screen::Signing { .. } => self.render_signing(ui),
            Screen::Done { .. } => self.render_done(ui),
            Screen::Verified { .. } => self.render_verified(ui),
            Screen::NeedsContent { .. } => self.render_needs_content(ui),
            Screen::Failed { .. } => self.render_failed(ui),
        });
        while let Some(action) = self.deferred.pop() {
            match action {
                Deferred::OpenStore(d) => self.open_descriptor(&d),
                Deferred::AskAnchor(path) => {
                    // The anchor picker carries its own title (review C-1): it
                    // asks for a certification AUTHORITY to trust, not "your
                    // certificate" — and whatever gets picked passes core's
                    // anchor rule, which refuses a CA:FALSE leaf outright.
                    let title = self.tr.dialog_open_anchor.clone();
                    let anchor = self.open_file(&title);
                    self.finish_anchor(path, anchor);
                }
                Deferred::AskContent(sig_path) => {
                    let title = self.tr.dialog_content_for_detached.clone();
                    match (self.open_file(&title), std::fs::read(&sig_path)) {
                        (Some(content_path), Ok(bytes)) => {
                            self.verify_file_with_content(sig_path, bytes, Some(content_path));
                        }
                        (_, Err(e)) => {
                            let report = errors::report(
                                &openfirma_core::Error::Other(format!(
                                    "cannot read {}: {e}",
                                    sig_path.display()
                                )),
                                &self.tr,
                            );
                            self.screen = Screen::Failed {
                                error: report,
                                back: None,
                            };
                        }
                        (None, _) => {} // declined: stay on the question
                    }
                }
                Deferred::AskOverwrite(back) => self.ask_overwrite(back),
                Deferred::SignTo(back, dest) => self.sign_to(back, dest),
            }
        }
        if self.close_question.is_some() {
            // The guard window (ADR-0006 "never a silent success"), asking the
            // TRUE question for its reason (B-1): a signature being MADE is
            // not "a result not yet saved" — it is work in progress whose
            // words now match, because a job running says so out loud. Rendered
            // as its own window because winit keeps close_requested high across
            // frames while the user wants out: each frame cancels it, this
            // guard answers, and only its buttons end the run.
            let tr = &self.tr;
            let title = tr.error_title.clone();
            let which = self.close_question;
            egui::Window::new(title)
                .id(egui::Id::unique("close-guard"))
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(&ctx, |ui| {
                    let msg = match which {
                        Some(CloseDecision::WarnBusy) => tr.close_signing.clone(),
                        _ => tr.close_unsaved.clone(),
                    };
                    ui.label(msg);
                    ui.horizontal(|ui| {
                        if ui.button(tr.keep_working.clone()).clicked() {
                            self.close_question = None;
                        }
                        // The explicit discard answer: release the held bytes;
                        // the close request winit keeps re-delivering now passes
                        // the guard (close_decision sees nothing to protect). A
                        // written file stays on disk at the path the Done screen
                        // showed. A running worker is abandoned with the process
                        // — it writes nothing after its sender's death.
                        if ui.button(tr.discard_result.clone()).clicked() {
                            self.screen = Screen::Idle;
                            self.worker_rx = None;
                            self.close_question = None;
                        }
                    });
                });
        }
    }
}

/// The drag-and-drop support at the panel level: egui hands external files on the
/// context and one dropped path enters the wizard exactly as typing it would
/// (one rule for both, no special-casing of paths by origin). `dropped_files`
/// arrives with the release only; while a file merely hovers, `hovered_files`
/// drives the idle screen's highlight and NOTHING is loaded (M-1: winit keeps
/// hovered files alive every frame of a drag, so reading them was re-entering
/// the wizard per frame — cancel an in-flight drop and the review watched it
/// happen).
fn read_dropped_file(ctx: &egui::Context) -> Option<PathBuf> {
    let files = ctx.input(|i| i.raw.dropped_files.clone());
    // Drain semantics: egui clears `dropped_files` itself after consuming a
    // frame's raw input, so one path per drop without bookkeeping here.
    files.first().map(|f| f.path().to_path_buf())
}

/// Opening the result's folder, cross-platform: folders only (see
/// `render_done`), std::process only. A refused spawn is reported by the
/// caller and never silent.
fn open_in_file_manager(dir: &Path) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    let opener = "xdg-open";
    #[cfg(target_os = "macos")]
    let opener = "open";
    #[cfg(target_os = "windows")]
    let opener = "explorer";
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = dir;
        return Err(std::io::Error::other(
            "no folder-opening command is known for this operating system",
        ));
    }
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    {
        std::process::Command::new(opener).arg(dir).status()?;
        Ok(())
    }
}

/// Durability behind "Firma guardada": the bytes are on disk before the word
/// is shown (ADR-0006's never-a-silent-success clause, pinned in docs too).
/// The same handle the write used is flushed — a re-open would ask for a
/// second share of the file, which on Windows an antivirus real-time scan can
/// answer with ERROR_ACCESS_DENIED while it still holds its own scan open:
/// a durability check must never depend on who else is looking.
fn file_sync(file: &std::fs::File) -> std::io::Result<()> {
    file.sync_data()
}

/// How many signature dictionaries a PDF holds (the question that splits
/// verify from sign at load time). The pades crate's inspector — the same
/// read `inspect` and `verify` run, no second parser.
fn pades_signature_count(bytes: &[u8]) -> usize {
    openfirma_pades::inspect::signatures(bytes)
        .map(|s| s.len())
        .unwrap_or_default()
}

/// Whether a non-PDF file is already a CMS `SignedData` (then it gets the
/// verdict list, not wrapped inside another signature): a DER SEQUENCE whose
/// first OID is signedData. Cheap and exact enough to route; the verifier
/// judges for real.
fn looks_like_cms(bytes: &[u8]) -> bool {
    // 30 82.. / 30 81.. / short form, then OID 1.2.840.113549.1.7.2.
    if !bytes.starts_with(&[0x30]) {
        return false;
    }
    const SIGNED_DATA_OID: &[u8] = &[
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02,
    ];
    let after_len = match bytes.get(1) {
        Some(0x81) => 3,
        Some(0x82) => 4,
        Some(&l) if l < 0x80 => 2,
        _ => return false,
    };
    bytes.get(after_len..after_len + SIGNED_DATA_OID.len()) == Some(SIGNED_DATA_OID)
}

/// The signing worker's whole run: build the TSA provider (its https refusal
/// is a retryable sentence — it names the flag that answers it), open the key
/// (card access lives here, off every frame), sign, write and sync. Runs on
/// `std::thread`; everything it owns came in through [`SignJob`], nothing is
/// borrowed from the window (which paints its spinner meanwhile).
fn run_sign_job(job: SignJob, tr: &Tr) -> SignOutcome {
    let SignJob {
        key,
        chosen_format,
        digest,
        tsa_url,
        reason,
        content,
        path,
        out,
    } = job;
    let display = key.display().to_string();
    let _ = &path; // the Done screen reads its path from the parked back screen
    let result: openfirma_core::Result<Vec<u8>> = (|| {
        let timestamp = if tsa_url.trim().is_empty() {
            None
        } else {
            Some(crate::tsa::provider(tsa_url.trim())?)
        };
        let signer = key.signer()?;
        signing::execute(
            &chosen_format,
            &content,
            signer.as_ref(),
            digest,
            timestamp,
            reason,
        )
    })();
    match result {
        Ok(signature) => {
            // Write as the first act of the result (ADR-0006: the name is
            // decided by the library — one write, next to the original —
            // and it is durable before the word "guardada" appears). The
            // bytes also stay on the Done screen for Save As / never lose.
            // Write then flush the SAME handle (see `file_sync`): the
            // bytes are on disk before "guardada" can appear.
            let written = (|| -> std::io::Result<()> {
                use std::io::Write;
                let mut f = std::fs::File::create(&out)?;
                f.write_all(&signature)?;
                file_sync(&f)
            })();
            if let Err(e) = written {
                return SignOutcome::Failed(errors::report(
                    &openfirma_core::Error::Other(format!("cannot write {}: {e}", out.display())),
                    tr,
                ));
            }
            SignOutcome::Done {
                signature,
                output: out,
                format_label: signing::format_label(&chosen_format).to_string(),
                signer_display: display,
            }
        }
        Err(e) => {
            let report = errors::report(&e, tr);
            if errors::is_wrong_password(&report) {
                // M-4: the retry answer stays on the picker (the caller keeps
                // it and paints the sentence under the field). The store rows,
                // its PIN-backed Arcs included, survive untouched.
                return SignOutcome::Retryable { reason: report };
            }
            SignOutcome::Failed(report)
        }
    }
}

/// The verify worker's whole run: detect, verify with the shared verdict
/// rules, hand back owned lines. `Err` here is only the no-anchors mark or an
/// OS refusal — every VERDICT (valid, not valid, cannot tell) arrives inside
/// the Ok list (A-5): the error screen is for things a verdict cannot express,
/// and nothing about a bad signature is one.
fn run_verify_job(job: LoadJob, tr: &Tr) -> Result<crate::wizard::VerifiedAnswer, ErrorReport> {
    let LoadJob {
        path,
        bytes,
        content,
        anchors,
    } = job;
    match crate::verdicts::verdict_lines(&bytes, content.as_deref(), anchors, tr) {
        Ok(verdicts) => Ok(crate::wizard::VerifiedAnswer { path, verdicts }),
        Err(e) => Err(errors::report(&e, tr)),
    }
}

impl CertificateChoice {
    /// A row backed by an opened store entry: its thunk rebuilds the signer
    /// from the kept Arc (a second session never needs the PIN again, and the
    /// key still never leaves the holder).
    pub fn store_entry(e: crate::keystore_io::StoreEntry) -> Self {
        certificate_choice(e)
    }
}

impl Screen {
    /// A screen's path if it remembers one (the Done screen re-shows what its
    /// worker wrote; the name rides on the parked back screen only in tests).
    fn dropped_path(&self) -> Option<PathBuf> {
        match self {
            Screen::Picked { path, .. } => Some(path.clone()),
            _ => None,
        }
    }
}
