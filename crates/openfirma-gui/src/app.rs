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
/// therefore opens as a verification task, and co-signing is deliberately not
/// offered in v1 (docs/adr/0006-gui-toolkit.md omissions): adding one's signature next to
/// one nobody has read is how bad paperwork starts.
use std::path::{Path, PathBuf};

use egui::{RichText, Ui};
use zeroize::Zeroizing;

use crate::errors;
use crate::keystore_io;
use crate::signing;
use crate::strings::Tr;
use crate::wizard::{
    CertCatalog, CertificateChoice, CloseDecision, ErrorReport, KeySource, Screen, VerdictLine,
    close_decision, display_name, effective_formats, output_path, tsa_available,
};
use openfirma_core::workflow::{Format, StoreSpec};

/// The window state. Beyond the screen itself it holds only raw text fields
/// (paths, passwords, descriptors) owned by whichever input owns them; every
/// state *decision* lives in `wizard`.
pub struct App {
    tr: Tr,
    screen: Screen,
    path_input: String,
    /// Password for a `.p12` row waiting on one (the catalog holds at most
    /// one pending `.p12`: the picker's own button adds it and replaces any
    /// earlier pending row).
    password_input: String,
    pin_input: String,
    descriptor_input: String,
    show_add_store: bool,
    show_details: bool,
    /// The unsaved-result guard window is open (`CloseDecision::Warn`).
    close_question: bool,
    /// Actions rendering asked for but could not take while borrowing the
    /// screen; run at the end of every frame.
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
    /// Dialog fixtures for this App (tests set it via [`App::with_dialogs`];
    /// production keeps the default, which runs real rfd dialogs).
    dialogs: Dialogs,
}

/// An action collected during rendering and executed after it (the borrow
/// shape: `render_*` moved `self.screen` into UI closures, so a `&mut self`
/// keystore call cannot nest inside them).
enum Deferred {
    OpenStore(String, Option<String>),
    /// Ask the OS for the trust-anchor file of the verify path; its answer
    /// finishes the load that started it.
    AskAnchor(PathBuf),
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
            tr: Tr::es(),
            screen: Screen::Idle,
            path_input: String::new(),
            password_input: String::new(),
            pin_input: String::new(),
            descriptor_input: String::new(),
            show_add_store: false,
            show_details: false,
            close_question: false,
            deferred: Vec::new(),
            scratch: Screen::Idle,
            dialogs: Dialogs::default(),
            pending_note: None,
        }
    }
}

impl App {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        App::default()
    }

    // ---------------------------------------------------------------- loading

    /// The one door every file enters through: read, detect, then either the
    /// verdict list (the bytes already carry signatures) or the signing flow.
    /// Same detection rule both frontends share (`workflow::Format`); for PDFs
    /// "already signed?" comes from the same inspector `inspect`/`verify` run.
    fn load_path(&mut self, path: PathBuf) {
        self.path_input = path.display().to_string();
        let outcome = (|| -> openfirma_core::Result<Loaded> {
            let bytes = keystore_io::read_file(&path)?;
            let format = Format::detect(&bytes);
            if format == Format::Pdf && pades_signature_count(&bytes) > 0 {
                return Ok(Loaded::Verify(bytes));
            }
            if format != Format::Pdf && looks_like_cms(&bytes) {
                return Ok(Loaded::Verify(bytes));
            }
            Ok(Loaded::Sign(bytes, format))
        })();
        match outcome {
            Ok(Loaded::Verify(bytes)) => self.verify_file(path, bytes),
            Ok(Loaded::Sign(bytes, format)) => {
                self.pending_note = None;
                self.screen = Screen::Picked {
                    path,
                    content: bytes,
                    format,
                    chosen_format: format.default_signature_format().to_string(),
                    catalog: CertCatalog::default(),
                    selected: None,
                    advanced: false,
                    tsa_url: String::new(),
                    digest: openfirma_core::DigestAlg::Sha256,
                    reason: String::new(),
                };
            }
            Err(e) => self.fail(errors::report(&e), path),
        }
    }

    /// The verify half of `load_path`, including the ask-for-an-anchor step:
    /// with no trust anchors configured there is nothing to chain to, and
    /// inventing one would be exactly the unfounded success this project
    /// bans — so the screen says what it needs and opens one file picker.
    fn verify_file(&mut self, path: PathBuf, bytes: Vec<u8>) {
        let anchors = openfirma_core::workflow::default_trust_anchors();
        if anchors.is_empty() {
            // The ask-the-user step (docs/adr/0006-gui-toolkit.md): "who do you trust?" is one
            // file picker, nothing more clever, and the reason shows on the
            // drop screen while it waits for the pick. Declining leaves the
            // zone where it was — a half-finished verify is not an error.
            self.pending_note = Some(self.tr.no_trust_anchors.clone());
            self.deferred.push(Deferred::AskAnchor(path));
            return;
        }
        // Every anchor of every configured file joins the pool (a bundle
        // contributes all its certificates — core's load rule, one for both
        // frontends); a file that fails to read stays out but never blocks
        // the others, the same no-silent-all-or-nothing as keystores list.
        let certs: Vec<_> = anchors
            .iter()
            .flat_map(|p| openfirma_core::workflow::load_trust_anchors(p).unwrap_or_default())
            .collect();
        match crate::verdicts::verdicts_for(&bytes, certs) {
            Ok(list) => {
                self.screen = Screen::Verified {
                    path,
                    verdicts: list,
                }
            }
            Err(e) => self.fail(errors::report(&e), path),
        }
    }

    fn finish_anchor(&mut self, path: PathBuf, anchor: Option<PathBuf>) {
        let Some(anchor) = anchor else { return }; // declined: stay idle
        match (
            openfirma_core::workflow::load_trust_anchors(&anchor),
            keystore_io::read_file(&path),
        ) {
            (Ok(certs), Ok(bytes)) => match crate::verdicts::verdicts_for(&bytes, certs) {
                Ok(list) => {
                    self.screen = Screen::Verified {
                        path,
                        verdicts: list,
                    }
                }
                Err(e) => self.fail(errors::report(&e), path),
            },
            (Err(msg), _) => self.fail(
                ErrorReport {
                    plain: msg.clone(),
                    technical: msg,
                },
                path,
            ),
            (_, Err(e)) => self.fail(errors::report(&e), path),
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

    // -------------------------------------------------------------------- idle

    fn render_idle(&mut self, ui: &mut Ui) {
        let tr = &self.tr;
        if let Some(note) = self.pending_note.clone() {
            ui.colored_label(egui::Color32::from_rgb(150, 110, 30), note);
        }
        let mut open_dialog = false;
        ui.vertical_centered(|ui| {
            ui.add_space(36.0);
            ui.label(RichText::new(tr.drop_here.clone()).heading());
            ui.weak(tr.drop_hint.clone());
            ui.add_space(20.0);
            // The drop zone doubles as the file button: egui's drag-and-drop
            // fires for the whole window (read_dropped_file), and this frame
            // is where "no se ve nada que pulsar" gets answered. A Button
            // sized to the old frame keeps one click target for the same job.
            let label = format!("\u{2913}  {}", tr.browse.clone());
            if ui
                .add_sized(
                    [(ui.available_width() - 60.0).clamp(360.0, 560.0), 120.0],
                    egui::Button::new(RichText::new(label).size(22.0)),
                )
                .clicked()
            {
                open_dialog = true;
            }
        });
        ui.add_space(16.0);
        let mut path_to_load: Option<PathBuf> = None;
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
        // without goes on to be signed (ADR-0006: one job per screen).
        if ui.button(tr.verify_verb.clone()).clicked() {
            open_dialog = true;
        }
        if open_dialog {
            let title = tr.dialog_open_file.clone();
            let path = self.open_file(&title);
            if let Some(path) = path {
                self.load_path(path);
            }
        }
        if let Some(path) = path_to_load {
            self.load_path(path);
        }
    }

    /// Open-dialog indirection so kittest swaps in fixtures (the real one is
    /// rfd; see [`Dialogs`]). The live context's data carries the fixture.
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
        self.load_path(path);
    }

    pub fn dialogs_for_test(&mut self) -> &mut Dialogs {
        &mut self.dialogs
    }

    pub fn pending_note_for_test(&self) -> Option<String> {
        self.pending_note.clone()
    }

    /// Stand in for what typing into the password widget holds between frames.
    pub fn force_password_for_test(&mut self, p: String) {
        self.password_input = p;
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

    pub fn close_question_for_test(&self) -> bool {
        self.close_question
    }

    /// Borrow the live screen (tests match on its variants).
    pub fn screen_ref_for_test(&self) -> &Screen {
        &self.screen
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
            ui.colored_label(egui::Color32::from_rgb(180, 60, 60), e);
        }

        egui::ScrollArea::vertical()
            .id_salt("cert-list")
            .auto_shrink([false, false])
            .max_height(190.0)
            .show(ui, |ui| {
                if catalog.entries.is_empty() {
                    // The two doors: a certificate file, or a keystore. Only
                    // nameable keystores are offered — never a guessed module.
                    if ui.button(tr.p12_button.clone()).clicked() {
                        let title = tr.dialog_open_cert.clone();
                        let picked = self.open_file(&title);
                        if let Some(p) = picked {
                            catalog.entries.retain(|c| c.pending_p12.is_none());
                            catalog.entries.push(CertificateChoice {
                                display: format!("{}…", display_name(&p)),
                                origin: display_name(&p),
                                source: None,
                                pending_p12: Some(p),
                            });
                        }
                    }
                    if ui.button(tr.open_keystore.clone()).clicked() {
                        self.show_add_store = true;
                    }
                    for d in suggested_descriptors() {
                        let label = format!("Abrir {}", d);
                        if ui.link(label).clicked() {
                            self.deferred.push(Deferred::OpenStore(d, None));
                        }
                    }
                } else {
                    for (i, e) in catalog.entries.iter().enumerate() {
                        let sel = *selected == Some(i);
                        if ui
                            .selectable_label(sel, format!("{}  ·  {}", e.display, e.origin))
                            .clicked()
                        {
                            *selected = Some(i);
                            self.password_input.clear();
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
            ui.add(
                egui::TextEdit::singleline(&mut self.password_input)
                    .password(true)
                    .desired_width(320.0),
            )
            .labelled_by(label.id);
            if *selected != Some(i) {
                *selected = Some(i);
            }
        }

        if self.show_add_store {
            self.render_add_store(ui, catalog);
            // borrow note: the form mutates App fields only; catalog stays.
        }

        // Advanced: off by default, each option explains itself in one
        // Spanish sentence. The PAdES long-term levels are *not* silently
        // offered: B-LT/B-LTA archive CRL/OCSP data a window must not omit
        // without saying so, and `signing::execute` refuses half a level with
        // the CLI's honest pointer to the terminal (docs/adr/0006-gui-toolkit.md).
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
            .map(|c| c.pending_p12.is_some() && self.password_input.is_empty())
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
            } else if !can_sign && selected.is_some() {
                ui.weak("Falta la contraseña del certificado.");
            }
        });

        let _ = content; // bytes stay untouched until the signing step reads them

        if !sign_now {
            put_back!(taken);
        }
        // Signing: gather owned values, hand the screen back (its borrow ends
        // here), then run the library calls through &mut self.
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
        let key = selected.and_then(|i| catalog.entries.get(i)).map(|e| {
            if let Some(p) = &e.pending_p12 {
                KeySource::P12 {
                    path: p.clone(),
                    password: Zeroizing::new(std::mem::take(&mut self.password_input)),
                    alias: None,
                    display: e.display.clone(),
                }
            } else {
                // A selectable row without a pending .p12 always has its
                // source thunk (store entries set it when built).
                e.key()
                    .expect("a picker row is either pending-password or sourced")
            }
        });
        let Some(key) = key else {
            put_back!(taken);
        };
        let content_copy = content.clone();
        let path_copy = path.clone();
        let back_screen = taken;
        self.scratch = Screen::Idle;
        std::mem::swap(&mut self.screen, &mut self.scratch);
        // The Picked screen must survive the sign for "Intentar de nuevo":
        // park it in scratch while signing works on owned copies.
        self.scratch = back_screen;
        let outcome = self.sign_with(SignJob {
            key,
            chosen_format,
            digest: digest_copy,
            tsa_url,
            reason,
            content: content_copy,
            path: path_copy,
            out,
        });
        match outcome {
            Ok(done) => {
                self.scratch = Screen::Idle;
                self.screen = done;
            }
            Err(report) => {
                let back = std::mem::replace(&mut self.scratch, Screen::Idle);
                self.screen = Screen::Failed {
                    error: report,
                    back: Some(Box::new(back)),
                };
            }
        }
    }

    fn render_add_store(&mut self, ui: &mut Ui, catalog: &mut CertCatalog) {
        let _ = catalog; // the form touches App fields; errors land via deferred open
        let tr = &self.tr;
        let mut open_it = false;
        let mut cancel = false;
        ui.group(|ui| {
            ui.weak(
                "Escribe el descriptor del repositorio: pkcs11:/ruta/modulo.so[:token], \
                 nss (la base de Firefox/Chromium), o los almacenes del sistema.",
            );
            let mut d = std::mem::take(&mut self.descriptor_input);
            let mut p = std::mem::take(&mut self.pin_input);
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
            if ui.button("Abrir").clicked() {
                open_it = true;
            }
            if ui.button("Cancelar").clicked() {
                cancel = true;
            }
            self.descriptor_input = d;
            self.pin_input = p;
        });
        if open_it {
            let d = std::mem::take(&mut self.descriptor_input);
            let p = std::mem::take(&mut self.pin_input);
            self.show_add_store = false;
            self.deferred
                .push(Deferred::OpenStore(d, (!p.is_empty()).then_some(p)));
        }
        if cancel {
            self.show_add_store = false;
            self.descriptor_input.clear();
            self.pin_input.clear();
        }
    }

    fn render_signing(&mut self, ui: &mut Ui) {
        let tr = &self.tr;
        ui.spinner();
        ui.label(format!("Firmando… ({})", tr.sign_verb));
    }

    /// The signing run, from owned inputs (`render_picked` parks the Picked
    /// screen in scratch first so "Intentar de nuevo" has somewhere to go).
    /// The job travels as one struct because it is one decision — who signs
    /// what, how, and where the answer goes.
    fn sign_with(&mut self, job: SignJob) -> Result<Screen, ErrorReport> {
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
        let result: openfirma_core::Result<Vec<u8>> = (|| {
            let timestamp = if tsa_url.trim().is_empty() {
                None
            } else {
                Some(crate::tsa::provider(tsa_url.trim()).map_err(openfirma_core::Error::Other)?)
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
                    return Err(errors::report(&openfirma_core::Error::Other(format!(
                        "cannot write {}: {e}",
                        out.display()
                    ))));
                }
                Ok(Screen::Done {
                    path,
                    output: out,
                    content,
                    signature,
                    format_label: signing::format_label(&chosen_format).to_string(),
                    signer_display: display,
                    saved: true,
                })
            }
            Err(e) => Err(errors::report(&e)),
        }
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

        ui.label(
            RichText::new(format!("✓ {}", tr.signed_ok))
                .heading()
                .color(egui::Color32::from_rgb(30, 120, 60)),
        );
        ui.label(format!(
            "{} · {} · «{}»",
            display_name(path),
            format_label,
            signer_display,
        ));
        ui.label(RichText::new(output.display().to_string()).monospace());

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
                // shown; the first write (sign_with, synced) still stands if
                // this one fails, so a failed copy cannot silently un-save.
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
            ui.colored_label(egui::Color32::from_rgb(180, 60, 60), msg);
        }
        if another {
            put_back!(Screen::Idle);
        }
        put_back!(taken);
    }

    // ---------------------------------------------------------------- verified

    fn render_verified(&mut self, ui: &mut Ui) {
        std::mem::swap(&mut self.screen, &mut self.scratch);
        let taken = std::mem::replace(&mut self.scratch, Screen::Idle);
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
        } = taken
        else {
            put_back!(taken);
        };
        let tr = &self.tr;
        ui.heading(display_name(path));
        if verdicts.lines.is_empty() {
            ui.label(tr.verdict_unsigned.clone());
        }
        for line in &verdicts.lines {
            render_verdict(ui, line, tr);
        }
        for n in &verdicts.notes {
            let n = n.clone();
            ui.weak(n);
        }
        if ui.button(tr.verify_another.clone()).clicked() {
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
                .color(egui::Color32::from_rgb(180, 60, 60)),
        );
        let plain = error.plain.clone();
        ui.label(plain);
        let mut details = self.show_details;
        if ui
            .checkbox(&mut details, tr.details_toggle.clone())
            .changed()
        {
            self.show_details = details;
        }
        if details {
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
        put_back!(taken);
    }

    // ------------------------------------------------------------- keystores

    /// Open a keystore descriptor and merge its signable certificates into
    /// the catalog (the CLI's `keystores list` rule: one store failing never
    /// hides another's listing, and it never aborts what is already open).
    fn open_descriptor(&mut self, descriptor: &str, pin: Option<String>) {
        let outcome = (|| -> openfirma_core::Result<Vec<keystore_io::StoreEntry>> {
            let spec = StoreSpec::parse(descriptor).map_err(openfirma_core::Error::Keystore)?;
            let store = keystore_io::open_store(&spec, pin)?;
            keystore_io::store_entries(&store, descriptor)
        })();
        match outcome {
            Ok(list) => {
                if let Screen::Picked { catalog, .. } = &mut self.screen {
                    for e in list {
                        catalog.entries.push(CertificateChoice::store_entry(e));
                    }
                    if catalog.entries.is_empty() {
                        catalog.errors.push(format!(
                            "{descriptor}: no contiene ningún certificado con clave privada"
                        ));
                    }
                }
            }
            Err(e) => {
                let report = errors::report(&e);
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
    }
}

/// What a loaded file turned out to be.
enum Loaded {
    Sign(Vec<u8>, Format),
    Verify(Vec<u8>),
}

/// One signing job, the owned form of everything the Picked screen decided:
/// the key (whose PIN/password was spent or typed), the effective choices,
/// the document bytes, and the two paths (original, written result). Passing
/// it whole keeps `sign_with`'s signature honest about being one decision.
struct SignJob {
    key: KeySource,
    chosen_format: String,
    digest: openfirma_core::DigestAlg,
    tsa_url: String,
    reason: Option<String>,
    content: Vec<u8>,
    path: PathBuf,
    out: PathBuf,
}

/// The frame entry point: render, then run what rendering asked for.
impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        // The never-lose-the-result rule in its window form: while a signature
        // is being made or held unsaved, a close request is cancelled until the
        // guard's two explicit answers — no OS can close over an unseen result.
        if ctx.input(|i| i.viewport().close_requested()) {
            match close_decision(&self.screen) {
                CloseDecision::Allow => {}
                CloseDecision::Warn => {
                    // A close request stays high across frames while the OS
                    // wants out (and kittest replays its event), so every
                    // frame of that wish cancels itself: only the guard's own
                    // buttons ever change the screen. The Ask variant means a
                    // result nobody saved stands behind the window.
                    if !self.close_question {
                        self.close_question = true;
                    }
                    ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                }
            }
        }
        if let Some(path) = read_dropped_file(&ctx) {
            // A dropped file over a Done screen is the next task the user is
            // already thinking about; ignoring it would be the silent case.
            if !self.screen.is_done() {
                self.load_path(path);
            }
        }
        egui::CentralPanel::default().show(ui, |ui| match &mut self.screen {
            Screen::Idle => self.render_idle(ui),
            Screen::Picked { .. } => self.render_picked(ui),
            Screen::Signing => self.render_signing(ui),
            Screen::Done { .. } => self.render_done(ui),
            Screen::Verified { .. } => self.render_verified(ui),
            Screen::Failed { .. } => self.render_failed(ui),
        });
        while let Some(action) = self.deferred.pop() {
            match action {
                Deferred::OpenStore(d, pin) => self.open_descriptor(&d, pin),
                Deferred::AskAnchor(path) => {
                    let title = self.tr.dialog_open_cert.clone();
                    let anchor = self.open_file(&title);
                    self.finish_anchor(path, anchor);
                }
            }
        }
        if self.close_question {
            // The unsaved-result guard (ADR-0006 "never a silent success"):
            // rendered as its own window because winit keeps close_requested
            // high across frames while the user wants out: each frame cancels
            // it, this guard answers, and only its discard button ends the run.
            let tr = &self.tr;
            egui::Window::new(tr.error_title.clone())
                .id(egui::Id::unique("close-guard"))
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(&ctx, |ui| {
                    let msg = tr.close_unsaved.clone();
                    ui.label(msg);
                    ui.horizontal(|ui| {
                        if ui.button(tr.keep_working.clone()).clicked() {
                            self.close_question = false;
                        }
                        // The explicit discard answer: release the held bytes;
                        // the close request winit keeps re-delivering now passes
                        // the guard (close_decision sees nothing to protect). A
                        // written file stays on disk at the path the Done screen
                        // showed.
                        if ui.button(tr.discard_result.clone()).clicked() {
                            self.screen = Screen::Idle;
                            self.close_question = false;
                        }
                    });
                });
        }
    }
}

/// The descriptors the picker offers with one click: only what can be named
/// without guessing — the NSS database when it exists at its standard place,
/// the platform store on Windows/macOS. PKCS#11 modules are never guessed
/// (same rule as `keystores list` without arguments).
fn suggested_descriptors() -> Vec<String> {
    let mut lines: Vec<String> = openfirma_core::workflow::discoverable_stores()
        .iter()
        .map(|s| s.descriptor())
        .collect();
    if let Ok(home) = std::env::var("HOME") {
        if PathBuf::from(home).join(".pki/nssdb").is_dir() {
            lines.insert(0, "nss".into());
        }
    }
    lines
}

fn render_verdict(ui: &mut Ui, line: &VerdictLine, tr: &Tr) {
    let color = if line.valid {
        egui::Color32::from_rgb(30, 120, 60)
    } else {
        egui::Color32::from_rgb(180, 60, 60)
    };
    ui.group(|ui| {
        let head = if line.valid {
            tr.verdict_valid.clone()
        } else {
            match &line.why_not {
                Some(w) => format!("{} — {}", tr.verdict_invalid, w),
                None => tr.verdict_invalid.clone(),
            }
        };
        ui.label(RichText::new(head).strong().size(16.0).color(color));
        ui.label(format!("{}: {}", tr.signer_line, line.signer));
        if !line.when.is_empty() {
            ui.label(format!("{}: {}", tr.signed_at_line, line.when));
        }
        let mut details = false;
        if ui
            .checkbox(&mut details, tr.details_toggle.clone())
            .changed()
        {
            // per-render on purpose: a citizen reading one verdict once does
            // not need the toggle to persist across screens or lines.
        }
        if details {
            // The chain summary first, labelled (a citizen skimming details
            // should still find the trust answer), then raw technical lines.
            if let Some(chain) = line.trust_anchor.clone() {
                ui.label(format!("{}: {}", tr.chain_line, chain));
            }
            for t in &line.technical {
                let t = t.clone();
                ui.monospace(t);
            }
        }
    });
}

/// Drag-and-drop support at the panel level: egui hands external files on the
/// context and one dropped path enters the wizard exactly as typing it would
/// (one rule for both, no special-casing of paths by origin). `hovered_files`
/// repeats while a file hovers; `update` takes at most one per frame and only
/// into screens that accept files, so a held file cannot retrigger forever.
fn read_dropped_file(ctx: &egui::Context) -> Option<PathBuf> {
    let files = ctx.input(|i| i.raw.hovered_files.clone());
    files.first().and_then(|f| f.path.clone())
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
/// first OID is signedData. Cheap and exact enough to route; `verdicts_for`
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

impl CertificateChoice {
    /// A row backed by an opened store entry: its thunk rebuilds the signer
    /// from the kept Arc (a second session never needs the PIN again, and the
    /// key still never leaves the holder).
    pub fn store_entry(e: crate::keystore_io::StoreEntry) -> Self {
        let arc = e.source.clone();
        let cert = e.cert.clone();
        CertificateChoice {
            display: e.display.clone(),
            origin: e.origin,
            source: Some(Box::new(move || KeySource::Store {
                store: arc.clone(),
                cert: Box::new(cert.clone()),
                display: String::new(),
            })),
            pending_p12: None,
        }
    }
}
