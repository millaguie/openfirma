//! The wizard's state machine, deliberately free of any widget or window
//! type so it is testable headlessly (`egui_kittest` drives the rendering;
//! this module is tested as plain logic — and both assert the same rules).
//!
//! One principle from docs/adr-0006 governs everything below: never a silent
//! success, never a lost result. The `Done` state keeps every byte of the
//! signature in memory until the user has seen where it was written *and* an
//! explicit save (or an explicit discard confirmed twice) releases it; the
//! window cannot be closed through it while unsaved (see `close_decision`).

use std::path::{Path, PathBuf};

use openfirma_core::workflow::{Format, StoreSpec};

/// Where a signable certificate came from and how to show it. `KeySource` is
/// the same three-way split `openfirma sign` takes (`--p12`, `--store`; a
/// bare cert+key pair is not a citizen's shape and stays CLI-only).
pub enum KeySource {
    P12 {
        path: PathBuf,
        password: zeroize::Zeroizing<String>,
        alias: Option<String>,
        display: String,
    },
    /// `cert` rides boxed: a `StoreCertificate` embeds the parsed certificate
    /// inline (hundreds of bytes), and boxing it keeps this enum — carried by
    /// every picker row — the size of two pointers plus the display name.
    Store {
        store: std::sync::Arc<dyn openfirma_keystore::SystemStore>,
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

/// One row of the picker. Building the signer is a lazy `Box<dyn Fn()>`
/// because the row must survive without borrowing the catalog that holds it;
/// for store entries the thunk keeps the opened `Arc<dyn SystemStore>` (the
/// PIN was spent once when the store opened) and rebuilds only an adapter —
/// no second session, no second login. For a `.p12` the thunk is created at
/// selection time with the password field's contents by the caller.
pub struct CertificateChoice {
    pub display: String,
    /// Which keystore it came from, or the .p12 file name.
    pub origin: String,
    /// How to build the signer when clicked. `None` marks a `.p12` row that
    /// still needs its password typed first (the picker then shows one
    /// password field).
    pub source: Option<Box<dyn Fn() -> KeySource>>,
    /// A `.p12` awaiting its password, kept with the path so the field and
    /// the eventual `KeySource::P12` cannot disagree about which file they
    /// describe.
    pub pending_p12: Option<PathBuf>,
}

impl CertificateChoice {
    pub fn key(&self) -> Option<KeySource> {
        self.source.as_ref().map(|f| f())
    }
}

/// The error panel's content: one plain sentence for the user plus the full
/// technical text behind "Ver detalles técnicos" — never the other way round.
#[derive(Clone, Debug)]
pub struct ErrorReport {
    /// One sentence in Spanish with what went wrong and, where a way out
    /// exists, what to run. Built by `crate::errors`.
    pub plain: String,
    /// The technical error exactly as the library reported it.
    pub technical: String,
}

/// A per-signature verdict line of the verify screen — built from the same
/// `VerifyReport`/`DocumentReport` the CLI prints (`crate::verdicts`).
#[derive(Clone)]
pub struct VerdictLine {
    pub valid: bool,
    /// Who signed (friendly name, never a DN).
    pub signer: String,
    /// Human-readable time, or empty when the signature carries none.
    pub when: String,
    /// For an invalid one: the one-sentence reason already in Spanish.
    pub why_not: Option<String>,
    /// The trust anchor a valid chain reached, if any — shown first inside
    /// the details area so "¿en quién confía esto?" has an answer.
    pub trust_anchor: Option<String>,
    /// Technical detail for the details control (chain, byte ranges…).
    pub technical: Vec<String>,
}

/// The whole verify verdict list for one file.
#[derive(Clone)]
pub struct VerdictList {
    pub lines: Vec<VerdictLine>,
    /// Document-level notes that are not a signature verdict (unsigned doc,
    /// validation data present…) as plain sentences.
    pub notes: Vec<String>,
}

/// The wizard's states, in the order of the happy path plus error/verify.
pub enum Screen {
    /// First screen: an empty drop zone.
    Idle,
    /// A file has been picked or dropped: its bytes are held, the format is
    /// detected and named in Spanish, the certificate picker is open.
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
    },
    /// Signing in progress — kept so a slow token cannot be raced by a second
    /// click of the same button.
    Signing,
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
    /// Verify mode: a file with signatures was dropped.
    Verified {
        path: PathBuf,
        verdicts: VerdictList,
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

    /// Rebuild the screen "Intentar de nuevo" returns to. The expensive
    /// fields are owned and cloned; a Picked screen loses its catalog rows
    /// (they hold store Arcs and thunks that do not clone — reopening a
    /// keystore is one click, and AutoFirma's redo flow restarts from the
    /// certificate dialog too), while the document bytes, path, format and
    /// advanced choices stay exactly where they were. A Done screen clones in
    /// full: its signature bytes *are* the result, and losing them would be
    /// the silent-loss failure this project bans (ADR-0006).
    pub fn restore(&self) -> Screen {
        match self {
            Screen::Idle | Screen::Signing => Screen::Idle,
            Screen::Picked {
                path,
                content,
                format,
                chosen_format,
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
                catalog: CertCatalog::default(),
                selected: None,
                advanced: *advanced,
                tsa_url: tsa_url.clone(),
                digest: *digest,
                reason: reason.clone(),
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
            Screen::Verified { path, verdicts } => Screen::Verified {
                path: path.clone(),
                verdicts: verdicts.clone(),
            },
            Screen::Failed { error, .. } => Screen::Failed {
                error: error.clone(),
                back: None,
            },
        }
    }
}

/// What the window should do when its close button (or Alt-F4) fires while a
/// result is held and not saved. The GUI has no "Save" button on the done
/// screen: it writes immediately to a default path *and* keeps the bytes, so
/// closing can only ever discard a result nobody confirmed — hence the two
/// explicit answers (docs/adr-0006, "never a silent success").
#[derive(Debug, PartialEq, Eq)]
pub enum CloseDecision {
    /// Nothing is unsaved; close.
    Allow,
    /// A signature is held and never written anywhere: warn first.
    Warn,
}

/// The close rule as a function (tested directly, not only through widgets).
pub fn close_decision(screen: &Screen) -> CloseDecision {
    match screen {
        Screen::Done { saved: false, .. } | Screen::Signing => CloseDecision::Warn,
        _ => CloseDecision::Allow,
    }
}

/// The friendly name of the file for headings and buttons (never a raw path).
pub fn display_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

/// Formats the advanced-area TSA flag should expose for this kind of file and
/// chosen format: only PDF long-term levels have a place for a TSA beyond the
/// signature time-stamp, which `openfirma` offers through the same TSA for
/// all of them; XML/text signatures are B-B today, so nothing to show.
pub fn tsa_available(chosen_format: &str) -> bool {
    matches!(chosen_format, "pades-b-b" | "pades-b-lt" | "pades-b-lta")
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

#[cfg(test)]
mod descriptor_tests {
    use super::parse_descriptor;

    #[test]
    fn the_form_parses_through_the_library_rule() {
        // The add-a-keystore field and `openfirma keystores list` parse the
        // same text with the same function, so a spelling accepted by one is
        // accepted by the other. `nss` expands to the discovered database;
        // an empty pkcs11 module never passes anywhere.
        assert!(parse_descriptor("nss").is_ok());
        assert!(parse_descriptor("pkcs11:").is_err());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closing_a_saved_or_idle_window_is_allowed() {
        assert_eq!(close_decision(&Screen::Idle), CloseDecision::Allow);
        let done = Screen::Done {
            path: PathBuf::from("doc.pdf"),
            output: PathBuf::from("doc.signed.pdf"),
            content: vec![1],
            signature: vec![2],
            format_label: "PAdES-B-B".into(),
            signer_display: "ANA".into(),
            saved: true,
        };
        assert_eq!(close_decision(&done), CloseDecision::Allow);
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
        assert_eq!(close_decision(&done), CloseDecision::Warn);
    }

    #[test]
    fn closing_mid_signing_warns_too() {
        assert_eq!(close_decision(&Screen::Signing), CloseDecision::Warn);
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

    #[test]
    fn the_output_path_is_the_libraries_rule() {
        let p = output_path(Format::Pdf, Path::new("/a/contrato.pdf"));
        assert_eq!(p.file_name().unwrap(), "contrato.signed.pdf");
    }

    #[test]
    fn display_names_never_leak_directories() {
        assert_eq!(display_name(Path::new("/x/y/doc.pdf")), "doc.pdf");
        assert_eq!(display_name(Path::new("doc.txt")), "doc.txt");
    }
}
