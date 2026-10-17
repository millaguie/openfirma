//! The `main` of a GUI is one thing done exactly once: ask eframe, on the
//! glow backend, for the window. Every failure to create it (no OpenGL, no
//! display at all) says what to run instead — never a panic dump. All the
//! windows' *logic* lives in the `openfirma_gui` library (its modules), so
//! the windowless tests drive the same code this binary runs.
//!
//! A document may be named on the command line (`openfirma-gui contrato.pdf`)
//! or handed over by the desktop through an `Exec=` line of
//! `packaging/openfirma.desktop` (finding B-7: AutoFirma's launcher takes a
//! file argument, and so does double-clicking with the registration active).
//! It arrives exactly as any other drop would — same detection, same preview,
//! same guard against losing an in-flight result. A name that cannot be read
//! prints why on stderr (a GUI without a terminal has no reader for more than
//! that) and starts on the welcome screen anyway.

use std::path::PathBuf;

use openfirma_gui::{app, strings};

fn main() -> eframe::Result<()> {
    let file = std::env::args().nth(2).filter(|a| !a.starts_with('-'));
    // A double-clicked or `Exec=`-passed name is a request to open, not a
    // promise it can: checking readability here says "this file" in its own
    // words instead of surfacing later as a generic load error.
    let startup = file.as_deref().map(|name| match std::fs::metadata(name) {
        Ok(md) if md.is_file() => Ok(PathBuf::from(name)),
        Ok(_) => Err(format!("{name}: es un directorio, no un documento.")),
        Err(e) => Err(format!("{name}: {e}.")),
    });

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([860.0, 620.0])
            .with_min_inner_size([540.0, 400.0])
            // The app title is a string; the window's *contents* are the App.
            // A browser would show the user what they signed and let them
            // decide to trust it; a signing tool shows its own verdict only
            // (docs/adr/0006-gui-toolkit.md), so there is no webview here by
            // design, and no embedded document viewer either.
            .with_title(strings::Tr::es().app_title),
        // glow (OpenGL) is the backend ADR-0006 chose; reordering it here
        // would silently contradict the recorded decision.
        renderer: eframe::Renderer::Glow,
        ..Default::default()
    };
    eframe::run_native(
        &strings::Tr::es().app_title,
        options,
        Box::new(move |cc| {
            let mut a = app::App::new(cc);
            // Production dialogs are the OS pickers; tests build the same App
            // and swap in fixtures (ADR-0006's headless seam).
            a.with_dialogs(app::Dialogs::default());
            if let Some(_name) = file {
                match startup.expect("built from `file` just above") {
                    Ok(path) => a.load_path_from_cli(path),
                    Err(msg) => eprintln!("openfirma: {msg}"),
                }
            }
            Ok(Box::new(a))
        }),
    )
}
