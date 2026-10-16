//! The `main` of a GUI is one thing done exactly once: ask eframe, on the
//! glow backend, for the window. Every failure to create it (no OpenGL, no
//! display at all) says what to run instead — never a panic dump. All the
//! windows' *logic* lives in the `openfirma_gui` library (its modules), so
//! the windowless tests drive the same code this binary runs.

use openfirma_gui::{app, strings};

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([760.0, 560.0])
            .with_min_inner_size([620.0, 460.0])
            .with_title(strings::Tr::es().app_title),
        // glow (OpenGL) is the backend ADR-0006 chose; reordering it here
        // would silently contradict the recorded decision.
        renderer: eframe::Renderer::Glow,
        ..Default::default()
    };
    eframe::run_native(
        &strings::Tr::es().app_title,
        options,
        Box::new(|cc| {
            let mut a = app::App::new(cc);
            // Production dialogs are the OS pickers; tests build the same App
            // and swap in fixtures (ADR-0006's headless seam).
            a.with_dialogs(app::Dialogs::default());
            Ok(Box::new(a))
        }),
    )
}
