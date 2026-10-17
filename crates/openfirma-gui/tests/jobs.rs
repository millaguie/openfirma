//! The one-job-in-flight rule (review 06 A-1), tested as the state machine it
//! is — no threads, no widgets: a job parks the picker behind `Signing`, and
//! while that park stands there is no way to start a second job. The eframe
//! spinner frame is kittest-timing territory (a local worker answers before
//! the next paint), so this owns the *rule*; `tests/ui.rs` drives the same
//! transition through widgets and drains the real thread's reply.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use openfirma_gui::app::App;
use openfirma_gui::wizard::{CertCatalog, CertificateChoice, KeySource, Screen, SignJob};

fn doc(dir: &Path) -> PathBuf {
    let d = dir.join("job-one.pdf");
    std::fs::write(&d, b"%PDF-1.4 one-job test").unwrap();
    d
}

/// Which screen a `Screen` value is, spelled for assert failures (the type
/// itself deliberately has no `Debug`: its variants hold megabytes of document
/// and secret material that must never end up in a log line).
fn which(screen: &openfirma_gui::wizard::Screen) -> &'static str {
    use openfirma_gui::wizard::Screen as S;
    match screen {
        S::Idle => "Idle",
        S::Picked { .. } => "Picked",
        S::Signing { .. } => "Signing",
        S::Done { .. } => "Done",
        S::Verified { .. } => "Verified",
        S::NeedsContent { .. } => "NeedsContent",
        S::Failed { .. } => "Failed",
    }
}

fn picker(path: &Path) -> Screen {
    Screen::Picked {
        path: path.to_path_buf(),
        content: b"%PDF-1.4 one-job test".to_vec(),
        format: openfirma_core::workflow::Format::Pdf,
        chosen_format: "pades-b-b".into(),
        catalog: CertCatalog::default(),
        selected: None,
        advanced: false,
        tsa_url: String::new(),
        digest: openfirma_core::DigestAlg::Sha256,
        reason: String::new(),
        password_error: false,
    }
}

fn job(path: &Path) -> SignJob {
    let p12 = PathBuf::from("does-not-exist.p12");
    SignJob {
        // The thunk never runs here (tests poll outcomes, never crypto); an
        // Arc is what makes the job movable for A-3's rebuild.
        key: KeySource::P12 {
            path: p12,
            password: zeroize::Zeroizing::new(String::new()),
            alias: None,
            display: "test".into(),
        },
        chosen_format: "pades-b-b".into(),
        digest: openfirma_core::DigestAlg::Sha256,
        tsa_url: String::new(),
        reason: None,
        content: b"%PDF-1.4 one-job test".to_vec(),
        path: path.to_path_buf(),
        out: path.with_extension("signed.pdf"),
    }
}

#[test]
fn a_job_parks_the_picker_and_holds_the_only_slot() {
    let dir = std::env::temp_dir().join(format!("openfirma-job-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let d = doc(&dir);
    let mut app = App::default();
    app.set_screen_for_test(picker(&d));

    // start_sign is private (production never lets a caller skip it); the
    // public seam reaches the same function, which pins why it exists.
    app.start_sign_via_button_for_test(job(&d));

    // The park: the picker waits INSIDE the Signing screen (nothing was lost)
    // and the slot holds exactly one job.
    match app.screen_ref_for_test() {
        Screen::Signing { back } => {
            assert!(
                matches!(back.as_ref(), Screen::Picked { .. }),
                "the picker parks intact"
            );
        }
        other => panic!("a started job must park its picker, got {}", which(other)),
    }
    assert!(app.worker_running_for_test(), "one job in flight");

    // The second click has nowhere to go. `start_sign` enforces the one-slot
    // rule twice: a debug shout (the review's frozen double-click had no
    // such rule at all) and a release-enforced early return. This harness
    // drives the button seam from an already-held slot on purpose — the
    // shout would abort the test binary — so what is asserted here is that
    // the enforced return changes nothing at all: park intact, one worker,
    // no extra reply when it drains (a second worker would leave a stray).
    app.start_sign_via_button_for_test(job(&d));
    assert!(
        app.worker_running_for_test(),
        "the second start never started a worker"
    );
    match app.screen_ref_for_test() {
        Screen::Signing { back } => {
            assert!(
                matches!(back.as_ref(), Screen::Picked { .. }),
                "and the park is untouched"
            )
        }
        other => panic!(
            "a refused second start cannot change the park, got {}",
            which(other)
        ),
    }
    let before = std::mem::discriminant(app.screen_ref_for_test());
    // And again from a caller standing on the painted Signing screen: still
    // refused, still the same park.
    app.start_sign_via_button_for_test(job(&d));
    assert!(app.worker_running_for_test());
    assert_eq!(
        std::mem::discriminant(app.screen_ref_for_test()),
        before,
        "a second start cannot double-park or replace the park"
    );

    // When its answer lands, the slot frees with it (exactly one reply drains;
    // a second poll finds nothing) — and the picker park is what retry keeps.
    let failed = openfirma_gui::wizard::SignOutcome::Failed(openfirma_gui::wizard::ErrorReport {
        plain: "no se pudo leer la clave".into(),
        technical: "does-not-exist.p12: No such file".into(),
    });
    app.deliver_sign_outcome_for_test(failed);
    assert!(
        !app.worker_running_for_test(),
        "a drained reply frees the slot"
    );
    match app.screen_ref_for_test() {
        Screen::Failed { back, .. } => {
            assert!(
                back.is_some(),
                "the parked picker is retry's starting point"
            );
        }
        other => panic!(
            "a failed job lands Failed with its picker behind it, got {}",
            which(other)
        ),
    }
    assert!(
        app.poll_worker_for_test().is_none(),
        "one reply, drained once"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn pin_backed_rows_survive_from_document_to_document() {
    // A-6's catalog half: rows whose store was opened (their thunk holds the
    // logged-in Arc) are reused across documents; a pending .p12 (a password
    // that belongs to one file dialog, not to a session) is not. This is what
    // "one card login, any number of documents" is at the state level.
    let dir = std::env::temp_dir().join(format!("openfirma-rows-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let d = doc(&dir);
    let mut app = App::default();
    let row_path = d.clone();
    let row = CertificateChoice {
        display: "ANA".into(),
        origin: "pkcs11:/m.so".into(),
        issuer: None,
        valid_until: None,
        badges: Vec::new(),
        source: Some(Arc::new(move || KeySource::P12 {
            path: row_path.clone(),
            password: zeroize::Zeroizing::new(String::new()),
            alias: None,
            display: "ANA".into(),
        })),
        pending_p12: None,
    };
    let mut screen = picker(&d);
    if let Screen::Picked { catalog, .. } = &mut screen {
        catalog.entries.push(row);
    }
    app.set_screen_for_test(screen);

    // Sign another document: the same App asked for nothing; its rows carry
    // over (the reusable catalog is what `load_path` builds from).
    let second = dir.join("otro.pdf");
    std::fs::write(&second, b"%PDF-1.4 two").unwrap();
    app.load_second_document_for_test(second.clone());
    match app.screen_ref_for_test() {
        Screen::Picked { catalog, .. } => {
            assert_eq!(catalog.entries.len(), 1, "the logged-in store row survived");
            assert_eq!(catalog.entries[0].display, "ANA");
        }
        other => panic!(
            "the second document opens its own picker, got {}",
            which(other)
        ),
    }
    std::fs::remove_dir_all(&dir).ok();
}
