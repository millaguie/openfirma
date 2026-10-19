//! The one-job-in-flight rule (review 06 A-1), tested as the state machine it
//! is — no threads, no widgets: a job parks the picker behind `Signing`, and
//! while that park stands there is no way to start a second job. The eframe
//! spinner frame is kittest-timing territory (a local worker answers before
//! the next paint), so this owns the *rule*; `tests/ui.rs` drives the same
//! transition through widgets and drains the real thread's reply.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use openfirma_gui::app::App;
use openfirma_gui::wizard::{
    CertCatalog, CertificateChoice, ErrorReport, KeySource, OpenStoreOutcome, Screen, SignJob,
    SignOutcome,
};

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
        S::OpeningStore { .. } => "OpeningStore",
        S::Verifying { .. } => "Verifying",
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

/// A picker with no rows and no errors, ready to have a store open folded in.
fn empty_picker(path: &Path) -> Screen {
    picker(path)
}

fn failure(which: &str) -> OpenStoreOutcome {
    OpenStoreOutcome::Failed {
        descriptor: which.to_string(),
        report: ErrorReport {
            plain: "keystore refused".into(),
            technical: "PKCS#11: no token present".into(),
        },
    }
}

#[test]
fn opening_a_store_parks_the_picker_and_replaces_its_own_line() {
    // 06-N-10, the state half: opening a keystore ran inside the frame and
    // every failed click pushed ANOTHER identical red line, so the fifth click
    // landed on a different button than the first (the review's
    // `26b-other.png`). The park is the job's; the line is per store.
    let dir = std::env::temp_dir().join(format!("openfirma-store-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let d = doc(&dir);
    let mut app = App::default();
    // The starter parks the picker (production reaches it from the form; this
    // asserts the screen the job hands back to).
    app.set_screen_for_test(Screen::OpeningStore {
        back: Box::new(empty_picker(&d)),
    });

    let dead = "pkcs11:/no/existe/modulo.so";
    app.deliver_store_outcome_for_test(failure(dead));
    let lines = |app: &App| match app.screen_ref_for_test() {
        Screen::Picked { catalog, .. } => catalog.errors.clone(),
        other => panic!("the picker must come back, got {}", which(other)),
    };
    let once = lines(&app);
    assert_eq!(once.len(), 1, "one store, one line: {once:?}");
    assert!(once[0].starts_with(dead), "{once:?}");
    assert!(
        once[0].contains("no se ha podido abrir el almacén"),
        "the line leads in Spanish (06-N-10): {once:?}"
    );

    // The same dead store clicked five times: still exactly one line, and not
    // five.
    for _ in 0..4 {
        let back = app.take_screen_for_test();
        app.set_screen_for_test(Screen::OpeningStore {
            back: Box::new(back),
        });
        app.deliver_store_outcome_for_test(failure(dead));
    }
    let lines_after = lines(&app);
    assert_eq!(
        lines_after.len(),
        1,
        "five clicks, one line: {lines_after:?}"
    );

    // A second store's line does not touch the first's, and a store that
    // opens carrying no signable certificate says so in its own line.
    let other = "nss";
    {
        let back = app.take_screen_for_test();
        app.set_screen_for_test(Screen::OpeningStore {
            back: Box::new(back),
        });
        app.deliver_store_outcome_for_test(failure(other));
    }
    let two = lines(&app);
    assert_eq!(two.len(), 2, "one line per store: {two:?}");
    {
        let back = app.take_screen_for_test();
        app.set_screen_for_test(Screen::OpeningStore {
            back: Box::new(back),
        });
        app.deliver_store_outcome_for_test(OpenStoreOutcome::Opened {
            descriptor: dead.to_string(),
            entries: Vec::new(),
            pin: None,
        });
    }
    let after_open = lines(&app);
    assert_eq!(
        after_open.len(),
        2,
        "the dead store's line was replaced, not added to: {after_open:?}"
    );
    assert!(
        after_open
            .iter()
            .any(|l| l.contains(dead)
                && l.contains("no contiene ningún certificado con clave privada")),
        "{after_open:?}"
    );
    assert!(
        after_open.iter().any(|l| l.starts_with(other)),
        "the other store's line is untouched: {after_open:?}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_worker_that_dies_leaves_a_sentence_not_a_spinner() {
    // 06-N-11: a thread that vanished (a panic, an OS refusal) used to read as
    // "not yet" forever, so the window spun on a job nobody was running. The
    // park comes back and the window says what happened.
    let dir = std::env::temp_dir().join(format!("openfirma-dead-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let d = doc(&dir);
    let mut app = App::default();
    app.set_locale_for_test(openfirma_gui::strings::Tr::es());
    app.set_screen_for_test(Screen::Signing {
        back: Box::new(picker(&d)),
    });
    app.kill_worker_for_test();
    assert!(app.worker_running_for_test());
    app.poll_worker_for_test();
    assert!(
        !app.worker_running_for_test(),
        "the dead slot is released: it is not a job"
    );
    match app.screen_ref_for_test() {
        Screen::Picked { .. } => {}
        other => panic!("the park must come back, got {}", which(other)),
    }
    assert_eq!(
        app.pending_note_for_test(),
        Some(openfirma_gui::strings::Tr::es().fail_worker_died)
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_time_stamp_nobody_checked_is_said_on_the_done_screen() {
    // Review M-11: every token this window embeds is accepted on its imprint
    // alone — nothing here knows which TSA to trust — and that fact lived only
    // on the stderr of whoever started the window from a terminal. A green
    // "Firma guardada" that silently carried an unchecked stamp is the same
    // class of false comfort the verify side refuses.
    let dir = std::env::temp_dir().join(format!("openfirma-tsa-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let d = doc(&dir);
    let done = |checked: bool| SignOutcome::Done {
        signature: b"%PDF-1.4 firmado".to_vec(),
        output: d.with_extension("signed.pdf"),
        format_label: "PAdES-B-B".into(),
        signer_display: "ANA".into(),
        tsa_token_unchecked: checked,
    };

    let mut app = App::default();
    app.set_locale_for_test(openfirma_gui::strings::Tr::es());
    app.set_screen_for_test(Screen::Signing {
        back: Box::new(picker(&d)),
    });
    app.deliver_sign_outcome_for_test(done(true));
    assert!(
        matches!(app.screen_ref_for_test(), Screen::Done { .. }),
        "an unchecked stamp never turns a signature into a failure"
    );
    assert_eq!(
        app.pending_note_for_test(),
        Some(openfirma_gui::strings::Tr::es().fail_tsa_unverified)
    );

    // No stamp, no note: the sentence is about the stamp, not about signing.
    let mut app = App::default();
    app.set_locale_for_test(openfirma_gui::strings::Tr::es());
    app.set_screen_for_test(Screen::Signing {
        back: Box::new(picker(&d)),
    });
    app.deliver_sign_outcome_for_test(done(false));
    assert!(matches!(app.screen_ref_for_test(), Screen::Done { .. }));
    assert_eq!(app.pending_note_for_test(), None);
    std::fs::remove_dir_all(&dir).ok();
}
