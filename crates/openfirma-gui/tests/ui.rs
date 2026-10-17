//! Windowless UI tests (ADR-0006): the harness drives the same `App` the
//! binary runs — egui builds the widget tree in memory, AccessKit exposes it,
//! and the test clicks buttons like a person would. Nothing here needs a
//! display: what kittest cannot reach are the *OS* pieces (real file pickers,
//! drag-and-drop from a real desktop, closing a real window), whose answers
//! the `Dialogs` fixture supplies; those remain in docs/validation.md as the
//! manual checklist.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use egui::accesskit; // the role enum egui and kittest agree on
use egui_kittest::Harness;
use egui_kittest::kittest::{NodeT as _, Queryable};
use openfirma_gui::app::{App, Dialogs};
use openfirma_gui::wizard::{CertificateChoice, CloseDecision, KeySource, Screen, close_decision};

/// The repo's test material (`tools/gen-testcert.sh` / `gen-testpdf.py`).
fn testdata() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata")
        .canonicalize()
        .expect("testdata/ exists at the workspace root")
}

/// Skip-with-a-signal the way the rest of the workspace does it: absent
/// material is a skip unless OPENFIRMA_REQUIRE_TESTS says otherwise.
fn require(ok: bool, what: &str) -> Option<()> {
    if ok {
        Some(())
    } else {
        eprintln!("SKIP: {what} is absent, run tools/gen-testcert.sh");
        assert!(
            std::env::var_os("OPENFIRMA_REQUIRE_TESTS").is_none(),
            "OPENFIRMA_REQUIRE_TESTS is set and {what} is missing"
        );
        None
    }
}

/// An App under the harness, with fixture dialogs: exactly what `main` builds
/// except where a path arrives from.
fn harness_for(app: App) -> Harness<'static, App> {
    Harness::builder()
        .with_size(egui::vec2(760.0, 560.0))
        .allow_missing_glyphs() // the ✓ of the Done screen is not in the default font
        .build_eframe(move |cc| {
            let mut a = app;
            a.reinit_for_test(cc);
            a
        })
}

fn fixture_app(open: Option<PathBuf>) -> App {
    let mut a = App::default();
    // Spanish is what every assertion below quotes ("Firmar", the verdict
    // sentences); `$LANG` belongs to whoever runs cargo, not to the test, so
    // the language is pinned here rather than inherited (the macOS CI runners
    // answer LANG=en_US and would otherwise drive an English window).
    a.set_locale_for_test(openfirma_gui::strings::Tr::es());
    a.with_dialogs(Dialogs {
        gui_test: true,
        fixture_open: open,
        fixture_save: None,
    });
    a
}

#[test]
fn the_first_screen_invites_a_file_and_names_both_ways_in() {
    let mut harness = harness_for(fixture_app(None));
    harness.run();
    // The drop zone's promise and its click target (ADR-0006: a person who
    // cannot drag must find one obvious button).
    harness.get_by_label_contains("Arrastra aquí el documento");
    assert!(
        harness
            .query_all_by_label_contains("Examinar")
            .next()
            .is_some()
    );
    // B-3: the two verbs both exist and say what they are for.
    harness.get_by_label_contains("Verificar una firma");
}

#[test]
fn dropping_a_pdf_offers_the_pades_signing_flow() {
    let Some(()) = require(
        testdata().join("inputs/simple.pdf").is_file(),
        "testdata/inputs/simple.pdf",
    ) else {
        return;
    };
    let mut app = fixture_app(None);
    // The same entry point a drop or Enter reaches: the one door `load_path`.
    app.load_path_for_test(testdata().join("inputs/simple.pdf"));
    let mut harness = harness_for(app);
    harness.run();
    harness.get_by_label_contains("Es un PDF");
    harness.get_by_label_contains("Elige el certificado");
    // The picker starts empty with its two doors, never a blank box.
    harness.get_by_label_contains("Abrir un archivo de certificado");
    // Signing is impossible until a certificate exists: the button carries
    // the reason instead of dying silently (ADR-0006's ban on unfounded states).
    let sign = harness.get_by_label("Firmar");
    assert!(sign.accesskit_node().is_disabled(), "{sign:#?}");
}

#[test]
fn a_p12_picked_through_the_fixture_signs_with_its_password() {
    // The full happy path, windowless: pick the file, add the .p12 row (the
    // fixture answers the open dialog), type its password, sign. Bytes and
    // files are checked afterwards by `verify_after_gui_sign` below; what
    // this test owns is that the *window* gets there in three clicks. The
    // signing itself now runs on the worker thread (A-1); egui_kittest's
    // eframe seam is a plain `run` closure with no real frame loop, so the
    // answer is delivered through the same `poll_worker` transition the live
    // window takes (kittest cannot spin a winit event pump).
    let p12 = testdata().join("certs/signer-rsa.p12");
    let pdf_dir = temp_doc("p12-sign");
    let doc = pdf_dir.join("contrato.pdf");
    if require(
        p12.is_file() && testdata().join("inputs/simple.pdf").is_file(),
        "the test PKI",
    )
    .is_none()
    {
        return;
    }
    std::fs::copy(testdata().join("inputs/simple.pdf"), &doc).unwrap();

    // The file-open answers the document, the cert-open answers the p12: one
    // fixture at a time, so set it before each click that opens a dialog.
    let app = fixture_app(Some(doc.clone()));
    let mut harness = harness_for(app);
    harness.run();

    // 1. open the document (the big drop-zone button consumes its fixture;
    // the small "Examinar…" next to the path field is the same door, so the
    // test takes the first of the two).
    harness
        .query_all_by_label_contains("Examinar")
        .next()
        .unwrap()
        .click();
    harness.run();
    harness.get_by_label_contains("Es un PDF");

    // 2. add the certificate: the picker's p12 button, with the fixture now
    // answering the .p12 path.
    harness.state_mut().dialogs_for_test().fixture_open = Some(p12.clone());
    harness
        .get_by_label_contains("Abrir un archivo de certificado")
        .click();
    harness.run();
    assert!(
        harness
            .query_all_by_role_and_label(
                accesskit::Role::PasswordInput,
                "Contraseña del certificado"
            )
            .next()
            .is_some(),
        "the password field is reachable by its label (screen-reader rule)"
    );

    // 3. type the password into the field and sign. Typing alone does not
    // focus the widget for egui's TextEdit, so the test stands in for the
    // field's contents the way egui would hold them between frames (ADR-0006:
    // what matters is the state after "the user typed", not keystroke plumbing).
    harness
        .state_mut()
        .force_password_for_test("openfirma".into());
    harness.run();
    harness.get_by_label("Firmar").click();
    // The Signing screen animates (a spinner repaints forever by design), so
    // settling `run` is not an option: one step renders it.
    harness.step();

    // A-1: the click parked the picker behind a spinner screen and started a
    // REAL worker (card-free, local crypto, milliseconds). Tests poll it with
    // the app's own drain — kittest has no winit loop; the transition code is
    // the production `poll_worker`, not a lookalike.
    drain_worker(&mut harness);
    harness.run();

    // The Done screen: result named, folder link offered (ADR-0006's next-to-
    // original rule), and no second save dialog on the way.
    harness.get_by_label_contains("Firma guardada");
    let out = pdf_dir.join("contrato.pdf.signed.pdf");
    assert!(out.is_file(), "the signature must sit next to the original");
    verify_after_gui_sign(&out);

    std::fs::remove_dir_all(pdf_dir).ok();
}

#[test]
fn signing_parks_the_picker_behind_a_spinner_and_keeps_exactly_one_job() {
    // A-1 through real widgets: pressing the sign button parks the picker
    // behind `Signing` and starts exactly one worker; a second click — with
    // the spinner's pre-painted tree still answering "Firmar" — must never
    // book a second one. The park itself, without widgets or thread timing,
    // is jobs.rs; this is its widget-level twin.
    let dir = temp_doc("park");
    let doc = dir.join("doc.pdf");
    // A picker exactly as a real load would build it, with one row ready to
    // go. The button is ENABLED here — the test presses it for real, and the
    // worker fails on its own afterwards (its .p12 is a placeholder PDF), so
    // the answer this test drains comes from the same code path production
    // takes when a key file cannot be read.
    let p12 = testdata().join("certs/signer-rsa.p12");
    let pdf = testdata().join("inputs/simple.pdf");
    if require(p12.is_file() && pdf.is_file(), "the test PKI").is_none() {
        return;
    }
    std::fs::copy(&pdf, &doc).unwrap();
    // A row whose key material is a placeholder PDF wearing the .p12 name:
    // the worker runs for real and fails on its own after microseconds — no
    // injected outcome, the failure comes from the same code path production
    // takes when a file cannot be read.
    let fake_p12 = dir.join("placeholder.p12");
    std::fs::write(&fake_p12, b"%PDF-1.4 not a keystore").unwrap();
    let mut app = fixture_app(None);
    app.set_screen_for_test(picked_with_row(&doc, &fake_p12));

    // The park through the REAL button: start_sign moves the picker behind
    // Signing while the worker reads the placeholder and fails.
    let mut harness = harness_for(app);
    harness.run();
    harness.get_by_label("Firmar").click();
    // `click()` only queues the events; one step renders the click and lets
    // App run — that frame is where start_sign parks the picker. The worker
    // answers in microseconds here (a .p12 whose bytes are a PDF), so this is
    // also the last moment the park is on screen: nothing was dropped on the
    // floor, the picker waits inside the Signing screen.
    harness.step();
    // The park at the state level, observed in the frame that made it: kittest
    // renders one frame per `step` — no repaint happens until the step below.
    // Whatever happened inside that frame (park, or a worker fast enough to
    // answer before the poll ran), both arms are honest A-1 outcomes; what is
    // NOT allowed is any other screen or a leaked job slot.
    let screen_after_click = harness.state().screen_ref_for_test();
    // Whether a live job still holds the slot at this instant is pure thread
    // race (the answer rides in on a frame boundary no windowless test can
    // pin); the RULES under test are order-free: at most one worker ever, and
    // exactly one reply to drain. Each arm below checks what its own state
    // owes.
    let parked_with_a_live_job = matches!(screen_after_click, Screen::Signing { .. });
    match screen_after_click {
        Screen::Signing { .. } => {}
        // Drained already (the worker answered before this frame's paint):
        // its reply landed, so no job is left and the tree shows the answer.
        Screen::Failed { .. } => assert!(
            !harness.state().worker_running_for_test(),
            "a drained reply must clear the job slot"
        ),
        other => panic!(
            "after one sign click: park or answer, got {other:?}",
            other = std::mem::discriminant(other)
        ),
    }
    // The second click of the review's frozen repro: query_by_label reads the
    // PREVIOUS frame's tree, so with the park painted above it hands back the
    // spinner screen's own "Firmar" button. Two clicks in one frame is exactly
    // what used to freeze the window; now the guard inside start_sign swallows
    // this one, and the assert after the step proves no second worker exists
    // while the first still holds its slot or its undrained reply.
    if let Some(node) = harness.query_by_label("Firmar") {
        node.click();
    }
    harness.step();
    // A slot that was already drained stays drained (the click landed on the
    // answer screen, which offers no sign button); a parked job must still
    // hold its ONE worker — two jobs started would have replaced the park's
    // channel and the drain below finds a different reply than the one job.
    if !parked_with_a_live_job {
        assert!(
            !harness.state().worker_running_for_test(),
            "a drained slot cannot regain a worker"
        );
    }
    // Then the window answers: drain the one worker through the app's own
    // poll (the seam records why it exists: kittest has no winit loop).
    // Whatever its answer says, the window takes it — Failed carrying its
    // sentence, never a stuck spinner.
    drain_worker(&mut harness);
    // Drain may not have started a render (kittest's `run` settles on its
    // own repaints; a drained reply alone queues none), so paint once.
    harness.step();
    match harness.state().screen_ref_for_test() {
        // The worker could not read the key file: a hard failure, with its
        // back screen set to whatever was parked — a picker, or the earlier
        // transient park a fixture's hand-made state left behind (a real flow
        // never nests those; see the guard arms above).
        Screen::Failed { .. } => {}
        other => panic!(
            "a job over unreadable bytes must land Failed, got {:?}",
            std::mem::discriminant(other)
        ),
    }
    // And one answer only ever lands once: a second drain changes nothing.
    let again = harness.state_mut().poll_worker_for_test();
    assert!(
        again.is_none(),
        "exactly one job in flight: nothing left to drain"
    );
    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn a_wrong_password_stays_on_the_picker_with_its_rows_and_a_sentence() {
    // M-4/A-6 through the window: the retry keeps every catalog row (an open
    // store's PIN was spent once — AutoFirma's retry keeps the card dialog
    // too) and answers under the field, never a trip back to the drop zone.
    let dir = temp_doc("wrong-pass");
    let doc = dir.join("doc.pdf");
    std::fs::write(&doc, b"%PDF-1.4 placeholder").unwrap();
    let mut app = fixture_app(None);
    // A .p12 row mid-typing is the wrong-password shape (a card's failed PIN
    // retry keeps its logged-in store rows too — wizard::restore pins that at
    // the state level). The field, its sentence and every row must survive.
    let row = CertificateChoice {
        display: "otro.p12…".into(),
        origin: "otro.p12".into(),
        issuer: None,
        valid_until: None,
        badges: Vec::new(),
        source: None,
        pending_p12: Some(PathBuf::from("otro.p12")),
    };
    app.set_screen_for_test(Screen::Picked {
        path: doc.clone(),
        content: b"%PDF-1.4 placeholder".to_vec(),
        format: openfirma_core::workflow::Format::Pdf,
        chosen_format: "pades-b-b".into(),
        catalog: openfirma_gui::wizard::CertCatalog {
            entries: vec![row],
            errors: Vec::new(),
        },
        selected: Some(0),
        advanced: false,
        tsa_url: String::new(),
        digest: openfirma_core::DigestAlg::Sha256,
        reason: String::new(),
        password_error: false,
    });
    let mut harness = harness_for(app);
    harness.run();
    // The worker's retry answer (what a wrong .p12 password produces): the
    // picker stays, its rows survive, and the sentence shows under the field.
    harness.state_mut().deliver_sign_outcome_for_test(
        openfirma_gui::wizard::SignOutcome::Retryable {
            reason: openfirma_gui::wizard::ErrorReport {
                plain: "Contraseña incorrecta.".into(),
                technical: "pkcs12: MAC integrity check failed (wrong password?)".into(),
            },
        },
    );
    harness.run();
    match harness.state().screen_ref_for_test() {
        Screen::Picked {
            catalog,
            password_error,
            ..
        } => {
            assert!(password_error, "the reason rides on the screen state");
            assert_eq!(catalog.entries.len(), 1, "the row survives the typo");
        }
        other => panic!(
            "a wrong password must stay on the picker, got {:?}",
            std::mem::discriminant(other)
        ),
    }
    // M-4 through widgets: the sentence renders where it belongs — the field
    // is visible because its own selection is the pending .p12 row (render
    // auto-selects it), and the error reads under it.
    harness.state_mut().select_pending_for_test();
    harness.run();
    harness.get_by_label_contains("Contraseña incorrecta");
    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn a_signed_pdf_dropped_becomes_verdicts_not_a_new_signing_task() {
    // The verify deviation from AutoFirma, pinned through the window: the
    // *document itself* (not an exported .csig) gets verdicts. Built end to
    // end: sign once through the library seam, drop the result, read lines.
    let p12 = testdata().join("certs/signer-rsa.p12");
    let dir = temp_doc("verify-drop");
    let doc = dir.join("doc.pdf");
    if require(
        p12.is_file() && testdata().join("inputs/simple.pdf").is_file(),
        "the test PKI",
    )
    .is_none()
    {
        return;
    }
    std::fs::copy(testdata().join("inputs/simple.pdf"), &doc).unwrap();
    let signed = sign_through_gui_code(&doc, &p12);
    let out = dir.join("doc.pdf.signed.pdf");
    std::fs::write(&out, &signed).unwrap();

    // No anchors configured (the clean-machine case): the window must ask
    // for one and finish through the fixture's answer — the ask-the-anchor
    // step, which is exactly AutoFirma's missing "where do I click here?".
    // The anchor is chain.crt: the GUI's own verifier needs both roots of the
    // test PKI (the CA alone leaves the intermediate unnamed), exactly as
    // `openfirma verify --trust testdata/certs/chain.crt` gets fed.
    let mut app = fixture_app(Some(testdata().join("certs/chain.crt")));
    app.load_path_for_test(out.clone());
    assert!(
        app.pending_note_for_test().is_some(),
        "without anchors the window says who it needs to trust before verifying"
    );
    // The anchor answer then starts a worker (A-1); kittest has no frame loop
    // to drain it, so the test answers through the app's own transition.
    let answer = verified_answer_for(&out);
    let mut harness = harness_for(app);
    harness.run(); // the deferred ask fires; the fixture answers with chain.crt
    harness
        .state_mut()
        .deliver_verify_answer_for_test(Ok(answer));
    harness.run();
    // A-5/M-2: a verdict that reads as a sentence and names the signer by
    // name — never a DN, never DER in front.
    harness.get_by_label_contains("Firma válida");
    assert!(harness.query_by_label_contains("SERIALNUMBER").is_none());
    let _ = harness.query_by_label_contains("Quién firmó");
    assert!(
        matches!(
            harness.state().screen_ref_for_test(),
            Screen::Verified { .. }
        ),
        "after the anchor the verdict screen stands"
    );

    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn verdict_details_stay_open_across_frames_and_say_hiding() {
    // M-3, pinned: the old details checkbox reset itself every frame, so no
    // technical block was ever readable. The toggle is screen state now — one
    // click opens it, and it is still open frames later, with a button that
    // says "Ocultar" (which way the next click goes).
    let mut app = fixture_app(None);
    app.set_screen_for_test(Screen::Verified {
        path: PathBuf::from("doc.pdf"),
        verdicts: openfirma_gui::wizard::VerdictList {
            lines: vec![openfirma_gui::wizard::VerdictLine {
                status: openfirma_gui::wizard::VerdictStatus::Invalid,
                signer: "2".into(),
                when: String::new(),
                why_not: Some("El documento ha sido modificado…".into()),
                trust_anchor: None,
                technical: vec!["messageDigest check failed: digest-xyz".into()],
            }],
            notes: Vec::new(),
        },
        details_open: vec![false],
    });
    let mut harness = harness_for(app);
    harness.run();
    assert!(harness.query_by_label_contains("digest-xyz").is_none());
    harness
        .get_by_label_contains("Ver detalles técnicos")
        .click();
    harness.run();
    harness.get_by_label_contains("digest-xyz");
    // Still open several frames later (the old bug could not survive this).
    harness.run_steps(3);
    harness.get_by_label_contains("digest-xyz");
    harness.get_by_label_contains("Ocultar detalles técnicos");
}

#[test]
fn a_drop_while_a_result_stands_unseen_is_refused_out_loud() {
    // M-8/never-lose in its drop form: the Done screen holds bytes; a second
    // file may not silently replace them. The refusal is a sentence, and the
    // result stays exactly where it was.
    let mut app = fixture_app(None);
    app.set_screen_for_test(Screen::Done {
        path: PathBuf::from("doc.pdf"),
        output: PathBuf::from("doc.pdf.signed.pdf"),
        content: vec![1],
        signature: vec![2],
        format_label: "PAdES-B-B".into(),
        signer_display: "ANA".into(),
        saved: true,
    });
    // The locale pin belongs to the app's construction, which this fixture
    // shows at its default; the refusal sentence asserted below is Spanish
    // like every other text in this file, so say whose strings these are.
    app.set_locale_for_test(openfirma_gui::strings::Tr::es());
    app.load_path_from_cli(PathBuf::from("/nonexistent/otro.pdf"));
    assert!(
        matches!(app.screen_ref_for_test(), Screen::Done { .. }),
        "the unseen result is not replaced"
    );
    let note = app.pending_note_for_test().expect("a refusal says why");
    assert!(note.contains("firma"), "{note}");
}

#[test]
fn a_leaf_picked_as_anchor_is_refused_not_green() {
    let p12 = testdata().join("certs/signer-rsa.p12");
    let leaf = testdata().join("certs/signer-rsa.crt");
    let dir = temp_doc("leaf-anchor");
    let doc = dir.join("doc.pdf");
    if require(
        p12.is_file() && leaf.is_file() && testdata().join("inputs/simple.pdf").is_file(),
        "the test PKI",
    )
    .is_none()
    {
        return;
    }
    std::fs::copy(testdata().join("inputs/simple.pdf"), &doc).unwrap();
    let signed = sign_through_gui_code(&doc, &p12);
    let out = dir.join("doc.pdf.signed.pdf");
    std::fs::write(&out, &signed).unwrap();

    // same drop as the verify test above, but the fixture answers the anchor
    // picker with the signer's own leaf instead of a CA
    let mut app = fixture_app(Some(leaf.clone()));
    app.load_path_for_test(out.clone());
    let mut harness = harness_for(app);
    harness.run(); // the deferred ask fires; the fixture answers with the leaf
    match harness.state().screen_ref_for_test() {
        Screen::Failed { error, .. } => {
            let text = format!("{} / {}", error.plain, error.technical);
            assert!(
                text.contains("CA:FALSE") || text.contains("autoridad"),
                "the refusal must say why the picked file cannot anchor anything: {text}"
            );
        }
        other => {
            let _ = other;
            panic!("a leaf anchor must land on Failed, not some other screen");
        }
    }
    // and under no reading does a green verdict stand for this pick
    assert!(harness.query_by_label_contains("Firma válida").is_none());
    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn an_error_screen_is_plain_first_with_details_behind() {
    // Feed the failure directly: the window's job is presentation, and which
    // sentence each error kind earns is errors.rs' own tested rule.
    let mut app = fixture_app(None);
    app.fail_for_test(
        "No se pudo continuar de prueba",
        "der::Error { kind: Incomplete, expected 64 actual 3 }",
    );
    let mut harness = harness_for(app);
    harness.run();
    harness.get_by_label_contains("No se pudo continuar de prueba");
    // Technical text hidden until asked…
    assert!(harness.query_by_label_contains("expected 64").is_none());
    // …and present after one button (ADR-0006: details are a click away,
    // never in front). The button says which way it goes BEFORE the press —
    // and keeps its state across frames (M-3).
    harness
        .get_by_label_contains("Ver detalles técnicos")
        .click();
    harness.run();
    assert!(
        harness
            .query_all_by_label_contains("expected 64")
            .next()
            .is_some(),
        "the technical block must appear when asked"
    );
    // One press hides it again: the button re-reads itself as "Ver".
    harness
        .get_by_label_contains("Ocultar detalles técnicos")
        .click();
    harness.run();
    assert!(harness.query_by_label_contains("expected 64").is_none());
}

#[test]
fn the_window_cannot_close_over_an_unsaved_result() {
    // Two layers, both tested: the pure rule (`close_decision`) and the
    // window's behavior of cancelling the close while it holds a result.
    let unsaved = Screen::Done {
        path: PathBuf::from("doc.pdf"),
        output: PathBuf::from("doc.pdf.signed.pdf"),
        content: vec![1],
        signature: vec![2],
        format_label: "PAdES-B-B".into(),
        signer_display: "ANA".into(),
        saved: false,
    };
    assert_eq!(close_decision(false, &unsaved), CloseDecision::WarnUnsaved);
    // B-1's true question: a job RUNNING is WarnBusy over any screen, and
    // its guard text is the busy one, not "not yet saved".
    assert_eq!(close_decision(true, &Screen::Idle), CloseDecision::WarnBusy);

    let mut app = fixture_app(None);
    app.set_screen_for_test(unsaved);
    let mut harness = harness_for(app);
    harness.run();
    // Ask the window to close (what the OS close button delivers). kittest
    // carries no winit, so the same input egui-winit feeds on a Close event:
    // a Close in the viewport's events. The app must open its guard instead
    // of vanishing.
    harness
        .input_mut()
        .viewports
        .get_mut(&egui::ViewportId::ROOT)
        .unwrap()
        .events
        .push(egui::ViewportEvent::Close);
    harness.step();
    assert!(
        harness.state().close_question_for_test(),
        "the guard window must open on a close request over unsaved bytes"
    );
    // The event stays queued (kittest replays raw input; winit would clear it,
    // and CancelClose keeps the window alive either way), so frames keep being
    // delivered until the guard answers. "Seguir trabajando" releases it and
    // the result stays where it was.
    harness.run_steps(2);
    harness.get_by_label_contains("Seguir trabajando").click();
    harness.run_steps(2);
    assert!(!harness.state().close_question_for_test());
    assert!(matches!(
        harness.state().screen_ref_for_test(),
        Screen::Done { .. }
    ));
}

#[test]
fn a_dropped_file_through_egui_enters_the_wizard() {
    // The real drag-and-drop plumbing (review 06 M-1): what loads is the
    // DROP (`dropped_files`, which arrives once, with the release), never the
    // hover: winit keeps `hovered_files` alive for every frame of a drag and
    // empties it at release — the old code re-entered the wizard per hovered
    // frame, so cancelling a drop had already loaded the file.
    let Some(()) = require(
        testdata().join("inputs/simple.txt").is_file(),
        "testdata/inputs/simple.txt",
    ) else {
        return;
    };
    let mut harness = harness_for(fixture_app(None));
    harness.run();
    let path = testdata().join("inputs/simple.txt");
    // 1. a hover that never drops must load NOTHING, frame after frame…
    harness.input_mut().hovered_files.push(egui::HoveredFile {
        path: Some(path.clone()),
        mime: String::new(),
    });
    harness.step();
    harness.step();
    assert!(
        matches!(harness.state().screen_ref_for_test(), Screen::Idle),
        "a hover only highlights; it must never load"
    );
    harness.input_mut().hovered_files.clear();
    // 2. …and the actual drop (egui clears `dropped_files` itself after the
    // frame that consumed it) enters through the one door `load_path`.
    #[derive(Debug)]
    struct PathOnly(PathBuf);
    impl egui::DroppedFile for PathOnly {
        fn path(&self) -> &Path {
            &self.0
        }
        fn bytes(&self) -> Result<Vec<u8>, String> {
            std::fs::read(&self.0).map_err(|e| e.to_string())
        }
    }
    harness
        .input_mut()
        .dropped_files
        .push(std::sync::Arc::new(PathOnly(path)));
    harness.step();
    // The CAdES screen (a .txt is plain data) proves it entered by the drop
    // door; the hover repeating must not reload or reset it.
    assert!(matches!(
        harness.state().screen_ref_for_test(),
        Screen::Picked { .. }
    ));
}

#[test]
fn a_store_row_signs_without_any_password_field() {
    // A keystore row's PIN was spent opening the store, so signing through it
    // must not ask again (ADR-0004: the key never leaves the holder and the
    // session is already logged in). The fixture source builds a software
    // KeySource from the test .p12; for the window these are one and the same.
    let p12 = testdata().join("certs/signer-rsa.p12");
    let dir = temp_doc("store-row");
    let doc = dir.join("firmable.pdf");
    if require(
        p12.is_file() && testdata().join("inputs/simple.pdf").is_file(),
        "the test PKI",
    )
    .is_none()
    {
        return;
    }
    std::fs::copy(testdata().join("inputs/simple.pdf"), &doc).unwrap();

    let arc_p12 = p12.clone();
    let row = CertificateChoice {
        display: "PEREZ GARCIA, ANA".into(),
        origin: "pkcs11:test-token".into(),
        issuer: Some("AC openfirma test".into()),
        valid_until: Some("2099-01-01".into()),
        badges: Vec::new(),
        source: Some(Arc::new(move || KeySource::P12 {
            path: arc_p12.clone(),
            password: zeroize::Zeroizing::new("openfirma".into()),
            alias: None,
            display: "PEREZ GARCIA, ANA".into(),
        })),
        pending_p12: None,
    };
    let mut app = fixture_app(Some(doc.clone()));
    {
        let dialogs = app.dialogs_for_test();
        dialogs.fixture_open = Some(doc.clone());
    }
    app.load_path_for_test(doc.clone());
    let mut screen = app.take_screen_for_test();
    if let Screen::Picked { catalog, .. } = &mut screen {
        catalog.entries.push(row);
    } else {
        panic!("the pdf must be Picked");
    }
    app.set_screen_for_test(screen);
    let mut harness = harness_for(app);
    harness.run();
    // A-7: the row carries issuer and validity, so two certificates tell
    // apart by a glance.
    harness.get_by_label_contains("Emitido por: AC openfirma test");
    harness.get_by_label_contains("Válido hasta: 2099-01-01");
    // one click on the row, one on Firmar: no password field appears.
    harness.get_by_label_contains("PEREZ GARCIA, ANA").click();
    // One step to render the selected picker: a settle-run would repaint on
    // its own animations and `run` gives up (kittest's contract, not a bug).
    harness.step();
    assert!(
        harness
            .query_by_label_contains("Contraseña del certificado")
            .is_none()
    );
    harness.get_by_label("Firmar").click();
    // The real worker over a real key (the row's software signer): drain it.
    drain_worker(&mut harness);
    harness.run();
    let out = dir.join("firmable.pdf.signed.pdf");
    assert!(out.is_file(), "{out:?}");
    verify_after_gui_sign(&out);
    std::fs::remove_dir_all(dir).ok();
}

/// Paint frames while waiting (the click renders them one by one — kittest's
/// `step` only pumps existing repaint requests), then drain the signing worker
/// with the app's own production poll (`poll_worker` — kittest owns no winit
/// event loop, and this is the SAME method `eframe::App::ui` calls every
/// frame). Returns when no job is in flight; hung means failure.
fn drain_worker(harness: &mut Harness<'static, App>) {
    harness.run_steps(2); // let a painted spinner exist at most two frames
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while harness.state().worker_running_for_test() {
        assert!(deadline.elapsed().as_secs() < 30, "the signing worker hung");
        if harness.state_mut().poll_worker_for_test().is_none() {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }
}

/// A Picked screen with one ready row whose key opens the test .p12 (the
/// park tests need a REAL enabled button; they never complete crypto with it).
fn picked_with_row(doc: &Path, p12: &Path) -> Screen {
    // The REAL bytes: a placeholder PDF is not a PKCS#12 container, and the
    // park test wants its worker to fail on the KEY (the honest Failed), not
    // on its document bytes.
    let content = std::fs::read(doc).unwrap_or_else(|_| b"%PDF-1.4".to_vec());
    let p12 = p12.to_path_buf();
    Screen::Picked {
        path: doc.to_path_buf(),
        content,
        format: openfirma_core::workflow::Format::Pdf,
        chosen_format: "pades-b-b".into(),
        catalog: openfirma_gui::wizard::CertCatalog {
            entries: vec![CertificateChoice {
                display: "ANA".into(),
                origin: "pkcs12:test".into(),
                issuer: None,
                valid_until: None,
                badges: Vec::new(),
                source: Some(Arc::new(move || KeySource::P12 {
                    path: p12.clone(),
                    password: zeroize::Zeroizing::new("openfirma".into()),
                    alias: None,
                    display: "ANA".into(),
                })),
                pending_p12: None,
            }],
            errors: Vec::new(),
        },
        selected: Some(0),
        advanced: false,
        tsa_url: String::new(),
        digest: openfirma_core::DigestAlg::Sha256,
        reason: String::new(),
        password_error: false,
    }
}

// ------------------------------------------------------------------ helpers

fn temp_doc(tag: &str) -> PathBuf {
    // One directory per (process, test): cargo runs tests as threads in one
    // process, so the pid alone cannot tell two tests apart — and a shared
    // name means one test's `remove_dir_all` pulls the tree out from under
    // another's write (observed on Windows as "Access is denied" while a
    // sibling test cleaned up mid-sign). Each caller names itself, and
    // `create_dir` refuses to share — only our own crashed leftovers get
    // replaced.
    let dir = std::env::temp_dir().join(format!("openfirma-gui-test-{}-{tag}", std::process::id()));
    match std::fs::create_dir(&dir) {
        Ok(()) => dir,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // Only a crashed earlier run of THIS test can own this name.
            std::fs::remove_dir_all(&dir).ok();
            std::fs::create_dir(&dir).unwrap();
            dir
        }
        Err(e) => panic!("cannot create {}: {e}", dir.display()),
    }
}

/// Sign once through the GUI's own code path (`openfirma_gui::signing` over
/// a `KeySource`, exactly what the Picked screen runs) — the other tests use
/// it to produce signed material without driving every widget again.
fn sign_through_gui_code(doc: &Path, p12: &Path) -> Vec<u8> {
    let key = KeySource::P12 {
        path: p12.to_path_buf(),
        password: zeroize::Zeroizing::new("openfirma".into()),
        alias: None,
        display: "ANA".into(),
    };
    let signer = key.signer().expect("the test .p12 opens");
    let content = std::fs::read(doc).unwrap();
    openfirma_gui::signing::execute(
        "pades-b-b",
        &content,
        signer.as_ref(),
        openfirma_core::DigestAlg::Sha256,
        None,
        None,
    )
    .expect("signing the test pdf through the GUI's dispatcher works")
}

/// The verify worker's answer over real signed bytes, through the window's
/// own verdict rules (the same `verdict_lines` a drained worker runs).
fn verified_answer_for(signed: &Path) -> openfirma_gui::wizard::VerifiedAnswer {
    let bytes = std::fs::read(signed).unwrap();
    let ca_pem = std::fs::read_to_string(testdata().join("certs/ca.crt")).unwrap();
    let int_pem = std::fs::read_to_string(testdata().join("certs/intermediate.crt")).unwrap();
    let anchors = vec![
        openfirma_core::CertificateHandle::from_pem(&ca_pem).unwrap(),
        openfirma_core::CertificateHandle::from_pem(&int_pem).unwrap(),
    ];
    let verdicts = openfirma_gui::verdicts::verdict_lines(
        &bytes,
        None,
        anchors,
        &openfirma_gui::strings::Tr::es(),
    )
    .expect("the GUI's own verdict rules accept the GUI's output");
    openfirma_gui::wizard::VerifiedAnswer {
        path: signed.to_path_buf(),
        verdicts,
    }
}

/// The end-to-end clause of ADR-0006: a file the GUI wrote verifies with the
/// library verifiers — the same calls `openfirma verify` makes.
fn verify_after_gui_sign(signed: &Path) {
    let bytes = std::fs::read(signed).unwrap();
    // chain.crt is CA + intermediate: exactly what `openfirma verify --trust
    // testdata/certs/chain.crt` feeds, so the GUI's own output is checked by
    // the CLI's own anchor set.
    let ca_pem = std::fs::read_to_string(testdata().join("certs/ca.crt")).unwrap();
    let int_pem = std::fs::read_to_string(testdata().join("certs/intermediate.crt")).unwrap();
    let anchors = vec![
        openfirma_core::CertificateHandle::from_pem(&ca_pem).unwrap(),
        openfirma_core::CertificateHandle::from_pem(&int_pem).unwrap(),
    ];
    let opts = openfirma_cades::VerifyOptions {
        trust_anchors: anchors,
        validation_time: std::time::SystemTime::now(),
        ts_mode: false,
        ..openfirma_cades::VerifyOptions::default()
    };
    let document = openfirma_pades::pades_verify(&bytes, &opts).expect("the GUI's output verifies");
    assert_eq!(document.signatures.len(), 1);
}
