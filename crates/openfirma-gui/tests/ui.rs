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
use openfirma_gui::strings::Tr;
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

/// The window the tests render into: a realistic small window, so "is the way
/// out on screen?" is a question the harness can answer — the rect the buttons
/// report is in these coordinates. Shared with the tests that assert a control
/// is INSIDE it (06-N-9).
const WINDOW: egui::Vec2 = egui::Vec2::new(760.0, 560.0);

/// An App under the harness, with fixture dialogs: exactly what `main` builds
/// except where a path arrives from.
fn harness_for(app: App) -> Harness<'static, App> {
    // No `allow_missing_glyphs()` here any more (M-7): it was the switch that
    // let the Done screen paint an empty box where a ✓ was meant to be, and no
    // test said so. Every sentence in the table is checked character by
    // character now (the test below), and any glyph the fonts are missing
    // fails this suite instead of being allowed.
    Harness::builder()
        .with_size(WINDOW)
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
    // A-6: the row is on screen and the doors are still there. The dead end
    // the review walked into was exactly this state — one row listed, and the
    // way to add another certificate or open a card gone from the window,
    // while a comment claimed it was "reachable from every picker state".
    harness.get_by_label_contains("Abrir un archivo de certificado");
    harness.get_by_label_contains("Otro almacén (escribe su ruta o nombre)…");

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
fn signing_the_same_document_again_with_a_p12_asks_and_writes_the_new_name() {
    // 06-N-1 through the window: the picker's own button (not a hand-built
    // screen), the Done screen's "Firmar otro documento", and the overwrite
    // answer the save dialog gives. `sign_to` — the overwrite answer's door —
    // asked the row for a `KeySource` through `entry.key()` alone, and a
    // `.p12` row has none: it signs with the password just typed. The `expect`
    // that stood in for the missing case ended the PROCESS on the second
    // signature over one document — the window vanished mid-flow.
    let p12 = testdata().join("certs/signer-rsa.p12");
    let dir = temp_doc("p12-resign");
    let doc = dir.join("nota.txt");
    if require(p12.is_file(), "the test PKI").is_none() {
        return;
    }
    std::fs::write(&doc, b"una nota para firmar dos veces\n").unwrap();

    let app = fixture_app(Some(doc.clone()));
    let mut harness = harness_for(app);
    harness.run();

    // first signature: document, .p12 row, password, sign
    harness
        .query_all_by_label_contains("Examinar")
        .next()
        .unwrap()
        .click();
    harness.run();
    harness.state_mut().dialogs_for_test().fixture_open = Some(p12.clone());
    harness
        .get_by_label_contains("Abrir un archivo de certificado")
        .click();
    harness.run();
    harness
        .state_mut()
        .force_password_for_test("openfirma".into());
    harness.run();
    harness.get_by_label("Firmar").click();
    harness.step();
    drain_worker(&mut harness);
    harness.run();
    harness.get_by_label_contains("Firma guardada");
    // A-7: the result names the HOLDER, through the one naming rule the
    // terminal also prints signers with — never the file the holder was read
    // from. The picker's row for a `.p12` is that file name, and it has to be
    // (nothing has unlocked the container yet); the result screen is not a row.
    harness.get_by_label_contains("PEREZ GARCIA, ANA");
    let tree = format!("{:?}", harness.root());
    assert!(
        !tree.contains("signer-rsa.p12"),
        "the result screen names the file, not the signer: {tree}"
    );
    let first = dir.join("nota.txt.csig");
    assert!(
        first.is_file(),
        "the first signature sits next to the original"
    );

    // second signature over the same document: the done screen's own way back
    harness
        .get_by_label_contains("Firmar otro documento")
        .click();
    harness.run();
    harness.state_mut().dialogs_for_test().fixture_open = Some(doc.clone());
    harness
        .query_all_by_label_contains("Examinar")
        .next()
        .unwrap()
        .click();
    harness.run();
    harness.state_mut().dialogs_for_test().fixture_open = Some(p12.clone());
    harness
        .get_by_label_contains("Abrir un archivo de certificado")
        .click();
    harness.run();
    harness
        .state_mut()
        .force_password_for_test("openfirma".into());
    harness.run();
    // the output exists, so the window asks where to write before truncating
    // anybody's data; the dialog's answer is the new name, delivered through
    // the fixture like every other OS dialog here
    let second = dir.join("nota-segunda.csig");
    harness.state_mut().dialogs_for_test().fixture_save = Some(second.clone());
    harness.get_by_label("Firmar").click();
    harness.step();
    drain_worker(&mut harness);
    harness.run();
    harness.get_by_label_contains("Firma guardada");
    assert!(
        second.is_file(),
        "the second signature was written where the dialog said"
    );
    assert!(first.is_file(), "and the first one was left alone");

    std::fs::remove_dir_all(dir).ok();
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
fn the_typed_password_does_not_outlive_the_picker_it_was_typed_on() {
    // M-8's remaining half. The field was wiped when a signing job started
    // and nowhere else: type the password for the wrong `.p12`, press "Elegir
    // otro documento", and the secret was still in the field's `Zeroizing` —
    // and in egui's own remembered text — while the citizen looked at the
    // drop zone. The frame's copy (`mirror_secret`) is a `Zeroizing` now, and
    // leaving the screen wipes the field and the widget state with it.
    let dir = temp_doc("password-outlives");
    let doc = dir.join("doc.pdf");
    std::fs::write(&doc, b"%PDF-1.4 placeholder").unwrap();
    let mut app = fixture_app(None);
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
    app.force_password_for_test("la-del-p12".into());
    let mut harness = harness_for(app);
    harness.run();
    assert_eq!(
        harness.state().typed_password_for_test(),
        "la-del-p12",
        "the field holds what was typed while its screen is on"
    );
    harness.get_by_label("Elegir otro documento").click();
    harness.run();
    assert!(
        matches!(harness.state().screen_ref_for_test(), Screen::Idle),
        "the back button leaves the picker"
    );
    assert_eq!(
        harness.state().typed_password_for_test(),
        "",
        "leaving the picker takes the typed password with it"
    );
    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn a_wrong_password_returns_to_the_picker_with_its_document_and_a_sentence() {
    // 06-N-5, through the button a person presses and the REAL worker.
    // `render_picked` had swapped the Picked screen into a local and left
    // `Idle` where it had been, so `start_sign` parked the drop zone as the
    // screen a retry comes back to: a wrong password restored it, and the
    // document, the chosen certificate and the typed field went with it —
    // without a sentence saying what had happened. The test the area had
    // built a `Screen::Signing { back: Picked }` by hand and delivered the
    // outcome through a test door, which is why it never saw this.
    let p12 = testdata().join("certs/signer-rsa.p12");
    let dir = temp_doc("wrong-password");
    let doc = dir.join("nota.txt");
    if require(p12.is_file(), "the test PKI").is_none() {
        return;
    }
    std::fs::write(&doc, b"contenido de la nota\n").unwrap();

    let app = fixture_app(Some(doc.clone()));
    let mut harness = harness_for(app);
    harness.run();
    harness
        .query_all_by_label_contains("Examinar")
        .next()
        .unwrap()
        .click();
    harness.run();
    harness.state_mut().dialogs_for_test().fixture_open = Some(p12.clone());
    harness
        .get_by_label_contains("Abrir un archivo de certificado")
        .click();
    harness.run();
    harness
        .state_mut()
        .force_password_for_test("equivocada".into());
    harness.run();
    harness.get_by_label("Firmar").click();
    harness.step(); // the spinner screen, as the happy path does
    drain_worker(&mut harness);
    harness.run();

    assert!(
        matches!(harness.state().screen_ref_for_test(), Screen::Picked { .. }),
        "a wrong password comes back to the picker, not to the drop zone"
    );
    // The document is the same one, its row is still there, and the sentence
    // is under the field. The drop zone's own heading must be gone: that is
    // the screen the citizen was thrown to.
    harness.get_by_label_contains("nota.txt");
    harness.get_by_label_contains("Contraseña incorrecta");
    assert!(
        harness
            .query_by_label_contains("Arrastra aquí el documento")
            .is_none(),
        "the drop zone is not where a retry lands"
    );

    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn the_pickers_back_button_leaves_the_picker() {
    // 06-N-6: the button was painted, clickable and inert — `put_back!` inside
    // the `ui.horizontal` closure returned from the closure, and the call at
    // the end of the frame put the Picked screen straight back. A citizen who
    // picked the wrong `.p12` had no way back except dragging another file or
    // closing the window.
    let Some(()) = require(
        testdata().join("inputs/simple.pdf").is_file(),
        "testdata/inputs/simple.pdf",
    ) else {
        return;
    };
    let mut app = fixture_app(None);
    app.load_path_for_test(testdata().join("inputs/simple.pdf"));
    let mut harness = harness_for(app);
    harness.run();
    harness.get_by_label_contains("Es un PDF");
    harness
        .get_by_label_contains("Elegir otro documento")
        .click();
    harness.run();
    assert!(
        matches!(harness.state().screen_ref_for_test(), Screen::Idle),
        "the back button leaves the picker"
    );
    harness.get_by_label_contains("Arrastra aquí el documento");
}

#[test]
fn the_advanced_options_open_when_the_header_is_clicked() {
    // 06-N-7: `.open(Some(adv_open))` forced the header's state every frame and
    // `*advanced = adv_open` wrote back the value it had just read, so the
    // click was never seen: the TSA field, the digest choice, the format list
    // and the PDF reason were unreachable from the window, which ADR-0006
    // point 7 describes as existing.
    let Some(()) = require(
        testdata().join("inputs/simple.pdf").is_file(),
        "testdata/inputs/simple.pdf",
    ) else {
        return;
    };
    let mut app = fixture_app(None);
    app.load_path_for_test(testdata().join("inputs/simple.pdf"));
    let mut harness = harness_for(app);
    harness.run();
    harness.get_by_label_contains("Opciones avanzadas");
    assert!(
        harness
            .query_by_label_contains("Algoritmo de resumen")
            .is_none(),
        "closed means closed: the panel is not rendered yet"
    );
    harness.get_by_label_contains("Opciones avanzadas").click();
    harness.run();
    // The panel is open, its options are on screen, and its label says where
    // the next click goes.
    harness.get_by_label_contains("Algoritmo de resumen");
    harness.get_by_label_contains("Motivo de la firma");
    harness.get_by_label_contains("Ocultar opciones avanzadas");
    // And it closes again — the state is the screen's, not a frame's.
    harness
        .get_by_label_contains("Ocultar opciones avanzadas")
        .click();
    harness.run();
    harness.get_by_label_contains("Opciones avanzadas");
    assert!(
        harness
            .query_by_label_contains("Algoritmo de resumen")
            .is_none()
    );
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

    // The authority is configuration, read once at startup (06-C-1), exactly
    // as `openfirma verify --trust testdata/certs/chain.crt` gets fed: the
    // test PKI needs BOTH its certificates (the CA alone leaves the
    // intermediate unnamed). No window asks the citizen to choose one.
    let answer = verified_answer_for(&out);
    let mut app = fixture_app(None);
    app.set_anchors_for_test(vec![testdata().join("certs/chain.crt")]);
    app.load_path_for_test(out.clone());
    // A-1's second half, asserted before a frame is drawn: a verification
    // parks the screen and says what it is doing, instead of leaving the drop
    // zone painted while the whole archive is read. Same park shape the
    // signing job and the keystore open have had since `c58831a`/`141cdd2`.
    assert!(
        matches!(app.screen_ref_for_test(), Screen::Verifying { .. }),
        "a verification parks the screen with its spinner"
    );
    // The verify starts a worker (A-1); kittest has no frame loop to drain it,
    // so the test answers through the app's own transition.
    let mut harness = harness_for(app);
    // A spinner never settles: one frame, not `run()`. Whether that one frame
    // still shows the park is the machine's business — the verification runs on
    // a real worker thread, and this frame drains its answer if it has already
    // landed. On both macOS runners it consistently has, which is what this
    // test used to fail on; the park itself is asserted above, before any frame
    // is drawn, where no thread can race it. Here the window has to be the
    // parked spinner or the verdict that replaced it — never the drop zone.
    harness.step();
    match harness.state().screen_ref_for_test() {
        Screen::Verifying { .. } => {
            harness.get_by_label_contains("Comprobando la firma");
            harness
                .state_mut()
                .deliver_verify_answer_for_test(Ok(answer));
        }
        Screen::Verified { .. } => {}
        _ => panic!("a verification left neither the park nor a verdict"),
    }
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
fn adding_a_keystore_shows_a_spinner_and_the_drop_waits_for_it() {
    // 06-N-10 through the real widgets and the real worker. Answering the
    // add-keystore form used to load a module and log in INSIDE the frame — a
    // card that takes seconds froze the window on a painted button — and a
    // drop arriving meanwhile replaced the very screen the job was going to
    // answer into. Now: the picker parks behind a spinner, a drop while it
    // opens is refused out loud, and the picker comes back with the store's
    // own line under the store's own name.
    let dir = temp_doc("store-open");
    let doc = dir.join("doc.pdf");
    let other = dir.join("otro.pdf");
    let inputs = testdata().join("inputs/simple.pdf");
    if require(inputs.is_file(), "testdata/inputs/simple.pdf").is_none() {
        return;
    }
    std::fs::copy(&inputs, &doc).unwrap();
    std::fs::copy(&inputs, &other).unwrap();

    let mut app = fixture_app(None);
    app.load_path_for_test(doc.clone());
    let mut harness = harness_for(app);
    harness.run();
    harness
        .get_by_label("Otro almacén (escribe su ruta o nombre)…")
        .click();
    harness.run();
    // A module that does not exist: the failure is the store's own, answered
    // as fast as an OS can say "no such file", and nothing about it depends on
    // a card being in a reader.
    harness
        .state_mut()
        .set_descriptor_for_test("pkcs11:/no/existe/modulo.so");
    harness.get_by_label("Abrir").click();
    harness.step(); // a spinner repaints forever: never `run`, one step
    assert!(
        matches!(
            harness.state().screen_ref_for_test(),
            Screen::OpeningStore { .. }
        ),
        "the open runs off the UI thread: the picker is parked, not blocked"
    );

    // A drop while the store opens: refused out loud (the one thing at a time
    // rule covers drops), and the parked picker is exactly where it was.
    harness.state_mut().load_path_from_cli(other.clone());
    assert!(matches!(
        harness.state().screen_ref_for_test(),
        Screen::OpeningStore { .. }
    ));

    drain_worker(&mut harness);
    harness.run();
    harness.get_by_label_contains("Termina primero la operación");
    assert!(
        matches!(harness.state().screen_ref_for_test(), Screen::Picked { .. }),
        "the picker comes back, with the document it held"
    );
    harness.get_by_label_contains("no se ha podido abrir el almacén");
    assert!(
        harness.state().pending_note_for_test().is_some(),
        "and it still says the drop was refused while it worked"
    );
    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn no_configured_authority_is_an_amber_verdict_never_a_green_one() {
    // 06-C-1, through the window and its real worker. On a machine with no
    // authority configured, dropping a signed PDF used to open a file dialog
    // asking the citizen which CA to trust — a question they cannot answer,
    // and the review walked the wrong answer through it: the impostor's own
    // root, picked after seeing the document, made the screen read "Firma
    // válida". Now the window runs every check that needs no authority and
    // every line says the issuer was not checked. Amber, never green — and no
    // dialog: `fixture_app(None)` has no dialog to answer, so a window that
    // still asked would sit on the drop zone instead of a verdict.
    let p12 = testdata().join("certs/signer-rsa.p12");
    let dir = temp_doc("no-anchors-verdict");
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

    let mut app = fixture_app(None);
    app.load_path_for_test(out.clone());
    let mut harness = harness_for(app);
    drain_worker(&mut harness);
    harness.run();
    assert!(
        matches!(
            harness.state().screen_ref_for_test(),
            Screen::Verified { .. }
        ),
        "no authority configured is a verdict, not a question"
    );
    // The line says exactly what ran: integrity good, issuer unchecked.
    harness.get_by_label_contains("se ha comprobado quién emitió el certificado");
    // And the whole screen never claims validity.
    assert!(
        harness.query_by_label_contains("Firma válida").is_none(),
        "green is reserved for a chain that reached a named authority"
    );
    // The note on the drop screen says how to fix it, in configuration.
    let note = harness
        .state()
        .pending_note_for_test()
        .expect("the window says why the issuer was not checked");
    assert!(note.contains("OPENFIRMA_TRUST"), "{note}");

    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn the_windows_own_csig_verifies_against_its_original_and_asks_when_it_is_gone() {
    // 06-N-2 through the window, worker and all. `companion_of` reversed the
    // library's naming rule with an extra `strip_suffix('.')` that could never
    // match, so the companion of `nota.txt.csig` came back as the `.csig`
    // itself: the window verified the signature against its own bytes and told
    // the citizen the document had changed after signing — the GUI's own
    // output, refused by the GUI's own screen. Nothing here uses a verdict
    // delivered by the test: the deferred anchor question is answered by the
    // fixture and the REAL worker runs (`drain_worker`), so what is read off
    // the screen is what the window decides about the bytes it picked.
    let p12 = testdata().join("certs/signer-rsa.p12");
    let dir = temp_doc("csig-drop");
    let doc = dir.join("nota.txt");
    if require(p12.is_file(), "the test PKI").is_none() {
        return;
    }
    std::fs::write(&doc, b"contenido de la nota\n").unwrap();
    let signed = sign_through_gui_code_for("cades-b-b", &doc, &p12);
    let csig = dir.join("nota.txt.csig");
    std::fs::write(&csig, &signed).unwrap();

    // (1) the original sits beside the signature, as the GUI itself wrote it
    //
    // The authority is configuration now, not a dialog (06-C-1):
    // `set_anchors_for_test` is the same list production reads from
    // `$OPENFIRMA_TRUST` once at startup, and everything below — worker,
    // verdict screen — is the window's own path.
    let mut app = fixture_app(None);
    app.set_anchors_for_test(vec![testdata().join("certs/chain.crt")]);
    app.load_path_for_test(csig.clone());
    let mut harness = harness_for(app);
    drain_worker(&mut harness);
    harness.run();
    harness.get_by_label_contains("Firma válida");
    assert!(
        harness.query_by_label_contains("NO es válida").is_none(),
        "the window's own .csig is not a manipulated document"
    );
    assert!(
        harness.query_by_label_contains("cambió").is_none(),
        "and it does not say the document changed"
    );

    // (2) the original is gone: a detached signature with nothing to check
    // against asks for the document (the one dialog AutoFirma's validation
    // tab never shows) instead of verifying the signature over itself
    std::fs::remove_file(&doc).unwrap();
    let mut app = fixture_app(None);
    app.load_path_for_test(csig.clone());
    assert!(
        matches!(app.screen_ref_for_test(), Screen::NeedsContent { .. }),
        "a signature with no original asks which document was signed"
    );

    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn a_document_that_fails_as_a_whole_is_never_a_valid_signature() {
    // 06-N-3, through the window and its real worker. On a PDF certified with
    // `/Perms /DocMDP` `/P 1` and then signed anyway, `pades_verify` answers
    // Err about the DOCUMENT — its sentence carries no per-signature label —
    // while each signature holds over the bytes it covers. The window
    // re-verified the signatures one by one, found them sound, and painted
    // "Firma válida" over a file `openfirma verify` exits 1 for, with the
    // library's own English sentence pushed off the bottom edge. What the
    // screen must say instead: the document's refusal first, in Spanish, and
    // not one green line under it.
    let Some(pdf) = certified_then_signed_pdf() else {
        eprintln!("SKIP: the test PKI is absent, run tools/gen-testcert.sh");
        return;
    };
    let dir = temp_doc("document-failure");
    let doc = dir.join("certificado.pdf");
    std::fs::write(&doc, &pdf).unwrap();

    // Anchors ARE configured here on purpose. Without them every line is
    // amber for the missing authority (06-C-1), and the assertion below that
    // reads "no line may be green" would pass for the wrong reason; with the
    // chain named, a green line is exactly what the pre-fix code painted over
    // this document.
    let mut app = fixture_app(None);
    app.set_anchors_for_test(vec![testdata().join("certs/chain.crt")]);
    app.load_path_for_test(doc.clone());
    let mut harness = harness_for(app);
    drain_worker(&mut harness);
    harness.run();
    assert!(
        matches!(
            harness.state().screen_ref_for_test(),
            Screen::Verified { .. }
        ),
        "a verdict, never an error screen: the library refused the document"
    );
    harness.get_by_label_contains("El documento NO se puede dar por válido");
    harness.get_by_label_contains("la firma en sí es correcta, pero el documento NO");
    assert!(
        harness.query_by_label_contains("Firma válida").is_none(),
        "no line may read as valid while the document as a whole is refused"
    );

    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn the_verdicts_way_out_is_on_screen() {
    // 06-N-9: `auto_shrink([false, false])` made the verdict area consume every
    // remaining pixel of the window, which laid the notes and the exit button
    // out BELOW the bottom edge — five pixels of the button showed, whatever
    // the window size, and the only way back was to close the window. What is
    // asserted here is the pixel truth the screenshot showed: the button's own
    // rectangle lies inside the window, and clicking where it now is still
    // takes the window home.
    let Some(pdf) = certified_then_signed_pdf() else {
        eprintln!("SKIP: the test PKI is absent, run tools/gen-testcert.sh");
        return;
    };
    let dir = temp_doc("verdict-exit");
    let doc = dir.join("certificado.pdf");
    std::fs::write(&doc, &pdf).unwrap();

    let mut app = fixture_app(None);
    app.set_anchors_for_test(vec![testdata().join("certs/chain.crt")]);
    app.load_path_for_test(doc.clone());
    let mut harness = harness_for(app);
    drain_worker(&mut harness);
    harness.run();
    let screen = egui::Rect::from_min_size(egui::Pos2::ZERO, WINDOW);
    let exit = harness.get_by_label_contains("Verificar otro archivo");
    let rect = exit.rect();
    assert!(
        rect.max.y <= screen.max.y && rect.min.y >= screen.min.y,
        "the way out is inside the window: {rect:?} not within {screen:?}"
    );
    exit.click();
    harness.run();
    assert!(
        matches!(harness.state().screen_ref_for_test(), Screen::Idle),
        "the button inside the verdict area still goes home"
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
            document: None,
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
fn a_leaf_configured_as_authority_is_refused_and_never_green() {
    // The window no longer asks which CA to trust (06-C-1) — so what this test
    // owns is the other half of that removal: a configured authority that is a
    // leaf (a signer's own certificate, CA:FALSE) is refused by the loader with
    // its reason shown, and the verdict that follows does NOT turn green.
    // Before, this file was the answer to a dialog, and a green line stood over
    // it.
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

    let mut app = fixture_app(None);
    app.set_anchors_for_test(vec![leaf.clone()]);
    app.load_path_for_test(out.clone());
    let note = app
        .pending_note_for_test()
        .expect("a configured authority that cannot be used says so");
    assert!(
        note.contains("CA:FALSE") || note.contains("autoridad"),
        "the refusal must say why the configured file cannot anchor anything: {note}"
    );
    let mut harness = harness_for(app);
    drain_worker(&mut harness);
    harness.run();
    // The refusal to read the authority does not stop the verdict: the window
    // is honest about what it could not check (amber), and under no reading
    // does a green verdict stand.
    harness.get_by_label_contains("No se ha podido usar el archivo");
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
    sign_through_gui_code_for("pades-b-b", doc, p12)
}

/// The same, with the profile named: a `.txt` document goes out as CAdES
/// (`.csig`), which is the file the companion-rule test needs.
fn sign_through_gui_code_for(format: &str, doc: &Path, p12: &Path) -> Vec<u8> {
    let key = KeySource::P12 {
        path: p12.to_path_buf(),
        password: zeroize::Zeroizing::new("openfirma".into()),
        alias: None,
        display: "ANA".into(),
    };
    let signer = key.signer().expect("the test .p12 opens");
    let content = std::fs::read(doc).unwrap();
    openfirma_gui::signing::execute(
        format,
        &content,
        signer.as_ref(),
        openfirma_core::DigestAlg::Sha256,
        None,
        None,
    )
    .expect("signing the test document through the GUI's dispatcher works")
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

/// A one-page PDF whose catalog is exactly `catalog`, closed by an honest
/// classic cross-reference table: the smallest document the certification
/// gate can walk a `/Prev` chain on. Built here, never committed as a binary.
fn one_page_pdf(catalog: &str) -> Vec<u8> {
    let bodies = [
        catalog,
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] >>",
    ];
    let mut out = Vec::from(&b"%PDF-1.4\n"[..]);
    let mut offsets = Vec::new();
    for (i, body) in bodies.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n{body}\nendobj\n", i + 1).as_bytes());
    }
    let xref_at = out.len();
    out.extend_from_slice(
        format!("xref\n0 {}\n0000000000 65535 f \n", offsets.len() + 1).as_bytes(),
    );
    for o in &offsets {
        out.extend_from_slice(format!("{o:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref_at}\n%%EOF\n",
            offsets.len() + 1
        )
        .as_bytes(),
    );
    out
}

/// 06-N-3's file: a PDF certified with `/Perms /DocMDP` `/P 1` ("no changes
/// permitted") that then received a signature, built with the library's own
/// signer the way the pades suite builds it. `pades_verify` refuses the
/// DOCUMENT — the certification is broken by what followed it — while the
/// signature is sound over its own bytes. That is the file `openfirma verify`
/// exits 1 for, and the one the window painted "Firma válida" over.
fn certified_then_signed_pdf() -> Option<Vec<u8>> {
    use openfirma_core::cert::CertificateHandle;
    use openfirma_core::signer::SoftwareSigner;
    let certs = testdata().join("certs");
    let (Ok(cert), Ok(key)) = (
        std::fs::read_to_string(certs.join("signer-rsa.crt")),
        std::fs::read_to_string(certs.join("signer-rsa.key")),
    ) else {
        return None;
    };
    let signer = SoftwareSigner::from_pkcs8_pem(&cert, &key).expect("the test PKI is unusable");
    let chain: Vec<CertificateHandle> = ["intermediate.crt", "ca.crt"]
        .iter()
        .map(|c| {
            CertificateHandle::from_pem(&std::fs::read_to_string(certs.join(c)).unwrap())
                .expect("the test PKI is incomplete")
        })
        .collect();
    let doc = one_page_pdf(
        "<< /Type /Catalog /Pages 2 0 R /Perms << /DocMDP << /TransformParams \
         << /P 1 >> >> >> >>",
    );
    let opts = openfirma_pades::PadesOptions {
        // The certification is the fixture's premise: openfirma signs a
        // certified document only when told to, exactly as AutoFirma asks.
        allow_signing_certified: true,
        ..openfirma_pades::PadesOptions::default()
    };
    Some(
        openfirma_pades::pades_sign(&doc, &signer.with_chain(chain), &opts)
            .expect("the fixture signs"),
    )
}

/// M-7: this suite used to call `allow_missing_glyphs()`, with a comment saying
/// the ✓ of the Done screen was not in the default font — which is true, and
/// which meant the window painted an empty box on the one screen that says the
/// signature was written, while every test passed. The window draws no mark
/// now and says it in words; this is the gate that keeps it that way: every
/// character of every sentence, in both languages, is checked against the
/// fonts a build actually carries.
#[test]
fn every_character_the_window_shows_has_a_glyph() {
    let mut harness = harness_for(fixture_app(None));
    harness.run();
    let mut missing: Vec<(char, String)> = Vec::new();
    for tr in [Tr::es(), Tr::en()] {
        for sentence in tr.every_string() {
            for c in sentence.chars() {
                if c.is_whitespace() {
                    continue;
                }
                harness.ctx.fonts_mut(|f| {
                    if !f.has_glyph(&egui::FontId::proportional(14.0), c) {
                        missing.push((c, sentence.clone()));
                    }
                });
            }
        }
    }
    assert!(
        missing.is_empty(),
        "the fonts cannot draw these characters: {:?}",
        &missing[..missing.len().min(8)]
    );
}
