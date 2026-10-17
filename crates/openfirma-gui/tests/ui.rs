//! Windowless UI tests (ADR-0006): the harness drives the same `App` the
//! binary runs — egui builds the widget tree in memory, AccessKit exposes it,
//! and the test clicks buttons like a person would. Nothing here needs a
//! display: what kittest cannot reach are the *OS* pieces (real file pickers,
//! drag-and-drop from a real desktop, closing a real window), whose answers
//! the `Dialogs` fixture supplies; those remain in docs/validation.md as the
//! manual checklist.

use std::path::{Path, PathBuf};

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
    // this test owns is that the *window* gets there in three clicks.
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
    harness.run();

    // The Done screen: result named, folder link offered (ADR-0006's next-to-
    // original rule), and no second save dialog on the way.
    harness.get_by_label_contains("Firma guardada");
    let out = pdf_dir.join("contrato.signed.pdf");
    assert!(out.is_file(), "the signature must sit next to the original");
    verify_after_gui_sign(&out);

    std::fs::remove_dir_all(pdf_dir).ok();
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
    let out = dir.join("doc.signed.pdf");
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
    let mut harness = harness_for(app);
    harness.run(); // the deferred ask fires; the fixture answers with ca.crt
    harness.get_by_label_contains("Firma válida");
    harness.get_by_label_contains("Quién firmó");
    assert!(
        matches!(
            harness.state().screen_ref_for_test(),
            Screen::Verified { .. }
        ),
        "after the anchor the verdict screen stands"
    );

    std::fs::remove_dir_all(dir).ok();
}

/// Review C-1(06)/M-10, the GUI half. The anchor picker asks "¿en quién
/// confías?"; picking a signer's LEAF certificate — CA:FALSE, one human of
/// flesh and bone — must never light the window green. Before the fix the
/// pick became an anchor for whoever held that key: any document that same
/// attacker signed verified against it. Now core's anchor rule refuses the
/// file at load, the Failed screen shows the reason, and nothing verifies.
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
    let out = dir.join("doc.signed.pdf");
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
    // …and present after one checkbox (ADR-0006: details are a click away,
    // never in front).
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
}

#[test]
fn the_window_cannot_close_over_an_unsaved_result() {
    // Two layers, both tested: the pure rule (`close_decision`) and the
    // window's behavior of cancelling the close while it holds a result.
    let unsaved = Screen::Done {
        path: PathBuf::from("doc.pdf"),
        output: PathBuf::from("doc.signed.pdf"),
        content: vec![1],
        signature: vec![2],
        format_label: "PAdES-B-B".into(),
        signer_display: "ANA".into(),
        saved: false,
    };
    assert_eq!(close_decision(&unsaved), CloseDecision::Warn);

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
    // The real drag-and-drop plumbing (egui's `hovered_files`, which kittest
    // *can* feed — winit only carries the OS path in): one hover, and the
    // idle screen must become the detection screen.
    let Some(()) = require(
        testdata().join("inputs/simple.txt").is_file(),
        "testdata/inputs/simple.txt",
    ) else {
        return;
    };
    let mut harness = harness_for(fixture_app(None));
    harness.run();
    // winit's contract: `hovered_files` repeats every frame while the file
    // hovers and is cleared on drop; the app takes at most one per frame. A
    // second, different hover must not retrigger over a Picked screen either.
    let path = testdata().join("inputs/simple.txt");
    // kittest feeds frames from `harness.input` (its RawInput), exactly what
    // egui-winit fills when the OS reports a drag hovering the window.
    harness.input_mut().hovered_files.push(egui::HoveredFile {
        path: Some(path.clone()),
        mime: String::new(),
    });
    harness.step();
    // The CAdES screen (a .txt is plain data) proves it entered by the drop
    // door; the hover repeating must not reload or reset it.
    harness.input_mut().hovered_files.clear();
    harness.input_mut().hovered_files.push(egui::HoveredFile {
        path: Some(path),
        mime: String::new(),
    });
    harness.step();
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
        source: Some(Box::new(move || KeySource::P12 {
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
    // one click on the row, one on Firmar: no password field appears.
    harness.get_by_label_contains("PEREZ GARCIA, ANA").click();
    harness.run();
    assert!(
        harness
            .query_by_label_contains("Contraseña del certificado")
            .is_none()
    );
    harness.get_by_label("Firmar").click();
    harness.run();
    let out = dir.join("firmable.signed.pdf");
    assert!(out.is_file(), "{out:?}");
    verify_after_gui_sign(&out);
    std::fs::remove_dir_all(dir).ok();
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
