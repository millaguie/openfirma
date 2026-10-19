//! Finding 04-N8: what a consent refusal answers, and to whom.
//!
//! A browser-launched handler has no terminal and no window, so a call against
//! a key whose file never opted in used to answer 600002/SAF_04 — "La operacion
//! no esta soportada" — which sends the person reading the sede to look for an
//! upgrade over a key that merely had no `allow_unattended = true`. The outcome
//! for the page is the one AutoFirma's own dialog produces when it is dismissed:
//! no signature, and no retry. So the pair is 500001/CANCEL (`err-11:=`), the
//! same one a user who actually answered "no" gets — while the machine code and
//! the message keep the two apart in logs.
//!
//! The tests here drive the dispatch front doors directly and assert on the
//! ERROR, not on a message: the code the page reads, the legacy text the older
//! readers split on, and that neither path touched a key (both are asked with a
//! container that does not exist, so a keystore error would mean the gate let
//! the call through).

use std::path::Path;

use openfirma_browser::dispatch::{
    BrowserError, Consent, ConsentAnswer, ConsentFn, KeySource, OperationSummary, UnattendedKey,
    WireTarget, execute, execute_with_consent,
};

/// A prompter that answers no, the way a person closing the dialog does.
struct SaysNo;

impl ConsentFn for SaysNo {
    fn approve(
        &self,
        _summary: &OperationSummary,
        _needs_password: bool,
    ) -> Result<ConsentAnswer, BrowserError> {
        Ok(ConsentAnswer::No)
    }
}

/// The page's own reading of an error (autoscript.js's predicate, as pinned in
/// `autoscript_wire`): `err-XX:=AF<code> - <text>` with a catalogue code.
fn the_page_sees_an_error(text: &str) -> Option<String> {
    let body = text
        .strip_prefix("err-11:=")
        .or_else(|| text.strip_prefix("err-00:="))?;
    let candidate = &body[..8];
    candidate
        .strip_prefix("AF")
        .filter(|digits| digits.bytes().all(|b| b.is_ascii_digit()))
        .map(|_| candidate.to_string())
}

const A_SIGN_CALL: &str =
    "afirma://sign?op=sign&format=CAdES&algorithm=SHA256withRSA&dat=aGVsbG8%3D";

#[test]
fn a_key_nobody_could_be_asked_about_answers_the_cancellation_pair() {
    let uri = openfirma_browser::uri::parse(A_SIGN_CALL).expect("a sign call");
    // The container is deliberately absent: if the consent gate let this
    // through, the next thing to happen is opening it, and the test would see
    // a keystore error instead of the refusal it is about.
    let key = KeySource::Unattended(UnattendedKey {
        path: Path::new("/nonexistent/nunca-existe.p12"),
        password: Some("no-es-la-clave"),
        allow_unattended: false,
        label: "clave del navegador",
    });

    let error = execute_with_consent(&uri, &key, Consent::Granted)
        .expect_err("no opt-in, nobody to ask: no signature");
    assert_eq!(
        error.code, "consent-required",
        "the machine code must still say WHICH refusal this is: {}",
        error.message
    );
    assert_eq!(
        error.wire.af_code, "500001",
        "the page reads a cancellation, not \"operation not supported\": {}",
        error.message
    );
    assert_eq!(error.wire.old_code, "CANCEL");
    // Both wire forms, as a page parses them.
    let modern = error.wire(WireTarget::Protocol41Plus);
    assert_eq!(
        the_page_sees_an_error(&modern).as_deref(),
        Some("AF500001"),
        "{modern}"
    );
    assert_eq!(
        error.wire(WireTarget::Legacy),
        "CANCEL",
        "pre-4.1 readers split on the bare CANCEL word"
    );

    // The same refusal through the other front door (`execute`, which has no
    // consent callback at all).
    let error = execute(&uri, &key).expect_err("no way to ask: no signature");
    assert_eq!(error.code, "consent-required");
    assert_eq!(error.wire.af_code, "500001");
}

#[test]
fn the_user_saying_no_and_nobody_being_asked_differ_where_it_matters() {
    // A user's own "no" is `cancelled`; a key nobody could be asked about is
    // `consent-required`. Same wire pair — both mean "not signed, do not
    // retry" — and different machine codes, so a log can tell them apart.
    let uri = openfirma_browser::uri::parse(A_SIGN_CALL).expect("a sign call");
    let key = KeySource::Unattended(UnattendedKey {
        path: Path::new("/nonexistent/nunca-existe.p12"),
        // No stored password, so the prompt is genuinely needed and is reached
        // before the container is opened.
        password: None,
        allow_unattended: true,
        label: "clave del navegador",
    });

    let error =
        execute_with_consent(&uri, &key, Consent::Prompt(&SaysNo)).expect_err("the user said no");
    assert_eq!(error.code, "cancelled", "{}", error.message);
    assert_eq!(error.wire.af_code, "500001");
    assert_eq!(
        the_page_sees_an_error(&error.wire(WireTarget::Protocol41Plus)).as_deref(),
        Some("AF500001")
    );

    // And that distinction survives the other way round: the granted-but-not-
    // opted-in key is NOT the user's cancellation.
    let error = execute_with_consent(
        &uri,
        &KeySource::Unattended(UnattendedKey {
            path: Path::new("/nonexistent/nunca-existe.p12"),
            password: Some("no-es-la-clave"),
            allow_unattended: false,
            label: "clave del navegador",
        }),
        Consent::Granted,
    )
    .expect_err("granted is not an opt-in");
    assert_ne!(error.code, "cancelled");
    assert_eq!(error.code, "consent-required");
}
