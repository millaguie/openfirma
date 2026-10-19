//! Finding 04-N9: `dat=` — an empty payload — is not a document.
//!
//! The round-two report sent `afirma://sign?format=CAdES&algorithm=SHA256&dat=`
//! and got a signature: the empty value decoded to zero bytes, the request was
//! built around them, and every layer below signed happily. What comes out is a
//! structurally valid signature over nothing, which a viewer shows as a signed
//! but empty document — while the page that sent it thought it had attached a
//! file. `dat` empty is no payload at all, and gets AutoFirma's own
//! DATA_NOT_FOUND (600100 / SAF_03) for one.
//!
//! The assertion is on the RESULT of a real call through the front door, not on
//! a message: before the fix this call returns Ok with a signature in it, which
//! is exactly what the test must not be able to say.

use std::path::{Path, PathBuf};

use openfirma_browser::dispatch::{KeySource, WireTarget, execute};

fn testdata() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata")
}

/// CI sets OPENFIRMA_REQUIRE_TESTS so a missing test PKI fails instead of
/// skipping; only the keystore-scoped opt-out relaxes it (the rule the other
/// browser test files follow).
fn require_or_skip(reason: &str) {
    let required = std::env::var("OPENFIRMA_REQUIRE_TESTS").is_ok();
    let allowed = std::env::var("OPENFIRMA_ALLOW_NONKEYSTORE_SKIP").is_ok();
    if required && !allowed {
        panic!("cannot run the test: {reason}");
    }
    eprintln!("skipped, {reason}");
}

#[test]
fn an_empty_dat_payload_is_refused_as_a_missing_one() {
    let key = testdata().join("certs/signer-rsa.p12");
    if !key.is_file() {
        require_or_skip(&format!("{} is missing", key.display()));
        return;
    }
    let ks = KeySource::P12 {
        path: &key,
        password: "openfirma",
    };

    // The report's own call. `dat=%20` is the same case, not a second one: the
    // value is base64, whitespace inside base64 is ignored, so a space decodes
    // to zero bytes exactly like the empty value does.
    for (name, query) in [
        (
            "empty",
            "afirma://sign?op=sign&format=CAdES&algorithm=SHA256withRSA&dat=",
        ),
        (
            "blank",
            "afirma://sign?op=sign&format=CAdES&algorithm=SHA256withRSA&dat=%20",
        ),
    ] {
        let uri = openfirma_browser::uri::parse(query)
            .unwrap_or_else(|e| panic!("the {name} call parses as a URI: {e}"));
        let error = match execute(&uri, &ks) {
            Ok(result) => panic!(
                "the {name} call was SIGNED ({} bytes of payload) instead of refused",
                result.payload.len()
            ),
            Err(error) => error,
        };
        assert_eq!(
            error.code, "empty-data",
            "the {name} call must be refused FOR being empty, not for something else: \
             {}",
            error.message
        );
        assert_eq!(error.wire.af_code, "600100", "{}", error.message);
        assert_eq!(error.wire.old_code, "SAF_03");
        // And the page's own error predicate has to see an error, not prose.
        let text = error.wire(WireTarget::Protocol41Plus);
        assert!(
            text.contains("600100"),
            "the page must read this as an error carrying the code: {text}"
        );
    }

    // And the payload that is one byte long is not empty: `IA==` is a single
    // space, which a caller is allowed to ask for. The rule above must not have
    // grown into "refuse anything odd".
    let uri = openfirma_browser::uri::parse(
        "afirma://sign?op=sign&format=CAdES&algorithm=SHA256withRSA&dat=IA%3D%3D",
    )
    .expect("a one-byte payload parses");
    assert_eq!(uri.data.as_deref(), Some(&b" "[..]));
    assert!(
        execute(&uri, &ks).is_ok(),
        "a single byte is a document; only the zero-byte one is the accident"
    );

    // A call with no `dat` parameter at all is refused one layer earlier, by
    // the parser, which names the reason itself — the same protection, and it
    // is the socket layer's business to keep that shape out of here.
    let missing =
        openfirma_browser::uri::parse("afirma://sign?op=sign&format=CAdES&algorithm=SHA256withRSA");
    let message = format!(
        "{}",
        missing.expect_err("a sign call with no dat is not a call")
    );
    assert!(
        message.contains("dat"),
        "the parse refusal names the missing document: {message}"
    );
}
