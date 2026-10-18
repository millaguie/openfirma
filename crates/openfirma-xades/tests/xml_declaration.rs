//! Round 2, N-3: the XML declaration's `Eq ::= S? '=' S?` (production [25])
//! allows whitespace on both sides of the `=`, and the reader used to demand it
//! immediately after the name. `encoding ="ISO-8859-1"` therefore looked like a
//! declaration that named no encoding at all, and openfirma signed the bytes as
//! UTF-8 and wrote a UTF-8 declaration over them — a file whose text every
//! parser that obeys the declaration reads as Latin-1. The A-3 refusal only
//! worked for the spellings where the `=` sat flush.
//!
//! Two halves, and both bite: a declaration that names an encoding must be read
//! whatever the spacing, and a name that cannot be read as a quoted value is
//! refused rather than treated as absent.

use openfirma_core::cert::CertificateHandle;
use openfirma_core::signer::SoftwareSigner;
use openfirma_xades::xml::parse;
use openfirma_xades::{XadesOptions, xades_sign};

fn signer() -> Option<SoftwareSigner> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/certs");
    let cert = std::fs::read_to_string(dir.join("signer-rsa.crt")).ok()?;
    let key = std::fs::read_to_string(dir.join("signer-rsa.key")).ok()?;
    let chain: Vec<CertificateHandle> = ["intermediate.crt", "ca.crt"]
        .iter()
        .map(|name| {
            CertificateHandle::from_pem(&std::fs::read_to_string(dir.join(name)).unwrap()).unwrap()
        })
        .collect();
    let signer = SoftwareSigner::from_pkcs8_pem(&cert, &key).ok()?;
    Some(signer.with_chain(chain))
}

/// The reporter's two documents: valid UTF-8 bytes that are also meaningful
/// Latin-1, so obeying the declaration and ignoring it give different text.
/// Both must be refused by the reader *and* by the signer, with the encoding
/// spelled back the way the document spelled it.
#[test]
fn a_declared_encoding_is_read_whatever_the_spacing() {
    let documents: &[&[u8]] = &[
        b"<?xml version = \"1.0\"  encoding = \"ISO-8859-1\" ?><doc>caf\xc3\xa9</doc>",
        b"<?xml version=\"1.0\" encoding =\"windows-1252\"?><doc>caf\xc3\xa9</doc>",
        b"<?xml version=\"1.0\" encoding= \"ISO-8859-1\"?><doc>caf\xc3\xa9</doc>",
    ];
    for input in documents {
        let err = parse(input)
            .expect_err("a declaration that names a non-UTF-8 encoding must be refused");
        let text = err.to_string();
        assert!(
            text.contains("ISO-8859-1") || text.contains("windows-1252"),
            "the refusal must name the declared encoding: {text}"
        );
    }
}

/// The fail-closed half: a name that is present but whose value is not a quoted
/// name is not "no encoding". Unquoted values are outside production [24], and
/// guessing what the bytes mean is what produced N-3 in the first place.
#[test]
fn an_encoding_whose_value_is_not_a_quoted_name_is_refused() {
    let bad: &[&[u8]] = &[
        b"<?xml version=\"1.0\" encoding=ISO-8859-1?><doc/>",
        b"<?xml version=\"1.0\" encoding=>?><doc/>",
        b"<?xml version=\"1.0\" encoding=\"ISO-8859-1?><doc/>",
    ];
    for input in bad {
        assert!(
            parse(input).is_err(),
            "{:?} was accepted as if it declared nothing",
            String::from_utf8_lossy(input)
        );
    }
}

/// Spacing around the `=` is legal for every pseudo-attribute, the one the
/// reader honors included: it must not start refusing well-formed documents.
#[test]
fn spacing_around_the_equals_stays_well_formed() {
    let good: &[&[u8]] = &[
        b"<?xml version = \"1.0\" ?><doc/>",
        b"<?xml version = '1.0' encoding ='utf8'?><doc>caf\xc3\xa9</doc>",
        b"<?xml version='1.0'\tencoding\t=\t'UTF-8' ?><doc/>",
        b"<?xml version=\"1.0\" standalone = \"yes\" encoding=\"us-ascii\"?><doc/>",
    ];
    for input in good {
        assert!(
            parse(input).is_ok(),
            "{:?} must stay readable",
            String::from_utf8_lossy(input)
        );
    }
}

/// End to end, the way the reporter reached it: the signer runs the same
/// reader, so the document that used to be signed with a UTF-8 declaration over
/// Latin-1 text now fails naming the encoding.
#[test]
fn signing_a_document_that_declares_latin1_refuses_it() {
    let Some(signer) = signer() else {
        let required = std::env::var("OPENFIRMA_REQUIRE_TESTS").is_ok();
        assert!(!required, "test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    let input = b"<?xml version = \"1.0\"  encoding = \"ISO-8859-1\" ?><doc>caf\xc3\xa9</doc>";
    let err = xades_sign(input, &signer, &XadesOptions::default())
        .expect_err("signing must refuse a document that declares ISO-8859-1");
    let text = err.to_string();
    assert!(text.contains("ISO-8859-1"), "{text}");
}
