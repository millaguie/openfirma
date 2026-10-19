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

mod common;

use common::{load_signer, require_or_skip};
use openfirma_core::signer::SoftwareSigner;
use openfirma_xades::xml::parse;
use openfirma_xades::{XadesOptions, xades_sign};

fn signer() -> Option<SoftwareSigner> {
    load_signer(
        "signer-rsa.crt",
        "signer-rsa.key",
        &["intermediate.crt", "ca.crt"],
    )
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
        // …in production [24]'s own order: `standalone` before `encoding` is
        // not a declaration libxml2 reads (round two, N-4 — this case used to
        // sit here in the wrong order because the reader did not look at it).
        b"<?xml version=\"1.0\" encoding = 'us-ascii' standalone = \"yes\"?><doc/>",
    ];
    for input in good {
        assert!(
            parse(input).is_ok(),
            "{:?} must stay readable",
            String::from_utf8_lossy(input)
        );
    }
}

/// Round 2, N-4: the declaration must BE production [24], not merely contain a
/// version and an encoding somewhere. `<?xml version="1.0"
/// encodi:ng="ISO-8859-1"?>` was accepted and signed — libxml2 answers
/// "parsing XML declaration: '?>' expected" — and the same token scan swallowed
/// an unknown pseudo-attribute, a repeated one and the two in the wrong order.
/// The accepting side matters as much: a tab after `<?xml` is S, libxml2 reads
/// it, and the old literal-space check refused a legal document.
#[test]
fn the_declaration_is_the_production() {
    let refused: &[&[u8]] = &[
        b"<?xml version=\"1.0\" encodi:ng=\"ISO-8859-1\"?><doc/>",
        b"<?xml version=\"1.0\" foo=\"1\"?><doc/>",
        b"<?xml version=\"1.0\" encoding=\"UTF-8\" encoding=\"UTF-8\"?><doc/>",
        b"<?xml version=\"1.0\" standalone=\"yes\" encoding=\"us-ascii\"?><doc/>",
        b"<?xml version=\"1.0\" standalone=\"maybe\"?><doc/>",
        // Skipping an absent optional slot must not turn into a licence to
        // reorder or repeat: `version` is production [24]'s first and only
        // mandatory name, and a name twice is not the production.
        b"<?xml encoding=\"UTF-8\" version=\"1.0\"?><doc/>",
        b"<?xml version=\"1.0\" version=\"1.1\"?><doc/>",
        b"<?xml version=\"1.0\" standalone=\"yes\" standalone=\"no\"?><doc/>",
        b"<?xml VERSION=\"1.0\"?><doc/>",
        b"<?xml version=\"1.0\"encoding=\"UTF-8\"?><doc/>",
        b"<?xml?><doc/>",
        b"<?xml version=\"1.0\"?><doc/>junk<?xml version=\"1.0\"?><d/>",
    ];
    for input in refused {
        assert!(
            parse(input).is_err(),
            "{:?} is not an XML declaration any other parser reads",
            String::from_utf8_lossy(input)
        );
    }
    let accepted: &[&[u8]] = &[
        b"<?xml\tversion=\"1.0\"?><doc/>",
        b"<?xml\nversion=\"1.0\"?><doc/>",
        b"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\" ?><doc/>",
        b"<?xml version='1.0'?><doc/>",
        // The two optional slots are optional *independently*. Production [24]
        // has EqEncoding? and EqStandalone?, so a declaration may carry the
        // standalone without the encoding — libxml2 and AutoFirma both read this,
        // and the positional reader added with N-4 refused it (which is a false
        // refusal about a legal document, the more expensive direction).
        b"<?xml version=\"1.0\" standalone=\"yes\"?><doc/>",
        b"<?xml version=\"1.0\" standalone = 'no'?><doc/>",
    ];
    for input in accepted {
        assert!(
            parse(input).is_ok(),
            "{:?} is XML libxml2 reads",
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
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    let input = b"<?xml version = \"1.0\"  encoding = \"ISO-8859-1\" ?><doc>caf\xc3\xa9</doc>";
    let err = xades_sign(input, &signer, &XadesOptions::default())
        .expect_err("signing must refuse a document that declares ISO-8859-1");
    let text = err.to_string();
    assert!(text.contains("ISO-8859-1"), "{text}");
}
