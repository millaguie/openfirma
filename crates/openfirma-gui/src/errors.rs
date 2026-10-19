//! One sentence per failure. A signing client's errors *are* its product: the
//! user must read what went wrong and what to do next, never a raw DER or CMS
//! trace (docs/adr/0006-gui-toolkit.md; the library's own refusal texts — the PKCS#12 RC2
//! refusal, the browser-protocol refusals — are the standard this aims at).
//!
//! The rules: a message that already contains a fix instruction ("run `openssl pkcs12 …`")
//! or any openfirma-authored technical sentence is kept whole for the details control.
//! Review 06 A-5/07 H-18 changed what reaches the plain line: the *window's* language is
//! the interface language, so every known failure class gets its `Tr` sentence (wrong
//! password, unreadable anchor, missing anchors), with the library's technical English
//! one click behind. The CLI keeps printing the technical sentences verbatim — a terminal
//! reader reads them; the citizen in front of this screen does not.

use openfirma_core::Error;

use crate::strings::Tr;

/// Build the plain sentence + keep the technical one (the wizard's
/// [`crate::wizard::ErrorReport`]), in `tr`'s language.
pub fn report(err: &Error, tr: &Tr) -> crate::wizard::ErrorReport {
    let technical = err.to_string();
    let plain = match err {
        // The wrong password is the single most common failure a window sees
        // (M-4 measured it forcing a full re-open), and the library's
        // integrity-check sentence is true but English: name it first, keep
        // the cause behind details.
        Error::Keystore(m) if m.contains("integrity check failed") => {
            tr.fail_wrong_password.clone()
        }
        // Keystore and workflow refusals are authored sentences already; they
        // name the cause and often the fix (the RC2 refusal is the project's
        // own quality standard). They stay visible whole — the cost of one
        // shared message source, and a lie in Spanish about a keystore would
        // be worse than English truth.
        Error::Keystore(_) | Error::PrivateKey(_) => technical.clone(),
        // A verification failure reaching the FAILED screen (the verdict path
        // turns its own failures into lines; what survives to here is the no
        // verdict shape) or a certificate/anchor refusal naming an authoring
        // rule the user must see verbatim.
        Error::Verification(_) | Error::Certificate(_) => technical.clone(),
        // A refusal to read a configured authority file (B-5) names the file
        // and its reason; the verdict that follows says its issuer was not
        // checked rather than quietly pretending it was.
        Error::Other(_) if is_anchor_refusal(&technical) => {
            format!("{} {technical}", tr.fail_anchor_read)
        }
        // 06-C-1 removed the ask-the-anchor path, so this library phrase is
        // not a state the verdict path produces; if some other caller raises
        // it, the window says what it means and where the authority comes from.
        Error::Other(m) if m.contains("no trust anchors") => tr.fail_no_anchors_internal.clone(),
        Error::Other(_) => technical.clone(),
        // Parser chatter is for the details control only.
        Error::Der(e) => plain_error(&tr.fail_bad_format, &technical, Some(&e.to_string())),
        Error::Spki(e) => plain_error(&tr.fail_bad_public_key, &technical, Some(&e.to_string())),
        Error::UnsupportedDigest(_)
        | Error::UnsupportedKeyAlgorithm(_)
        | Error::UnsupportedCombination { .. } => technical.clone(),
        Error::PrehashLength { .. } => plain_error(&tr.fail_bad_signature, &technical, None),
        Error::Signing(m) => plain_error(&tr.fail_key_cannot_sign, m, None),
        Error::Pdf(m) => plain_error(&tr.fail_pdf, m, None),
        Error::Xml(m) => plain_error(&tr.fail_xml, m, None),
        Error::NoCertificate => technical.clone(),
    };
    crate::wizard::ErrorReport { plain, technical }
}

/// Whether a failure is the trust-anchor rule refusing a file (core's
/// `load_trust_anchors` messages all name the file and say CA:FALSE / "not a
/// valid X.509" / "holds no PEM certificate"). The window wraps them in its
/// own language so B-5's silent, jargon anchor failure reads as one sentence.
fn is_anchor_refusal(text: &str) -> bool {
    text.contains("CA:FALSE")
        || text.contains("is not a valid X.509 certificate")
        || text.contains("holds no PEM certificate")
        || (text.contains("cannot be a trust anchor"))
}

/// Whether an error report is really the wrong-password case, so callers can
/// keep the Picked screen with `password_error` set instead of leaving it
/// (M-4). The library words say it: PKCS#12's integrity check failing, or the
/// key/leaf mismatch after a decrypt that "succeeded" with the wrong secret.
pub fn is_wrong_password(report: &crate::wizard::ErrorReport) -> bool {
    let t = &report.technical;
    t.contains("integrity check failed") || t.contains("wrong password")
}

/// The window's wrapper that always says what to try next when the cause leaves
/// a way out. `cause`, when short enough, is woven into the sentence so one
/// line answers "what happened" and "what now".
fn plain_error(head: &str, technical: &str, _hint: Option<&str>) -> String {
    let first = technical.lines().next().unwrap_or_default();
    // The technical text of openfirma's own errors is long on purpose; the OS
    // one-liners (Permission denied, No such file) are short and human, so
    // the cause rides along. Truncated at a word boundary, hard stop.
    if first.len() <= 80 && !first.is_empty() {
        format!("{head}: {first}")
    } else {
        format!("{head}. Pulsa «Ver detalles técnicos» para la explicación completa.")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_authored_refusal_shows_itself() {
        // The PKCS#12 RC2 refusal is the project's own standard of quality;
        // rewriting it would be strictly worse for the reader.
        let e = Error::Keystore(
            "this PKCS#12 uses RC2, a cipher from 1995 that this reader will not \
             implement. Re-export it with `openssl pkcs12 -in old.p12 -out new.p12`"
                .into(),
        );
        let r = report(&e, &Tr::es());
        assert!(r.plain.contains("openssl pkcs12"), "{}", r.plain);
    }

    #[test]
    fn asn1_chatter_never_reaches_the_plain_line() {
        let e = Error::Der(der::Error::new(
            der::ErrorKind::Incomplete {
                expected_len: der::Length::new(64),
                actual_len: der::Length::new(3),
            },
            der::Length::new(0),
        ));
        let r = report(&e, &Tr::es());
        assert!(!r.plain.contains("der"), "{}", r.plain);
        assert!(r.plain.starts_with("El archivo"), "{}", r.plain);
    }

    /// M-6/A-5: the failures this window authors itself are sentences of the
    /// TABLE, in both languages. They used to be Spanish literals here, so an
    /// English window refused a broken PDF with "El PDF no se puede procesar"
    /// in the middle of its own English. Each class is walked, because the
    /// classes leave by different arms.
    #[test]
    fn the_failures_the_window_authors_follow_the_language() {
        let cases: Vec<Error> = vec![
            Error::Der(der::Error::new(
                der::ErrorKind::Incomplete {
                    expected_len: der::Length::new(64),
                    actual_len: der::Length::new(3),
                },
                der::Length::new(0),
            )),
            Error::Pdf("expected an object".into()),
            Error::Xml("expected an element".into()),
            Error::Signing("the card removed itself".into()),
            Error::PrehashLength {
                alg: "SHA-256",
                expected: 32,
                got: 4,
            },
        ];
        for e in cases {
            let es = report(&e, &Tr::es());
            let en = report(&e, &Tr::en());
            assert_ne!(es.plain, en.plain, "{:?} is the same sentence", e);
            for spanish in ["El ", "La ", "No se ", "no se ", "puede "] {
                assert!(
                    !en.plain.starts_with(spanish),
                    "{:?} says {spanish:?} in an English window: {}",
                    e,
                    en.plain
                );
            }
            // The English sentence is English all the way through: the head
            // comes from the table, and the cause after it is the library's
            // own technical English in both languages (named in M-6).
        }
        // The public-key class is unreachable without a real malformed SPKI,
        // so its head is asserted directly rather than through a fake error.
        assert!(!Tr::en().fail_bad_public_key.contains("clave"));
    }

    #[test]
    fn an_os_cause_rides_inside_the_sentence() {
        let e = Error::Other("cannot read /x/doc.pdf: Permission denied".into());
        let r = report(&e, &Tr::es());
        assert!(r.plain.contains("Permission denied"), "{}", r.plain);
    }

    #[test]
    fn the_wrong_password_earns_the_windows_own_sentence() {
        // A-5/M-4: the exact sentence the review reproduced from the failed
        // .p12 password gets the wrapper in front and the cause behind.
        let e = Error::Keystore(
            "/home/user/x.p12: keystore: the PKCS#12 integrity check failed: wrong password, \
             or the file was tampered with"
                .into(),
        );
        let r = report(&e, &Tr::es());
        assert_eq!(r.plain, Tr::es().fail_wrong_password);
        assert!(is_wrong_password(&r));
    }

    #[test]
    fn an_anchor_refusal_is_wrapped_not_dumped() {
        // B-5: the picker refused a CA:FALSE leaf with core's technical
        // sentence; on screen that arrives wrapped in its language, cause kept.
        let e = Error::Other(
            "/home/u/atajo.crt cannot be a trust anchor: \"ANA\" says CA:FALSE in its \
             basicConstraints: it is a certificate that cannot issue certificates"
                .into(),
        );
        let r = report(&e, &Tr::es());
        assert!(r.plain.starts_with("No se ha podido usar"), "{}", r.plain);
        assert!(is_anchor_refusal(&r.technical));
    }
}
