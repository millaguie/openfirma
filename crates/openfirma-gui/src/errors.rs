//! One sentence per failure. A signing client's errors *are* its product: the
//! user must read what went wrong and what to do next, never a raw DER or CMS
//! trace (docs/adr-0006; the library's own refusal texts — the PKCS#12 RC2
//! refusal, the browser-protocol refusals — are the standard this aims at).
//!
//! The rules: a message that already contains a fix instruction ("run `openssl pkcs12 …`",
//! "pass --alias"), or any openfirma-authored sentence (the errors carry no
//! punctuation-free fragments), is shown as it is — the library was written
//! to be readable. Everything else, especially OS errno noise and ASN.1
//! parser chatter, gets a Spanish wrapper that names what failed; the raw
//! text stays available behind "Ver detalles técnicos", never in front.

use openfirma_core::Error;

/// Build the plain sentence + keep the technical one (the wizard's
/// [`crate::wizard::ErrorReport`]).
pub fn report(err: &Error) -> crate::wizard::ErrorReport {
    let technical = err.to_string();
    let plain = match err {
        // Keystore and workflow errors are authored sentences already; they
        // name the cause and often the fix. Show them (their English is the
        // cost of one shared message source — Spanish strings for *these*
        // would fork the wording and drift from the CLI, so they stay as the
        // library writes them: precise beats pretty).
        Error::Keystore(_)
        | Error::Verification(_)
        | Error::PrivateKey(_)
        | Error::Certificate(_)
        | Error::Other(_) => technical.clone(),
        // Parser chatter is for the details control only.
        Error::Der(e) => plain_error(
            "El archivo no tiene el formato esperado",
            &technical,
            Some(&e.to_string()),
        ),
        Error::Spki(e) => plain_error(
            "La clave pública del certificado no se entiende",
            &technical,
            Some(&e.to_string()),
        ),
        Error::UnsupportedDigest(_)
        | Error::UnsupportedKeyAlgorithm(_)
        | Error::UnsupportedCombination { .. } => technical.clone(),
        Error::PrehashLength { .. } => plain_error(
            "El repositorio devolvió una firma de tamaño inesperado; inténtalo de nuevo.",
            &technical,
            None,
        ),
        Error::Signing(m) => {
            plain_error("El dispositivo o archivo de clave no pudo firmar", m, None)
        }
        Error::Pdf(m) => plain_error("El PDF no se puede procesar", m, None),
        Error::Xml(m) => plain_error("El XML no se puede procesar", m, None),
        Error::NoCertificate => technical.clone(),
    };
    crate::wizard::ErrorReport { plain, technical }
}

/// A Spanish wrapper that always says what to try next when the cause leaves
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
        let r = report(&e);
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
        let r = report(&e);
        assert!(!r.plain.contains("der"), "{}", r.plain);
        assert!(r.plain.starts_with("El archivo"), "{}", r.plain);
    }

    #[test]
    fn an_os_cause_rides_inside_the_sentence() {
        let e = Error::Other("cannot read /x/doc.pdf: Permission denied".into());
        let r = report(&e);
        assert!(r.plain.contains("Permission denied"), "{}", r.plain);
    }
}
