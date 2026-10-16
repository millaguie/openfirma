//! The signing dispatcher: one chosen format string in, signature bytes out,
//! through the exact library calls the CLI makes (`openfirma_cades::sign`,
//! `openfirma_pades::pades_sign`, `openfirma_xades::xades_sign`) with the same
//! fixed options PAdES/XAdES demand. This is the function the GUI and — after
//! this change — the CLI's `sign` command share: a format that signs one way
//! in the terminal and another way in the window is exactly the drift the
//! project forbids, so the choice lives here once.

use openfirma_cades::{CadesOptions, TimestampFn};
use openfirma_core::alg::DigestAlg;
use openfirma_core::signer::Signer;
use openfirma_core::workflow::Format;
use openfirma_core::{Error, Result};
use openfirma_pades::{Appearance, PadesOptions};

/// What a caller asks for: the format string (the same spelling the CLI's
/// `--format` takes), the digest, an optional TSA provider already wired to
/// its transport (each frontend owns its transport; see `signer_for` docs in
/// openfirma-keystore ADR-0004 for why nothing here fetches), a visible
/// appearance for PDFs, and a reason string. Everything long-term that needs
/// caller-supplied material (CRLs, OCSP responses, validation certificates)
/// is refused with the CLI's own honest sentence instead of silently signing
/// a weaker document: B-LT without revocation data is nothing, and `openfirma
/// verify` would say so afterwards.
pub struct SignRequest<'a> {
    pub format: &'a str,
    pub digest: DigestAlg,
    pub timestamp: Option<TimestampFn>,
    pub visible: Option<Appearance>,
    pub reason: Option<String>,
}

/// The format string's fixed display name (the labels of the CLI's `--format`
/// values; one table so both frontends print identical success lines).
pub fn format_label(format: &str) -> &'static str {
    match format {
        "cades-b-b" => "CAdES-B-B",
        "pades-b-b" => "PAdES-B-B",
        "pades-b-lt" => "PAdES-B-LT",
        "pades-b-lta" => "PAdES-B-LTA",
        "xades-b-b" => "XAdES-B-B",
        // An unknown string is echoed as given: it came from a caller's own
        // flag, and inventing a prettier lie helps nobody.
        _ => "desconocido",
    }
}

/// Produce the signature for one request. `input` is the whole document to
/// sign (what `openfirma sign -i` reads; a PDF, an XML, or plain bytes).
pub fn execute(
    format: &str,
    content: &[u8],
    signer: &dyn Signer,
    digest: DigestAlg,
    timestamp: Option<TimestampFn>,
    reason: Option<String>,
) -> Result<Vec<u8>> {
    let detected = Format::detect(content);
    execute_request(
        &mut SignRequest {
            format,
            digest,
            timestamp,
            visible: None,
            reason,
        },
        detected,
        content,
        signer,
    )
}

/// The full form, with the GUI's extra knob (a visible rectangle).
pub fn execute_request(
    req: &mut SignRequest<'_>,
    detected: Format,
    content: &[u8],
    signer: &dyn Signer,
) -> Result<Vec<u8>> {
    // A format that cannot carry this file shape is refused here, before any
    // signing: the citizen who picks CAdES for a PDF (or the reverse) gets
    // one sentence about what they have, not an ASN.1 stack trace.
    let allowed = detected.supported_formats();
    if !allowed.contains(&req.format) {
        return Err(Error::Other(format!(
            "{} is not a format this file can be signed as (it holds {}).",
            req.format,
            match detected {
                Format::Pdf => "a PDF document",
                Format::Xml => "an XML document",
                Format::Data => "plain data",
            }
        )));
    }
    match req.format {
        // The CLI's CAdES defaults, verbatim (docs/pades.md records why PAdES
        // pins its own shape): encapsulation is the caller's choice and the
        // GUI keeps AutoFirma's default off — detached is the citizen answer.
        "cades-b-b" => {
            let mut opts = CadesOptions {
                digest: req.digest,
                encapsulate_content: false,
                ..CadesOptions::default()
            };
            opts.timestamp = req.timestamp.clone();
            openfirma_cades::sign(content, signer, &opts)
        }
        // PAdES fixes the CAdES shape itself: detached, no signingTime (the
        // time lives in /M), no contentHint. B-LT/B-LTA need caller material
        // the GUI does not collect; see the refusals below.
        "pades-b-b" | "pades-b-lt" | "pades-b-lta" => {
            let ltv = matches!(req.format, "pades-b-lt" | "pades-b-lta");
            if ltv && req.timestamp.is_none() {
                // The same honest refusal `openfirma sign` prints for the LTA
                // level: the document time-stamp imprints bytes that exist
                // only while signing, so a pre-fetched token cannot serve it.
                return Err(Error::Other(
                    "the long-term levels need a TSA url (advanced options): their \
                     time-stamps imprint bytes that only exist while signing."
                        .into(),
                ));
            }
            if ltv {
                // No CRL/OCSP path in the GUI, so B-LT cannot honestly claim
                // what B-LT means. The CLI documents why it refuses half a
                // level; the window says the same thing in one sentence.
                return Err(Error::Other(
                    "PAdES B-LT archives revocation data (CRLs or OCSP responses) that \
                     openfirma never downloads, and this window collects none: use \
                     `openfirma sign --format pades-b-lt --crl …` from a terminal for the \
                     long-term level."
                        .into(),
                ));
            }
            openfirma_pades::pades_sign(
                content,
                signer,
                &PadesOptions {
                    digest: req.digest,
                    reason: req.reason.clone(),
                    visible: req.visible.take(),
                    timestamp: req.timestamp.clone(),
                    ..PadesOptions::default()
                },
            )
        }
        "xades-b-b" => openfirma_xades::xades_sign(
            content,
            signer,
            &openfirma_xades::XadesOptions {
                digest: req.digest,
                mime_type: None,
                ..Default::default()
            },
        ),
        other => Err(Error::Other(format!("unknown signature format {other:?}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The dispatcher must refuse a mismatched format *before* touching the
    /// signer: the same guard runs whether bytes were read by file, drag or
    /// paste. `none` stands for any signer — it is never called on a refusal.
    #[test]
    fn a_format_that_cannot_hold_the_file_is_refused() {
        let signer: &dyn Signer = &Mock;
        let err = execute(
            "cades-b-b",
            b"%PDF-1.4\n",
            signer,
            DigestAlg::Sha256,
            None,
            None,
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("not a format this file can be signed as"),
            "{err}"
        );
        let err =
            execute("pades-b-b", b"hello", signer, DigestAlg::Sha256, None, None).unwrap_err();
        assert!(err.to_string().contains("plain data"), "{err}");
    }

    #[test]
    fn half_a_long_term_level_is_refused() {
        // Without a TSA even B-LT cannot seal anything, so the first refusal
        // is the missing url…
        let err = execute(
            "pades-b-lt",
            b"%PDF-1.4\n",
            &Mock,
            DigestAlg::Sha256,
            None,
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("TSA url"), "{err}");
        // …and with one, the missing CRL/OCSP collection is still refused
        // with the CLI's pointer to the terminal (the GUI collects none).
        let tsa: TimestampFn = std::sync::Arc::new(|_, _| Ok(vec![vec![0u8; 2]]));
        let err = execute(
            "pades-b-lt",
            b"%PDF-1.4\n",
            &Mock,
            DigestAlg::Sha256,
            Some(tsa),
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("openfirma sign"), "{err}");
    }

    #[test]
    fn labels_are_the_clis_table() {
        assert_eq!(format_label("pades-b-lta"), "PAdES-B-LTA");
        assert_eq!(format_label("cades-b-b"), "CAdES-B-B");
    }

    use openfirma_core::CertificateHandle;
    struct Mock;
    impl Signer for Mock {
        fn certificate(&self) -> &CertificateHandle {
            unreachable!("a refusal never asks who signs")
        }
        fn chain(&self) -> &[CertificateHandle] {
            &[]
        }
        fn key_algorithm(&self) -> openfirma_core::Result<openfirma_core::KeyAlgorithm> {
            Ok(openfirma_core::KeyAlgorithm::Rsa)
        }
        fn sign_prehash(&self, _: DigestAlg, _: &[u8]) -> openfirma_core::Result<Vec<u8>> {
            unreachable!("a refusal never signs")
        }
    }
}
