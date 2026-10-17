//! The window's format dispatcher: one list, one token access path, shared by
//! the terminal and this GUI.
//!
//! The logic lives in `openfirma_browser::signing` — the only crate that
//! depends on the three format crates without dragging in anything graphic —
//! and this module calls it marking the request as coming from the window
//! (`from_window`), so an incomplete long-term level receives the honest
//! sentence that points at the terminal instead of flags this window never
//! showed (finding M-4: with three separate `match`es, a renamed format signed
//! in one place and was unknown in the other without any test noticing).

use openfirma_cades::TimestampFn;
use openfirma_core::alg::DigestAlg;
use openfirma_core::signer::Signer;
use openfirma_pades::Appearance;

pub use openfirma_browser::signing::{all_formats, format_label};

/// What the window asks to sign: the format (the same spelling as the
/// terminal's `--format`), the digest and the few things the window collects.
pub struct WinRequest<'a> {
    pub format: &'a str,
    pub digest: DigestAlg,
    pub timestamp: Option<TimestampFn>,
    pub visible: Option<Appearance>,
    pub reason: Option<String>,
}

/// Produces the signature for a window request. `input` is the whole document
/// (what `openfirma sign -i` would read). Exactly what the terminal does with
/// the same arguments; the only difference is `from_window`.
pub fn execute(
    format: &str,
    content: &[u8],
    signer: &dyn Signer,
    digest: DigestAlg,
    timestamp: Option<TimestampFn>,
    reason: Option<String>,
) -> openfirma_core::Result<Vec<u8>> {
    let mut req = shared_request(WinRequest {
        format,
        digest,
        timestamp,
        visible: None,
        reason,
    });
    openfirma_browser::signing::execute_with_detection(&mut req, content, signer)
}

/// The full form, with the GUI's extra knob (a visible rectangle).
pub fn execute_request(
    req: WinRequest<'_>,
    detected: openfirma_core::workflow::Format,
    content: &[u8],
    signer: &dyn Signer,
) -> openfirma_core::Result<Vec<u8>> {
    let mut shared = shared_request(req);
    openfirma_browser::signing::execute_request(&mut shared, detected, content, signer)
}

/// Window-request → shared-request translation; no other path may exist: a
/// new knob the window comes to control is added here.
fn shared_request(req: WinRequest<'_>) -> openfirma_browser::signing::SignRequest<'_> {
    let mut out =
        openfirma_browser::signing::SignRequest::new(req.format, req.digest).from_window();
    out.timestamp = req.timestamp;
    out.visible = req.visible;
    out.reason = req.reason;
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The delegation must refuse an incompatible format before touching the
    /// signer: the same guard runs here as in the shared dispatcher. `Mock`
    /// stands for any signer — it is never called when the request is refused.
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
    }

    #[test]
    fn half_a_long_term_level_is_refused() {
        // Without a TSA, B-LT cannot seal anything and the first thing heard
        // is the url…
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
        // …and with one comes the honest refusal this window collects: the
        // delegation sentence is shared and points at the terminal (the GUI
        // collects nothing). The from_window marker makes the sentence specific.
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
