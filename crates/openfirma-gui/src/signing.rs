//! El despachador de formatos de la ventana: una sola lista, una sola cadena
//! de acceso al token, tanto para el terminal como para esta GUI.
//!
//! La lógica vive en `openfirma_browser::signing` — el único crate que depende
//! de los tres de formato sin arrastrar nada gráfico — y este módulo la llama
//! marcando la petición como venida de la ventana (`from_window`), para que un
//! nivel largo-term incompleto reciba la frase honesta que señala al terminal
//! en lugar de banderas que esta ventana nunca enseñó (hallazgo M-4: con tres
//! `match`es separados, un formato renombrado firmaba en un sitio y era
//! desconocido en otro sin que ningún test lo notase).

use openfirma_cades::TimestampFn;
use openfirma_core::alg::DigestAlg;
use openfirma_core::signer::Signer;
use openfirma_pades::Appearance;

pub use openfirma_browser::signing::{all_formats, format_label};

/// Lo que la ventana pide firmar: el formato (la misma ortografía que el
/// `--format` del terminal), el digest y lo poco que la ventana recoge.
pub struct WinRequest<'a> {
    pub format: &'a str,
    pub digest: DigestAlg,
    pub timestamp: Option<TimestampFn>,
    pub visible: Option<Appearance>,
    pub reason: Option<String>,
}

/// Produce la firma de una petición de la ventana. `input` es el documento
/// completo (lo que `openfirma sign -i` leería). Equivale exacta a lo que el
/// terminal hace con los mismos argumentos; la diferencia es solo `from_window`.
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

/// La forma completa, con la perilla extra de la GUI (un rectángulo visible).
pub fn execute_request(
    req: WinRequest<'_>,
    detected: openfirma_core::workflow::Format,
    content: &[u8],
    signer: &dyn Signer,
) -> openfirma_core::Result<Vec<u8>> {
    let mut shared = shared_request(req);
    openfirma_browser::signing::execute_request(&mut shared, detected, content, signer)
}

/// Traducción petición-ventana → petición-compartida; ningún otro camino debe
/// existir: una knob nueva que la ventana llegue a controlar se añade aquí.
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

    /// La delegación debe negarse a un formato incompatible antes de tocar el
    /// firmante: la misma guard corre aquí que en el despachador compartido.
    /// `Mock` representa cualquier signer — nunca se llama cuando se niega.
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
        // Sin TSA, B-LT no puede sellar nada y lo primero que oye es la url…
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
        // …y con ella sigue la negación honesta que esta ventana recoge: la
        // frase de delegación es compartida y apunta al terminal (la GUI no
        // recoge nada). La marca from_window hace la frase específica.
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
            unreachable!("una negativa nunca pregunta quién firma")
        }
        fn chain(&self) -> &[CertificateHandle] {
            &[]
        }
        fn key_algorithm(&self) -> openfirma_core::Result<openfirma_core::KeyAlgorithm> {
            Ok(openfirma_core::KeyAlgorithm::Rsa)
        }
        fn sign_prehash(&self, _: DigestAlg, _: &[u8]) -> openfirma_core::Result<Vec<u8>> {
            unreachable!("una negativa nunca firma")
        }
    }
}
