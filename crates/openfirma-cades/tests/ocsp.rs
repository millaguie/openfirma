//! OCSP regressions from the adversarial review (A4): an archived response
//! is a revocation datum only while its signature verifies under the CA the
//! CertID names (or a delegate that CA authorized for id-kp-OCSPSigning),
//! and only inside the interval the answer speaks about. Everything else is
//! a claim nobody made, and the verifier must say so rather than count it.

use std::path::{Path, PathBuf};

use openfirma_cades::read_ocsp_response;
use openfirma_cades::revocation::parse_der_time;
use openfirma_core::CertificateHandle;

fn certs_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/certs")
}

fn require_or_skip(what: &str) -> Option<PathBuf> {
    let dir = certs_dir();
    if dir.join("signer-rsa.crt").is_file() {
        Some(dir)
    } else {
        eprintln!("SKIP: {what}");
        None
    }
}

/// A4: an OCSP response used as a revocation datum must be verified the way
/// openssl verifies it: responder signature over the response data, the
/// signer being the hashed CA itself or a delegated OCSPSigning certificate
/// chaining to it, and the singleResponse interval covering the validation
/// time. The old reader trusted the plaintext, so a re-signed or expired
/// answer was indistinguishable from a live one.
#[test]
fn an_ocsp_response_is_only_trusted_when_its_signer_and_validity_check_out() {
    let Some(dir) = require_or_skip("el PKI de pruebas") else {
        return;
    };
    let handle = |name: &str| -> CertificateHandle {
        CertificateHandle::from_pem(&std::fs::read_to_string(dir.join(name)).unwrap())
            .expect("un certificado del PKI")
    };
    let ocsp = std::fs::read(dir.join("signer-rsa.ocsp.der")).expect("la respuesta OCSP");
    let ca = handle("ca.crt");
    let intermediate = handle("intermediate.crt");
    let at = std::time::SystemTime::now();

    // La respuesta auténtica, validada bajo su CA.
    let status = read_ocsp_response(&ocsp, &[ca.clone(), intermediate.clone()], at);
    assert!(
        status.verified(),
        "la respuesta auténtica debe verificarse: {:?}",
        status.problem
    );

    // La misma respuesta con un byte del periodo de validez alterado (se
    // cambia un byte anterior a la firma, donde no toca ninguna DER length).
    // Alteracion quirurgica: el ultimo byte del producedAt (la primera
    // GeneralizedTime del tbsResponseData) se cambia en un bit. La DER no se
    // rompe, pero la firma deja de cubrir lo que se lee. El horario OCSP se
    // escribe en UTCTime ("YYMMDDHHMMSSZ"), así que se busca esa forma.
    let utc = ocsp
        .windows(15)
        .position(|w| w[0] == 0x17 && w[1] == 13 && w[14] == b'Z')
        .expect("la respuesta OCSP lleva producedAt en UTCTime");
    let mut forged = ocsp.clone();
    forged[utc + 14] ^= 1;
    let status = read_ocsp_response(&forged, &[ca.clone(), intermediate.clone()], at);
    // `signature_verified` stays false when the certificate that made the
    // statement can no longer be recognised as its signer: nothing verified
    // may be counted as a revocation datum either way.
    assert!(
        !status.verified(),
        "una respuesta alterada no puede pasar por auténtica: {:?}",
        status.problem
    );

    // Con un pool que no contiene al CertID-named issuer, la respuesta queda
    // desasociada de toda cadena aunque su firma sea legible para el lector.
    let status = read_ocsp_response(&ocsp, std::slice::from_ref(&ca), at);
    assert!(
        !status.verified() && !status.chains_to_issuer,
        "el CertID nombra a la intermedia y ese pool no la incluye: {:?}",
        status.problem
    );

    // El firmante debe ser LA CA nombrada o una delegada OCSPSigning suya
    // (RFC 6960 4.2.2.2), no cualquier certificado cuya clave verifique. El
    // fixture `ocsp-unauthorized.der` es una respuesta REAL de este PKI fir-
    // mada con la clave del firmante comun — ni CA ni delegada; el viejo lec-
    // tor la aceptaba porque solo miraba que la firma cuadrase.
    let unauth = dir.join("ocsp-unauthorized.der");
    if unauth.is_file() {
        let forged = std::fs::read(&unauth).unwrap();
        let status = read_ocsp_response(&forged, &[ca.clone(), intermediate.clone()], at);
        assert!(
            !status.verified(),
            "una respuesta firmada por un certificado sin OCSPSigning no es \
             un dato de revocacion: {:?}",
            status.problem
        );
    } else {
        eprintln!("SKIP: ocsp-unauthorized.der no esta en el PKI de pruebas");
    }

    // Una respuesta caducada no cubre una validación posterior a su inter-
    // valo. El fixture del PKI de pruebas trae su propio nextUpdate (hoy una
    // ventana larga, para que el test no caduque a la hora de generarlo);
    // validar justo después de ese instante debe devolverla fuera de
    // intervalo aunque firma y autoridad sigan cuadrando. Bajo el viejo
    // lector, que ignoraba el intervalo, una respuesta vieja pasaba por
    // actual para siempre. El momento exacto se lee del fixture para no
    // depender de cuando se genero.
    // El intervalo se comprueba ANTES de la autoridad del firmante (un firma
    // caducada no necesita probar quien hablo), asi que basta el momento ca-
    // ducado mas pequeño posible: justo despues del nextUpdate del fixture,
    // dentro aun de la validez del certificado de la delegada. El nextUpdate
    // es el ultimo UTCTime/GeneralizedTime del SingleResponse.
    let next_update = {
        let mut times = Vec::new();
        let mut i = 0;
        // solo los tiempos del responseBytes: el ultimo par UTCTime es el de
        // laSingleResponse, y tras el viene el certificado embebido, que lle-
        // va sus propias fechas de validez que no son el intervalo OCSP.
        let body_end = {
            let basic = b"\x06\x0b+\x06\x01\x05\x05\x070\x01\x01"; // basicOCSPResponse OID
            ocsp.windows(basic.len())
                .position(|w| w == basic)
                .map(|p| p + basic.len() + 4)
                .unwrap_or(ocsp.len())
        };
        while i + 2 < body_end {
            if matches!(ocsp[i], 0x17 | 0x18) && i + 2 <= ocsp.len() {
                let len = ocsp[i + 1] as usize;
                if (len == 13 || len == 15)
                    && i + 2 + len <= ocsp.len()
                    && ocsp[i + 2 + len - 1] == b'Z'
                {
                    let whole = &ocsp[i..i + 2 + len];
                    if let Some(t) = parse_der_time(whole) {
                        times.push(t);
                    }
                }
            }
            i += 1;
        }
        times.sort();
        *times
            .last()
            .expect("la respuesta OCSP lleva thisUpdate y nextUpdate")
    };
    let late = next_update + std::time::Duration::from_secs(60);
    let status = read_ocsp_response(&ocsp, &[ca.clone(), intermediate.clone()], late);
    assert!(
        !status.verified() && status.signature_verified && !status.current,
        "una respuesta caducada no cubre la validación: {:?}",
        status.problem
    );
}
