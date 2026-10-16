//! Chain-rule regressions from the adversarial review: only a certificate
//! the X.509 rules mark as an authority may issue another (C1), and a chain
//! built over non-authorities — the CA:FALSE leaf anchored in itself, the
//! reviewer's "FALSO MINISTRO" PoC that used to answer FIRMA VALIDA — is
//! refused while the legitimate chain keeps verifying.

use std::path::{Path, PathBuf};
use std::process::Command;

use openfirma_cades::verify::{CertRole, check_certificate_rules};
use openfirma_core::SoftwareSigner;

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

fn openfirma_cli() -> Option<PathBuf> {
    let mut path = std::env::current_exe()
        .expect("current exe")
        .parent()
        .and_then(|p| p.parent())
        .expect("target dir")
        .join("openfirma");
    if cfg!(windows) {
        path.set_extension("exe");
    }
    path.exists().then_some(path)
}

/// Encapsulated CMS produced by openfirma's own signer (the same code path the
/// golden tests use), signed with `cert`/`key` and embedding `chain`.
fn of_sign(certs: &Path, cert: &str, key: &str, chain: &[&str], content: &[u8]) -> Vec<u8> {
    let cert_pem = std::fs::read_to_string(certs.join(cert)).unwrap();
    let key_pem = std::fs::read_to_string(certs.join(key)).unwrap();
    let signer = SoftwareSigner::from_pkcs8_pem(&cert_pem, &key_pem)
        .unwrap_or_else(|e| panic!("{cert}: {e}"));
    let handles: Vec<CertificateHandle> = chain
        .iter()
        .map(|c| {
            CertificateHandle::from_pem(&std::fs::read_to_string(certs.join(c)).unwrap())
                .unwrap_or_else(|e| panic!("{c}: {e}"))
        })
        .collect();
    let signer = signer.with_chain(handles);
    sign(
        content,
        &signer,
        &CadesOptions {
            encapsulate_content: true,
            ..Default::default()
        },
    )
    .expect("signing failed")
}


/// C1, the reviewer's PoC: `testdata/certs/signer-nonca.crt` is a perfectly
/// ordinary CA:FALSE leaf of the test intermediate. The attack the verifier
/// used to swallow was climbing chains over certificates that are not
/// authorities; what must now hold is that (a) a certificate may only certify
/// others when basicConstraints says so, and (b) the legitimate chain still
/// verifies with its real root.
#[test]
fn only_certificates_marked_ca_may_issue_others() {
    let Some(certs) = require_or_skip("falta el PKI de pruebas, ejecuta tools/gen-testcert.sh")
    else {
        return;
    };
    let leaf = CertificateHandle::from_pem(
        &std::fs::read_to_string(certs.join("signer-nonca.crt")).unwrap(),
    )
    .unwrap();
    // The direct statement of the rule the old build_chain_refs never made.
    let err = check_certificate_rules(&leaf, CertRole::Issuer { depth_below: 1 })
        .expect_err("un certificado CA:FALSE jamas debe poder emitir certificados");
    let texto = err.to_string();
    assert!(
        (texto.contains("CA:FALSE") && texto.contains("basicConstraints"))
            || texto.contains("keyCertSign"),
        "el error debe nombrar la regla de emisor que falla: {texto}"
    );

    // An intermediate legitima si puede, con su keyCertSign incluido.
    let intermediate = CertificateHandle::from_pem(
        &std::fs::read_to_string(certs.join("intermediate.crt")).unwrap(),
    )
    .unwrap();
    check_certificate_rules(&intermediate, CertRole::Issuer { depth_below: 1 })
        .expect("la intermedia de pruebas es una CA correcta");

    // Y el firmante normal pasa como Signer.
    let signer = CertificateHandle::from_pem(
        &std::fs::read_to_string(certs.join("signer-rsa.crt")).unwrap(),
    )
    .unwrap();
    check_certificate_rules(&signer, CertRole::Signer).expect("el firmante puede firmar");
}

/// End to end over the CLI: a CA:FALSE leaf signing through openssl smime with
/// its chain embedded verifies against the root (it is a normal leaf, and
/// over-hardening must not break it). The PoC shape — the signer's own
/// certificate offered as the only anchor — must fail instead of green.
#[test]
fn ca_false_leaf_with_itself_as_anchor_is_not_a_valid_signature() {
    let Some(certs) = require_or_skip("falta el PKI de pruebas, ejecuta tools/gen-testcert.sh")
    else {
        return;
    };
    if !openssl_available() || openfirma_cli().is_none() {
        eprintln!("SKIP: openssl o el binario openfirma no estan disponibles");
        return;
    }
    let dir = scratch("poc");
    let der = of_sign(
        &certs,
        "signer-nonca.crt",
        "signer-nonca.key",
        &["intermediate.crt"],
        b"Resolucion firmada por el ministro.\n",
    );
    // El CLI abre un fichero, no una variable: el CMS se escribe en el scratch
    // del test y desde ahi lo lee `verify`.
    let cms_path = dir.join("poc.cms");
    std::fs::write(&cms_path, &der).unwrap();
    let cms = cms_path.as_path();

    // Ancla = el propio firmante: ninguna autoridad responde por el, y un
    // CA:FALSE no puede auto-certificarse. Antes daba FIRMA VALIDA (C1). El
    // error nombra la regla que lo impide.
    let (ok, text) = verify_cli(cms, None, &[certs.join("signer-nonca.crt")]);
    assert!(
        !ok,
        "un certificado CA:FALSE auto-ancorado no puede dar FIRMA VALIDA:\n{text}"
    );

    // Y con la cadena legitima en mano (raiz + intermedia), SI verifica.
    let (ok, text) = verify_cli(
        cms,
        None,
        &[certs.join("ca.crt"), certs.join("intermediate.crt")],
    );
    assert!(ok, "la cadena legitima debe seguir verificando:\n{text}");
}
