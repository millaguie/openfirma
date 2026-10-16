//! Verification-side regressions from the adversarial review: a time-stamp
//! token whose TSTInfo bytes are rewritten after the TSA signed them no
//! longer verifies, and its verified genTime is reported (C2/A2); external
//! content that contradicts the encapsulated one is refused instead of
//! silently ignored (A1).

use std::path::{Path, PathBuf};
use std::process::Command;

use openfirma_cades::{CadesOptions, sign};
use openfirma_core::{CertificateHandle, DigestAlg, SoftwareSigner};

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

fn openssl_available() -> bool {
    Command::new("openssl")
        .arg("-version")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn scratch(name: &str) -> PathBuf {
    let test = std::thread::current()
        .name()
        .unwrap_or("main")
        .replace("::", "_");
    let dir = std::env::temp_dir().join(format!("openfirma-{}-{test}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

/// The genuine openssl-produced token for `message` from the test TSA: a
/// library-built query (`tsp::request`), an offline reply, and the token
/// sliced out of it — the same construction the B-T crosscheck uses.
fn tsa_token(certs: &Path, dir: &Path, message: &[u8]) -> Vec<u8> {
    let data = dir.join("sigvalue.bin");
    std::fs::write(&data, message).unwrap();
    let request = dir.join("consulta.tsq");
    let reply = dir.join("respuesta.tsr");
    let query = openfirma_cades::tsp::request(DigestAlg::Sha256, message, 0x0a0b_0c0d)
        .expect("la consulta se construye");
    std::fs::write(&request, &query).unwrap();
    // openssl ts -reply wants a TSA config section; the serial file it reads
    // lives next to this scratch cnf, inside the scratch dir (a relative path
    // would resolve against the process' cwd and litter the repository).
    let serial = dir.join("tsaserial");
    std::fs::write(&serial, "4242\n").unwrap();
    let cnf = dir.join("tsa.cnf");
    std::fs::write(
        &cnf,
        format!(
            "[tsa]\ndefault_tsa = tsa_config1\n[tsa_config1]\nserial = {}\ncrypto_device = builtin\ndefault_policy = 1.2.3.4.1\ndigests = sha256\naccuracy = secs:1\nordering = no\ntsa_name = no\ness_cert_id_chain = no\ness_cert_id_alg = sha256\nsigner_digest = sha256\n",
            serial.display()
        ),
    )
    .unwrap();
    let out = Command::new("openssl")
        .args([
            "ts",
            "-reply",
            "-config",
            cnf.to_str().unwrap(),
            "-queryfile",
            request.to_str().unwrap(),
            "-out",
            reply.to_str().unwrap(),
            "-signer",
            certs.join("tsa.crt").to_str().unwrap(),
            "-inkey",
            certs.join("tsa.key").to_str().unwrap(),
            "-chain",
            certs.join("chain.crt").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    openfirma_cades::tsp::token_from_response(
        &std::fs::read(&reply).unwrap(),
        DigestAlg::Sha256,
        message,
    )
    .expect("el token del TSA de pruebas debe leerse")
}

/// `openfirma verify <cms>` with explicit anchors and no bundle from the
/// environment: (ok, stdout+stderr).
fn verify_cli(signature: &Path, content: Option<&Path>, trust: &[PathBuf]) -> (bool, String) {
    let cli = openfirma_cli().expect("el binario openfirma no esta construido");
    let mut cmd = Command::new(cli);
    cmd.env_remove("OPENFIRMA_TRUST");
    // the CLI takes its input with -i/--input, like `sign` does
    cmd.arg("verify").arg("--input").arg(signature);
    if let Some(content) = content {
        cmd.arg("--content").arg(content);
    }
    for anchor in trust {
        cmd.arg("--trust").arg(anchor);
    }
    let out = cmd.output().expect("openfirma no arranca");
    let mut text = String::from_utf8_lossy(&out.stdout).to_string();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.success(), text)
}

/// C2/A2: token verification bound to its TSTInfo. The reviewer's PoC (a
/// genuine `openssl ts -reply` token whose genTime or messageImprint is
/// rewritten) used to return Ok; now both tampered forms fail, the untouched
/// one passes and reports its genTime, and openssl refuses the same file.
#[test]
fn timestamp_token_is_bound_to_its_tstinfo() {
    let Some(certs) = require_or_skip("falta el PKI de pruebas, ejecuta tools/gen-testcert.sh")
    else {
        return;
    };
    if !openssl_available() {
        eprintln!("SKIP: openssl no disponible");
        return;
    }
    let dir = scratch("tst");
    let data = dir.join("sigvalue.bin");
    std::fs::write(&data, b"sigvalue").unwrap();
    let token = tsa_token(&certs, &dir, b"sigvalue");

    let ca = CertificateHandle::from_pem(&std::fs::read_to_string(certs.join("ca.crt")).unwrap())
        .unwrap();
    let now = std::time::SystemTime::now();

    // el token intacto verifica y devuelve su genTime
    let status =
        openfirma_cades::tsp::verify_token_signature(&token, std::slice::from_ref(&ca), now)
            .expect("un token genuino debe verificar");
    assert!(
        status.gen_time < std::time::SystemTime::now()
            && status.gen_time
                > std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000),
        "debe reportar un genTime verificado razonable: {:?}",
        status.gen_time
    );

    // PoC del revisor 1: reescribir el genTime (2026 -> 2016) dentro del
    // TSTInfo. Antes verificaba; ahora el messageDigest no cuadra.
    let mut tampered = token.clone();
    let pos = tampered
        .windows(4)
        .position(|w| w == b"2026")
        .expect("el genTime lleva 2026");
    tampered[pos + 2] = b'1';
    let err =
        openfirma_cades::tsp::verify_token_signature(&tampered, std::slice::from_ref(&ca), now)
            .expect_err("un genTime reescrito debe rechazarse");
    assert!(
        err.to_string().contains("messageDigest"),
        "el error debe nombrar la prueba que falla: {err}"
    );

    // PoC del revisor 2: sustituir el messageImprint por el de otro mensaje.
    let mut reimprinted = token.clone();
    let want = DigestAlg::Sha256.digest(b"sigvalue");
    let p = reimprinted
        .windows(32)
        .position(|w| w == want.as_slice())
        .expect("el imprint esta en el token");
    reimprinted[p..p + 32].copy_from_slice(&DigestAlg::Sha256.digest(b"OTRO DOCUMENTO"));
    let err =
        openfirma_cades::tsp::verify_token_signature(&reimprinted, std::slice::from_ref(&ca), now)
            .expect_err("un imprint reescrito debe rechazarse");
    let _ = err;

    // openssl, criterio independiente, rechaza el mismo fichero adulterado.
    let tst = dir.join("adulterado.tst");
    std::fs::write(&tst, &tampered).unwrap();
    let out = Command::new("openssl")
        .args(["ts", "-verify", "-token_in", "-in"])
        .arg(&tst)
        .args(["-data"])
        .arg(&data)
        .args(["-CAfile", certs.join("ca.crt").to_str().unwrap()])
        .output()
        .unwrap();
    let texto =
        String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "openssl acepto el token adulterado:\n{texto}"
    );

    // y acepta el genuino: la puerta no esta simplemente al reves
    let tst = dir.join("genuino.tst");
    std::fs::write(&tst, &token).unwrap();
    let out = Command::new("openssl")
        .args(["ts", "-verify", "-token_in", "-in"])
        .arg(&tst)
        .args(["-data"])
        .arg(&data)
        .args(["-CAfile", certs.join("ca.crt").to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{:?}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A1 through the CLI: `--content` against an encapsulated signature is no
/// longer silently ignored. Same bytes pass; different bytes fail naming the
/// cause (the reviewer's a.csig + b.txt PoC).
#[test]
fn explicit_content_conflicting_with_the_encapsulated_one_is_refused() {
    let Some(certs) = require_or_skip("falta el PKI de pruebas, ejecuta tools/gen-testcert.sh")
    else {
        return;
    };
    if !openssl_available() || openfirma_cli().is_none() {
        eprintln!("SKIP: openssl o el binario openfirma no estan disponibles");
        return;
    }
    let dir = scratch("contenido");
    let a = dir.join("a.txt");
    std::fs::write(&a, b"contrato A: pago 10 EUR\n").unwrap();
    let b = dir.join("b.txt");
    std::fs::write(&b, b"contrato B: pago 990 EUR\n").unwrap();
    let der = of_sign(
        &certs,
        "signer-rsa.crt",
        "signer-rsa.key",
        &["intermediate.crt"],
        b"contrato A: pago 10 EUR\n",
    );
    let cms_path = dir.join("a.cms");
    std::fs::write(&cms_path, &der).unwrap();
    let cms = cms_path.as_path();

    let ca_pem = certs.join("ca.crt");
    let (ok, text) = verify_cli(cms, Some(&a), std::slice::from_ref(&ca_pem));
    assert!(ok, "el mismo contenido debe pasar:\n{text}");

    let (ok, text) = verify_cli(cms, Some(&b), std::slice::from_ref(&ca_pem));
    assert!(!ok, "la firma de a.txt paso contra b.txt:\n{text}");
    assert!(
        text.contains("not the same document"),
        "el error debe nombrar la causa:\n{text}"
    );
}
