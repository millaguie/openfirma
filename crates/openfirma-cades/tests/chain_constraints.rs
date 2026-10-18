//! Round 2, findings N1 and N2: the two extension rules the chain walk has to
//! apply to a CA, both found by minting chains the shared test PKI cannot
//! express.
//!
//! N1, `pathLenConstraint` off by one. The walk asked each CA to certify
//! `chain.len()` certificates, which counted the end-entity signer, so a CA
//! carrying `pathlen:0` — the shape of AC FNMT Usuarios, AC Representación, the
//! FNMT sealing CAs and Firmaprofesional's intermediates, i.e. nearly every
//! Spanish citizen certificate — refused every chain that ended on it. The
//! shared test PKI carries no `pathLenConstraint` at all, which is why neither
//! CI nor the golden diff could see it, so the certificates here are minted
//! with openssl at test time.
//!
//! What must hold for N1, in both directions:
//!
//! * a CA with `pathlen:0` that issues the signer directly verifies (it is
//!   being asked to certify no intermediate at all), and so does a root with
//!   `pathlen:0` above a self-issued intermediate (RFC 5280 6.1.4 (l)/(m)
//!   only counts *non-self-issued* intermediates);
//! * a CA with `pathlen:0` that has a real intermediate below it still refuses.
//!
//! N2, `nameConstraints` (and its siblings `policyMappings` and
//! `policyConstraints`) were listed among the extensions this verifier
//! "understands" and then never applied: a sub-CA restricted to `C=FR` issued
//! for a `C=ES` signer and `verify` answered OK, every digest and signature
//! genuinely valid, while `openssl verify` refused the same chain with
//! "permitted subtree violation". They are now refused instead of read past,
//! whatever their critical bit says, which is fail-closed: a properly
//! constrained CA is refused too until the subtrees are implemented. The last
//! test pins that as a declared residual rather than leaving it to be
//! discovered.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

use openfirma_cades::verify::{CertRole, VerifyOptions, check_certificate_rules};
use openfirma_cades::{CadesOptions, sign, verify};
use openfirma_core::{CertificateHandle, SoftwareSigner};

fn openssl_available() -> bool {
    Command::new("openssl")
        .arg("-version")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn openssl(dir: &Path, args: &[&str]) {
    let out = Command::new("openssl")
        .args(args)
        .current_dir(dir)
        .output()
        .expect("openssl no arranca");
    assert!(
        out.status.success(),
        "openssl {args:?} falló:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn scratch(name: &str) -> PathBuf {
    let test = std::thread::current()
        .name()
        .unwrap_or("main")
        .replace("::", "_");
    let dir = std::env::temp_dir().join(format!(
        "openfirma-pathlen-{}-{test}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

/// One certificate minted by openssl: `ext` is the list of extension lines,
/// and `issuer` is the (key, certificate) pair that signs it, or `None` for a
/// self-signed root.
///
/// The two openssl verbs disagree on how extensions arrive: `req -x509` takes
/// them one by one with `-addext` (its `-extfile` is gone as of OpenSSL 3.6),
/// while `x509 -req` still reads an extension file.
fn mint(
    dir: &Path,
    name: &str,
    subj: &str,
    ext: &[&str],
    issuer: Option<(&Path, &Path)>,
) -> (PathBuf, PathBuf) {
    let key = dir.join(format!("{name}.key"));
    let csr = dir.join(format!("{name}.csr"));
    let crt = dir.join(format!("{name}.crt"));
    let key_s = key.to_str().unwrap();
    let crt_s = crt.to_str().unwrap();
    openssl(
        dir,
        &[
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
            "-out",
            key_s,
        ],
    );
    openssl(
        dir,
        &[
            "req",
            "-new",
            "-key",
            key_s,
            "-subj",
            subj,
            "-out",
            csr.to_str().unwrap(),
        ],
    );
    match issuer {
        None => {
            let mut args: Vec<String> = vec![
                "req".into(),
                "-x509".into(),
                "-key".into(),
                key_s.into(),
                "-subj".into(),
                subj.into(),
                "-days".into(),
                "3650".into(),
                "-sha256".into(),
            ];
            for line in ext {
                args.push("-addext".into());
                args.push((*line).into());
            }
            args.push("-out".into());
            args.push(crt_s.into());
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            openssl(dir, &args);
        }
        Some((ca_key, ca_crt)) => {
            let ext_file = dir.join(format!("{name}.ext"));
            std::fs::write(&ext_file, format!("[v3]\n{}\n", ext.join("\n"))).unwrap();
            openssl(
                dir,
                &[
                    "x509",
                    "-req",
                    "-in",
                    csr.to_str().unwrap(),
                    "-CA",
                    ca_crt.to_str().unwrap(),
                    "-CAkey",
                    ca_key.to_str().unwrap(),
                    "-CAcreateserial",
                    "-days",
                    "3650",
                    "-sha256",
                    "-extfile",
                    ext_file.to_str().unwrap(),
                    "-extensions",
                    "v3",
                    "-out",
                    crt_s,
                ],
            );
        }
    }
    (crt, key)
}

const CA_EXT: &[&str] = &[
    "basicConstraints = critical, CA:TRUE",
    "keyUsage = critical, keyCertSign, cRLSign",
];
const LEAF_EXT: &[&str] = &[
    "basicConstraints = critical, CA:FALSE",
    "keyUsage = critical, digitalSignature, nonRepudiation",
];

fn handle(path: &Path) -> CertificateHandle {
    CertificateHandle::from_pem(&std::fs::read_to_string(path).unwrap())
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// `leaf` signs `content`, the chain embedded in the CMS is `chain` in the
/// order the walk climbs it (issuer of the signer first).
fn sign_with(leaf_crt: &Path, leaf_key: &Path, chain: &[&Path], content: &[u8]) -> Vec<u8> {
    let signer = SoftwareSigner::from_pkcs8_pem(
        &std::fs::read_to_string(leaf_crt).unwrap(),
        &std::fs::read_to_string(leaf_key).unwrap(),
    )
    .expect("la clave del firmante se lee");
    let signer = signer.with_chain(chain.iter().map(|p| handle(p)).collect());
    sign(
        content,
        &signer,
        &CadesOptions {
            encapsulate_content: true,
            ..Default::default()
        },
    )
    .expect("la firma se produce")
}

fn verify_with(
    cms: &[u8],
    anchors: &[&Path],
) -> Result<Vec<openfirma_cades::verify::VerifyReport>, String> {
    verify(
        cms,
        None,
        &VerifyOptions {
            trust_anchors: anchors.iter().map(|p| handle(p)).collect(),
            validation_time: SystemTime::now() + Duration::from_secs(60),
            ..Default::default()
        },
    )
    .map_err(|e| e.to_string())
}

/// N1, positive direction: a CA with `pathlen:0` issuing the signer directly is
/// one certificate below the anchor and zero intermediates below the CA, so
/// the chain verifies. Before the fix this failed with "one certificate too
/// many sit under this CA", which is what every FNMT citizen signature hit.
#[test]
fn a_ca_with_pathlen_zero_may_issue_the_signer_directly() {
    if !openssl_available() {
        eprintln!("SKIP: openssl no disponible");
        return;
    }
    let dir = scratch("direct");
    let (root_crt, root_key) = mint(
        &dir,
        "root",
        "/CN=AC FNMT Usuarios (sintetica)",
        &[
            "basicConstraints = critical, CA:TRUE, pathlen:1",
            "keyUsage = critical, keyCertSign, cRLSign",
        ],
        None,
    );
    let root_key = root_key.as_path();
    let (int_crt, int_key) = mint(
        &dir,
        "int",
        "/CN=AC representacion (sintetica)",
        &[
            "basicConstraints = critical, CA:TRUE, pathlen:0",
            "keyUsage = critical, keyCertSign, cRLSign",
        ],
        Some((root_key, root_crt.as_path())),
    );
    let (leaf_crt, leaf_key) = mint(
        &dir,
        "leaf",
        "/C=ES/CN=NIF 00000000T (sintetico)",
        LEAF_EXT,
        Some((int_key.as_path(), int_crt.as_path())),
    );

    let cms = sign_with(
        &leaf_crt,
        &leaf_key,
        &[int_crt.as_path(), root_crt.as_path()],
        b"Certificado de la Sede Electronica.\n",
    );
    let report = verify_with(&cms, &[root_crt.as_path()])
        .expect("una CA con pathlen:0 emitiendo al firmante directo debe verificar");
    assert_eq!(report.len(), 1);
    assert!(
        report[0]
            .chain_subjects
            .iter()
            .any(|s| s.contains("AC representacion"))
    );

    // openssl, criterio independiente, acepta la misma cadena.
    let out = Command::new("openssl")
        .arg("verify")
        .arg("-CAfile")
        .arg(&root_crt)
        .arg("-untrusted")
        .arg(&int_crt)
        .arg(&leaf_crt)
        .output()
        .expect("openssl verify no arranca");
    assert!(
        out.status.success(),
        "openssl acepta esta cadena; openfirma no puede ser mas estricta por error:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// N1, negative direction: a CA with `pathlen:0` that really has an
/// intermediate below it is still refused, and the message names the
/// extension. This is the half the fix must not loosen.
#[test]
fn a_ca_with_pathlen_zero_may_not_have_an_intermediate_below() {
    if !openssl_available() {
        eprintln!("SKIP: openssl no disponible");
        return;
    }
    let dir = scratch("nested");
    let (root_crt, root_key) = mint(&dir, "root", "/CN=root sintetica", CA_EXT, None);
    let root_key = root_key.as_path();
    let (top_crt, top_key) = mint(
        &dir,
        "top",
        "/CN=CA de sellado de tiempo (sintetica)",
        &[
            "basicConstraints = critical, CA:TRUE, pathlen:0",
            "keyUsage = critical, keyCertSign, cRLSign",
        ],
        Some((root_key, root_crt.as_path())),
    );
    let (int_crt, int_key) = mint(
        &dir,
        "int",
        "/CN=intermedia (sintetica)",
        CA_EXT,
        Some((top_key.as_path(), top_crt.as_path())),
    );
    let (leaf_crt, leaf_key) = mint(
        &dir,
        "leaf",
        "/C=ES/CN=NIF 00000001R (sintetico)",
        LEAF_EXT,
        Some((int_key.as_path(), int_crt.as_path())),
    );

    let cms = sign_with(
        &leaf_crt,
        &leaf_key,
        &[int_crt.as_path(), top_crt.as_path(), root_crt.as_path()],
        b"Documento cualquiera.\n",
    );
    let err = verify_with(&cms, &[root_crt.as_path()])
        .expect_err("una CA pathlen:0 no puede tener una intermedia debajo");
    assert!(
        err.contains("pathLenConstraint"),
        "el error debe nombrar la extension que falla: {err}"
    );
}

/// N1, the RFC 5280 nuance the fix implements: 6.1.4 (l)/(m) decrements the
/// path length counter only "if the certificate is not self-issued", so a
/// self-issued intermediate below a `pathlen:0` CA still fits. openssl accepts
/// the same chain, which keeps the two verifiers in agreement.
#[test]
fn a_self_issued_intermediate_does_not_spend_the_path_length() {
    if !openssl_available() {
        eprintln!("SKIP: openssl no disponible");
        return;
    }
    let dir = scratch("selfissued");
    let (root_crt, root_key) = mint(
        &dir,
        "root",
        "/CN=AC raiz (sintetica)",
        &[
            "basicConstraints = critical, CA:TRUE, pathlen:0",
            "keyUsage = critical, keyCertSign, cRLSign",
        ],
        None,
    );
    let root_key = root_key.as_path();
    // Self-issued: the same subject as its issuer (the root), as rollover and
    // cross-signed material does. It is a real intermediate in the path, but
    // RFC 5280 does not charge it to the root's path length.
    let (int_crt, int_key) = mint(
        &dir,
        "int",
        "/CN=AC raiz (sintetica)",
        &[
            "basicConstraints = critical, CA:TRUE, pathlen:0",
            "keyUsage = critical, keyCertSign, cRLSign",
        ],
        Some((root_key, root_crt.as_path())),
    );
    let (leaf_crt, leaf_key) = mint(
        &dir,
        "leaf",
        "/C=ES/CN=NIF 00000002W (sintetico)",
        LEAF_EXT,
        Some((int_key.as_path(), int_crt.as_path())),
    );

    let cms = sign_with(
        &leaf_crt,
        &leaf_key,
        &[int_crt.as_path(), root_crt.as_path()],
        b"Renovacion de la CA raiz.\n",
    );
    verify_with(&cms, &[root_crt.as_path()])
        .expect("una intermedia autoemitida no consume el pathLenConstraint de su emisor");

    let out = Command::new("openssl")
        .arg("verify")
        .arg("-CAfile")
        .arg(&root_crt)
        .arg("-untrusted")
        .arg(&int_crt)
        .arg(&leaf_crt)
        .output()
        .expect("openssl verify no arranca");
    assert!(
        out.status.success(),
        "openssl acepta la cadena con la intermedia autoemitida:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// N2, the hole itself: a sub-CA whose `nameConstraints` permit only `C=FR`
/// issued a `C=ES` signer, and `verify` answered OK — the extension was listed
/// among the ones this verifier "understands" and then never applied. openssl
/// refuses the same chain with "permitted subtree violation", which is the
/// independent oracle for the attack this pins.
///
/// The same test pins the declared residual the refusal costs: a chain that is
/// *inside* its permitted subtree is refused as well, because the subtrees are
/// not interpreted at all. That is the fail-closed direction (a validator that
/// says no to a valid chain is wrong, one that says yes to an invalid chain is
/// dangerous), and it is written down here so the next round finds it declared
/// rather than discovered.
#[test]
fn a_ca_limited_to_another_country_may_not_issue_for_this_one() {
    if !openssl_available() {
        eprintln!("SKIP: openssl no disponible");
        return;
    }
    let dir = scratch("nameconstraints");
    let (root_crt, root_key) = mint(&dir, "root", "/CN=root sintetica", CA_EXT, None);
    let root_key = root_key.as_path();
    // the constraint is a directoryName subtree, the shape of the reviewer's
    // PoC: a CA that may only certify certificates under C=FR
    let nc_ext: &[&str] = &[
        "basicConstraints = critical, CA:TRUE, pathlen:0",
        "keyUsage = critical, keyCertSign, cRLSign",
        "nameConstraints = critical, permitted;dirName:perm_dn",
        "",
        "[perm_dn]",
        "C = FR",
    ];
    let (nc_crt, nc_key) = mint(
        &dir,
        "nc",
        "/C=ES/CN=AC limitada (sintetica)",
        nc_ext,
        Some((root_key, root_crt.as_path())),
    );

    // outside the subtree: C=ES under a C=FR limit
    let (es_crt, es_key) = mint(
        &dir,
        "leaf-es",
        "/C=ES/O=Firmante/CN=NIF 33333333C (sintetico)",
        LEAF_EXT,
        Some((nc_key.as_path(), nc_crt.as_path())),
    );
    let cms = sign_with(
        &es_crt,
        &es_key,
        &[nc_crt.as_path(), root_crt.as_path()],
        b"Instancia con sede en el extranjero.\n",
    );

    let out = Command::new("openssl")
        .arg("verify")
        .arg("-CAfile")
        .arg(&root_crt)
        .arg("-untrusted")
        .arg(&nc_crt)
        .arg(&es_crt)
        .output()
        .expect("openssl verify no arranca");
    assert!(
        !out.status.success(),
        "openssl tiene que rechazar una cadena fuera del subarbol permitido"
    );
    let oracle = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        oracle.contains("subtree violation"),
        "el oraculo tiene que ser el subarbol, no otra cosa: {oracle}"
    );

    let err = verify_with(&cms, &[root_crt.as_path()])
        .expect_err("una CA limitada a C=FR no puede emitir para C=ES");
    assert!(
        err.contains("nameConstraints"),
        "el error debe nombrar la extension que no se aplica: {err}"
    );

    // inside the subtree: the same CA issuing for C=FR is a chain openssl
    // accepts and we refuse, the declared residual
    let (fr_crt, fr_key) = mint(
        &dir,
        "leaf-fr",
        "/C=FR/O=Firmante/CN=NIF 44444444D (sintetico)",
        LEAF_EXT,
        Some((nc_key.as_path(), nc_crt.as_path())),
    );
    let out = Command::new("openssl")
        .arg("verify")
        .arg("-CAfile")
        .arg(&root_crt)
        .arg("-untrusted")
        .arg(&nc_crt)
        .arg(&fr_crt)
        .output()
        .expect("openssl verify no arranca");
    assert!(
        out.status.success(),
        "dentro del subarbol permitido openssl acepta la cadena:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let cms = sign_with(
        &fr_crt,
        &fr_key,
        &[nc_crt.as_path(), root_crt.as_path()],
        b"Instancia con sede en Francia.\n",
    );
    let err = verify_with(&cms, &[root_crt.as_path()])
        .expect_err("residuo declarado: los subarboles no se interpretan todavia");
    assert!(err.contains("nameConstraints"), "{err}");
}

/// N2, the two halves the fix must not leave open. RFC 5280 requires
/// `nameConstraints` to be critical, so the extension file a real CA writes
/// says so; a certificate whose constraint is *not* marked critical is still a
/// certificate whose limits nobody applies, and the refusal cannot be reached
/// only through the critical-extension path. And the two siblings that limit
/// what a CA may certify — `policyMappings` and `policyConstraints` — are
/// refused the same way, since they were in the same list by the same mistake.
#[test]
fn a_constraint_is_refused_even_when_it_is_not_marked_critical() {
    if !openssl_available() {
        eprintln!("SKIP: openssl no disponible");
        return;
    }
    let dir = scratch("noncritical");
    let cases: &[(&str, &[&str], &str)] = &[
        (
            "names",
            &[
                "basicConstraints = critical, CA:TRUE, pathlen:0",
                "keyUsage = critical, keyCertSign, cRLSign",
                "nameConstraints = permitted;DNS:.example.com",
            ],
            "nameConstraints",
        ),
        (
            "policies",
            &[
                "basicConstraints = critical, CA:TRUE, pathlen:0",
                "keyUsage = critical, keyCertSign, cRLSign",
                "policyConstraints = critical, requireExplicitPolicy:0",
            ],
            "policyConstraints",
        ),
        (
            "mappings",
            &[
                "basicConstraints = critical, CA:TRUE, pathlen:0",
                "keyUsage = critical, keyCertSign, cRLSign",
                "policyMappings = critical, \"1.3.6.1.4.1.5734.3.10.1\":\"2.23.140.1.2.1\"",
            ],
            "policyMappings",
        ),
    ];
    for (name, ext, expected) in cases {
        let (crt, _key) = mint(&dir, name, &format!("/CN=CA con {expected}"), ext, None);
        let err = check_certificate_rules(&handle(&crt), CertRole::Issuer { depth_below: 0 })
            .expect_err("una CA con una restriccion que no se aplica no puede emitir");
        let text = err.to_string();
        assert!(
            text.contains(expected) && text.contains("does not apply"),
            "el error debe nombrar la extension y decir que no se aplica: {text}"
        );
    }
}
