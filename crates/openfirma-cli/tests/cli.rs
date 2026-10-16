//! End to end CLI behaviour that the unit tests in main.rs cannot reach:
//! what the binary itself does with the flags, through argv and stderr.

use std::path::Path;
use std::process::Command;

/// Temp file named after the running test, because cargo runs the tests of
/// one binary in parallel threads.
fn write_tmp(name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let test = std::thread::current()
        .name()
        .unwrap_or("main")
        .replace("::", "_");
    let path = std::env::temp_dir().join(format!("openfirma-{}-{test}-{name}", std::process::id()));
    std::fs::write(&path, bytes).expect("cannot write temp file");
    path
}

/// `-i f.pdf -o f.pdf` replaces the only copy of the document the user named,
/// and the guard against that typo runs before anything is read or signed, so
/// this needs no certificate material to fail in exactly the right way.
#[test]
fn sign_refuses_to_overwrite_its_input_without_force() {
    let doc = write_tmp("in-place.pdf", b"%PDF-1.4\nnot really, but never read\n");
    let out = Command::new(env!("CARGO_BIN_EXE_openfirma"))
        .args([
            "sign",
            "-i",
            doc.to_str().unwrap(),
            "-o",
            doc.to_str().unwrap(),
            "--cert",
            "nonexistent.crt",
            "--key",
            "nonexistent.key",
        ])
        .output()
        .expect("the binary must run");
    assert!(!out.status.success(), "in-place signing must be refused");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--force"),
        "the refusal must name the flag that makes it explicit: {stderr}"
    );
    assert!(
        stderr.contains("both the input and the output"),
        "the refusal must say what is wrong: {stderr}"
    );
    assert!(
        !stderr.contains("nonexistent.crt"),
        "the guard runs before any file is read: {stderr}"
    );
    std::fs::remove_file(&doc).ok();
}

/// --at is judged as a calendar: a date that never existed is refused with
/// the reason, instead of silently rolling into the next month.
#[test]
fn verify_refuses_an_impossible_validation_date() {
    let doc = write_tmp("impossible-date.bin", b"not a signature");
    let trust = write_tmp("impossible-date.crt", b"not a certificate");
    let out = Command::new(env!("CARGO_BIN_EXE_openfirma"))
        .args([
            "verify",
            "-i",
            doc.to_str().unwrap(),
            "--trust",
            trust.to_str().unwrap(),
            "--at",
            "2026-02-31",
        ])
        .output()
        .expect("the binary must run");
    // the trust file is not a certificate, so the run fails either way; what
    // this test pins is that the failure is the date, which is checked while
    // the flag is parsed, before the file is touched
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("not a calendar date"),
        "2026-02-31 must be refused as a date: {stderr}"
    );
    std::fs::remove_file(&doc).ok();
    std::fs::remove_file(&trust).ok();
}

/// `OPENFIRMA_PASSWORD` is offered by the refusal text of every command that
/// opens a PKCS#12, so every one of them must actually read it: an earlier
/// revision wired it only into `sign`, and `afirma-uri`/`afirma-serve` failed
/// with a message pointing at an input they ignored. The env is set on the
/// child only — not this test process — so the tests stay independent.
#[test]
fn openfirma_password_reaches_the_browser_subcommands_too() {
    let certs = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/certs");
    let p12 = certs.join("signer-rsa.p12");
    if !p12.exists() {
        if std::env::var_os("OPENFIRMA_REQUIRE_TESTS").is_some() {
            panic!("OPENFIRMA_REQUIRE_TESTS is set and testdata/certs/signer-rsa.p12 is missing");
        }
        eprintln!("skipped: the test PKI is absent, run tools/gen-testcert.sh");
        return;
    }
    let uri = "afirma://sign?format=CAdES&algorithm=SHA256withRSA&dat=aG9sYSBtdW5kbyBzaWduYWRvIGRlc2RlLg%3D%3D";
    let out_path = write_tmp("env-password.sig", b"");
    let out = Command::new(env!("CARGO_BIN_EXE_openfirma"))
        .args([
            "afirma-uri",
            uri,
            "--p12",
            p12.to_str().unwrap(),
            "-o",
            out_path.to_str().unwrap(),
        ])
        .env("OPENFIRMA_PASSWORD", "openfirma")
        .output()
        .expect("the binary must run");
    assert!(
        out.status.success(),
        "afirma-uri must sign with the password from OPENFIRMA_PASSWORD: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let payload = std::fs::read(&out_path).expect("the signature file was written");
    assert!(
        String::from_utf8_lossy(&payload).contains('|'),
        "the payload is AutoFirma's cert|signature form"
    );

    // afirma-serve: --token-only opens the container (fail-fast on the key)
    // and prints port + token without serving; a wrong password must therefore
    // fail where an env-supplied correct one succeeds.
    let out = Command::new(env!("CARGO_BIN_EXE_openfirma"))
        .args([
            "afirma-serve",
            "--p12",
            p12.to_str().unwrap(),
            "--token-only",
        ])
        .env("OPENFIRMA_PASSWORD", "openfirma")
        .output()
        .expect("the binary must run");
    assert!(
        out.status.success(),
        "afirma-serve must start with the password from OPENFIRMA_PASSWORD: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("listening on"), "{stdout}");
    assert!(stdout.contains("token:"), "{stdout}");
    std::fs::remove_file(&out_path).ok();
}

/// Finding M-4's standing proof. The terminal's `--format` values, the shared
/// dispatcher's list, and every label both frontends print must be one table:
/// while each frontend kept its own, a renamed format signed in one place and
/// was unknown in the other with no test to notice. Here the CLI's clap enum
/// is asked for its own accepted values (exactly what `--help` prints), and
/// both sides are compared against the browser crate's shared table.
#[test]
fn every_format_is_one_table_across_terminal_window_and_dispatcher() {
    // 1. The flags the CLI actually accepts, straight out of its clap parser.
    let accepted = Command::new(env!("CARGO_BIN_EXE_openfirma"))
        .args(["sign", "--help"])
        .output()
        .expect("the binary must run");
    assert!(accepted.status.success(), "--help must succeed");
    let help = String::from_utf8_lossy(&accepted.stdout);
    let block = help
        .split("--format <FORMAT>")
        .nth(1)
        .and_then(|rest| rest.split("[default:").next())
        .expect("the --format block of the help");
    let mut cli_formats: Vec<&str> = block
        .lines()
        .map(str::trim)
        .filter_map(|l| l.strip_prefix("- "))
        .map(|rest| rest.split([':', ' ']).next().unwrap_or_default())
        .filter(|w| w.contains("-b-"))
        .collect();
    cli_formats.sort_unstable();

    // 2. The shared dispatcher's listing, and its labels.
    let mut shared: Vec<&str> = openfirma_browser::signing::all_formats().to_vec();
    shared.sort();
    assert_eq!(
        cli_formats, shared,
        "--format values and the shared format list must be one table"
    );

    // 3. Every listed format has a real label (never the unknown echo), and
    //    the CLI's own success line uses that same label — checked live in
    //    `signing_a_pdf_prints_the_shared_label`, this is the static half.
    for f in openfirma_browser::signing::all_formats() {
        let label = openfirma_browser::signing::format_label(f);
        assert_ne!(label, "desconocido", "{f} has no shared label");
        assert!(
            label.starts_with(|c: char| c.is_ascii_uppercase()),
            "{f} -> {label}"
        );
    }

    // 4. Both halves of the one-table guarantee, live: clap names every shared
    //    format in its refusal of a near-miss, and the dispatcher — reached
    //    past clap by any caller that spells the flag wrong at runtime — is
    //    honest about what it does not know instead of signing something.
    let out = Command::new(env!("CARGO_BIN_EXE_openfirma"))
        .args(["sign", "--format", "pades-b-ltbogus"])
        .output()
        .expect("the binary must run");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("possible values"), "{stderr}");
    for f in openfirma_browser::signing::all_formats() {
        assert!(stderr.contains(f), "clap's list is missing {f}: {stderr}");
    }
    // The dispatcher's own table says no, not the file-shape gate: a request
    // whose format fits the bytes' shape but names a level that frontend and
    // dispatcher both lack (an unknown *suffix* of a supported prefix — exactly
    // how M-4 drift appeared) must hear "unknown signature format", proving the
    // refusal comes from the table, not from checking file shapes.
    let mut req = openfirma_browser::signing::SignRequest::new(
        "cades-b-b-extra",
        openfirma_core::alg::DigestAlg::Sha256,
    );
    let err = openfirma_browser::signing::execute_request(
        &mut req,
        openfirma_core::workflow::Format::Data,
        b"hello",
        &fail_signer(),
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("unknown signature format"),
        "{err}"
    );
    // …and the shape gate keeps its own honest sentence for a format that is
    // valid somewhere but not for these bytes (a PDF cannot carry CAdES):
    // neither door ever signs what it does not know, and each says which.
    let mut req = openfirma_browser::signing::SignRequest::new(
        "cades-b-b",
        openfirma_core::alg::DigestAlg::Sha256,
    );
    let pdf_path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/inputs/simple.pdf");
    let Ok(pdf) = std::fs::read(&pdf_path) else {
        eprintln!("skipped the shape sentence, run tools/gen-testpdf.py");
        return;
    };
    let err = openfirma_browser::signing::execute_with_detection(&mut req, &pdf, &fail_signer())
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("not a format this file can be signed as"),
        "{err}"
    );
}

/// Every CAdES knob `sign` offers must reach the CMS the binary actually
/// writes — through argv, not through a library call. The request builder in
/// main.rs was shadowed once by a second one (the PAdES LTV fields replaced
/// the shared request instead of joining it), and every flag set before that
/// line vanished from the signature with every gate still green: this test
/// signs real bytes and reads the attributes back through `inspect`, which is
/// exactly the way a user discovers such a bug.
#[test]
fn every_cades_flag_reaches_the_signature_the_binary_writes() {
    let Some(pki) = test_certs() else {
        eprintln!("skipped, test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    let out = write_tmp("flags.csig", b"");
    let input = write_tmp("flagged.dat", b"bytes that carry every flag\n");
    let status = Command::new(env!("CARGO_BIN_EXE_openfirma"))
        .args(["sign", "-i"])
        .arg(&input)
        .arg("-o")
        .arg(&out)
        .args(["--cert"])
        .arg(pki.join("signer-rsa.crt"))
        .arg("--key")
        .arg(pki.join("signer-rsa.key"))
        .args(["--chain"])
        .arg(pki.join("intermediate.crt"))
        .args(["--chain"])
        .arg(pki.join("ca.crt"))
        .args([
            "--content-hint",
            "documento",
            "--mime-type",
            "text/plain",
            "--no-signing-time",
        ])
        .output()
        .expect("the binary must run");
    assert!(
        status.status.success(),
        "{}",
        String::from_utf8_lossy(&status.stderr)
    );
    let report = Command::new(env!("CARGO_BIN_EXE_openfirma"))
        .args(["inspect", "-i"])
        .arg(&out)
        .output()
        .expect("the binary must run");
    let dump = String::from_utf8_lossy(&report.stdout);
    // The shared CMS attribute OIDs (RFC 5652 / ESS): signingTime .9.5,
    // contentType .9.3, messageDigest .9.4, ESS signing-certificate-v2
    // …16.2.47, contentHint …16.2.4; the mimeType attribute is the older
    // 0.4.0.1733.2.1 that our writer emits (see docs/cades.md). `inspect`
    // prints OIDs and raw values, so that is what gets asserted. Each absence
    // would be the shadowed request returning: a flag accepted, remembered
    // nowhere.
    assert!(
        dump.contains("1.2.840.113549.1.9.16.2.4") && dump.contains("UTF8String \"documento\""),
        "no contentHint reached the CMS:\n{dump}"
    );
    assert!(
        dump.contains("OID 0.4.0.1733.2.1") && dump.contains("IA5String \"text/plain\""),
        "no mimeType reached the CMS:\n{dump}"
    );
    assert!(
        !dump.contains("OID 1.2.840.113549.1.9.5\n"),
        "--no-signing-time did not reach the CMS:\n{dump}"
    );
}

/// The test PKI directory, if it has been generated.
fn test_certs() -> Option<std::path::PathBuf> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/certs");
    dir.join("signer-rsa.crt").is_file().then_some(dir)
}

/// A signer that can only fail loudly: anything but the dispatcher's own
/// refusal must not silently succeed past it.
fn fail_signer() -> NoSigner {
    NoSigner
}

struct NoSigner;
impl openfirma_core::signer::Signer for NoSigner {
    fn certificate(&self) -> &openfirma_core::CertificateHandle {
        unreachable!("the unknown-format refusal never asks who signs")
    }
    fn chain(&self) -> &[openfirma_core::CertificateHandle] {
        &[]
    }
    fn key_algorithm(&self) -> openfirma_core::Result<openfirma_core::KeyAlgorithm> {
        Ok(openfirma_core::KeyAlgorithm::Rsa)
    }
    fn sign_prehash(
        &self,
        _: openfirma_core::alg::DigestAlg,
        _: &[u8],
    ) -> openfirma_core::Result<Vec<u8>> {
        unreachable!("the unknown-format refusal never signs")
    }
}
