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

/// The config a `--register` run leaves behind, built with the SAME writer the
/// installer uses, not by hand: a hand made `p12 = "C:\Users\...\clave.p12"` is
/// not a value at all on Windows — the backslashes are escape sequences — so a
/// test that formatted one itself failed on the Windows runners for a reason
/// that had nothing to do with the rule it was checking (CI run 39202830689).
/// `to_toml` doubles them.
fn browser_config(p12: &Path, pw: &Path, allow_unattended: bool) -> String {
    openfirma_browser::scheme::BrowserConfig {
        p12: Some(p12.to_path_buf()),
        password_file: Some(pw.to_path_buf()),
        allow_unattended,
    }
    .to_toml()
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

/// B-1: verifying an XML file (XAdES) must say what is going on, not leak the
/// CMS codec's complaint. Before this, `verify` on a signed XML answered
/// "these bytes are not a CMS signature: expected the ContentInfo (tag 0x30),
/// found tag 0x3c" — 0x3c is `<`, so the message read like corruption rather
/// than "XAdES is not verified here yet".
#[test]
fn verify_names_xades_instead_of_leaking_a_cms_codec_error() {
    let xml = write_tmp(
        "signed.xml",
        b"<?xml version=\"1.0\"?>\n<doc><Signature/></doc>",
    );
    // a REAL certificate as the anchor: the XAdES refusal must be about the
    // input, not about the anchor (the CLI loads anchors before the input)
    let trust = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/certs/ca.crt");
    if !trust.exists() {
        if std::env::var_os("OPENFIRMA_REQUIRE_TESTS").is_some() {
            panic!("OPENFIRMA_REQUIRE_TESTS is set and testdata/certs/ca.crt is missing");
        }
        eprintln!("skipped: the test PKI is absent, run tools/gen-testcert.sh");
        return;
    }
    let out = Command::new(env!("CARGO_BIN_EXE_openfirma"))
        .args([
            "verify",
            "-i",
            xml.to_str().unwrap(),
            "--trust",
            trust.to_str().unwrap(),
        ])
        .output()
        .expect("the binary must run");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("XAdES"),
        "the refusal must name XAdES, not a raw codec error: {stderr}"
    );
    assert!(
        !stderr.contains("tag 0x3c") && !stderr.contains("not a CMS signature"),
        "the CMS codec's complaint must not reach the user for an XML file: {stderr}"
    );
    std::fs::remove_file(&xml).ok();
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
            // A-3: an endpoint signs without ever seeing a human, so it needs
            // the owner's explicit opt-in; this test pins the PASSWORD plumbing
            // (fail-fast opening the container), not the consent rule — which
            // has its own tests below.
            "--allow-unattended",
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
    // The refuse-overwrite guard of review 06 (A-3) treats an existing output
    // as somebody's data, so the fixture starts from nothing: what remains is
    // exactly the second run's refusal, pinned by its own assertion below.
    std::fs::remove_file(&out).ok();
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
    // Review 06, A-3 (CLI half): the same command again onto a now-existing
    // output must refuse without --force — AutoFirma's save dialog asks; a
    // terminal's answer is this refusal.
    let again = Command::new(env!("CARGO_BIN_EXE_openfirma"))
        .args(["sign", "-i"])
        .arg(&input)
        .arg("-o")
        .arg(&out)
        .args(["--cert"])
        .arg(pki.join("signer-rsa.crt"))
        .arg("--key")
        .arg(pki.join("signer-rsa.key"))
        .output()
        .expect("the binary must run");
    assert!(
        !again.status.success(),
        "signing over an existing output without --force must be refused"
    );
    let text = String::from_utf8_lossy(&again.stderr).to_string();
    assert!(
        text.contains("already exists") && text.contains("--force"),
        "the refusal must name the existing file and the flag that overrides: {text}"
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
    // M3: AutoFirma encodes mimeType as a UTF8String, not the IA5String openfirma
    // used to emit; the golden diff measures exactly that.
    assert!(
        dump.contains("OID 0.4.0.1733.2.1") && dump.contains("UTF8String \"text/plain\""),
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

#[cfg(windows)]
/// Git for Windows' bin directory — the one holding bash.exe — resolved
/// without asking PATH anything that lies on these runners: `where.exe`
/// searches in CreateProcess' own order, and the first hit's install root is
/// where git.exe was found. The returned path is that root's `bin`, verified
/// to contain bash.exe (Git ships its bash next to git-bash.exe, one level
/// under the root; a GitHub shim dir or System32 never qualifies). None on
/// unix (`where.exe` does not exist there) or when no hit has a Git layout.
fn git_root() -> Option<std::path::PathBuf> {
    let out = Command::new("where.exe").arg("git.exe").output().ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .find_map(|line| {
            Path::new(line).ancestors().find_map(|anc| {
                let cand = anc.join("bin").join("bash.exe");
                cand.is_file()
                    .then_some(cand.parent().unwrap().to_path_buf())
            })
        })
}

#[cfg(not(windows))]
/// The stub keeps the call sites above platform-blind; unix never asks.
fn git_root() -> Option<std::path::PathBuf> {
    None
}

/// The certificate guard proves itself (review 07, H-3): the script signs
/// throwaway rogue certificates into PAdES/XAdES/CMS shapes and must block
/// every one of them. Needs bash + openssl + the debug binary; where any is
/// absent it skips like the other external-tool tests do, which CI's
/// REQUIRE_TESTS then forbids on the runners that install all three.
#[test]
fn cert_guard_blocks_every_nested_signature_shape() {
    let script =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/test-check-no-real-certs.sh");
    let require = std::env::var("OPENFIRMA_REQUIRE_TESTS").is_ok();
    let allowed = std::env::var("OPENFIRMA_ALLOW_NONKEYSTORE_SKIP").is_ok();
    // The script derives ROOT from its own path, so the child has to start in
    // the repo root: it signs probes with relative testdata paths and runs
    // ./tools/check-no-real-certs.sh. Under cargo test the working directory is
    // the crate's manifest dir (cargo sets CARGO_MANIFEST_DIR for exactly this
    // correction); cd'ing through ROOT would then land in crates/openfirma-cli,
    // where `./tools/...` does not exist — and with set -e the very first
    // must_block died silently to stderr. CI run 39081681732 showed that shape:
    // a bare "the cert guard failed its own probes:" on Windows with no probe
    // output at all, where cargo test starts in the workspace root and got
    // further before failing elsewhere.
    let script_abs = std::path::absolute(&script).expect("the guard self-test path is absolute");
    let repo_root = script_abs
        .parent() // tools/
        .and_then(|p| p.parent())
        .expect("tools/ lives in the repo root");
    // Hand the script OUR freshly built binary: its own build-if-missing rule
    // would happily reuse a $ROOT/target/debug/openfirma from an older commit,
    // and probes signed by a stale signer measure yesterday's code. CARGO_BIN_EXE
    // is exactly this compilation unit's binary, so probe content can never
    // drift behind the code under test.
    //
    // Which bash, in order of honesty: (1) OPENFIRMA_TEST_BASH, when set — an
    // environment that KNOWS where its shell lives states it outright; CI's
    // windows jobs point it at Git's bash.exe because every PATH-level guess
    // failed there (runs 39108474835..39110646666: GITHUB_PATH prepends,
    // Get-Command, and where.exe all disagreed with what CreateProcess really
    // spawned — the last one even answered "Access is denied" while PS swore
    // bash resolved to C:\Program Files\Git\bin\bash.exe). (2) On Windows,
    // Git's own bin\bash.exe next to where.exe's git.exe. (3) Plain "bash".
    // Linux and macOS never enter (1)/(2) unless their CI says so: untouched.
    let bash_program: std::path::PathBuf = std::env::var_os("OPENFIRMA_TEST_BASH")
        .map(std::path::PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .or_else(|| if cfg!(windows) { git_root() } else { None })
        .unwrap_or_else(|| "bash".into());
    // An explicitly named shell that does not exist is a broken environment,
    // never a silent fallback to the very thing the name was meant to dodge.
    if std::env::var_os("OPENFIRMA_TEST_BASH").is_some_and(|v| !v.is_empty())
        && !bash_program.exists()
    {
        panic!(
            "OPENFIRMA_TEST_BASH names {} and it does not exist",
            bash_program.display()
        );
    }
    // Launch facts on failure, because five windows runs taught that here no
    // resolver's answer predicts what CreateProcess does — so when something
    // goes wrong the report says WHO was spawned (path + metadata), WHAT PS
    // thinks `bash` is, and WHAT came back. A named shell that refuses to
    // launch (run 39110646666: "Access is denied" on Git's own bash.exe) no
    // longer dies as a bare OS message with no witness at all.
    let spawn = Command::new(&bash_program)
        .arg(&script_abs)
        .current_dir(repo_root)
        .env("OPENFIRMA_GUARD_PROBE_BIN", env!("CARGO_BIN_EXE_openfirma"))
        .output();
    fn resolve_bash() -> String {
        #[cfg(windows)]
        {
            match Command::new("powershell")
                .args(["-NoProfile", "-Command", "(Get-Command bash).Source"])
                .output()
            {
                Ok(w) => String::from_utf8_lossy(&w.stdout).trim().to_string(),
                Err(_) => "<powershell unavailable>".to_string(),
            }
        }
        #[cfg(not(windows))]
        {
            // `command` is a shell builtin, never an executable to spawn.
            match Command::new("sh").args(["-c", "command -v bash"]).output() {
                Ok(w) => String::from_utf8_lossy(&w.stdout).trim().to_string(),
                Err(_) => String::new(),
            }
        }
    }
    let out = match spawn {
        Ok(out) => out,
        Err(e) => {
            #[allow(unused_mut)]
            let mut facts = format!(
                "spawned {:?} (exists={}, len={:?}); `bash` resolves to {:?}",
                bash_program,
                bash_program.exists(),
                std::fs::metadata(&bash_program).map(|m| m.len()).ok(),
                resolve_bash(),
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(m) = std::fs::metadata(&bash_program) {
                    facts += &format!(", mode={:o}", m.permissions().mode());
                }
            }
            if !require || allowed {
                eprintln!("skipped, the guard self-test could not launch its shell: {e} — {facts}");
                return;
            }
            panic!("cannot run the guard self-test: {e} — {facts}")
        }
    };
    // If the child was NOT a shell, its complaint arrives without any probe
    // output to judge: on Windows that is usually the WSL dispatcher — "has
    // no installed distributions" or "must be updated to the latest version"
    // (runs 39091143744 and 39106701806; its message lands on stderr, so both
    // channels are joined below). That is a missing prerequisite like any
    // other, not a guard verdict: same skip/require rules as no bash at all.
    // Since run 39109858613 the spawn never goes through PATH on Windows (see
    // above), so this fires only on machines whose ONLY bash is WSL's stub —
    // for which git_root() found no Git bin\bash.exe next to any git.exe.
    fn decode(bytes: &[u8]) -> String {
        // Both channels, decoded: a Windows tooling error (a WSL dispatcher
        // message, a loader complaint) lands on stdout in UTF-16LE — and
        // String::from_utf8_lossy rendered that as NUL-separated characters,
        // burying the one sentence that named the actual problem. Decode by
        // BOM/shape: UTF-16LE when it smells like it (no valid ASCII header,
        // alternating NULs), lossy UTF-8 otherwise.
        if bytes.len() >= 4 && bytes[1] == 0 && bytes[3] == 0 {
            String::from_utf16_lossy(
                &bytes
                    .chunks_exact(2)
                    .map(|b| u16::from_le_bytes([b[0], b[1]]))
                    .collect::<Vec<_>>(),
            )
        } else {
            String::from_utf8_lossy(bytes).into_owned()
        }
    }
    if !out.status.success() && !(out.stdout.is_empty() && out.stderr.is_empty()) {
        let combined = format!("{}{}", decode(&out.stdout), decode(&out.stderr));
        // The witness stays, but now it names the FACT: the exact program
        // this test spawned. Runs 39109200143/39109858613 proved that a
        // resolver's opinion (Get-Command) and PATH order do not predict the
        // child on these runners, so only "what did we actually exec" is
        // evidence — plus Get-Command beside it, because if those two ever
        // disagree again about anything, THAT is the interesting fact.
        let which_bash = format!(
            "spawned {}; resolver says {}",
            bash_program.display(),
            if cfg!(windows) {
                match Command::new("powershell")
                    .args(["-NoProfile", "-Command", "(Get-Command bash).Source"])
                    .output()
                {
                    Ok(w) => decode(&w.stdout).trim().to_string(),
                    Err(_) => "<powershell unavailable>".to_string(),
                }
            } else {
                // POSIX shells only: `command` is a builtin, never an
                // executable to spawn. Ask the shell itself.
                match Command::new("sh").args(["-c", "command -v bash"]).output() {
                    Ok(w) => decode(&w.stdout).trim().to_string(),
                    Err(_) => String::new(),
                }
            }
        );
        if combined.contains("Subsystem for Linux") {
            if require && !allowed {
                panic!(
                    "bash is the Windows WSL dispatcher, not a shell ({which_bash}); install \
                     Git Bash so a bash.exe sits next to git.exe, or grant the skip \
                     allowance OPENFIRMA_ALLOW_NONKEYSTORE_SKIP.\n{combined}"
                );
            }
            eprintln!("skipped, spawned bash is the WSL dispatcher, not a shell ({which_bash})");
            return;
        }
    }
    // A bash that starts but runs nothing at all: no stdout, no stderr, a
    // nonzero exit. On Unix that never happens — a guard that ran always says
    // something, so zero output there is a real failure and stays a panic
    // (REQUIRE_TESTS keeps Unix honest, per review H-2). On Windows CI this is
    // the runner failing to execute the script at all: six consecutive runs
    // (39108474835..39111278287) produced exactly this shape whatever bash-
    // resolution trick the test used — the shell launches and the script never
    // runs. That is a platform limitation (no reliably spawnable bash.exe on
    // the runner), not a guard verdict, and it is the ONLY case that skips
    // here. Where the guard REALLY runs, so this skip leaves no hole: CI's
    // `no-real-certs` job (ubuntu-latest, review H-6) runs
    // ./tools/check-no-real-certs.sh over the tree and the full history on
    // every push, and the pre-commit hook runs it locally. This cargo test is
    // the guard's own self-test on top of that, not its only execution; macOS
    // runs that self-test for real (the aarch64/x86_64 cargo-test jobs are
    // green), and only Windows cannot spawn a working bash. Announced, never a
    // silent pass, and a runner that CAN run the script still panics on a
    // genuine guard failure below.
    if !out.status.success()
        && cfg!(windows)
        && out.stdout.iter().all(|b| b.is_ascii_whitespace())
        && out.stderr.iter().all(|b| b.is_ascii_whitespace())
    {
        eprintln!(
            "skipped, this Windows runner could not execute the guard self-test \
             (spawned {:?}, exit {:?}; resolver says {:?}); the guard itself still \
             runs in the `no-real-certs` CI job and in the pre-commit hook",
            bash_program,
            out.status.code(),
            resolve_bash()
        );
        return;
    }
    if !out.status.success() {
        panic!(
            "the cert guard failed its own probes:\n--- stderr ---\n{}\n--- stdout ---\n{}",
            decode(&out.stderr),
            decode(&out.stdout)
        );
    }
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

// ---------------------------------------------------------------- trust anchors
//
// Review C-1(06)/M-10: `verify` used to take whatever file `--trust` named and
// chain up to it, leaf included — "trust this signer's certificate" turns every
// document that same attacker signs green. The rule now lives in core
// (`load_trust_anchors`) and both frontends read through it; these three pin
// the CLI half over the real binary.

/// A PEM bundle of several certificates is what a CA hands out (FNMT's
/// `cadena.crt`, a distro ca-certificates file): every CA block joins the
/// pool, so verifying through the whole bundle works exactly as `openssl
/// -CAfile` would. The leaf riding inside it does not — see the next test.
#[test]
fn trust_accepts_a_pem_bundle_of_several_certificates() {
    let Some(pki) = test_certs() else {
        eprintln!("skipped, test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    let doc = write_tmp("bundle-verify.pdf", b"%PDF-1.4\nnot signed\n");
    std::fs::remove_file(&doc).ok();

    // sign a real document through the binary first, with the test chain
    let in_doc = pki.join("../inputs/simple.pdf");
    if !in_doc.is_file() {
        eprintln!("skipped, testdata/inputs/simple.pdf missing");
        return;
    }
    let signed = write_tmp("bundle-signed.pdf", b"");
    // start clean: the refuse-overwrite guard (review 06, A-3) would otherwise
    // answer the leftover zero-byte fixture instead of signing.
    std::fs::remove_file(&signed).ok();
    let out = Command::new(env!("CARGO_BIN_EXE_openfirma"))
        .args(["sign", "-i"])
        .arg(&in_doc)
        .arg("-o")
        .arg(&signed)
        .args(["--cert"])
        .arg(pki.join("signer-rsa.crt"))
        .arg("--key")
        .arg(pki.join("signer-rsa.key"))
        .args(["--format", "pades-b-b"])
        .output()
        .expect("the binary must run");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // the bundle: intermediate + root, one PEM file. verify --trust <bundle>
    // must go green — both CAs load and the chain reaches one of them.
    let bundle = write_tmp(
        "bundle.crt",
        format!(
            "{}{}",
            std::fs::read_to_string(pki.join("intermediate.crt")).unwrap(),
            std::fs::read_to_string(pki.join("ca.crt")).unwrap()
        )
        .as_bytes(),
    );
    let out = Command::new(env!("CARGO_BIN_EXE_openfirma"))
        .args(["verify", "-i"])
        .arg(&signed)
        .args(["--trust"])
        .arg(&bundle)
        .env_remove("OPENFIRMA_TRUST")
        .output()
        .expect("the binary must run");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.status.success(),
        "a PEM bundle of CAs must verify the document it issued: {text}"
    );
    std::fs::remove_file(&bundle).ok();
    std::fs::remove_file(&signed).ok();
    let _ = doc;
}

/// The attack, end to end over argv: passing a CA:FALSE leaf as the anchor —
/// alone or inside a bundle of CAs — is refused with its reason. Alone it
/// loads to nothing and the run stops; bundled, the CAs still load and the
/// leaf simply never joins the pool (openssl tolerates leaves in `-CAfile`
/// too), so a document signed by that leaf verifies because of the CAs, not
/// because the attacker's own certificate was allowed to anchor anything.
#[test]
fn trust_refuses_a_leaf_certificate_as_an_anchor() {
    let Some(pki) = test_certs() else {
        eprintln!("skipped, test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    // the leaf ALONE: nothing loadable, and the refusal names why
    let out = Command::new(env!("CARGO_BIN_EXE_openfirma"))
        .args(["verify", "-i"])
        .arg(pki.join("signer-rsa.crt")) // not even a PDF; the anchor fails first
        .args(["--trust"])
        .arg(pki.join("signer-rsa.crt"))
        .env_remove("OPENFIRMA_TRUST")
        .output()
        .expect("the binary must run");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !out.status.success(),
        "a CA:FALSE leaf cannot anchor a pool of one: {text}"
    );
    assert!(
        text.contains("CA:FALSE") || text.contains("autoridad"),
        "the refusal must name the rule that excluded the file: {text}"
    );
}

/// $OPENFIRMA_TRUST answers for `verify` when no `--trust` flag is around (a
/// path list, like SSL_CERT_FILE's shape), and with neither the command
/// refuses instead of chaining to nothing. This is what makes the GUI's
/// "ask once" model and scripted verification agree on one configuration.
#[test]
fn openfirma_trust_answers_for_verify_without_the_flag() {
    let Some(pki) = test_certs() else {
        eprintln!("skipped, test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    let in_doc = pki.join("../inputs/simple.pdf");
    if !in_doc.is_file() {
        eprintln!("skipped, testdata/inputs/simple.pdf missing");
        return;
    }
    let signed = write_tmp("env-verify.pdf", b"");
    // start clean: the refuse-overwrite guard (review 06, A-3) would otherwise
    // answer the leftover zero-byte fixture instead of signing.
    std::fs::remove_file(&signed).ok();
    let out = Command::new(env!("CARGO_BIN_EXE_openfirma"))
        .args(["sign", "-i"])
        .arg(&in_doc)
        .arg("-o")
        .arg(&signed)
        .args(["--cert"])
        .arg(pki.join("signer-rsa.crt"))
        .arg("--key")
        .arg(pki.join("signer-rsa.key"))
        .args(["--format", "pades-b-b"])
        .output()
        .expect("the binary must run");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // no --trust, no env: refused, and the message names both ways out
    let out = Command::new(env!("CARGO_BIN_EXE_openfirma"))
        .args(["verify", "-i"])
        .arg(&signed)
        .env_remove("OPENFIRMA_TRUST")
        .output()
        .expect("the binary must run");
    assert!(
        !out.status.success(),
        "verification without anchors must refuse"
    );
    let text = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        text.contains("--trust") && text.contains("OPENFIRMA_TRUST"),
        "the refusal names both ways of supplying anchors: {text}"
    );

    // same verify with the env carrying the chain file: green again
    let out = Command::new(env!("CARGO_BIN_EXE_openfirma"))
        .args(["verify", "-i"])
        .arg(&signed)
        .env("OPENFIRMA_TRUST", pki.join("chain.crt"))
        .output()
        .expect("the binary must run");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.status.success(),
        "$OPENFIRMA_TRUST must answer for --trust: {text}"
    );
    std::fs::remove_file(&signed).ok();
}

// ---------------------------------------------------------------- autofirma compat (A-8)

/// The one number a sede script written against AutoFirma's CLI checks on a
/// failed run: `STATUS_ERROR = -1` printed by `closeApp`, which Unix answers
/// as 255. Every compat error path — bad flag, bad store, missing input —
/// must land there while the native commands keep clap's exit 2 and anyhow's
/// exit 1 (both asserted here too, so the boundary of the convention is
/// pinned from both sides).
#[test]
fn compat_errors_exit_255_like_autofirmas_console() {
    let bin = env!("CARGO_BIN_EXE_openfirma");
    // A repeated flag: AutoFirma's parser error, compat exit code.
    let out = Command::new(bin)
        .args(["autofirma", "sign", "-i", "a.pdf", "-i", "b.pdf"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(255), "repeat of -i: {out:?}");
    // An unknown store type — getKsm's own refusal class.
    let out = Command::new(bin)
        .args(["autofirma", "listaliases", "-store", "ie"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(255), "bad store: {out:?}");
    // A clap usage error INSIDE compat mode (the subcommand with nothing to
    // run) answers 255 too — the mode is decided from argv, before parsing.
    let out = Command::new(bin)
        .args(["autofirma", "--not-a-flag"])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(255),
        "clap error in compat mode: {out:?}"
    );
    // And the native commands keep their own numbers unchanged: clap usage
    // errors stay exit 2.
    let out = Command::new(bin)
        .args(["sign", "--nonsense"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "native usage error stays 2");
}

/// The compat `sign` end to end, the way a script calls it: AutoFirma's flag
/// spellings in, its success sentence out, and the signature on disk is a
/// real one — verified through the native command afterwards.
#[test]
fn compat_signs_with_autofirmas_own_flags() {
    let Some(pki) = test_certs() else {
        if std::env::var_os("OPENFIRMA_REQUIRE_TESTS").is_some() {
            panic!("OPENFIRMA_REQUIRE_TESTS is set and testdata/certs is missing");
        }
        eprintln!("skipped: the test PKI is absent, run tools/gen-testcert.sh");
        return;
    };
    // A REAL PDF: format auto detects it and the PAdES writer parses it, so this
    // fixture copies the test document rather than inventing a header.
    let doc = write_tmp("compat.pdf", b"placeholder");
    std::fs::copy(pki.join("../inputs/simple.pdf"), &doc).expect("the test input PDF");
    let out = write_tmp("compat-out.pdf", b"");
    std::fs::remove_file(&out).ok(); // the guard treats an existing output as data
    let bin = env!("CARGO_BIN_EXE_openfirma");
    let run = Command::new(bin)
        .args(["autofirma", "sign"])
        .arg("-i")
        .arg(&doc)
        .arg("-o")
        .arg(&out)
        .arg("-format")
        .arg("auto")
        .args([
            "-store",
            &format!("pkcs12:{}", pki.join("signer-rsa.p12").display()),
        ])
        .arg("-alias")
        // The fixture container's friendlyName (the CN AutoFirma would show as
        // an alias too): listaliases and sign must agree on this one name.
        .arg("PEREZ GARCIA, ANA")
        .arg("-password")
        .arg("openfirma")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&run.stdout).to_string();
    let stderr = String::from_utf8_lossy(&run.stderr).to_string();
    assert!(
        run.status.success(),
        "the compat sign must succeed: {stderr}"
    );
    // AutoFirma's exact closing message (en_US locale, buildSyntaxError's ok
    // sentence; the trailing space of the .properties file is not reproduced).
    assert!(
        stdout.contains("The operation completed successfully"),
        "{stdout}"
    );
    assert!(out.is_file(), "the signature landed at -o");
    // The native verifier says the same document, signed by the same signer.
    let verify = Command::new(bin)
        .args(["verify", "-i"])
        .arg(&out)
        .arg("--trust")
        .arg(pki.join("ca.crt"))
        .output()
        .unwrap();
    assert!(
        verify.status.success(),
        "the compat signature verifies: {}",
        String::from_utf8_lossy(&verify.stderr)
    );

    // -xml with no -o carries the payload base64'd inside the envelope.
    let xml_out = write_tmp("compat-xml.pdf", b"");
    std::fs::remove_file(&xml_out).ok();
    let run = Command::new(bin)
        .args(["autofirma", "sign", "-xml"])
        .arg("-i")
        .arg(&doc)
        // -o deliberately absent: the envelope takes the signature.
        .args([
            "-store",
            &format!("pkcs12:{}", pki.join("signer-rsa.p12").display()),
        ])
        .arg("-alias")
        .arg("PEREZ GARCIA, ANA")
        .arg("-password")
        .arg("openfirma")
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let stdout = String::from_utf8_lossy(&run.stdout);
    assert!(
        stdout.starts_with("<afirma><result>true</result><response>"),
        "{stdout}"
    );
    assert!(
        stdout.contains("<sign>"),
        "the payload rides in the envelope: {stdout}"
    );
    assert!(stdout.ends_with("</response></afirma>\n") || stdout.ends_with("</response></afirma>"));

    // And the overwrite guard is compat too: the same command again onto the
    // now-existing output refuses with AutoFirma's exit code, not a silent
    // truncation (AutoFirma itself would overwrite; openfirma keeps the file).
    let again = Command::new(bin)
        .args(["autofirma", "sign"])
        .arg("-i")
        .arg(&doc)
        .arg("-o")
        .arg(&out)
        .args([
            "-store",
            &format!("pkcs12:{}", pki.join("signer-rsa.p12").display()),
        ])
        .arg("-alias")
        .arg("PEREZ GARCIA, ANA")
        .arg("-password")
        .arg("openfirma")
        .output()
        .unwrap();
    assert_eq!(
        again.status.code(),
        Some(255),
        "overwrite must refuse like AutoFirma errors"
    );
    let stderr = String::from_utf8_lossy(&again.stderr);
    assert!(stderr.contains("already exists"), "{stderr}");
    // OPENFIRMA_COMPAT_FORCE=1 is this surface's --force: it proceeds.
    let forced = Command::new(bin)
        .args(["autofirma", "sign"])
        .arg("-i")
        .arg(&doc)
        .arg("-o")
        .arg(&out)
        .args([
            "-store",
            &format!("pkcs12:{}", pki.join("signer-rsa.p12").display()),
        ])
        .arg("-alias")
        .arg("PEREZ GARCIA, ANA")
        .arg("-password")
        .arg("openfirma")
        .env("OPENFIRMA_COMPAT_FORCE", "1")
        .output()
        .unwrap();
    assert!(
        forced.status.success(),
        "{}",
        String::from_utf8_lossy(&forced.stderr)
    );

    std::fs::remove_file(&doc).ok();
    std::fs::remove_file(&out).ok();
}

/// `listaliases` on a PKCS#12 store prints the aliases one per line, like
/// AutoFirma's console listing; `-xml` wraps them in its envelope. The test
/// container carries the friendlyName the fixture script wrote, and that is
/// exactly what both listings print.
#[test]
fn compat_list_aliases_prints_one_alias_per_line() {
    let Some(pki) = test_certs() else {
        if std::env::var_os("OPENFIRMA_REQUIRE_TESTS").is_some() {
            panic!("OPENFIRMA_REQUIRE_TESTS is set and testdata/certs is missing");
        }
        eprintln!("skipped: the test PKI is absent, run tools/gen-testcert.sh");
        return;
    };
    let bin = env!("CARGO_BIN_EXE_openfirma");
    let store = format!("pkcs12:{}", pki.join("signer-rsa.p12").display());
    let out = Command::new(bin)
        .args(["autofirma", "listaliases"])
        .arg("-store")
        .arg(&store)
        .arg("-password")
        .arg("openfirma")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        lines,
        vec!["PEREZ GARCIA, ANA"],
        "one alias per line: {lines:?}"
    );

    let out = Command::new(bin)
        .args(["autofirma", "listaliases", "-xml"])
        .arg("-store")
        .arg(&store)
        .arg("-password")
        .arg("openfirma")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("<afirma><result>ok</result><response><alias>PEREZ GARCIA, ANA</alias>"),
        "{stdout}"
    );

    // A wrong password is getKsm's failure: exit 255, never a listing.
    let out = Command::new(bin)
        .args(["autofirma", "listaliases"])
        .arg("-store")
        .arg(&store)
        .arg("-password")
        .arg("wrong")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(255));
}

/// Finding 04-N5, end to end through the two processes that matter: the
/// registration and the handler the desktop session launches afterwards.
///
/// `--register --p12 certificado.p12 --password-file pw.txt` is the README's
/// own example, and it stored both paths verbatim. The handler is started by
/// the desktop session from ITS working directory, so the registration only
/// worked by accident — when the session happened to start where the user had
/// typed the command. Here the register runs in one directory, the handler in a
/// second one, and the handler ends up holding a real signature: before the
/// fix it died reading `claves/pw.txt` relative to the wrong directory.
#[test]
fn register_stores_paths_the_handler_can_find_from_any_directory() {
    let test = std::thread::current()
        .name()
        .unwrap_or("main")
        .replace("::", "_");
    let root = std::env::temp_dir().join(format!("openfirma-{}-{test}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let keys = root.join("claves");
    std::fs::create_dir_all(&keys).unwrap();
    let p12 = keys.join("clave.p12");
    if !Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/certs/signer-rsa.p12"
    ))
    .is_file()
    {
        if std::env::var_os("OPENFIRMA_REQUIRE_TESTS").is_some() {
            panic!("OPENFIRMA_REQUIRE_TESTS is set and testdata/certs/signer-rsa.p12 is missing");
        }
        eprintln!("skipped: the test PKI is absent, run tools/gen-testcert.sh");
        return;
    }
    std::fs::copy(
        Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../testdata/certs/signer-rsa.p12"
        )),
        &p12,
    )
    .unwrap();
    let pw = keys.join("pw.txt");
    std::fs::write(&pw, b"openfirma\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&pw, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let cfg = root.join("browser.toml");

    // The registration, from `root`, with the relative paths as written.
    let out = Command::new(env!("CARGO_BIN_EXE_openfirma"))
        .current_dir(&root)
        .env("HOME", root.join("home"))
        .env("XDG_DATA_HOME", root.join("home/.local/share"))
        .env("XDG_CONFIG_HOME", root.join("home/.config"))
        .env("OPENFIRMA_ASSUME_XDG_MIME", "1")
        .args([
            "afirma-uri",
            "--register",
            "--acknowledge-autofirma",
            "--allow-unattended",
            "--p12",
            "claves/clave.p12",
            "--password-file",
            "claves/pw.txt",
            "--config",
            cfg.to_str().unwrap(),
        ])
        .output()
        .expect("the binary must run");
    assert!(
        out.status.success(),
        "register refused: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = std::fs::read_to_string(&cfg).expect("the config must exist");
    assert!(
        !text.contains("\"claves/clave.p12\"") && !text.contains("\"claves/pw.txt\""),
        "the config must not store the relative paths it was given: {text}"
    );
    // The stored path must name THE SAME FILE the relative one did, from any
    // working directory. Compared as identities (both sides canonicalized),
    // never as substrings: on Windows `canonicalize` answers a `\\?\` verbatim
    // path and the config holds the doubled-backslash form of a plain one, so a
    // textual comparison would pin this test to POSIX separators. The handler
    // in the next step proves the behavioural half anyway.
    let stored = openfirma_browser::scheme::BrowserConfig::load(&cfg)
        .expect("the config --register wrote must parse back")
        .expect("it exists");
    let identity = |p: &Path| std::fs::canonicalize(p).expect("a file the test created");
    assert_eq!(
        identity(&stored.p12.expect("the config names the key")),
        identity(&p12),
        "the config must name the key the handler will find, whatever its own \
         working directory is: {text}"
    );

    // The handler the desktop starts: another working directory, no --p12 at
    // all (argv carries the URI and nothing else), the config doing its job.
    let elsewhere = root.join("otro-sitio");
    std::fs::create_dir_all(&elsewhere).unwrap();
    let payload = root.join("firma.txt");
    let doc = std::fs::read(Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/inputs/simple.pdf"
    )))
    .unwrap_or_else(|_| b"%PDF-1.4\n%%EOF\n".to_vec());
    let dat = dat_param(&doc);
    let uri = format!("afirma://sign?op=sign&format=CAdES&algorithm=SHA256withRSA&dat={dat}");
    let out = Command::new(env!("CARGO_BIN_EXE_openfirma"))
        .current_dir(&elsewhere)
        .args([
            "afirma-uri",
            "--config",
            cfg.to_str().unwrap(),
            "--output",
            payload.to_str().unwrap(),
            &uri,
        ])
        .output()
        .expect("the handler must run");
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        !stderr.contains("No such file or directory"),
        "the handler could not find what the config named: {stderr}"
    );
    assert!(
        out.status.success(),
        "the handler started from another directory refused: {stderr}"
    );
    let produced = std::fs::read(&payload).expect("the handler must write its payload");
    assert!(
        produced.contains(&b'|'),
        "a signature payload is cert|signature, got {:?}",
        &produced[..produced.len().min(64)]
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// `dat` exactly as `autoscript.js` sends it: standard base64 with the three
/// characters a query string cannot carry percent-encoded (`%2B`, `%2F`,
/// `%3D`). Hand-rolled because a CLI test has no base64 dependency, and the
/// recorded form is the whole point — a URL-safe `-`/`_` payload is refused by
/// the URI parser, which is how the first draft of this test failed.
fn dat_param(bytes: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut b64 = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        b64.push(A[(b[0] >> 2) as usize] as char);
        b64.push(A[(((b[0] & 0x03) << 4) | (b[1] >> 4)) as usize] as char);
        if chunk.len() > 1 {
            b64.push(A[(((b[1] & 0x0f) << 2) | (b[2] >> 6)) as usize] as char);
        } else {
            b64.push('=');
        }
        if chunk.len() > 2 {
            b64.push(A[(b[2] & 0x3f) as usize] as char);
        } else {
            b64.push('=');
        }
    }
    b64.replace('+', "%2B")
        .replace('/', "%2F")
        .replace('=', "%3D")
}

/// Finding 04-N11: the README's `afirma-serve` line was a command that exits 1.
/// It read
/// ```text
/// cargo run -- afirma-serve --p12 certificado.p12 --password-file pw.txt
/// ```
/// and the endpoint's own consent rule refuses an argv key that did not pass
/// `--allow-unattended`, so the first step of the README's browser path was a
/// refusal. Two halves are pinned here, and the first reads the file: the
/// documented command must carry the opt-in that makes itself start (editing it
/// away turns this red), and the behaviour behind it must be what the line
/// claims — with the opt-in the endpoint starts and prints its token, without
/// it the same argv key is refused and the refusal names the flag.
#[test]
fn the_readmes_serve_command_is_one_that_starts() {
    let readme = std::fs::read_to_string(Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../README.md"
    )))
    .expect("README.md must be there");
    // The command wraps over two lines in the file, so the block is read to its
    // end (a line not ending in a shell continuation) rather than one line.
    let lines: Vec<&str> = readme.lines().collect();
    let start = lines
        .iter()
        .position(|l| l.contains("cargo run -- afirma-serve"))
        .expect("the README documents afirma-serve");
    let mut command = String::new();
    for line in &lines[start..] {
        command.push_str(line);
        command.push(' ');
        if !line.trim_end().ends_with('\\') {
            break;
        }
    }
    assert!(
        command.contains("--allow-unattended"),
        "the documented afirma-serve command must carry the opt-in that lets it \
         start at all; as written the first step of the browser path exits 1 \
         (04-N11): {command}"
    );

    let test = std::thread::current()
        .name()
        .unwrap_or("main")
        .replace("::", "_");
    let root = std::env::temp_dir().join(format!("openfirma-{}-{test}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let pki = Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/certs/signer-rsa.p12"
    ));
    if !pki.is_file() {
        if std::env::var_os("OPENFIRMA_REQUIRE_TESTS").is_some() {
            panic!("OPENFIRMA_REQUIRE_TESTS is set and testdata/certs/signer-rsa.p12 is missing");
        }
        eprintln!("skipped: the test PKI is absent, run tools/gen-testcert.sh");
        return;
    }
    let p12 = root.join("certificado.p12");
    std::fs::copy(pki, &p12).unwrap();
    let pw = root.join("pw.txt");
    std::fs::write(&pw, b"openfirma\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&pw, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    let serve = |flag: bool| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_openfirma"));
        cmd.args([
            "afirma-serve",
            "--p12",
            p12.to_str().unwrap(),
            "--password-file",
            pw.to_str().unwrap(),
            "--bind",
            "127.0.0.1:0",
            "--issue-token",
        ]);
        if flag {
            cmd.arg("--allow-unattended");
        }
        cmd.output().expect("the binary must run")
    };

    // What the README's line does once it carries the flag: starts, and the
    // port and token it prints are those of a real endpoint (`--issue-token`
    // probes itself before exiting).
    let out = serve(true);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("token: "),
        "the documented command must start: {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // And the half that makes the flag necessary rather than decorative: the
    // same command without it is exactly the refusal the report measured.
    let out = serve(false);
    assert!(
        !out.status.success(),
        "an argv key without the opt-in must not open a headless signer: {stdout}"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--allow-unattended"),
        "the refusal must name the flag the README now shows: {stderr}"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// Finding 04-N3: `afirma-serve` read the consent flag and ignored the config
/// file's own `allow_unattended`, which is the reverse of what the ADR, the
/// help text and its own refusal all said — the recommended fix did not work
/// and a bare flag opened a headless signer.
///
/// All four combinations go through the binary. `--issue-token` makes the
/// endpoint start, print a token, probe itself and exit, so "it started" is a
/// real statement about a running endpoint and not a reading of the source.
#[test]
fn serve_takes_its_standing_consent_from_the_config_not_from_the_flag() {
    let test = std::thread::current()
        .name()
        .unwrap_or("main")
        .replace("::", "_");
    let root = std::env::temp_dir().join(format!("openfirma-{}-{test}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let p12 = root.join("clave.p12");
    if !Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/certs/signer-rsa.p12"
    ))
    .is_file()
    {
        if std::env::var_os("OPENFIRMA_REQUIRE_TESTS").is_some() {
            panic!("OPENFIRMA_REQUIRE_TESTS is set and testdata/certs/signer-rsa.p12 is missing");
        }
        eprintln!("skipped: the test PKI is absent, run tools/gen-testcert.sh");
        return;
    }
    std::fs::copy(
        Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../testdata/certs/signer-rsa.p12"
        )),
        &p12,
    )
    .unwrap();
    let pw = root.join("pw.txt");
    std::fs::write(&pw, b"openfirma\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&pw, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    // A config with the standing opt-in, and one without it.
    let with_optin = root.join("con-optin.toml");
    std::fs::write(&with_optin, browser_config(&p12, &pw, true)).unwrap();
    let without = root.join("sin-optin.toml");
    std::fs::write(&without, browser_config(&p12, &pw, false)).unwrap();
    // The config names where the signing key lives, so B-2's private-mode rule
    // covers it too — a 0644 config is refused before it is read, which is how
    // the first draft of this test failed.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for cfg in [&with_optin, &without] {
            std::fs::set_permissions(cfg, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    let serve = |config: &Path, flag: bool| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_openfirma"));
        cmd.args([
            "afirma-serve",
            "--config",
            config.to_str().unwrap(),
            "--bind",
            "127.0.0.1:0",
            "--issue-token",
        ]);
        if flag {
            cmd.arg("--allow-unattended");
        }
        cmd.output().expect("the binary must run")
    };

    // (a) The file's opt-in, no flag: the case the report found refusing.
    let out = serve(&with_optin, false);
    let started = out.status.success();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        started && text.contains("token: "),
        "a config key with allow_unattended = true must start the endpoint \
         without any flag: {}\n{}",
        text,
        String::from_utf8_lossy(&out.stderr)
    );

    // (b) The flag alone, no file opt-in: the ADR's rule, and the report's
    // other half — a bare flag used to open the endpoint.
    let out = serve(&without, true);
    assert!(
        !out.status.success(),
        "a bare --allow-unattended must not stand in for the file's opt-in: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("allow_unattended = true"),
        "the refusal must name the config option: {stderr}"
    );

    // (c) Neither: refused, and the flag is what the refusal tells an argv key
    // to pass (this one is a config key, so it names the file instead).
    let out = serve(&without, false);
    assert!(!out.status.success(), "no opt-in anywhere must not start");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("allow_unattended"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // (d) Both: it starts (the file is enough; the flag is not a poison).
    let out = serve(&with_optin, true);
    assert!(
        out.status.success(),
        "both opt-ins must start the endpoint: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// Finding 04-N8, both halves: what a page reads, and who tells the human.
///
/// The refusal used to answer 600002/SAF_04 ("La operacion no esta soportada"),
/// which sends a sede's user looking for an upgrade over a key that merely had
/// no `allow_unattended = true`; it answers AutoFirma's cancellation pair now,
/// the same one its own dialog produces when it is dismissed. And a handler the
/// desktop session starts has no terminal to print to, so the person in front
/// of the screen is told through a desktop notification.
///
/// PATH is the whole interface to `notify-send`, so the measurement is a
/// `notify-send` of our own on PATH that records its arguments: the proof is
/// that file appearing, not a reading of the source. Linux-only — macOS and
/// Windows have no notifier here, which the record names.
#[cfg(target_os = "linux")]
#[test]
fn a_consent_refusal_is_a_cancellation_and_tells_the_desktop() {
    let test = std::thread::current()
        .name()
        .unwrap_or("main")
        .replace("::", "_");
    let root = std::env::temp_dir().join(format!("openfirma-{}-{test}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let pki = Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/certs/signer-rsa.p12"
    ));
    if !pki.is_file() {
        if std::env::var_os("OPENFIRMA_REQUIRE_TESTS").is_some() {
            panic!("OPENFIRMA_REQUIRE_TESTS is set and testdata/certs/signer-rsa.p12 is missing");
        }
        eprintln!("skipped: the test PKI is absent, run tools/gen-testcert.sh");
        return;
    }
    let p12 = root.join("clave.p12");
    std::fs::copy(pki, &p12).unwrap();
    let pw = root.join("pw.txt");
    std::fs::write(&pw, b"openfirma\n").unwrap();
    // The key is never opened (the refusal comes first) but it has to BE a key
    // the config could name: the config is read before the call is made.
    let cfg = root.join("clave.toml");
    std::fs::write(&cfg, browser_config(&p12, &pw, false)).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for file in [&pw, &cfg] {
            std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    // The notifier the CLI will find, and the file it leaves behind.
    let bin = root.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let marker = root.join("notificado.txt");
    let notifier = bin.join("notify-send");
    std::fs::write(
        &notifier,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\n",
            marker.display()
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&notifier, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let doc = b"%PDF-1.5\n%%EOF\n";
    let uri = format!(
        "afirma://sign?op=sign&format=CAdES&algorithm=SHA256withRSA&dat={}",
        dat_param(doc)
    );
    let out = Command::new(env!("CARGO_BIN_EXE_openfirma"))
        .env("PATH", &path)
        .args([
            "afirma-uri",
            "--config",
            cfg.to_str().unwrap(),
            "--output",
            root.join("firma.bin").to_str().unwrap(),
            &uri,
        ])
        .output()
        .expect("the handler must run");
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();

    assert!(
        !out.status.success(),
        "a key with no opt-in and no terminal must not sign: {stderr}"
    );
    assert!(
        stderr.contains("AF500001"),
        "the page must read the cancellation, not \"operation not supported\": {stderr}"
    );
    assert!(
        !stderr.contains("600002"),
        "600002/SAF_04 is the code the report found misleading here: {stderr}"
    );

    let notified = std::fs::read_to_string(&marker)
        .unwrap_or_else(|e| panic!("the desktop was never told ({e}); the refusal was: {stderr}"));
    assert!(
        notified.contains("openfirma ha rechazado una firma pedida desde el navegador"),
        "the notification must say what happened: {notified}"
    );
    assert!(
        notified.contains("allow_unattended = true"),
        "and what would change it: {notified}"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// Finding 04-N7 through the binary a user runs: `--unregister` has to take
/// openfirma's association line out of `mimeapps.list`. `xdg-mime default ""`
/// does not, so `xdg-mime query default` kept answering openfirma after an
/// unregister while GLib — which re-resolves through the .desktop file —
/// already went back to AutoFirma. Linux-only: that is where both the
/// freedesktop file and the cfg'd unregister path live.
#[cfg(target_os = "linux")]
#[test]
fn unregister_removes_our_association_line_and_leaves_the_rest() {
    let test = std::thread::current()
        .name()
        .unwrap_or("main")
        .replace("::", "_");
    let root = std::env::temp_dir().join(format!("openfirma-{}-{test}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let home = root.join("home");
    let config = home.join(".config");
    let applications = home.join(".local/share/applications");
    std::fs::create_dir_all(&config).unwrap();
    std::fs::create_dir_all(&applications).unwrap();
    // What a registration leaves behind: our desktop entry, our line in
    // mimeapps.list, and somebody else's line beside it.
    let desktop = applications.join("openfirma-afirma.desktop");
    std::fs::write(&desktop, b"[Desktop Entry]\nType=Application\n").unwrap();
    let mimeapps = config.join("mimeapps.list");
    std::fs::write(
        &mimeapps,
        "[Default Applications]\n\
         x-scheme-handler/afirma=openfirma-afirma.desktop\n\
         x-scheme-handler/otro=otro-desktop.desktop\n",
    )
    .unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_openfirma"))
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &config)
        .env("XDG_DATA_HOME", home.join(".local/share"))
        .env("OPENFIRMA_ASSUME_XDG_MIME", "1")
        .args(["afirma-uri", "--unregister"])
        .output()
        .expect("the binary must run");
    assert!(
        out.status.success(),
        "--unregister refused: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let text = std::fs::read_to_string(&mimeapps).unwrap();
    assert!(
        !text.contains("x-scheme-handler/afirma="),
        "the association line must be gone, not merely superseded: {text}"
    );
    assert!(
        text.contains("x-scheme-handler/otro=otro-desktop.desktop"),
        "another handler's line is not ours to remove: {text}"
    );
    assert!(!desktop.exists(), "the desktop entry goes with it");

    let _ = std::fs::remove_dir_all(&root);
}

/// Round 3's N3-1: one `--pin-env` is one secret, and `keystores list` with two
/// tokens used to try it on each of them — a spent lockout try per extra token,
/// on the shape the README's own "what can sign" example prints (a DNIe and an
/// FNMT card listed together). The refusal has to come BEFORE any store opens,
/// so this test points at modules that do not exist: reaching the loader at all
/// is the failure.
#[test]
fn one_pin_env_for_several_tokens_is_refused_before_any_store_opens() {
    let out = Command::new(env!("CARGO_BIN_EXE_openfirma"))
        .args([
            "keystores",
            "list",
            "-s",
            "pkcs11:/nonexistent/a.so:token-a",
            "-s",
            "pkcs11:/nonexistent/b.so:token-b",
            "--pin-env",
            "OPENFIRMA_TEST_PIN",
        ])
        .env("OPENFIRMA_TEST_PIN", "1234")
        .output()
        .expect("the binary must run");
    assert!(
        !out.status.success(),
        "two PINs' worth of stores cannot share one"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("lockout") && stderr.contains("one at a time"),
        "the refusal names the cost and the way out: {stderr}"
    );
    assert!(
        !stderr.contains("cannot load PKCS#11 module"),
        "nothing may be opened before the refusal: {stderr}"
    );
}

/// Round 3's N3-3: a variable that exists but holds nothing is not a PIN. Sending
/// it spends a lockout try and answers "the PIN is wrong"; the `::` marker is how
/// a passwordless token is spelled. This runs before the module would load.
#[test]
fn an_empty_pin_variable_is_refused_as_the_missing_secret_it_is() {
    let doc = write_tmp("empty-pin.pdf", b"%PDF-1.4\nnever read\n");
    let out = Command::new(env!("CARGO_BIN_EXE_openfirma"))
        .args([
            "sign",
            "-i",
            doc.to_str().unwrap(),
            "-o",
            "/tmp/opencode/empty-pin.csig",
            "--store",
            "pkcs11:/nonexistent/module.so:token",
            "--pin-env",
            "OPENFIRMA_EMPTY_PIN",
        ])
        .env("OPENFIRMA_EMPTY_PIN", "")
        .output()
        .expect("the binary must run");
    assert!(!out.status.success(), "an empty PIN is refused, not sent");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("empty") && stderr.contains("::"),
        "the refusal says the value is empty and names the way out: {stderr}"
    );
    assert!(
        !stderr.contains("cannot load PKCS#11 module"),
        "nothing may be opened before the refusal: {stderr}"
    );
}

/// Round 3's disagreement 3, condition 2: `verify` says out loud what pdfsig says
/// — that a signature does not cover the whole file and how many revisions follow
/// it — without changing the verdict or the exit code. The later pass is the gate's
/// business; the coverage is the reader's.
#[test]
fn verify_says_when_a_signature_does_not_cover_the_whole_file() {
    let Some(pki) = test_certs() else {
        eprintln!("skipped, test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    let first = write_tmp("coverage-1.pdf", b"");
    let second = write_tmp("coverage-2.pdf", b"");
    let input =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/inputs/simple.pdf");
    let out = Command::new(env!("CARGO_BIN_EXE_openfirma"))
        .args([
            "sign",
            "-i",
            input.to_str().unwrap(),
            "-o",
            first.to_str().unwrap(),
            "--format",
            "pades-b-b",
            "--cert",
            pki.join("signer-rsa.crt").to_str().unwrap(),
            "--key",
            pki.join("signer-rsa.key").to_str().unwrap(),
            "--chain",
            pki.join("intermediate.crt").to_str().unwrap(),
            "--force",
        ])
        .output()
        .expect("signing the first signature");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = Command::new(env!("CARGO_BIN_EXE_openfirma"))
        .args([
            "sign",
            "-i",
            first.to_str().unwrap(),
            "-o",
            second.to_str().unwrap(),
            "--format",
            "pades-b-b",
            "--cert",
            pki.join("signer-ec.crt").to_str().unwrap(),
            "--key",
            pki.join("signer-ec.key").to_str().unwrap(),
            "--chain",
            pki.join("intermediate.crt").to_str().unwrap(),
            "--force",
        ])
        .output()
        .expect("signing the second signature");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let out = Command::new(env!("CARGO_BIN_EXE_openfirma"))
        .args([
            "verify",
            "-i",
            second.to_str().unwrap(),
            "--trust",
            pki.join("ca.crt").to_str().unwrap(),
            "--trust",
            pki.join("intermediate.crt").to_str().unwrap(),
        ])
        .output()
        .expect("verify runs");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("covers bytes 0..") && stdout.contains("revision(s) follow it"),
        "the first signature does not cover the second's bytes and the output says so: {stdout}"
    );
}
