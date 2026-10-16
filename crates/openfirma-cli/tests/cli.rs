//! End to end CLI behaviour that the unit tests in main.rs cannot reach:
//! what the binary itself does with the flags, through argv and stderr.

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
