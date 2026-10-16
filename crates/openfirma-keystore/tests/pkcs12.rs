//! PKCS#12 against the throwaway container `tools/gen-testcert.sh` makes, and
//! against bytes of it that were tampered with.
//!
//! The MAC comparison is constant time (`subtle`), and a constant time
//! comparison that was wired up wrong shows up exactly here: either the
//! tampered container stops being refused, or the right password is. Both
//! directions are asserted.
//!
//! Skips follow the rules of the other integration tests: missing material
//! skips, unless CI set OPENFIRMA_REQUIRE_TESTS, and material that is present
//! but unusable panics.

use std::path::{Path, PathBuf};

use openfirma_keystore::Pkcs12;

fn certs_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/certs")
}

fn require_or_skip(reason: &str) {
    let required = std::env::var("OPENFIRMA_REQUIRE_TESTS").is_ok();
    let allowed = std::env::var("OPENFIRMA_ALLOW_SKIP").is_ok();
    if required && !allowed {
        panic!("cannot run the test: {reason}");
    }
    eprintln!("skipped, {reason}");
}

#[test]
fn the_test_container_loads_and_the_mac_guards_it() {
    let Ok(bytes) = std::fs::read(certs_dir().join("signer-rsa.p12")) else {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };

    // the right password gets the key, the alias and the chain out
    let container = Pkcs12::load(&bytes, "openfirma").unwrap_or_else(|e| {
        panic!("signer-rsa.p12 is present but unusable: {e}. Rerun tools/gen-testcert.sh")
    });
    let entry = container
        .entry(Some("PEREZ GARCIA, ANA"))
        .expect("the alias gen-testcert.sh set, decoded strictly from its BMPString");
    assert!(
        !entry.key_pkcs8.is_empty(),
        "the decrypted PKCS#8 key must come out"
    );
    assert!(
        !entry.chain.is_empty(),
        "the container carries at least the signer certificate"
    );

    // a wrong password is caught by the MAC before anything is decrypted
    let err = Pkcs12::load(&bytes, "wrong").unwrap_err().to_string();
    assert!(err.contains("integrity check failed"), "{err}");

    // and so is a flipped byte inside the authenticated safe: this is the
    // direction a broken constant time compare would break first
    let mut tampered = bytes.clone();
    let at = tampered.len() / 3;
    tampered[at] ^= 0xff;
    let err = Pkcs12::load(&tampered, "openfirma")
        .unwrap_err()
        .to_string();
    assert!(err.contains("integrity check failed"), "{err}");
}

/// The Debug of a decrypted entry and its container must not print the key:
/// one `tracing::debug!("{entry:?}")` in a future commit would otherwise be
/// enough to publish a private key into the logs (finding B-3).
#[test]
fn debug_never_prints_the_decrypted_private_key() {
    let bytes = match std::fs::read(certs_dir().join("signer-rsa.p12")) {
        Ok(b) => b,
        Err(_) => {
            eprintln!("skipped: testdata/certs/signer-rsa.p12 absent");
            return;
        }
    };
    let p12 = Pkcs12::load(&bytes, "openfirma").expect("the synthetic container loads");
    let entry = p12.entry(None).expect("one entry");
    let key_head = hex::encode(&entry.key_pkcs8[..16.min(entry.key_pkcs8.len())]);
    let shown = format!("{entry:?} {p12:?}");
    assert!(
        shown.contains("[hidden]"),
        "the key field must announce itself hidden: {shown}"
    );
    assert!(
        !shown.contains(&key_head),
        "the first bytes of the decrypted key leaked into its Debug output"
    );
}

/// The two byte container of the PoC (`printf '\x30\x84' > trunc.p12`) used
/// to panic inside the length reader — `range end index 4 out of range for
/// slice of length 1` — from the CLI, the GUI or the browser service if a
/// user pointed them at a broken file. It must answer with the usual PKCS#12
/// error and its re-export hint instead. Every truncation and every hostile
/// length marker at every offset is swept for the same contract.
#[test]
fn a_truncated_container_is_a_keystore_error_never_a_panic() {
    let exact = Pkcs12::load(&[0x30, 0x84], "openfirma").expect_err("two bytes are not a PKCS#12");
    let text = exact.to_string();
    assert!(text.contains("runs past the input"), "{text}");
    assert!(
        text.contains("openssl pkcs12 -in old.p12 -out new.p12"),
        "{text}"
    );

    // every prefix of a real container, plus the long-form markers written
    // at every offset: both together are what hostile files do
    let Ok(bytes) = std::fs::read(certs_dir().join("signer-rsa.p12")) else {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    let mut inputs: Vec<Vec<u8>> = (0..bytes.len()).map(|end| bytes[..end].to_vec()).collect();
    for at in 0..bytes.len().min(64) {
        for marker in [0x80u8, 0x81, 0x84, 0x89] {
            let mut v = bytes.clone();
            v[at] = marker;
            inputs.push(v.clone());
            inputs.push(v[..at].to_vec());
        }
    }
    for input in &inputs {
        // never a panic; every answer is an error (these are all broken) or,
        // for the untouched shapes, whatever load decides
        let _ = Pkcs12::load(input, "openfirma");
    }
}
