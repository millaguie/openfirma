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
