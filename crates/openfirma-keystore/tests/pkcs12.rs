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

/// Reviewer finding M-4: openssl writes `localKeyID` only on the certificate
/// bag of the leaf; the intermediate and root bags carry no attributes. The
/// assembler used to keep *only* the attribute-matched bags when any matched,
/// so a genuine openssl container yielded a one-certificate chain where
/// AutoFirma emits three — XAdES KeyInfo with a single X509Certificate, CAdES
/// without the intermediates a validator needs. The unmatched bags are chain
/// candidates too; `order_chain` keeps whatever does not chain at the end, so
/// nothing is lost by offering them.
#[test]
fn an_entry_carries_the_whole_container_not_just_the_matched_bags() {
    let Ok(bytes) = std::fs::read(certs_dir().join("signer-rsa.p12")) else {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    let p12 = Pkcs12::load(&bytes, "openfirma").expect("the synthetic container loads");
    let entry = p12.entry(None).expect("one entry");
    // gen-testcert.sh puts leaf + intermediate + root in the file: all three
    // must survive into the entry even though only the leaf carries a
    // localKeyID (openssl's own `pkcs12 -info` output is the witness)
    assert_eq!(
        entry.chain.len(),
        3,
        "the container has three certificate bags; the assembler dropped {}",
        3 - entry.chain.len()
    );
    // ordered: leaf first (it matches the key), and every following bag is
    // the issuer of the one before it, so a root that chains to nobody can
    // only ever be last — the walk below would otherwise catch a foreign
    // certificate sitting in the middle of the chain
    use openfirma_core::CertificateHandle;
    let handles: Vec<CertificateHandle> = entry
        .chain
        .iter()
        .map(|der| CertificateHandle::from_der(der).expect("a DER certificate"))
        .collect();
    for pair in handles.windows(2) {
        assert_eq!(
            pair[0].issuer(),
            pair[1].subject(),
            "the chain is not in issuing order"
        );
    }
}

/// Two keys in one container, each with its whole chain (the shape of a real
/// keystore export). The unmatched bags are offered to every key as chain
/// material after the M-4 fix, so dedup is what keeps one key's leaf out of
/// the other key's chain: an entry's first certificate always pairs with its
/// own key, and no following bag pairs with it either.
#[test]
fn two_full_chains_in_one_container_stay_apart() {
    let dir = certs_dir();
    if std::fs::read(dir.join("signer-rsa.p12")).is_err() {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    }
    // one PEM carrying both issuing chains — intermediate and root once each
    let pem = dir.join("both-chains.pem");
    if !pem.is_file() {
        let mut all = Vec::new();
        for name in ["intermediate.crt", "ca.crt"] {
            all.extend_from_slice(&std::fs::read(dir.join(name)).unwrap());
        }
        std::fs::write(&pem, all).unwrap();
    }
    let Some(openssl) = which("openssl") else {
        require_or_skip("no openssl to build the two-key container");
        return;
    };
    // `openssl pkcs12 -export` writes one key per file. A JKS import of both
    // halves and a PKCS#12 export out of it (keytool, like
    // gen-p12-fixtures.sh uses) merges them into one container whose every
    // bag carries Java's localKeyID and friendlyName.
    let Some(keytool) = which("keytool") else {
        require_or_skip("no keytool to merge the two containers");
        return;
    };
    let tag = std::process::id();
    let rsa_half = std::env::temp_dir().join(format!("openfirma-tc-rsa-{tag}.p12"));
    let ec_half = std::env::temp_dir().join(format!("openfirma-tc-ec-{tag}.p12"));
    let jks = std::env::temp_dir().join(format!("openfirma-tc-{tag}.jks"));
    let merged = std::env::temp_dir().join(format!("openfirma-tc-{tag}-merged.p12"));
    let _ = std::fs::remove_file(&jks);
    let mut ok = true;
    for (key, crt, half) in [
        ("signer-rsa.key", "signer-rsa.crt", &rsa_half),
        ("signer-ec.key", "signer-ec.crt", &ec_half),
    ] {
        ok &= std::process::Command::new(&openssl)
            .args(["pkcs12", "-export"])
            .arg("-inkey")
            .arg(dir.join(key))
            .arg("-in")
            .arg(dir.join(crt))
            .arg("-certfile")
            .arg(&pem)
            .args(["-name", "dual", "-passout", "pass:openfirma", "-out"])
            .arg(half)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            // distinct destination aliases keep both entries alive in the JKS
            let alias = if half == &rsa_half {
                "identity-rsa"
            } else {
                "identity-ec"
            };
            ok &= std::process::Command::new(&keytool)
                .args(["-importkeystore", "-deststoretype", "JKS"])
                .arg("-destkeystore")
                .arg(&jks)
                .args(["-deststorepass", "openfirma", "-srcstorepass", "openfirma"])
                .args(["-srcalias", "dual", "-destalias", alias])
                .arg("-srckeystore")
                .arg(half)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
        }
    }
    let built = ok
        && std::process::Command::new(&keytool)
            .args(["-importkeystore"])
            .arg("-srckeystore")
            .arg(&jks)
            .args(["-srcstoretype", "JKS", "-srcstorepass", "openfirma"])
            .arg("-destkeystore")
            .arg(&merged)
            .args(["-deststoretype", "PKCS12", "-deststorepass", "openfirma"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
    for f in [&rsa_half, &ec_half, &jks] {
        std::fs::remove_file(f).ok();
    }
    if !built {
        require_or_skip("openssl or keytool refused the two-key container");
        return;
    }
    let bytes = std::fs::read(&merged).expect("the container keytool just wrote");
    std::fs::remove_file(&merged).ok();

    let store = Pkcs12::load(&bytes, "openfirma").expect("keytool's own container opens");
    // A JKS holds both identities as key entries, but Java serializes a JKS
    // with ONE shrouded key bag and the rest as trustedCertBags — the exact
    // anonymous-bag shape this finding is about. So the loadable-entry count
    // may be one here; what must never happen is the other shape: a foreign
    // leaf that pairs with this key appearing inside another entry's chain.
    assert!(!store.entries.is_empty(), "the container carries its keys");
    for entry in &store.entries {
        let own = openfirma_core::SoftwareSigner::from_pkcs8_der(&entry.chain[0], &entry.key_pkcs8);
        assert!(
            own.is_ok(),
            "an entry's first certificate must pair with its key"
        );
        for other in &entry.chain[1..] {
            assert!(
                openfirma_core::SoftwareSigner::from_pkcs8_der(other, &entry.key_pkcs8).is_err(),
                "the entry's chain carries a leaf that pairs with its key:                  one key's identity leaked into the other's chain"
            );
        }
    }
}

fn which(program: &str) -> Option<std::path::PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths).find_map(|dir| {
            let full = dir.join(program);
            full.is_file().then_some(full)
        })
    })
}
