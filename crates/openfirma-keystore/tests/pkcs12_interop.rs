//! Keystore interoperability regression tests (wave 4a, review 04).
//!
//! Every test here pins down one finding from the keystore review against
//! a fixture written by a *real* producer (`keytool`, `openssl`, NSS's
//! `pk12util` — see `tools/gen-p12-fixtures.sh`). The fixtures live in
//! `testdata/certs/p12-fixtures/` next to the golden PKI, and all of them
//! are synthetic.
//!
//! Findings covered:
//! - C2: BER indefinite-length containers (OpenSSL/NSS exports)
//! - A1: PBKDF2 keyLength must match the cipher's key length
//! - A3: empty password — Java writes zero BMP chars, OpenSSL/NSS write
//!   the `00 00` BMP terminator; both spellings must open
//! - A2: PBES2 + RC2-40-CBC envelopes (the legacy export recipe)

use std::path::{Path, PathBuf};

use openfirma_core::cert::CertificateHandle;
use openfirma_keystore::pkcs12::Pkcs12;

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/certs/p12-fixtures")
}

fn require_or_skip(name: &str) -> PathBuf {
    let path = fixtures_dir().join(name);
    if !path.exists() {
        if std::env::var_os("OPENFIRMA_REQUIRE_TESTS").is_some() {
            panic!("fixture {name} is missing; run tools/gen-p12-fixtures.sh");
        }
        eprintln!("skipping {name}: fixture not present");
        return PathBuf::new();
    }
    path
}

fn load(name: &str, password: &str) -> Pkcs12 {
    let path = require_or_skip(name);
    if path.as_os_str().is_empty() {
        return Pkcs12::default();
    }
    let bytes = std::fs::read(&path).expect("fixture readable");
    Pkcs12::load(&bytes, password).unwrap_or_else(|e| panic!("{name} must open: {e}"))
}

/// The pairing rule exercised through the container: the first certificate of
/// every entry must be the one whose SPKI the private key derives.
fn assert_entry_key_matches_leaf(name: &str, chain: &[Vec<u8>], key_pkcs8: &[u8]) {
    let cert = CertificateHandle::from_der(&chain[0])
        .unwrap_or_else(|e| panic!("{name}: leaf must parse: {e}"));
    // Negative control: the certificate's own public SPKI is not a
    // certificate, so feeding the pairing anything but the real pair fails.
    let foreign = cert.spki_der().expect("leaf has an SPKI");
    assert!(
        openfirma_core::SoftwareSigner::from_pkcs8_der(foreign.as_ref(), key_pkcs8).is_err(),
        "{name}: a public key is not a certificate: the pairing must refuse it"
    );
    // Positive: through the crate's own signer machinery, the entry's key
    // must sign for its own leaf.
    let signed = openfirma_core::SoftwareSigner::from_pkcs8_der(&chain[0], key_pkcs8)
        .unwrap_or_else(|e| panic!("{name}: the leaf certificate does not belong to its key: {e}"));
    use openfirma_core::signer::Signer as _;
    let _ = signed
        .sign_prehash(openfirma_core::DigestAlg::Sha256, &[7u8; 32])
        .expect("the entry's key signs");
}

/// C2: OpenSSL and NSS serialise PKCS#12 with BER indefinite lengths.
/// DER-only readers refuse the whole container. openssl-empty.p12 is the BER
/// shape *and* an empty password (one fixture, two findings; A3 pins the
/// password side), nss-export.p12 is pk12util's own export under its password.
#[test]
fn opens_a_ber_indefinite_length_container_from_openssl_or_nss() {
    let store = load("openssl-empty.p12", "");
    assert_eq!(store.entries.len(), 1);
    assert_entry_key_matches_leaf(
        "openssl-empty.p12",
        &store.entries[0].chain,
        &store.entries[0].key_pkcs8,
    );

    let store = load("nss-export.p12", "openfirma");
    assert_eq!(
        store.entries.len(),
        1,
        "nss-export.p12 must yield one entry"
    );
    assert_entry_key_matches_leaf(
        "nss-export.p12",
        &store.entries[0].chain,
        &store.entries[0].key_pkcs8,
    );
}

/// A1: Java 11+ writes PBES2 with HMAC-SHA256 + AES-256-CBC and a PBKDF2
/// keyLength of 32. The KDF must use the cipher's real key length — silently
/// using SHA-256's default 20 would derive a different, useless key.
#[test]
fn derives_pbkdf2_keys_with_the_declared_key_length() {
    let store = load("java-default.p12", "openfirma");
    assert_eq!(store.entries.len(), 1);
    let entry = &store.entries[0];
    assert!(
        !entry.chain.is_empty(),
        "the java-default chain must be present"
    );
    assert_entry_key_matches_leaf("java-default.p12", &entry.chain, &entry.key_pkcs8);
    // And the legacy spelling (PBMAC=SHA-1 + RC2-40) still opens.
    let legacy = load("java-legacy.p12", "openfirma");
    assert_eq!(legacy.entries.len(), 1);
}

/// A1: a corrupt container must be refused with a named cause. Byte-editing a
/// PBES2 identifier's keyLength inside a real file also invalidates the MAC,
/// so end-to-end we pin the two honest outcomes the review asks to tell apart:
/// either the parameter contradiction is caught by name, or integrity fails
/// first — never a silent accept. (The pure parameter check — declared length
/// vs cipher's key size, naming both values — lives in the crate unit tests,
/// where the contradiction can be built without a MAC in the way.)
#[test]
fn refuses_a_key_length_that_contradicts_the_cipher_instead_of_guessing() {
    let path = require_or_skip("java-default.p12");
    if path.as_os_str().is_empty() {
        return;
    }
    let mut der = std::fs::read(&path).expect("fixture readable");
    let needle = [0x02, 0x01, 0x20];
    let hit = der
        .windows(needle.len())
        .rposition(|w| w == needle)
        .expect("the declared keyLength is present");
    der[hit + 2] = 0x10; // INTEGER 16 — an AES-256 cipher with a 128-bit KDF

    let err = Pkcs12::load(&der, "openfirma").expect_err("a corrupt parameter must be refused");
    let text = format!("{err}");
    assert!(
        text.contains("keyLength") || text.contains("integrity"),
        "the refusal must name the contradiction or the integrity failure, got: {text}"
    );
}

/// A3 (OpenSSL/NSS spelling): PKCS#12 encodes the empty password as one
/// BMP character (two zero bytes), so the MacData of an empty-password
/// container is keyed with `00 00`.
#[test]
fn checks_the_mac_of_an_empty_password_container_written_as_bmp_terminator() {
    let path = require_or_skip("openssl-empty-legacy.p12");
    if path.as_os_str().is_empty() {
        return;
    }
    let bytes = std::fs::read(&path).expect("fixture readable");
    Pkcs12::load(&bytes, "").unwrap_or_else(|e| panic!("openssl-empty-legacy.p12 must open: {e}"));

    // And a wrong password is still refused.
    let err = Pkcs12::load(&bytes, "not-it").expect_err("a wrong password must not open it");
    let text = format!("{err}");
    assert!(
        text.contains("integrity") || text.contains("password"),
        "{text}"
    );
}

/// A3 (Java spelling): SunJSSE's PBECodec converts an empty password to the
/// ASCII string "" *before* the BMP encoding, so the MAC key for Java's
/// empty-password containers is the two-byte terminator `00 00` — while the
/// ENCRYPTED BAGS were still derived from a non-empty password at creation
/// time. java-empty*.p12 are keytool containers re-keyed to the empty MAC
/// (tools/p12-empty-mac.py): reading them proves the Java MAC spelling is
/// accepted; opening their bags then honestly reports the real cause.
#[test]
fn checks_the_mac_of_a_java_empty_password_container_without_terminator() {
    for name in ["java-empty.p12", "java-empty-legacy.p12"] {
        let path = require_or_skip(name);
        if path.as_os_str().is_empty() {
            continue;
        }
        let bytes = std::fs::read(&path).expect("fixture readable");
        // The MAC check must pass with the empty password (the review's bug:
        // Java containers were refused outright because we never tried this
        // spelling), and a wrong password must still be refused.
        let err_with_password =
            Pkcs12::load(&bytes, "nope").expect_err("a wrong password must not pass the MAC check");
        let _ = format!("{err_with_password}");
        match Pkcs12::load(&bytes, "") {
            // Either fully open (if ever re-encrypted end to end) or refused
            // past the MAC with an honest cause: never a false "integrity
            // check failed", which would mean we never tried Java's spelling.
            Ok(store) => assert_eq!(store.entries.len(), 1),
            Err(e) => {
                let text = format!("{e}");
                assert!(
                    !text.contains("integrity check"),
                    "the MAC must pass for the Java empty spelling, got: {text}"
                );
            }
        }
    }
}

/// A3: NSS's pk12util exports unencrypted containers whose MAC is keyed
/// with the same `00 00` BMP spelling.
#[test]
fn opens_an_nss_empty_password_container() {
    let path = require_or_skip("nss-export-empty.p12");
    if path.as_os_str().is_empty() {
        return;
    }
    let bytes = std::fs::read(&path).expect("fixture readable");
    Pkcs12::load(&bytes, "").unwrap_or_else(|e| panic!("nss-export-empty.p12 must open: {e}"));
}

/// A2: `openssl pkcs12` with the legacy provider writes the certificates
/// and/or the key as PBES2 with RC2-40-CBC. OpenSSL still validates these
/// containers; so do we.
#[test]
fn decrypts_pbkdf2_rc2_40_envelopes_from_legacy_export_recipes() {
    let store = load("rc2-certs.p12", "openfirma");
    assert_eq!(store.entries.len(), 1);
    assert_entry_key_matches_leaf(
        "rc2-certs.p12",
        &store.entries[0].chain,
        &store.entries[0].key_pkcs8,
    );

    // And when *both* bag types are RC2-40 (the full legacy recipe).
    let both = load("rc2-both.p12", "openfirma");
    assert_eq!(both.entries.len(), 1);
    assert_entry_key_matches_leaf(
        "rc2-both.p12",
        &store.entries[0].chain,
        &store.entries[0].key_pkcs8,
    );
}

/// The whole fixture set, opened with its real producer's password: every
/// container must yield an entry whose certificate and key agree.
#[test]
fn every_fixture_yields_an_entry_whose_key_matches_its_certificate() {
    let dir = fixtures_dir();
    if !dir.exists() {
        if std::env::var_os("OPENFIRMA_REQUIRE_TESTS").is_some() {
            panic!("fixture directory missing; run tools/gen-p12-fixtures.sh");
        }
        return;
    }
    let mut opened = 0;
    // Non-empty-password fixtures, under the password the producer wrote them
    // with (see gen-p12-fixtures.sh).
    for name in [
        "nss-export.p12",
        "java-default.p12",
        "java-legacy.p12",
        "rc2-certs.p12",
        "rc2-both.p12",
    ] {
        let store = load(name, "openfirma");
        for entry in &store.entries {
            assert_entry_key_matches_leaf(name, &entry.chain, &entry.key_pkcs8);
            opened += 1;
        }
    }
    // Empty-password fixtures, opened with the empty password.
    for name in [
        "openssl-empty.p12",
        "openssl-empty-legacy.p12",
        "nss-export-empty.p12",
    ] {
        let store = load(name, "");
        for entry in &store.entries {
            assert_entry_key_matches_leaf(name, &entry.chain, &entry.key_pkcs8);
            opened += 1;
        }
    }
    assert!(opened >= 8, "expected to open the whole fixture set");
}
