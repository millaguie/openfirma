//! The PKCS#11 and NSS keystores against real modules, with the material
//! `tools/setup-test-keystores.sh` builds: a SoftHSM token holding the RSA and
//! EC test signers, and an NSS shared DB holding the same two.
//!
//! Every signature this suite produces is verified twice over — once by
//! `openfirma_core::signer::verify_prehash` (pure Rust) and once by the
//! openssl CLI — because a keystore bug that only one verifier sees is exactly
//! the kind of bug that ships silently: an RSA path double-hashing, or an ECDSA
//! raw r||s left undee-encoded, each verified fine by *some* thing. Both saw
//! real failures while these backends were being written; that is why both stay.
//!
//! Layout safety: `types.rs` asserts the v2.40 offsets at compile time for
//! every target, and this file proves them against live modules — SoftHSM on
//! Linux, and NSS softokn3 wherever its library exists. Skips follow the same
//! rules as tests/pkcs12.rs: missing material skips (unless
//! OPENFIRMA_REQUIRE_TESTS says the environment promised to have it), and
//! material that is present but fails is a panic, never a quiet pass.

use std::path::{Path, PathBuf};
use std::process::Command;

use openfirma_core::alg::DigestAlg;
use openfirma_core::signer::{Signer, verify_prehash};
use openfirma_keystore::pkcs11::Pkcs11Store;
use openfirma_keystore::{StoreCertificate, StoreSigner, SystemStore};

fn require_or_skip(reason: &str) {
    let required = std::env::var("OPENFIRMA_REQUIRE_TESTS").is_ok();
    let allowed = std::env::var("OPENFIRMA_ALLOW_SKIP").is_ok();
    if required && !allowed {
        panic!("cannot run the test: {reason}");
    }
    eprintln!("skipped, {reason}");
}

/// SHA-256 of `b"openfirma pkcs11 integration"` — the bytes every signature
/// here covers; kept as a fixed hex string so the openssl cross-check signs
/// exactly the same content.
fn message_and_digest() -> (Vec<u8>, Vec<u8>) {
    let msg = b"openfirma pkcs11 integration".to_vec();
    let digest = hex::decode("2075b035c9fd4d2911fb93310fb07bc7f748a07b088cff42c5cda8314d3f5b9f")
        .expect("the constant digest must be valid hex");
    (msg, digest)
}

fn check_signature(store: &dyn SystemStoreLike, cert: &StoreCertificate) {
    let (msg, digest) = message_and_digest();
    let signer = store.signer(cert);
    let sig = signer
        .sign_prehash(DigestAlg::Sha256, &digest)
        .expect("a present token must sign");

    // Verifier one: openfirma's own.
    verify_prehash(&cert.cert, DigestAlg::Sha256, &digest, &sig)
        .expect("the token's signature must verify against its own certificate");

    // Verifier two: openssl over the message itself (it computes the digest;
    // if the constant above ever drifted from the message this catches it).
    // The scratch files are named after the thread, not just the process:
    // cargo runs these tests in parallel threads sharing one pid.
    let dir = std::env::temp_dir().join(format!(
        "openfirma-pkcs11-check-{}-{}",
        std::process::id(),
        std::thread::current()
            .name()
            .unwrap_or("main")
            .replace("::", "_"),
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let der_path = dir.join("cert.der");
    let sig_path = dir.join("sig.bin");
    let msg_path = dir.join("msg.bin");
    std::fs::write(&der_path, cert.cert.der()).unwrap();
    std::fs::write(&sig_path, &sig).unwrap();
    std::fs::write(&msg_path, &msg).unwrap();
    let pem_path = dir.join("cert.pem");
    let status = Command::new("openssl")
        .args(["x509", "-inform", "DER", "-in"])
        .arg(&der_path)
        .args(["-pubkey", "-noout", "-out"])
        .arg(&pem_path)
        .status()
        .expect("openssl must be installed for this test");
    assert!(status.success(), "openssl x509 -pubkey failed");
    let out = Command::new("openssl")
        .args(["dgst", "-sha256", "-verify"])
        .arg(&pem_path)
        .args(["-signature"])
        .arg(&sig_path)
        .arg(&msg_path)
        .output()
        .expect("openssl must be installed for this test");
    assert!(
        out.status.success() && String::from_utf8_lossy(&out.stdout).contains("OK"),
        "openssl must verify the token signature: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Object-safe shim so both backends share one body. `SystemStore` itself is
/// not object safe (it takes &self generically nowhere — it *is* object safe,
/// but StoreSigner is generic over S); this keeps the test readable either way.
trait SystemStoreLike {
    fn signer<'a>(&'a self, cert: &'a StoreCertificate) -> Box<dyn Signer + 'a>;
}

impl<S: SystemStore + Sized> SystemStoreLike for S {
    fn signer<'a>(&'a self, cert: &'a StoreCertificate) -> Box<dyn Signer + 'a> {
        Box::new(StoreSigner::new(self, cert.clone()))
    }
}

// ---------------------------------------------------------------------------
// SoftHSM

fn softhsm_env() -> Option<(PathBuf, String)> {
    let module = PathBuf::from(std::env::var("OPENFIRMA_TEST_PKCS11_MODULE").ok()?);
    if !module.is_file() {
        return None;
    }
    // The token lives under the SoftHSM config the setup script exported, and
    // the module needs that exact config in *this* process: libsofthsm2 reads
    // SOFTHSM2_CONF itself at init.
    let conf = std::env::var("SOFTHSM2_CONF").ok()?;
    if !Path::new(&conf).is_file() {
        return None;
    }
    Some((module, "openfirma test".into()))
}

#[test]
fn softhsm_lists_pairs_and_signs_both_keys() {
    let Some((module, token)) = softhsm_env() else {
        require_or_skip(
            "no SoftHSM test material: set OPENFIRMA_TEST_PKCS11_MODULE and SOFTHSM2_CONF \
             from tools/setup-test-keystores.sh",
        );
        return;
    };
    let store = Pkcs11Store::open(&module, Some(&token), Some("12345678".into()))
        .expect("the SoftHSM token built by setup-test-keystores.sh must open");
    assert_eq!(store.token_label(), "openfirma test");

    let certs = store.certificates().expect("listing must succeed");
    // Every certificate on the token carries a signable key: rsa, ec,
    // always-auth, and the two DNIe shapes the A5 filter test needs. (The
    // always-auth pair exists for tests/pkcs11_always_auth.rs; the DNIE pair
    // for tests/dnie_filter.rs.)
    assert_eq!(
        certs.len(),
        5,
        "expected rsa + ec + always-auth + DNIE auth/sign, got {certs:?}"
    );
    let labels: Vec<&str> = certs.iter().filter_map(|c| c.label.as_deref()).collect();
    assert!(labels.contains(&"openfirma rsa"), "{labels:?}");
    assert!(labels.contains(&"openfirma ec"), "{labels:?}");
    assert!(labels.contains(&"openfirma always-auth"), "{labels:?}");
    for c in &certs {
        assert!(
            matches!(c.key_handle, openfirma_keystore::KeyHandle::Pkcs11Id(_)),
            "a PKCS#11 store must hand out PKCS#11 handles"
        );
        check_signature(&store, c);
    }

    // A wrong PIN is refused up front, at open time — SoftHSM does check the
    // PIN on C_Login — and the refusal says which token and that the PIN is
    // wrong. Ordering matters: do this last, a real token locks its PIN after
    // too many failures and we never want to leave test material in that
    // state. (The --pin-env hint rides on CKR_USER_NOT_LOGGED_IN, for tokens
    // where an absent PIN surfaces at sign time instead.)
    let err = Pkcs11Store::open(&module, Some("openfirma test"), Some("00000000".into()))
        .err()
        .expect("a wrong PIN must be refused");
    let msg = err.to_string();
    for expected in ["openfirma test", "CKR_PIN_INCORRECT", "the PIN is wrong"] {
        assert!(
            msg.contains(expected),
            "the refusal must contain '{expected}': {msg}"
        );
    }

    // Listing without a PIN proves the pairing rule: SoftHSM keeps
    // certificates public but hides private keys until login, so an anonymous
    // session sees two certificates and no key to pair them with, and the
    // store must report *zero* usable signers — never a certificate that
    // cannot actually sign. A token that hid even the certificates would fail
    // the same listing with the --pin-env hint instead; both shapes are safe.
    let anon = Pkcs11Store::open(&module, Some("openfirma test"), None)
        .expect("listing may open without a PIN");
    let certs = anon
        .certificates()
        .expect("a token whose certificates are public lists them or reports none");
    assert!(
        certs.is_empty(),
        "an anonymous listing must never hand out unpairable certificates: {certs:?}"
    );
}

/// Round 2, 04-N6. SoftHSM's own refusal for a wrong PIN advertises the token's
/// remaining tries, so an empty `C_Login` is not a no-op there: it is a real
/// failed attempt. A key the token lets us use without a login (OpenSC serves
/// many cards that way) must therefore sign without one. Before the fix this
/// failed with CKR_PIN_INCORRECT, because `sign_prehash` always logged in and
/// with no PIN it sent the empty string.
#[test]
fn a_key_visible_without_a_login_signs_without_spending_a_pin_try() {
    let Some((module, _)) = softhsm_env() else {
        require_or_skip(
            "no SoftHSM test material: set OPENFIRMA_TEST_PKCS11_MODULE and SOFTHSM2_CONF \
             from tools/setup-test-keystores.sh",
        );
        return;
    };
    // The token with a CKA_PRIVATE=false key needs p11tool to build (see the
    // setup script); where that is missing the label is not there at all, which
    // is a skip and never a pass.
    let Some(store) = Pkcs11Store::open(&module, Some("openfirma publica"), None)
        .ok()
        .filter(|s| s.token_label() == "openfirma publica")
    else {
        require_or_skip(
            "no public-key token: tools/setup-test-keystores.sh builds it when p11tool \
             (gnutls-bin) is installed",
        );
        return;
    };
    let certs = store
        .certificates()
        .expect("a key visible without a login lists without a PIN");
    assert_eq!(
        certs.len(),
        1,
        "the public-key token holds one signer: {certs:?}"
    );
    // The bite: this only succeeds if no empty C_Login ran first, and this
    // token's PIN is not empty.
    check_signature(&store, &certs[0]);

    // And nothing above left the fixture unusable: it still opens with its own
    // PIN (a token whose tries a stray login had exhausted would not). Named
    // limit: whether an attempt was spent is not read back here — the bite is
    // that the anonymous signature succeeds at all, which it cannot do while an
    // empty C_Login runs first, and the second half of the fix (what a token
    // that *does* demand a PIN gets told) has no live shape on SoftHSM: a key
    // that is visible without a login cannot carry CKA_ALWAYS_AUTHENTICATE
    // there, so it is pinned by the unit test below instead.
    let with_pin = Pkcs11Store::open(&module, Some("openfirma publica"), Some("12345678".into()))
        .expect("the fixture still opens with its PIN");
    assert_eq!(with_pin.token_label(), "openfirma publica");
}

// ---------------------------------------------------------------------------
// NSS shared database (libsoftokn3)

fn nss_env() -> Option<(PathBuf, String)> {
    let db = std::env::var("OPENFIRMA_TEST_NSS_DB").ok()?;
    if !Path::new(db.strip_prefix("sql:").unwrap_or(&db)).exists() {
        return None;
    }
    // OPENFIRMA_NSS_MODULE wins; otherwise probe. The library is *not* where
    // every package installs it: Debian's libnss3 ships it under the multiarch
    // dir (/usr/lib/x86_64-linux-gnu), which does not even exist on Arch (and
    // differs by triplet between x86_64 and aarch64 runners). Trusting one
    // path silently skipped the NSS suite in CI while the SoftHSM one ran.
    if let Ok(explicit) = std::env::var("OPENFIRMA_NSS_MODULE") {
        let module = PathBuf::from(explicit);
        return module.is_file().then_some((module, db));
    }
    let mut candidates: Vec<PathBuf> = vec![PathBuf::from("/usr/lib/libsoftokn3.so")];
    if let Ok(triplet) = std::process::Command::new("dpkg-architecture")
        .args(["-q", "DEB_HOST_MULTIARCH"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
    {
        if !triplet.is_empty() {
            candidates.push(PathBuf::from(format!("/usr/lib/{triplet}/libsoftokn3.so")));
        }
    }
    let module = candidates.into_iter().find(|p| p.is_file())?;
    Some((module, db))
}

#[test]
fn nss_db_lists_signs_and_still_explains_a_bogus_database() {
    let Some((module, db)) = nss_env() else {
        require_or_skip(
            "no NSS test material: set OPENFIRMA_TEST_NSS_DB (and the module if not \
             /usr/lib) from tools/setup-test-keystores.sh",
        );
        return;
    };
    let store = Pkcs11Store::open_nss(&module, &db, None, Some(String::new()))
        .expect("the NSS DB built by setup-test-keystores.sh must open");
    // The default picks the certificate database out of NSS's two slots.
    assert_eq!(store.token_label(), "NSS Certificate DB");

    let certs = store.certificates().expect("listing must succeed");
    assert_eq!(certs.len(), 2, "expected both signers, got {certs:?}");
    for c in &certs {
        check_signature(&store, c);
    }

    // A token name that does not exist is refused by listing the ones that do.
    let err = Pkcs11Store::open_nss(&module, &db, Some("does not exist"), None)
        .err()
        .expect("must fail")
        .to_string();
    assert!(
        err.contains("NSS Certificate DB"),
        "must show the real labels: {err}"
    );

    // A database location with a quote inside cannot be expressed in
    // softokn3's config syntax; refuse with our message, not NSS's. The
    // module argument is never even opened — but softokn3 is already
    // initialized by the successful open above and absorbs that anyway.
    let err = Pkcs11Store::open_nss(&module, "/no/such/'db", None, None)
        .err()
        .expect("must fail")
        .to_string();
    assert!(
        err.contains("quote"),
        "must explain the quoting limit: {err}"
    );
}

#[test]
fn a_second_nss_database_in_one_process_is_refused_by_name() {
    // Round 2, 04-N2: softokn3 reads its `configDir` out of C_Initialize once
    // per process, and Cryptoki has no second initialize for the same library.
    // Before this was checked, opening a second NSS database in the same run
    // handed it the FIRST one's handle, and it listed the first database's
    // certificates under the second one's origin — a certificate attributed to
    // the wrong store (and, in the window, rows whose origin was a lie).
    let Some((module, db)) = nss_env() else {
        require_or_skip(
            "no NSS test material: set OPENFIRMA_TEST_NSS_DB (and the module if not \
             /usr/lib) from tools/setup-test-keystores.sh",
        );
        return;
    };
    // Whichever test ran first, the fixture database is the one this process
    // initialized softokn3 with: every NSS test here opens it before anything
    // else, and opening it again is the reuse path.
    let _fixture =
        Pkcs11Store::open_nss(&module, &db, None, Some(String::new())).expect("the fixture DB");

    // A copy of it, in a directory of its own: same certificates, different
    // `configDir`. It must be refused, and the refusal must name both.
    let dir = std::env::temp_dir().join(format!("openfirma-nss-second-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    let source = Path::new(db.strip_prefix("sql:").unwrap_or(&db));
    for entry in std::fs::read_dir(source).unwrap().flatten() {
        if entry.path().is_file() {
            std::fs::copy(entry.path(), dir.join(entry.file_name())).unwrap();
        }
    }
    let other = format!("sql:{}", dir.display());
    let err = Pkcs11Store::open_nss(&module, &other, None, Some(String::new()))
        .err()
        .expect("a second NSS database cannot be opened in the same process")
        .to_string();
    assert!(
        err.contains("already open in this process"),
        "the refusal must say why one library cannot hold two databases: {err}"
    );
    assert!(
        err.contains(&dir.display().to_string()),
        "the refusal must name the database that cannot be opened: {err}"
    );
    // And the fixture is still the one this process can answer with.
    let again = Pkcs11Store::open_nss(&module, &db, None, Some(String::new()))
        .expect("the fixture database is still the open one");
    assert_eq!(again.token_label(), "NSS Certificate DB");
    std::fs::remove_dir_all(&dir).ok();
}

// ---------------------------------------------------------------------------
// module loading and table validation (no token material needed)

#[test]
fn not_a_module_is_reported_clearly() {
    let this = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let err = Pkcs11Store::open(&this, None, None)
        .err()
        .expect("must fail")
        .to_string();
    assert!(
        err.contains("cannot load PKCS#11 module"),
        "a random file must be refused at load time, got: {err}"
    );

    let missing = Pkcs11Store::open(Path::new("/nonexistent/libfake.so"), None, None)
        .err()
        .expect("must fail")
        .to_string();
    assert!(
        missing.contains("cannot load PKCS#11 module"),
        "a missing file must say so: {missing}"
    );
}

#[test]
fn function_list_offsets_match_their_documented_bytes() {
    // The same numbers types.rs asserts at compile time, spelled out here as
    // the test the module documentation promises.
    for (name, off) in openfirma_keystore::pkcs11::function_list_offsets() {
        let slot: usize = match name {
            "C_Initialize" => 1,
            "C_GetSlotList" => 5,
            "C_OpenSession" => 13,
            "C_Login" => 19,
            "C_GetAttributeValue" => 25,
            "C_FindObjectsInit" => 27,
            "C_SignInit" => 43,
            "C_Sign" => 44,
            other => panic!("offsets() grew a new entry: {other}"),
        };
        // Slot addresses depend on the platform ABI: Windows modules are
        // read under the packed cryptoki headers, where C_Initialize (spec
        // slot 1) sits two bytes into the table right behind the version
        // pair and every later spec slot one pointer after it — `2 +
        // (k−1)·p`. Unix LP64 naturally aligns each pointer behind slot 0's
        // tail padding, putting function k at byte 8k. See types.rs for the
        // measured tables both rules come from.
        let ptr = std::mem::size_of::<*const u8>();
        let want = if cfg!(windows) {
            2 + (slot - 1) * ptr
        } else {
            slot * 8
        };
        assert_eq!(
            off, want,
            "{name} must sit at byte {want} (spec slot {slot})"
        );
    }
}

#[test]
#[ignore = "sets a process-global env var: run alone with --ignored --test-threads=1"]
fn version_guard_refuses_an_incompatible_table() {
    // The refusal branch is only reachable on CI through its test hook: no
    // module older than 2.0 exists to load. With the hook set, a perfectly
    // good SoftHSM must be refused as if it were pre-2.0. Ignored by default
    // because an environment variable this wide cannot be raced against the
    // other tests of this binary; CI runs it in its own thread-zero pass.
    let Some((module, _)) = softhsm_env() else {
        require_or_skip("no PKCS#11 module to refuse");
        return;
    };
    unsafe { std::env::set_var("OPENFIRMA_FORCE_OLD_VERSION_REJECTION", "1") };
    let err = Pkcs11Store::open(&module, Some("openfirma test"), None)
        .err()
        .expect("the hook must force the version refusal");
    unsafe { std::env::remove_var("OPENFIRMA_FORCE_OLD_VERSION_REJECTION") };
    assert!(
        err.to_string().contains("openfirma speaks 2.40"),
        "the refusal must be the version message, got: {err}"
    );
}
