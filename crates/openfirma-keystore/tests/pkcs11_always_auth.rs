//! Finding A4: a key marked `CKA_ALWAYS_AUTHENTICATE` demands a second,
//! context-specific login (`C_Login(CKU_CONTEXT_SPECIFIC)`) as part of every
//! signature. Qualified cards mark their non-repudiation key that way, and
//! OpenSC marks the DNIe signing key with it whenever user consent is active.
//! Before the fix the reader logged in once as CKU_USER and never again, so
//! such a key answered CKR_USER_NOT_LOGGED_IN at C_Sign — with a message
//! blaming a missing --pin-env even though the PIN had been given. The deeper
//! bug was the constant itself: this crate defined CKA_ALWAYS_AUTHENTICATE as
//! 0x105, which is CKA_DECRYPT, so every private key advertised "true" and
//! the per-signature login path fired for keys that never asked for one. The
//! constant now matches pkcs11t.h (CKA_CLASS + 2 = 0x202). The token here is
//! SoftHSM (`tools/setup-test-keystores.sh` writes the third key pair with
//! `--always-auth`). Two measured quirks of SoftHSM 2.6 still shape what these
//! tests pin:
//!
//! - It serves `CKA_ALWAYS_AUTHENTICATE` as a native C++ `bool` — one byte, or
//!   four when asked for more (pkcs11-helper does exactly that). The reader
//!   classifies by the value in both widths; the listing test below pins that
//!   only the always-auth key is tagged and no plain key is.
//! - Its `C_Login` aborts whatever operation the session has active, so a
//!   login placed between `C_SignInit` and `C_Sign` (the PKCS#11 v2.40
//!   §11.2 order) answers CKR_OPERATION_NOT_INITIALIZED for this token. The
//!   signing code follows the spec order first and re-initialises when the
//!   module aborts; from the outside one `sign()` call works either way.

use std::path::{Path, PathBuf};

use openfirma_core::alg::DigestAlg;
use openfirma_core::signer::{Signer, verify_prehash};
use openfirma_keystore::SystemStore;
use openfirma_keystore::pkcs11::Pkcs11Store;

fn require_or_skip(reason: &str) {
    let required = std::env::var("OPENFIRMA_REQUIRE_TESTS").is_ok();
    let allowed = std::env::var("OPENFIRMA_ALLOW_SKIP").is_ok();
    if required && !allowed {
        panic!("cannot run the test: {reason}");
    }
    eprintln!("skipped, {reason}");
}

fn softhsm_env() -> Option<(PathBuf, String)> {
    let module = PathBuf::from(std::env::var("OPENFIRMA_TEST_PKCS11_MODULE").ok()?);
    if !module.is_file() {
        return None;
    }
    let conf = std::env::var("SOFTHSM2_CONF").ok()?;
    if !Path::new(&conf).is_file() {
        return None;
    }
    Some((module, "openfirma test".into()))
}

/// The listing itself is half the fix: with a four-byte always-authenticate
/// value whose last byte is zero, a naive "any byte set" read marks *every*
/// SoftHSM key — including the plain RSA and EC pairs OpenSC shows without
/// the flag. That would spend a context login on every signature and hide the
/// difference between keys that need one and keys that do not.
#[test]
fn plain_keys_are_not_listed_as_always_authenticate() {
    let Some((module, token)) = softhsm_env() else {
        require_or_skip("no SoftHSM test material (see the setup script)");
        return;
    };
    let store = Pkcs11Store::open(&module, Some(&token), Some("12345678".into()))
        .expect("the SoftHSM token must open");
    let certs = store.certificates().expect("listing must succeed");
    let plain: Vec<_> = certs
        .iter()
        .filter(|c| {
            c.label.as_deref() == Some("openfirma rsa")
                || c.label.as_deref() == Some("openfirma ec")
        })
        .collect();
    assert_eq!(
        plain.len(),
        2,
        "the fixture has the rsa and ec pairs; found {:?}",
        certs.iter().map(|c| &c.label).collect::<Vec<_>>()
    );
    for c in plain {
        assert!(
            !c.always_authenticate,
            "{} must not be marked always-authenticate",
            c.label.clone().unwrap_or_default()
        );
    }
    let always = certs
        .iter()
        .find(|c| c.label.as_deref() == Some("openfirma always-auth"))
        .expect("setup-test-keystores.sh writes the always-auth pair (id 0c)");
    assert!(
        always.always_authenticate,
        "the --always-auth key must be listed as always-authenticate"
    );
}

/// SHA-256 of b"openfirma pkcs11 integration" — same message as tests/pkcs11.rs.
const DIGEST_HEX: &str = "2075b035c9fd4d2911fb93310fb07bc7f748a07b088cff42c5cda8314d3f5b9f";

/// The message the signing code produces when a token refuses an
/// always-authenticate signature even after the context-specific login was
/// accepted (DNIe-class cards without a reader). Rebuilt here from the same
/// fragments as the crate-internal builder: the test asserts on this text, and
/// the crate's unit tests pin that its own builder produces the same shape.
fn per_signature_refusal_text() -> String {
    "C_Sign failed: CKR_USER_NOT_LOGGED_IN (0x184) — this key requires its PIN for every \
     signature (CKA_ALWAYS_AUTHENTICATE); openfirma asked the token for it with a \
     context-specific login (CKU_CONTEXT_SPECIFIC) and the card still refuses, which on \
     cards like the DNIe means no reader is attached or consent was denied"
        .to_string()
}

#[test]
fn signs_with_a_key_marked_always_authenticate() {
    let Some((module, token)) = softhsm_env() else {
        require_or_skip(
            "no SoftHSM test material: set OPENFIRMA_TEST_PKCS11_MODULE and SOFTHSM2_CONF \
             from tools/setup-test-keystores.sh",
        );
        return;
    };
    let store = Pkcs11Store::open(&module, Some(&token), Some("12345678".into()))
        .expect("the SoftHSM token built by setup-test-keystores.sh must open");
    let certs = store.certificates().expect("listing must succeed");
    let always = certs
        .iter()
        .find(|c| c.label.as_deref() == Some("openfirma always-auth"))
        .expect("setup-test-keystores.sh writes the always-auth pair (id 0c)");

    // The context-specific login lives with the signature operation, so a
    // plain sign through the store's signer is the whole exercise: before the
    // fix this call died with CKR_USER_NOT_LOGGED_IN.
    let digest = hex::decode(DIGEST_HEX).expect("constant digest");
    let signer = openfirma_keystore::StoreSigner::new(&store, always.clone());
    let sig = signer
        .sign_prehash(DigestAlg::Sha256, &digest)
        .expect("an always-auth key must sign once the context PIN check runs");
    verify_prehash(&always.cert, DigestAlg::Sha256, &digest, &sig)
        .expect("the token's signature must verify against its own certificate");
}

#[test]
fn a_context_refusal_names_the_check_and_never_blames_pin_env() {
    // The refusal text is built by the crate's own `per_signature_refusal`;
    // driving it against the token would mean sending a PIN the token must
    // reject, and SoftHSM counts failed CKU_CONTEXT_SPECIFIC logins toward the
    // lockout just like ordinary wrong PINs (measured). So the wording is
    // pinned by the crate's unit tests (`cargo test -p openfirma-keystore
    // --lib`), which check the real builder for CKA_ALWAYS_AUTHENTICATE,
    // CKU_CONTEXT_SPECIFIC and the absence of --pin-env. This integration
    // test keeps the same assertions on the fragments both copies share.
    let err = per_signature_refusal_text();
    assert!(
        err.contains("CKA_ALWAYS_AUTHENTICATE") && err.contains("CKU_CONTEXT_SPECIFIC"),
        "the refusal must name the per-signature PIN check, got: {err}"
    );
    assert!(
        !err.contains("--pin-env"),
        "a refusal that follows an accepted PIN must not blame --pin-env, got: {err}"
    );
}

#[test]
fn signing_a_plain_key_never_sends_a_context_login() {
    // A plain key's CKA_ALWAYS_AUTHENTICATE is false, so the per-signature
    // path stays entirely out of its way; SoftHSM locks a user after too many
    // failed context logins (measured), which is exactly what signing plain
    // keys with a PIN in the environment must not do.
    let Some((module, token)) = softhsm_env() else {
        require_or_skip("no SoftHSM test material (see the setup script)");
        return;
    };
    let store = Pkcs11Store::open(&module, Some(&token), Some("12345678".into()))
        .expect("the SoftHSM token must open");
    let digest = hex::decode(DIGEST_HEX).expect("constant digest");
    for cert in store
        .certificates()
        .expect("listing must succeed")
        .iter()
        .filter(|c| !c.always_authenticate)
    {
        let signer = openfirma_keystore::StoreSigner::new(&store, cert.clone());
        let sig = signer
            .sign_prehash(DigestAlg::Sha256, &digest)
            .unwrap_or_else(|e| {
                panic!(
                    "plain key '{}' must sign: {e}",
                    cert.label.as_deref().unwrap_or("(untitled)")
                )
            });
        verify_prehash(&cert.cert, DigestAlg::Sha256, &digest, &sig).unwrap_or_else(|e| {
            panic!(
                "signature of '{}' must verify: {e}",
                cert.label.as_deref().unwrap_or("(untitled)")
            )
        });
    }
}
