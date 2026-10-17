//! Finding A5: the keystore listing must apply AutoFirma's default filters —
//! `SkipAuthDNIeFilter` (`skipAuthCertDnie = true`) and expired-certificate
//! hiding — through one shared rule in openfirma-keystore, not per backend.
//! The fixture token carries the two shapes that rule was written for: a DNIe
//! authentication certificate (issuer cn=AC DNIE *, ou=DNIE, o=DIRECCION
//! GENERAL DE LA POLICIA; keyUsage digitalSignature) and its nonRepudiation
//! signing twin. `tools/setup-test-keystores.sh` writes both.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use openfirma_keystore::pkcs11::Pkcs11Store;
use openfirma_keystore::{FilteredStore, StoreCertificate, SystemStore};

fn softhsm_env() -> Option<(PathBuf, String)> {
    let module = PathBuf::from(std::env::var("OPENFIRMA_TEST_PKCS11_MODULE").ok()?);
    if !module.is_file() || std::env::var("SOFTHSM2_CONF").is_err() {
        return None;
    }
    Some((module, "openfirma test".into()))
}

fn require_or_skip(reason: &str) -> Option<Pkcs11Store> {
    let required = std::env::var("OPENFIRMA_REQUIRE_TESTS").is_ok();
    let allowed = std::env::var("OPENFIRMA_ALLOW_SKIP").is_ok();
    if required && !allowed {
        panic!("cannot run the test: {reason}");
    }
    eprintln!("skipped, {reason}");
    None
}

fn fixture_store() -> Option<Pkcs11Store> {
    let Some((module, token)) = softhsm_env() else {
        return require_or_skip("no SoftHSM test material (see tools/setup-test-keystores.sh)");
    };
    Some(
        Pkcs11Store::open(&module, Some(&token), Some("12345678".into()))
            .expect("the fixture token must open"),
    )
}

fn label(certs: &[StoreCertificate]) -> Vec<String> {
    certs
        .iter()
        .map(|c| c.label.clone().unwrap_or_default())
        .collect()
}

#[test]
fn the_token_lists_the_dnie_shapes_and_the_filter_hides_exactly_the_auth_one() {
    let Some(store) = fixture_store() else {
        return;
    };
    let all = store.certificates().expect("listing must succeed");
    for want in ["DNIE auth", "DNIE sign"] {
        assert!(
            label(&all).contains(&want.to_string()),
            "setup-test-keystores.sh writes the {want} pair, got {:?}",
            label(&all)
        );
    }
    let now = SystemTime::now();
    let visible: Vec<_> = all
        .iter()
        .filter(|c| !openfirma_keystore::hidden_by_default(c, now))
        .cloned()
        .collect();
    let labels = label(&visible);
    assert!(
        !labels.contains(&"DNIE auth".to_string()),
        "the authentication certificate (digitalSignature only, AC DNIE issuer) \
         must be hidden by the AutoFirma default filter: {labels:?}"
    );
    // The signing twin (nonRepudiation), and every ordinary key, stay.
    assert!(labels.contains(&"DNIE sign".to_string()), "{labels:?}");
    assert!(labels.contains(&"openfirma rsa".to_string()), "{labels:?}");
    assert!(labels.contains(&"openfirma ec".to_string()), "{labels:?}");
    // Expired certificates are the filter's other half; the fixture certs run
    // for years, so pin that half by time-travelling instead.
    let far_future = now + Duration::from_secs(60 * 60 * 24 * 365 * 10);
    let dead: Vec<_> = all
        .iter()
        .filter(|c| !openfirma_keystore::hidden_by_default(c, far_future))
        .collect();
    assert!(
        dead.is_empty(),
        "ten years from now every fixture certificate is expired and none may show"
    );
}

#[test]
fn a_filtered_keystore_leaves_exactly_one_signer_per_card() {
    // The picker promise behind the finding: on a DNIe, after filtering, the
    // signing certificate stands alone — `sign --store …` chooses it without
    // --store-alias and with no chance of picking the login card.
    let Some(store) = fixture_store() else {
        return;
    };
    let filtered: Arc<dyn SystemStore> =
        Arc::new(FilteredStore::new(Arc::new(store), SystemTime::now()));
    let certs = filtered.certificates().expect("listing");
    let labels = label(&certs);
    // Three signers remain (rsa, ec, DNIE sign): a DNIe alone in its reader
    // — the pair 0d/0e without the test keys — is what resolves to one.
    assert_eq!(
        certs
            .iter()
            .filter(|c| c.label.as_deref() == Some("DNIE sign"))
            .count(),
        1,
        "{labels:?}"
    );
    assert!(!labels.contains(&"DNIE auth".to_string()), "{labels:?}");
}

#[test]
fn the_auth_certificate_is_still_signable_by_explicit_name() {
    // The filter decides what is OFFERED, not what the token may do: naming
    // the hidden entry (the CLI's --store-alias path) reaches it. This is the
    // shape behind the CLI's warning — reachable by request, never silently.
    let Some(store) = fixture_store() else {
        return;
    };
    let all = store.certificates().expect("listing");
    let auth = all
        .iter()
        .find(|c| c.label.as_deref() == Some("DNIE auth"))
        .expect("the fixture carries the authentication shape");
    assert!(auth.cert.is_dnie_authentication_cert());
    assert!(matches!(
        auth.key_handle,
        openfirma_keystore::KeyHandle::Pkcs11Id(_)
    ));
    // And it signs when named: reaching this path is exactly what --store-alias
    // does, and the CLI turns it into a warning (pinned in the CLI's own
    // tests); here it just must not be the filter's job to forbid it.
    let digest = openfirma_core::alg::DigestAlg::Sha256;
    use openfirma_core::signer::Signer;
    let signer = openfirma_keystore::StoreSigner::new(&store, auth.clone());
    let prehash = {
        use sha2::Digest as _;
        sha2::Sha256::digest("openfirma a5 filter").to_vec()
    };
    let sig = signer
        .sign_prehash(digest, &prehash)
        .expect("the hidden entry still signs");
    openfirma_core::signer::verify_prehash(&auth.cert, digest, &prehash, &sig)
        .expect("and the signature verifies against its own certificate");
}
