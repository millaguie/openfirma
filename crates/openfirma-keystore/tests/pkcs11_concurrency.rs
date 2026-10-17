//! Regression for the module-lock fix: SoftHSM's object store is shared by
//! every handle in a process (two `dlopen`s of one file are one instance) and
//! is not thread-safe — concurrent calls corrupt its internal `std::set` and
//! crash it inside `C_Login`/`C_GetAttributeValue` (upstream issue #518, still
//! unfixed in the 2.7.0 shipped here). The keystore serialises every call on a
//! module under that module's own lock, so all four shapes below must hold up
//! under real thread pressure instead of segfaulting within milliseconds.

use std::path::PathBuf;

use openfirma_keystore::SystemStore;
use openfirma_keystore::pkcs11::Pkcs11Store;

fn softhsm_module() -> Option<PathBuf> {
    let module = PathBuf::from(std::env::var("OPENFIRMA_TEST_PKCS11_MODULE").ok()?);
    if !module.is_file() || std::env::var("SOFTHSM2_CONF").is_err() {
        return None;
    }
    Some(module)
}

fn require_or_skip(reason: &str) {
    let required = std::env::var("OPENFIRMA_REQUIRE_TESTS").is_ok();
    let allowed = std::env::var("OPENFIRMA_ALLOW_SKIP").is_ok();
    if required && !allowed {
        panic!("cannot run the test: {reason}");
    }
    eprintln!("skipped, {reason}");
}

/// One store shared by many threads (each listing takes its own session).
#[test]
fn one_store_many_threads() {
    let Some(module) = softhsm_module() else {
        require_or_skip("no SoftHSM test material (see tools/setup-test-keystores.sh)");
        return;
    };
    let store = Pkcs11Store::open(&module, Some("openfirma test"), Some("12345678".into()))
        .expect("the fixture token must open");
    std::thread::scope(|s| {
        for _ in 0..4 {
            let store = &store;
            s.spawn(move || {
                for _ in 0..5 {
                    let certs = store.certificates().expect("listing must succeed");
                    assert_eq!(certs.len(), 5, "the fixture token holds five certificates");
                }
            });
        }
    });
}

/// Independent threads that each open a fresh store on the same library and
/// list through it — the exact shape whose `std::set` race used to crash
/// SoftHSM (parsec issue #264, SoftHSM issue #518).
#[test]
fn concurrent_opens_and_listings() {
    let Some(module) = softhsm_module() else {
        require_or_skip("no SoftHSM test material (see tools/setup-test-keystores.sh)");
        return;
    };
    std::thread::scope(|s| {
        for _ in 0..4 {
            let module = module.clone();
            s.spawn(move || {
                for _ in 0..3 {
                    let store =
                        Pkcs11Store::open(&module, Some("openfirma test"), Some("12345678".into()))
                            .expect("reopening the shared library must succeed");
                    assert_eq!(store.certificates().expect("listing").len(), 5);
                }
            });
        }
    });
}

/// Login-free listing in parallel. A SoftHSM logout tears down the object
/// handles its still-open sessions hold (upstream issue #329), so concurrent
/// PIN-less listings of a token whose objects only show after login are not a
/// supported shape — the module lock keeps them from crashing; what they must
/// never do is crash. The answer itself is whatever the module gives.
#[test]
fn no_pin_listing_parallel() {
    let Some(module) = softhsm_module() else {
        require_or_skip("no SoftHSM test material (see tools/setup-test-keystores.sh)");
        return;
    };
    let store = Pkcs11Store::open(&module, Some("openfirma test"), None)
        .expect("a PIN-less listing of this fixture must work");
    std::thread::scope(|s| {
        for _ in 0..4 {
            let store = &store;
            s.spawn(move || {
                for _ in 0..5 {
                    let _ = store.certificates();
                }
            });
        }
    });
}
