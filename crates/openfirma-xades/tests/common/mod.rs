//! What the XAdES integration tests share: where the test PKI is, how to say
//! "this cannot run here", how to load a signer, and where a file handed to an
//! external verifier goes.
//!
//! Round two's B-4 closed the dead code in `src/` and pointed at what was left:
//! four near-copies of these helpers across `sign_structure.rs`,
//! `autofirma_verify.rs`, `xmlsec_crosscheck.rs` and `xml_declaration.rs`,
//! already drifting — two panicking wordings for the same skip, two panic
//! messages for the same broken PKI, and two temp directories with different
//! rules, one of them chosen precisely to rule out a race that the other is
//! still exposed to. One copy, with the better of each decision.
//!
//! The same idiom exists in the sibling crates' tests (`openfirma-cades`,
//! `openfirma-browser`). Sharing it across crates would mean a test-support
//! dev-dependency for all of them, which is a bigger change than the finding
//! asks for and is named here rather than done quietly.
#![allow(dead_code)] // each target imports the few it needs

use std::path::{Path, PathBuf};

use openfirma_core::cert::CertificateHandle;
use openfirma_core::signer::SoftwareSigner;

/// The generated test PKI (`tools/gen-testcert.sh`).
pub fn certs_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/certs")
}

/// A missing tool or a missing test PKI: skip, unless CI said skipping is not
/// allowed. `OPENFIRMA_REQUIRE_TESTS` turns an absence into a failure, and
/// `OPENFIRMA_ALLOW_NONKEYSTORE_SKIP` is the only way out of it — a job whose
/// PKI step could not run sets that, and nothing else relaxes the rule here.
/// The keystore tests have their own flag (`OPENFIRMA_ALLOW_SKIP`, read
/// nowhere else), which is the point: one flag for everything let a broken PKI
/// step go green with nothing verified on macOS and Windows (review 07, H-2).
pub fn require_or_skip(reason: &str) {
    let required = std::env::var("OPENFIRMA_REQUIRE_TESTS").is_ok();
    let allowed = std::env::var("OPENFIRMA_ALLOW_NONKEYSTORE_SKIP").is_ok();
    if required && !allowed {
        panic!("cannot run the test: {reason}");
    }
    eprintln!("skipped, {reason}");
}

/// The software signer a test wants, or `None` when the PKI is not there —
/// `None` goes to [`require_or_skip`], never a silent pass. A file that is
/// present but unusable is a hard failure: silently skipping a broken PKI is
/// how a suite starts testing nothing.
pub fn load_signer(cert: &str, key: &str, chain: &[&str]) -> Option<SoftwareSigner> {
    let dir = certs_dir();
    let (Ok(cert_pem), Ok(key_pem)) = (
        std::fs::read_to_string(dir.join(cert)),
        std::fs::read_to_string(dir.join(key)),
    ) else {
        return None;
    };
    let signer = SoftwareSigner::from_pkcs8_pem(&cert_pem, &key_pem).unwrap_or_else(|e| {
        panic!(
            "{cert} / {key} are present but unusable: {e}. \
             Keys must be PKCS#8 PEM, rerun tools/gen-testcert.sh"
        )
    });
    let handles = chain
        .iter()
        .map(|c| {
            let pem = std::fs::read_to_string(dir.join(c)).unwrap_or_else(|e| {
                panic!("{c} is listed in the test PKI but cannot be read: {e}")
            });
            CertificateHandle::from_pem(&pem)
                .unwrap_or_else(|e| panic!("{c} is not a certificate: {e}"))
        })
        .collect();
    Some(signer.with_chain(handles))
}

/// A file a test hands to another program (`xmlsec1`, AutoFirma's validator).
///
/// Kept in a fixed directory we own and do not delete until the next run:
/// CI's macOS runners showed an external verifier rejecting a freshly written
/// file that our own checks had just passed, which is what a race with
/// per-directory temp cleanup looks like, and a stable path removes that
/// variable from the diagnosis. One subdirectory per test target, from the
/// caller's file name, because cargo runs the targets in parallel and two of
/// them writing the same name into one directory would be the same race with a
/// new address. Tamper tests still clean their own file up right away.
#[track_caller]
pub fn write_tmp(name: &str, bytes: &[u8]) -> PathBuf {
    let caller = std::panic::Location::caller().file();
    let target = caller
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or("crosscheck")
        .trim_end_matches(".rs");
    let dir = std::env::temp_dir()
        .join("openfirma-xades-crosscheck")
        .join(target);
    std::fs::create_dir_all(&dir).unwrap();
    // The pid keeps two concurrent runs of the same binary from writing one
    // another's file over: the name is per *target*, so a green run and a broken
    // one could otherwise read each other's output and agree with the wrong file.
    let path = dir.join(format!("{name}-{}", std::process::id()));
    std::fs::write(&path, bytes).unwrap();
    path
}
