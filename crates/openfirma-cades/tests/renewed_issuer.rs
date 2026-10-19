//! A renewed CA certificate must not hide the one that still works.
//!
//! Round two's N11: while walking the chain, `build_chain_refs` asked each
//! candidate with the issuer's name to verify the signature, and the first one
//! whose key did was then run through `check_validity` and
//! `check_certificate_rules` with `?`. Those two checks are about the
//! certificate, but their failure ended the whole search, so a pool holding the
//! expired copy of a CA next to the current one refused the chain whenever the
//! expired copy happened to come first — a false refusal about ordering, not
//! about trust.
//!
//! This matters because renewed CA certificates keep their subject *and their
//! key*: that is what makes a renewal painless for everyone below. The pair
//! therefore verifies the same child signature, which is exactly the case the
//! old code could not tell apart. openssl's `-untrusted` pools routinely carry
//! both, and so does a `/DSS` archive that grew over the years.
//!
//! A renewed pair cannot be conjured out of `testdata/certs`, which holds one
//! certificate per name, so this file mints its own: one CSR, one key, two
//! certificates from the test root — one valid from three years ago to
//! yesterday, one current — and a leaf issued under that key. Everything lands
//! in a scratch directory, including the serial file (`-CAcreateserial` would
//! otherwise write into `testdata/certs`, where parallel tests race it).

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

use der::{Encode as _, asn1::GeneralizedTime};
use openfirma_cades::verify::chain_certificates;
use openfirma_core::cert::CertificateHandle;

fn certs_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/certs")
}

/// CI sets OPENFIRMA_REQUIRE_TESTS so a missing tool or PKI fails the build
/// instead of quietly skipping; OPENFIRMA_ALLOW_NONKEYSTORE_SKIP is the only way
/// out and is what a job whose PKI step could not run sets (review 07, H-2).
fn require_or_skip(reason: &str) {
    if std::env::var("OPENFIRMA_REQUIRE_TESTS").is_ok()
        && std::env::var("OPENFIRMA_ALLOW_NONKEYSTORE_SKIP").is_err()
    {
        panic!("cannot run the test: {reason}");
    }
    eprintln!("skipped, {reason}");
}

fn run(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .output()
        .is_ok_and(|o| o.status.success())
}

fn load(path: &Path) -> CertificateHandle {
    let pem = std::fs::read_to_string(path).expect("a certificate just written");
    CertificateHandle::from_pem(&pem).expect("the certificate openssl wrote is PEM")
}

/// `CCYYMMDDHHMMSSZ`, the shape openssl's `-not_before` and `-not_after` want.
fn openssl_date(when: SystemTime) -> String {
    let der = GeneralizedTime::from_system_time(when)
        .expect("in range")
        .to_der()
        .expect("it encodes");
    String::from_utf8_lossy(&der[2..]).to_string()
}

/// The three pieces: the expired and current copies of one intermediate (same
/// subject, same key, both issued by the test root) and a leaf issued under that
/// key.
struct Pair {
    scratch: PathBuf,
    root: CertificateHandle,
    expired: CertificateHandle,
    current: CertificateHandle,
    leaf: CertificateHandle,
}

fn mint(tag: &str) -> Option<Pair> {
    let root_dir = certs_dir();
    if !root_dir.join("ca.key").is_file() {
        return None;
    }
    let scratch =
        std::env::temp_dir().join(format!("openfirma-renewed-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&scratch).ok()?;

    let ca_crt = root_dir.join("ca.crt");
    let ca_key = root_dir.join("ca.key");
    let ca_srl = scratch.join("ca.srl");

    // one key, one request: the two certificates differ only in their dates
    let int_key = scratch.join("int.key");
    let int_csr = scratch.join("int.csr");
    if !run(
        "openssl",
        &[
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            int_key.to_str()?,
            "-out",
            int_csr.to_str()?,
            "-subj",
            "/CN=openfirma Renewing Test Intermediate CA/O=openfirma test/C=ES",
        ],
    ) {
        return None;
    }
    let ext = scratch.join("ca.ext");
    std::fs::write(
        &ext,
        "basicConstraints = critical, CA:TRUE\nkeyUsage = critical, keyCertSign, cRLSign\n\
         subjectKeyIdentifier = hash\n",
    )
    .ok()?;

    let now = SystemTime::now();
    let expired = scratch.join("int-old.crt");
    let current = scratch.join("int-new.crt");
    // the expired copy: valid from three years ago until yesterday
    if !run(
        "openssl",
        &[
            "x509",
            "-req",
            "-in",
            int_csr.to_str()?,
            "-CA",
            ca_crt.to_str()?,
            "-CAkey",
            ca_key.to_str()?,
            "-CAcreateserial",
            "-CAserial",
            ca_srl.to_str()?,
            "-extfile",
            ext.to_str()?,
            "-not_before",
            &openssl_date(now - Duration::from_secs(3 * 365 * 86_400)),
            "-not_after",
            &openssl_date(now - Duration::from_secs(86_400)),
            "-out",
            expired.to_str()?,
        ],
    ) {
        return None;
    }
    // and the current copy of the very same request, same subject and same key
    if !run(
        "openssl",
        &[
            "x509",
            "-req",
            "-in",
            int_csr.to_str()?,
            "-CA",
            ca_crt.to_str()?,
            "-CAkey",
            ca_key.to_str()?,
            "-CAcreateserial",
            "-CAserial",
            ca_srl.to_str()?,
            "-extfile",
            ext.to_str()?,
            "-days",
            "400",
            "-out",
            current.to_str()?,
        ],
    ) {
        return None;
    }

    // a leaf under that key, so both copies really are its issuer
    let leaf_key = scratch.join("leaf.key");
    let leaf_csr = scratch.join("leaf.csr");
    if !run(
        "openssl",
        &[
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            leaf_key.to_str()?,
            "-out",
            leaf_csr.to_str()?,
            "-subj",
            "/CN=openfirma Renewed Leaf/O=openfirma test/C=ES",
        ],
    ) {
        return None;
    }
    let leaf_ext = scratch.join("leaf.ext");
    std::fs::write(
        &leaf_ext,
        "basicConstraints = critical, CA:FALSE\nkeyUsage = critical, digitalSignature, \
         nonRepudiation\nsubjectKeyIdentifier = hash\n",
    )
    .ok()?;
    let leaf_crt = scratch.join("leaf.crt");
    if !run(
        "openssl",
        &[
            "x509",
            "-req",
            "-in",
            leaf_csr.to_str()?,
            "-CA",
            current.to_str()?,
            "-CAkey",
            int_key.to_str()?,
            "-CAcreateserial",
            "-days",
            "400",
            "-extfile",
            leaf_ext.to_str()?,
            "-out",
            leaf_crt.to_str()?,
        ],
    ) {
        return None;
    }

    Some(Pair {
        scratch,
        root: load(&ca_crt),
        expired: load(&expired),
        current: load(&current),
        leaf: load(&leaf_crt),
    })
}

/// The whole point: with the expired copy first in the pool, the chain still
/// reaches the root through the current one.
#[test]
fn an_expired_copy_of_the_issuing_ca_does_not_end_the_search() {
    let Some(pair) = mint("chain") else {
        require_or_skip("openssl or the test root key is unavailable");
        return;
    };
    let at = SystemTime::now();
    let anchors = [pair.root.clone()];

    for (order, pool) in [
        (
            "expired first",
            vec![pair.expired.clone(), pair.current.clone()],
        ),
        (
            "current first",
            vec![pair.current.clone(), pair.expired.clone()],
        ),
    ] {
        let chain = chain_certificates(&pair.leaf, &pool, &anchors, at)
            .unwrap_or_else(|e| panic!("the chain must build with the {order} copy: {e}"));
        assert_eq!(chain.len(), 3, "leaf, intermediate, root: {chain:?}");
        assert_eq!(
            chain[1].der(),
            pair.current.der(),
            "the link used must be the certificate that is valid, not the expired one with \
             the same name and key"
        );
        assert_eq!(chain[2].der(), pair.root.der(), "and it stands on the root");
    }

    std::fs::remove_dir_all(&pair.scratch).ok();
}

/// The refusal survives where there is nothing else to try: an archive that
/// carries only the expired copy is still refused, and now says why in terms of
/// the candidate rather than pretending nobody signed it.
#[test]
fn a_pool_with_only_the_expired_copy_is_still_refused() {
    let Some(pair) = mint("refusal") else {
        require_or_skip("openssl or the test root key is unavailable");
        return;
    };
    let at = SystemTime::now();
    let err = chain_certificates(
        &pair.leaf,
        std::slice::from_ref(&pair.expired),
        std::slice::from_ref(&pair.root),
        at,
    )
    .expect_err(
        "an expired issuer is still an expired issuer, with or without a better candidate around",
    )
    .to_string();
    assert!(
        err.contains("cannot stand as its issuer"),
        "the refusal must say the candidate verified and could not stand: {err}"
    );
    assert!(
        err.contains("not valid at"),
        "and it must carry the reason the candidate failed: {err}"
    );

    std::fs::remove_dir_all(&pair.scratch).ok();
}

/// A trust store that holds an expired root and its renewal: the anchor loop is
/// the one that has to move on, because a renewed self-signed root is a different
/// DER value under the same name and key, and the anchors are consulted before
/// anything else. This is what `openssl verify -trusted` is handed when somebody
/// leaves the old copy in the bundle.
#[test]
fn a_trust_store_with_an_expired_root_and_its_renewal_still_builds() {
    let root_dir = certs_dir();
    if !root_dir.join("ca.crt").is_file() {
        require_or_skip("the test PKI is missing, run tools/gen-testcert.sh");
        return;
    }
    let scratch =
        std::env::temp_dir().join(format!("openfirma-renewed-store-{}", std::process::id()));
    std::fs::create_dir_all(&scratch).unwrap();
    let key = scratch.join("root.key");
    let csr = scratch.join("root.csr");
    if !run(
        "openssl",
        &[
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            key.to_str().unwrap(),
            "-out",
            csr.to_str().unwrap(),
            "-subj",
            "/CN=openfirma Renewing Test Root/O=openfirma test/C=ES",
        ],
    ) {
        require_or_skip("openssl could not generate the root's key");
        return;
    }
    let ext = scratch.join("root.ext");
    std::fs::write(
        &ext,
        "basicConstraints = critical, CA:TRUE\nkeyUsage = critical, keyCertSign, cRLSign\n\
         subjectKeyIdentifier = hash\n",
    )
    .unwrap();
    let now = SystemTime::now();
    let expired = scratch.join("root-old.crt");
    let current = scratch.join("root-new.crt");
    let selfsign = |out: &Path, extra: &[&str]| {
        let mut args = vec![
            "x509",
            "-req",
            "-in",
            csr.to_str().unwrap(),
            "-signkey",
            key.to_str().unwrap(),
            "-extfile",
            ext.to_str().unwrap(),
        ];
        args.extend_from_slice(extra);
        args.push("-out");
        args.push(out.to_str().unwrap());
        run("openssl", &args)
    };
    let old_dates = [
        "-not_before".to_string(),
        openssl_date(now - Duration::from_secs(6 * 365 * 86_400)),
        "-not_after".to_string(),
        openssl_date(now - Duration::from_secs(86_400)),
    ];
    let new_dates = ["-days".to_string(), "400".to_string()];
    let ok = selfsign(
        &expired,
        &old_dates.iter().map(String::as_str).collect::<Vec<_>>(),
    ) && selfsign(
        &current,
        &new_dates.iter().map(String::as_str).collect::<Vec<_>>(),
    );
    if !ok {
        require_or_skip("openssl could not self-sign the pair of roots");
        std::fs::remove_dir_all(&scratch).ok();
        return;
    }

    // a leaf issued under that key by the current copy
    let leaf_key = scratch.join("leaf.key");
    let leaf_csr = scratch.join("leaf.csr");
    let leaf_crt = scratch.join("leaf.crt");
    let leaf_ext = scratch.join("leaf.ext");
    std::fs::write(
        &leaf_ext,
        "basicConstraints = critical, CA:FALSE\nkeyUsage = critical, digitalSignature, \
         nonRepudiation\n",
    )
    .unwrap();
    let minted = run(
        "openssl",
        &[
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            leaf_key.to_str().unwrap(),
            "-out",
            leaf_csr.to_str().unwrap(),
            "-subj",
            "/CN=openfirma Leaf under a renewed root/O=openfirma test/C=ES",
        ],
    ) && run(
        "openssl",
        &[
            "x509",
            "-req",
            "-in",
            leaf_csr.to_str().unwrap(),
            "-CA",
            current.to_str().unwrap(),
            "-CAkey",
            key.to_str().unwrap(),
            "-CAcreateserial",
            "-days",
            "400",
            "-extfile",
            leaf_ext.to_str().unwrap(),
            "-out",
            leaf_crt.to_str().unwrap(),
        ],
    );
    if !minted {
        require_or_skip("openssl could not issue the leaf");
        std::fs::remove_dir_all(&scratch).ok();
        return;
    }

    let expired = load(&expired);
    let current = load(&current);
    let leaf = load(&leaf_crt);
    // the expired root first, as a bundle accumulated over the years would have
    let chain = chain_certificates(
        &leaf,
        &[],
        &[expired.clone(), current.clone()],
        SystemTime::now(),
    )
    .expect("the store's second root is the same CA and is valid: refusing the first must not refuse the chain");
    assert_eq!(chain.len(), 2, "leaf and the root that stands: {chain:?}");
    assert_eq!(chain[1].der(), current.der(), "the valid copy stands");

    std::fs::remove_dir_all(&scratch).ok();
}
