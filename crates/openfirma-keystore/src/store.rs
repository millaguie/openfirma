//! The boundary between formats and key material held outside a file.
//!
//! A [`SystemStore`] is anything that holds certificates whose private keys
//! never leave their container: a PKCS#11 token, an NSS database, the Windows
//! certificate store, the macOS keychain. AutoFirma reaches all of them through
//! `afirma-core-keystores` (its `AOKeyStore` enum names them: `PKCS11`, `NSS`,
//! `WINDOWS`, `APPLE`); here they implement this trait and nothing else is
//! allowed to know which one it is looking at.
//!
//! The trait deliberately mirrors what a token can do, not what a file does.
//! A token is asked for its certificates, and then asked to sign a digest
//! *with* a certificate — the key is never handed over, only the signature
//! is. That is the entire point of a hardware keystore, so it is also the
//! shape of the interface: there is no method here that returns a private
//! key, and adding one would defeat the crate.
//!
//! The signing half matches [`openfirma_core::signer::Signer::sign_prehash`]
//! exactly — digest already computed, signature bytes back — so a store's
//! certificate can be turned into a `Signer` with [`StoreSigner`] and every
//! format crate keeps working unchanged. See docs/adr/0004-system-keystores.md.

use std::sync::Arc;

use openfirma_core::Result;
use openfirma_core::alg::DigestAlg;
use openfirma_core::cert::CertificateHandle;
use openfirma_core::signer::Signer;

/// A keystore the operating system or a token owns, and whose keys cannot be
/// read out of it.
pub trait SystemStore {
    /// Every certificate in the store that has a private key the store can
    /// sign with, leaf first. Objects without a matching private key are not
    /// returned: they cannot sign, and listing them would let `--store` pick
    /// one and fail later.
    fn certificates(&self) -> Result<Vec<StoreCertificate>>;

    /// Signs an already computed digest with the private key that belongs to
    /// `cert`. Backends map this to whatever their platform calls it: PKCS#11
    /// `C_SignInit`/`C_Sign`, Windows `CryptSignHash`, macOS
    /// `SecKeyCreateSignature`. An unsupported combination of key type and
    /// digest must be refused by name, not attempted.
    fn sign_prehash(
        &self,
        cert: &StoreCertificate,
        alg: DigestAlg,
        prehash: &[u8],
    ) -> Result<Vec<u8>>;
}

/// One certificate a store holds, plus the identity of the private key that
/// travels with it inside the store, and the chain the store itself carries.
#[derive(Clone, Debug)]
pub struct StoreCertificate {
    /// The certificate. Its DER is what goes into `signingCertificateV2`.
    pub cert: CertificateHandle,
    /// The label or alias the store knows this entry by: PKCS#11 `CKA_LABEL`,
    /// the NSS nickname, the Windows friendly name, the keychain label. It is
    /// what a person recognizes when two certificates have the same subject.
    pub label: Option<String>,
    /// The opaque handle `sign_prehash` needs to find the key again: the
    /// PKCS#11 object's `CKA_ID`, the Windows provider handle, the macOS
    /// SecKey reference. Nothing may interpret it but its own backend.
    pub key_handle: KeyHandle,
    /// The key demands a fresh PIN for every signature (PKCS#11
    /// `CKA_ALWAYS_AUTHENTICATE`; other backends report what their platform's
    /// equivalent means). Qualified cards mark their non-repudiation key this
    /// way. Backends honour it themselves at sign time; listing it lets a
    /// picker warn before the document is opened (finding A4).
    pub always_authenticate: bool,
    /// The rest of the chain (intermediates and any root) that the store
    /// carries, for `SignedData.certificates`. A token usually holds only the
    /// leaf; whatever is not there the caller supplies with `--chain` exactly
    /// as it does for `--p12`.
    pub chain: Vec<CertificateHandle>,
}

/// Which private key inside a store a [`StoreCertificate`] can be signed
/// with. Each backend understands only its own variant; seeing another one is
/// a programming error, not a user error.
#[derive(Clone, Debug)]
pub enum KeyHandle {
    /// PKCS#11 `CKA_ID` of the private key object paired with the
    /// certificate. On many tokens (OpenSC/DNIe included) certificate and key
    /// share the same `CKA_ID`, but the pairing is resolved at list time and
    /// only an actually matched key gets this handle.
    Pkcs11Id(Vec<u8>),
    /// Windows: index into the store's cached vector of CSP provider handles,
    /// with the hash algorithm to acquire the key with kept alongside it. The
    /// handle must stay open between acquisition and `CryptSignHash`, so it
    /// is created at sign time by the backend, not cached; what travels here
    /// is only the position of the certificate context in the cache.
    #[cfg(target_os = "windows")]
    WindowsStoreIndex(usize),
    /// macOS: an ASN.1 DER `SEQUENCE { OCTET KEY_ID }` wrapping the keychain
    /// item's `kSecAttrApplicationTag`, as a borrowed-safe way to carry it
    /// between listing and signing within one process (the tag itself is just
    /// bytes, but keeping it in a variant of its own says which backend owns
    /// it).
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    MacApplicationTag(Vec<u8>),
}

/// A [`Signer`] over a store: the bridge that lets `openfirma sign --store`
/// hand a token to the format crates, which only ever talk to `Signer`.
pub struct StoreSigner<'a, S: SystemStore> {
    store: &'a S,
    cert: StoreCertificate,
}

impl<'a, S: SystemStore> StoreSigner<'a, S> {
    pub fn new(store: &'a S, cert: StoreCertificate) -> Self {
        Self { store, cert }
    }

    pub fn store_certificate(&self) -> &StoreCertificate {
        &self.cert
    }
}

impl<S: SystemStore> Signer for StoreSigner<'_, S> {
    fn certificate(&self) -> &CertificateHandle {
        &self.cert.cert
    }

    fn chain(&self) -> &[CertificateHandle] {
        &self.cert.chain
    }

    fn sign_prehash(&self, digest: DigestAlg, prehash: &[u8]) -> openfirma_core::Result<Vec<u8>> {
        // The same length check SoftwareSigner makes, before the round trip
        // into a token: a token that gets a wrong-length digest may accept it
        // and sign something nobody intended.
        let expected = digest.output_len();
        if prehash.len() != expected {
            return Err(openfirma_core::Error::PrehashLength {
                alg: digest.name(),
                expected,
                got: prehash.len(),
            });
        }
        self.store.sign_prehash(&self.cert, digest, prehash)
    }
}

/// A `Signer` over any store, boxed: the CLI holds one `Box<dyn Signer>` for
/// all its sources — files, PKCS#12, every system store — instead of a
/// generic per backend. The dyn boxing has to happen here because the store's
/// own type (`Pkcs11Store`, `WindowsStore`) is only nameable by callers that
/// can see it, and the point of `SystemStore` is that the format crates never
/// do. The store travels behind an `Arc` so it provably outlives the signer.
pub fn boxed_signer(
    store: Arc<dyn SystemStore>,
    cert: StoreCertificate,
) -> Box<dyn Signer + 'static> {
    struct ArcSigner(Arc<dyn SystemStore>, StoreCertificate);
    impl Signer for ArcSigner {
        fn certificate(&self) -> &CertificateHandle {
            &self.1.cert
        }
        fn chain(&self) -> &[CertificateHandle] {
            &self.1.chain
        }
        fn sign_prehash(
            &self,
            digest: DigestAlg,
            prehash: &[u8],
        ) -> openfirma_core::Result<Vec<u8>> {
            // Same length guard `StoreSigner` applies: never let a
            // wrong-length digest reach a token.
            let expected = digest.output_len();
            if prehash.len() != expected {
                return Err(openfirma_core::Error::PrehashLength {
                    alg: digest.name(),
                    expected,
                    got: prehash.len(),
                });
            }
            self.0.sign_prehash(&self.1, digest, prehash)
        }
    }
    Box::new(ArcSigner(store, cert))
}

/// Whether the AutoFirma default view would hide this entry (finding A5) —
/// the shared rule from [`openfirma_core::filter`] lifted to the store entry
/// it decorates. `SkipAuthDNIeFilter` (`skipAuthCertDnie = true`) hides the
/// DNIe's authentication certificate, and `showExpiredCerts = false` hides
/// anything past its expiry. Both rules read the certificate itself, so they
/// apply identically to every backend — which is why they live here rather
/// than in each one. A listing that runs this filter shows exactly what
/// AutoFirma's default configuration would show: nothing less can be assumed
/// by someone comparing the two programs' pickers.
pub fn hidden_by_default(cert: &StoreCertificate, now: std::time::SystemTime) -> bool {
    openfirma_core::filter::hidden_by_default(&cert.cert, now)
}

/// A store whose listing has [`hidden_by_default`] applied. The private key
/// operations pass through untouched: the filter decides what is *offered*,
/// never what the token is allowed to sign — an explicitly named entry (the
/// CLI's `--store-alias`) stays reachable, with a warning.
pub struct FilteredStore {
    inner: std::sync::Arc<dyn SystemStore>,
    now: std::time::SystemTime,
}

impl FilteredStore {
    pub fn new(inner: std::sync::Arc<dyn SystemStore>, now: std::time::SystemTime) -> Self {
        Self { inner, now }
    }
}

// `dyn SystemStore` carries no auto traits of its own, so the wrapper would
// not be Send/Sync without this line — yet every real backend is shared
// through `Arc<dyn SystemStore>` across threads already (the CLI builds that
// very type for its signers in `boxed_signer`), and FilteredStore only ever
// forwards to such an Arc.
unsafe impl Send for FilteredStore {}
unsafe impl Sync for FilteredStore {}

impl SystemStore for FilteredStore {
    fn certificates(&self) -> openfirma_core::Result<Vec<StoreCertificate>> {
        Ok(self
            .inner
            .certificates()?
            .into_iter()
            .filter(|c| !hidden_by_default(c, self.now))
            .collect())
    }

    fn sign_prehash(
        &self,
        cert: &StoreCertificate,
        alg: openfirma_core::alg::DigestAlg,
        prehash: &[u8],
    ) -> openfirma_core::Result<Vec<u8>> {
        self.inner.sign_prehash(cert, alg, prehash)
    }
}

#[cfg(test)]
mod filter_tests {
    use super::*;
    use crate::KeyHandle;
    use openfirma_core::CertificateHandle;
    use openfirma_core::filter::{dnie_shaped_pair, shape_cert};
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};

    fn entry(cert: CertificateHandle, label: &str) -> StoreCertificate {
        StoreCertificate {
            cert,
            label: Some(label.into()),
            key_handle: KeyHandle::Pkcs11Id(vec![1]),
            always_authenticate: false,
            chain: Vec::new(),
        }
    }

    struct Fixed(Vec<StoreCertificate>);
    impl SystemStore for Fixed {
        fn certificates(&self) -> openfirma_core::Result<Vec<StoreCertificate>> {
            Ok(self.0.clone())
        }
        fn sign_prehash(
            &self,
            _cert: &StoreCertificate,
            _alg: openfirma_core::alg::DigestAlg,
            _prehash: &[u8],
        ) -> openfirma_core::Result<Vec<u8>> {
            unreachable!("the filters never sign")
        }
    }

    #[test]
    fn the_dnie_authentication_certificate_is_hidden_and_the_signing_one_shown() {
        // The pair from openfirma-core's shared fixture builder: AutoFirma's
        // exact authentication rule (AC DNIE issuer, digitalSignature alone)
        // beside its nonRepudiation twin.
        let (auth_cert, sign_cert) = dnie_shaped_pair();
        let auth = entry(auth_cert, "CertAutenticacion");
        let sign = entry(sign_cert, "CertFirmaDigital");
        let now = SystemTime::now();
        assert!(hidden_by_default(&auth, now));
        assert!(!hidden_by_default(&sign, now));

        let store = FilteredStore::new(Arc::new(Fixed(vec![auth.clone(), sign.clone()])), now);
        let labels: Vec<_> = store
            .certificates()
            .expect("listing")
            .iter()
            .map(|c| c.label.clone().unwrap_or_default())
            .collect();
        // With the auth certificate out of view, exactly one signer is left:
        // `sign --store …` picks it with no --store-alias and no ambiguity —
        // the behaviour AutoFirma's default shows.
        assert_eq!(labels, ["CertFirmaDigital"]);
    }

    #[test]
    fn an_expired_certificate_is_hidden() {
        let dead = shape_cert(
            "CN=Ana Test",
            "CN=openfirma Test Intermediate CA,O=openfirma test",
            Duration::ZERO,
            Some((true, true)),
        );
        std::thread::sleep(Duration::from_millis(10));
        assert!(hidden_by_default(
            &entry(dead, "caducado"),
            SystemTime::now()
        ));
    }

    #[test]
    fn ordinary_certificates_are_never_hidden() {
        let alive = shape_cert(
            "CN=Ana Test",
            "CN=openfirma Test Intermediate CA,O=openfirma test",
            Duration::from_secs(3600),
            Some((true, false)),
        );
        let unflagged = shape_cert(
            "CN=Ana Test",
            "CN=openfirma Test Intermediate CA,O=openfirma test",
            Duration::from_secs(3600),
            None,
        );
        let now = SystemTime::now();
        assert!(!hidden_by_default(&entry(alive, "ana"), now));
        assert!(!hidden_by_default(&entry(unflagged, "sin keyUsage"), now));
    }
}
