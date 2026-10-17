//! The only interface format crates use to sign.
//!
//! Everything platform or token specific hides behind it. See
//! docs/adr/0002-signer-trait.md.

use pkcs8::DecodePrivateKey;
use signature::SignatureEncoding;
use signature::hazmat::PrehashSigner;
use spki::EncodePublicKey;

use crate::alg::{DigestAlg, SignatureAlg};
use crate::cert::CertificateHandle;
use crate::{Error, Result};

pub trait Signer {
    /// The certificate whose key produces the signature. This is the one that
    /// goes into `signingCertificateV2`.
    fn certificate(&self) -> &CertificateHandle;

    /// The rest of the chain, leaf excluded, for `SignedData.certificates`.
    fn chain(&self) -> &[CertificateHandle];

    fn key_algorithm(&self) -> Result<crate::alg::KeyAlgorithm> {
        self.certificate().key_algorithm()
    }

    /// The signature algorithm implied by this key and the requested digest.
    fn signature_alg(&self, digest: DigestAlg) -> Result<SignatureAlg> {
        SignatureAlg::for_key(self.key_algorithm()?, digest)
    }

    /// Signs an already computed digest. Hardware backends map this to the
    /// token operation, software backends build the DigestInfo themselves.
    fn sign_prehash(&self, digest: DigestAlg, prehash: &[u8]) -> Result<Vec<u8>>;
}

/// A `&dyn Signer` is itself a `Signer`, so a caller that type-erased its
/// signer (`Box<dyn Signer>`, one per source: file, PKCS#12, token) still
/// satisfies the format crates' `S: Signer` bounds without a second box.
impl<S: Signer + ?Sized> Signer for &S {
    fn certificate(&self) -> &CertificateHandle {
        (**self).certificate()
    }

    fn chain(&self) -> &[CertificateHandle] {
        (**self).chain()
    }

    fn key_algorithm(&self) -> Result<crate::alg::KeyAlgorithm> {
        (**self).key_algorithm()
    }

    fn sign_prehash(&self, digest: DigestAlg, prehash: &[u8]) -> Result<Vec<u8>> {
        (**self).sign_prehash(digest, prehash)
    }
}

enum SoftwareKey {
    Rsa(rsa::RsaPrivateKey),
    P256(p256::ecdsa::SigningKey),
    P384(p384::ecdsa::SigningKey),
    P521(p521::ecdsa::SigningKey),
}

/// A signer is the one object that must not leave the private key in freed
/// memory for the next allocation to find. Both backends zeroize themselves
/// on drop in their own crates (`ZeroizeOnDrop`), and this asserts the
/// guarantee at compile time: an upgrade that ever swaps in a key type
/// without it breaks the build instead of quietly dropping the zeroing.
const _: fn() = || {
    fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    assert_zeroize_on_drop::<rsa::RsaPrivateKey>();
    assert_zeroize_on_drop::<p256::ecdsa::SigningKey>();
    assert_zeroize_on_drop::<p384::ecdsa::SigningKey>();
    assert_zeroize_on_drop::<p521::ecdsa::SigningKey>();
};

enum KeyMaterial<'a> {
    Pem(&'a str),
    Der(&'a [u8]),
}

fn parse_key(material: KeyMaterial<'_>) -> Result<SoftwareKey> {
    match material {
        KeyMaterial::Pem(pem) => {
            if let Ok(key) = rsa::RsaPrivateKey::from_pkcs8_pem(pem) {
                return Ok(SoftwareKey::Rsa(key));
            }
            if let Ok(key) = p256::ecdsa::SigningKey::from_pkcs8_pem(pem) {
                return Ok(SoftwareKey::P256(key));
            }
            if let Ok(key) = p384::ecdsa::SigningKey::from_pkcs8_pem(pem) {
                return Ok(SoftwareKey::P384(key));
            }
            if let Ok(key) = p521::ecdsa::SigningKey::from_pkcs8_pem(pem) {
                return Ok(SoftwareKey::P521(key));
            }
        }
        KeyMaterial::Der(der) => {
            if let Ok(key) = rsa::RsaPrivateKey::from_pkcs8_der(der) {
                return Ok(SoftwareKey::Rsa(key));
            }
            if let Ok(key) = p256::ecdsa::SigningKey::from_pkcs8_der(der) {
                return Ok(SoftwareKey::P256(key));
            }
            if let Ok(key) = p384::ecdsa::SigningKey::from_pkcs8_der(der) {
                return Ok(SoftwareKey::P384(key));
            }
            if let Ok(key) = p521::ecdsa::SigningKey::from_pkcs8_der(der) {
                return Ok(SoftwareKey::P521(key));
            }
        }
    }
    Err(Error::PrivateKey(
        "not a PKCS#8 RSA or EC (P-256/P-384/P-521) private key".into(),
    ))
}

/// In process signer over a PKCS#8 key. Used by the CLI for file based
/// certificates and by every test. Real deployments sign through PKCS#11, CNG,
/// the macOS keychain or a smartcard.
pub struct SoftwareSigner {
    cert: CertificateHandle,
    chain: Vec<CertificateHandle>,
    key: SoftwareKey,
}

impl SoftwareSigner {
    pub fn from_pkcs8_pem(cert_pem: &str, key_pem: &str) -> Result<Self> {
        Self::new(
            CertificateHandle::from_pem(cert_pem)?,
            parse_key(KeyMaterial::Pem(key_pem))?,
        )
    }

    pub fn from_pkcs8_der(cert_der: &[u8], key_der: &[u8]) -> Result<Self> {
        Self::new(
            CertificateHandle::from_der(cert_der)?,
            parse_key(KeyMaterial::Der(key_der))?,
        )
    }

    /// Adds the issuing chain that will be embedded in the signature.
    pub fn with_chain(mut self, chain: Vec<CertificateHandle>) -> Self {
        self.chain = chain;
        self
    }

    /// A signer from an already parsed certificate and a PKCS#8 key (DER).
    /// The `from_pkcs8_*` constructors parse the certificate themselves; a
    /// caller that read one through another route (a keystore's DER bytes)
    /// takes this one instead of re-encoding into PEM to feed those.
    pub fn from_certificate_and_pkcs8_der(cert: CertificateHandle, key_der: &[u8]) -> Result<Self> {
        Self::new(cert, parse_key(KeyMaterial::Der(key_der))?)
    }

    /// The public half of a PKCS#8 key as the `SubjectPublicKeyInfo` DER a
    /// certificate carries. Total for every key this crate can sign with —
    /// RSA, P-256, P-384, P-521 — and None for anything else, which lets a
    /// PKCS#12 chain matcher pair keys and certificates without re-signing
    /// anything. (Finding M6 taught the lesson: a hand-written derivation per
    /// curve drifts behind the curve list; this one is the single source.)
    pub fn pkcs8_public_spki(key_pkcs8: &[u8]) -> Option<Vec<u8>> {
        use spki::EncodePublicKey;
        match parse_key(KeyMaterial::Der(key_pkcs8)).ok()? {
            SoftwareKey::Rsa(k) => rsa::RsaPublicKey::from(&k)
                .to_public_key_der()
                .map(|d| d.as_bytes().to_vec())
                .ok(),
            SoftwareKey::P256(k) => k
                .verifying_key()
                .to_public_key_der()
                .map(|d| d.as_bytes().to_vec())
                .ok(),
            SoftwareKey::P384(k) => k
                .verifying_key()
                .to_public_key_der()
                .map(|d| d.as_bytes().to_vec())
                .ok(),
            SoftwareKey::P521(k) => k
                .verifying_key()
                .to_public_key_der()
                .map(|d| d.as_bytes().to_vec())
                .ok(),
        }
    }

    fn new(cert: CertificateHandle, key: SoftwareKey) -> Result<Self> {
        // Reject a mismatched key here. Otherwise the failure shows up much
        // later, in a validator, with no clue about the cause.
        let cert_spki = cert.spki_der()?;
        let matches = match &key {
            SoftwareKey::Rsa(priv_key) => rsa::RsaPublicKey::from(priv_key)
                .to_public_key_der()
                .map(|d| d.as_bytes() == cert_spki)
                .unwrap_or(false),
            SoftwareKey::P256(priv_key) => priv_key
                .verifying_key()
                .to_public_key_der()
                .map(|d| d.as_bytes() == cert_spki)
                .unwrap_or(false),
            SoftwareKey::P384(priv_key) => priv_key
                .verifying_key()
                .to_public_key_der()
                .map(|d| d.as_bytes() == cert_spki)
                .unwrap_or(false),
            SoftwareKey::P521(priv_key) => priv_key
                .verifying_key()
                .to_public_key_der()
                .map(|d| d.as_bytes() == cert_spki)
                .unwrap_or(false),
        };
        if !matches {
            return Err(Error::PrivateKey(
                "the private key does not match the certificate public key".into(),
            ));
        }

        Ok(Self {
            cert,
            chain: Vec::new(),
            key,
        })
    }
}

impl Signer for SoftwareSigner {
    fn certificate(&self) -> &CertificateHandle {
        &self.cert
    }

    fn chain(&self) -> &[CertificateHandle] {
        &self.chain
    }

    fn sign_prehash(&self, digest: DigestAlg, prehash: &[u8]) -> Result<Vec<u8>> {
        let expected = digest.output_len();
        if prehash.len() != expected {
            return Err(Error::PrehashLength {
                alg: digest.name(),
                expected,
                got: prehash.len(),
            });
        }
        match &self.key {
            SoftwareKey::Rsa(key) => rsa_sign_prehash(key, digest, prehash),
            SoftwareKey::P256(key) => {
                // P-256 pairs with SHA-256 in every profile we target
                if !matches!(digest, DigestAlg::Sha256) {
                    return Err(Error::UnsupportedCombination {
                        key: "prime256v1",
                        digest: digest.name(),
                    });
                }
                let sig: p256::ecdsa::Signature = key
                    .sign_prehash(prehash)
                    .map_err(|e| Error::Signing(e.to_string()))?;
                // CMS carries ECDSA signatures DER encoded, not as raw r||s
                Ok(sig.to_der().as_bytes().to_vec())
            }
            SoftwareKey::P384(key) => {
                if !matches!(digest, DigestAlg::Sha384) {
                    return Err(Error::UnsupportedCombination {
                        key: "secp384r1",
                        digest: digest.name(),
                    });
                }
                let sig: p384::ecdsa::Signature = key
                    .sign_prehash(prehash)
                    .map_err(|e| Error::Signing(e.to_string()))?;
                Ok(sig.to_der().as_bytes().to_vec())
            }
            SoftwareKey::P521(key) => {
                if !matches!(digest, DigestAlg::Sha512) {
                    return Err(Error::UnsupportedCombination {
                        key: "secp521r1",
                        digest: digest.name(),
                    });
                }
                let sig: p521::ecdsa::Signature = key
                    .sign_prehash(prehash)
                    .map_err(|e| Error::Signing(e.to_string()))?;
                Ok(sig.to_der().as_bytes().to_vec())
            }
        }
    }
}

fn rsa_sign_prehash(
    key: &rsa::RsaPrivateKey,
    digest: DigestAlg,
    prehash: &[u8],
) -> Result<Vec<u8>> {
    use rsa::pkcs1v15::SigningKey;
    macro_rules! sign_with {
        ($ty:ty) => {{
            let signing_key = SigningKey::<$ty>::new(key.clone());
            let sig: rsa::pkcs1v15::Signature = signing_key
                .sign_prehash(prehash)
                .map_err(|e| Error::Signing(e.to_string()))?;
            Ok(sig.to_vec())
        }};
    }
    match digest {
        DigestAlg::Sha1 => sign_with!(sha1::Sha1),
        DigestAlg::Sha224 => sign_with!(sha2::Sha224),
        DigestAlg::Sha256 => sign_with!(sha2::Sha256),
        DigestAlg::Sha384 => sign_with!(sha2::Sha384),
        DigestAlg::Sha512 => sign_with!(sha2::Sha512),
    }
}

/// Verifies an already computed digest signature under a certificate's public
/// key: the verification counterpart of [`Signer::sign_prehash`], and the only
/// place where public key crypto lives outside the `Signer` backends. The
/// `Signer` trait stays the only home of key material for *signing*; a
/// verifier never holds a private key, it holds certificates.
///
/// Supported: RSA PKCS#1 v1.5 and ECDSA over P-256, P-384 and P-521, each
/// over SHA-1/256/384/512 (RSA also SHA-224). The digest is named explicitly,
/// exactly like on the signing side, because that is what CMS carries:
/// `digestAlgorithm` in the `SignerInfo` and, for RSA PKCS#1 v1.5, inside the
/// DigestInfo the signature recovers. Algorithm *strength* is not this
/// function's decision — see `openfirma_cades::verify::AlgorithmPolicy`,
/// which refuses SHA-1 and short RSA keys before anything reaches here.
/// The RSA modulus length, in bits, below which nothing signs that anyone
/// should trust: 2048 is the floor of ETSI TS 119 312's conservative policy
/// and of every CA/B baseline since. Lives here because both sides of the
/// door need the same number — the signing side would refuse to produce such
/// a signature before its digest gets refused, and the verifying side
/// (`openfirma_cades::verify::AlgorithmPolicy`) refuses one. It is a policy
/// constant, not an arithmetic limit: the crypto itself has no opinion.
pub const RSA_MINIMUM_BITS: usize = 2048;

pub fn verify_prehash(
    cert: &CertificateHandle,
    digest: DigestAlg,
    prehash: &[u8],
    signature: &[u8],
) -> Result<()> {
    use crate::alg::{EcCurve, KeyAlgorithm};
    use signature::hazmat::PrehashVerifier;
    use spki::DecodePublicKey;

    let expected = digest.output_len();
    if prehash.len() != expected {
        return Err(Error::PrehashLength {
            alg: digest.name(),
            expected,
            got: prehash.len(),
        });
    }
    let spki_der = cert.spki_der()?;
    match cert.key_algorithm()? {
        KeyAlgorithm::Rsa => {
            let key = rsa::RsaPublicKey::from_public_key_der(&spki_der).map_err(|e| {
                Error::Certificate(format!("the certificate carries no readable RSA key: {e}"))
            })?;
            let sig = rsa::pkcs1v15::Signature::try_from(signature)
                .map_err(|e| Error::Verification(format!("unreadable RSA signature: {e}")))?;
            macro_rules! verify_with {
                ($ty:ty) => {{
                    rsa::pkcs1v15::VerifyingKey::<$ty>::new(key)
                        .verify_prehash(prehash, &sig)
                        .map_err(|e| {
                            Error::Verification(format!("the signature does not verify: {e}"))
                        })
                }};
            }
            match digest {
                DigestAlg::Sha1 => verify_with!(sha1::Sha1),
                DigestAlg::Sha224 => verify_with!(sha2::Sha224),
                DigestAlg::Sha256 => verify_with!(sha2::Sha256),
                DigestAlg::Sha384 => verify_with!(sha2::Sha384),
                DigestAlg::Sha512 => verify_with!(sha2::Sha512),
            }
        }
        KeyAlgorithm::EcPrimeField(EcCurve::P256) => {
            let key = p256::PublicKey::from_public_key_der(&spki_der).map_err(|e| {
                Error::Certificate(format!(
                    "the certificate carries no readable P-256 key: {e}"
                ))
            })?;
            let sig = p256::ecdsa::Signature::from_der(signature)
                .map_err(|e| Error::Verification(format!("the ECDSA signature is not DER: {e}")))?;
            p256::ecdsa::VerifyingKey::from(key)
                .verify_prehash(prehash, &sig)
                .map_err(|e| Error::Verification(format!("the signature does not verify: {e}")))
        }
        // P-384 and P-521 join P-256 (finding M6): several European roots and
        // CAs are P-384, so refusing them is refusing the chain of real
        // certificates. Same pattern, same DER signature encoding; p384/p521
        // are RustCrypto's own crates of the same generation as p256.
        KeyAlgorithm::EcPrimeField(EcCurve::P384) => {
            let key = p384::PublicKey::from_public_key_der(&spki_der).map_err(|e| {
                Error::Certificate(format!(
                    "the certificate carries no readable P-384 key: {e}"
                ))
            })?;
            let sig = p384::ecdsa::Signature::from_der(signature)
                .map_err(|e| Error::Verification(format!("the ECDSA signature is not DER: {e}")))?;
            p384::ecdsa::VerifyingKey::from(key)
                .verify_prehash(prehash, &sig)
                .map_err(|e| Error::Verification(format!("the signature does not verify: {e}")))
        }
        KeyAlgorithm::EcPrimeField(EcCurve::P521) => {
            let key = p521::PublicKey::from_public_key_der(&spki_der).map_err(|e| {
                Error::Certificate(format!(
                    "the certificate carries no readable P-521 key: {e}"
                ))
            })?;
            let sig = p521::ecdsa::Signature::from_der(signature)
                .map_err(|e| Error::Verification(format!("the ECDSA signature is not DER: {e}")))?;
            p521::ecdsa::VerifyingKey::from(key)
                .verify_prehash(prehash, &sig)
                .map_err(|e| Error::Verification(format!("the signature does not verify: {e}")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pkcs8::DecodePrivateKey;
    use signature::hazmat::PrehashSigner;

    /// Same rule as the integration tests: skip when the throwaway PKI has not
    /// been generated, but fail the build when CI asked for the tests to run.
    fn require_or_skip(reason: &str) {
        let required = std::env::var("OPENFIRMA_REQUIRE_TESTS").is_ok();
        let allowed = std::env::var("OPENFIRMA_ALLOW_SKIP").is_ok();
        if required && !allowed {
            panic!("cannot run the test: {reason}");
        }
        eprintln!("skipped, {reason}");
    }

    fn certs_dir() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/certs")
    }

    /// The requirement is RSA PKCS#1 v1.5 and ECDSA P-256, each over
    /// SHA-1/256/384/512 (RSA also SHA-224, which the signing side supports).
    /// The signing half of this test goes directly to the crypto crates rather
    /// than through `SoftwareSigner`, whose P-256 backend deliberately pairs
    /// with SHA-256 only: verification must accept what other implementations
    /// produce, not only what we would sign ourselves.
    #[test]
    fn verify_prehash_covers_the_required_key_and_digest_combinations() {
        let dir = certs_dir();
        let (Ok(rsa_cert), Ok(rsa_key), Ok(ec_cert), Ok(ec_key)) = (
            std::fs::read(dir.join("signer-rsa.crt.der")),
            std::fs::read_to_string(dir.join("signer-rsa.key")),
            std::fs::read(dir.join("signer-ec.crt.der")),
            std::fs::read_to_string(dir.join("signer-ec.key")),
        ) else {
            require_or_skip("test PKI missing, run tools/gen-testcert.sh");
            return;
        };
        let rsa_cert = CertificateHandle::from_der(&rsa_cert).expect("signer-rsa.crt.der");
        let rsa_key =
            rsa::RsaPrivateKey::from_pkcs8_pem(&rsa_key).expect("signer-rsa.key must be PKCS#8");
        let ec_cert = CertificateHandle::from_der(&ec_cert).expect("signer-ec.crt.der");
        let ec_key =
            p256::ecdsa::SigningKey::from_pkcs8_pem(&ec_key).expect("signer-ec.key must be PKCS#8");

        macro_rules! rsa_round_trip {
            ($digest:expr, $ty:ty) => {{
                let d = $digest;
                let prehash = d.digest(b"the message");
                let sig: rsa::pkcs1v15::Signature =
                    rsa::pkcs1v15::SigningKey::<$ty>::new(rsa_key.clone())
                        .sign_prehash(&prehash)
                        .expect("rsa sign_prehash");
                verify_prehash(&rsa_cert, d, &prehash, &sig.to_vec())
                    .unwrap_or_else(|e| panic!("RSA {}: {e}", d.name()));
                // a digest of a different message must not verify
                let other = d.digest(b"another message");
                assert!(
                    verify_prehash(&rsa_cert, d, &other, &sig.to_vec()).is_err(),
                    "RSA {} verified the wrong digest",
                    d.name()
                );
            }};
        }
        rsa_round_trip!(DigestAlg::Sha1, sha1::Sha1);
        rsa_round_trip!(DigestAlg::Sha224, sha2::Sha224);
        rsa_round_trip!(DigestAlg::Sha256, sha2::Sha256);
        rsa_round_trip!(DigestAlg::Sha384, sha2::Sha384);
        rsa_round_trip!(DigestAlg::Sha512, sha2::Sha512);

        for digest in [
            DigestAlg::Sha1,
            DigestAlg::Sha256,
            DigestAlg::Sha384,
            DigestAlg::Sha512,
        ] {
            let prehash = digest.digest(b"the message");
            let sig: p256::ecdsa::Signature = ec_key
                .sign_prehash(&prehash)
                .expect("p256 sign_prehash accepts any prehash length");
            let der = sig.to_der();
            verify_prehash(&ec_cert, digest, &prehash, der.as_bytes())
                .unwrap_or_else(|e| panic!("ECDSA P-256 {}: {e}", digest.name()));
            let other = digest.digest(b"another message");
            assert!(
                verify_prehash(&ec_cert, digest, &other, der.as_bytes()).is_err(),
                "ECDSA P-256 {} verified the wrong digest",
                digest.name()
            );
        }
    }

    #[test]
    fn verify_prehash_rejects_a_wrong_length_prehash() {
        let dir = certs_dir();
        let Ok(der) = std::fs::read(dir.join("signer-rsa.crt.der")) else {
            require_or_skip("test PKI missing, run tools/gen-testcert.sh");
            return;
        };
        let cert = CertificateHandle::from_der(&der).expect("signer-rsa.crt.der");
        let err = verify_prehash(&cert, DigestAlg::Sha256, &[0u8; 31], &[0u8; 256]).unwrap_err();
        assert!(
            matches!(
                err,
                Error::PrehashLength {
                    expected: 32,
                    got: 31,
                    ..
                }
            ),
            "unexpected error: {err}"
        );
    }
}
