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

enum SoftwareKey {
    Rsa(rsa::RsaPrivateKey),
    P256(p256::ecdsa::SigningKey),
}

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
        }
        KeyMaterial::Der(der) => {
            if let Ok(key) = rsa::RsaPrivateKey::from_pkcs8_der(der) {
                return Ok(SoftwareKey::Rsa(key));
            }
            if let Ok(key) = p256::ecdsa::SigningKey::from_pkcs8_der(der) {
                return Ok(SoftwareKey::P256(key));
            }
        }
    }
    Err(Error::PrivateKey(
        "not a PKCS#8 RSA or EC P-256 private key".into(),
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
