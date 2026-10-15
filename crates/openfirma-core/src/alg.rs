//! Digest, key and signature algorithm identifiers.
//!
//! These are the vocabulary every format crate speaks. Formats never touch a
//! crypto library directly, they ask for a digest and hand it to a
//! [`crate::Signer`].

use const_oid::ObjectIdentifier;
use der::Tag;
use der::asn1::Any;
use spki::AlgorithmIdentifierOwned;

use crate::oid;
use crate::{Error, Result};

/// An `AlgorithmIdentifier` with NULL parameters, which is what RFC 3370
/// requires for the digest algorithms inside CMS, and what AutoFirma emits.
fn ai_with_null(oid: ObjectIdentifier) -> Result<AlgorithmIdentifierOwned> {
    Ok(AlgorithmIdentifierOwned {
        oid,
        parameters: Some(Any::new(Tag::Null, &[][..])?),
    })
}

/// An `AlgorithmIdentifier` with absent parameters, as required for the ECDSA
/// signature algorithms by RFC 5758.
fn ai_no_params(oid: ObjectIdentifier) -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid,
        parameters: None,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DigestAlg {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl DigestAlg {
    pub const fn name(self) -> &'static str {
        match self {
            DigestAlg::Sha1 => "SHA-1",
            DigestAlg::Sha224 => "SHA-224",
            DigestAlg::Sha256 => "SHA-256",
            DigestAlg::Sha384 => "SHA-384",
            DigestAlg::Sha512 => "SHA-512",
        }
    }

    pub const fn oid(self) -> ObjectIdentifier {
        match self {
            DigestAlg::Sha1 => oid::ID_SHA1,
            DigestAlg::Sha224 => oid::ID_SHA224,
            DigestAlg::Sha256 => oid::ID_SHA256,
            DigestAlg::Sha384 => oid::ID_SHA384,
            DigestAlg::Sha512 => oid::ID_SHA512,
        }
    }

    pub const fn output_len(self) -> usize {
        match self {
            DigestAlg::Sha1 => 20,
            DigestAlg::Sha224 => 28,
            DigestAlg::Sha256 => 32,
            DigestAlg::Sha384 => 48,
            DigestAlg::Sha512 => 64,
        }
    }

    pub fn from_oid(oid: &ObjectIdentifier) -> Result<Self> {
        Ok(match *oid {
            x if x == oid::ID_SHA1 => DigestAlg::Sha1,
            x if x == oid::ID_SHA224 => DigestAlg::Sha224,
            x if x == oid::ID_SHA256 => DigestAlg::Sha256,
            x if x == oid::ID_SHA384 => DigestAlg::Sha384,
            x if x == oid::ID_SHA512 => DigestAlg::Sha512,
            other => return Err(Error::UnsupportedDigest(other.to_string())),
        })
    }

    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        use digest::Digest;
        match self {
            DigestAlg::Sha1 => sha1::Sha1::digest(data).to_vec(),
            DigestAlg::Sha224 => sha2::Sha224::digest(data).to_vec(),
            DigestAlg::Sha256 => sha2::Sha256::digest(data).to_vec(),
            DigestAlg::Sha384 => sha2::Sha384::digest(data).to_vec(),
            DigestAlg::Sha512 => sha2::Sha512::digest(data).to_vec(),
        }
    }

    pub fn algorithm_identifier(self) -> Result<AlgorithmIdentifierOwned> {
        ai_with_null(self.oid())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EcCurve {
    P256,
    P384,
    P521,
}

impl EcCurve {
    pub const fn name(self) -> &'static str {
        match self {
            EcCurve::P256 => "prime256v1",
            EcCurve::P384 => "secp384r1",
            EcCurve::P521 => "secp521r1",
        }
    }

    pub const fn oid(self) -> ObjectIdentifier {
        match self {
            EcCurve::P256 => oid::ID_PRIME256V1,
            EcCurve::P384 => oid::ID_SECP384R1,
            EcCurve::P521 => oid::ID_SECP521R1,
        }
    }
}

/// The kind of key behind a certificate. Decided from the SPKI, not from the
/// signature algorithm, because a token signs whatever the key allows.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeyAlgorithm {
    Rsa,
    EcPrimeField(EcCurve),
}

impl KeyAlgorithm {
    pub const fn name(self) -> &'static str {
        match self {
            KeyAlgorithm::Rsa => "RSA",
            KeyAlgorithm::EcPrimeField(c) => c.name(),
        }
    }

    pub fn from_spki_oid(
        alg_oid: &ObjectIdentifier,
        curve: Option<&ObjectIdentifier>,
    ) -> Result<Self> {
        match *alg_oid {
            x if x == oid::ID_RSA_ENCRYPTION || x == oid::ID_RSASSA_PSS => Ok(KeyAlgorithm::Rsa),
            x if x == oid::ID_EC_PUBLIC_KEY => match curve.copied() {
                Some(c) if c == oid::ID_PRIME256V1 => Ok(KeyAlgorithm::EcPrimeField(EcCurve::P256)),
                Some(c) if c == oid::ID_SECP384R1 => Ok(KeyAlgorithm::EcPrimeField(EcCurve::P384)),
                Some(c) if c == oid::ID_SECP521R1 => Ok(KeyAlgorithm::EcPrimeField(EcCurve::P521)),
                Some(other) => Err(Error::UnsupportedKeyAlgorithm(other.to_string())),
                None => Err(Error::UnsupportedKeyAlgorithm(
                    "ecPublicKey without a named curve".into(),
                )),
            },
            other => Err(Error::UnsupportedKeyAlgorithm(other.to_string())),
        }
    }
}

/// The signature algorithm as it goes into `SignerInfo.signatureAlgorithm`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureAlg {
    /// RSASSA-PKCS1-v1_5, the overwhelmingly common case in Spanish PKI.
    RsaPkcs1v15(DigestAlg),
    /// RSASSA-PSS, allowed by PAdES. Params encoding is not implemented yet.
    RsaPss {
        digest: DigestAlg,
        salt_len: usize,
    },
    Ecdsa(DigestAlg),
}

impl SignatureAlg {
    /// Picks the algorithm that a given key and digest imply.
    pub fn for_key(key: KeyAlgorithm, digest: DigestAlg) -> Result<Self> {
        Ok(match key {
            KeyAlgorithm::Rsa => SignatureAlg::RsaPkcs1v15(digest),
            KeyAlgorithm::EcPrimeField(EcCurve::P256) => match digest {
                DigestAlg::Sha256 => SignatureAlg::Ecdsa(DigestAlg::Sha256),
                DigestAlg::Sha1 | DigestAlg::Sha224 => {
                    return Err(Error::UnsupportedCombination {
                        key: key.name(),
                        digest: digest.name(),
                    });
                }
                d => SignatureAlg::Ecdsa(d),
            },
            KeyAlgorithm::EcPrimeField(EcCurve::P384) => match digest {
                DigestAlg::Sha384 => SignatureAlg::Ecdsa(DigestAlg::Sha384),
                DigestAlg::Sha1 | DigestAlg::Sha224 => {
                    return Err(Error::UnsupportedCombination {
                        key: key.name(),
                        digest: digest.name(),
                    });
                }
                d => SignatureAlg::Ecdsa(d),
            },
            KeyAlgorithm::EcPrimeField(EcCurve::P521) => match digest {
                DigestAlg::Sha512 => SignatureAlg::Ecdsa(DigestAlg::Sha512),
                DigestAlg::Sha1 | DigestAlg::Sha224 => {
                    return Err(Error::UnsupportedCombination {
                        key: key.name(),
                        digest: digest.name(),
                    });
                }
                d => SignatureAlg::Ecdsa(d),
            },
        })
    }

    pub fn digest(self) -> DigestAlg {
        match self {
            SignatureAlg::RsaPkcs1v15(d) => d,
            SignatureAlg::RsaPss { digest, .. } => digest,
            SignatureAlg::Ecdsa(d) => d,
        }
    }

    pub fn algorithm_identifier(self) -> Result<AlgorithmIdentifierOwned> {
        let d = self.digest();
        match self {
            SignatureAlg::RsaPkcs1v15(_) => ai_with_null(match d {
                DigestAlg::Sha1 => oid::ID_SHA1_WITH_RSA,
                DigestAlg::Sha224 => oid::ID_SHA224_WITH_RSA,
                DigestAlg::Sha256 => oid::ID_SHA256_WITH_RSA,
                DigestAlg::Sha384 => oid::ID_SHA384_WITH_RSA,
                DigestAlg::Sha512 => oid::ID_SHA512_WITH_RSA,
            }),
            SignatureAlg::Ecdsa(_) => Ok::<_, Error>(ai_no_params(match d {
                DigestAlg::Sha256 => oid::ID_ECDSA_WITH_SHA256,
                DigestAlg::Sha384 => oid::ID_ECDSA_WITH_SHA384,
                DigestAlg::Sha512 => oid::ID_ECDSA_WITH_SHA512,
                DigestAlg::Sha1 => {
                    return Err(Error::UnsupportedCombination {
                        key: "ECDSA",
                        digest: d.name(),
                    });
                }
                DigestAlg::Sha224 => {
                    return Err(Error::UnsupportedCombination {
                        key: "ECDSA",
                        digest: d.name(),
                    });
                }
            })),
            SignatureAlg::RsaPss { .. } => Err(Error::other(
                "RSASSA-PSS AlgorithmIdentifier encoding is not implemented yet",
            )),
        }
    }

    /// The `AlgorithmIdentifier` for `SignerInfo.signatureAlgorithm`.
    ///
    /// RFC 3370 3.1 identifies RSASSA-PKCS1-v1_5 by `rsaEncryption` with NULL
    /// parameters and leaves the digest in `digestAlgorithm`. That is what
    /// BouncyCastle and therefore AutoFirma emit. OpenSSL writes
    /// `sha256WithRSAEncryption` here instead and accepts both, so this is a
    /// difference only the golden diff would have caught.
    pub fn cms_algorithm_identifier(self) -> Result<AlgorithmIdentifierOwned> {
        match self {
            SignatureAlg::RsaPkcs1v15(_) => ai_with_null(oid::ID_RSA_ENCRYPTION),
            other => other.algorithm_identifier(),
        }
    }

    pub fn oid(self) -> Result<ObjectIdentifier> {
        Ok(self.algorithm_identifier()?.oid)
    }
}

impl core::fmt::Display for SignatureAlg {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SignatureAlg::RsaPkcs1v15(d) => write!(f, "RSA-PKCS1-v1_5 with {}", d.name()),
            SignatureAlg::RsaPss { digest, salt_len } => {
                write!(f, "RSA-PSS with {} salt {}", digest.name(), salt_len)
            }
            SignatureAlg::Ecdsa(d) => write!(f, "ECDSA with {}", d.name()),
        }
    }
}
