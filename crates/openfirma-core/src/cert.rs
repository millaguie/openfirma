//! Certificate handle: the raw DER we must reproduce byte for byte inside a
//! signature, plus the parsed form we need to build issuer/serial and to pick
//! algorithms.

use const_oid::ObjectIdentifier;
use der::{Decode, DecodePem, Encode};
use x509_cert::Certificate;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;

use crate::alg::{DigestAlg, KeyAlgorithm};
use crate::{Error, Result};

#[derive(Clone, Debug)]
pub struct CertificateHandle {
    der: Vec<u8>,
    parsed: Certificate,
}

impl CertificateHandle {
    pub fn from_der(der: &[u8]) -> Result<Self> {
        let parsed = Certificate::from_der(der).map_err(|e| Error::Certificate(e.to_string()))?;
        Ok(Self {
            der: der.to_vec(),
            parsed,
        })
    }

    pub fn from_pem(pem: &str) -> Result<Self> {
        let parsed = Certificate::from_pem(pem).map_err(|e| Error::Certificate(e.to_string()))?;
        let der = parsed
            .to_der()
            .map_err(|e| Error::Certificate(format!("re-encoding failed: {e}")))?;
        Ok(Self { der, parsed })
    }

    /// The exact DER bytes, to be embedded in `SignedData.certificates`.
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    pub fn parsed(&self) -> &Certificate {
        &self.parsed
    }

    /// The DER of the SubjectPublicKeyInfo, used to check that a private key
    /// belongs to this certificate.
    pub fn spki_der(&self) -> Result<Vec<u8>> {
        Ok(self
            .parsed
            .tbs_certificate()
            .subject_public_key_info()
            .to_der()?)
    }

    pub fn issuer(&self) -> &Name {
        self.parsed.tbs_certificate().issuer()
    }

    pub fn subject(&self) -> &Name {
        self.parsed.tbs_certificate().subject()
    }

    pub fn serial_number(&self) -> &SerialNumber {
        self.parsed.tbs_certificate().serial_number()
    }

    pub fn key_algorithm(&self) -> Result<KeyAlgorithm> {
        let spki = self.parsed.tbs_certificate().subject_public_key_info();
        // `parameters_oid` only exists on the borrowed form, and the owned one
        // is what x509-cert hands out, so the curve OID is decoded by hand
        let curve = spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|params| ObjectIdentifier::try_from(params.to_ref()).ok());
        KeyAlgorithm::from_spki_oid(&spki.algorithm.oid, curve.as_ref())
    }

    /// Hash of the whole certificate DER, the value that goes into
    /// `signingCertificateV2.certHash`.
    pub fn fingerprint(&self, alg: DigestAlg) -> Vec<u8> {
        alg.digest(&self.der)
    }

    pub fn subject_cn(&self) -> Option<String> {
        self.subject()
            .common_name()
            .ok()
            .flatten()
            .map(String::from)
    }
}
