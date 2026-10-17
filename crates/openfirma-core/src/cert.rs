//! Certificate handle: the raw DER we must reproduce byte for byte inside a
//! signature, plus the parsed form we need to build issuer/serial and to pick
//! algorithms.

use const_oid::ObjectIdentifier;
use der::{Decode, DecodePem, Encode, Tagged};
use x509_cert::Certificate;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;

use crate::alg::{DigestAlg, KeyAlgorithm};
use crate::workflow::decode_directory_string;
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

    /// The subject `Name` exactly as encoded. Name matching in this codebase
    /// is byte level: DER leaves exactly one spelling per name, and the
    /// crates that compare names (chain building, CRL association) do not
    /// all depend on `der`, so the bytes come from here.
    pub fn subject_der(&self) -> Result<Vec<u8>> {
        Ok(self.subject().to_der()?)
    }

    /// The issuer `Name` exactly as encoded, the counterpart of
    /// [`Self::subject_der`].
    pub fn issuer_der(&self) -> Result<Vec<u8>> {
        Ok(self.issuer().to_der()?)
    }

    pub fn serial_number(&self) -> &SerialNumber {
        self.parsed.tbs_certificate().serial_number()
    }

    /// The kind of key plus its concrete parameters (RSA's modulus length,
    /// which decides whether the algorithm policy accepts it).
    pub fn key_info(&self) -> Result<crate::alg::KeyInfo> {
        crate::alg::KeyInfo::from_spki(self.parsed.tbs_certificate().subject_public_key_info())
    }

    pub fn key_algorithm(&self) -> Result<KeyAlgorithm> {
        let spki = self.parsed.tbs_certificate().subject_public_key_info();
        // the owned form x509-cert hands out, decoded by hand for its curve OID
        let curve = spki.algorithm.parameters.as_ref().and_then(|params| {
            let any: der::asn1::AnyRef = params.into();
            ObjectIdentifier::try_from(any).ok()
        });
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

    /// The certificate's keyUsage bits, or `None` when the extension is
    /// absent (or does not parse — an unparsable keyUsage says nothing, and
    /// guessing its contents would be worse than saying nothing).
    pub fn key_usage(&self) -> Option<x509_cert::ext::pkix::KeyUsage> {
        self.parsed()
            .tbs_certificate()
            .extensions()?
            .iter()
            .find(|ext| ext.extn_id.to_string() == "2.5.29.15")
            .and_then(|ext| der::Decode::from_der(ext.extn_value.as_bytes()).ok())
    }

    /// The signing keyUsages RFC 5280 knows: digitalSignature (an ordinary
    /// signature) and nonRepudiation (a qualified one that must be kept).
    pub fn can_sign(&self) -> bool {
        self.key_usage()
            .as_ref()
            .is_none_or(|ku| ku.digital_signature() || ku.non_repudiation())
    }

    /// `true` when the certificate's validity window ended before `now`.
    pub fn expired_at(&self, now: std::time::SystemTime) -> bool {
        self.not_after() < now
    }

    /// The instant the validity window ends (RFC 5280 `notAfter`), as a plain
    /// `SystemTime` so frontends never need the ASN.1 type by name — the GUI's
    /// picker prints "válido hasta" from exactly this value and cannot drift
    /// from what `expired_at` decided (finding A-7).
    pub fn not_after(&self) -> std::time::SystemTime {
        let not_after = self.parsed().tbs_certificate().validity().not_after;
        std::time::SystemTime::from(not_after)
    }

    /// The DNIe's authentication certificate, by the rule AutoFirma applies
    /// (`SkipAuthDNIeFilter`): issued under `cn=AC DNIE *, ou=DNIE,
    /// o=DIRECCION GENERAL DE LA POLICIA, cn=administracion electronica`, and
    /// usable for digitalSignature but not nonRepudiation — the exact shape
    /// of the certificate that sits beside a DNIe's signing pair. Everything
    /// else answers `false`.
    pub fn is_dnie_authentication_cert(&self) -> bool {
        let ku = match self.key_usage() {
            Some(ku) => ku,
            // No keyUsage to tell the two apart: an unflagged DNIe cert keeps
            // AutoFirma's behaviour too (the filter keys on digitalSignature).
            None => x509_cert::ext::pkix::KeyUsage(der::flagset::FlagSet::empty()),
        };
        if !ku.digital_signature() || ku.non_repudiation() {
            return false;
        }
        let issuer = self.issuer();
        issuer_matches_dnie_authority(issuer)
    }
}

/// One attribute of a name whose OID and value match: `(2.5.4.x, contains)`.
fn name_has_attribute(name: &Name, want_oid: &str, needle: &str) -> bool {
    name.iter().any(|atv| {
        atv.oid.to_string() == want_oid && contains_ignore_case(&attribute_value(atv), needle)
    })
}

/// The value of one AttributeTypeAndValue as text: the decoded directory
/// string for the standard types (the same decoder the name formatter uses),
/// and the raw content bytes' lossy text otherwise — a name spelled with
/// something exotic still compares by what it shows.
fn attribute_value(atv: &x509_cert::attr::AttributeTypeAndValue) -> String {
    let tag = atv.value.tag();
    let bytes = atv.value.value();
    // Universal string tags are the single byte itself; anything contextual
    // or exotic falls through to lossy text of the raw value.
    let universal = match tag.class() {
        der::Class::Universal => tag.number().value(),
        _ => 0,
    };
    decode_directory_string(universal as u8, bytes)
        .unwrap_or_else(|| String::from_utf8_lossy(bytes).into())
}

/// Case-insensitive `contains`, because an issuer is spelled with whatever
/// capitalisation the CA happened to use.
fn contains_ignore_case(hay: &str, needle: &str) -> bool {
    hay.to_ascii_lowercase()
        .contains(&needle.to_ascii_lowercase())
}

/// The DNIe issuing authority: every RDN type AutoFirma's
/// `AuthenticationDNIeFilter` compares (CN beginning "AC DNIE", OU "DNIE",
/// O "DIRECCION GENERAL DE LA POLICIA"), case-insensitively. Requiring all
/// three keeps a certificate that merely mentions the police in one field
/// from being hidden by the filter.
fn issuer_matches_dnie_authority(issuer: &Name) -> bool {
    let cn = issuer.iter().any(|atv| {
        atv.oid.to_string() == "2.5.4.3"
            && attribute_value(atv)
                .to_ascii_uppercase()
                .starts_with("AC DNIE")
    });
    cn && name_has_attribute(issuer, "2.5.4.11", "DNIE")
        && name_has_attribute(issuer, "2.5.4.10", "DIRECCION GENERAL DE LA POLICIA")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::{shape_cert, throwaway_key};
    use std::str::FromStr;
    use std::sync::OnceLock;
    use std::time::{Duration, SystemTime};

    /// One 2048-bit generation per test binary is enough for every fixture.
    fn key() -> rsa::RsaPrivateKey {
        static KEY: OnceLock<rsa::RsaPrivateKey> = OnceLock::new();
        KEY.get_or_init(throwaway_key).clone()
    }

    const DNIE_ISSUER: &str =
        "CN=AC DNIE 0000000000,OU=DNIE,O=DIRECCION GENERAL DE LA POLICIA,C=ES";

    /// The Name parser in x509-cert has no room for the spaces an openssl
    /// `-subj` line carries ("CN=x, OU=y"): real certificates never show
    /// that spelling — they carry DER. What must round-trip is Display's own
    /// output, so a name read from any certificate survives a text round trip
    /// through exactly this parser.
    #[test]
    fn the_dnie_issuer_of_a_real_certificate_parses() {
        let name = Name::from_str(DNIE_ISSUER).expect("the DNIe issuer parses");
        let again = Name::from_str(&name.to_string()).expect("Display output parses back");
        assert_eq!(name, again);
    }

    #[test]
    fn dnie_authentication_rule_follows_autofirma() {
        let life = Duration::from_secs(3600);
        let auth = shape_cert(
            "CN=Marta Viajera Garcia",
            DNIE_ISSUER,
            life,
            Some((true, false)),
        );
        assert!(auth.is_dnie_authentication_cert());
        // The signing certificate of the same card: nonRepudiation present.
        let sign = shape_cert(
            "CN=Marta Viajera Garcia",
            DNIE_ISSUER,
            life,
            Some((true, true)),
        );
        assert!(!sign.is_dnie_authentication_cert());
        // Same keyUsage, foreign issuer: not a DNIe at all — and an issuer
        // that merely *mentions* the authority in one field is refused too:
        // the CN must actually begin "AC DNIE", which this one's does not.
        let other = shape_cert(
            "CN=Marta Viajera Garcia",
            "CN=Direccion General de la Policia,OU=Certificacion,C=ES",
            life,
            Some((true, false)),
        );
        assert!(!other.is_dnie_authentication_cert());
        // Capitalisation is the CA's to choose: AC dnie… still matches.
        let lower = shape_cert(
            "CN=Marta Viajera Garcia",
            "CN=ac dnie 0000000000,ou=dnie,o=Direccion General de la Policia,C=ES",
            life,
            Some((true, false)),
        );
        assert!(lower.is_dnie_authentication_cert());
    }

    #[test]
    fn key_usage_and_expiry_read_the_certificate() {
        let life = Duration::from_secs(3600);
        let non_repudiation_only = shape_cert("CN=S", "CN=I", life, Some((false, true)));
        assert!(
            non_repudiation_only.can_sign(),
            "nonRepudiation is a signing usage"
        );
        let auth_only = shape_cert("CN=S", "CN=I", life, Some((true, false)));
        assert!(auth_only.can_sign());
        // A keyEncipherment-only keyUsage must refuse; no keyUsage at all
        // stays admissible (pre-RFC5280 certificates exist).
        let encipher = shape_cert_encipher_only();
        assert!(!encipher.can_sign());
        let unflagged = shape_cert("CN=S", "CN=I", life, None);
        assert!(unflagged.can_sign(), "no keyUsage at all stays admissible");

        let now = SystemTime::now();
        let dead = shape_cert("CN=S", "CN=I", Duration::ZERO, None);
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(dead.expired_at(SystemTime::now()), "not_after has passed");
        assert!(!shape_cert("CN=S", "CN=I", life, None).expired_at(now));
    }

    /// keyUsage = KeyEncipherment alone: `shape_cert` speaks the two signing
    /// usages directly, this one needs the third bit.
    fn shape_cert_encipher_only() -> CertificateHandle {
        use der::{Encode, oid::AssociatedOid};
        use std::str::FromStr;
        use x509_cert::builder::profile::BuilderProfile;
        use x509_cert::builder::{Builder, CertificateBuilder};
        use x509_cert::ext::Extension;
        use x509_cert::ext::pkix::{KeyUsage, KeyUsages};

        struct Profile;
        impl BuilderProfile for Profile {
            fn get_issuer(&self, _s: &Name) -> Name {
                Name::from_str("CN=I").unwrap()
            }
            fn get_subject(&self) -> Name {
                Name::from_str("CN=S").unwrap()
            }
            fn build_extensions(
                &self,
                _spk: x509_cert::spki::SubjectPublicKeyInfoRef<'_>,
                _ik: x509_cert::spki::SubjectPublicKeyInfoRef<'_>,
                _tbs: &x509_cert::TbsCertificate,
            ) -> core::result::Result<Vec<Extension>, x509_cert::builder::Error> {
                let mut bits = der::flagset::FlagSet::<KeyUsages>::empty();
                bits |= KeyUsages::KeyEncipherment;
                let value = KeyUsage(bits).to_der().expect("encode");
                Ok(vec![Extension {
                    extn_id: <KeyUsage as AssociatedOid>::OID,
                    critical: true,
                    extn_value: der::asn1::OctetString::new(value).expect("octets"),
                }])
            }
        }

        let key = key();
        use spki::EncodePublicKey;
        let pub_der = rsa::RsaPublicKey::from(&key)
            .to_public_key_der()
            .expect("pubkey");
        let spki =
            x509_cert::spki::SubjectPublicKeyInfoOwned::from_der(pub_der.as_bytes()).expect("spki");
        let now = std::time::SystemTime::now();
        let signer = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(key);
        let cert = CertificateBuilder::new(
            Profile,
            x509_cert::serial_number::SerialNumber::new(&[7]).expect("serial"),
            x509_cert::time::Validity::new(
                x509_cert::time::Time::try_from(now - Duration::from_secs(60)).unwrap(),
                x509_cert::time::Time::try_from(now + Duration::from_secs(3600)).unwrap(),
            ),
            spki,
        )
        .expect("builder")
        .build::<_, rsa::pkcs1v15::Signature>(&signer)
        .expect("build");
        CertificateHandle::from_der(&cert.to_der().expect("encode")).expect("parses back")
    }
}
