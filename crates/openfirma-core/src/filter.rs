//! The signing-certificate filters every frontend shares (finding A5).
//!
//! AutoFirma hides two kinds of certificate by default: `SkipAuthDNIeFilter`
//! (`skipAuthCertDnie = true`, applied in `afirma-simple`'s `SignPanel`) hides
//! the DNIe's authentication certificate, and `showExpiredCerts = false`
//! hides anything past its expiry. The rules live here — one implementation,
//! read from the certificate itself — so no backend or frontend can offer a
//! login-only card beside a signing card, or a certificate that died years
//! ago, by accident.

use std::sync::Arc;
use std::time::SystemTime;

use crate::CertificateHandle;

/// Whether AutoFirma's default view would hide a certificate carrying `cert`.
pub fn hidden_by_default(cert: &CertificateHandle, now: SystemTime) -> bool {
    cert.expired_at(now) || cert.is_dnie_authentication_cert()
}

/// The DNIe-shaped synthetic pair every filter test shares (the same shapes
/// `tools/setup-test-keystores.sh` writes to the SoftHSM fixture): one
/// certificate with keyUsage digitalSignature alone — AutoFirma's exact
/// authentication rule: AC DNIE issuer and no nonRepudiation — and the same
/// card's signing twin, whose keyUsage adds nonRepudiation. Built at call
/// time over a throwaway RSA key; nothing about them is certificate material
/// of anyone.
pub fn dnie_shaped_pair() -> (CertificateHandle, CertificateHandle) {
    let issuer = "CN=AC DNIE 0000000000,OU=DNIE,O=DIRECCION GENERAL DE LA POLICIA,C=ES";
    let subject = "CN=Marta Viajera Garcia - test";
    (
        shape_cert(
            subject,
            issuer,
            std::time::Duration::from_secs(3600),
            Some((true, false)),
        ),
        shape_cert(
            subject,
            issuer,
            std::time::Duration::from_secs(3600),
            Some((true, true)),
        ),
    )
}

/// A certificate with exactly the asked-for shape: names parsed from RFC
/// 4514 spelling, `not_after` at now+`life`, and a critical keyUsage of
/// (digitalSignature?, nonRepudiation?) — or no keyUsage extension at all.
/// Signed by the throwaway test key below. Test-support code that lives in
/// the library because every crate's filter tests build the same shapes; it
/// is never reachable from openfirma's own signing paths.
pub fn shape_cert(
    subject: &str,
    issuer: &str,
    life: std::time::Duration,
    key_usage: Option<(bool, bool)>,
) -> CertificateHandle {
    use der::{Decode, Encode};
    use std::str::FromStr;
    use std::sync::OnceLock;
    use x509_cert::builder::profile::BuilderProfile;
    use x509_cert::builder::{Builder, CertificateBuilder};
    use x509_cert::ext::pkix::{KeyUsage, KeyUsages};
    use x509_cert::ext::{Extension, ToExtension};
    use x509_cert::name::Name;
    use x509_cert::time::{Time, Validity};

    /// One 2048-bit generation per process is enough for every fixture; RSA
    /// key generation is the slow part of building these shapes.
    fn key() -> rsa::RsaPrivateKey {
        static KEY: OnceLock<rsa::RsaPrivateKey> = OnceLock::new();
        KEY.get_or_init(throwaway_key).clone()
    }

    struct Usage(KeyUsage);
    impl ToExtension for Usage {
        type Error = der::Error;
        fn to_extension(
            self,
            _subject: &Name,
            _extensions: &[Extension],
        ) -> der::Result<Extension> {
            use der::oid::AssociatedOid;
            Ok(Extension {
                extn_id: <KeyUsage as AssociatedOid>::OID,
                critical: true,
                extn_value: der::asn1::OctetString::new(self.0.to_der()?)?,
            })
        }
    }

    struct Shape {
        subject: Name,
        issuer: Name,
        usage: Option<KeyUsage>,
    }
    impl BuilderProfile for Shape {
        fn get_issuer(&self, _subject: &Name) -> Name {
            self.issuer.clone()
        }
        fn get_subject(&self) -> Name {
            self.subject.clone()
        }
        fn build_extensions(
            &self,
            _spk: x509_cert::spki::SubjectPublicKeyInfoRef<'_>,
            _issuer_spk: x509_cert::spki::SubjectPublicKeyInfoRef<'_>,
            _tbs: &x509_cert::TbsCertificate,
        ) -> core::result::Result<Vec<Extension>, x509_cert::builder::Error> {
            match self.usage {
                Some(u) => Usage(u)
                    .to_extension(&self.subject, &[])
                    .map(|e| vec![e])
                    .map_err(x509_cert::builder::Error::Asn1),
                None => Ok(Vec::new()),
            }
        }
    }

    let usage = key_usage.map(|(digital, non_repudiation)| {
        let mut bits = der::flagset::FlagSet::<KeyUsages>::empty();
        if digital {
            bits |= KeyUsages::DigitalSignature;
        }
        if non_repudiation {
            bits |= KeyUsages::NonRepudiation;
        }
        KeyUsage(bits)
    });
    let key = key();
    let now = std::time::SystemTime::now();
    let profile = Shape {
        subject: Name::from_str(subject).expect("subject parses"),
        issuer: Name::from_str(issuer).expect("issuer parses"),
        usage,
    };
    let signer = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(key.clone());
    // The certificate's SPKI must match the signing key or build() would
    // produce a certificate whose public key differs from the one that
    // signed it.
    let spki = {
        use spki::EncodePublicKey;
        let pub_der = rsa::RsaPublicKey::from(&key)
            .to_public_key_der()
            .expect("throwaway public key");
        x509_cert::spki::SubjectPublicKeyInfoOwned::from_der(pub_der.as_bytes())
            .expect("throwaway spki")
    };
    let not_before = Time::try_from(now - std::time::Duration::from_secs(60))
        .or_else(|_| Time::try_from(std::time::SystemTime::UNIX_EPOCH))
        .expect("in DER time range");
    let not_after = Time::try_from(now + life).expect("in DER time range");
    let cert = CertificateBuilder::new(
        profile,
        x509_cert::serial_number::SerialNumber::new(&[7]).expect("serial"),
        Validity::new(not_before, not_after),
        spki,
    )
    .expect("builder")
    .build::<_, rsa::pkcs1v15::Signature>(&signer)
    .expect("build");
    CertificateHandle::from_der(&cert.to_der().expect("encode")).expect("parses back")
}

/// A read-only store view with the default filters applied to its listing.
/// The wrapper exists so every backend is filtered by the same code path at
/// the point a listing leaves the keystore crate; private-key operations pass
/// through untouched — the filter decides what is *offered*, never what a
/// token is allowed to sign.
pub trait CertificateSource: Send + Sync {
    /// Every certificate this view can see, each with its validity and
    /// keyUsage already parsed.
    fn certificates(&self) -> crate::Result<Vec<CertificateHandle>>;
}

/// The [`hidden_by_default`] rule applied to a [`CertificateSource`].
pub struct FilteredView<S: CertificateSource + ?Sized> {
    inner: Arc<S>,
    now: SystemTime,
}

impl<S: CertificateSource + ?Sized> FilteredView<S> {
    pub fn new(inner: Arc<S>, now: SystemTime) -> Self {
        Self { inner, now }
    }

    pub fn certificates(&self) -> crate::Result<Vec<CertificateHandle>> {
        Ok(self
            .inner
            .certificates()?
            .into_iter()
            .filter(|c| !hidden_by_default(c, self.now))
            .collect())
    }
}

/// Build the certificate shapes [`shape_cert`] describes without embedding
/// any key in source: a throwaway RSA key generated with openssl at run time.
/// The fixtures it signs protect nothing and must never be given a
/// certificate that means anything; generating them here keeps private-key
/// text out of the repository (the same rule `tools/check-no-real-certs.sh`
/// enforces for real material applies to fake material too).
pub fn throwaway_key() -> rsa::RsaPrivateKey {
    let out = std::process::Command::new("openssl")
        .args([
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
        ])
        .output()
        .expect("the openssl CLI (the same one tools/gen-testcert.sh needs)");
    assert!(out.status.success(), "openssl genpkey failed: {out:?}");
    use pkcs8::DecodePrivateKey;
    rsa::RsaPrivateKey::from_pkcs8_pem(&String::from_utf8_lossy(&out.stdout))
        .expect("openssl emits a PKCS#8 PEM")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CertificateHandle;
    use std::time::{Duration, SystemTime};

    const PLAIN_CA: &str = "CN=openfirma Test Intermediate CA,O=openfirma test";

    fn alive() -> Duration {
        Duration::from_secs(3600)
    }

    #[test]
    fn the_dnie_authentication_rule_hides_the_login_card_only() {
        let (auth, sign) = dnie_shaped_pair();
        let now = SystemTime::now();
        assert!(hidden_by_default(&auth, now));
        assert!(!hidden_by_default(&sign, now));
    }

    #[test]
    fn expired_certificates_are_hidden_whatever_their_key_usage() {
        let dead = shape_cert("CN=Ana Test", PLAIN_CA, Duration::ZERO, Some((true, true)));
        // Its not_after is `now` (Duration::ZERO); a second later it is past.
        std::thread::sleep(Duration::from_millis(10));
        assert!(hidden_by_default(&dead, SystemTime::now()));
    }

    #[test]
    fn ordinary_certificates_are_never_hidden() {
        let signer = shape_cert("CN=Ana Test", PLAIN_CA, alive(), Some((true, false)));
        let unflagged: CertificateHandle = shape_cert("CN=Ana Test", PLAIN_CA, alive(), None);
        let now = SystemTime::now();
        assert!(!hidden_by_default(&signer, now));
        assert!(!hidden_by_default(&unflagged, now));
    }

    struct Fixed(Vec<CertificateHandle>);
    impl CertificateSource for Fixed {
        fn certificates(&self) -> crate::Result<Vec<CertificateHandle>> {
            Ok(self.0.clone())
        }
    }

    #[test]
    fn the_view_offers_exactly_what_the_rule_keeps() {
        let (auth, sign) = dnie_shaped_pair();
        let view = FilteredView::new(Arc::new(Fixed(vec![auth, sign])), SystemTime::now());
        let certs = view.certificates().expect("listing");
        assert_eq!(certs.len(), 1);
        assert!(!certs[0].is_dnie_authentication_cert());
    }
}
