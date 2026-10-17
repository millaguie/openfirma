//! The thin bridge to `openfirma-keystore`: opening descriptors and loading
//! containers with exactly the code paths `openfirma sign` runs, so the two
//! frontends' key sources are one implementation (the brief's rule: never a
//! second one). This module owns nothing: it opens what the keystore crate
//! opens and hands the same types back.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use openfirma_core::workflow::StoreSpec;
use openfirma_core::{CertificateHandle, Error, Result};
use openfirma_keystore::{Pkcs12, StoreCertificate, SystemStore};
use zeroize::Zeroizing;

/// Open a store descriptor behind one `Arc<dyn SystemStore>`. The work lives
/// in openfirma-keystore's [`openfirma_keystore::open_store`] — the CLI's
/// `--store` runs the same function (finding B8), so the two frontends' key
/// sources cannot drift. This thin wrapper only keeps the GUI's import list
/// pointing at its own bridge module.
pub fn open_store(
    spec: &StoreSpec,
    pin: Option<Zeroizing<String>>,
) -> Result<Arc<dyn SystemStore>> {
    openfirma_keystore::open_store(spec, pin)
}

/// Read a certificate from PEM or DER bytes (the CLI's loader, verbatim in
/// rule): used for trust anchors and for reading a PKCS#12 leaf.
pub fn parse_certificate(bytes: &[u8]) -> Result<CertificateHandle> {
    if bytes.starts_with(b"-----BEGIN") {
        CertificateHandle::from_pem(
            std::str::from_utf8(bytes)
                .map_err(|e| Error::Certificate(format!("invalid PEM text: {e}")))?,
        )
    } else {
        CertificateHandle::from_der(bytes)
    }
}

/// Load a PKCS#12 entry into the software signer the CLI builds for `--p12`:
/// same container read, same alias rule (several keys and no alias is an
/// error that lists them), same chain order, same zeroization. The GUI's
/// `.p12` button ends here; there is no second PKCS#12 path.
pub fn load_p12(
    path: &Path,
    password: &str,
    alias: Option<&str>,
) -> Result<openfirma_core::SoftwareSigner> {
    let bytes = std::fs::read(path)
        .map_err(|e| Error::Keystore(format!("cannot read {}: {e}", path.display())))?;
    let container = Pkcs12::load(&bytes, password)
        .map_err(|e| Error::Keystore(format!("{}: {e}", path.display())))?;
    let entry = container.entry(alias)?;
    let leaf = parse_certificate(&entry.chain[0])
        .map_err(|_| Error::Certificate("the PKCS#12 leaf is not a valid certificate".into()))?;
    let mut chain = Vec::with_capacity(entry.chain.len().saturating_sub(1));
    for der in &entry.chain[1..] {
        chain.push(parse_certificate(der)?);
    }
    let signer = openfirma_core::SoftwareSigner::from_pkcs8_der(leaf.der(), &entry.key_pkcs8)
        .map_err(|_| Error::PrivateKey("the PKCS#12 key does not match its certificate".into()))?;
    Ok(signer.with_chain(chain))
}

/// One signable certificate of an opened store, with the friendly name the
/// picker shows. `Arc<dyn SystemStore>` travels inside so a picked entry can
/// produce its signer without re-opening (and re-PIN-ing) anything.
pub struct StoreEntry {
    pub source: Arc<dyn SystemStore>,
    pub cert: StoreCertificate,
    /// The picker's name for this certificate: store label when it has one,
    /// subject CN otherwise (`friendly_name_with_label` rules). Never the DN.
    pub display: String,
    /// What a tooltip explains: the keystore descriptor this came from.
    pub origin: String,
}

/// List what an opened store holds that can sign (the same filter
/// `keystores list` applies — certificates whose key handle is present).
pub fn store_entries(store: &Arc<dyn SystemStore>, origin: &str) -> Result<Vec<StoreEntry>> {
    let certs = store.certificates()?;
    Ok(certs
        .into_iter()
        .map(|c| {
            let display =
                openfirma_core::workflow::friendly_name_with_label(c.label.as_deref(), &c.cert);
            StoreEntry {
                source: store.clone(),
                cert: c,
                display,
                origin: origin.to_string(),
            }
        })
        .collect())
}

/// Read a whole file for signing or verifying, with the CLI's honest error:
/// what was attempted and why it failed. A directory named where a file
/// belongs says so instead of an OS errno sentence.
pub fn read_file(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => Error::Other(format!(
            "{} does not exist. Check the path.",
            path.display()
        )),
        std::io::ErrorKind::PermissionDenied => Error::Other(format!(
            "{} cannot be read: permission denied.",
            path.display()
        )),
        _ if path.is_dir() => {
            Error::Other(format!("{} is a folder, not a document.", path.display()))
        }
        _ => Error::Other(format!("cannot read {}: {e}", path.display())),
    })
}

/// Where "Abrir carpeta" points: the parent directory of a written result.
pub fn containing_dir(path: &Path) -> PathBuf {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map_or_else(|| PathBuf::from("."), |p| p.to_path_buf())
}
