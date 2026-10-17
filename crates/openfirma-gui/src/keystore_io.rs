//! The thin bridge to `openfirma-keystore`: opening descriptors and loading
//! containers with exactly the code paths `openfirma sign` runs, so the two
//! frontends' key sources are one implementation (the brief's rule: never a
//! second one). This module owns nothing: it opens what the keystore crate
//! opens and hands the same types back.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use openfirma_core::workflow::StoreSpec;
use openfirma_core::{CertificateHandle, Error, Result};
use openfirma_keystore::{StoreCertificate, SystemStore};
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
    let container = openfirma_keystore::Pkcs12::load(&bytes, password)
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

/// The PKCS#11 modules a smart-card reader on this machine almost certainly
/// has installed, probed by file existence only (never opened, never
/// PIN-touched — the CLI's `keystores list` rule that a token is only ever
/// named, not guessed at). Review 06 A-6's first half: AutoFirma finds the
/// DNIe without the citizen learning what a `.so` is; the names shown here
/// are what makes that true in openfirma. The order is by how much each one
/// is what the user meant (a smart card IS the DNIe on every Spanish desktop
/// that has one).
pub fn detected_card_modules() -> Vec<(&'static str, PathBuf)> {
    let mut found: Vec<(&'static str, PathBuf)> = Vec::new();
    // Every path below is where a vendor's own package installs its module
    // on a Debian/Ubuntu/Fedora desktop (AutoFirma's three Linux targets) —
    // the probe reads file existence only. A family name matches a *file*,
    // never a guess about what a card contains; OpenSC comes first because
    // the government's own DNIe install script configures it, and one row
    // per family is one door for the user either way.
    #[cfg(target_os = "linux")]
    {
        push_existing(&mut found, "opensc", "/usr/lib/opensc-pkcs11.so");
        push_existing(
            &mut found,
            "opensc",
            "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
        );
        push_existing(
            &mut found,
            "opensc",
            "/usr/lib/x86_64-linux-gnu/pkcs11/opensc-pkcs11.so",
        );
        push_existing(&mut found, "opensc", "/usr/lib64/pkcs11/opensc-pkcs11.so");
        // The DNIe's own vendor module (dnie-action package), tried after
        // OpenSC because OpenSC is what the government's own install script
        // configures.
        push_existing(&mut found, "dniaction", "/usr/lib/dnie/libdnie-sof.so");
        push_existing(
            &mut found,
            "fnmt-ceres",
            "/usr/lib/libpkcs11nShield2015FNMT.so",
        );
        push_existing(
            &mut found,
            "fnmt-ceres",
            "/usr/local/lib/libpkcs11nShield2015FNMT.so",
        );
    }
    #[cfg(target_os = "macos")]
    {
        push_existing(&mut found, "opensc", "/usr/local/lib/opensc-pkcs11.so");
        push_existing(&mut found, "opensc", "/opt/homebrew/lib/opensc-pkcs11.so");
    }
    #[cfg(target_os = "windows")]
    {
        // AutoFirma's Windows default is the CAPI store (open_store's
        // `windows` spec), which discoverable_stores already offers; these
        // are third-party middleware installs, named not guessed.
        for dir in [
            std::env::var_os("ProgramFiles"),
            std::env::var_os("ProgramFiles(x86)"),
        ]
        .into_iter()
        .flatten()
        {
            let root = PathBuf::from(dir);
            push_existing(
                &mut found,
                "opensc",
                root.join("OpenSC Project\\OpenSC\\pkcs11\\opensc-pkcs11.dll"),
            );
            push_existing(
                &mut found,
                "fnmt-ceres",
                root.join("FNMT-RCM\\libpkcs11nShield2015FNMT.dll"),
            );
        }
    }
    // One entry per family: the first path wins; two OpenSC installs are one
    // door, and listing both only teaches the user to distrust pickers.
    let mut seen = std::collections::HashSet::new();
    found.retain(|(family, _)| seen.insert(*family));
    found
}

fn push_existing(
    found: &mut Vec<(&'static str, PathBuf)>,
    family: &'static str,
    path: impl AsRef<Path>,
) {
    let path = path.as_ref().to_path_buf();
    if path.is_file() {
        found.push((family, path));
    }
}

/// The descriptors the picker offers with one click: the cards this machine
/// has middleware for (A-6), the NSS databases discovery can name (the CLI's
/// own `nss::discover` — Firefox profiles included; finding A7 called its
/// absence in the window a defect, and it is the same list `keystores list`
/// prints), and the platform store on Windows/macOS. PKCS#11 modules are
/// never *guessed* at (same rule as `keystores list` without arguments): a
/// detected middleware file is named by path exactly like the CLI names it,
/// so window and terminal accept the same descriptors.
pub fn suggested_stores() -> Vec<(String, String)> {
    let mut lines: Vec<(String, String)> = Vec::new();
    for (family, module) in detected_card_modules() {
        let descriptor = format!("pkcs11:{}", module.display());
        let name = match family {
            "dniaction" => "dnie",
            "opensc" => "opensc",
            "fnmt-ceres" => "fnmt",
            _ => continue,
        };
        lines.push((name.to_string(), descriptor));
    }
    // The NSS side: discovery never opens anything (the keystore crate's own
    // promise), so this costs nothing when no browser exists. `nss::discover`
    // already dedupes and returns ready-to-parse specs.
    for spec in openfirma_keystore::nss::discover() {
        let name = match &spec {
            StoreSpec::NssFirefox { .. } => "firefox",
            _ => "nssdb",
        };
        lines.push((name.to_string(), spec.descriptor()));
    }
    for spec in openfirma_core::workflow::discoverable_stores() {
        let name = match &spec {
            StoreSpec::Windows => "windows",
            StoreSpec::Macos => "macos",
            _ => continue,
        };
        lines.push((name.to_string(), spec.descriptor()));
    }
    lines
}
