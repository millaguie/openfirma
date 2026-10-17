//! Opening a store descriptor behind one shared implementation (finding B8).
//!
//! The CLI's `--store` and the GUI's descriptor field both used to carry
//! their own copy of this match, and they drifted within weeks: NSS grew its
//! install hint on one side only, and each frontend had to remember the no-PIN
//! `::` marker by hand. One function now; neither frontend can be right alone.

use std::sync::Arc;

use openfirma_core::workflow::StoreSpec;
use openfirma_core::{Error, Result};
use std::path::Path;
use zeroize::Zeroizing;

/// Opens a PKCS#11 module and picks one token in it — M4's other half: the
/// path must be **absolute**. A bare name (`libsofthsm2.so`) goes through the
/// OS loader's own search, which on Windows includes the current directory
/// and PATH: an attacker who can plant `DNIe_P11.dll` in the folder the user
/// last worked in (a Downloads directory openfirma was started from) gets
/// their code loaded. A relative path resolves against whatever the process's
/// working directory happens to be, which is a second way to get pointed at
/// something other than what was typed. AutoFirma's helper uses absolute
/// paths for every module it loads (`MozillaKeyStoreUtilities.java`); so does
/// openfirma, and the descriptor says why.
pub fn require_absolute_module(module: &Path) -> Result<()> {
    if module.is_absolute() {
        return Ok(());
    }
    Err(Error::Keystore(format!(
        "PKCS#11 modules are loaded by absolute path only; {} is relative (a \
         bare name would be searched for on PATH and the current directory, \
         which is where planted copies wait — pass --store pkcs11:/full/path/to/module.so)",
        module.display()
    )))
}

/// Open a store descriptor behind one `Arc<dyn SystemStore>` (docs/adr-0004:
/// the dyn erasure keeps every backend out of the callers, and the Arc keeps
/// the store alive past every signer borrowed from it).
pub fn open_store(
    spec: &StoreSpec,
    pin: Option<Zeroizing<String>>,
) -> Result<Arc<dyn crate::SystemStore>> {
    if let StoreSpec::Pkcs11 { module, .. } = spec {
        require_absolute_module(module)?;
    }
    let store: Arc<dyn crate::SystemStore> = match spec {
        StoreSpec::Pkcs11 {
            module,
            token,
            wants_no_pin,
        } => Arc::new(crate::pkcs11::Pkcs11Store::open(
            module,
            token.as_deref(),
            if *wants_no_pin && pin.is_none() {
                // The descriptor said "no PIN": log in with an empty one, the
                // shape a SoftHSM token initialized --pin '' accepts.
                Some(String::new())
            } else {
                pin.map(|p| p.to_string())
            },
        )?),
        StoreSpec::Nss { db } => match crate::nss::open(db, None, pin.map(|p| p.to_string())) {
            Ok(store) => Arc::new(store),
            Err(e) => {
                // `nss` and `nspr` are separate packages on every Linux that
                // ships the library anywhere a browser needs it; telling the
                // user which to install beats "library not found".
                let text = e.to_string();
                if text.contains("OPENFIRMA_NSS_MODULE") {
                    return Err(Error::Keystore(format!(
                        "{text} (on Debian/Ubuntu: apt install libnss3)"
                    )));
                }
                return Err(e);
            }
        },
        StoreSpec::NssFirefox { profile } => {
            match crate::nss::open_firefox(profile.as_deref(), pin.map(|p| p.to_string())) {
                Ok(store) => Arc::new(store),
                Err(e) => {
                    let text = e.to_string();
                    if text.contains("OPENFIRMA_NSS_MODULE") {
                        return Err(Error::Keystore(format!(
                            "{text} (on Debian/Ubuntu: apt install libnss3)"
                        )));
                    }
                    return Err(e);
                }
            }
        }
        StoreSpec::Windows => {
            #[cfg(target_os = "windows")]
            {
                Arc::new(crate::windows::WindowsStore::open()?)
            }
            #[cfg(not(target_os = "windows"))]
            {
                return Err(Error::Keystore(
                    "--store windows is the Windows certificate store; run it on Windows".into(),
                ));
            }
        }
        StoreSpec::Macos => {
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            {
                Arc::new(crate::macos::MacStore::open()?)
            }
            #[cfg(not(any(target_os = "macos", target_os = "ios")))]
            {
                return Err(Error::Keystore(
                    "--store macos is the macOS keychain; run it on macOS".into(),
                ));
            }
        }
    };
    Ok(store)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn off_platform_stores_refuse_by_name() {
        // One shared sentence for both frontends: the descriptor parses and
        // the refusal says what to run it on.
        if !matches!(std::env::consts::OS, "windows") {
            let err = open_store(&StoreSpec::Windows, None)
                .err()
                .expect("this OS must refuse --store windows")
                .to_string();
            assert!(err.contains("run it on Windows"), "{err}");
        }
        if !matches!(std::env::consts::OS, "macos" | "ios") {
            let err = open_store(&StoreSpec::Macos, None)
                .err()
                .expect("this OS must refuse --store macos")
                .to_string();
            assert!(err.contains("run it on macOS"), "{err}");
        }
    }

    #[test]
    fn opening_a_missing_module_names_the_file() {
        let spec = StoreSpec::Pkcs11 {
            module: std::path::PathBuf::from("/nonexistent/mod.so"),
            token: None,
            wants_no_pin: false,
        };
        let err = open_store(&spec, None)
            .err()
            .expect("a missing module cannot open");
        assert!(err.to_string().contains("/nonexistent/mod.so"), "{err}");
    }

    #[test]
    fn a_relative_module_path_is_refused_before_any_loading() {
        // M4: the loader's search path (PATH, and the current directory on
        // Windows) is exactly where planted copies wait; openfirma never
        // enters it, for either spelling of "not absolute".
        for module in ["libsofthsm2.so", "./x.so", "../vendor/mod.dll"] {
            let spec = StoreSpec::Pkcs11 {
                module: std::path::PathBuf::from(module),
                token: None,
                wants_no_pin: false,
            };
            let err = open_store(&spec, None)
                .err()
                .unwrap_or_else(|| panic!("{module} must be refused"));
            let text = err.to_string();
            assert!(text.contains("absolute path only"), "{text}");
            assert!(text.contains(module), "{text}");
        }
    }
}
