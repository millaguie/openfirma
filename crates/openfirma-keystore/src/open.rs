//! Opening a store descriptor behind one shared implementation (finding B8).
//!
//! The CLI's `--store` and the GUI's descriptor field both used to carry
//! their own copy of this match, and they drifted within weeks: NSS grew its
//! install hint on one side only, and each frontend had to remember the no-PIN
//! `::` marker by hand. One function now; neither frontend can be right alone.

use std::sync::Arc;

use openfirma_core::workflow::StoreSpec;
use openfirma_core::{Error, Result};
use zeroize::Zeroizing;

/// Open a store descriptor behind one `Arc<dyn SystemStore>` (docs/adr-0004:
/// the dyn erasure keeps every backend out of the callers, and the Arc keeps
/// the store alive past every signer borrowed from it).
pub fn open_store(
    spec: &StoreSpec,
    pin: Option<Zeroizing<String>>,
) -> Result<Arc<dyn crate::SystemStore>> {
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
}
