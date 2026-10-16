//! The NSS shared database, AutoFirma's `SHARED_NSS` store.
//!
//! There is no separate NSS wire protocol to speak: the NSS certificate and
//! key database *is* a PKCS#11 module — libsoftokn3.so on Linux, softokn3.dll
//! on Windows, libsoftokn3.dylib on macOS — and what AutoFirma's NSS helper
//! does is point it at the shared DB (`sql:~/.pki/nssdb` and friends) through
//! SunPKCS11 with a configuration string. This module does the same thing over
//! the [`crate::pkcs11`] machinery: find the softokn3 library, initialize it
//! with the database location as its `LibraryParameters`, and drive the v2.40
//! function list. The whole NSS-specific surface is therefore two small
//! differences from a generic token, both verified against live libsoftokn3:
//!
//! - the initialize-args shape, [`crate::pkcs11::NssInitializeArgs`] (NSS's
//!   own `CK_C_INITIALIZE_ARGS`, mutex callbacks first — see ADR-0004); and
//! - which library file to load and how to name the database, below.
//!
//! The DNIe, FNMT@Fábrica Nacional smart cards included: AutoFirma reaches a
//! card whose vendor ships an NSS-style configuration by naming that module
//! with this same mechanism, and openfirma needs no code for it either — point
//! `--store pkcs11:<vendor module>` at the card's PKCS#11 library directly.

use std::path::{Path, PathBuf};

use openfirma_core::Result;
use openfirma_core::error::Error;

use crate::pkcs11::Pkcs11Store;

/// Opens the NSS database `db` — a location like `sql:~/.pki/nssdb` (the `~`
/// and a leading `$HOME` are expanded; a bare path is treated as `sql:<path>`,
/// which is softokn3's own default for un-prefixed locations).
///
/// The softokn3 library itself is found like AutoFirma's helper does not have
/// to (it ships NSS inside the JRE): explicit environment override first,
/// then the system paths. `token` picks a named token within the database —
/// an NSS DB exposes two slots, the "NSS FIPS User Keys"/"NSS User Private
/// Keys" pair or their non-FIPS names; private keys live in the private-key
/// slot, and listing certificates from the wrong one simply yields none.
pub fn open(db: &str, token: Option<&str>, pin: Option<String>) -> Result<Pkcs11Store> {
    let db = config_string(db)?;
    let module = find_softokn()?;
    Pkcs11Store::open_nss(&module, &db, token, pin)
}

/// Normalizes a user-written database location into the parameter string NSS
/// needs. Public because [`crate::pkcs11::Pkcs11Store::open_nss`] applies it
/// too — every path into an NSS softokn3 must pass through here so the same
/// friendly input shape works from either entry point.
pub fn config_string(db: &str) -> Result<String> {
    let expanded = expand_db_location(db);
    if db.trim().is_empty() || expanded.is_empty() {
        return Err(Error::Keystore(format!(
            "the NSS database location {db:?} cannot be expressed in softokn3's \
             configuration syntax (its path contains a quote)"
        )));
    }
    Ok(expanded)
}

/// Respects `OPENFIRMA_NSS_MODULE` so a test (or a user with a bundled NSS)
/// can point at an exact libsoftokn3 without touching the search below.
fn find_softokn() -> Result<PathBuf> {
    if let Ok(explicit) = std::env::var("OPENFIRMA_NSS_MODULE") {
        let path = PathBuf::from(explicit);
        if path.is_file() {
            return Ok(path);
        }
        return Err(Error::Keystore(format!(
            "OPENFIRMA_NSS_MODULE points at {}, which is not a file",
            path.display()
        )));
    }
    // The names and locations the three platforms actually ship. NSS may be
    // packaged beside other libraries (/usr/lib, /usr/lib64, the macOS Homebrew
    // Cellar) or inside an application bundle (Firefox, Thunderbird — where a
    // shared DB is frequently used together with a bundled softokn3).
    let names: &[&str] = if cfg!(target_os = "windows") {
        &["softokn3.dll", "nss3.dll"]
    } else if cfg!(any(target_os = "macos", target_os = "ios")) {
        &["libsoftokn3.dylib"]
    } else {
        &["libsoftokn3.so"]
    };
    let mut dirs: Vec<PathBuf> = Vec::new();
    if cfg!(unix) {
        dirs.extend([
            PathBuf::from("/usr/lib"),
            PathBuf::from("/usr/local/lib"),
            PathBuf::from("/usr/lib64"),
        ]);
        if let Ok(extra) = std::env::var("LD_LIBRARY_PATH") {
            dirs.extend(std::env::split_paths(&extra));
        }
    }
    for name in names {
        for dir in &dirs {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    Err(Error::Keystore(
        "no NSS softokn3 library was found (looked for the system libsoftokn3). \
         Install the nss package or set OPENFIRMA_NSS_MODULE to its full path"
            .into(),
    ))
}

/// Turns whatever a person wrote into softokn3's own parameter string.
///
/// The `LibraryParameters` parser inside softokn3 (`sftk_parseParameters`) is
/// key-value based: a bare location — `sql:/path`, `dbm:/path` or `/path` —
/// makes it answer its vendor `CKR_ARGUMENTS_BAD` (0xce534351, proved by
/// probing), and the CLI surface is friendlier than a parser, so this is the
/// mapping: `/path` → `sql:/path` (softokn3's own default for un-prefixed
/// paths), `~`/`$HOME` expanded, wrapped as `configDir='...'` (the quotes let
/// a path contain spaces). Anything that already carries the `configDir=`
/// key or other keys (it contains a space) passes through with expansion only.
fn expand_db_location(db: &str) -> String {
    let trimmed = db.trim();
    if trimmed.to_ascii_lowercase().starts_with("configdir=") || trimmed.contains(' ') {
        return expand_tilde(trimmed);
    }
    let location = expand_tilde(trimmed);
    // Quote-safe: a path containing a single quote cannot be represented in
    // softokn3's parameter syntax, and passing it through mangled would make
    // the module fail with an opaque parse error. Refuse with our own message
    // instead. (A database directory named this way is absurd; a hostile env
    // var pointing at one deserves the clear error.)
    if location.contains('\'') {
        return String::new();
    }
    let location = if location.starts_with("sql:") || location.starts_with("dbm:") {
        location
    } else {
        format!("sql:{location}")
    };
    format!("configDir='{location}'")
}

fn expand_tilde(s: &str) -> String {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    for (needle, replacement) in [
        ("~", home.as_deref().unwrap_or(Path::new("~"))),
        ("$HOME", home.as_deref().unwrap_or(Path::new("$HOME"))),
    ] {
        if let Some(rest) = s.strip_prefix(needle) {
            if rest.is_empty() || rest.starts_with('/') {
                return format!("{}{rest}", replacement.display());
            }
        }
    }
    s.to_string()
}
