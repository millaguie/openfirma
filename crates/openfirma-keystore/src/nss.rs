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

/// Opens the Firefox profile store — AutoFirma's `MOZ_UNI` keystore (review
/// 04, A7). The profile holds an NSS database of its own: the one that backs
/// *Tools ▸ Settings ▸ Privacy ▸ Security ▸ Security Devices*, which is where
/// a DNIe or FNMT module registered from Firefox lives. `profile` names one
/// by its `Name=` from profiles.ini; without it, the profile Firefox itself
/// uses (the `Default=1` or `[Install…]` default) opens.
pub fn open_firefox(profile: Option<&str>, pin: Option<String>) -> Result<Pkcs11Store> {
    let db = firefox_profile_db(profile)?;
    let module = find_softokn()?;
    Pkcs11Store::open_nss(&module, &db, None, pin)
}

/// The NSS databases of every Firefox (and Thunderbird) profile this machine
/// has: one descriptor per profile, the shared database included. This is
/// what `keystores list` shows with no arguments on Linux (AutoFirma offers
/// MOZ_UNI and SHARED_NSS in its keystore menu without being asked for a
/// path); discovery never opens anything, so an absent browser costs nothing
/// but a couple of directory reads. The database *is* the store — the modules
/// a profile registers inside it (pkcs11.txt) speak through their own PKCS#11
/// libraries, which openfirma asks for by absolute path like every other
/// token (finding M4), not from files a browser owns.
pub fn discover() -> Vec<openfirma_core::workflow::StoreSpec> {
    use openfirma_core::workflow::StoreSpec;
    let mut specs = Vec::new();
    if shared_db_exists() {
        specs.push(StoreSpec::Nss {
            db: shared_db_location(),
        });
    }
    for dir in firefox_parents() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        // profiles.ini is the authority on which directories under a parent
        // are profiles: Crash Reports, Profile Groups and whatever else a
        // browser keeps beside them can hold files too (a stray cert9.db in
        // one made this very listing offer a non-profile as a keystore). An
        // ini that exists but names no profile is therefore the strictest
        // answer — list nothing, ask for the path by name. Only where there
        // is no ini at all falls back to the database files themselves: snap
        // mirror roots genuinely have none, and there the files are all
        // there is to go by.
        let listed = profile_paths(&dir.join("profiles.ini"));
        let fallback = listed.is_empty() && !dir.join("profiles.ini").is_file();
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.join("cert9.db").exists() && !path.join("cert8.db").exists() {
                continue;
            }
            if fallback || listed.contains(&path) {
                let db = path.display().to_string();
                specs.push(StoreSpec::Nss {
                    db: format!("sql:{db}"),
                });
            }
        }
    }
    // Two environment variables can name one directory — %APPDATA% and
    // %LOCALAPPDATA%\Mozilla\Firefox versus a profiles.ini that keeps profiles
    // directly under the parent, or both spellings Windows browsers use — and
    // a picker must show every database once.
    specs.sort_by_key(|s| s.descriptor());
    specs.dedup_by(|a, b| a.descriptor() == b.descriptor());
    // …and the profile Firefox ITSELF would open comes first (round 4's B-3:
    // only one NSS database can be open per process, so the first descriptor is
    // the one a listing reaches; alphabetically `.pki/nssdb` or an old profile
    // used to win over the profile Firefox opens, which is the one a citizen
    // expects the window to show). The rule is the same one `nss:firefox` uses.
    // The root, not the config string: descriptors spell an NSS database
    // "nss:sql:<absolute path>", and comparing paths avoids depending on how
    // config_string quotes a location with spaces.
    let preferred_root = firefox_parents().iter().find_map(|parent| {
        profiles_ini(&parent.join("profiles.ini"), None)
            .ok()
            .flatten()
    });
    if let Some(root) = preferred_root {
        let preferred = format!("nss:sql:{}", root.display());
        specs.sort_by_key(|s| {
            let d = s.descriptor();
            (d != preferred, d)
        });
    }
    specs
}

/// Every profile directory profiles.ini names, whether or not it is on disk.
fn profile_paths(ini: &Path) -> Vec<PathBuf> {
    let Ok(text) = std::fs::read_to_string(ini) else {
        return Vec::new();
    };
    let parent = ini.parent().unwrap_or(Path::new("."));
    let mut out = Vec::new();
    let (mut is_profile, mut path, mut relative) = (false, String::new(), true);
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') && line.ends_with(']') {
            if is_profile && !path.is_empty() {
                out.push(profile_root(parent, &path, relative));
            }
            is_profile = line[1..line.len() - 1].starts_with("Profile");
            path.clear();
            relative = true;
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key.trim().to_ascii_lowercase().as_str() {
            "path" => path = value.trim().replace('\\', std::path::MAIN_SEPARATOR_STR),
            "isrelative" => relative = value.trim() != "0",
            _ => {}
        }
    }
    if is_profile && !path.is_empty() {
        out.push(profile_root(parent, &path, relative));
    }
    out
}

fn profile_root(parent: &Path, path: &str, relative: bool) -> PathBuf {
    if relative {
        parent.join(path)
    } else {
        PathBuf::from(path)
    }
}

/// Whether the standard shared database (`$HOME/.pki/nssdb`) exists.
pub fn shared_db_exists() -> bool {
    let Some(home) = home_dir() else {
        return false;
    };
    home.join(".pki").join("nssdb").is_dir()
}

/// The location of the standard shared database in descriptor spelling.
pub fn shared_db_location() -> String {
    let home = home_dir()
        .map(|h| h.display().to_string())
        .unwrap_or_default();
    format!("sql:{home}/.pki/nssdb")
}

fn home_dir() -> Option<PathBuf> {
    // A single read per call from one place: the tests that lay a fake HOME
    // down for discovery swap it with set_var, and a sibling test's window in
    // between two reads of `HOME` would otherwise let one discover() mix two
    // homes. (std::env::home_dir is not an option here on purpose — its
    // deprecation warning would leak into builds that deny warnings.)
    std::env::var_os("HOME").map(PathBuf::from)
}

/// Resolves a Firefox profile to its database location in softokn3 spelling.
/// With `wanted`, the profiles.ini section whose `Name=` matches; without it,
/// the profile Firefox itself opens with no choice: the `Default=` of an
/// `[Install…]` section (the dedicated profile), or `Default=1` on a
/// `[ProfileX]` section under snap, where the dedicated profile is not used.
/// Profiles may be marked `IsRelative=0`, in which case their `Path=` is
/// already absolute.
fn firefox_profile_db(wanted: Option<&str>) -> Result<String> {
    let mut looked = Vec::new();
    for parent in firefox_parents() {
        let ini = parent.join("profiles.ini");
        if !ini.is_file() {
            continue;
        }
        looked.push(ini.display().to_string());
        let Some(root) = profiles_ini(&ini, wanted)? else {
            continue;
        };
        let db = root.display().to_string();
        return config_string(&format!("sql:{db}"));
    }
    Err(Error::Keystore(format!(
        "no Firefox profiles.ini was found ({}). Name the profile database \
         directly: --store nss:sql:/path/to/profile",
        if looked.is_empty() {
            "looked in the native, snap and flatpak locations".to_string()
        } else {
            looked.join(", ")
        }
    )))
}

/// Reads one profiles.ini. `Ok(None)` means it was read but holds no profile
/// that answers; an absolute path is returned ready to be a database root.
fn profiles_ini(ini: &Path, wanted: Option<&str>) -> Result<Option<PathBuf>> {
    let text = std::fs::read_to_string(ini)
        .map_err(|e| Error::Keystore(format!("{}: {e}", ini.display())))?;
    let parent = ini.parent().unwrap_or(Path::new("."));
    let mut fallback: Option<PathBuf> = None;
    let mut dedicated: Option<PathBuf> = None;
    let (mut section, mut name, mut path, mut relative, mut default) =
        (String::new(), String::new(), String::new(), true, false);
    let flush = |section: &str,
                 name: &str,
                 path: &str,
                 relative: bool,
                 default: bool,
                 fallback: &mut Option<PathBuf>|
     -> Result<Option<PathBuf>> {
        if section.is_empty() || path.is_empty() || !section.starts_with("Profile") {
            return Ok(None);
        }
        let root = if relative {
            parent.join(path)
        } else {
            PathBuf::from(path)
        };
        if wanted.is_some_and(|want| name == want) {
            // A named profile that is gone says so: silently answering with
            // a different profile would sign from the wrong database.
            if !root.is_dir() {
                return Err(Error::Keystore(format!(
                    "Firefox profile '{name}' from {} points at {}, which does \
                     not exist",
                    ini.display(),
                    root.display()
                )));
            }
            return Ok(Some(root));
        }
        if wanted.is_none() && default && fallback.is_none() {
            *fallback = Some(root);
        }
        Ok(None)
    };
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') && line.ends_with(']') {
            if let Some(found) = flush(&section, &name, &path, relative, default, &mut fallback)? {
                return Ok(Some(found));
            }
            section = line[1..line.len() - 1].to_string();
            name.clear();
            path.clear();
            relative = true;
            default = false;
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if section.starts_with("Install") {
            // The [Install…] section's `Default=` names the profile this
            // installation of Firefox opens; see the precedence at the end of
            // this function. First install section wins, which on a machine
            // that has used one browser is the only one there is.
            if key.trim().eq_ignore_ascii_case("default") && dedicated.is_none() {
                let v = value.trim();
                if !v.is_empty() {
                    // NSS profile directories keep their separators as `/`
                    // even in Windows profiles.ini spellings, and an install
                    // descriptor may be absolute.
                    let replaced = v.replace('\\', std::path::MAIN_SEPARATOR_STR);
                    dedicated = Some(if Path::new(&replaced).is_absolute() {
                        PathBuf::from(replaced)
                    } else {
                        parent.join(replaced)
                    });
                }
            }
            continue;
        }
        match key.trim().to_ascii_lowercase().as_str() {
            "name" => name = value.trim().to_string(),
            // NSS profile directories keep their separators as `/` even in
            // Windows profiles.ini spellings; PathBuf joins both.
            "path" => path = value.trim().replace('\\', std::path::MAIN_SEPARATOR_STR),
            "isrelative" => relative = value.trim() != "0",
            "default" => default = value.trim() == "1",
            _ => {}
        }
    }
    if let Some(found) = flush(&section, &name, &path, relative, default, &mut fallback)? {
        return Ok(Some(found));
    }
    if wanted.is_some() {
        // The caller named a profile and none matched: the defaults below are
        // not that profile, so there is nothing to answer with.
        return Ok(None);
    }
    // Which profile Firefox itself opens when none is named
    // (`nsToolkitProfileService::GetDefaultProfile`): with
    // `mUseDedicatedProfile` — true unless the browser is confined as a snap
    // (`!IsSnapEnvironment() && !UseLegacyProfiles()`) — it is the dedicated
    // profile, the one the [Install…] section's `Default=` names, even though
    // Firefox 67+ also leaves `Default=1` on the empty `default` profile it
    // creates first. Under snap the dedicated profile is not used and
    // `Default=1` wins. AutoFirma's own reader agrees for a version 2 file:
    // `NSPreferences.getActiveProfile` answers with the install section's
    // `defaultProfilePath`, not the flag.
    //
    // Round 2 (04-N5) measured the old order — the flag first, whatever the
    // version and however late the install section was — and `nss:firefox`
    // opened the empty `default` profile while the citizen's certificates sat
    // in `default-release`. The round-1 reading of the C++ it was justified
    // with was wrong: `GetSelectedProfile` (what a person chooses in the
    // profile dialog) is not `GetDefaultProfile` (what the browser opens with
    // no choice), and only the latter decides here.
    let in_snap = ini.components().any(|c| c.as_os_str() == "snap");
    let (first, second) = if in_snap {
        (fallback, dedicated)
    } else {
        (dedicated, fallback)
    };
    for candidate in [first, second].into_iter().flatten() {
        if candidate.is_dir() {
            return Ok(Some(candidate));
        }
    }
    Ok(None)
}

/// Every directory a profiles.ini can live in: the native spelling of each
/// platform plus snap and flatpak roots (finding A7 — AutoFirma's helper
/// reads the same list, `MozillaKeyStoreUtilities.java`). Both Firefox and
/// Thunderbird hold NSS databases of this exact shape.
///
/// `OPENFIRMA_FIREFOX_PARENTS` (path-separator-joined) replaces the list
/// wholesale when set. It exists for two reasons: packaging that keeps a
/// profile tree outside the platform standard (rare), and tests — discovery
/// otherwise reads `$HOME`, which any sibling test that relocates `HOME` in
/// its own thread turns into a race, and CI runners are full of services
/// with real Firefox profiles. The CI lanes anchor it to `/nonexistent` so
/// every determinism claim below is about this crate, not the runner's
/// desktop.
fn firefox_parents() -> Vec<PathBuf> {
    if let Some(list) = std::env::var_os("OPENFIRMA_FIREFOX_PARENTS") {
        return std::env::split_paths(&list)
            .filter(|p| !p.as_os_str().is_empty())
            .collect();
    }
    let mut dirs = Vec::new();
    if cfg!(target_os = "windows") {
        for var in ["APPDATA", "LOCALAPPDATA"] {
            if let Some(root) = std::env::var_os(var) {
                let root = PathBuf::from(root);
                dirs.push(root.join("Mozilla").join("Firefox"));
                dirs.push(root.join("Thunderbird"));
            }
        }
    } else if cfg!(any(target_os = "macos", target_os = "ios")) {
        if let Some(home) = home_dir() {
            let library = home.join("Library").join("Application Support");
            dirs.push(library.join("Firefox"));
            dirs.push(library.join("Thunderbird"));
        }
    } else if let Some(home) = home_dir() {
        dirs.push(home.join(".mozilla").join("firefox"));
        dirs.push(home.join(".thunderbird"));
        // snap: the confined application's own data directory is its `common`
        // one — `$SNAP_USER_COMMON`, i.e. `~/snap/<app>/common` — and that is
        // where the profile tree lives, not under a revision number. AutoFirma
        // reads exactly this path (`MozillaKeyStoreUtilities`). Round 2 found
        // the walk below, which skips `common` itself; on a machine where
        // Firefox is the snap package it found nothing and the README already
        // claimed it did.
        let snap = home.join("snap");
        for (app, profile_dir) in [
            ("firefox", ".mozilla/firefox"),
            ("thunderbird", ".thunderbird"),
        ] {
            dirs.push(snap.join(app).join("common").join(profile_dir));
        }
        // A revision tree keeps its own `common` directory when a snap is
        // pinned (`snap refresh --hold`): same shape one level down. Taken
        // after the live `common` above, so the running profile wins.
        for app in ["firefox", "thunderbird"] {
            let Ok(entries) = std::fs::read_dir(snap.join(app)) else {
                continue;
            };
            for entry in entries.flatten() {
                if entry.file_name() == "common" {
                    continue; // already pushed
                }
                dirs.push(entry.path().join("common").join(".mozilla").join("firefox"));
                dirs.push(entry.path().join("common").join(".thunderbird"));
            }
        }
        // flatpak keeps one root per application id.
        for app in ["org.mozilla.firefox", "org.mozilla.Thunderbird"] {
            dirs.push(
                home.join(".var")
                    .join("app")
                    .join(app)
                    .join(".mozilla")
                    .join("firefox"),
            );
            dirs.push(home.join(".var").join("app").join(app).join(".thunderbird"));
        }
    }
    dirs
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
             configuration syntax (its path is empty or contains a quote)"
        )));
    }
    Ok(expanded)
}

/// Respects `OPENFIRMA_NSS_MODULE` so a test (or a user with a bundled NSS)
/// can point at an exact libsoftokn3 without touching the search below.
fn find_softokn() -> Result<PathBuf> {
    if let Ok(explicit) = std::env::var("OPENFIRMA_NSS_MODULE") {
        // The same rule the descriptor parser enforces (finding M4): a bare
        // name here would reach the loader's search — the current directory
        // included, on Windows first of all — which is exactly what the
        // absolute-path guarantee exists to close. An override that wants an
        // exact library can spell it exactly.
        let path = PathBuf::from(explicit);
        if !path.is_absolute() {
            return Err(Error::Keystore(format!(
                "OPENFIRMA_NSS_MODULE must name an absolute file, not {}",
                path.display()
            )));
        }
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
    // shared DB is frequently used together with a bundled softokn3). On
    // Windows nothing installs NSS system-wide at all: every copy lives in an
    // application directory (finding A7 — the old search built an empty list
    // there, so `--store nss` could never work without OPENFIRMA_NSS_MODULE).
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
        // Debian's libnss3 installs into the multiarch directory, which no
        // fixed spelling covers. B5: do not ask dpkg-architecture (it lives
        // in dpkg-dev, absent on ordinary desktops, and running a PATH-found
        // process to learn a constant is its own small risk); try the
        // triplets of the architectures these packages actually ship for,
        // plus Debian's NSS subdir. One stat each; wrong guesses are free.
        for triplet in [
            "x86_64-linux-gnu",
            "aarch64-linux-gnu",
            "arm-linux-gnueabihf",
            "i386-linux-gnu",
            "riscv64-linux-gnu",
        ] {
            dirs.push(PathBuf::from(format!("/usr/lib/{triplet}")));
            dirs.push(PathBuf::from(format!("/usr/lib/{triplet}/nss")));
        }
        // Homebrew on Apple silicon (and Intel's /usr/local alternative) is
        // where macOS carries libsoftokn3 outside a browser bundle.
        if cfg!(any(target_os = "macos", target_os = "ios")) {
            dirs.push(PathBuf::from("/opt/homebrew/opt/nss/lib"));
            dirs.push(PathBuf::from("/opt/homebrew/lib"));
            dirs.push(PathBuf::from("/usr/local/opt/nss/lib"));
        }
        if let Ok(extra) = std::env::var("LD_LIBRARY_PATH") {
            // M4: an empty LD_LIBRARY_PATH entry means "the current directory"
            // to the loader; a relative one is relative to it too. Neither is
            // a place openfirma agrees to load code from.
            dirs.extend(
                std::env::split_paths(&extra)
                    .filter(|p| !p.as_os_str().is_empty() && p.is_absolute()),
            );
        }
    }
    if cfg!(target_os = "windows") {
        // The system directory (NSS ships inside Chrome, Firefox, Thunderbird
        // and some VPN suites) plus the application directories themselves.
        if let Some(root) = std::env::var_os("SystemRoot") {
            dirs.push(PathBuf::from(root).join("System32"));
        }
        for var in ["PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA"] {
            if let Some(root) = std::env::var_os(var) {
                let root = PathBuf::from(root);
                for app in [
                    "Mozilla Firefox",
                    "Mozilla Thunderbird",
                    "Google/Chrome/Application",
                    "Microsoft/Edge/Application",
                ] {
                    let app_dir = root.join(app);
                    // Browser layouts keep the DLLs one or two levels deeper:
                    // Firefox has softokn3.dll right in its directory, Chrome
                    // beside the versioned exe dir. Probe both spellings.
                    dirs.push(app_dir.clone());
                    if let Ok(entries) = std::fs::read_dir(&app_dir) {
                        for entry in entries.flatten() {
                            let path = entry.path();
                            if path.is_dir() {
                                dirs.push(path);
                            }
                        }
                    }
                }
            }
        }
    }
    // macOS (and any Unix with a browser at hand): the application bundles
    // carry their own softokn3 next to XUL, and a shared DB opened with the
    // system NSS would be a *different* version of it — the same reason
    // AutoFirma's helper points at the bundled library for MOZ_UNI stores.
    if cfg!(any(target_os = "macos", target_os = "ios")) {
        let mut roots = vec![PathBuf::from("/Applications")];
        if let Some(home) = home_dir() {
            roots.push(home.join("Applications"));
        }
        for app in [
            "Firefox.app/Contents/MacOS",
            "Thunderbird.app/Contents/MacOS",
            "Google Chrome.app/Contents/MacOS",
            "Safari.app/Contents/Frameworks",
        ] {
            for root in &roots {
                dirs.push(root.join(app));
            }
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
        "no NSS softokn3 library was found (looked for the system libsoftokn3 \
         and the copies browsers ship). Install the nss package or set \
         OPENFIRMA_NSS_MODULE to its full path"
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
/// a path contain spaces — finding M3: `%APPDATA%`, snap and flatpak profile
/// directories are full of them on the machines that have them). Anything
/// that carries its own key (`=`, or an opening quote) is treated as a
/// parameter string already written by someone else and passes through with
/// expansion only.
fn expand_db_location(db: &str) -> String {
    let trimmed = db.trim();
    // B5's counterpart in the parameter string: only something that already
    // carries an NSS key (`configDir=`/`parameters=`) is a spelling to pass
    // through. No default flags ride along on it: softokn3's own
    // `sftk_parseParameters` treats any unquoted value after the first
    // space-separated key as garbage and answers its vendor "did not parse"
    // (measured with this library), so a caller who writes their own
    // parameter string owns it verbatim.
    if trimmed.contains('=') || trimmed.starts_with('\'') || trimmed.starts_with('"') {
        return openfirma_core::workflow::expand_home(trimmed);
    }
    let location = openfirma_core::workflow::expand_home(trimmed);
    // The bare `nss` descriptor carries the unexpanded `$HOME/.pki/nssdb`
    // sentinel (parse must not read HOME — see workflow.rs), so this is where
    // a missing HOME becomes an error, at open time when somebody actually
    // means to use that database.
    if location.starts_with("$HOME") {
        return String::new();
    }
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
    // B4: AutoFirma's NSS helper adds the same flag (MozillaKeyStoreUtilities
    // passes flags='readOnly'). Signing only ever reads, and opening a
    // browser's live profile in writing lets a *different* NSS version decide
    // to migrate its database under the browser's feet.
    format!("configDir='{location}' flags=readOnly")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::SystemStore;

    fn tmp(name: &str) -> PathBuf {
        // Fresh per *process and thread*: a CI matrix can leave an old
        // runner's or another binary's fixture of the same name in the shared
        // temp directory, and discovery would count its contents as part of
        // this test's answer. A random suffix makes that impossible.
        let dir = std::env::temp_dir().join(format!(
            "openfirma-nss-test-{}-{}-{name}",
            std::process::id(),
            std::thread::current()
                .name()
                .unwrap_or("t")
                .replace("::", "_"),
        ));
        let _ = std::fs::remove_dir_all(&dir);
        if dir.try_exists().unwrap_or(true) {
            // Even a failed removal must not leave a foreign fixture behind:
            // retire to a name nothing else can have created.
            let salted = format!(
                "{}-{}",
                dir.display(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.subsec_nanos())
                    .unwrap_or(0)
            );
            let dir = PathBuf::from(salted);
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("test temp dir");
            return dir;
        }
        std::fs::create_dir_all(&dir).expect("test temp dir");
        dir
    }

    /// One HOME swap at a time: `set_var` is process-global, so every test in
    /// this module that changes it takes the same lock. (These tests are about
    /// *paths*; nothing else in the suite reads HOME while they run — the
    /// guard exists because cargo runs them on four threads.)
    static HOME_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn profiles_ini_default_follows_firefoxs_own_rules() {
        let dir = tmp("default");
        std::fs::write(
            dir.join("profiles.ini"),
            "[InstallD93B17C472302F2A]\nDefault=aaaa.default-release\nLocked=1\n\n\
             [Profile0]\nName=release\nIsRelative=1\nPath=aaaa.default-release\nDefault=1\n\n\
             [Profile1]\nName=esr\nIsRelative=1\nPath=bbbb.default-esr\n\n\
             [General]\nStartWithLastProfile=1\nVersion=2\n",
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("aaaa.default-release")).unwrap();
        std::fs::create_dir_all(dir.join("bbbb.default-esr")).unwrap();
        let got = profiles_ini(&dir.join("profiles.ini"), None)
            .unwrap()
            .expect("the default profile");
        assert_eq!(got, dir.join("aaaa.default-release"));
        // Named profiles resolve by Name= whatever the defaults say.
        let got = profiles_ini(&dir.join("profiles.ini"), Some("esr"))
            .unwrap()
            .expect("the named profile");
        assert_eq!(got, dir.join("bbbb.default-esr"));
        // A name that is not in the file answers with nothing, and the caller
        // turns that into "no such profile" — never a silent default.
        assert!(
            profiles_ini(&dir.join("profiles.ini"), Some("nope"))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn profiles_ini_install_default_and_absolute_paths_still_resolve() {
        let dir = tmp("install");
        // The modern Firefox shape: no Default=1 on the profile, only the
        // [Install…] section knows which one the browser opens.
        std::fs::write(
            dir.join("profiles.ini"),
            "[InstallABC]\nDefault=zzz.default-release\n\n\
             [Profile0]\nName=release\nIsRelative=1\nPath=zzz.default-release\n",
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("zzz.default-release")).unwrap();
        let got = profiles_ini(&dir.join("profiles.ini"), None)
            .unwrap()
            .expect("the install default");
        assert_eq!(got, dir.join("zzz.default-release"));
    }

    #[test]
    fn the_install_sections_default_is_the_profile_firefox_opens() {
        // Round 2 (04-N5), against Firefox's own nsToolkitProfileService:
        // GetDefaultProfile answers with the DEDICATED profile — the
        // `[Install…] Default=` — because mUseDedicatedProfile is true unless
        // the browser runs confined as a snap. Firefox 67+ still leaves
        // `Default=1` on the empty `default` profile it creates first; the
        // round-1 rule (the flag first, whatever the version) opened that
        // empty profile while the citizen's certificates sat in
        // `default-release`, and AutoFirma's own reader opens the install
        // section's `defaultProfilePath` for the same file.
        let dir = tmp("precedence");
        std::fs::write(
            dir.join("profiles.ini"),
            "[InstallABC]\nDefault=zzz.default-release\n\n\
             [Profile0]\nName=default\nIsRelative=1\nPath=yyy.default\nDefault=1\n\n\
             [Profile1]\nName=release\nIsRelative=1\nPath=zzz.default-release\n",
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("yyy.default")).unwrap();
        std::fs::create_dir_all(dir.join("zzz.default-release")).unwrap();
        let got = profiles_ini(&dir.join("profiles.ini"), None)
            .unwrap()
            .expect("the install default");
        assert_eq!(got, dir.join("zzz.default-release"));
    }

    #[test]
    fn under_snap_the_profile_flag_decides_again() {
        // The other half of 04-N5: `mUseDedicatedProfile` is false when the
        // browser runs as a snap, so the same file read from
        // `~/snap/firefox/common/.mozilla/firefox` answers with Default=1.
        let dir = tmp("snap-precedence");
        let snap = dir.join("snap/firefox/common/.mozilla/firefox");
        std::fs::create_dir_all(snap.join("yyy.default")).unwrap();
        std::fs::create_dir_all(snap.join("zzz.default-release")).unwrap();
        std::fs::write(
            snap.join("profiles.ini"),
            "[InstallABC]\nDefault=zzz.default-release\n\n\
             [Profile0]\nName=default\nIsRelative=1\nPath=yyy.default\nDefault=1\n\n\
             [Profile1]\nName=release\nIsRelative=1\nPath=zzz.default-release\n",
        )
        .unwrap();
        let got = profiles_ini(&snap.join("profiles.ini"), None)
            .unwrap()
            .expect("the snap default");
        assert_eq!(got, snap.join("yyy.default"));
    }

    #[test]
    fn an_absolute_profile_path_is_used_as_written() {
        // IsRelative=0: Path= is a full directory already (relocated and
        // enterprise profiles keep this spelling on every platform).
        let dir = tmp("absolute");
        let outside = tmp("outside").join("absoluto");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(
            dir.join("profiles.ini"),
            format!(
                "[Profile0]\nName=fuera\nIsRelative=0\nPath={}\n",
                outside.display()
            ),
        )
        .unwrap();
        let got = profiles_ini(&dir.join("profiles.ini"), Some("fuera"))
            .unwrap()
            .expect("the absolute profile");
        assert_eq!(got, outside);
    }

    #[test]
    fn a_named_profile_whose_directory_is_gone_names_it() {
        let dir = tmp("gone");
        std::fs::write(
            dir.join("profiles.ini"),
            "[Profile0]\nName=absent\nIsRelative=1\nPath=does-not-exist\n",
        )
        .unwrap();
        let err = profiles_ini(&dir.join("profiles.ini"), Some("absent"))
            .expect_err("a profile whose path is gone must not resolve");
        assert!(err.to_string().contains("does not exist"), "{err}");
    }

    #[test]
    fn a_database_path_with_spaces_is_quoted_not_refused() {
        // Finding M3: `C:\Users\Juan Pérez\AppData\…` and every snap profile
        // are paths with spaces; the old code passed them unquoted (and the
        // module rejected them), because it treated *any* space as "already a
        // parameter string".
        let dir = tmp("spaces");
        let spaced = dir.join("dir con espacio").join("nssdb");
        std::fs::create_dir_all(&spaced).unwrap();
        let got = config_string(&format!("sql:{}", spaced.display())).unwrap();
        assert_eq!(
            got,
            format!("configDir='sql:{}' flags=readOnly", spaced.display())
        );
        // The spelling the module parses from here on is exactly this quoted
        // form, and a real softokn3 accepts it — proven end to end, not by
        // string shape: copy the real fixture database (OPENFIRMA_TEST_NSS_DB)
        // into a directory whose name has spaces and list through *this* code
        // path. A spaced, freshly created directory makes NSS answer its
        // unusable-database error before any query runs (softokn3 does not
        // create sql databases inside an empty directory), which is exactly
        // why the proof below uses a database that exists.
        if let Ok(module) = find_softokn() {
            let real = std::env::var("OPENFIRMA_TEST_NSS_DB")
                .unwrap_or_default()
                .strip_prefix("sql:")
                .unwrap_or_default()
                .to_string();
            if !real.is_empty() && Path::new(&real).is_dir() {
                let spaced_real = dir.join("db with spaces");
                std::fs::create_dir_all(&spaced_real).unwrap();
                for entry in std::fs::read_dir(&real).unwrap().flatten() {
                    let to = spaced_real.join(entry.file_name());
                    std::fs::copy(entry.path(), &to).unwrap();
                }
                // The copy's pkcs11.txt still names the old configdir; NSS
                // reads its internal module from the string we pass, so a
                // stale path inside that file is what the shared-DB flow must
                // survive. Remove it anyway: its absence makes softokn3 use
                // the parameters we hand C_Initialize verbatim.
                let _ = std::fs::remove_file(spaced_real.join("pkcs11.txt"));
                let store = crate::pkcs11::Pkcs11Store::open_nss(
                    &module,
                    &spaced_real.display().to_string(),
                    None,
                    Some(String::new()),
                )
                .expect("softokn3 opens a database whose directory has spaces");
                assert_eq!(
                    store.certificates().expect("listing").len(),
                    2,
                    "the copied fixture holds both signers"
                );
            }
        }
    }

    #[test]
    fn tilde_and_home_expansion_reach_the_config_string() {
        // B-9: both frontends' expansions were one-sided; the shared helper
        // means `~/db` and `$HOME/db` arrive absolute at either entry point.
        // The real HOME travels untouched through a second call first, so a
        // sibling thread mid-its-own-HOME-swap cannot make this assertion read
        // another test's value: with the machine's own home expanded and
        // asserted, only our two spellings can match once the swap is in.
        let _home_lock = HOME_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let home = std::env::var_os("HOME").map(PathBuf::from);
        if let Some(h) = &home {
            let own = format!("configDir='sql:{}' flags=readOnly", h.display());
            assert_eq!(config_string("~").unwrap(), own, "the real HOME expands");
        }
        unsafe { std::env::set_var("HOME", "/home/openfirma-nss-test") };
        assert_eq!(
            config_string("~/db").unwrap(),
            "configDir='sql:/home/openfirma-nss-test/db' flags=readOnly"
        );
        assert_eq!(
            config_string("$HOME/db").unwrap(),
            "configDir='sql:/home/openfirma-nss-test/db' flags=readOnly"
        );
        unsafe {
            match home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
    }

    #[test]
    fn an_already_written_parameter_string_travels_with_expansion_only() {
        let got = config_string("configDir='sql:/somewhere' flags=readOnly").unwrap();
        assert_eq!(got, "configDir='sql:/somewhere' flags=readOnly");
    }

    #[test]
    fn a_quote_in_a_database_path_is_refused_with_the_reason() {
        // Same behaviour as always (tests/pkcs11.rs pins the wording), now
        // with the message telling both truths: empty, or unquotable.
        let err = config_string("/no/such/'db").expect_err("must fail");
        assert!(err.to_string().contains("quote"), "{err}");
        let err = config_string("   ").expect_err("empty must fail too");
        assert!(err.to_string().contains("empty"), "{err}");
    }

    /// Round 4's B-3: with several databases, discovery must put the profile
    /// Firefox itself opens FIRST — one NSS database per process means the first
    /// descriptor is the one a listing can reach, and alphabetical order used to
    /// hand that place to an old profile or to Chrome's `~/.pki/nssdb`.
    #[test]
    fn discovery_offers_the_profile_firefox_opens_before_the_others() {
        let dir = tmp("discovery-order");
        // Firefox's own layout: a.old sorts before b.default-release, and the
        // [Install…] section says the latter is the one Firefox opens.
        let ff = dir.join(".mozilla/firefox");
        std::fs::create_dir_all(&ff).unwrap();
        std::fs::write(
            ff.join("profiles.ini"),
            "[Install4F96D1932A9F858E]\nDefault=b.default-release\nLocked=1\n\n\
             [Profile0]\nName=default-release\nIsRelative=1\nPath=b.default-release\nDefault=1\n\n\
             [Profile1]\nName=old\nIsRelative=1\nPath=a.old\n",
        )
        .unwrap();
        for name in ["a.old", "b.default-release"] {
            let p = ff.join(name);
            std::fs::create_dir_all(&p).unwrap();
            std::fs::write(p.join("cert9.db"), b"").unwrap();
        }
        // Chrome's shared database, alphabetically first under HOME
        std::fs::create_dir_all(dir.join(".pki/nssdb")).unwrap();

        let _home_lock = HOME_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let home = std::env::var_os("HOME").map(PathBuf::from);
        let anchored = std::env::var_os("OPENFIRMA_FIREFOX_PARENTS");
        unsafe {
            std::env::set_var("HOME", &dir);
            std::env::remove_var("OPENFIRMA_FIREFOX_PARENTS");
        }
        let specs = discover();
        unsafe {
            match home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
            if let Some(list) = anchored {
                std::env::set_var("OPENFIRMA_FIREFOX_PARENTS", list);
            }
        }
        if !cfg!(unix) || cfg!(any(target_os = "macos", target_os = "ios")) {
            return; // the walk is unix-only
        }
        let first = specs.first().expect("at least one database");
        assert_eq!(
            first.descriptor(),
            format!("nss:sql:{}", ff.join("b.default-release").display()),
            "the profile Firefox opens is the one offered first: {specs:?}"
        );
    }

    #[test]
    fn firefox_parents_cover_snap_and_flatpak_roots() {
        // The list is built from HOME only on unix; point HOME at a tree
        // laid out like a machine with both packaging formats. CI anchors
        // OPENFIRMA_FIREFOX_PARENTS to /nonexistent, and the override wins
        // over the platform walk by design — so this test removes it for its
        // locked window; that is precisely what it exists to pin down.
        let dir = tmp("parents");
        std::fs::create_dir_all(dir.join(".mozilla/firefox")).unwrap();
        // The live snap layout: `$SNAP_USER_COMMON` is `~/snap/firefox/common`,
        // with no revision number in it (round 2, 04-N4 — the old walk looked
        // only under `<revision>/common` and found nothing on a real machine).
        std::fs::create_dir_all(dir.join("snap/firefox/common/.mozilla/firefox")).unwrap();
        // A pinned revision keeps its own common tree one level down.
        std::fs::create_dir_all(dir.join("snap/firefox/4285/common/.mozilla/firefox")).unwrap();
        std::fs::create_dir_all(dir.join(".var/app/org.mozilla.firefox/.mozilla/firefox")).unwrap();
        let _home_lock = HOME_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let home = std::env::var_os("HOME").map(PathBuf::from);
        let anchored = std::env::var_os("OPENFIRMA_FIREFOX_PARENTS");
        unsafe {
            std::env::set_var("HOME", &dir);
            std::env::remove_var("OPENFIRMA_FIREFOX_PARENTS");
        }
        let parents = firefox_parents();
        unsafe {
            match home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
            if let Some(list) = anchored {
                std::env::set_var("OPENFIRMA_FIREFOX_PARENTS", list);
            }
        }
        if cfg!(unix) && !cfg!(any(target_os = "macos", target_os = "ios")) {
            assert!(
                parents.contains(&dir.join(".mozilla/firefox")),
                "{parents:?}"
            );
            assert!(
                parents.contains(&dir.join("snap/firefox/common/.mozilla/firefox")),
                "the live snap data directory is what Firefox uses: {parents:?}"
            );
            assert!(
                parents.contains(&dir.join("snap/firefox/4285/common/.mozilla/firefox")),
                "a pinned revision keeps its own tree: {parents:?}"
            );
            assert!(
                parents.contains(&dir.join(".var/app/org.mozilla.firefox/.mozilla/firefox")),
                "{parents:?}"
            );
        }
    }

    #[test]
    fn discovery_finds_profile_databases_and_names_them() {
        let name = "discover";
        let dir = tmp(name);
        // The strictest shape the listing honours — an ini that names one
        // profile and nothing else — under every parent discovery consults on
        // this platform. Crash Reports below is a directory a real browser's
        // own bookkeeping keeps beside profiles and that must stay invisible.
        // Which directories those parents are belongs to firefox_parents, not
        // here: every variable it reads moves into this fixture further down,
        // so the fixture lays its tree wherever discovery actually looks. The
        // runner may hold real Firefox profiles in those variables (one x64
        // run counted a third spec because Windows runners ship
        // %LOCALAPPDATA%\Mozilla\Firefox\Profiles with a profile in it), which
        // is why the swap has to cover them all and this file lays profiles
        // under both spellings discovery could resolve them to.
        let firefox_trees = [
            dir.join(".mozilla").join("firefox"),
            dir.join("Mozilla").join("Firefox"),
            dir.join("Library")
                .join("Application Support")
                .join("Firefox"),
        ];
        for tree in &firefox_trees {
            std::fs::create_dir_all(tree).unwrap();
            let profile = tree.join("abcd.default-release");
            std::fs::create_dir_all(&profile).unwrap();
            std::fs::write(profile.join("cert9.db"), b"synthetic").unwrap();
            std::fs::write(
                tree.join("profiles.ini"),
                "[Profile0]\nName=release\nIsRelative=1\nPath=abcd.default-release\nDefault=1\n\n\
                 [General]\nStartWithLastProfile=1\nVersion=2\n",
            )
            .unwrap();
        }
        // A non-profile directory inside the first tree must stay invisible.
        std::fs::create_dir_all(firefox_trees[0].join("Crash Reports")).unwrap();
        std::fs::write(
            firefox_trees[0].join("Crash Reports/cert9.db"),
            b"synthetic",
        )
        .unwrap();
        // The shared DB too — asserted through a HOME of the test's own, not
        // through whatever the machine happens to have: `shared_db_exists` is
        // a $HOME thing (`$HOME/.pki/nssdb`, the Chromium location) on every
        // platform. macOS runners start test processes with no HOME at all;
        // moving one into the fixture makes it count here and nowhere else.
        std::fs::create_dir_all(dir.join(".pki/nssdb")).unwrap();
        std::fs::write(dir.join(".pki/nssdb/cert9.db"), b"synthetic").unwrap();
        let _home_lock = HOME_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // Every variable discovery consults moves into this fixture for the
        // duration of the call, so the fixture — not the runner's environment
        // — decides what gets found. A sibling test swapping them concurrently
        // would make discovery look at the wrong tree, so the whole swap lives
        // inside one locked window; every candidate path contains this test's
        // own directory name, so a leaked window elsewhere could not add to
        // this count either.
        let mut vars: Vec<&str> = vec!["HOME", "APPDATA", "LOCALAPPDATA"];
        if cfg!(windows) {
            vars.push("USERPROFILE");
        }
        // The swapped set includes OPENFIRMA_FIREFOX_PARENTS: CI anchors it
        // to /nonexistent so the runner's service-account Firefox profiles
        // are invisible, and this fixture replaces that anchor with its own
        // trees for the duration of the call.
        vars.push("OPENFIRMA_FIREFOX_PARENTS");
        let saved: Vec<(&str, Option<std::ffi::OsString>)> =
            vars.iter().map(|v| (*v, std::env::var_os(v))).collect();
        unsafe {
            for v in saved.iter().map(|(v, _)| *v) {
                std::env::set_var(v, &dir);
            }
            // Point the parent list at the platform's fixture tree only —
            // the other two spellings are the Windows and macOS trees, so
            // listing all three here would count one profile three times on
            // any single OS. The invariant this test guards (a fixture-decided
            // count, deduped) is about the lookup variables, and CI's anchor
            // makes it hold with exactly one tree everywhere.
            std::env::set_var("OPENFIRMA_FIREFOX_PARENTS", &firefox_trees[0]);
        }
        let specs: Vec<_> = discover()
            .into_iter()
            .filter(|s| match s {
                // descriptor_at keeps the shared DB's text independent of
                // whatever HOME the filter runs under; the fixture spells it.
                openfirma_core::workflow::StoreSpec::Nss { db } => {
                    s.descriptor_at(Some(dir.as_os_str())).contains(name) || db.contains(name)
                }
                _ => false,
            })
            .collect();
        // A spec that appears twice is a bug in its own right (two parents
        // offering one database), and comparing sets rather than lengths keeps
        // Windows — where APPDATA and LOCALAPPDATA are the same directory, so
        // one fixture legitimately answers through both spellings — assertable
        // against unix's two distinct paths.
        let mut unique = specs.clone();
        unique.sort_by(|a, b| format!("{a:?}").cmp(&format!("{b:?}")));
        unique.dedup_by(|a, b| format!("{a:?}") == format!("{b:?}"));
        unsafe {
            for (v, value) in saved {
                match value {
                    Some(h) => std::env::set_var(v, h),
                    None => std::env::remove_var(v),
                }
            }
        }
        // One profile plus the shared DB, after dedup. With every lookup
        // variable pointed into this fixture, nothing else can answer on any
        // platform — which is exactly what failed before: the runner's own
        // %APPDATA% had a real Firefox profile (Windows found that parent
        // first), and macOS runners start test processes with no HOME at all.
        // Both counted through the `name` filter, so only a fixture-decided
        // count is stable. A duplicate before dedup means discovery listed one
        // database twice, so that is checked too.
        assert_eq!(unique.len(), 2, "{specs:?}");
        assert_eq!(
            specs.len(),
            unique.len(),
            "discovery listed the same database twice: {specs:?}"
        );
    }
}
