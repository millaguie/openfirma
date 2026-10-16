//! Registering `afirma://` with the operating system.
//!
//! The scheme itself needs no code beyond openfirma's argv parsing: what an OS
//! "scheme handler" is, is one entry that maps `afirma:` to a command line
//! receiving the URI as `%u`/`%1`. What AutoFirma ships is exactly that, and
//! this module generates the same files — it does not write them into the
//! system on its own, because a signing client installing itself from an
//! arbitrary invocation is the kind of persistence the user asked for once at
//! install time, not something a signature operation should do as a side
//! effect. `openfirma afirma-uri --register` prints where each file belongs and
//! installs it only with that flag; the files below are what CI can lint and
//! a reviewer can read.
//!
//! Recorded sources (AutoFirma 1.9, same clone as everywhere else in this
//! crate):
//! - Linux: `afirma-simple-installer/linux/instalador_deb/src/usr/share/applications/afirma.desktop`
//!   — `MimeType=x-scheme-handler/afirma;`, `Exec=/usr/bin/autofirma %u`. The
//!   scheme mechanism itself is freedesktop's; openfirma's file differs from
//!   AutoFirma's in the Exec path only, plus the NoDisplay flag AutoFirma's GUI
//!   entry does not need and ours does (an application that exists to answer a
//!   URI should not show up in the desktop menu).
//! - Windows: `afirma-simple-installer/Autofirma_NSIS_project_MSI_64.nsi`
//!   lines 331–334 — `HKCR\afirma` with `URL Protocol` and an open command of
//!   `Autofirma.exe "%1"`. The .reg file below is the same four values.
//! - macOS: AutoFirma's installer registers through its app bundle; a `.desktop`-style
//!   plist is not how macOS ships handlers (LaunchServices reads
//!   `CFBundleURLTypes` inside a `.app`). openfirma is a bare binary, so on
//!   macOS the documented route is wrapping it in a minimal .app once — we
//!   provide the plist fragment and the one command that uses it, and no more.

use std::path::{Path, PathBuf};

/// Escape a path for the `Exec` value of a desktop entry. The desktop entry
/// spec keeps quoting inside this one unquoted token: spaces are written
/// `\s`, a tab `\t`, a newline `\n`, and the escaping character itself
/// (`\\`) goes out doubled. Leaving any of them raw is how an install under
/// `/home/Ana María/` used to produce an entry whose `Exec` the desktop
/// environment could not parse at all (finding M-3): the registration looked
/// installed and never fired.
fn desktop_key(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 8);
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            ' ' => out.push_str("\\s"),
            '\t' => out.push_str("\\t"),
            '\n' | '\r' => out.push_str("\\n"),
            _ => out.push(c),
        }
    }
    out
}

/// Whether a path can appear in a desktop entry at all. The escaping above
/// covers the characters the format represents; what it cannot represent is a
/// line break inside the value or an empty path no desktop environment would
/// resolve. `--register` refuses those at generation time rather than writing
/// a file whose handling breaks on first use, which is the whole difference
/// between a broken install and a silent one.
fn desktop_entry_usable(binary: &Path) -> Result<(), String> {
    let text = binary.to_string_lossy();
    if text.trim().is_empty() {
        return Err("la ruta del ejecutable está vacía".into());
    }
    if text.chars().any(|c| c == '\n' || c == '\r') {
        return Err(
            "la ruta del ejecutable contiene saltos de línea, y un entry de escritorio \
             no los representa"
                .into(),
        );
    }
    Ok(())
}

/// The Linux desktop entry that registers the scheme, as `--register` writes
/// it to `~/.local/share/applications/openfirma-afirma.desktop`. An unusable
/// path (empty, or one no desktop entry format can hold) is a refusal here,
/// at generation time, instead of a file that installs and never fires.
pub fn linux_desktop_entry(binary: &Path) -> Result<String, String> {
    desktop_entry_usable(binary)?;
    Ok(format!(
        "[Desktop Entry]\n\
         Version=1.0\n\
         Type=Application\n\
         Name=openfirma (afirma:// handler)\n\
         GenericName=Electronic signature client\n\
         Comment=Answers afirma:// browser calls with a CAdES/PAdES/XAdES signature\n\
         Exec={binary} afirma-uri \"%u\"\n\
         Terminal=false\n\
         NoDisplay=true\n\
         Categories=Office;Utilities;Signature;\n\
         MimeType=x-scheme-handler/afirma;\n",
        binary = desktop_key(&binary.display().to_string()),
    ))
}

/// The Windows registry file for the same scheme, the four values AutoFirma's
/// NSIS installer writes. `--register` does not touch a registry from Rust on
/// purpose: importing a .reg is an explicit act with UAC, and hiding it behind
/// a signing client is not what users expect. We generate; Windows imports.
pub fn windows_registry_file(exe_path: &Path) -> String {
    // Registry escaping: backslashes double, and the inner quotes around the
    // URI argument need \" inside the quoted command string — the same shape
    // NSIS produced with its "$INSTDIR…\Autofirma.exe \"%1\"".
    let escaped = exe_path.display().to_string().replace('\\', "\\\\");
    format!(
        "Windows Registry Editor Version 5.00\r\n\r\n\
         [HKEY_CLASSES_ROOT\\afirma]\r\n\
         @=\"URL:openfirma Protocol\"\r\n\
         \"URL Protocol\"=\"\"\r\n\r\n\
         [HKEY_CLASSES_ROOT\\afirma\\shell\\open\\command]\r\n\
         @=\"\\\"{escaped}\\\" afirma-uri \\\"%1\\\"\"\r\n\r\n"
    )
}

/// The macOS LaunchServices fragment: not a self-registering file, and the
/// module says so in its output too. It is documented in docs/adr/0005 rather
/// than applied; there is no honest way to register a URL scheme from a bare
/// binary without owning an app bundle, which openfirma's release process does
/// not build yet.
pub fn macos_plist_fragment() -> &'static str {
    "<!-- Inside a minimal openfirma.app/Contents/Info.plist:
      <key>CFBundleURLTypes</key>
      <array>
        <dict>
          <key>CFBundleURLName</key><string>net.millaguie.openfirma.afirma</string>
          <key>CFBundleURLSchemes</key><array><string>afirma</string></array>
        </dict>
      </array>
     macOS never runs a bare binary for a URL scheme; it launches the .app that
     owns it. Until openfirma ships bundles, this is instructions, not code. -->\n"
}

/// Where `--register` puts the Linux file and what to run afterwards so
/// desktop environments re-read the database (xdg's cache does not notice a
/// new file by itself).
pub fn linux_install_paths() -> (PathBuf, &'static str) {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("~"));
    (
        home.join(".local/share/applications/openfirma-afirma.desktop"),
        "update-desktop-database ~/.local/share/applications",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn linux_entry_registers_the_scheme_and_calls_the_real_subcommand() {
        let entry = linux_desktop_entry(Path::new("/usr/local/bin/openfirma")).unwrap();
        assert!(entry.contains("MimeType=x-scheme-handler/afirma;"));
        // The Exec must name a subcommand the CLI actually has: a registration
        // pointing at an argument AutoFirma's binary took and ours does not is
        // the quietest possible way for scheme handling to be broken.
        assert!(entry.contains("Exec=/usr/local/bin/openfirma afirma-uri \"%u\""));
        assert!(entry.contains("NoDisplay=true"));
    }

    #[test]
    fn linux_entry_survives_the_paths_real_installs_have() {
        // Finding M-3: spaces and other escaping characters used to go out
        // raw, which is an Exec no desktop environment reassembles. Each of
        // these is a directory someone actually installs into.
        for path in [
            "/home/Ana María/bin/openfirma",
            "/opt/Local Tools/openfirma",
            r"C:\Archivos\openfirma",
        ] {
            let entry = linux_desktop_entry(Path::new(path))
                .unwrap_or_else(|e| panic!("{path} debe generar un entry válido: {e}"));
            let exec = entry
                .lines()
                .find(|l| l.starts_with("Exec="))
                .expect("el entry lleva siempre su Exec");
            // The value is the spec's escaped form, checked by round-trip at
            // the end of this block: whatever escaping we choose, re-reading
            // the entry has to hand back the binary path exactly.
            let value = exec.strip_prefix("Exec=").unwrap();
            let command = value
                .split(" afirma-uri ")
                .next()
                .expect("el Exec siempre llama a afirma-uri");
            if path.contains(' ') {
                assert!(
                    command.contains("\\s"),
                    "un espacio debe salir como \\s: {exec}"
                );
            }
            if path.contains('\\') {
                assert!(
                    command.contains(r"\\"),
                    "una barra invertida debe ir duplicada: {exec}"
                );
            }
            // and what the escaping produced is reversible: unescaping gives
            // back exactly the binary path
            let restored = command
                .replace(r"\\", "\u{0}")
                .replace("\\s", " ")
                .replace('\u{0}', "\\");
            assert_eq!(restored, path, "{exec}");
        }
    }

    #[test]
    fn linux_entry_refuses_a_path_it_could_not_write() {
        // generation-time refusal: what cannot be a desktop entry value never
        // becomes a file that silently does nothing
        let err = linux_desktop_entry(Path::new("")).unwrap_err();
        assert!(err.contains("ejecutable"), "{err}");
        let with_newline = std::path::PathBuf::from("/opt/open\nfirma");
        let err = linux_desktop_entry(&with_newline).unwrap_err();
        assert!(err.contains("saltos de línea"), "{err}");
    }

    #[test]
    fn windows_reg_is_the_measured_four_values() {
        let reg = windows_registry_file(Path::new(r"C:\Program Files\openfirma\openfirma.exe"));
        assert!(reg.starts_with("Windows Registry Editor Version 5.00\r\n"));
        assert!(reg.contains("[HKEY_CLASSES_ROOT\\afirma]"));
        assert!(reg.contains("\"URL Protocol\"=\"\""));
        assert!(reg.contains(
            "@=\"\\\"C:\\\\Program Files\\\\openfirma\\\\openfirma.exe\\\" \
             afirma-uri \\\"%1\\\"\""
        ));
    }
}
