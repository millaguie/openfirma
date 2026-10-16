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

/// Where `--register` writes the browser config so the registered handler can
/// find a key (finding M-3b: the Exec it installs named no keystore at all,
/// so every real sede call died demanding `--p12`). One file, one place: the
/// XDG configuration directory — `$XDG_CONFIG_HOME/openfirma/browser.toml`,
/// or `$HOME/.config/openfirma/browser.toml` when the variable is unset (the
/// specification's own fallback). A deliberate non-place is a *system* path:
/// this file names where a signing key lives, and writing it anywhere shared
/// would let another user name someone else's key for everyone's handler.
pub fn browser_config_path() -> Option<PathBuf> {
    browser_config_path_in(
        std::env::var_os("XDG_CONFIG_HOME").as_deref(),
        std::env::var_os("HOME").as_deref().map(Path::new),
    )
}

/// The same rule on inputs given, so the XDG semantics are testable without
/// racing sibling threads over the process environment (cargo runs them all
/// in one address space; an earlier draft of these tests proved that a
/// `set_var` around an assertion is observable by another test mid-flight).
fn browser_config_path_in(xdg: Option<&std::ffi::OsStr>, home: Option<&Path>) -> Option<PathBuf> {
    let mut dir = match xdg {
        Some(v) if Path::new(&v).is_absolute() => PathBuf::from(v),
        // an unset or relative XDG_CONFIG_HOME is the specification's signal
        // to fall back to $HOME/.config, and a handler must resolve the same
        // file the installer wrote no matter which branch got taken.
        _ => PathBuf::from(home?).join(".config"),
    };
    dir.push("openfirma");
    dir.push("browser.toml");
    Some(dir)
}

/// The two values one browser handler needs to be able to sign: the PKCS#12
/// container, and a file whose first line is its password. Only those two —
/// an environment variable name would put a secret's location inside a
/// install-time file whose whole point is surviving without a terminal (no
/// caller's environment can be assumed there), and a store/PIN story belongs
/// to `--store` invocations, not to the one key the scheme channel signs with.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct BrowserConfig {
    pub p12: Option<PathBuf>,
    pub password_file: Option<PathBuf>,
}

/// Parse the config file's own tiny grammar: `key = "value"` lines, comments
/// from `#` to end of line, blank lines ignored. Deliberately not a TOML
/// dependency — two keys do not need a parser crate and the vendor offline
/// rule says the same thing. The value is either a double-quoted string (a
/// plain `\` escapes the next character) or bare text taken to the end of the
/// line, trimmed. Anything unrepresentable refuses at the key that broke it:
/// this file decides which key signs browser calls, and a silently-misread
/// line is exactly the quiet failure the handler story cannot afford twice.
fn parse_config(text: &str) -> Result<BrowserConfig, String> {
    let mut out = BrowserConfig::default();
    for (n, line) in text.lines().enumerate() {
        let line = strip_comment(line);
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(format!(
                "línea {}: se esperaba `clave = \"valor\"`, no {line:?}",
                n + 1
            ));
        };
        let key = key.trim();
        let value = parse_value(value.trim()).map_err(|e| format!("línea {}: {e}", n + 1))?;
        match key {
            "p12" => out.p12 = Some(PathBuf::from(value)),
            "password_file" => out.password_file = Some(PathBuf::from(value)),
            other => {
                return Err(format!(
                    "línea {}: clave desconocida {other:?} (solo p12 y password_file)",
                    n + 1
                ));
            }
        }
    }
    Ok(out)
}

/// Comments run from an unquoted `#` to end of line. The quoting rule keeps
/// paths with `#` in them writable (`/home/ana/caso#7.p12` is a real path):
/// inside quotes, `#` is data unless it was written `\#`.
fn strip_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    let mut i = 0;
    let mut in_quotes = false;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' if in_quotes => i += 1, // the escaped character is data
            b'"' => in_quotes = !in_quotes,
            b'#' if !in_quotes => return &line[..i],
            _ => {}
        }
        i += 1;
    }
    line
}

fn parse_value(value: &str) -> Result<String, String> {
    if let Some(rest) = value.strip_prefix('"') {
        let mut out = String::with_capacity(rest.len());
        let mut chars = rest.chars();
        loop {
            match chars.next() {
                None => return Err("la clave va entre comillas dobles y falta la de cierre".into()),
                Some('"') => {
                    if chars.next().is_some() {
                        return Err("sobran caracteres tras el cierre de comillas".into());
                    }
                    return Ok(out);
                }
                Some('\\') => {
                    match chars.next() {
                        Some(c @ ('"' | '\\')) => out.push(c),
                        Some('#') => out.push('#'),
                        Some(_) | None => return Err(
                            "una barra invertida solo admite los escapes \\\", \\\\\\\\ y \\\\#"
                                .into(),
                        ),
                    }
                }
                Some(c) => out.push(c),
            }
        }
    }
    // bare value: the whole rest of the (comment-stripped) line, trimmed. A
    // quoted-looking or empty one is refused, never guessed at.
    let value = value.trim();
    if value.is_empty() || value.starts_with('#') {
        return Err("la clave va entre comillas dobles".into());
    }
    Ok(value.to_string())
}

/// The preamble every generated config carries: what the file is and which
/// two keys exist. A const so the writer, its escaping, and the test all read
/// the same bytes back.
const CONFIG_PREAMBLE: &str = "# openfirma's browser handler configuration.\n\
# Written by `openfirma afirma-uri --register`; edit freely.\n\
# The key a browser call signs with: one PKCS#12 and a file whose\n\
# first line is its password (never the password itself here).\n";

impl BrowserConfig {
    /// Read the config file at `path`. A file that does not exist is no
    /// configuration at all (`Ok(None)`) — before `--register` has run, every
    /// invocation lives in this branch, and it must not be an error. A file
    /// that exists and cannot be read or understood is the opposite: the user
    /// asked for a key by writing it, and answering `Ok(None)` would sign
    /// with nothing after being told otherwise, so load refuses with what
    /// exactly broke.
    pub fn load(path: &Path) -> Result<Option<Self>, String> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(format!(
                    "reading the browser config {}: {e}",
                    path.display()
                ));
            }
        };
        let parsed = parse_config(&text)?;
        if parsed.p12.is_none() && parsed.password_file.is_none() {
            return Err(format!(
                "the browser config {} names neither p12 nor password_file",
                path.display()
            ));
        }
        Ok(Some(parsed))
    }

    /// The bytes `--register` writes. Exactly the shape `load` reads back —
    /// and the test round-trips it, so what the installer ships cannot drift
    /// from what the handler parses. Paths are quoted with a doubled backslash
    /// and an escaped hash, the same rule that makes an install under
    /// `/home/Ana María/` work for the desktop entry.
    pub fn to_toml(&self) -> String {
        let mut out = String::from(CONFIG_PREAMBLE);
        if let Some(p) = &self.p12 {
            out.push_str(&format!(
                "p12 = \"{}\"\n",
                quote_value(&p.display().to_string())
            ));
        }
        if let Some(p) = &self.password_file {
            out.push_str(&format!(
                "password_file = \"{}\"\n",
                quote_value(&p.display().to_string())
            ));
        }
        out
    }
}

fn quote_value(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    for c in text.chars() {
        match c {
            '"' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            '#' => out.push_str("\\#"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

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

    #[test]
    fn browser_config_round_trips_the_paths_real_installs_have() {
        // What the installer writes must be what the handler reads, byte for
        // byte through the parse: every path here is one a real home directory
        // has contained, including the awkward characters that broke the
        // desktop entry once (finding M-3a) — spaces, backslashes, and a `#`
        // that must not be mistaken for the start of a comment.
        for p12 in [
            "/home/user/certificado.p12",
            "/home/Ana María/certificado.p12",
            r"C:\Archivos\openfirma\clave.p12",
            "/tmp/caso#7.p12",
            "/tmp/con \"comillas\"\\.p12",
        ] {
            let config = BrowserConfig {
                p12: Some(PathBuf::from(p12)),
                password_file: Some(PathBuf::from(format!("{p12}.pw"))),
            };
            let text = config.to_toml();
            let back =
                parse_config(&text).unwrap_or_else(|e| panic!("{p12} no vuelve a leerse: {e}"));
            assert_eq!(back, config, "round trip of {p12:?} through to_toml");
        }
    }

    #[test]
    fn browser_config_load_distinguishes_absent_from_broken() {
        // Absent is the normal state (nothing registered yet) and no error.
        let missing = std::env::temp_dir().join("openfirma-no-such-config-ever.toml");
        let _ = std::fs::remove_file(&missing);
        assert_eq!(BrowserConfig::load(&missing).unwrap(), None);

        let dir = std::env::temp_dir().join("openfirma-browser-config-tests");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cfg.toml");

        // readable and complete: Some with both keys, comments stripped.
        std::fs::write(
            &path,
            "# a comment\np12 = \"/home/x/clave.p12\" # trailing\npassword_file = \"/home/x/pw\"\n",
        )
        .unwrap();
        let got = BrowserConfig::load(&path).unwrap().expect("config exists");
        assert_eq!(got.p12, Some(PathBuf::from("/home/x/clave.p12")));
        assert_eq!(got.password_file, Some(PathBuf::from("/home/x/pw")));

        // broken content REFUSES rather than reporting no configuration: after the
        // user asked for a key by writing this file, silence would sign with
        // nothing while claiming there was no configuration.
        std::fs::write(&path, "p12 = \"/home/x/clave.p12\n").unwrap();
        let err = BrowserConfig::load(&path).unwrap_err();
        assert!(err.contains("línea 1"), "{err}");

        std::fs::write(&path, "store = \"pkcs11:/x\"\n").unwrap();
        let err = BrowserConfig::load(&path).unwrap_err();
        assert!(err.contains("desconocida"), "{err}");

        // an empty (or comment-only) file names no key at all: also a refusal,
        // because someone wrote the file expecting it to mean something.
        std::fs::write(&path, "# nothing here\n").unwrap();
        let err = BrowserConfig::load(&path).unwrap_err();
        assert!(err.contains("neither p12 nor password_file"), "{err}");

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn browser_config_path_follows_the_xdg_rule() {
        // The resolution as a pure function of its two inputs: cargo's test
        // threads share one environment, so these tests (unlike the CLI's
        // single HOME test) never mutate it — `browser_config_path_in` makes
        // every branch reachable without set_var at all.

        // XDG_CONFIG_HOME names an absolute directory: that is the config root.
        let got =
            browser_config_path_in(Some("/xdg-root".as_ref()), Some(Path::new("/home/x"))).unwrap();
        assert_eq!(got, PathBuf::from("/xdg-root/openfirma/browser.toml"));

        // a relative XDG_CONFIG_HOME is not a config root (spec: ignore it) —
        // and on Windows semantics a drive-less "/xdg-root" is not absolute
        // either, so this branch's fallback is the same code path everywhere.
        let got =
            browser_config_path_in(Some("relative/path".as_ref()), Some(Path::new("/home/x")))
                .unwrap();
        assert_eq!(got, PathBuf::from("/home/x/.config/openfirma/browser.toml"));

        // unset XDG_CONFIG_HOME: the $HOME/.config fallback (the branch a
        // handler lands on whenever the desktop session kept its variables to
        // itself). No HOME at all resolves nowhere, and says so.
        let got = browser_config_path_in(None, Some(Path::new("/home/unused-elsewhere"))).unwrap();
        assert_eq!(
            got,
            PathBuf::from("/home/unused-elsewhere/.config/openfirma/browser.toml")
        );
        assert_eq!(browser_config_path_in(None, None), None);

        // and the live function is this rule on the live environment — checked
        // only for the shape both branches share (one file, under a directory
        // called openfirma), because what the variables hold here is the
        // developer's machine.
        let live = browser_config_path().expect("this process has HOME or XDG_CONFIG_HOME");
        assert_eq!(live.file_name().unwrap(), "browser.toml");
        assert_eq!(live.parent().unwrap().file_name().unwrap(), "openfirma");
    }
}
