//! Registering `afirma://` with the operating system, and the browser handler's
//! own config file.
//!
//! The scheme itself needs no code beyond openfirma's argv parsing: what an OS
//! "scheme handler" is, is one entry that maps `afirma:` to a command line
//! receiving the URI. What AutoFirma ships is exactly that, and this module
//! generates — and, when explicitly asked (`--register`), installs — the same
//! files. Recorded sources (AutoFirma 1.9, same clone as everywhere else in
//! this crate):
//!
//! - Linux: the reference configurator registers
//!   `Exec="/opt/AutoFirma/AutoFirma" afirma-uri %u` with
//!   `MimeType=x-scheme-handler/afirma;`, i.e. the binary is quoted and the
//!   browser expands `%u` itself. Finding A-1 (observed on Chrome under X11):
//!   a `%u` inside double quotes arrives at the handler literally, with the
//!   quotes; an unquoted path containing spaces splits into several argv
//!   entries and nothing launches at all. The quoting is therefore part of
//!   the interop contract, not cosmetics.
//! - Windows: `afirma-simple-installer/Autofirma_NSIS_project_MSI_64.nsi`
//!   lines 331–334 — `HKCR\afirma` with `URL Protocol` and an open command of
//!   `"Autofirma.exe" "%1"`. Finding A-2: registration is exclusive (one
//!   default handler per scheme), so taking over from an installed AutoFirma
//!   must be explicit and reversible, never a side effect.
//! - macOS: LaunchServices reads `CFBundleURLTypes` inside a `.app`; a bare
//!   binary cannot own a URL scheme there. We provide the plist fragment and
//!   the one command that uses it, and no more.

use std::path::{Path, PathBuf};

/// URI scheme handled by the product.
pub const SCHEME: &str = "afirma";

/// MIME type registered for the scheme (RFC 6838 `x-` tree).
pub const MIME_TYPE: &str = "x-scheme-handler/afirma";

/// Desktop entry file name — unchanged from before A-1 so an upgraded
/// openfirma replaces its own old entry instead of adding a second handler.
pub const DESKTOP_FILE: &str = "openfirma-afirma.desktop";

fn browser_error(message: impl Into<String>) -> crate::dispatch::BrowserError {
    crate::dispatch::BrowserError::new("scheme-registration", message)
}

/// Whether a path can appear in a desktop entry at all. The new Exec shape
/// (A-1) quotes the whole path as one G_TOKEN_STRING, which represents spaces
/// and backslashes directly; what no desktop entry format can hold is a line
/// break inside the value or an empty path no desktop environment would
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
/// it to `<data home>/applications/openfirma-afirma.desktop`.
///
/// Finding A-1, recorded shape: AutoFirma's own registration runs
///
/// ```ini
/// Exec="/opt/AutoFirma/AutoFirma" afirma-uri %u
/// ```
///
/// and openfirma reproduces it exactly: the binary path in double quotes
/// escaped as a G_TOKEN_STRING (backslashes and `"` doubled — what GNOME's
/// GKeyFile unescapes back into the original path), the marker argument
/// `afirma-uri` next, and `%u` OUTSIDE any quotes so the browser substitutes
/// the URI itself. An earlier revision put `"%u"` in quotes with `\s`-escaped
/// paths; Chrome under X11 hands the handler a leading double quote then, and
/// every real sede call died on "URI does not start with afirma://" while the
/// registration looked healthy (that is what A-1 observed).
pub fn linux_desktop_entry(binary: &Path) -> Result<String, String> {
    desktop_entry_usable(binary)?;
    let escaped = binary
        .display()
        .to_string()
        .replace('\\', r"\\")
        .replace('"', "\\\"");
    Ok(format!(
        "[Desktop Entry]\n\
         Version=1.0\n\
         Type=Application\n\
         Name=openfirma (afirma:// handler)\n\
         GenericName=Electronic signature client\n\
         Comment=Answers afirma:// browser calls with a CAdES/PAdES/XAdES signature\n\
         Exec=\"{escaped}\" afirma-uri %u\n\
         Terminal=false\n\
         NoDisplay=true\n\
         MimeType=x-scheme-handler/afirma;\n"
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
/// new file by itself). Finding B-1: `$XDG_DATA_HOME` overrides the
/// `~/.local/share` default per the freedesktop spec, and an earlier revision
/// wrote `~/.local/share` even when the variable said otherwise — registering
/// into a directory no desktop environment reads. Callable on every platform
/// (it is only path arithmetic; the CLI prints it as advice where it cannot
/// register), so nothing here is cfg'd.
pub fn linux_install_paths() -> (PathBuf, &'static str) {
    let dir = applications_dir();
    let hint = "xdg-mime default openfirma-afirma.desktop x-scheme-handler/afirma";
    (dir.join(DESKTOP_FILE), hint)
}

/// `$XDG_DATA_HOME/applications`, with the specification's fallback — the
/// exact resolution XDG tells desktop environments to read ([finding B-1]).
/// A non-absolute `XDG_DATA_HOME` is ignored, like every other XDG variable.
fn applications_dir() -> PathBuf {
    applications_dir_in(
        std::env::var_os("XDG_DATA_HOME").as_deref(),
        std::env::var_os("HOME").as_deref().map(Path::new),
    )
}

/// The same rule on given inputs, so it is testable without racing sibling
/// tests over the process environment (see browser_config_path_in).
fn applications_dir_in(xdg: Option<&std::ffi::OsStr>, home: Option<&Path>) -> PathBuf {
    let mut dir = match xdg {
        Some(v) if Path::new(&v).is_absolute() => PathBuf::from(v),
        _ => PathBuf::from(home.unwrap_or(Path::new("~"))).join(".local/share"),
    };
    dir.push("applications");
    dir
}

/// Whether an AutoFirma installation is present whose `afirma://` registration
/// `--register` would replace: the two places the reference packages live
/// (the Unix package's `/opt/AutoFirma` and the JNLP installer's per-user
/// directory — the same pair `~/.config/autofirma.last` tracks). Finding A-2:
/// a scheme has exactly ONE default handler, so takeover must be visible.
pub fn detect_autofirma_install() -> Vec<PathBuf> {
    let mut found = Vec::new();
    if Path::new("/opt/AutoFirma").is_dir() {
        found.push(PathBuf::from("/opt/AutoFirma"));
    }
    if let Some(home) = std::env::var_os("HOME") {
        let per_user = PathBuf::from(home).join(".local/share/autofirma");
        if per_user.is_dir() {
            found.push(per_user);
        }
    }
    found
}

/// Which handler the OS would launch for an `afirma:` URI right now (Linux:
/// what `xdg-mime query default` answers; elsewhere: None — the CLI prints
/// each platform's own way of checking).
pub fn get_current_handler() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let out = std::process::Command::new("xdg-mime")
            .args(["query", "default", MIME_TYPE])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
        (!text.is_empty()).then_some(text)
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// Whether THIS product is registered: our desktop entry exists (Linux). Not
/// the same question as `get_current_handler` — another handler may be the
/// default while our file still sits there, and vice versa.
pub fn get_registered_scheme() -> bool {
    linux_install_paths().0.is_file()
}

/// Install the Linux desktop entry AND register it as the scheme's default
/// handler ([finding A-1]: writing the file is not registration; before xdg-mime
/// recorded it, Firefox kept launching whatever handler was registered last).
/// Creates the applications directory when missing ([finding B-1]). Returns
/// whether `xdg-mime` accepted the registration (a false here with the file
/// written means reindex/desktop-environment trouble the caller must report).
#[cfg(target_os = "linux")]
pub fn linux_install_and_register() -> Result<(), crate::dispatch::BrowserError> {
    let (path, _reindex) = linux_install_paths();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .map_err(|e| browser_error(format!("no se puede crear {}: {e}", dir.display())))?;
    }
    let exe = std::env::current_exe().map_err(|e| {
        browser_error(format!(
            "the registration must name openfirma's own absolute path: {e}"
        ))
    })?;
    // The same generation-time refusal as before: an Exec no desktop
    // environment can parse looks installed and never fires.
    let contents = linux_desktop_entry(&exe)
        .map_err(|e| browser_error(format!("el ejecutable no se puede registrar: {e}")))?;
    std::fs::write(&path, contents)
        .map_err(|e| browser_error(format!("writing {}: {e}", path.display())))?;
    let _ = std::process::Command::new("update-desktop-database")
        .arg(path.parent().unwrap())
        .output();
    if !is_xdg_mime_available() {
        return Err(browser_error(
            "xdg-mime no esta disponible: sin él el escritorio no sabe que \
             afirma:// es nuestro; instala xdg-utils y repite --register",
        ));
    }
    // `xdg-mime default` does the registration itself (it resolves the desktop
    // file through the data dirs), and it also refreshes mimeapps.list — what
    // earlier revisions left to a printed hint nobody ran.
    // The file exists and `is_xdg_mime_available` promised it runs. With the
    // promise still set (a test's OPENFIRMA_ASSUME_XDG_MIME), a missing binary
    // means only what the caller already accepted — no desktop to register
    // into — so skip the association step instead of dying; CI images without
    // xdg-utils would otherwise fail tests that pin other rules than this
    // one's environment. Without the promise, the error stays fatal: a real
    // user's --register must hear about a broken xdg-utils, not assume success.
    if std::env::var_os("OPENFIRMA_ASSUME_XDG_MIME").is_some() && !which_on_path("xdg-mime") {
        return Ok(());
    }
    let status = std::process::Command::new("xdg-mime")
        .args(["default", DESKTOP_FILE, MIME_TYPE])
        .output()
        .map_err(|e| browser_error(format!("running xdg-mime: {e}")))?;
    if !status.status.success() {
        return Err(browser_error(format!(
            "xdg-mime default {DESKTOP_FILE} {MIME_TYPE} fallo: {}",
            String::from_utf8_lossy(&status.stderr).trim()
        )));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn linux_install_and_register() -> Result<(), crate::dispatch::BrowserError> {
    Err(browser_error(
        "there is no .desktop registration on this operating system",
    ))
}

/// Whether `xdg-mime` names a program on PATH (a bare existence check: the
/// installer skips its association step when it does not and the caller has
/// already promised to tolerate that — see OPENFIRMA_ASSUME_XDG_MIME below).
#[expect(
    dead_code,
    reason = "the only caller is the linux install path (cfg'd); on macOS/Windows this helper compiles with no calls — H-9's per-platform clippy caught it"
)]
fn which_on_path(program: &str) -> bool {
    std::env::var_os("PATH")
        .into_iter()
        .flat_map(|paths| {
            std::env::split_paths(&paths)
                .map(|dir| dir.join(program))
                .collect::<Vec<_>>()
        })
        .any(|candidate| candidate.is_file())
}

/// Whether `xdg-mime` can run here (the CLI's --register/--unregister paths
/// name this when it cannot, instead of half-registering). CI images without
/// xdg-utils have no desktop to register into either; tests that only need a
/// successful registration set this override, which is exactly the promise
/// `linux_install_and_register` makes below ("unreachable on this branch").
pub fn is_xdg_mime_available() -> bool {
    if std::env::var_os("OPENFIRMA_ASSUME_XDG_MIME").is_some() {
        return true;
    }
    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-mime")
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Remove THIS product's registration: our desktop entry, and the default
/// association only while it still points at us ([finding A-2]: uninstalling
/// openfirma must never unregister a reinstalled AutoFirma).
#[cfg(target_os = "linux")]
pub fn linux_unregister() -> Result<(), crate::dispatch::BrowserError> {
    let (path, _) = linux_install_paths();
    if path.exists() {
        std::fs::remove_file(&path)
            .map_err(|e| browser_error(format!("removing {}: {e}", path.display())))?;
    }
    if get_current_handler().as_deref() == Some(DESKTOP_FILE) && is_xdg_mime_available() {
        // An empty application resets the association to "nothing registered".
        let _ = std::process::Command::new("xdg-mime")
            .args(["default", "", MIME_TYPE])
            .output();
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn linux_unregister() -> Result<(), crate::dispatch::BrowserError> {
    Err(browser_error(
        "there is no .desktop registration on this operating system",
    ))
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

/// What one browser handler needs to be able to sign: the PKCS#12 container,
/// a file whose first line is its password, and — finding A-3 — whether that
/// key may sign a browser call WITHOUT asking anybody. AutoFirma asks at every
/// call (its certificate dialog plus the PIN prompt); openfirma's headless
/// handler has no dialog, so it refuses to sign quietly unless the key's owner
/// wrote `allow_unattended = true` here. The opt-in is per key file and only
/// ever explicit: nothing defaults to it, and `--register` prints what it
/// means when it writes it.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct BrowserConfig {
    pub p12: Option<PathBuf>,
    pub password_file: Option<PathBuf>,
    /// A-3: the owner's standing consent for THIS key to sign browser calls
    /// without a prompt. `false` (the default) means every call must be
    /// confirmed by a human or refused.
    pub allow_unattended: bool,
}

/// Parse the config file's own tiny grammar: `key = "value"` lines, comments
/// from `#` to end of line, blank lines ignored. Deliberately not a TOML
/// dependency — three keys do not need a parser crate and the vendor offline
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
        // The boolean keys take their own values, never a path quote.
        if key == "allow_unattended" {
            out.allow_unattended = match value.trim() {
                "true" => true,
                "false" => false,
                other => {
                    return Err(format!(
                        "línea {}: allow_unattended solo admite true o false, no {other:?}",
                        n + 1
                    ));
                }
            };
            continue;
        }
        let value = parse_value(value.trim()).map_err(|e| format!("línea {}: {e}", n + 1))?;
        match key {
            "p12" => out.p12 = Some(PathBuf::from(value)),
            "password_file" => out.password_file = Some(PathBuf::from(value)),
            other => {
                return Err(format!(
                    "línea {}: clave desconocida {other:?} (solo p12, password_file y \
                     allow_unattended)",
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
/// keys exist. A const so the writer, its escaping, and the test all read the
/// same bytes back.
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
    /// exactly broke. The file also has to be owner-private on unix — see
    /// [`check_private`].
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
        check_private(path)?;
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
    /// `/home/Ana María/` work for the desktop entry. `allow_unattended` is
    /// written only when true: a file without it means false, which is the
    /// state whose meaning nobody has to remember.
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
        if self.allow_unattended {
            out.push_str(
                "# A-3: this line is the owner's standing consent. Every browser call\n\
                 # signs with this key WITHOUT asking anybody first.\n\
                 allow_unattended = true\n",
            );
        }
        out
    }
}

/// Owner-private or refuse ([finding B-2]): both this config and a password
/// file name — or are — the material that opens a signing key. The XDG user
/// dirs on a multi-user machine (a shared /home, an NFS mount with defaults)
/// regularly arrive world-readable; a handler that read them anyway would
/// sign whatever any other account asked for. Group- or world-readable modes
/// refuse; the fix is one `chmod` and the message says which.
pub fn check_private(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)
            .map_err(|e| format!("reading {}: {e}", path.display()))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return Err(format!(
                "{} es legible por otros usuarios (modo {:04o}): este archivo protege \
                 una clave de firma; ejecuta chmod go-rwx {} y repite",
                path.display(),
                mode & 0o777,
                path.display()
            ));
        }
    }
    // Windows has no POSIX mode here: the rule that carries over is the ACL
    // one, and checking it means reading a security descriptor — out of scope
    // until someone can test it. The path argument exists on every platform;
    // saying so keeps the non-unix build from warning it away.
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
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
    fn linux_entry_matches_autofirmas_recorded_exec_shape() {
        // [finding A-1] recorded reference shape:
        //   Exec="/opt/AutoFirma/AutoFirma" afirma-uri %u
        // The path quoted, the marker next, %u outside quotes.
        let entry = linux_desktop_entry(Path::new("/usr/local/bin/openfirma")).unwrap();
        assert!(entry.contains("MimeType=x-scheme-handler/afirma;"));
        assert!(entry.contains(r#"Exec="/usr/local/bin/openfirma" afirma-uri %u"#));
        assert!(entry.contains("NoDisplay=true"));
    }

    #[test]
    fn exec_path_quoted_and_placeholder_never_inside_quotes() {
        // The two halves of finding A-1, checked on the paths real installs
        // have: a quoted `%u` arrives at Chrome literally (the URI reached the
        // handler as `""afirma://…"` and died on the scheme check), and an
        // unquoted path with spaces never launches anything.
        for path in [
            "/home/user/bin/openfirma",
            "/home/Ana María/bin/openfirma",
            "/opt/Local Tools/openfirma",
            r"C:\Archivos\openfirma",
        ] {
            let entry = linux_desktop_entry(Path::new(path))
                .unwrap_or_else(|e| panic!("{path} debe generar un entry válido: {e}"));
            let exec = entry
                .lines()
                .find(|l| l.starts_with("Exec="))
                .expect("el entry lleva siempre su Exec")
                .strip_prefix("Exec=")
                .unwrap();
            assert!(
                exec.starts_with('"'),
                "la ruta debe ir entrecomillada: {exec}"
            );
            // The closing quote is the last `"` before the marker argument.
            let marker = " afirma-uri %u";
            assert!(
                exec.ends_with(marker),
                "el Exec debe terminar en el marcador exacto, con %u fuera de \
                 comillas: {exec}"
            );
            let quoted_path = &exec[1..exec.len() - marker.len() - 1];
            assert!(
                !quoted_path.contains("%u"),
                "%u no puede caer dentro de la comilla de la ruta: {exec}"
            );
            // G_TOKEN_STRING unescaping (what GKeyFile does): `\\` → `\`,
            // `\"` → `"`, everything else literal. Round-tripping must give
            // the original path back, spaces included.
            let mut restored = String::new();
            let mut chars = quoted_path.chars();
            while let Some(c) = chars.next() {
                if c == '\\' {
                    match chars.next() {
                        Some(n) => restored.push(n),
                        None => panic!("escape suelto en {exec}"),
                    }
                } else {
                    restored.push(c);
                }
            }
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

    #[cfg(target_os = "linux")]
    #[test]
    fn applications_dir_follows_the_xdg_data_home_rule() {
        // [finding B-1] the same pure-input style as browser_config_path_in:
        // no environment mutation, every branch reachable.
        let absolute = Path::new("/xdg-data-root").is_absolute();
        let got = applications_dir_in(Some("/xdg-data-root".as_ref()), Some(Path::new("/home/x")));
        if absolute {
            assert_eq!(got, PathBuf::from("/xdg-data-root/applications"));
        }
        // a relative XDG_DATA_HOME is never a data root (spec: ignore it).
        let got = applications_dir_in(Some("relative/path".as_ref()), Some(Path::new("/home/x")));
        assert_eq!(got, PathBuf::from("/home/x/.local/share/applications"));
        // unset: the ~/.local/share fallback.
        let got = applications_dir_in(None, Some(Path::new("/home/ana")));
        assert_eq!(got, PathBuf::from("/home/ana/.local/share/applications"));
        // and the live resolution ends where XDG says, whichever branch ran.
        let live = linux_install_paths().0;
        assert_eq!(live.file_name().unwrap(), DESKTOP_FILE);
    }

    #[test]
    fn autofirma_detection_names_known_layouts_only() {
        for p in detect_autofirma_install() {
            let text = p.display().to_string();
            assert!(
                text.contains("AutoFirma") || text.ends_with(".local/share/autofirma"),
                "deteccion fuera de los directorios registrados: {text}"
            );
        }
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
                allow_unattended: true,
            };
            let text = config.to_toml();
            let back =
                parse_config(&text).unwrap_or_else(|e| panic!("{p12} no vuelve a leerse: {e}"));
            assert_eq!(back, config, "round trip of {p12:?} through to_toml");
        }
    }

    #[test]
    fn allow_unattended_is_explicit_and_never_defaulted() {
        // [finding A-3] the opt-in is a value with exactly two spellings; no
        // parse branch invents `true`.
        assert!(!parse_config("p12 = \"/x.p12\"\n").unwrap().allow_unattended);
        assert!(
            parse_config("allow_unattended = true\n")
                .unwrap()
                .allow_unattended
        );
        assert!(
            !parse_config("allow_unattended = false\n")
                .unwrap()
                .allow_unattended
        );
        let err = parse_config("allow_unattended = yes\n").unwrap_err();
        assert!(err.contains("true o false"), "{err}");
        // to_toml writes the key only when it means it.
        assert!(
            !BrowserConfig::default()
                .to_toml()
                .contains("allow_unattended")
        );
    }

    #[cfg(unix)]
    #[test]
    fn browser_config_load_distinguishes_absent_from_broken() {
        use std::os::unix::fs::PermissionsExt;
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
        // The private tmp dir's umask is not ours to trust (B-2 refuses a
        // group/world-readable config, and /tmp here is 0777-umask), so the
        // fixture starts in the mode a real handler would only ever accept.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
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

    #[cfg(unix)]
    #[test]
    fn world_readable_config_or_password_file_refuses() {
        use std::os::unix::fs::PermissionsExt;
        // [finding B-2] mode 0644 config = any local user can point everyone's
        // handler at their key; the handler refuses to read it until chmod.
        let dir = std::env::temp_dir().join("openfirma-private-check");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cfg.toml");
        std::fs::write(
            &path,
            "p12 = \"/home/x/clave.p12\"\npassword_file = \"/home/x/pw\"\n",
        )
        .unwrap();

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = BrowserConfig::load(&path).unwrap_err();
        assert!(err.contains("go-rwx"), "debe decir el chmod exacto: {err}");

        // 0640 (group-readable) refuses too — on a shared machine "group" is
        // as public as "other".
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(BrowserConfig::load(&path).unwrap_err().contains("go-rwx"));

        // 0600 is the state the message asks for, and loads.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(BrowserConfig::load(&path).unwrap().is_some());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn browser_config_path_follows_the_xdg_rule() {
        // The resolution as a pure function of its two inputs: cargo's test
        // threads share one environment, so these tests (unlike the CLI's
        // single HOME test) never mutate it — `browser_config_path_in` makes
        // every branch reachable without set_var at all.

        // "Absolute" is path semantics, and the matrix runs Windows too: on a
        // POSIX host "/xdg-root" is the config root; on a Windows host its own
        // rules decide (a drive-less root is not absolute there, so that input
        // takes the $HOME fallback — still the rule working, not breaking).
        let posix_absolute = Path::new("/xdg-root").is_absolute();
        let got =
            browser_config_path_in(Some("/xdg-root".as_ref()), Some(Path::new("/home/x"))).unwrap();
        if posix_absolute {
            assert_eq!(got, PathBuf::from("/xdg-root/openfirma/browser.toml"));
        } else {
            assert!(
                got.display().to_string().contains("openfirma"),
                "the Windows resolution still names the same file: {got:?}"
            );
        }

        // a relative XDG_CONFIG_HOME is never a config root (spec: ignore it):
        // the $HOME fallback on every platform, since no host calls a bare
        // "relative/path" absolute.
        let got =
            browser_config_path_in(Some("relative/path".as_ref()), Some(Path::new("/home/x")))
                .unwrap();
        if posix_absolute {
            assert_eq!(got, PathBuf::from("/home/x/.config/openfirma/browser.toml"));
        }

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
        // only when one of its two inputs actually exists here (Windows CI
        // exports neither HOME nor XDG_CONFIG_HOME; the process that needs the
        // file fails at startup, so the CLI refuses with a named reason rather
        // than inventing a location). Where an input does exist, check only
        // the shape both branches share, because what the variables hold is
        // the developer's machine.
        let live = browser_config_path();
        if let Some(live) = live {
            assert_eq!(live.file_name().unwrap(), "browser.toml");
            assert_eq!(live.parent().unwrap().file_name().unwrap(), "openfirma");
        }
    }
}
