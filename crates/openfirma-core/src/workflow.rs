//! The decision steps both frontends make, so the CLI and the GUI cannot
//! drift: what format a file gets signed as, which certificate a store is
//! asked to sign with, where an output path goes.
//!
//! This is the shared layer behind `openfirma sign`/`verify` on the command
//! line and `openfirma-gui` on the screen (docs/adr/0006-gui-toolkit.md records why the GUI
//! must not duplicate these rules). Nothing here knows about argv or widgets:
//! it takes paths, bytes and certificates and answers questions. The formats
//! themselves stay in their crates; what lives here is the choosing around
//! them.

use std::path::{Path, PathBuf};

use der::Decode;
use x509_cert::ext::pkix::BasicConstraints;

use crate::CertificateHandle;

/// basicConstraints (RFC 5280 4.2.1.9), the extension that says whether a
/// certificate may issue others at all — and therefore whether it can stand
/// as a trust anchor.
const OID_BASIC_CONSTRAINTS: &str = "2.5.29.19";
use zeroize::Zeroizing;

/// What kind of file a set of bytes is, decided by its magic rather than its
/// extension: an extension lies (renaming a PDF to `.txt` is common), the
/// first bytes do not. This is the same detection `openfirma verify` applies
/// when it decides between the PDF and the CMS reader (`%PDF-` → PAdES, else
/// CAdES).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    /// A PDF document: `%PDF-` at byte 0. Signed as PAdES.
    Pdf,
    /// An XML document — the leading whitespace and an optional byte-order
    /// mark are skipped before the `<` of the root element or its `<?xml`.
    /// Signed as XAdES-B-B.
    Xml,
    /// Anything else: plain bytes. Signed as a detached CAdES.
    Data,
}

impl Format {
    /// The format openfirma signs this kind of file as, in its default shape:
    /// PDF is PAdES-B-B, XML is XAdES-B-B, everything else a detached CAdES.
    pub fn default_signature_format(self) -> &'static str {
        match self {
            Format::Pdf => "pades-b-b",
            Format::Xml => "xades-b-b",
            Format::Data => "cades-b-b",
        }
    }

    /// Every openfirma format this kind of file can be signed as, in the
    /// order a UI should list them (the default first). A PDF cannot be an
    /// XAdES and bytes cannot become a PAdES; pretending otherwise hands the
    /// user a guaranteed error. The long-term PAdES levels are listed with
    /// `pades-b-lt`/`pades-b-lta` where a TSA is available — the caller who
    /// knows about a TSA extends the list, this function only answers what
    /// the file shape allows without extra material.
    pub fn supported_formats(self) -> &'static [&'static str] {
        match self {
            Format::Pdf => &["pades-b-b", "pades-b-lt", "pades-b-lta"],
            Format::Xml => &["xades-b-b"],
            Format::Data => &["cades-b-b"],
        }
    }

    /// The default output path for a signature over `input`: next to the
    /// original, named after it, with the extension AutoFirma's own save
    /// dialog proposes (`.pdf` documents keep `.pdf`, XML keeps `.xml`,
    /// everything else becomes `.signature`). openfirma names detached CMS
    /// `.csig` instead of AutoFirma's ambiguous `.signature`: a file named
    /// `contrato.signature` says nothing about its shape to the next reader,
    /// and the GUI writes next to the original without asking (the deliberate
    /// deviation from AutoFirma's save-dialog-every-time is docs/adr/0006-gui-toolkit.md).
    pub fn default_output(self, input: &Path) -> PathBuf {
        let base = input.with_extension("");
        let ext = match self {
            Format::Pdf => "signed.pdf",
            Format::Xml => "signed.xml",
            Format::Data => "csig",
        };
        base.with_extension(ext)
    }

    /// Detects the format of `bytes`: `%PDF-` at byte 0 wins, then a leading
    /// XML declaration or root element after optional BOM and whitespace, and
    /// everything else is data. A PDF that has been encrypted (the bytes are
    /// still readable — encryption in the PDF spec hides content, not the
    /// header) still detects as Pdf; refusing it is the signer's job when it
    /// cannot open it, not the detector's.
    pub fn detect(bytes: &[u8]) -> Format {
        if bytes.starts_with(b"%PDF-") {
            return Format::Pdf;
        }
        let mut rest = bytes;
        // A UTF-8 or UTF-16 BOM before the XML declaration is legal and common.
        for bom in [&b"\xef\xbb\xbf"[..], b"\xff\xfe", b"\xfe\xff"] {
            if rest.starts_with(bom) {
                rest = &rest[bom.len()..];
                break;
            }
        }
        let trimmed = rest.len() - rest.trim_ascii_start().len();
        let body = &rest[trimmed..];
        if body.starts_with(b"<?xml") || (body.starts_with(b"<") && looks_like_markup(body)) {
            Format::Xml
        } else {
            Format::Data
        }
    }
}

/// Whether a `<` opens markup rather than, say, a C-ish comparison in a text
/// file: the next non-comment byte must be a name-start character or one of
/// `?!/`, within the first few bytes. Cheap and conservative: a plain-text
/// file beginning with "<hola" is data; `<html>`, `<foo/>`, `<!-- x --><a>`
/// are markup.
fn looks_like_markup(body: &[u8]) -> bool {
    let after = body[1..].iter().take(16).find(|b| !b.is_ascii_whitespace());
    matches!(after, Some(c) if c.is_ascii_alphabetic() || matches!(c, b'!' | b'?' | b'/'))
}

/// The default trust anchors of the GUI's verify path, in this order:
///
/// 1. `$OPENFIRMA_TRUST`, a `:`-separated list of PEM/DER files (the knob
///    tests and power users use, mirroring how other tools take an explicit
///    CAfile),
/// 2. the system trust store where one can be read without a dependency that
///    breaks the pure-Rust rule — which today means nothing portable in-tree,
///    so with no variable set there are no anchors and the caller must show
///    its "what certificate do you trust?" affordance instead of pretending.
///
/// The default trust anchors of both frontends' verify path: today exactly
/// one source, `$OPENFIRMA_TRUST`, a search-path list of PEM/DER files (the
/// platform separator — `:` on unix, `;` on Windows, so paths carrying a
/// drive letter survive). There is deliberately no second source yet — reading
/// the platform's root store would need either a C-backed trust crate or per-
/// platform FFI beyond what openfirma-keystore does with certificates, and
/// inventing anchors is worse than having none: an empty list makes
/// `openfirma_cades::verify` refuse every chain, which is the correct
/// behaviour (trusting nothing verifies nothing), and the GUI's verify screen
/// then says so and asks the user for a certificate to trust instead of
/// reporting an unfounded verdict.
pub fn default_trust_anchors() -> Vec<PathBuf> {
    match std::env::var_os("OPENFIRMA_TRUST") {
        Some(list) if !list.to_string_lossy().trim().is_empty() => {
            std::env::split_paths(&list).collect()
        }
        _ => Vec::new(),
    }
}

/// One trust anchor as openfirma reads it: PEM (a `-----BEGIN` head) or DER,
/// and a file that is neither is refused with its name — the same rule and
/// the same sentence both frontends show for `--trust` and for the GUI's
/// "choose the certificate you trust" picker.
/// Load every certificate a trust-anchor file names. PEM bundles (a CA file
/// with several certificates — what distros ship as roots and FNMT hands out
/// as `cadena.crt`) contribute ALL their blocks, exactly the list `openssl
/// -CAfile` reads; DER files hold one. The verifier closes each signature's
/// chain against whichever anchor in the pool fits, so dropping any block of
/// a bundle would silently refuse a document its own CA file verifies.
///
/// An ANCHOR is configuration that stands for "a certification authority I
/// trust", so every certificate the file names must be fit to issue: one
/// marked `basicConstraints CA:FALSE` (a signer's leaf — exactly what the
/// review's attack handed the picker, green-lighting any document signed by
/// that same attacker) is refused here, in both frontends, at once. A file
/// whose every block fails the rule is an error naming each one; a bundle
/// where some blocks pass keeps those — `openssl -CAfile` tolerates leaves
/// sitting inside CA bundles too, and what matters is that no leaf joins the
/// pool as an anchor.
pub fn load_trust_anchors(path: &Path) -> Result<Vec<CertificateHandle>, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let certs = if bytes.starts_with(b"-----BEGIN") {
        let text = std::str::from_utf8(&bytes)
            .map_err(|e| format!("{}: PEM is not UTF-8: {e}", path.display()))?;
        let mut handles: Vec<CertificateHandle> = Vec::new();
        for block in pem_blocks(text) {
            handles.push(CertificateHandle::from_pem(block).map_err(|e| {
                format!("{} is not a valid X.509 certificate: {e}", path.display())
            })?);
        }
        if handles.is_empty() {
            return Err(format!("{} holds no PEM certificate", path.display()));
        }
        handles
    } else {
        vec![
            CertificateHandle::from_der(&bytes)
                .map_err(|e| format!("{} is not a valid X.509 certificate: {e}", path.display()))?,
        ]
    };
    let mut anchors = Vec::with_capacity(certs.len());
    let mut refused: Vec<String> = Vec::new();
    for cert in certs {
        match anchor_rule(&cert) {
            Ok(()) => anchors.push(cert),
            Err(reason) => refused.push(reason),
        }
    }
    if anchors.is_empty() {
        return Err(format!(
            "{} cannot be a trust anchor: {}",
            path.display(),
            refused.join("; ")
        ));
    }
    Ok(anchors)
}

/// What makes a certificate fit to stand as a trust anchor: it must not say
/// it cannot issue (RFC 5280 4.2.1.9 — `basicConstraints cA = FALSE` is that
/// statement). A certificate with no basicConstraints at all stays admissible:
/// pre-v3 roots exist in real PKIs, and RFC 5280 6.1.1(e)/(p) treats the trust
/// anchor's own properties as configuration data — the same exemption the
/// chain builder applies to anchors. Leaf certificates (the attacker's own),
/// which is what the review picked, carry CA:FALSE in every real PKI and here.
fn anchor_rule(cert: &CertificateHandle) -> Result<(), String> {
    for ext in cert
        .parsed()
        .tbs_certificate()
        .extensions()
        .into_iter()
        .flatten()
    {
        if ext.extn_id.to_string() == OID_BASIC_CONSTRAINTS {
            let Ok(bc) = BasicConstraints::from_der(ext.extn_value.as_bytes()) else {
                return Err("its basicConstraints do not parse".to_string());
            };
            if !bc.ca {
                let who = cert
                    .subject_cn()
                    .unwrap_or_else(|| cert.subject().to_string());
                return Err(format!(
                    "\"{who}\" says CA:FALSE in its basicConstraints: it is a certificate \
                     that cannot issue certificates, so trusting it as an authority would \
                     validate nothing beyond whoever holds it. Choose the issuing \
                     authority's certificate instead"
                ));
            }
        }
    }
    Ok(())
}
fn pem_blocks(text: &str) -> Vec<&str> {
    const BEG: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(b) = rest.find(BEG) {
        let after = &rest[b..];
        match after.find(END) {
            Some(e) => {
                out.push(&after[..e + END.len()]);
                rest = &after[e + END.len()..];
            }
            None => break,
        }
    }
    out
}

/// The store descriptor forms of `sign --store`, parsed once for both
/// frontends (docs/adr-0004: a keystore is named by a descriptor string, and
/// the GUI names keystores the same way the CLI does — it renders these into
/// its picker, never a private spelling).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoreSpec {
    /// `pkcs11:/path/to/module.so[:token label][:]` — the token part is
    /// optional and means "the first slot with a token"; a second colon after
    /// the label marks a keystore that needs no PIN at all.
    Pkcs11 {
        module: PathBuf,
        token: Option<String>,
        wants_no_pin: bool,
    },
    /// `nss` or `nss:sql:/path/to/db` — without a database, `$HOME/.pki/nssdb`
    /// is used, the standard location for a shared NSS database.
    Nss {
        db: String,
    },
    Windows,
    Macos,
}

impl StoreSpec {
    /// The descriptor of a discovered keystore in exactly the spelling this
    /// module parses back, so the GUI's list and the CLI's `--store` are one
    /// language.
    pub fn descriptor(&self) -> String {
        match self {
            StoreSpec::Pkcs11 {
                module,
                token: Some(token),
                wants_no_pin: false,
            } => format!("pkcs11:{}:{token}", module.display()),
            StoreSpec::Pkcs11 {
                module,
                token: None,
                wants_no_pin: false,
            } => format!("pkcs11:{}", module.display()),
            // `::` at the end says "log in with an empty PIN", which is how a
            // passwordless NSS database or an unpassworded token is named.
            StoreSpec::Pkcs11 {
                module,
                token,
                wants_no_pin: true,
            } => match token {
                Some(token) => format!("pkcs11:{module}:{token}::", module = module.display()),
                None => format!("pkcs11:{}::", module.display()),
            },
            StoreSpec::Nss { db } => format!("nss:{db}"),
            StoreSpec::Windows => "windows".into(),
            StoreSpec::Macos => "macos".into(),
        }
    }

    /// A short human name for a keystore descriptor, used by the GUI's
    /// picker. Names are derived from what the descriptor already carries;
    /// nothing here invents identity: an unlabeled token lists under its
    /// module file name, which is honest about where it came from.
    pub fn display_name(&self) -> String {
        match self {
            StoreSpec::Pkcs11 {
                module,
                token: Some(token),
                ..
            } => format!("{token} ({})", module.display()),
            StoreSpec::Pkcs11 { module, .. } => module.display().to_string(),
            StoreSpec::Nss { db } => {
                let path = db.strip_prefix("sql:").unwrap_or(db);
                format!("NSS database {path}")
            }
            StoreSpec::Windows => "the Windows certificate store".into(),
            StoreSpec::Macos => "the macOS keychain".into(),
        }
    }

    /// Parses a store descriptor (same rules `openfirma sign --store` uses).
    pub fn parse(text: &str) -> Result<Self, String> {
        let (kind, rest) = text.split_once(':').unwrap_or((text, ""));
        // Two colons at the end (`…mod.so:label::`, or `…mod.so::` with no
        // label): strip the marker once, up front, so splitting sees exactly
        // one separator. A single trailing colon is a token split (or a
        // drive), and stays for the rules below to resolve.
        let (rest, wants_no_pin) = match rest.strip_suffix("::") {
            Some(base) => (base, true),
            None => (rest, false),
        };
        match kind.to_ascii_lowercase().as_str() {
            "pkcs11" => {
                if rest.is_empty() {
                    return Err("--store pkcs11: needs the module path: \
                         --store pkcs11:/usr/lib/opensc-pkcs11.so[:token label]"
                        .into());
                }
                let (module, tail) = split_trailing_token(rest);
                let token = match tail {
                    Some(tail) if !tail.is_empty() => Some(tail.to_string()),
                    _ => None,
                };
                Ok(StoreSpec::Pkcs11 {
                    module: PathBuf::from(module),
                    token,
                    wants_no_pin,
                })
            }
            "nss" => {
                let db = if rest.is_empty() {
                    let home = std::env::var("HOME").map_err(|_| {
                        "the default NSS database is $HOME/.pki/nssdb and HOME is not set: \
                         name the database with --store nss:sql:/path/to/db"
                            .to_string()
                    })?;
                    format!("sql:{home}/.pki/nssdb")
                } else {
                    rest.to_string()
                };
                Ok(StoreSpec::Nss { db })
            }
            "windows" | "macos" | "apple" => {
                if !rest.is_empty() {
                    return Err(format!("--store {kind} takes no argument, got {text:?}"));
                }
                if kind.eq_ignore_ascii_case("windows") {
                    Ok(StoreSpec::Windows)
                } else {
                    Ok(StoreSpec::Macos)
                }
            }
            other => Err(format!(
                "unknown --store {other:?}: use pkcs11:/path/to/module.so[:token], \
                 nss[:sql:/path/to/db], windows, or macos"
            )),
        }
    }
}

/// Splits `module[:token]` on the last colon — but only when what precedes it
/// names a file. That rule protects Windows drive letters without any OS
/// special case: `C:\path\mod.dll` has its trailing colon at index 1, where
/// `C` is not a file, so nothing is split; `...\mod.dll:mytoken` splits after
/// the module because the module exists. A path that does not exist reports
/// through the loader's own error later, and there splitting is moot anyway.
///
/// The second guard is what makes paths that legitimately contain a colon
/// parse whole: `pkcs11:C:\tokens\mod.dll:Mi Token` splits at the last colon
/// because the token names no directory separator, while
/// `pkcs11:/tmp/x:1/mod.so` and `C:\mis tokens:obj.dll` do *not* split — a
/// token label is one flat name, so anything after the last colon that still
/// contains `/` or `\` is part of the path, not a token. Without it a module
/// living in a directory whose name holds a colon (legal on every Unix, and
/// the reason the drive-letter guard exists on Windows) silently lost its
/// trailing component to a phantom token label.
fn split_trailing_token(rest: &str) -> (&str, Option<&str>) {
    // The separator between module and token is the LAST colon — a drive
    // letter (index 1) never separates. Two guards decide whether that cut
    // stands, both from what a real descriptor can look like:
    //
    // * the tail after the colon must be a flat name — no `/`, no `\`. A path
    //   whose directories contain colons (`/tmp/x:1/mod.so`) stays whole: its
    //   last colon still has separators behind it.
    // * when the path has separators, the module's final segment — what sits
    //   between the last separator and that colon — must look like a file
    //   (carry a `.`). On Windows a folder may be named `mis tokens:`
    //   (`C:\mis tokens:obj.dll`): there the cut colon has a flat tail AND
    //   separators before it, yet "mis tokens" is a directory with a colon in
    //   its name, not the module — this guard keeps the whole path in one
    //   piece. The token spelling `C:\tokens\mod.dll:Mi Token` passes it
    //   ("mod.dll"), so it splits exactly as users write it.
    let Some(i) = rest.rfind(':') else {
        return (rest, None);
    };
    if i < 2 || rest[i + 1..].contains(['/', '\\']) {
        return (rest, None);
    }
    let last_sep = rest[..i].rfind('/').max(rest[..i].rfind('\\'));
    if last_sep.is_some_and(|s| !rest[s + 1..i].contains('.')) {
        return (rest, None);
    }
    (&rest[..i], Some(&rest[i + 1..]))
}

/// The keystores the GUI lists without being pointed at one: on Windows and
/// macOS the platform store; elsewhere nothing is guessed at — a PKCS#11
/// module or an NSS database is named by path, exactly like `keystores list`
/// refuses to invent them. A user adds more from the picker itself. Opening
/// these descriptors is the frontends' job (`open_store` in openfirma-cli and
/// openfirma-gui, which share this spelling): core must not know keystores
/// exist, or the layering of docs/architecture.md flips upside down.
pub fn discoverable_stores() -> Vec<StoreSpec> {
    #[allow(unused_mut)]
    let mut specs = Vec::new();
    #[cfg(target_os = "windows")]
    specs.push(StoreSpec::Windows);
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    specs.push(StoreSpec::Macos);
    specs
}

/// The environment variable every subcommand reads the PKCS#12 password from
/// when its flag is absent. Public so no frontend can grow a private spelling
/// of it; `p12_password` is the only reader.
pub const PASSWORD_ENV: &str = "OPENFIRMA_PASSWORD";

/// Resolve a PKCS#12 password from its three sources, in the order the CLI's
/// help promises: `--password-file` first (it wins when both are given), else
/// an explicit value (the insecure `--password` flag), else
/// `$OPENFIRMA_PASSWORD`. Everything that carries a secret lands in
/// [`Zeroizing`]; a wrong path or non-UTF-8 secret is refused with the reason.
///
/// The resolution lives here — not in any one subcommand — because all three
/// of `sign`, `afirma-uri` and `afirma-serve` take a `--p12`, and an earlier
/// revision wired the environment only into `sign`: the two browser commands
/// printed an error offering `OPENFIRMA_PASSWORD` that they themselves did not
/// read. A rule this small, duplicated, rots exactly like that.
pub fn p12_password(
    flag: Option<&std::ffi::OsStr>,
    file: Option<&Path>,
) -> Result<Option<Zeroizing<String>>, String> {
    if let Some(path) = file {
        let bytes = Zeroizing::new(
            std::fs::read(path)
                .map_err(|e| format!("reading the password file {}: {e}", path.display()))?,
        );
        // the first line, with one CRLF or LF ending ignored: `echo secret >
        // file` must not sign with a newline in the password
        let line = bytes.split(|b| *b == b'\n').next().unwrap_or(&[]);
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let text = std::str::from_utf8(line).map_err(|_| non_utf8_secret_error())?;
        return Ok(Some(Zeroizing::new(text.to_string())));
    }
    if let Some(value) = flag {
        let value = value
            .to_str()
            .ok_or_else(non_utf8_secret_error)?
            .to_string();
        return Ok(Some(Zeroizing::new(value)));
    }
    match std::env::var_os(PASSWORD_ENV) {
        Some(value) => {
            let text = value
                .to_str()
                .ok_or_else(non_utf8_secret_error)?
                .to_string();
            Ok(Some(Zeroizing::new(text)))
        }
        None => Ok(None),
    }
}

/// Why a password that is not UTF-8 cannot be used, and what to do about it.
/// Lives with `p12_password` because the three entry points must refuse a
/// non-UTF-8 secret with one identical sentence.
fn non_utf8_secret_error() -> String {
    "the password is not valid UTF-8: it may contain non-ASCII characters in an \
     encoding openfirma cannot represent. PKCS#12 encodes passwords as UTF-16 \
     BMPStrings and openfirma re-encodes them from UTF-8; supply the password as \
     UTF-8, or re-export the container with an ASCII password: \
     `openssl pkcs12 -in old.p12 -out new.p12`"
        .to_string()
}

/// Refuses `sign -i f -o f` unless `--force` says the overwrite is meant.
///
/// Both paths are compared before any reading happens, and twice: the plain
/// absolute spelling catches `-o ./f` and `-o dir/../f`, and the canonical
/// one catches an output that is a symlink or a hard link to the input. The
/// input is read whole before the output is written, so nothing is lost
/// mechanically — what is refused is the silent case, where one typo turns a
/// signature into a replacement of the only copy of a document. The GUI uses
/// this same check when its default "next to the original" path collides with
/// a source file it was not supposed to touch; the message names `--force`
/// because the refusal is written once, for both frontends.
pub fn check_not_in_place(input: &Path, output: &Path, force: bool) -> Result<(), String> {
    if force {
        return Ok(());
    }
    let absolute_same = match (std::path::absolute(input), std::path::absolute(output)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    };
    let canonical_same = match (std::fs::canonicalize(input), std::fs::canonicalize(output)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    };
    if absolute_same || canonical_same {
        return Err(format!(
            "{} is both the input and the output: signing would replace the document \
             itself. Choose a different output, or pass --force to overwrite it anyway",
            input.display()
        ));
    }
    Ok(())
}

/// The friendly name of a certificate for a picker: never the raw DN dump.
///
/// A person recognizes their own name (the subject CN), not `CN=GARCIA GOMEZ,
/// Maria@CUF=..., serialNumber=IDCES-...`. The rules, in order:
///
/// 1. the certificate's subject common name when it is present and readable
///    (this includes the FNMT/DNIe convention of CN carrying `APELLIDO1
///    APELLIDO2, NOMBRE`),
/// 2. the store label or alias when there is no CN (a token nickname or a
///    PKCS#12 friendlyName stands in: it is what the user typed themselves),
/// 3. otherwise `serialNumber` of the subject — a DNIe certificate's identity
///    *is* its IDES/IDNIE serial, which the citizen knows — labelled as such
///    so it cannot be mistaken for a name,
/// 4. and finally the hexadecimal serial number of the certificate itself,
///    which at least distinguishes two anonymous certificates from each
///    other.
///
/// Every branch ends in a string; nothing here returns a DN to show.
pub fn friendly_name(cert: &CertificateHandle) -> String {
    if let Some(cn) = cert.subject_cn() {
        let cn = cn.trim();
        if !cn.is_empty() {
            return cn.to_string();
        }
    }
    // subject serialNumber (2.5.4.5): the DNIe/NIE/CIF carrier in Spanish
    // qualified certificates, per ETSI EN 319 412-1.
    if let Some(serial) = subject_serial_number(cert) {
        return format!("Documento {serial}");
    }
    let serial = hex::encode_upper(cert.serial_number().as_bytes());
    format!("certificado sin nombre (nº {serial})")
}

/// Same as [`friendly_name`], with the store label preferred: in a keystore
/// listing the user's own nickname (NSS) or CKA_LABEL (PKCS#11) is what they
/// recognize; a PKCS#12 friendlyName likewise. Without one, the CN rules of
/// [`friendly_name`] apply.
pub fn friendly_name_with_label(label: Option<&str>, cert: &CertificateHandle) -> String {
    if let Some(label) = label.map(str::trim).filter(|s| !s.is_empty()) {
        return label.to_string();
    }
    friendly_name(cert)
}

/// The one name a frontend prints for a signer it built from any source: the
/// store label or PKCS#12 alias when there is one, the certificate's own
/// [`friendly_name`] otherwise. `openfirma sign` prints this on success and
/// the GUI shows it on its result card; both call this function so the two
/// can never disagree about who signed.
pub fn signer_display(label: Option<&str>, cert: &CertificateHandle) -> String {
    friendly_name_with_label(label, cert)
}

/// Days since the epoch to a proleptic Gregorian date, Howard Hinnant's
/// `civil_from_days`, the same one openfirma-pades uses for PDF dates and
/// the CLI parses its verification times with. In core so every frontend
/// that prints a date prints it from one conversion (the GUI's verdict list
/// and `openfirma verify` must never state different days).
pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (y + i64::from(m <= 2), m, d)
}

/// One `serialNumber` (2.5.4.5) attribute value from the subject, if any.
/// The first RDN that carries one wins; Spanish qualified certificates put it
/// in its own RDN and never repeat it with a different value.
fn subject_serial_number(cert: &CertificateHandle) -> Option<String> {
    use const_oid::ObjectIdentifier;

    const OID_SERIAL_NUMBER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.5");
    // The Name is walked with the crate's own TLV cursor (core owns the DER
    // reading rules — see `dump`), so this adds no x509-cert assumptions and
    // works on every string CHOICE type issued material uses: PrintableString,
    // UTF8String, BMPString and TeletexString all appear, and each carries
    // either ASCII bytes or UTF-16, which the decoder below handles.
    let name_der = cert.subject_der().ok()?;
    let (tag, rdns) = read_tlv(&name_der)?;
    if tag != 0x30 {
        return None;
    }
    let mut rest = rdns;
    while let Some((rdn_tag, rdn)) = read_tlv(rest) {
        rest = &rest[tlv_end(rest)?..];
        if rdn_tag != 0x31 {
            continue;
        }
        let mut inner = rdn;
        while let Some((atv_tag, atv)) = read_tlv(inner) {
            inner = &inner[tlv_end(inner)?..];
            if atv_tag != 0x30 {
                continue;
            }
            let (oid_tag, oid_bytes) = read_tlv(atv)?;
            if oid_tag != 0x06 || ObjectIdentifier::try_from(oid_bytes).ok()? != OID_SERIAL_NUMBER {
                continue;
            }
            let after_oid = &atv[tlv_end(atv)?..];
            let Some((str_tag, value)) = read_tlv(after_oid) else {
                continue;
            };
            if let Some(text) = decode_directory_string(str_tag, value) {
                if !text.is_empty() {
                    return Some(text);
                }
            }
        }
    }
    None
}

/// One TLV at the start of `bytes`: total header+value length, or None when
/// it does not fit. The single place the header sizes are computed, so
/// [`read_tlv`] and this cannot disagree about where a value ends.
fn tlv_end(bytes: &[u8]) -> Option<usize> {
    let &len0 = bytes.get(1)?;
    let (len, header): (usize, usize) = if len0 < 0x80 {
        (len0 as usize, 2)
    } else if len0 == 0x81 {
        (usize::from(*bytes.get(2)?), 3)
    } else if len0 == 0x82 {
        (u16::from_be_bytes(bytes[2..4].try_into().ok()?) as usize, 4)
    } else {
        return None;
    };
    let end = header.checked_add(len)?;
    (end <= bytes.len()).then_some(end)
}

/// One TLV at the start of `bytes`: tag and value, or None when truncated.
fn read_tlv(bytes: &[u8]) -> Option<(u8, &[u8])> {
    let end = tlv_end(bytes)?;
    let header = end - value_len_after_header(bytes)?;
    Some((bytes[0], &bytes[header..end]))
}

/// The declared length of the first TLV's value (the `L` of L-V), None when
/// the header is not one of the three forms used by real DER.
fn value_len_after_header(bytes: &[u8]) -> Option<usize> {
    let &len0 = bytes.get(1)?;
    if len0 < 0x80 {
        Some(len0 as usize)
    } else if len0 == 0x81 {
        Some(usize::from(*bytes.get(2)?))
    } else if len0 == 0x82 {
        Some(u16::from_be_bytes(bytes[2..4].try_into().ok()?) as usize)
    } else {
        None
    }
}

/// The text of a DirectoryString CHOICE member: the universal string types
/// that appear in subjects. Printable/IA5/Teletex/Videotex are ASCII-range;
/// BMPString is UTF-16BE. NumericString is digits and spaces only (a real
/// one — DIT rules forbid others); anything else returns None.
fn decode_directory_string(tag: u8, value: &[u8]) -> Option<String> {
    match tag {
        // PrintableString | IA5String | TeletexString | VideotexString | NumericString
        0x12..=0x16 => std::str::from_utf8(value).ok().map(|s| s.to_string()),
        // UTF8String
        0x0c => std::str::from_utf8(value).ok().map(|s| s.to_string()),
        // BMPString: UTF-16 big endian without BOM
        0x1e => {
            let units: Vec<u16> = value
                .chunks_exact(2)
                .map(|b| u16::from_be_bytes([b[0], b[1]]))
                .collect();
            String::from_utf16(&units).ok()
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_leaf_certificate_is_refused_as_a_trust_anchor() {
        // The review's C-1 attack in one line: hand the verifier (both
        // frontends share this loader) the SIGNER's own certificate and every
        // document that attacker signs turns green. A CA:FALSE leaf is now
        // refused as an anchor, with the reason in words.
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/certs");
        if !dir.join("signer-rsa.crt").is_file() {
            return; // pure-unit crate may run where testdata is absent
        }
        let err = load_trust_anchors(&dir.join("signer-rsa.crt"))
            .expect_err("a signer leaf cannot be an authority");
        assert!(
            err.contains("CA:FALSE"),
            "the refusal names the rule: {err}"
        );

        // A real CA file still loads as one anchor.
        let anchors =
            load_trust_anchors(&dir.join("ca.crt")).expect("the root CA is a fine anchor");
        assert_eq!(anchors.len(), 1);

        // The review's exact bundle: chain.crt + the attacker's leaf appended.
        // Every CA block survives; the leaf never joins the pool.
        let mut text = std::fs::read_to_string(dir.join("chain.crt")).unwrap();
        text.push('\n');
        text.push_str(&std::fs::read_to_string(dir.join("signer-rsa.crt")).unwrap());
        let both =
            std::env::temp_dir().join(format!("openfirma-{}-mixed-bundle.crt", std::process::id()));
        std::fs::write(&both, &text).unwrap();
        let chain_len = load_trust_anchors(&dir.join("chain.crt"))
            .expect("the chain bundle loads")
            .len();
        let anchors = load_trust_anchors(&both).expect("the bundle's CAs survive");
        assert_eq!(anchors.len(), chain_len, "exactly the CA blocks remain");
        std::fs::remove_file(&both).ok();
    }

    #[test]
    fn a_bundle_of_only_leaves_is_the_anchored_refusal() {
        // FNMT-style files in the wild sometimes hold only end entities; every
        // block refused is an error naming them, not a silent empty pool.
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/certs");
        if !dir.join("signer-rsa.crt").is_file() {
            return;
        }
        let one =
            std::env::temp_dir().join(format!("openfirma-{}-two-leaves.crt", std::process::id()));
        let mut text = std::fs::read_to_string(dir.join("signer-rsa.crt")).unwrap();
        text.push('\n');
        text.push_str(&std::fs::read_to_string(dir.join("signer-ec.crt")).unwrap());
        std::fs::write(&one, &text).unwrap();
        let err = load_trust_anchors(&one).expect_err("no CA inside: nothing to trust");
        assert!(err.contains("CA:FALSE"), "both refusals are quoted: {err}");
        std::fs::remove_file(&one).ok();
    }

    #[test]
    fn detection_follows_magic_not_extension() {
        assert_eq!(Format::detect(b"%PDF-1.7\n%\xc7\xec"), Format::Pdf);
        assert_eq!(
            Format::detect(b"<?xml version=\"1.0\"?>\n<a/>"),
            Format::Xml
        );
        assert_eq!(Format::detect(b"\xef\xbb\xbf<?xml?>"), Format::Xml);
        assert_eq!(Format::detect(b"   \n\t <root>x</root>"), Format::Xml);
        assert_eq!(Format::detect(b"<html lang=\"es\"></html>"), Format::Xml);
        // an opening angle bracket that opens no markup is data
        assert_eq!(Format::detect(b"<3 and falling\n"), Format::Data);
        assert_eq!(Format::detect(b""), Format::Data);
        assert_eq!(Format::detect(b"contrato en texto plano"), Format::Data);
    }

    #[test]
    fn defaults_name_formats_and_paths() {
        assert_eq!(Format::Pdf.default_signature_format(), "pades-b-b");
        assert_eq!(Format::Xml.default_signature_format(), "xades-b-b");
        assert_eq!(Format::Data.default_signature_format(), "cades-b-b");
        let p = std::path::Path::new("/docs/contrato.pdf");
        assert_eq!(
            Format::Pdf.default_output(p).file_name().unwrap(),
            "contrato.signed.pdf"
        );
        let x = std::path::Path::new("a/facturae.xml");
        assert_eq!(
            Format::Xml.default_output(x).file_name().unwrap(),
            "facturae.signed.xml"
        );
        let d = std::path::Path::new("a/nota.txt");
        assert_eq!(
            Format::Data.default_output(d).file_name().unwrap(),
            "nota.csig"
        );
        // a file with no extension still gets a clean sibling name
        let n = std::path::Path::new("a/SIN_EXT");
        assert_eq!(
            Format::Data.default_output(n).file_name().unwrap(),
            "SIN_EXT.csig"
        );
    }

    #[test]
    fn shapes_constrain_the_format_menu() {
        assert_eq!(
            Format::Pdf.supported_formats(),
            ["pades-b-b", "pades-b-lt", "pades-b-lta"]
        );
        assert_eq!(Format::Xml.supported_formats(), ["xades-b-b"]);
        assert_eq!(Format::Data.supported_formats(), ["cades-b-b"]);
    }

    #[test]
    fn trust_anchors_come_from_the_environment_and_default_to_none() {
        // The variable name is fixed, and the one other test that touches the
        // environment (`bare nss`-style HOME reads) does not read this one;
        // env mutation stays scoped inside this thread and restores whatever
        // was there. Rust 2024 marks it unsafe for exactly this reason: no
        // sibling may be reading the same name, and none is.
        let saved = std::env::var_os("OPENFIRMA_TRUST");
        unsafe {
            std::env::set_var("OPENFIRMA_TRUST", "/tmp/a.pem:/tmp/b.der");
            let anchors = default_trust_anchors();
            assert_eq!(anchors.len(), 2);
            assert_eq!(anchors[0], PathBuf::from("/tmp/a.pem"));
            assert_eq!(anchors[1], PathBuf::from("/tmp/b.der"));
            std::env::remove_var("OPENFIRMA_TRUST");
            // unset means no anchors, which the UI must treat as "ask the
            // user", never as "everything verifies".
            assert!(default_trust_anchors().is_empty());
            match saved {
                Some(v) => std::env::set_var("OPENFIRMA_TRUST", v),
                None => std::env::remove_var("OPENFIRMA_TRUST"),
            }
        }
    }

    #[test]
    fn descriptors_round_trip_their_own_spellings() {
        let cases = [
            "pkcs11:/usr/lib/opensc-pkcs11.so",
            "nss:sql:/tmp/db",
            "windows",
            "macos",
        ];
        for text in cases {
            let spec = StoreSpec::parse(text).unwrap_or_else(|e| panic!("{text}: {e}"));
            assert_eq!(spec.descriptor(), text, "{text} must spell itself back");
        }
        // a token label round trips through the display and parse too
        let spec = StoreSpec::parse("pkcs11:/tmp/mod.so:Mi tarjeta").unwrap();
        assert_eq!(spec.descriptor(), "pkcs11:/tmp/mod.so:Mi tarjeta");
    }

    #[test]
    fn store_specs_parse_the_documented_shapes() {
        let spec = StoreSpec::parse("pkcs11:/usr/lib/nosuch-mod.so:Token::").unwrap();
        match spec {
            StoreSpec::Pkcs11 {
                token,
                wants_no_pin,
                ..
            } => {
                assert_eq!(token.as_deref(), Some("Token"));
                assert!(wants_no_pin);
            }
            other => panic!("expected pkcs11, got {other:?}"),
        }
        // A drive letter is never split: `C` is not a file.
        let spec = StoreSpec::parse("pkcs11:C:\\tokens\\mod.dll").unwrap();
        match spec {
            StoreSpec::Pkcs11 {
                module,
                token: None,
                ..
            } => {
                assert_eq!(module, PathBuf::from("C:\\tokens\\mod.dll"));
            }
            other => panic!("expected an unsplit module path, got {other:?}"),
        }
        let err = StoreSpec::parse("tpm:x").unwrap_err();
        assert!(err.contains("--store") && err.contains("pkcs11:"), "{err}");
    }

    #[test]
    fn a_module_path_with_a_colon_in_its_directories_stays_whole() {
        // A token label is one flat name; anything after the last colon that
        // still contains a path separator belongs to the module, not to a
        // token. Without this, `/tmp/x:1/mod.so` lost its `1/mod.so` tail to
        // a phantom token and the real file was never even opened.
        for text in [
            "pkcs11:/tmp/x:1/mod.so",
            "pkcs11:C:\\mis tokens:obj.dll",
            "pkcs11:/opt/pkcs11:extra/nested/dir/mod.so",
        ] {
            let spec =
                StoreSpec::parse(text).unwrap_or_else(|e| panic!("{text} must parse whole: {e}"));
            match spec {
                StoreSpec::Pkcs11 {
                    module,
                    token: None,
                    ..
                } => assert_eq!(module, PathBuf::from(text.trim_start_matches("pkcs11:"))),
                other => panic!("{text} must keep its full path and no token, got {other:?}"),
            }
        }
        // The Windows spelling of a real path *with* a token does split: the
        // drive letter alone never separates, but once the path has been an
        // absolute one since its first backslash, a later colon after the last
        // separator introduces a flat label (`Mi Token`) — the shape SoftHSM
        // and ActivClient users type on Windows.
        let spec = StoreSpec::parse("pkcs11:C:\\tokens\\mod.dll:Mi Token").unwrap();
        match spec {
            StoreSpec::Pkcs11 { module, token, .. } => {
                assert_eq!(module, PathBuf::from("C:\\tokens\\mod.dll"));
                assert_eq!(token.as_deref(), Some("Mi Token"));
            }
            other => panic!("expected a split descriptor, got {other:?}"),
        }
    }

    #[test]
    fn in_place_output_is_refused_with_the_cli_message() {
        let dir = std::env::temp_dir().join(format!("openfirma-wf-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let input = dir.join("doc.pdf");
        std::fs::write(&input, b"%PDF-1.4\n").unwrap();
        check_not_in_place(&input, &input, true).expect("--force is the explicit yes");
        let err = check_not_in_place(&input, &input, false).unwrap_err();
        assert!(err.contains("both the input and the output"), "{err}");
        assert!(err.contains("--force"), "{err}");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The synthetic PKI's RSA signer certificate: `tools/gen-testcert.sh`
    /// writes it at test time, its subject mimics the FNMT layout (a CN with
    /// the person's name and a serialNumber RDN with the IDES identifier), so
    /// the naming rules get asserted against real-shaped material. Without
    /// the PKI the certificate cannot be built by hand here — rcgen is banned
    /// (it pulls C crypto) — so this skips, the way the crosschecks do, and
    /// `OPENFIRMA_REQUIRE_TESTS=1` turns the skip into a failure.
    fn test_cert() -> Option<CertificateHandle> {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/certs");
        for name in ["signer-rsa.crt", "signer-rsa.crt.der"] {
            let Ok(bytes) = std::fs::read(dir.join(name)) else {
                continue;
            };
            let cert = if bytes.starts_with(b"-----BEGIN") {
                CertificateHandle::from_pem(std::str::from_utf8(&bytes).expect("PEM is ASCII"))
            } else {
                CertificateHandle::from_der(&bytes)
            };
            return Some(cert.expect("the test PKI's certificate parses"));
        }
        eprintln!("SKIP: testdata/certs/signer-rsa.crt is absent, run tools/gen-testcert.sh");
        if std::env::var_os("OPENFIRMA_REQUIRE_TESTS").is_some() {
            panic!("OPENFIRMA_REQUIRE_TESTS is set and the test PKI is missing");
        }
        None
    }

    #[test]
    fn friendly_name_prefers_the_subject_common_name() {
        let Some(cert) = test_cert() else { return };
        // The synthetic signer's CN is a readable name; what must hold for any
        // certificate is that no raw DN reaches the picker: exactly one value,
        // no attribute types, no separators between RDNs.
        let name = friendly_name(&cert);
        assert!(!name.is_empty());
        assert!(!name.contains('='), "a DN was dumped: {name}");
        // A qualified person's CN is itself `APELLIDOS, NOMBRE`; what must not
        // appear is a second attribute — no RDN separators (`+`), no OID
        // labels, no other attribute types.
        assert!(!name.contains('+'), "RDN sets leaked: {name}");
        assert!(
            !name.contains("SERIALNUMBER") && !name.contains("C=") && !name.contains("OU="),
            "other attributes leaked: {name}"
        );
    }

    #[test]
    fn a_store_label_beats_the_common_name_in_a_picker() {
        let Some(cert) = test_cert() else { return };
        let name = friendly_name_with_label(Some("Mi DNIe (tarjeta 1)"), &cert);
        assert_eq!(name, "Mi DNIe (tarjeta 1)");
        // An empty label is no label: the CN rules apply again.
        assert_eq!(
            friendly_name_with_label(Some("  "), &cert),
            friendly_name(&cert)
        );
    }

    #[test]
    fn a_pem_bundle_contributes_every_certificate_it_holds() {
        // chain.crt is CA + intermediate (what FNMT-style distributions ship).
        // A reader that stopped at the first block would silently refuse every
        // signature whose chain closes on the second — the exact drift this
        // shared loader exists to prevent.
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/certs");
        let path = dir.join("chain.crt");
        let Ok(bundle) = std::fs::read(&path) else {
            eprintln!("SKIP: testdata/certs/chain.crt is absent, run tools/gen-testcert.sh");
            if std::env::var_os("OPENFIRMA_REQUIRE_TESTS").is_some() {
                panic!("OPENFIRMA_REQUIRE_TESTS is set and the test PKI is missing");
            }
            return;
        };
        let handles = load_trust_anchors(&path).expect("a bundle loads");
        assert_eq!(handles.len(), 2, "every PEM block of the file is an anchor");
        // The two blocks are different certificates (not one parsed twice).
        assert_ne!(handles[0].der(), handles[1].der());
        // And a single-certificate file still loads as exactly one.
        let end = bundle
            .windows(9)
            .position(|w| w == b"-----END ")
            .unwrap_or(0);
        let _ = end;
        let first_only = {
            let text = std::str::from_utf8(&bundle).unwrap();
            let i = text.find("-----END CERTIFICATE-----").unwrap();
            text[..i + "-----END CERTIFICATE-----".len()].to_string()
        };
        let single = dir.join("one-bundle-test.pem");
        std::fs::write(&single, first_only).unwrap();
        let one = load_trust_anchors(&single).expect("one block loads");
        assert_eq!(one.len(), 1);
        std::fs::remove_file(single).ok();
    }
}
