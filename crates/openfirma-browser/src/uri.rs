//! The `afirma://` URI scheme: parsing and dispatch.
//!
//! Two independent measurements were taken before writing this file, both on
//! the AutoFirma 1.9 source clone (`docs/validation.md#reference-corpus`, see each
//! claim's citation) and against the shipped jar:
//!
//! - `afirma-core/src/main/java/es/gob/afirma/core/misc/protocol/ProtocolInvocationUriParser.java`
//!   (lines 320–354): the query string is split on the first `?`, pairs on the
//!   first `=`, values percent-decoded, and the *host* part of the URI — what
//!   sits between `afirma://` and `?` or the end — becomes the operation.
//! - `ProtocolInvocationLauncher.java` dispatches on the literal URI prefixes
//!   `afirma://sign?`, `afirma://cosign?`, `afirma://countersign?`,
//!   `afirma://selectcert?`, `afirma://save?`, `afirma://signandsave?`,
//!   `afirma://batch?`, `afirma://service?`, `afirma://websocket?` (each also
//!   in a `/?` spelling).
//!
//! What AutoFirma accepts as the *return channel* is what bounds this crate:
//!
//! - The custom-scheme call itself can only ever return the launcher's own
//!   process result. A web page cannot read it back through the scheme, so
//!   the caller must be able to reach something the page opened: either the
//!   loopback endpoint (`serve.rs`, mechanism 2) or — the legacy route — a
//!   government *intermediate server* whose two URLs travel in `rtservlet`/
//!   `stservlet` (retrieve and storage), keyed by `idsession`. This crate
//!   implements neither network path: the caller hands us the callback as a
//!   file sink (`Callback::File`) or keeps the bytes themselves
//!   (`Callback::Memory`). The payload format — base64, `|`, base64 — is
//!   AutoFirma's, see `dispatch.rs`.
//! - `dat` travels percent-encoded and base64'd (recorded forms in tests/
//!   uri_parse.rs carry the exact source line), optionally gzip-compressed on
//!   top when `gzip=true`, and may be a plain `http(s)://` URL which AutoFirma
//!   fetches. Fetching remote bytes is exactly what ADR-0005 forbids for the
//!   loopback transport, so a URI whose `dat` or `fileid` names a remote URL
//!   is refused with that reason; local `file:` data was already forbidden by
//!   AutoFirma itself (`UrlParameters.setCommonParameters`, "No se permite la
//!   lectura de ficheros locales").

use base64::Engine;

/// The largest `dat` payload we accept after decoding. A sede document is
/// kilobytes to a few megabytes; 16 MiB is well above anything real, and it is
/// the *document* limit: URI-level size lives in `serve::MAX_BODY_BYTES` (the
/// request) and in `MAX_URI_BYTES` (a hand-typed scheme argument). Three caps
/// on purpose — a loopback body must not be bigger than what an endpoint can
/// answer, a hand-off URI must stay launchable, and neither may grow the
/// document past what signing is meant to handle. AutoFirma caps none of them;
/// uncapped would mean any local process gets an unbounded allocation here.
pub const MAX_DATA_BYTES: usize = 16 * 1024 * 1024;

/// The largest URI `parse` reads, percent-encoded and raw. It is *input* only:
/// a document of 3 MiB arrives through the loopback endpoint in a body that
/// `MAX_BODY_BYTES` allows (8 MiB) even though no scheme hand-off URI could
/// carry it under this cap — which mirrors reality, where large documents go
// through the socket flow and small ones through either.
pub const MAX_URI_BYTES: usize = 2 * 1024 * 1024;

/// The operations AutoFirma's launcher dispatches, in its own words
/// (`SignOperation.Operation`: SIGN / COSIGN / COUNTERSIGN, matched
/// case-insensitively against the `op` query parameter).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Sign,
    Cosign,
    Countersign,
    /// The certificate-selection call the sedes use before signing with a
    /// hardware token ("read/select-certificate"): the page gets the leaf
    /// back and decides, then signs. AutoFirma's `afirma://selectcert?`.
    SelectCert,
}

impl Operation {
    /// Case-insensitive, like AutoFirma's `Operation.getOperation`.
    pub fn parse(text: &str) -> Option<Self> {
        if text.eq_ignore_ascii_case("sign") {
            Some(Operation::Sign)
        } else if text.eq_ignore_ascii_case("cosign") {
            Some(Operation::Cosign)
        } else if text.eq_ignore_ascii_case("countersign") {
            Some(Operation::Countersign)
        } else if text.eq_ignore_ascii_case("selectcert") {
            Some(Operation::SelectCert)
        } else {
            None
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Operation::Sign => "sign",
            Operation::Cosign => "cosign",
            Operation::Countersign => "countersign",
            Operation::SelectCert => "selectcert",
        }
    }
}

/// The two spellings of the session id on the wire (`UrlParameters.ID_PARAM`,
/// line 34 = `"id"`; `ProtocolInvocationLauncher.IDSESSION_PARAM` = `"idsession"`)
/// and every parameter openfirma's parser reads are keyed in `parse_inner`.
///
/// Why parse keeps `stservlet` instead of refusing it: the intermediate-server
/// route decides where an operation's ANSWER travels (autoscript.js adds the
/// parameter whenever a storage servlet was configured — lines 4798 and 5061 of
/// that file). A call that carries only `dat` can answer through our own channel
/// too, so its refusal belongs to dispatch (finding M-5: sign-and-deliver-nowhere
/// is the bug; parse refusing recorded URIs is a different one).
///
/// The protocol version of one operation URI, in AutoFirma's own semantics
/// (`afirma-core`'s `ProtocolVersion`, read from 1.9.1 sources):
///
/// - the value is `"X"` or `"X.Y"`; an unparseable identifier is VERSION_0
///   (`ProtocolInvocationLauncher.getVersion`, recorded behaviour: a broken
///   version falls back, it never refuses);
/// - absent means VERSION_0 for operations (`UrlParametersToSign`:
///   `setMinimumProtocolVersion(ProtocolVersion.VERSION_0)` when `ver` is not
///   in the map);
/// - two versions are *compatible* on equal major; support for a newer minor
///   asks `hasSupportTo(4.1)`, which is exactly `major > 4 || (major == 4 &&
///   minor >= 1)` — and that predicate alone selects the error wire form in
///   `ProtocolInvocationLauncherErrorManager` (`PROTOCOL_VERSION_WITH_ERROR_CODES`:
///   4.1+ answers `err-00:=AFxxxxxx - …`, anything below answers the old
///   `SAF_xx: mensaje`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolVersion {
    pub major: u32,
    pub minor: u32,
}

impl ProtocolVersion {
    /// `ProtocolVersion.getInstance`: `"X"`/`"X.Y"`, digits only; anything
    /// else is AutoFirma's VERSION_0 fallback (logged there, refused nowhere).
    pub fn parse(text: &str) -> ProtocolVersion {
        let text = text.trim();
        match text.split_once('.') {
            Some((maj, min)) if !maj.is_empty() && !min.is_empty() => {
                match (maj.parse::<u32>(), min.parse::<u32>()) {
                    (Ok(major), Ok(minor)) => ProtocolVersion { major, minor },
                    _ => ProtocolVersion::VERSION_0,
                }
            }
            None if !text.is_empty() => match text.parse::<u32>() {
                Ok(major) => ProtocolVersion { major, minor: 0 },
                Err(_) => ProtocolVersion::VERSION_0,
            },
            _ => ProtocolVersion::VERSION_0,
        }
    }

    /// `hasSupportTo(VERSION_4_1)` — the ONLY version predicate that changes
    /// what a page receives (error shapes; async websocket operations).
    pub fn supports_error_codes(&self) -> bool {
        self.major > 4 || (self.major == 4 && self.minor >= 1)
    }

    /// `isCompatibleWith` of the versions this client answers: AutoFirma 1.9's
    /// launcher declares supported `{4.1, 3, 2, 1}` (`SUPPORTED_PROTOCOLS`,
    /// ProtocolInvocationLauncher.java lines ~67-72) plus VERSION_0 as the
    /// fallback a broken `v=` produces. openfirma reproduces that set exactly:
    /// the SAME protocol versions the same pages send it must parse and answer,
    /// and only answering the newest one is what finding M-2 called out.
    pub fn is_supported(&self) -> bool {
        matches!(
            (self.major, self.minor),
            (4, 1) | (3, _) | (2, _) | (1, _) | (0, _)
        )
    }

    pub const VERSION_0: ProtocolVersion = ProtocolVersion { major: 0, minor: 0 };
}

/// One parsed `afirma://` URI, in the shape AutoFirma's launcher produces.
#[derive(Debug)]
pub struct AfirmaUri {
    pub operation: Operation,
    /// Raw `format` parameter, AutoFirma's strings ("CAdES", "PAdES", ...).
    pub format: Option<String>,
    /// Raw `algorithm` parameter (SHAxxx or SHAxxxwithRSA/ECDSA forms).
    pub algorithm: Option<String>,
    /// The `appname` query parameter — the page's domain in autoscript.js
    /// (`createSignRequest`, line 2274: `data.appname = … DOMAIN_NAME`). A
    /// top-level URI parameter (`UrlParameters.APP_NAME_PARAM`), never inside
    /// `properties`; the consent prompt shows it so the user sees WHO asks.
    pub app_name: Option<String>,
    /// The percent-decoded, base64-decoded payload bytes. `None` for
    /// `selectcert`, which carries no document.
    pub data: Option<Vec<u8>>,
    /// Session id (`idsession` on the wire), AutoFirma's own limit: at most
    /// 20 alphanumeric characters, because it is used as a file name on the
    /// intermediate server (see `UrlParametersToSign.setSignParameters`).
    pub id_session: Option<String>,
    /// The `properties` parameter (the page's extraParams): base64 of a Java
    /// `.properties` body. Decoded and parsed exactly like AutoFirma does —
    /// `UrlParametersToSign.setSignParameters` runs the value through
    /// `AOUtil.base642Properties`, an ISO-8859-1 `Properties.load` (finding
    /// A-4: ignoring this parameter silently meant signing bytes nobody asked
    /// to sign, e.g. a pre-computed hash signed as if it were the document).
    /// The one difference from AutoFirma's behaviour is on the strict side of
    /// the wire, not the payload: its parser base64-decodes with a decoder
    /// that SKIPS whitespace inside the stream (the iharder alphabet carries
    /// \t\n\r — `Base64.java:623`), while openfirma requires compact base64
    /// here and refuses otherwise. A wrapped `properties` value therefore
    /// lands where AutoFirma's logger line "no se han podido cargar" would:
    /// empty properties, applied as none; that is safe because dispatch, unlike
    /// AutoFirma, REFUSES by name any property whose absence it cannot verify
    /// (the A-4 rule below), so "could not load" can never silently become
    /// "sign something weaker". An absent or unparseable `properties` is still
    /// AutoFirma's own empty `Properties()`.
    pub properties: Properties,
    /// Whether the URI carried a storage-servlet callback (`stservlet`) at
    /// all. Recorded sedes URIs send it even when `dat` is present (it is
    /// their return channel); dispatch refuses any operation whose result can
    /// only leave through it, because openfirma posts nothing to remote
    /// servers (ADR-0005) and a silent success would leave the sede waiting
    /// for bytes that never arrive (finding M-5).
    pub storage_callback: bool,
    /// Protocol version parameters as recorded on the wire (`v` on the launch
    /// URIs — `ProtocolInvocationLauncher.PROTOCOL_VERSION_PARAM`, line 85 —
    /// and `ver`/`mcv` per operation — `UrlParametersToSign.VER_PARAM`). The
    /// error wire form depends on them (finding M-2:
    /// `ProtocolInvocationLauncherErrorManager.getErrorMessage` answers the
    /// `err-00:=AFxxxxxx - …` form only for protocol 4.1 and above, and the
    /// old `SAF_xx: mensaje` form below it), so parsing keeps them instead of
    /// dropping them like a version-blind client would.
    pub protocol_version: Option<String>,
}

/// The parsed `properties` parameter: a small ordered string map in Java
/// `.properties` shape. Ordered so refusals name keys in the order the sede
/// sent them; duplicate keys keep AutoFirma's last-wins rule (`Properties` is
/// a hashtable whose repeated put wins on value).
#[derive(Debug, Default, Clone)]
pub struct Properties(Vec<(String, String)>);

impl Properties {
    /// Parse like `java.util.Properties.load` (the decoder AutoFirma reaches
    /// through `AOUtil.base642Properties`): `#` and `!` start comment lines,
    /// a trailing odd run of `\` joins the next physical line, keys separate
    /// from values at the first unescaped `=`, `:` or whitespace run, leading
    /// whitespace is stripped on both sides, and `\n`/`\t`/`\r`/`\f`/`\\`
    /// escapes decode while any other escaped character loses its backslash.
    fn parse_java(text: &str) -> Properties {
        let mut out = Properties::default();
        let mut pending = String::new();
        for raw in text.split(['\n', '\r']) {
            let joined = if pending.is_empty() {
                raw.to_string()
            } else {
                pending.push_str(raw);
                std::mem::take(&mut pending)
            };
            let line = strip_properties_leading(&joined);
            if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
                continue;
            }
            // A trailing odd run of backslashes continues the logical line.
            let slashes = line.bytes().rev().take_while(|b| *b == b'\\').count();
            if slashes % 2 == 1 {
                pending.push_str(&line[..line.len() - 1]);
                continue;
            }
            out.set(match split_property_line(line) {
                Some(pair) => pair,
                // A line with no separator is a key with an empty value —
                // Properties.load semantics.
                None => (unescape_property(line), String::new()),
            });
        }
        // A file that ends mid-continuation: the joined line is still a line.
        let line = strip_properties_leading(&pending);
        if !line.is_empty() && !line.starts_with('#') && !line.starts_with('!') {
            out.set(match split_property_line(line) {
                Some((k, v)) => (k, v),
                None => (unescape_property(line), String::new()),
            });
        }
        out
    }

    /// The value of `key` by exact name — Java properties are case sensitive
    /// and every key AutoFirma defines has a fixed spelling.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0
            .iter()
            .rev()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// Whether no property was loaded at all — AutoFirma's empty
    /// `Properties()` branch: a call with no `properties` must behave exactly
    /// like one whose `properties` decodes to nothing.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Every key, in the order loaded. Dispatch walks this to apply what it
    /// can and refuse — by name — anything that changes what gets signed
    /// (finding A-4: never ignore in silence).
    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(|(k, _)| k.as_str())
    }

    fn set(&mut self, pair: (String, String)) {
        let key = pair.0.clone();
        self.0.retain(|(k, _)| *k != key);
        self.0.push(pair);
    }
}

fn strip_properties_leading(line: &str) -> &str {
    line.trim_start_matches([' ', '\t', '\u{c}'])
}

/// Split one logical properties line at its first unescaped `=`, `:` or
/// whitespace run (a whitespace separator may be followed by more whitespace,
/// which belongs to the separator, not the value — Properties.load semantics).
fn split_property_line(line: &str) -> Option<(String, String)> {
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'=' | b':' => {
                return Some((
                    unescape_property(&line[..i]),
                    unescape_property(line[i + 1..].trim_start_matches([' ', '\t', '\u{c}'])),
                ));
            }
            b' ' | b'\t' | 0x0c => {
                // The key ends at the whitespace run UNLESS a '=' or ':'
                // follows it (then that is the separator).
                let mut j = i;
                while j < bytes.len() && matches!(bytes[j], b' ' | b'\t' | 0x0c) {
                    j += 1;
                }
                if j < bytes.len() && matches!(bytes[j], b'=' | b':') {
                    i = j;
                    continue;
                }
                return Some((
                    unescape_property(&line[..i]),
                    unescape_property(line[j..].trim_start_matches([' ', '\t', '\u{c}'])),
                ));
            }
            _ => i += 1,
        }
    }
    None
}

/// The properties unescaping a loaded value went through: `\n`, `\t`, `\r`,
/// `\f` decode, and any other escaped character keeps itself without the
/// backslash (Properties.load drops the invalid escape marker).
fn unescape_property(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('f') => out.push('\u{c}'),
            Some(other) => out.push(other),
            None => out.push('\\'),
        }
    }
    out
}

/// Why an `afirma://` URI was refused. The message says what and why, in the
/// style every other error in this workspace follows.
#[derive(Debug)]
pub struct UriError {
    message: String,
    /// AutoFirma's own error code for this refusal (the 6-digit catalogues in
    /// `es.gob.afirma.core.ErrorCode` and `SimpleErrorCode`), so an error that
    /// reaches a page carries the number the page's script knows rather than
    /// one only openfirma assigns (finding M-2).
    code: crate::dispatch::WireError,
}

impl UriError {
    fn new(msg: impl Into<String>) -> Self {
        // The generic request-shaped refusal; call sites with a more exact
        // AutoFirma counterpart name one through `with_code`.
        UriError::with_code(crate::dispatch::WireError::MALFORMED_SOCKET_PARAMS, msg)
    }

    fn with_code(code: crate::dispatch::WireError, msg: impl Into<String>) -> Self {
        UriError {
            message: msg.into(),
            code,
        }
    }

    pub fn wire_error(&self) -> crate::dispatch::WireError {
        self.code
    }
}

impl std::fmt::Display for UriError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for UriError {}

impl From<UriError> for BrowserError {
    fn from(e: UriError) -> Self {
        BrowserError::with_wire(e.wire_error(), "uri-parse", e.to_string())
    }
}

use crate::dispatch::BrowserError;

/// Percent-decode one query value the way AutoFirma does: `+` and `%XX`,
/// UTF-8. A `%` not followed by two hex digits is a parse error, not a
/// silent pass-through — AutoFirma's decoder keeps the raw bytes in that
/// case, which we refuse instead of guessing an encoding for.
fn percent_decode(text: &str) -> Result<Vec<u8>, UriError> {
    percent_decode_bytes(text.as_bytes())
}

/// The byte-level decoder; a `dat` value must be decodable *before* it is
/// UTF-8 validated (base64 keeps its '=' padding through the wire, so bytes
/// are the honest domain here).
fn percent_decode_bytes(b: &[u8]) -> Result<Vec<u8>, UriError> {
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                // A '%' needs its two hex digits: at the very end of a value an
                // escape occupies indices len-3..len-1, so the truncation test
                // is `i > len - 3`. The first version of this check wrote
                // `i + 2 >= len` — off by one — which rejected every legal URI
                // whose last parameter ended in an escape (exactly what a
                // page's encodeURIComponent produces for padded base64:
                // `%3D%3D`). AutoFirma's URLDecoder treats the same input as
                // valid, so this decoder must accept it too.
                if i + 2 > b.len() - 1 {
                    return Err(UriError::new(
                        "the percent-encoding of a parameter is truncated: % must be followed \
                         by two hex digits",
                    ));
                }
                let hi = hex_val(b[i + 1])?;
                let lo = hex_val(b[i + 2])?;
                out.push(hi * 16 + lo);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    Ok(out)
}

fn hex_val(c: u8) -> Result<u8, UriError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(UriError::new(
            "the percent-encoding of a parameter contains non-hex characters",
        )),
    }
}

/// The operation part AutoFirma reads from the host position of the URI:
/// everything between `afirma://` and the first `?`, minus one trailing `/`.
fn parse_operation(scheme_and_host: &str) -> Result<Operation, UriError> {
    let after_scheme = scheme_and_host
        .strip_prefix("afirma://")
        .or_else(|| scheme_and_host.strip_prefix("AFIRMA://"))
        .ok_or_else(|| {
            UriError::new(
                "an openfirma browser call must start with the scheme afirma:// — register it \
                 with see docs/adr/0005-browser-protocol.md",
            )
        })?;
    let host = after_scheme.split(['?', '/']).next().unwrap_or("");
    // AutoFirma puts the raw host in as `op` without lowercasing, then matches
    // SIGN/COSIGN/COUNTERSIGN case-insensitively and the launcher dispatches
    // on lowercase prefixes. We canonicalise once, here.
    Operation::parse(host).ok_or_else(|| {
        UriError::new(format!(
            "the operation {host:?} is not one this client implements: an afirma:// URI carries \
             its operation as the host part, and openfirma supports sign, cosign, countersign \
             and selectcert"
        ))
    })
}

/// Splits a query string into pairs on the first `=`, percent-decoding the
/// key too (AutoFirma keys the parameters before decoding them — its decoder
/// does not touch the key; we keep that behaviour: keys stay as sent).
fn parse_query(query: &str) -> Result<Vec<(String, String)>, UriError> {
    let mut pairs = Vec::new();
    for part in query.split('&') {
        if part.is_empty() {
            continue;
        }
        let (key, value) = match part.split_once('=') {
            // A `dat` is the one parameter kept raw: its own decoder applies
            // percent decoding and base64 in AutoFirma's order, and the size
            // caps are meaningful on the encoded form. Every other parameter
            // is a text value that must be usable decoded or is refused.
            Some(("dat", v)) => ("dat".to_string(), v.to_string()),
            Some((k, v)) => {
                let decoded = percent_decode(v)?;
                let decoded = String::from_utf8(decoded).map_err(|_| {
                    UriError::new(format!(
                        "the parameter {k:?} does not decode to UTF-8; AutoFirma's parameters \
                         are percent-encoded text"
                    ))
                })?;
                (k.to_string(), decoded)
            }
            None => (part.to_string(), String::new()),
        };
        pairs.push((key, value));
    }
    Ok(pairs)
}

/// Percent-decoding that returns the decoded text: AutoFirma's parser decodes
/// every parameter once (`URLDecoder.decode`), so a dat whose percent escapes
/// leave invalid UTF-8 is refused then, not passed to base64 half-decoded.
fn percent_decode_str(text: &str) -> Result<String, UriError> {
    let bytes = percent_decode_bytes(text.as_bytes())?;
    String::from_utf8(bytes).map_err(|_| {
        UriError::new(
            "the dat parameter does not decode to UTF-8 text; AutoFirma sends it \
             percent-encoded and base64",
        )
    })
}

/// `dat` arrives percent-decoded already. AutoFirma then runs it through
/// `DataDownloader.downloadData`, which (in order) treats an `http(s)://` or
/// `ftp://` prefix as a URL to fetch, and otherwise decodes base64 — falling
/// back to the literal bytes when not base64 at all. The gzip flag decompresses
/// the decoded result. We implement the base64 + gzip paths, refuse the URL
/// ones (fetching remote documents from inside the browser protocol is what
/// ADR-0005 rules out; a URI that needs it belongs to the intermediate-server
/// flow, not to this client), and — the one deliberate deviation from AutoFirma
/// here — refuse instead of falling back when the payload does not decode: see
/// the comment at the decode call for why signing literal text is worse than
/// refusing the call.
fn decode_dat_text(value: &str, gzipped: bool) -> Result<Vec<u8>, UriError> {
    let trimmed = value.trim();
    if trimmed.starts_with("http://")
        || trimmed.starts_with("https://")
        || trimmed.starts_with("ftp://")
    {
        return Err(UriError::new(
            "a dat parameter that names a URL is not supported: openfirma never fetches \
             document bytes from the browser protocol (docs/adr/0005-browser-protocol.md); \
             pass the document itself base64-encoded, or use `openfirma sign` with a file",
        ));
    }
    if trimmed.starts_with("file:") {
        return Err(UriError::new(
            "reading local files through dat is refused, as it is by AutoFirma itself \
             (UrlParameters.setCommonParameters: \"No se permite la lectura de ficheros locales\")",
        ));
    }
    // base64 with the URL-safe variants accepted, which is what AutoFirma's
    // own decoder does (`Base64.decode`: "_" -> "/", "-" -> "+"), and with
    // percent-encoding already gone. A payload that is not base64 at all is
    // taken as literal bytes by AutoFirma; here it still has to look like
    // base64, because the sedes always send base64 and anything else means a
    // broken URI more often than a raw text document.
    //
    // ASCII whitespace is dropped before decoding, which is what AutoFirma's
    // decoder does too: its alphabet (`Base64.java:623`) contains \t, \n and
    // \r, so the iharder decoder it calls skips that whitespace *inside* the
    // stream. A sede whose server wraps the base64 into MIME lines of 76
    // (`Base64.encode(x, DO_BREAK_LINES)`, a normal practice) therefore signs
    // the document in AutoFirma; an implementation that rejected the newlines
    // instead — or fell back to signing the literal text when strict decoding
    // failed — would sign the base64 *text* with no warning, a detached
    // signature over bytes nobody asked to sign (RFC 4648 §3.3: whitespace is
    // ignored in the data). Only `\t \n \f \r space` are stripped; other
    // Unicode blanks are not part of AutoFirma's alphabet and must refuse.
    let mut b64 = String::with_capacity(trimmed.len());
    for c in trimmed.chars() {
        if !c.is_ascii_whitespace() {
            b64.push(match c {
                '_' => '/',
                '-' => '+',
                other => other,
            });
        }
    }
    // The cap applies to what the decoder will produce, which a byte count of
    // valid base64 bounds exactly (every 4 characters decode to at most 3
    // bytes). Checking before decoding is the whole point: an oversized
    // payload must never be materialised to discover its size. For gzip=true
    // the bound still holds and stays meaningful — decompression stops at
    // limit+1 below, so a bomb is refused without inflating, and any stream
    // whose *compressed* form exceeds the cap could only hold more data.
    if b64.len() / 4 * 3 + 3 > MAX_DATA_BYTES {
        return Err(UriError::new(format!(
            "a dat payload of about {} bytes exceeds the {} byte limit openfirma accepts for \
             one browser call",
            b64.len() / 4 * 3,
            MAX_DATA_BYTES
        )));
    }
    let engine = base64::engine::general_purpose::STANDARD;
    // There is deliberately no literal-text fallback here, where AutoFirma
    // has one (`DataDownloader.java:127-137` signs the raw bytes when its
    // `isBase64` check fails). The fallback's only effect in openfirma was
    // that a payload which failed to decode — historically a *wrapped*
    // base64, whose interior newlines the strict decoder rejected — was
    // signed as the base64 text instead of the document: a valid-looking
    // signature over bytes the sede never sent. Signing the wrong bytes in
    // silence is exactly what this client must never do; a `dat` that does
    // not decode is refused with the parameter named, and the caller fixes
    // the URI or uses `openfirma sign` with the real file.
    let bytes = engine.decode(b64.as_bytes()).map_err(|e| {
        UriError::new(format!(
            "the dat parameter is not valid base64 ({e}): openfirma signs the decoded \
             document bytes and never falls back to signing the text verbatim, because a \
             signature over the wrong bytes would still look valid to a sede"
        ))
    })?;
    if bytes.len() > MAX_DATA_BYTES {
        return Err(UriError::new(format!(
            "a dat payload of {} bytes exceeds the {} byte limit openfirma accepts for one \
             browser call",
            bytes.len(),
            MAX_DATA_BYTES
        )));
    }
    if !gzipped {
        return Ok(bytes);
    }
    // AutoFirma's `gzip=true` means "base64 of a GZIP stream, sign the
    // decompressed result" (DataDownloader.downloadData with gzipped). flate2
    // with rust_backend is pure Rust; the same pin as the PDF reader uses.
    use std::io::Read;
    let mut decoder = flate2::read::GzDecoder::new(&bytes[..]);

    // Read with a cap so a zip bomb cannot grow past the document limit.
    let mut out = Vec::new();
    let limit = MAX_DATA_BYTES + 1;
    decoder
        .by_ref()
        .take(limit as u64)
        .read_to_end(&mut out)
        .map_err(|e| UriError::new(format!("the gzip dat payload does not decompress: {e}")))?;
    if out.len() > MAX_DATA_BYTES {
        return Err(UriError::new(format!(
            "the gzip dat payload decompresses past the {} byte limit",
            MAX_DATA_BYTES
        )));
    }
    Ok(out)
}

/// The `idsession` check AutoFirma applies to every session id: at most
/// 20 characters, `[a-z0-9]` AFTER lower-casing, because the value becomes a
/// file name on whatever callback channel exists.
///
/// The lower-case fold is part of the rule and not an extra kindness
/// (finding A-5): `UrlParametersToSign.setSignParameters` validates
/// `sessionId.toLowerCase(Locale.ENGLISH)` — recorded at line 235 of that
/// file, in 1.9.1 sources:
///
/// ```java
/// for (final char c : sessionId.toLowerCase(Locale.ENGLISH).toCharArray()) {
///     if ((c < 'a' || c > 'z') && (c < '0' || c > '9')) {
///         throw new ParameterException("El identificador de la firma debe ser alfanumerico."…
/// ```
///
/// while the real page GENERATES ids with capitals: autoscript.js builds them
/// from `VALID_CHARS_TO_ID` (line 1902), a 61-character alphabet whose last
/// 26 entries are uppercase. A validator that required lower case in the raw
/// value would refuse essentially every call a real sede makes (the probability
/// of a 20-character id without a single capital is (35/61)^20 ≈ 1.5·10⁻⁵).
/// The ORIGINAL value is what we keep and compare — AutoFirma keeps it too
/// (`setSessionId(sessionId)`, the un-lower-cased one), and `afirma://service`
/// echoes it back to the socket peer byte for byte.
fn check_id_session(raw: &str) -> Result<Option<String>, UriError> {
    if raw.is_empty() {
        return Ok(None);
    }
    // The operation parsers name INVALID_SESSION_ID_* for both rules below
    // (UrlParametersToSign:231/237, UrlParametersToSelectCert:135/141), and the
    // error manager maps that family to SAF_46; AF 620010 is the launcher-side
    // session check (`AfirmaWebSocketServerV4Sup.onMessage` compares the socket
    // session). Both are "the session identifier is incorrect", so one pair.
    if raw.len() > 20 {
        return Err(UriError::with_code(
            crate::dispatch::WireError::INVALID_SESSION_ID,
            format!(
                "idsession is {} characters, AutoFirma's own limit for the session id is 20 \
                 (it becomes a file name on the callback)",
                raw.len()
            ),
        ));
    }
    // `checkIdSession`'s character test (`id.toLowerCase().matches("([a-z0-9])+")`)
    // runs AFTER its own lowercasing: upper-case ids pass the check but keep
    // their original case in the value (A-5 — the follow-up getresult matches
    // byte-for-byte, so only the TEST is case-folded, never the stored id).
    if !raw
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c.is_ascii_uppercase())
    {
        return Err(UriError::with_code(
            crate::dispatch::WireError::INVALID_SESSION_ID,
            "idsession must be alphanumeric (upper case included, lower-cased first exactly as \
             UrlParametersToSign does, because AutoFirma reuses it as a file name); this URI \
             carries characters outside that set",
        ));
    }
    Ok(Some(raw.to_string()))
}

/// Parses one `afirma://` invocation URI into the operation and payload a
/// sede's page actually sends. The rules are AutoFirma's, line by line in
/// `ProtocolInvocationUriParser.parserUri` / `UrlParameters*`. This is the
/// *scheme hand-off* entry: nothing else bounded the bytes before this call,
/// so [`MAX_URI_BYTES`] applies. Through the loopback endpoint the same text
/// arrives as a request body already bounded by `serve::MAX_BODY_BYTES` (a
/// different, larger wire bound), and that path parses via
/// [`parse_endpoint_body`]. Both share one implementation; the document cap
/// below them judges every path alike.
pub fn parse(uri: &str) -> Result<AfirmaUri, UriError> {
    parse_inner(uri, true)
}

/// Parse the body of one loopback endpoint request. The body is a JSON object
/// or plain text exactly as an sede's script posts it; through this channel
/// bytes were already bounded by `serve::MAX_BODY_BYTES` at the socket and
/// never travelled through a URI hand-off, so [`MAX_URI_BYTES`] — which exists
/// for that other channel — is not applied. The document cap
/// ([`MAX_DATA_BYTES`]) still judges every path alike.
pub fn parse_endpoint_body(body: &[u8]) -> Result<AfirmaUri, UriError> {
    let text = std::str::from_utf8(body).map_err(|_| {
        UriError::new(
            "the body of a signing call must be UTF-8 text (JSON or an afirma:// URI): openfirma \
             does not guess at binary it cannot read",
        )
    })?;
    let (candidate, message_version) = extract_endpoint_uri(text)?;
    let mut uri = parse_uri_no_channel_cap(&candidate)?;
    // A JSON wrapper may name the protocol version beside `message`; the URI
    // itself wins when it carries its own ver/v (recorded AutoFirma messages
    // re-emit the same value into the URI, so both readings agree whenever a
    // sender is consistent).
    if uri.protocol_version.is_none() {
        uri.protocol_version = message_version;
    }
    Ok(uri)
}

/// Pull the operation URI out of an endpoint body, plus its protocol version.
/// AutoFirma's socket receives the `afirma://` URI as the message text itself
/// (`AfirmaWebSocketServerV4Sup.onMessage` matches its prefixes directly —
/// `echo=`, the batch headers, and otherwise hands the whole string to the
/// same launcher that parsed the scheme URI). A JSON wrapper naming the URI
/// under `"message"` is also accepted, because a hand-written sede client
/// finds posting an object easier than URL-encoding a document into a
/// text/plain body. The returned version is the `ver` query parameter when the
/// message names one — the same rule as AutoFirma's JSON messages, whose
/// `version` member just re-emits that parameter onto the parsed URI.
fn extract_endpoint_uri(text: &str) -> Result<(String, Option<String>), UriError> {
    let trimmed = text.trim();
    if trimmed.starts_with('{') {
        // JSON body first — see below why this order matters. A small scanner
        // over the object's top level, string-aware: braces inside strings
        // cannot fake a nested scope and escape sequences (an encoded `\"` in
        // a URI member) cannot truncate the value. A hand-rolled substring
        // search once returned text between two unrelated quotes; with an
        // error wire now travelling to pages, that kind of misread is exactly
        // what must not exist. Richer JSON than {"message": "..."} still gets
        // a precise refusal below.
        if let Some(value) = json_string_member(trimmed, "message") {
            return Ok((value.to_string(), version_of(value)));
        }
        return Err(UriError::new(
            "a JSON endpoint body must carry the operation URI as its \"message\" member: \
             openfirma found a JSON object without one",
        ));
    }
    if trimmed.starts_with("afirma://") {
        return Ok((trimmed.to_string(), version_of(trimmed)));
    }
    Err(UriError::new(
        "an endpoint body must be an afirma:// URI (AutoFirma's message form) or a JSON \
         object with a \"message\" member holding one; anything else cannot name an \
         operation to run",
    ))
}

/// The `ver`/`v` parameter of a message URI, read straight from its query —
/// it selects the error wire form (finding M-2), so the endpoint's error path
/// must see it even before the full parse.
fn version_of(uri: &str) -> Option<String> {
    let query = uri.split_once('?').map(|(_, q)| q)?;
    for pair in query.split('&') {
        let mut halves = pair.splitn(2, '=');
        let key = halves.next()?;
        if key == "ver" || key == "v" {
            return halves.next().map(str::to_string).filter(|v| !v.is_empty());
        }
    }
    None
}

/// Find one string member of a JSON object (top level), returning its decoded
/// value. Enough of a parser to be correct about strings: `\\` and `\"` are
/// honoured inside them, which is all an ASCII afirma:// URI needs (it arrives
/// percent-encoded, so no other escapes can appear in a real message).
fn json_string_member<'a>(text: &'a str, wanted: &str) -> Option<&'a str> {
    let bytes = text.as_bytes();
    let mut i = 0usize;
    let mut depth = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'{' | b'[' => {
                depth += 1;
                i += 1;
            }
            b'}' | b']' => {
                depth = depth.saturating_sub(1);
                i += 1;
            }
            b'"' => {
                // Read the whole string token, tracking escapes.
                let start = i + 1;
                let mut j = start;
                while j < bytes.len() {
                    match bytes[j] {
                        b'\\' => j += 2,
                        b'"' => break,
                        _ => j += 1,
                    }
                }
                if j >= bytes.len() {
                    return None; // unterminated string
                }
                let token = &text[start..j];
                // A member name is followed (after whitespace) by ':'.
                let mut k = j + 1;
                while k < bytes.len() && (bytes[k] as char).is_whitespace() {
                    k += 1;
                }
                if depth == 1 && bytes.get(k) == Some(&b':') && token == wanted {
                    // Now read the member's value: it must be a string.
                    let mut v = k + 1;
                    while v < bytes.len() && (bytes[v] as char).is_whitespace() {
                        v += 1;
                    }
                    if bytes.get(v) != Some(&b'"') {
                        return None;
                    }
                    let vstart = v + 1;
                    let mut e = vstart;
                    while e < bytes.len() {
                        match bytes[e] {
                            b'\\' => e += 2,
                            b'"' => break,
                            _ => e += 1,
                        }
                    }
                    if e >= bytes.len() {
                        return None;
                    }
                    let raw = &text[vstart..e];
                    // An escaped member cannot be returned borrowed, and an
                    // encoded URI never needs escapes (percent-encoding
                    // reserves `\` itself), so a message carrying one is not a
                    // real client's path — refuse it rather than hand back the
                    // raw bytes with their backslashes.
                    if raw.contains('\\') {
                        return None;
                    }
                    return Some(raw);
                }
                i = j + 1;
            }
            _ => i += 1,
        }
    }
    None
}

/// Parse one operation URI with the channel cap lifted (the endpoint path).
fn parse_uri_no_channel_cap(uri: &str) -> Result<AfirmaUri, UriError> {
    parse_inner(uri, false)
}

/// The endpoint's error-path read of a body's protocol version WITHOUT the
/// full parse — an operation refusal must choose its wire form even when the
/// URI itself was refused. `serve.rs` reads it through this function on every
/// this same function, so the text a page receives and the version that
/// selected it cannot disagree.
pub fn endpoint_message_version(body: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(body).ok()?;
    extract_endpoint_uri(text.trim()).ok().and_then(|(_, v)| v)
}

/// The shared implementation; `apply_uri_cap` is the only difference between
/// the two entry points, so endpoint and scheme hand-off cannot drift apart in
/// any other rule.
fn parse_inner(uri: &str, apply_uri_cap: bool) -> Result<AfirmaUri, UriError> {
    if apply_uri_cap && uri.len() > MAX_URI_BYTES {
        return Err(UriError::new(format!(
            "the URI is {} bytes over the {} byte limit openfirma accepts for one browser \
             call",
            uri.len() - MAX_URI_BYTES,
            MAX_URI_BYTES
        )));
    }
    let operation = parse_operation(uri)?;
    let query = match uri.find('?') {
        Some(i) => &uri[i + 1..],
        None => "",
    };
    let pairs = parse_query(query)?;

    let mut format = None;
    let mut algorithm = None;
    let mut app_name = None;
    // The dat value stays percent-encoded here: the document's own decoder
    // percent-decodes it *then* base64s, in AutoFirma's order (parserUri ->
    // DataDownloader), and keeping the encoding visible on both sides of the
    // cap arithmetic is what keeps the URI-level limit honest about documents.
    let mut dat: Option<String> = None;
    let mut gzipped = false;
    let mut id_session = None;
    let mut rtservlet = false;
    let mut stservlet = false;
    let mut properties_raw: Option<String> = None;
    let mut protocol_version = None;

    for (key, value) in pairs {
        // AutoFirma's parser puts every pair with a non-empty key into the map;
        // duplicates let the *last* one win because it is a HashMap keyed by
        // name. Same here: we overwrite on repeat.
        match key.as_str() {
            "format" => format = Some(value),
            "algorithm" => algorithm = Some(value),
            "appname" => app_name = Some(value),
            "dat" => dat = Some(value),
            "gzip" => gzipped = value.eq_ignore_ascii_case("true"),
            "idsession" | "id" => {
                // The launcher reads `idsession` (ProtocolInvocationLauncher,
                // IDSESSION_PARAM); the per-operation parsers read `id`. Both
                // name the same session and both travel in recorded URIs.
                id_session = check_id_session(&value)?;
            }
            "rtservlet" => rtservlet = true,
            // stservlet is RECORDED (kept as a flag) rather than refused at
            // parse time: recorded sedes URIs carry it on every sign call even
            // when dat travels with them (`TestProtocolInvocation.java:18`),
            // and refusing at parse would fail URIs whose answer channel we
            // could in principle supply one day. What dispatch does with it is
            // the safety half: an operation whose result can only leave
            // through the servlet is refused there by name (finding M-5), not
            // signed-and-forgotten like the old code did.
            "stservlet" => stservlet = true,
            // AutoFirma keeps the raw value here and decodes it in the
            // operation's parser (`AOUtil.base642Properties`); the same split:
            // parse reads, dispatch applies or refuses by key name.
            "properties" => properties_raw = Some(value),
            // `v` is the launch URI's protocol version (autoscript.js:2470 puts
            // it there), `ver` the per-operation one, `mcv` the minimum client
            // version; all three decide reply shapes in AutoFirma's launcher, so
            // an error path must be able to see them.
            "v" | "ver" if protocol_version.is_none() => {
                protocol_version = Some(value);
            }
            _ => {}
        }
    }

    // The legacy intermediate-server flow is a *route*, not a ban on the
    // callback parameters: recorded URIs carry stservlet/rtservlet even when
    // they also carry dat (the servlets then only serve as the return channel,
    // and via fileid as the data source). A URI is refused for the route only
    // when it would *need* it — a sign/selectcert call without dat has no data
    // and no callback we could use. That rule lives after the parameter loop,
    // below; parsing a recorded URI must never fail just because AutoFirma's
    // legacy parameters travel in it.

    let properties = match &properties_raw {
        Some(raw) => {
            // The URL-safe fold runs first exactly like every other base64
            // AutoFirma reads (`base642Properties` itself replaces '-'/'_'
            // before decoding: `Base64.decode(base64.replace('-', '+').replace('_', '/'))`).
            let b64: String = raw
                .chars()
                .filter(|c| !c.is_ascii_whitespace())
                .map(|c| match c {
                    '_' => '/',
                    '-' => '+',
                    other => other,
                })
                .collect();
            match base64::engine::general_purpose::STANDARD.decode(b64.as_bytes()) {
                // Java's Properties.load reads ISO-8859-1 bytes; every key and
                // value AutoFirma defines is ASCII, so decoding the whole body
                // as UTF-8-with-fallback loses nothing a real sede can send.
                Ok(bytes) => Properties::parse_java(&String::from_utf8_lossy(&bytes)),
                // A properties body that cannot be decoded lands where
                // AutoFirma's own catch-and-log puts it — empty extraParams —
                // and is safe here only because dispatch refuses by NAME any
                // property whose absence it cannot verify (A-4). That refusal
                // is what makes "could not load" mean "nothing was asked",
                // never "something was silently dropped".
                Err(_) => Properties::default(),
            }
        }
        None => Properties::default(),
    };

    let data = match &dat {
        None => {
            if operation == Operation::SelectCert {
                // selectcert carries no document at all.
                None
            } else if rtservlet || stservlet {
                // The intermediate-server flow (recorded calls carry the
                // servlet URLs): AutoFirma fetches dat by fileid from a
                // government retrieve service and posts its answer to the
                // storage one. openfirma has no such callback — ADR-0005 — so
                // this is exactly the route that cannot be served here, said
                // with its own name.
                return Err(UriError::new(
                    "rtservlet/stservlet without dat make the government intermediate server \
                     both the data source and the callback; openfirma has no such path (see \
                     docs/adr/0005-browser-protocol.md), so this URI cannot be served here",
                ));
            } else {
                return Err(UriError::new(
                    "no dat parameter: a signing call must carry the document to sign \
                     (base64, optionally gzip), and only selectcert may arrive without one",
                ));
            }
        }
        // AutoFirma's parser URL-decodes every parameter before it is read;
        // the decode happens here so a dat whose percent escapes leave invalid
        // UTF-8 is refused where that happens, with its own message. The wire
        // length of the decoded text is what the *document* cap judges: 16 MiB
        // of data can travel in URI spellings far longer than MAX_URI_BYTES (a
        // base64 PDF expands again under percent-encoding); only the socket
        // flow's own body cap (`serve::MAX_BODY_BYTES`) bounds what we even
        // read, and this decode-time cap is the last one standing.
        Some(raw) => Some(decode_dat_text(&percent_decode_str(raw)?, gzipped)?),
    };

    Ok(AfirmaUri {
        operation,
        format,
        algorithm,
        app_name,
        data,
        id_session,
        properties,
        storage_callback: stservlet,
        protocol_version,
    })
}
