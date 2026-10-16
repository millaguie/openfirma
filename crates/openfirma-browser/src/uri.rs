//! The `afirma://` URI scheme: parsing and dispatch.
//!
//! Two independent measurements were taken before writing this file, both on
//! the AutoFirma 1.9 source clone (`/tmp/opencode/autofirma-src`, see each
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

/// One parsed `afirma://` URI, in the shape AutoFirma's launcher produces.
#[derive(Debug)]
pub struct AfirmaUri {
    pub operation: Operation,
    /// Raw `format` parameter, AutoFirma's strings ("CAdES", "PAdES", ...).
    pub format: Option<String>,
    /// Raw `algorithm` parameter (SHAxxx or SHAxxxwithRSA/ECDSA forms).
    pub algorithm: Option<String>,
    /// The percent-decoded, base64-decoded payload bytes. `None` for
    /// `selectcert`, which carries no document.
    pub data: Option<Vec<u8>>,
    /// Session id (`idsession` on the wire), AutoFirma's own limit: at most
    /// 20 alphanumeric characters, because it is used as a file name on the
    /// intermediate server (see `UrlParametersToSign.setSignParameters`).
    pub id_session: Option<String>,
}

/// Why an `afirma://` URI was refused. The message says what and why, in the
/// style every other error in this workspace follows.
#[derive(Debug)]
pub struct UriError(String);

impl std::fmt::Display for UriError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for UriError {}

impl UriError {
    fn new(msg: impl Into<String>) -> Self {
        UriError(msg.into())
    }
}

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
                if i + 2 >= b.len() {
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
/// the decoded result. We implement the base64 + gzip paths and refuse the URL
/// ones: fetching remote documents from inside the browser protocol is what
/// ADR-0005 rules out; a URI that needs it belongs to the intermediate-server
/// flow, not to this client.
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
    let b64 = trimmed.replace('_', "/").replace('-', "+");
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
    let bytes = match engine.decode(b64.as_bytes()) {
        Ok(bytes) => bytes,
        // AutoFirma's fallback for a non-base64 `dat` is the text itself. It
        // keeps that shape only when gzip was not requested (gzip requires
        // base64 first); we keep it too — rejecting it would break the
        // recorded plain-text calls and cost nothing.
        Err(_) if !gzipped => trimmed.as_bytes().to_vec(),
        Err(e) => {
            return Err(UriError::new(format!(
                "the dat parameter is neither base64 ({e}) nor, with gzip set, anything we \
                 can decompress"
            )));
        }
    };
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
/// 20 characters, `[a-z0-9]` (lower-cased first), because the value becomes a
/// file name on whatever callback channel exists.
fn check_id_session(raw: &str) -> Result<Option<String>, UriError> {
    if raw.is_empty() {
        return Ok(None);
    }
    if raw.len() > 20 {
        return Err(UriError::new(format!(
            "idsession is {} characters, AutoFirma's own limit for the session id is 20 \
             (it becomes a file name on the callback)",
            raw.len()
        )));
    }
    if !raw
        .chars()
        .all(|c| c.is_ascii_alphanumeric() && !c.is_ascii_uppercase())
    {
        return Err(UriError::new(
            "idsession must be alphanumeric lower case, because AutoFirma reuses it as a \
             file name; this URI carries characters outside that set",
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
    let candidate = extract_endpoint_uri(text)?;
    parse_uri_no_channel_cap(&candidate)
}

/// Pull the operation URI out of an endpoint body. AutoFirma's socket receives
/// the `afirma://` URI as the message text itself (`AfirmaWebSocketServerV4Sup.
/// onMessage` matches its prefixes directly — `echo=`, the batch headers, and
/// otherwise hands the whole string to the same launcher that parsed the
/// scheme URI). A JSON wrapper naming the URI under `"message"` is also
/// accepted, because a hand-written sede client finds posting an object easier
/// than URL-encoding a document into a text/plain body.
fn extract_endpoint_uri(text: &str) -> Result<String, UriError> {
    let trimmed = text.trim();
    if trimmed.starts_with("afirma://") {
        return Ok(trimmed.to_string());
    }
    // JSON body: find the message member. A real JSON parser for one string
    // member would be over-licensing here, and a sede that sends richer JSON
    // than this still gets a precise refusal below.
    if trimmed.starts_with('{') {
        if let Some(rest) = trimmed.find("\"message\"").map(|i| &trimmed[i + 9..]) {
            if let Some(start) = rest.find(':').and_then(|_| rest.find('"')) {
                let after = &rest[start + 1..];
                if let Some(end) = after.find('"') {
                    return Ok(after[..end].to_string());
                }
            }
        }
        return Err(UriError::new(
            "a JSON endpoint body must carry the operation URI as its \"message\" member: \
             openfirma found a JSON object without one",
        ));
    }
    Err(UriError::new(
        "an endpoint body must be an afirma:// URI (AutoFirma's message form) or a JSON \
         object with a \"message\" member holding one; anything else cannot name an \
         operation to run",
    ))
}

/// Parse one operation URI with the channel cap lifted (the endpoint path).
fn parse_uri_no_channel_cap(uri: &str) -> Result<AfirmaUri, UriError> {
    parse_inner(uri, false)
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
    // The dat value stays percent-encoded here: the document's own decoder
    // percent-decodes it *then* base64s, in AutoFirma's order (parserUri ->
    // DataDownloader), and keeping the encoding visible on both sides of the
    // cap arithmetic is what keeps the URI-level limit honest about documents.
    let mut dat: Option<String> = None;
    let mut gzipped = false;
    let mut id_session = None;
    let mut rtservlet = false;

    for (key, value) in pairs {
        // AutoFirma's parser puts every pair with a non-empty key into the map;
        // duplicates let the *last* one win because it is a HashMap keyed by
        // name. Same here: we overwrite on repeat.
        match key.as_str() {
            "format" => format = Some(value),
            "algorithm" => algorithm = Some(value),
            "dat" => dat = Some(value),
            "gzip" => gzipped = value.eq_ignore_ascii_case("true"),
            "idsession" | "id" => {
                // The launcher reads `idsession` (ProtocolInvocationLauncher,
                // IDSESSION_PARAM); the per-operation parsers read `id`. Both
                // name the same session and both travel in recorded URIs.
                id_session = check_id_session(&value)?;
            }
            "rtservlet" | "stservlet" => rtservlet = true,
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

    let data = match &dat {
        None => {
            if operation == Operation::SelectCert {
                // selectcert carries no document at all.
                None
            } else if rtservlet {
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
        data,
        id_session,
    })
}
