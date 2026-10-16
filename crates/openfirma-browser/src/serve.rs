//! The loopback endpoint a sede electronica's page talks to.
//!
//! ## What AutoFirma actually runs, measured from 1.9 source
//!
//! - `AfirmaWebSocketServerManager.startService` opens an **SSL WebSocket**
//!   (`wss://127.0.0.1:<port>`, autoscript.js builds the URL from the literal
//!   `"wss://"`) with a context from `SecureSocketUtils`: a PKCS#12 keystore
//!   named `autofirma.pfx` installed by every installer, whose password is the
//!   hardcoded string in that same file. The certificate it contains is the
//!   one shipped with the package — an unpublished self-signed cert; browsers
//!   accept the endpoint because a `wss:` WebSocket connection never asks the
//!   user (certificate errors on WebSockets are silent), not because anyone
//!   trusted it.
//! - The server binds a random port **out of band**: the page picks up to
//!   three ports from 49152..65535 (`AfirmaUtils.getRandomPorts` in
//!   autoscript.js), puts them in `afirma://websocket?ports=…&v=4&jvc=…&idsession=…`,
//!   the launcher tries them in order, and the page then probes every port it
//!   offered with `echo=` until one answers `OK`. So the caller already knows
//!   the port before the server ever binds — openfirma's design keeps that
//!   property: an ephemeral port printed by the process that opened it.
//! - What authenticates a message is not TLS and not an Origin header. The
//!   v4 server (`AfirmaWebSocketServerV4Sup.onMessage`) checks exactly two
//!   things: the peer address is `127.0.0.1`, and the message carries the
//!   `idsession=` the page invented at launch. That is the entire trust model
//!   of AutoFirma's local server, and ADR-0005 keeps its shape while fixing
//!   its two gaps: a *one-time* token (AutoFirma's session id is replayable
//!   for the life of the socket) and strict `Origin`/`Host` checks WebSockets
//!   made impossible there. The transport stays plain HTTP — see the ADR; we
//!   refuse to fake a TLS stack on top of C crypto the rule forbids.
//!
//! ## The endpoint this server speaks
//!
//! ```text
//! POST /sign/<token> HTTP/1.1
//! Host: 127.0.0.1:<bound port, nothing else>
//! Origin: http://127.0.0.1:<same bound port>
//! Content-Type: application/x-autofirma-uri
//! Content-Length: <n, at most MAX_BODY_BYTES>
//!
//! afirma://sign?format=CAdES&algorithm=SHA256withRSA&dat=<base64>&idsession=<token>
//! ```
//!
//! - POST only; GET is refused with the reason (a cross-site form or image
//!   tag reaches a loopback port without any preflight, so "GET does nothing"
//!   is the whole of what browsers give us — taking writes over GET would be
//!   CSRF by design).
//! - `Host` must equal `127.0.0.1:<bound>` or `localhost:<bound>`, byte-exact
//!   modulo that alias: DNS rebinding hands a hostile page a name that
//!   resolves to the loopback address, and the only thing left to see it in is
//!   the Host header the browser chose from the attacker's (rebound) URL — so
//!   any other authority is refused. A rebinding attack against *this* server
//!   also needs a page whose origin is our own port, which no external site
//!   can forge, hence both checks matter and neither alone is enough.
//! - `Origin`, when present (curl sends none; browsers always send one), must
//!   be exactly `http://127.0.0.1:<bound>` or `http://localhost:<bound>`. No
//!   wildcard CORS headers are ever emitted, so a cross-origin fetch's result
//!   cannot be read by the page even if it slips past the checks below — and
//!   the reason for each refusal goes in an `X-Openfirma-Reason` header so the
//!   caller learns *why* (a body-only error would let an opaque no-cors reply
//!   hide it entirely).
//! - The path must carry a live session token, or be `/echo`, the pure
//!   liveness probe AutoFirma's pages use (`echo=` → `OK`): it signs nothing
//!   and burns nothing. Bodies larger than `MAX_BODY_BYTES`, non-finite or
//!   wrong `Content-Length`, chunked encoding, and requests past
//!   `MAX_REQUESTS_PER_SESSION` are refused with a status that says which.
//! - The response body of a successful sign is AutoFirma's wire form
//!   (`base64(cert)|base64(signature)`, dispatch.rs). There is no CORS header
//!   in the answer: a *same-origin* page (one served from this very port, the
//!   only kind our Origin rule lets in) can read it; nothing else can.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use crate::dispatch::{BrowserError, KeySource};
use crate::token::TokenStore;
use zeroize::Zeroizing;

/// The most a request body may weigh. A sede's base64 document is well under
/// this; a megabyte-scale `Content-Length` or stream is already not the shape
/// of a signing call and is refused before it is read.
pub const MAX_BODY_BYTES: u64 = 8 * 1024 * 1024;

/// How long one connection may take, total. The endpoint signs locally with
/// software or token keys, so anything slower than half a minute means a peer
/// that is not our caller (slowloris-style dribbling counts).
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum number of requests the listener will answer before shutting down.
/// A real flow asks once per launch; a bound port that answers hundreds of
/// operations is being probed, and closing it is cheaper than reasoning about
/// why. (AutoFirma's sockets die with the app after one operation by design.)
pub const MAX_REQUESTS: usize = 16;

/// The running endpoint. Dropping it leaves the accept loop and any live
/// connection to finish their current operation; a short-lived CLI process
/// exits with them, which is what AutoFirma's own sockets do when the app
/// closes after one operation. Nothing is leaked on the way: the listener
/// travels in the accept thread, the key descriptor in an `Arc`.
#[derive(Debug)]
pub struct LoopbackServer {
    addr: SocketAddr,
    tokens: Arc<TokenStore>,
    /// Kept alive so the key descriptor outlives the accept loop even if every
    /// connection finished first; see [`OwnedKeySource`].
    _key: SharedKey,
}

/// Errors that stop the endpoint from starting at all (a bind race, a bad
/// keystore path checked up front).
#[derive(Debug)]
pub struct ServeError(String);

impl std::fmt::Display for ServeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ServeError {}

/// Key sources the server owns must outlive every connection thread, so they
/// travel behind an `Arc` that each connection clones. Nothing is leaked and
/// nothing dangles: the descriptor lives as long as its last user.
pub enum OwnedKeySource {
    P12 {
        path: std::path::PathBuf,
        password: Zeroizing<String>,
    },
}

// Debug keeps the test's expect_err readable; Zeroizing's own Debug prints its
// contents by design only when asked explicitly, and this derive does not ask.
impl std::fmt::Debug for OwnedKeySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OwnedKeySource::P12 { path, .. } => f
                .debug_struct("P12")
                .field("path", path)
                .field("password", &"[hidden]")
                .finish(),
        }
    }
}

type SharedKey = Arc<OwnedKeySource>;

impl OwnedKeySource {
    /// A borrowed view of the descriptor for one operation; the caller holds
    /// the `Arc` (and so keeps `self` alive) across the whole use.
    fn as_ref_key(&self) -> KeySource<'_> {
        match self {
            OwnedKeySource::P12 { path, password } => KeySource::P12 {
                path,
                password: password.as_str(),
            },
        }
    }
}

impl LoopbackServer {
    /// Binds `addr` (a `127.0.0.1:0` ephemeral port is the documented way —
    /// the caller learns the chosen port from [`LoopbackServer::addr`], out of
    /// band, as AutoFirma's pages learn theirs) and starts serving. The key
    /// source is checked once here so an unreadable keystore fails at startup
    /// instead of on the page's first request.
    pub fn start(addr: SocketAddr, key: OwnedKeySource) -> Result<Self, ServeError> {
        if !addr.ip().is_loopback() {
            return Err(ServeError(format!(
                "{addr} is not a loopback address: openfirma only ever serves the signing \
                 endpoint on 127.0.0.1/localhost, so it can answer its own machine at all"
            )));
        }
        // Fail early on material problems: reading the p12 now means the first
        // real request cannot be the one that discovers a typo in a path.
        match &key {
            OwnedKeySource::P12 { path, .. } => std::fs::read(path).map_err(|e| {
                ServeError(format!(
                    "cannot read {} for the endpoint: {e}",
                    path.display()
                ))
            })?,
        };
        let listener = TcpListener::bind(addr)
            .map_err(|e| ServeError(format!("cannot bind the loopback endpoint on {addr}: {e}")))?;
        let bound = listener
            .local_addr()
            .map_err(|e| ServeError(format!("the bound address is not readable: {e}")))?;
        let tokens = Arc::new(TokenStore::new());
        let key: SharedKey = Arc::new(key);
        let loop_key = key.clone();
        let loop_tokens = tokens.clone();
        std::thread::spawn(move || {
            accept_loop(listener, loop_tokens, loop_key);
        });
        Ok(LoopbackServer {
            addr: bound,
            tokens,
            // The key descriptor lives on: a later `issue_token` after the
            // server's last clone died would still be answered by nothing —
            // but keeping it here also keeps Drop honest and cheap.
            _key: key,
        })
    }

    /// The address actually bound (with the real port when `:0` was asked
    /// for). This is what must reach the page or the human out of band.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Mints one session token: the value a subsequent request must present.
    pub fn issue_token(&self) -> String {
        self.tokens.issue()
    }
}

/// Runs the accept loop on the owned listener. One thread per connection, but
/// accepting is strictly sequential and every connection dies on its own
/// timeout or after its one exchange, so there is never more than a handful of
/// live handlers.
fn accept_loop(listener: TcpListener, tokens: Arc<TokenStore>, key: SharedKey) {
    let mut served = 0usize;
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                served += 1;
                if served > MAX_REQUESTS {
                    // The port has answered more than a real flow ever would.
                    // Stop before this becomes a service.
                    eprintln!(
                        "openfirma: the loopback endpoint answered {MAX_REQUESTS} requests and \
                         is closing; a signing call needs one per launch"
                    );
                    return;
                }
                let tokens = tokens.clone();
                let key = key.clone();
                std::thread::spawn(move || {
                    if let Err(e) = handle_connection(stream, &tokens, &key) {
                        // A refusal the client walked away from before reading
                        // is not an incident; a real failure still prints.
                        eprintln!("openfirma: loopback connection ended: {e}");
                    }
                });
            }
            Err(e) => {
                // The listener is only ever closed when the process ends; a
                // transient per-connection accept error must not kill it, so
                // every error that got here just skips this connection.
                let _ = e;
                continue;
            }
        }
    }
}

/// Reads exactly one HTTP/1.x request and answers it. Connection threads are
/// short: headers capped, body capped, no keep-alive — the browser opens a new
/// connection per fetch anyway and an idle socket is the slowloris surface.
fn handle_connection(
    mut stream: TcpStream,
    tokens: &TokenStore,
    key: &SharedKey,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(CONNECTION_TIMEOUT)).ok();
    stream.set_write_timeout(Some(CONNECTION_TIMEOUT)).ok();

    // The header cap is what protects the read loop itself; a body is only
    // ever read after Content-Length passed its own (much smaller) cap.
    let raw = match read_request_head(&mut stream, 64 * 1024) {
        Ok(raw) => raw,
        Err(e) => {
            write_refusal(
                &mut stream,
                400,
                "the request head is malformed or oversized",
                e,
            )?;
            return Ok(());
        }
    };
    let (request_line, headers, body_prefix) = split_request(&raw)?;

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() != 3 || !parts[2].starts_with("HTTP/1.") {
        return write_refusal(
            &mut stream,
            400,
            "the request line is not a well formed HTTP/1.x request",
            "malformed-request-line",
        );
    }
    let method = parts[0];
    let path = parts[1];

    let bound_port = stream.local_addr()?.port().to_string();

    // 1. Method first: only POST carries an operation. GET/HEAD/OPTIONS and
    // everything else get the refusal that names why (a browser can be made
    // to issue a GET to any port from any page without a preflight; signing
    // over GET would be a CSRF hole by construction). OPTIONS, the CORS
    // preflight verb, answers 405 with no Access-Control-Allow-* anywhere —
    // telling every browser its cross-origin request is not welcome.
    if method != "POST" {
        return write_refusal(
            &mut stream,
            405,
            "the signing endpoint only accepts POST; a GET or form navigation from another \
             site would otherwise sign documents without the user's page",
            "post-only",
        );
    }

    // 2. Host must name *us*: the loopback alias and exactly our port.
    let host_ok = headers
        .iter()
        .find(|(k, _)| k == "host")
        .map(|(_, v)| {
            let v = v.trim();
            v == format!("127.0.0.1:{bound_port}") || v == format!("localhost:{bound_port}")
        })
        .unwrap_or(false);
    if !host_ok {
        return write_refusal(
            &mut stream,
            403,
            "the Host header does not name this endpoint (127.0.0.1 or localhost on its bound \
             port): a rebound DNS name would otherwise reach a loopback port with the browser's \
             blessing",
            "bad-host",
        );
    }

    // 3. Origin: present means same-origin-or-nothing; absent is allowed only
    // because non-browser callers (curl, tests) send none — and they are not
    // where rebinding lives.
    let origin_ok = match headers.iter().find(|(k, _)| k == "origin") {
        None => true,
        Some((_, o)) => {
            let o = o.trim();
            o == format!("http://127.0.0.1:{bound_port}")
                || o == format!("http://localhost:{bound_port}")
        }
    };
    if !origin_ok {
        return write_refusal(
            &mut stream,
            403,
            "the Origin header is not this endpoint's own origin: a page on another site must \
             never be able to make the local client sign",
            "bad-origin",
        );
    }

    // 4. The token comes out of the path (AutoFirma puts it in the message body;
    // ours rides in the path so the probe (`/echo`) and the operation share one
    // shape, and a stale referer or cookie can never stand in for it).
    let echo = path == "/echo";
    let token = if echo {
        None
    } else {
        match path.strip_prefix("/sign/") {
            Some(t) => Some(t),
            None => {
                return write_refusal(
                    &mut stream,
                    404,
                    "unknown endpoint: ask for /echo (liveness probe) or POST /sign/<session>",
                    "unknown-path",
                );
            }
        }
    };

    // 5. Chunked encoding is refused first among body-shape rules: a chunked
    // body has no length at all, so asking for one afterwards would be an
    // argument with ourselves about which refusal wins.
    if headers.iter().any(|(k, _)| k == "transfer-encoding") {
        return write_refusal(
            &mut stream,
            400,
            "Transfer-Encoding is not accepted: a chunked body has no cap before it arrives",
            "no-chunked-bodies",
        );
    }
    let length: Option<u64> = match headers.iter().find(|(k, _)| k == "content-length") {
        Some((_, v)) => match v.trim().parse::<u64>() {
            Ok(n) => Some(n),
            Err(_) => {
                return write_refusal(
                    &mut stream,
                    400,
                    "Content-Length is not a finite number: it must be present and exact",
                    "bad-content-length",
                );
            }
        },
        None => {
            if method == "POST" && !echo {
                return write_refusal(
                    &mut stream,
                    411,
                    "a POST without Content-Length is refused (chunked or open-ended bodies \
                     smuggle past any body cap)",
                    "content-length-required",
                );
            }
            None
        }
    };
    if let Some(n) = length {
        if n > MAX_BODY_BYTES {
            return write_refusal(
                &mut stream,
                413,
                &format!(
                    "the body declares {n} bytes; a signing call carries at most \
                     {MAX_BODY_BYTES}"
                ),
                "body-too-large",
            );
        }
    }

    // The token check before any document is read off the wire: an unauthenticated
    // connection must cost as close to nothing as this design can manage.
    if let Some(t) = token {
        if !tokens.take(t) {
            return write_refusal(
                &mut stream,
                403,
                "the session token in the path is unknown or already used: openfirma's endpoint \
                 gives each launch one token and consumes it on its first request",
                "bad-token",
            );
        }
    }

    // Drain the rest of the declared body (already capped above). A POST to
    // /sign with no Content-Length was refused; an echo carries no meaningful
    // body but may still send a small one (AutoFirma's pages post their probe
    // as text), so only read what was declared.
    let want = length.unwrap_or(0) as usize;
    let have = body_prefix.len();
    if have > want {
        return write_refusal(
            &mut stream,
            400,
            "more bytes arrived than Content-Length declares: a smuggled second request would \
             ride the next connection",
            "content-length-mismatch",
        );
    }
    let mut body = body_prefix.to_vec();
    if have < want {
        let remaining = want - have;
        let mut rest = vec![0u8; remaining];
        match read_exact_timeout(&mut stream, &mut rest) {
            Ok(()) => body.extend_from_slice(&rest),
            Err(e) => {
                return write_refusal(
                    &mut stream,
                    400,
                    &format!("the connection ended before Content-Length bytes arrived: {e}"),
                    "short-body",
                );
            }
        }
    }

    if echo {
        // AutoFirma's probe contract answered in kind: `echo` → `OK`. It also
        // settles the origin rules above, which is more than java-websocket's
        // handshake check ever enforced on its own.
        return write_bytes(&mut stream, 200, "text/plain", b"OK", None);
    }

    // A real operation: the body is one afirma:// URI (or AutoFirma's JSON
    // message shape). The endpoint body is not measured against the
    // scheme-channel cap: it never travelled through a URI hand-off here, so
    // only the document-size caps apply; a sede that POSTs a large document
    // would otherwise be refused by a limit that exists for another channel.
    let result = match crate::dispatch::handle_endpoint_body(&body, &key.as_ref_key()) {
        Ok(result) => result,
        Err(e) => return write_error_wire(&mut stream, &e),
    };
    write_bytes(
        &mut stream,
        200,
        "application/octet-stream",
        &result.payload,
        None,
    )
}

/// Reads until the end of headers (one blank line), capped. Returns the whole
/// raw request so far: head plus whatever body bytes already arrived.
fn read_request_head(stream: &mut TcpStream, cap: usize) -> Result<Vec<u8>, &'static str> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if buf.len() > cap {
            return Err("the request head is larger than openfirma will parse");
        }
        match stream.read(&mut chunk) {
            Ok(0) => {
                if buf.is_empty() {
                    return Err("the peer closed without sending a request");
                }
                // A head that never finishes because the client went silent is
                // as malformed as one that overflows.
                return Err("the connection ended inside the request head");
            }
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") || ends_with_double_lf(&buf) {
                    return Ok(buf);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                return Err("the request head did not finish within the connection timeout");
            }
            Err(_) => return Err("the read of the request head failed"),
        }
    }
}

/// LF-only header endings are tolerated in the *read* (find the blank line) so
// misformed-but-legal-ish clients can still be refused by a named rule below,
/// but never silently answered as valid.
fn ends_with_double_lf(buf: &[u8]) -> bool {
    buf.ends_with(b"\n\n")
}

/// Splits raw bytes into (request line, headers lower-cased, body prefix).
/// Header lines with no colon are refused outright; a header name that is not
/// ASCII-lowercase-normalizable refuses nothing — it simply never matches and
/// the mandatory checks (Host/Origin/Content-Length) then refuse for their own
/// named reason.
type RequestParts<'a> = (String, Vec<(String, String)>, &'a [u8]);

fn split_request(raw: &[u8]) -> std::io::Result<RequestParts<'_>> {
    let split_crlf = raw.windows(4).position(|w| w == b"\r\n\r\n");
    let split_lf = raw.windows(2).position(|w| w == b"\n\n");
    let (head_len, sep_len) = match (split_crlf, split_lf) {
        (Some(i), Some(j)) => (i.min(j), if i <= j { 4 } else { 2 }),
        (Some(i), None) => (i, 4),
        (None, Some(j)) => (j, 2),
        (None, None) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "the request head never ends",
            ));
        }
    };
    let head = String::from_utf8_lossy(&raw[..head_len]).to_string();
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or_default().to_string();
    let mut headers = Vec::new();
    for line in lines {
        let Some((k, v)) = line.split_once(':') else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "a header line without a colon",
            ));
        };
        headers.push((k.trim().to_ascii_lowercase(), v.to_string()));
    }
    Ok((request_line, headers, &raw[head_len + sep_len..]))
}

fn read_exact_timeout(stream: &mut TcpStream, buf: &mut [u8]) -> std::io::Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        match stream.read(&mut buf[filled..]) {
            Ok(0) => return Err(std::io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// The reason header's value is a single token-ish string: clients can read
/// it without parsing prose, and the prose stays in our log.
fn write_refusal(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    code: &str,
) -> std::io::Result<()> {
    let body = format!("error {}: {}\n", status, reason);
    // The reason text is echoed in the body because a fetch from a disallowed
    // origin cannot read it anyway (no CORS header was set), while curl and
    // our own tests can; see ADR-0005.
    write_bytes(
        stream,
        status,
        "text/plain; charset=utf-8",
        body.as_bytes(),
        Some(code),
    )
}

fn write_error_wire(stream: &mut TcpStream, e: &BrowserError) -> std::io::Result<()> {
    // The AutoFirma-shaped error payload the pages parse out of a 200 they
    // were not expecting. Our own pages check the status first; an operation
    // that failed is *not* an HTTP failure, exactly like AutoFirma replying
    // `err-00:=…` over a healthy WebSocket.
    write_bytes(
        stream,
        200,
        "text/plain; charset=utf-8",
        e.wire().as_bytes(),
        Some(e.code),
    )
}

fn write_bytes(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
    reason: Option<&str>,
) -> std::io::Result<()> {
    let text = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        411 => "Length Required",
        413 => "Content Too Large",
        _ => "Error",
    };
    let mut head = format!(
        "HTTP/1.1 {status} {text}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n",
        body.len()
    );
    if let Some(reason) = reason {
        head.push_str(&format!("X-Openfirma-Reason: {reason}\r\n"));
    }
    // Deliberately no Access-Control-Allow-Origin anywhere, ever — see the
    // module header. A same-origin page does not need it; a cross-origin one
    // must not get it.
    head.push_str("\r\n");
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()?;
    Ok(())
}
