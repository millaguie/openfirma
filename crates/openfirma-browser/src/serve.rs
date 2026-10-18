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
//!   wrong `Content-Length`, chunked encoding, and connections past
//!   `MAX_CONCURRENT_CONNECTIONS` are refused with a status that says which;
//!   the token is consumed only by a complete request (see B-4's note at the
//!   take), and each connection runs under an absolute deadline fixed at
//!   accept: silence cuts after 5 s and a peer that never falls silent — one
//!   byte every two seconds, say — still dies at the 30 s budget, because
//!   both read loops compare against it on every read, not only where a read
//!   would block.
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
/// that is not our caller (slowloris-style dribbling counts). Enforced as an
/// absolute `Instant` deadline checked around every read — NOT by trusting
/// `ErrorKind::TimedOut`: on Linux an `SO_RCVTIMEO` expiry surfaces as
/// `WouldBlock` and the earlier loop continued on it, re-arming the timeout
/// forever (finding M-2: the 30 s promise of ADR-0005 was dead code there).
/// While bytes are ARRIVING both read loops renew their inactivity window
/// ([`HEAD_GRACE`]) — but never past this absolute budget, and, since the
/// round-3 re-check of M-2, the budget is also evaluated on the *success*
/// path of every read, not only where a read would have blocked: a ceiling
/// that only silences can reach is invisible to a peer dribbling one byte
/// every two seconds, which never blocks and therefore never met it. The
/// deadline is set once, at accept, to `now + CONNECTION_TIMEOUT`; no renewal
/// may push it later and no arriving byte excuses skipping the check. Total
/// cost stays bounded by this number whatever the peer's rhythm; what the
/// grace protects — a real caller whose bytes keep coming on a loaded machine
/// — is protected inside it: a request that finishes before the budget is
/// answered normally, the check fires only when the budget has actually run
/// out.
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);

/// How long a connection may stay SILENT mid-request — before its head, or
/// between body parts. The full 30 s is the whole-request budget; counting an
/// idle first second of that against a real caller punished exactly the client
/// the defence exists to protect (a loaded CI runner schedules localhost worse
/// than a laptop does). A peer that stalls, sends half a request and then will
/// never speak again ages out in this window and frees their slot for it. A
/// peer whose bytes keep coming sees the window re-armed — up to
/// `CONNECTION_TIMEOUT` after accept, the absolute bound no renewal crosses
/// (M-2): both loops below take that instant alongside the grace and always
/// obey whichever of the two comes first.
const HEAD_GRACE: Duration = Duration::from_secs(5);

/// The deadline one more arriving byte buys a connection: [`HEAD_GRACE`] from
/// now, but never later than the connection's absolute budget (M-2 — renewals
/// that could cross the total made that total a lie). Every read loop re-arms
/// through exactly this function so no path can forget the ceiling. The
/// ceiling is only half of it: both loops ALSO compare against `absolute`
/// directly after every successful read (round-3 M-2), because a capped
/// renewal silently stops moving once the budget is reached and the grace
/// alone would keep waiting on a peer that is slowly dribbling, not silent.
fn head_deadline(absolute: std::time::Instant) -> std::time::Instant {
    let now = std::time::Instant::now();
    (now + HEAD_GRACE).min(absolute)
}

/// How many live connection threads may exist at once. A bare connection that
/// never speaks is closed by the deadline, so this only bounds the threads of
/// peers mid-request; a port past it answers 503 rather than dying (see
/// `accept_loop`: refusing a caller is survivable, shutting down the endpoint
/// for the one legitimate signing call is not).
pub const MAX_CONCURRENT_CONNECTIONS: usize = 16;

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
/// accepting is strictly sequential; every connection dies on its own absolute
/// deadline or after its one exchange, so a bare connection (opened and never
/// speaking — `nc`, a probing `<img>` tag) occupies a thread only for the
/// length of that deadline and nothing else.
///
/// The loop never shuts the endpoint down: an earlier revision counted
/// *accepted connections* against a cap of 16 and returned when past it, so
/// seventeen silent `nc` connects — no request, no token, nothing a browser
/// page cannot do with image tags — permanently killed the port before the
/// real call could arrive (finding M-2). Liveness is worth more than a crude
/// anti-flood switch an advertiser could press: what the loop bounds instead
/// is *concurrency*, answering 503 while `MAX_CONCURRENT_CONNECTIONS` handlers
/// are all mid-request. Two ceilings keep that refusal transient for a real
/// caller: stalled peers die after HEAD_GRACE of silence, and since the
/// round-3 re-check of M-2 so do ever-talking dribblers, at the absolute
/// budget every handler's Ok-path enforces. The steady-state slot cost of a
/// dribble flood is therefore bounded by the crowd's own reconnect rate (one
/// dead connection per reconnect it pays), not by how long each connection
/// lives; `dribbling_peers_never_starve_a_tokened_caller` measures that a
/// tokened caller is served within seconds of the first wave dying.
fn accept_loop(listener: TcpListener, tokens: Arc<TokenStore>, key: SharedKey) {
    // Live handler threads, counted with an Arc counter each handler holds for
    // exactly its own lifetime: no leak is possible when a thread panics, and
    // no state to reset on any exit path.
    let live = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    for stream in listener.incoming() {
        let Ok(stream) = stream else {
            // The listener is only ever closed when the process ends; a
            // transient per-connection accept error must not kill it, so
            // every error that got here just skips this connection.
            continue;
        };
        if live.load(std::sync::atomic::Ordering::Relaxed) >= MAX_CONCURRENT_CONNECTIONS {
            // Every slot busy means callers are mid-request at once — far
            // past what one signing flow ever looks like. Say so and close;
            // the next connection is still welcome.
            eprintln!(
                "openfirma: the loopback endpoint has {MAX_CONCURRENT_CONNECTIONS} requests \
                 in flight and answered a new connection with 503"
            );
            let mut stream = stream;
            let _ = write_refusal(
                &mut stream,
                503,
                "every request slot of the endpoint is busy; retry once the signing call \
                 that occupies them has finished",
                "too-many-in-flight",
            );
            continue;
        }
        let tokens = tokens.clone();
        let key = key.clone();
        let live = live.clone();
        live.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        struct Guard(Arc<std::sync::atomic::AtomicUsize>);
        impl Drop for Guard {
            fn drop(&mut self) {
                self.0.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
        std::thread::spawn(move || {
            let _guard = Guard(live);
            if let Err(e) = handle_connection(stream, &tokens, &key) {
                // A refusal the client walked away from before reading
                // is not an incident; a real failure still prints.
                eprintln!("openfirma: loopback connection ended: {e}");
            }
        });
    }
}

/// A stalled read is retried only until the connection deadline, then refused
/// with a distinct name (`request-head-timeout`): an idle peer must be cut at
/// the deadline, not waited on (M-2). Every other malformed head keeps the
/// generic 400 it has always answered.
fn write_head_refusal(stream: &mut TcpStream, error: &'static str) -> std::io::Result<()> {
    if error.contains("its total budget") || error.starts_with("the request head did not finish") {
        return write_refusal(
            stream,
            599,
            "the request head never finished: the connection timeout expired while it was \
             incomplete, which is the shape of a slowloris stall",
            "request-head-timeout",
        );
    }
    write_refusal(
        stream,
        400,
        "the request head is malformed or oversized",
        error,
    )
}

/// Reads exactly one HTTP/1.x request and answers it. Connection threads are
/// short: headers capped, body capped, no keep-alive — the browser opens a new
/// connection per fetch anyway and an idle socket is the slowloris surface.
fn handle_connection(
    mut stream: TcpStream,
    tokens: &TokenStore,
    key: &SharedKey,
) -> std::io::Result<()> {
    // Two clocks, one rule: silence is what costs a peer time (HEAD_GRACE),
    // and total cost is capped by an absolute budget that accept fixes for the
    // connection (CONNECTION_TIMEOUT). A CI runner that sat between accept()
    // and the first read for seconds must not lose the socket's answer — the
    // defence exists for connections that never send a request — while a peer
    // that dribbles bytes forever must still die, which renewals alone could
    // never deliver: they re-armed past every promise (finding M-2).
    stream.set_read_timeout(Some(HEAD_GRACE)).ok();
    stream.set_write_timeout(Some(CONNECTION_TIMEOUT)).ok();
    // The budget is one absolute instant, fixed here and never moved by a
    // renewal again (M-2). `deadline` starts as the head's own grace because
    // at accept that is the stricter of the two; every arriving byte re-arms
    // it through [`head_deadline`] — capped by `absolute`.
    let absolute = std::time::Instant::now() + CONNECTION_TIMEOUT;
    let deadline = head_deadline(absolute);

    // The header cap is what protects the read loop itself; a body is only
    // ever read after Content-Length passed its own (much smaller) cap.
    let raw = match read_request_head(&mut stream, 64 * 1024, deadline, absolute) {
        Ok(raw) => raw,
        Err(e) => {
            // A timeout gets its own named refusal (M-2's test asserts it);
            // anything else keeps the malformed-head answer.
            write_head_refusal(&mut stream, e)?;
            return Ok(());
        }
    };
    let (request_line, headers, body_prefix) = split_request(&raw)?;
    // A complete head means a client that was actually talking; the body now
    // runs inside whatever is left of `absolute` (below), never beyond it.

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
        match read_exact_timeout(&mut stream, &mut rest, deadline, absolute) {
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

    // The token is consumed here — after the head *and* the body have fully
    // arrived (finding B-4). `take` burns the one token of the launch, so
    // consuming it before reading meant a client that dropped mid-request (or
    // a proxy that truncated the body) destroyed the session: no signature, no
    // retry, a relaunched endpoint. Everything before this point is a named
    // refusal of bytes the caller chose to send, so an attacker without the
    // token still costs nothing beyond their own bandwidth; the first thing a
    // request can destroy is now only reached with a complete request.
    if let Some(t) = token {
        if !tokens.take(t) {
            return write_refusal(
                &mut stream,
                403,
                "the session token in the path is unknown or already used: openfirma's endpoint \
                 gives each launch one token and consumes it once a complete request presents it",
                "bad-token",
            );
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
    // B-4: the token was already consumed by a complete, authenticated request,
    // so every failure from here on is an OPERATION failure and answers in the
    // wire form for the version the message announced (finding M-2; one writer,
    // chosen once). A parse-level refusal carries no version — that reader never
    // got a URI to read it from — and takes the modern default, like every
    // unknown client does.
    let (result, version) = match handle_endpoint_call(&body, &key.as_ref_key()) {
        Ok(ok) => ok,
        Err(e) => {
            let version = crate::uri::endpoint_message_version(&body);
            return write_error_wire(&mut stream, &e, version.as_deref());
        }
    };
    let _ = &version; // the success payload needs no version: only refusals do
    write_bytes(
        &mut stream,
        200,
        "application/octet-stream",
        &result.payload,
        None,
    )
}

/// Reads until the end of headers (one blank line), capped, under a hard
/// connection deadline. `deadline` is checked every iteration and every read
/// interruption: on Linux `SO_RCVTIMEO` reports its expiry as `WouldBlock`, so
/// an error-kind check for `TimedOut` — the old rule — never fired there and
/// a stalled peer could stall forever (`continue` re-armed the socket timeout
/// each pass). A WouldBlock past the deadline is the refusal.
fn read_request_head(
    stream: &mut TcpStream,
    cap: usize,
    mut deadline: std::time::Instant,
    absolute: std::time::Instant,
) -> Result<Vec<u8>, &'static str> {
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
                // Headline rule: time counts against a peer that stops
                // talking, not against a slow scheduler on our own machine —
                // arriving bytes re-arm the head's grace window. But the
                // absolute budget is NOT delegated to the silence path: once
                // renewals pin the deadline at `absolute`, only an expired
                // read would ever notice it — and a peer dribbling one byte
                // every two seconds never blocks, so it never met that check
                // (round-3 M-2: the budget was consulted only in the
                // WouldBlock branches and lived 90 s+). Every successful read
                // compares against the budget too; a request that finishes
                // before it is answered normally — the fast path pays one
                // clock comparison. A budget-expired head is refused even if
                // this very read completed it: completing at t≥budget is the
                // signature of the dribble, and answering it would reward the
                // exact rhythm the budget exists to cut; a legitimately slow
                // machine completes inside the budget.
                if std::time::Instant::now() >= absolute {
                    return Err(
                        "the connection exceeded its total budget before its request head finished",
                    );
                }
                deadline = head_deadline(absolute);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") || ends_with_double_lf(&buf) {
                    return Ok(buf);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // The read timeout expired (Linux's spelling): the connection
                // deadline, not the socket option, decides what happens next.
                let left = deadline.saturating_duration_since(std::time::Instant::now());
                if left.is_zero() {
                    return Err(
                        "the connection exceeded its total budget before its request head finished",
                    );
                }
                // A spurious non-blocking wakeup inside the window is retried,
                // with the socket option re-armed to whatever time remains.
                let _ = stream.set_read_timeout(Some(left.max(Duration::from_millis(50))));
            }
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                return Err(
                    "the connection exceeded its total budget before its request head finished",
                );
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

fn read_exact_timeout(
    stream: &mut TcpStream,
    buf: &mut [u8],
    mut deadline: std::time::Instant,
    absolute: std::time::Instant,
) -> std::io::Result<()> {
    let mut filled = 0;
    // Body reads live in the body's own window: `deadline` enters as whatever
    // is stricter — grace left or budget left — and every arriving byte re-arms
    // it exactly like the head's loop does, capped by `absolute` (M-2).
    while filled < buf.len() {
        match stream.read(&mut buf[filled..]) {
            Ok(0) => return Err(std::io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => {
                filled += n;
                // Same rule as the head, same reason (round-3 M-2): arriving
                // bytes re-arm the grace capped by `absolute`, and because a
                // dribbling body never blocks, the budget is compared here on
                // every successful read — not only where a read would have
                // waited. A body delivered inside the budget never pays more
                // than a clock comparison per read.
                if std::time::Instant::now() >= absolute {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "the connection exceeded its total budget before the body arrived",
                    ));
                }
                deadline = head_deadline(absolute);
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            // A body that stops arriving is refused under the existing
            // short-body sentence (M-2's other half: the deadline must fire on
            // every platform's spelling of an expired read, not just the one).
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                let left = deadline.saturating_duration_since(std::time::Instant::now());
                if left.is_zero() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "the connection exceeded its total budget before the body arrived",
                    ));
                }
                let _ = stream.set_read_timeout(Some(left.max(Duration::from_millis(50))));
            }
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

fn write_error_wire(
    stream: &mut TcpStream,
    e: &BrowserError,
    protocol_version: Option<&str>,
) -> std::io::Result<()> {
    // The endpoint's one error writer: AutoFirma's refusal text for the given
    // protocol version — `err-00:=AFxxxxxx - …` for 4.1+ callers, `SAF_xx:`
    // legacy text below (finding M-2) — over a 200 the pages did not expect;
    // an operation that failed is *not* an HTTP failure, exactly like AutoFirma
    // answering `err-00:=…` over a healthy WebSocket. B-6: the reason header
    // quotes the same catalogue number the body carries.
    let target = crate::dispatch::wire_target(protocol_version);
    write_bytes(
        stream,
        200,
        "text/plain; charset=utf-8",
        e.wire(target).as_bytes(),
        Some(crate::dispatch::error_reason_header(e)),
    )
}

/// The endpoint's operation step: parse the body and run it. A parse-level
/// refusal travels as a structured `BrowserError` — never as pre-rendered wire
/// text — so this writer, and only this writer, decides which form (modern or
/// legacy) reaches the page (finding M-2: one door, chosen once).
fn handle_endpoint_call(
    body: &[u8],
    key: &crate::dispatch::KeySource<'_>,
) -> Result<(crate::dispatch::BrowserResult, Option<String>), BrowserError> {
    let uri = crate::uri::parse_endpoint_body(body)?;
    // The consent decision for the loopback endpoint lives with its operator:
    // `OwnedKeySource` only ever carries keys whose owner opted them in (the
    // CLI refuses to start an endpoint over a key without `allow_unattended`),
    // so `Granted` here restates an existing decision rather than making one —
    // the browser-scheme path, where nobody opted in anything, prompts or
    // refuses instead. See docs/adr/0005-browser-protocol.md and finding A-3.
    let result = crate::dispatch::execute(&uri, key)?;
    Ok((result, uri.protocol_version))
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
        // A stalled read answers before the request has a method to refuse,
        // so no verb is pending at that point: 599 is our own status for it.
        // (408 is not usable from this code path — with no method parsed yet,
        // every refusal would answer 599 and lose the distinction; the ADR's
        // process-limits entry records the same choice.)
        599 => "Request Timeout",
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
    // The response travels as ONE buffer: one write_all of the whole thing is
    // one syscall, so no FIN can be queued between a header and its body — an
    // ordering Windows lets a reader see otherwise, where an accepted socket
    // closed with unread data gets RST'd and the client's first read fails
    // before ever draining the answer.
    let mut response = head.into_bytes();
    response.extend_from_slice(body);
    let result = write_and_flush(stream, &response);
    // Graceful close before the socket drops: without it, a reply that is
    // still in flight when the thread ends can be RST'd instead of FIN'd —
    // macOS does this readily when the peer has already stopped reading (it
    // never reads a refusal's body) — and the client sees "connection reset"
    // where we promised a named refusal.
    //
    // And the request the refusal left unread is emptied first. A socket closed
    // with bytes still in its receive buffer is reset rather than closed, and a
    // reset discards what the peer has not read yet: measured on the
    // aarch64-windows runner, the 413 for a declared-but-unsent body was sent
    // and then lost anyway — the client's read failed with `ConnectionReset`
    // (`Os { code: 10054, kind: ConnectionReset }`) and the named refusal went
    // with it. Only what has ALREADY arrived is read, never a byte of the body
    // the refusal exists to avoid waiting for, and only up to a bounded count,
    // so a peer that keeps talking cannot hold the thread.
    drain_what_arrived(stream);
    stream.shutdown(std::net::Shutdown::Both).ok();
    result
}

/// Read and discard the bytes that have already arrived, without waiting for
/// any that have not. See the close in [`write_bytes`] for why the receive
/// buffer has to be empty before the socket goes away.
fn drain_what_arrived(stream: &mut TcpStream) {
    /// Enough for the request bytes a refusal leaves behind, and small enough
    /// that a peer which keeps sending cannot make this a reading loop.
    const DRAIN_LIMIT: usize = 64 * 1024;
    if stream.set_nonblocking(true).is_err() {
        return;
    }
    let mut buf = [0u8; 4096];
    let mut drained = 0usize;
    while drained < DRAIN_LIMIT {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => drained += n,
            // WouldBlock is the state this exists to reach — nothing more has
            // arrived — and any other error leaves nothing that can be read.
            Err(_) => break,
        }
    }
    let _ = stream.set_nonblocking(false);
}

fn write_and_flush(stream: &mut TcpStream, response: &[u8]) -> std::io::Result<()> {
    stream.write_all(response)?;
    stream.flush()
}
