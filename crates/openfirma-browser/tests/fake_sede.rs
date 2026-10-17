//! End to end over the loopback endpoint, driven by a fake sede written in
//! this file: raw HTTP/1.1 requests on an ephemeral loopback port — exactly
//! the bytes a page's `fetch()` puts on the wire, no HTTP client library that
//! could quietly add (or hide) a header between us and what we promise.
//!
//! Material rules the rest of the workspace keeps: the synthetic PKI from
//! `tools/gen-testcert.sh` only, nothing that names a real certificate; and
//! every connection here is to 127.0.0.1 by construction (the server refuses
//! to bind anywhere else, which its own start path checks).
//!
//! Skips follow the workspace rules: missing test PKI skips unless
//! OPENFIRMA_REQUIRE_TESTS, in which case it panics; ALLOW_SKIP opts back out.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};

use base64::Engine;
use openfirma_browser::serve::{LoopbackServer, MAX_BODY_BYTES, OwnedKeySource};
use zeroize::Zeroizing;

fn certs_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/certs")
}

fn require_or_skip(reason: &str) {
    let required = std::env::var("OPENFIRMA_REQUIRE_TESTS").is_ok();
    let allowed = std::env::var("OPENFIRMA_ALLOW_SKIP").is_ok();
    if required && !allowed {
        panic!("cannot run the test: {reason}");
    }
    eprintln!("skipped, {reason}");
}

/// The synthetic signer's PKCS#12 (password `openfirma`, set by gen-testcert.sh).
fn p12() -> Option<PathBuf> {
    let path = certs_dir().join("signer-rsa.p12");
    path.exists().then_some(path)
}

/// One raw request as a page would send it: method/path/Host/Origin/body, all
/// explicit here so every test decides its own headers byte for byte. A probe
/// (`/echo`) carries no credential: an answer discarded unread in the socket
/// layer is simply asked again, up to a bounded number of tries — that is how
/// the flood/stall loops read the endpoint at capacity, where Windows' close-
/// and-discard rule bites hardest. A token-bearing path must go through
/// [`ask`], which re-mints a token per attempt instead (a consumed one must
/// never come back; see TokenStore::take), so `request` refuses those here.
fn request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    host: &str,
    origin: Option<&str>,
    body: &[u8],
) -> (u16, Vec<(String, String)>, Vec<u8>) {
    // Re-asking an unread answer is free only where no credential rides along
    // — /echo probes and a /sign id that could never have been minted (see
    // sign_path_may_reask). A real one-shot token must never come back (B-4;
    // TokenStore::take), so `request` gives up after ONE attempt there with an
    // honest panic, while credential-free paths retry five times: they are the
    // flood/stall probes that read the endpoint exactly when its accept queue
    // is saturated and Windows discards answers most. Tests whose flow must
    // survive a discarded real answer call `ask`, which mints fresh per try.
    let may_reask = !path.starts_with("/sign/") || sign_path_may_reask(path);
    // Three retries normally, six from inside the 503 flood probe: that test
    // holds every handler slot busy with stalled connections and probes while
    // saturated — exactly when the endpoint answers fastest (the refusal is a
    // write-and-close) and Windows' accept queue drops the answer most. The
    // CI witness (run 39019344987, aarch64-pc-windows-msvc, twice) shows the
    // refused answer dying unread three times running while the endpoint kept
    // working for everything else, so patience — not a logic change — is what
    // this race needs. This sleep-retry loop replaces the old non-blocking
    // storm that starved the endpoint's backlog under CPU load (that storm is
    // what these helpers used to crash).
    let tries = if !may_reask {
        1
    } else if path == "/echo" {
        6
    } else {
        3
    };
    for attempt in 0..tries {
        let stream = TcpStream::connect(addr).expect("the endpoint must accept connections");
        let answer = request_on(stream, addr, method, path, host, origin, body);
        if answer.0 != u16::MAX {
            return answer;
        }
        // Give the listener a moment to reap its backlog before reconnecting;
        // a bare hot loop mostly meets it while it is still buried in accept.
        std::thread::sleep(std::time::Duration::from_millis(50 * (attempt as u64 + 1)));
    }
    panic!(
        "the endpoint's answer on {path:?} was discarded unread{}: a test that presents a \
         real token and must survive this race uses `ask`, which mints one per attempt",
        if may_reask { " three times" } else { "" }
    )
}

/// The raw-request helper behind [`request`] and [`ask`]: writes the exact
/// bytes, reads the answer with the reset rules of this harness, and hands
/// back either a parsed response or the sentinel `(u16::MAX, …, …)` — "the
/// endpoint's answer died unread in the socket layer" (Windows' rule that an
/// accepted socket closed with data unread discards that data and RSTs). The
/// sentinel exists so [`ask`] can re-mint a token instead of re-presenting one;
/// `request` turns it into an honest panic. A reset after PARTIAL bytes stays
/// a hard failure: those bytes should have been drained before the close, and
/// cutting mid-response is not the discard this arm tolerates.
fn request_on(
    mut stream: TcpStream,
    _addr: SocketAddr,
    method: &str,
    path: &str,
    host: &str,
    origin: Option<&str>,
    body: &[u8],
) -> (u16, Vec<(String, String)>, Vec<u8>) {
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .unwrap();
    let head = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\n");
    let mut text = head;
    if let Some(o) = origin {
        text.push_str(&format!("Origin: {o}\r\n"));
    }
    // The endpoint closes after its answer either way (it never keep-alives,
    // and the read below stops at the response's Content-Length boundary
    // rather than waiting for an EOF). What this client must NOT do is echo
    // "Connection: close": on Windows a client that says close then keeps the
    // socket open until drop asks its own stack to RST the connection on
    // teardown — and an RST queued before the answer was drained discards it
    // unread (the 10054-on-first-read this harness kept meeting). Silence
    // about keep-alive leaves the FIN the endpoint sends as the only close,
    // and reads finish at their own boundary regardless.
    text.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    // Writing may fail, and that is part of the contract: when the endpoint
    // refuses a request it answers and closes while a large body may still be
    // in flight, and whether the write then succeeds is OS timing (macOS RSTs,
    // Linux buffers), not an openfirma rule. The answer gets read regardless.
    let _ = stream.write_all(text.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
    let mut raw = Vec::new();
    // One read at a time, judged against the response's own boundary:
    // `complete_response` says when the bytes in hand ARE the whole answer,
    // and nothing after that point is raced with the endpoint's close — on
    // Windows even a perfectly delivered 200 can be followed by an RST of the
    // still-open queue, and read errors past a complete response carry no
    // information. Status u16::MAX is this harness's own sentinel for "the
    // answer died unread in the socket layer" — Windows discards the buffer
    // of an accepted socket closed with data unread (10054/10053 on the very
    // first read). `ask` re-asks that case through a fresh token; `request`
    // treats it as what it is for its callers: a failure to get an answer.
    let mut buf = [0u8; 16384];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&buf[..n]);
                // The endpoint caps responses far below any memory worry and
                // never streams; a runaway answer is a bug worth failing on.
                assert!(
                    raw.len() < 64 * 1024 * 1024,
                    "the endpoint streamed without end"
                );
                if complete_response(&raw) {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
                ) =>
            {
                if raw.is_empty() {
                    return (u16::MAX, Vec::new(), Vec::new());
                }
                assert!(
                    complete_response(&raw),
                    "the answer was cut mid-response: {:?}",
                    String::from_utf8_lossy(&raw)
                );
                break;
            }
            Err(e) => panic!("reading the answer failed: {e}"),
        }
    }
    parse_response(&raw)
}

/// Is `raw` a complete HTTP response already — header block plus the body its
/// Content-Length declares? A reset that arrives after this point carries no
/// information the bytes do not already hold, and both reset kinds (Windows
/// reports an aborted local connection as `ConnectionAborted`, a peer's RST as
/// `ConnectionReset`) are then the close every endpoint here performs.
fn complete_response(raw: &[u8]) -> bool {
    raw.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .is_some_and(|split| {
            let len: Option<usize> = String::from_utf8_lossy(&raw[..split])
                .lines()
                .filter_map(|l| {
                    let (k, v) = l.split_once(':')?;
                    k.eq_ignore_ascii_case("content-length")
                        .then(|| v.trim().to_owned())
                })
                .find_map(|v| v.parse().ok());
            len.is_none_or(|n| raw[split + 4..].len() >= n)
        })
}

fn parse_response(raw: &[u8]) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("the answer has no header/body separator");
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let status_line = head.lines().next().unwrap_or_default();
    let mut parts = status_line.split_whitespace();
    let version = parts.next().unwrap_or_default();
    let code: u16 = parts
        .next()
        .unwrap_or_default()
        .parse()
        .expect("the status line's second token is the numeric code");
    assert!(
        version.starts_with("HTTP/1."),
        "status line {status_line:?}"
    );
    let mut headers = Vec::new();
    for line in head.lines().skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
        }
    }
    (code, headers, raw[split + 4..].to_vec())
}

/// Request a signing endpoint through one token per attempt: every try gets
/// its own freshly minted id, so Windows' occasional discard of an unread
/// answer (see `request_on`) costs a token, never the fake 403 that
/// re-presenting a burned one would manufacture. Use it for the tests that
/// must see an answer to decide their next step *and* do not assert on a
/// specific token's history; tests about tokens themselves use `request`.
fn ask(
    server: &LoopbackServer,
    addr: SocketAddr,
    method: &str,
    host: &str,
    origin: Option<&str>,
    body: &[u8],
) -> (u16, Vec<(String, String)>, Vec<u8>) {
    // Twelve attempts a quarter-second apart, not five in a burst. On Windows
    // an answer written into a socket whose peer just vanished dies with it —
    // worst while handlers are still draining (a wave; slots freeing one
    // thread at a time), and a retry loop with no pause re-enters exactly the
    // window that swallowed the last attempt. Each attempt mints its own
    // token, so patience costs nothing an operation cares about: discarded
    // tokens never signed (a_quiet_half_header's "never burn without a full
    // request" rule) and each fresh one is the only thing ask promises.
    //
    // A discarded answer retries at once, minting a fresh token: that failure
    // is the socket layer's, cheap and unrelated to capacity. A real 503 is
    // different — the endpoint is saturated, and this helper serves callers
    // who wait for the wave to age out (the handler's five-second stall
    // deadline). A fast twelve-burst finishes inside a wave and reports every
    // answer it never had a chance to see: observed on aarch64-windows as
    // twelve 503s in twelve seconds while the caller's 90s patience loop
    // waited for ask to surface an available slot. Capacity therefore pauses
    // past the deadline between attempts.
    for attempt in 0..12 {
        let token = server.issue_token();
        let path = format!("/sign/{token}");
        let stream = TcpStream::connect(addr).expect("the endpoint must accept connections");
        let (status, headers, payload) =
            request_on(stream, addr, method, &path, host, origin, body);
        if status != u16::MAX {
            return (status, headers, payload);
        }
        if attempt + 1 < 12 {
            let pause = match status {
                503 => std::time::Duration::from_millis(6_000),
                u16::MAX => std::time::Duration::from_millis(250),
                // any real answer returns to the caller; never slept past
                other => unreachable!("ask sleeps only while {other:?} is retryable"),
            };
            std::thread::sleep(pause);
        }
    }
    panic!(
        "the endpoint discarded twelve consecutive answers unread or stayed at capacity \
         for a minute: a saturated endpoint whose stalled connections never age out is \
         the failure this test exists to catch"
    );
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

/// A /sign path is safe to re-ask when its id could never have been minted —
/// our tokens are exactly 16 lowercase alphanumerics (token.rs), so a guessed
/// or truncated id can only ever be refused, burning nothing. `request` trusts
/// nothing else: every other /sign path is treated as carrying a real one-shot
/// token and must go through [`ask`] instead. Test-harness bookkeeping alone.
fn sign_path_may_reask(path: &str) -> bool {
    match path.strip_prefix("/sign/") {
        Some(id) => {
            !(id.len() == 16
                && id
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()))
        }
        None => true,
    }
}

fn server_on(key: &Path) -> LoopbackServer {
    let server = LoopbackServer::start(
        "127.0.0.1:0".parse().unwrap(),
        OwnedKeySource::P12 {
            path: key.to_path_buf(),
            password: Zeroizing::new("openfirma".to_string()),
        },
    );
    server.expect("the endpoint must start against the test keystore")
}

fn uri_body(doc: &[u8]) -> String {
    // percent-encoded base64 of the document, which is how `dat` arrives from
    // a page (autoscript.js encodeURIComponent's every parameter value).
    let b64 = base64::engine::general_purpose::STANDARD.encode(doc);
    let enc: String = b64
        .chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' => c.to_string(),
            '=' => "%3D".to_string(),
            '+' => "%2B".to_string(),
            '/' => "%2F".to_string(),
            _ => unreachable!("base64's alphabet is ASCII-safe except these four"),
        })
        .collect();
    format!("afirma://sign?op=sign&format=CAdES&algorithm=SHA256withRSA&dat={enc}")
}

/// The response shapes pinned by construction (no hand-rolled base64 in the
/// test to be wrong about). Finding M-1 corrected what the shape IS: measured
/// against the shipped jar, `Base64.encode(x, true)` is **URL-safe alphabet,
/// '=' padding, a single line** (`es.gob.afirma.core.misc.Base64.encode(_,
/// true)` → the URL_SAFE option with no break-lines flag — recorded: 200 bytes
/// → 268 chars, no CR/LF, `-` present). A sign body is therefore two URL-safe
/// fields around one `|`, with no newline anywhere; a selectcert body is one
/// such field. The byte-level truth of those fields — that they *decode* to the
/// signer's certificate and a signature openssl accepts over the document — is
/// proven by `sede_crosscheck.rs`, which checks it against an independent
/// implementation rather than against another parser from this repository.
#[test]
fn the_sign_and_selectcert_response_shapes_are_autofirma_s_own() {
    let Some(key) = p12() else {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    let server = server_on(&key);
    let addr = server.addr();
    let host = format!("127.0.0.1:{}", addr.port());
    let origin = format!("http://127.0.0.1:{}", addr.port());

    let token = server.issue_token();
    let (_, _, body) = request(
        addr,
        "POST",
        &format!("/sign/{token}"),
        &host,
        Some(&origin),
        uri_body(b"shape check").as_bytes(),
    );
    assert_eq!(
        body.iter().filter(|b| **b == b'|').count(),
        1,
        "one separator in a sign response"
    );
    let sep = body
        .iter()
        .position(|b| *b == b'|')
        .expect("the separator is there");
    let (cert_field, sig_field) = (&body[..sep], &body[sep + 1..]);
    for field in [cert_field, sig_field] {
        // URL-safe and single-line: no CRLF anywhere (the jar's encoder never
        // breaks lines), and only the RFC 4648 §5 alphabet plus padding. A
        // MIME line-break here is exactly the M-1 regression.
        assert!(
            !field.contains(&b'\r') && !field.contains(&b'\n'),
            "AutoFirma's fields are a single line: {:?}",
            String::from_utf8_lossy(field)
        );
        assert!(
            field
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_' || *b == b'='),
            "the alphabet is RFC 4648 §5 URL-safe plus padding: {:?}",
            String::from_utf8_lossy(field)
        );
        // '+' and '/' of the standard alphabet must NOT appear either: a field
        // mixing alphabets could not have come from encode(_, true).
        assert!(
            !field.contains(&b'+') && !field.contains(&b'/'),
            "a URL-safe field carries no standard-alphabet characters"
        );
    }

    // autoscript.js's own success path proves the same thing from the page
    // side (recorded lines 2889-2899): it converts '-'→'+' and '_'→'/' on the
    // two fields before using them — a rewrite that only makes sense for
    // URL-safe input. Pin that the wire agrees with the page's decoder: the
    // fields round-trip through exactly that fold.
    let folded: Vec<u8> = body
        .iter()
        .map(|b| match b {
            b'-' => b'+',
            b'_' => b'/',
            other => *other,
        })
        .collect();
    let sep = folded.iter().position(|b| *b == b'|').unwrap();
    use base64::Engine;
    let cert = base64::engine::general_purpose::STANDARD
        .decode(&folded[..sep])
        .expect("the folded certificate field is standard base64");
    let sig = base64::engine::general_purpose::STANDARD
        .decode(&folded[sep + 1..])
        .expect("the folded signature field is standard base64");
    assert!(
        cert.starts_with(&[0x30]),
        "the cert field is a DER SEQUENCE"
    );
    assert!(!sig.is_empty(), "a signature travelled back to the page");

    // selectcert answers with the leaf certificate alone: no separator at all,
    // and one field's worth of bytes (one DER, base64'd).
    let token = server.issue_token();
    let (status, _, body) = request(
        addr,
        "POST",
        &format!("/sign/{token}"),
        &host,
        Some(&origin),
        b"afirma://selectcert?idsession=abc123",
    );
    assert_eq!(status, 200);
    assert!(
        !body.contains(&b'|'),
        "a selected certificate carries no separator"
    );
    // Same URL-safe single-line rule on the lone field.
    assert!(
        body.iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_' || *b == b'='),
        "a selected certificate is one URL-safe base64 field: {:?}",
        String::from_utf8_lossy(&body)
    );
}

/// Every hostile request a page can forge against a loopback port, and the
/// refusal each must meet. These are the CSRF / DNS-rebinding cases ADR-0005
/// claims the endpoint refuses; an untested claim is not a mitigation.
#[test]
fn cross_site_and_rebinding_attempts_are_refused_by_name() {
    let Some(key) = p12() else {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    let server = server_on(&key);
    let addr = server.addr();
    let port = addr.port().to_string();
    let good_host = format!("127.0.0.1:{port}");
    let good_origin = format!("http://127.0.0.1:{port}");
    let doc = b"no one gets this signed".to_vec();

    // A cross-site page's fetch: right port in the URL is not enough — its
    // Origin header names the attacker and the Host is the rebinding alias.
    let (status, headers, body) = request(
        addr,
        "POST",
        "/sign/deadbeefdeadbeef",
        "evil.example",
        Some("https://evil.example"),
        uri_body(&doc).as_bytes(),
    );
    assert_eq!(status, 403);
    assert_eq!(
        header(&headers, "x-openfirma-reason"),
        Some("bad-host"),
        "the Host check runs first and says so: {}",
        String::from_utf8_lossy(&body)
    );

    // DNS rebinding in isolation: a name that now resolves to 127.0.0.1 is
    // still not *us* on the two headers that decide identity. Same Origin as
    // us would first require the attacker's page to be served from our port;
    // bad Host alone already dies.
    let (status, headers, _) = request(
        addr,
        "POST",
        "/sign/deadbeefdeadbeef",
        &good_host,
        Some("http://evil-rebound.test"),
        uri_body(&doc).as_bytes(),
    );
    assert_eq!(status, 403);
    assert_eq!(header(&headers, "x-openfirma-reason"), Some("bad-origin"));

    // A missing or reused token: first use burns it, second use is a replay.
    let token = server.issue_token();
    let (status, _, _) = request(
        addr,
        "POST",
        &format!("/sign/{token}"),
        &good_host,
        Some(&good_origin),
        uri_body(b"first use spends the session").as_bytes(),
    );
    assert_eq!(status, 200, "the first request of a fresh token signs");
    let (status, headers, _) = request(
        addr,
        "POST",
        &format!("/sign/{token}"),
        &good_host,
        Some(&good_origin),
        uri_body(b"replay").as_bytes(),
    );
    assert_eq!(status, 403);
    assert_eq!(header(&headers, "x-openfirma-reason"), Some("bad-token"));

    // A token never issued (a guessed one) is refused the same way — the page
    // that never learned it cannot use it.
    let (status, headers, _) = request(
        addr,
        "POST",
        "/sign/zzzzzzzzzzzzzzz15",
        &good_host,
        Some(&good_origin),
        uri_body(b"guessed").as_bytes(),
    );
    assert_eq!(status, 403);
    assert_eq!(header(&headers, "x-openfirma-reason"), Some("bad-token"));

    // GET where POST is required — the plain CSRF vector (a form, an img tag,
    // anything a cross-site page loads without preflight).
    let token = server.issue_token();
    let (status, headers, _) = request(
        addr,
        "GET",
        &format!("/sign/{token}"),
        &good_host,
        Some(&good_origin),
        b"",
    );
    assert_eq!(status, 405);
    assert_eq!(header(&headers, "x-openfirma-reason"), Some("post-only"));

    // An oversized body is refused by the declared length before it is read;
    // the endpoint must not wait for bytes it already rejected.
    let token = server.issue_token();
    let (status, headers, _) = request_with_declared_length(
        addr,
        &format!("/sign/{token}"),
        &good_host,
        Some(&good_origin),
        MAX_BODY_BYTES + 1,
        // not written on purpose: the refusal must come from the header alone
        true,
    );
    assert_eq!(status, 413);
    assert_eq!(
        header(&headers, "x-openfirma-reason"),
        Some("body-too-large")
    );

    // Chunked bodies have no cap before they arrive; refused on sight — and
    // ahead of the missing-Content-Length rule, because "no length at all" is
    // what chunked *means*: the more specific refusal has to win.
    let token = server.issue_token();
    let (status, headers, _) = request_chunked(
        addr,
        &format!("/sign/{token}"),
        &good_host,
        Some(&good_origin),
        uri_body(b"chunked").as_bytes(),
    );
    assert_eq!(status, 400);
    assert_eq!(
        header(&headers, "x-openfirma-reason"),
        Some("no-chunked-bodies")
    );

    // A POST that declares no length at all cannot be capped; the refusal is
    // HTTP's own 411.
    let token = server.issue_token();
    let (status, headers, _) = request_no_length(
        addr,
        &format!("/sign/{token}"),
        &good_host,
        Some(&good_origin),
        uri_body(b"declaredless").as_bytes(),
    );
    assert_eq!(status, 411);
    assert_eq!(
        header(&headers, "x-openfirma-reason"),
        Some("content-length-required")
    );

    // A URI whose shape is broken (a sign call missing its document): the
    // request itself was valid — authenticated, well-shaped — so answering 403
    // or 411 would blame the transport for what the *call* got wrong. Like
    // AutoFirma replying `err-00:=…` over a healthy socket, this comes back as
    // a 200 carrying the error wire form with our named code in the header.
    let token = server.issue_token();
    let (status, headers, body) = request(
        addr,
        "POST",
        &format!("/sign/{token}"),
        &good_host,
        Some(&good_origin),
        b"afirma://sign?op=sign&format=CAdES",
    );
    assert_eq!(status, 200);
    assert_eq!(
        // The broken URI never reached an operation parser, so it is the
        // socket-level refusal AutoFirma answers with 620016 (and SAF_03 below
        // 4.1); B-6 made this header the same catalogue number the body carries.
        header(&headers, "x-openfirma-reason"),
        Some("620016")
    );
    let text = String::from_utf8_lossy(&body);
    assert!(
        text.starts_with("err-00:=AF620016 - "),
        "AutoFirma's error shape with ITS code: {text}"
    );

    // A URI naming an operation this client does not speak is still a broken
    // call over a healthy request, so it follows the same rule as the one
    // above: 200 with AutoFirma's err wire form and the parse refusal as its
    // description. (HTTP-level refusals are reserved for requests the endpoint
    // itself rejects before trusting them with a token.)
    let token = server.issue_token();
    let (status, _, body) = request(
        addr,
        "POST",
        &format!("/sign/{token}"),
        &good_host,
        Some(&good_origin),
        b"afirma://frobnicate?op=sign",
    );
    assert_eq!(status, 200);
    let text = String::from_utf8_lossy(&body);
    // M-2: an unknown operation is the socket-level refusal AutoFirma names
    // 620016 / SAF_03 for, and autoscript.js parses EXACTLY that shape (its
    // " - " must sit at index 8 of the err text) — openfirma's own words may
    // only live beside the code, never instead of it.
    assert!(
        text.starts_with("err-00:=AF620016 - "),
        "AutoFirma's error shape with ITS code: {text}"
    );

    // An executed operation that fails for its own reason comes back in
    // AutoFirma's error wire form over a 200 — the socket was healthy, the
    // *operation* was not. A cosign call is refused by dispatch design; see
    // ADR-0005 for why it stays refused (no golden for what a page expects).
    let token = server.issue_token();
    let mut cosign_body = uri_body(b"nobody co-signs through openfirma yet");
    cosign_body = cosign_body.replacen("afirma://sign?op=sign", "afirma://cosign?op=cosign", 1);
    let (status, headers, body) = request(
        addr,
        "POST",
        &format!("/sign/{token}"),
        &good_host,
        Some(&good_origin),
        cosign_body.as_bytes(),
    );
    assert_eq!(
        status, 200,
        "an operation failure is a payload, not an HTTP error"
    );
    let text = String::from_utf8_lossy(&body);
    assert!(
        text.starts_with("err-00:=AF"),
        "AutoFirma's error shape: {text}"
    );
    assert_eq!(
        // B-6: the header quotes the same catalogue number the wire body
        // carries — 600002, AutoFirma's UNSUPPORTED_OPERATION.
        header(&headers, "x-openfirma-reason"),
        Some("600002")
    );
}

/// A request whose Content-Length lies (too big), body deliberately unwritten:
/// the 413 must come from the header alone, never waiting on the missing part.
fn request_with_declared_length(
    addr: SocketAddr,
    path: &str,
    host: &str,
    origin: Option<&str>,
    declared: u64,
    _no_body: bool,
) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .unwrap();
    let mut text = format!("POST {path} HTTP/1.1\r\nHost: {host}\r\n");
    if let Some(o) = origin {
        text.push_str(&format!("Origin: {o}\r\n"));
    }
    text.push_str(&format!(
        "Content-Length: {declared}\r\nConnection: close\r\n\r\n"
    ));
    // one body byte, nowhere near the lie: proves the cap is on the header.
    stream.write_all(text.as_bytes()).unwrap();
    stream.write_all(b"x").unwrap();
    stream.flush().unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap();
    parse_response(&raw)
}

fn request_chunked(
    addr: SocketAddr,
    path: &str,
    host: &str,
    origin: Option<&str>,
    body: &[u8],
) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .unwrap();
    let mut text = format!("POST {path} HTTP/1.1\r\nHost: {host}\r\n");
    if let Some(o) = origin {
        text.push_str(&format!("Origin: {o}\r\n"));
    }
    text.push_str("Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n");
    // Same as `request`: the endpoint refuses chunked bodies without reading
    // one byte of them, so our own chunk write racing its close is expected;
    // what is asserted is the answer the read gets back.
    let _ = stream.write_all(text.as_bytes());
    let _ = stream.write_all(format!("{:x}\r\n", body.len()).as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.write_all(b"\r\n0\r\n\r\n");
    let _ = stream.flush();
    let mut raw = Vec::new();
    match stream.read_to_end(&mut raw) {
        Ok(_) => {}
        // ECONNRESET here means the refusal arrived and the close raced the
        // unread body — the refusal itself, which is what this case asserts,
        // may still be in the buffer before the reset; if it is not, the
        // parse below fails loudly, as a missing refusal should.
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
        Err(e) => panic!("reading the answer failed: {e}"),
    }
    parse_response(&raw)
}

fn request_no_length(
    addr: SocketAddr,
    path: &str,
    host: &str,
    origin: Option<&str>,
    body: &[u8],
) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .unwrap();
    let mut text = format!("POST {path} HTTP/1.1\r\nHost: {host}\r\n");
    if let Some(o) = origin {
        text.push_str(&format!("Origin: {o}\r\n"));
    }
    // no Content-Length at all — and the endpoint has nothing to cap, so it
    // must refuse rather than read until hope runs out.
    text.push_str("Connection: close\r\n\r\n");
    // Writing may fail, and that is part of the contract: when the endpoint
    // refuses a request it answers and closes while a large body may still be
    // in flight, and whether the write then succeeds is OS timing (macOS RSTs,
    // Linux buffers), not an openfirma rule. The answer gets read regardless.
    let _ = stream.write_all(text.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap();
    parse_response(&raw)
}

/// `Host: localhost:<port>` is an accepted alias of the same endpoint — a page
// that addressed us by name must not be refused for it (and curl's default
// form is what our own probe uses).
#[test]
fn localhost_is_the_alias_of_127001_it_claims_to_be() {
    let Some(key) = p12() else {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    let server = server_on(&key);
    let addr = server.addr();
    let port = addr.port().to_string();
    let token = server.issue_token();
    let (status, _, body) = request(
        addr,
        "POST",
        &format!("/sign/{token}"),
        &format!("localhost:{port}"),
        Some(&format!("http://localhost:{port}")),
        uri_body(b"addressed by name").as_bytes(),
    );
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
}

/// The endpoint binds loopback or refuses to start: a non-loopback bind would
/// hand the same token-only trust model to the whole network, which is not a
/// configuration this build may reach by argument.
#[test]
fn binding_a_non_loopback_address_is_refused_before_the_bind() {
    let err = LoopbackServer::start(
        "0.0.0.0:0".parse().unwrap(),
        OwnedKeySource::P12 {
            path: PathBuf::from("/does/not/matter"),
            password: Zeroizing::new(String::new()),
        },
    )
    .expect_err("0.0.0.0 is not a loopback address and must never be served");
    assert!(err.to_string().contains("loopback"), "{err}");
}

/// A JSON body naming the URI under `"message"` signs exactly like the bare
/// URI form; a JSON object without one is refused with the reason that names
/// what is missing. The wrapper exists for hand-written sede clients; AutoFirma's
/// own socket takes the URI as the message text (measured, see uri.rs), so
/// both forms being accepted costs nothing and refuses nothing ambiguous.
#[test]
fn a_json_message_body_signs_and_a_json_without_one_is_refused_by_name() {
    let Some(key) = p12() else {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    let server = server_on(&key);
    let addr = server.addr();
    let host = format!("127.0.0.1:{}", addr.port());
    let origin = format!("http://127.0.0.1:{}", addr.port());

    let wrapped = format!(
        "{{\"idsession\":\"abc\",\"message\":\"{}\"}}",
        uri_body(b"json body")
    );
    let token = server.issue_token();
    let (status, _, body) = request(
        addr,
        "POST",
        &format!("/sign/{token}"),
        &host,
        Some(&origin),
        wrapped.as_bytes(),
    );
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    assert!(
        body.contains(&b'|'),
        "a JSON-wrapped sign call produces the same sign shape"
    );

    let token = server.issue_token();
    let (status, headers, body) = request(
        addr,
        "POST",
        &format!("/sign/{token}"),
        &host,
        Some(&origin),
        br#"{"idsession":"abc"}"#,
    );
    assert_eq!(status, 200, "a broken call over a valid request");
    let text = String::from_utf8_lossy(&body);
    // M-2: the page reads the AF code out of the body (autoscript.js's error
    // parser splits on the " - " at position 8), so the refusal arrives as the
    // socket-level wire form — header and body quote the SAME catalogue number
    // (B-6). openfirma's own explanation stays in its logs, not on the wire.
    assert_eq!(
        header(&headers, "x-openfirma-reason"),
        Some("620016"),
        "the header quotes the catalogue number: {text}"
    );
    assert!(
        text.starts_with("err-00:=AF620016 - "),
        "AutoFirma's error shape with ITS code: {text}"
    );
}

/// A truncated request: headers complete, Content-Length honest, and then the
/// client dies before the body arrives. The refusal is `short-body` — and,
/// after finding B-4, the session token must still be alive afterwards: one
/// dropped connection may not destroy the launch's only signing attempt.
#[test]
fn a_truncated_request_refuses_without_burning_the_token() {
    let Some(key) = p12() else {
        require_or_skip("testdata/certs/signer-rsa.p12 is absent");
        return;
    };
    let server = server_on(&key);
    let addr = server.addr();
    let host = format!("127.0.0.1:{}", addr.port());
    let token = server.issue_token();

    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .unwrap();
    let body = uri_body(b"el documento completo nunca llega a la sede");
    stream
        .write_all(
            format!(
                "POST /sign/{token} HTTP/1.1\r\nHost: {host}\r\nContent-Length: {}\r\n\r\n",
                body.len() + 4096
            )
            .as_bytes(),
        )
        .unwrap();
    // Only part of what was declared — like a browser tab that died or a
    // proxy cut in half — and then *wait*: the endpoint notices on its own
    // connection timeout and answers short-body. Closing here instead would
    // RST the queued refusal away (the exact race write_bytes documents), so
    // reading stays open until the answer arrives.
    stream.write_all(&body.as_bytes()[..24]).unwrap();
    stream.flush().unwrap();
    // Read with a bounded wait instead of read_to_end: the answer comes when
    // the *body*'s silence deadline fires (HEAD_GRACE after the last byte),
    // and read_to_end on
    // an open socket would sit past that. The endpoint closes after answering,
    // so EOF is the natural end.
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(60)))
        .unwrap();
    let mut raw = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&buf[..n]);
                if raw.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            Err(e) => panic!("reading the short-body refusal failed: {e}"),
        }
    }
    let (status, headers, _) = parse_response(&raw);
    assert_eq!(status, 400, "an incomplete body is refused: {status}");
    assert_eq!(
        header(&headers, "x-openfirma-reason"),
        Some("short-body"),
        "the refusal names the truncation"
    );

    // The same token must still sign now that a complete request follows it.
    let (status, _, payload) = request(
        addr,
        "POST",
        &format!("/sign/{token}"),
        &host,
        None,
        uri_body(b"el documento real, reintentado").as_bytes(),
    );
    assert_eq!(
        status, 200,
        "a request that died mid-body must not consume the one token of the launch"
    );
    assert!(
        String::from_utf8_lossy(&payload).contains('|'),
        "the retry produced a signature"
    );
}

/// The timeout must actually fire: Linux reports an `SO_RCVTIMEO` expiry as
/// `WouldBlock`, and an earlier accept loop continued on that error, so a
/// connection that sent half a header and went quiet was waited on forever
/// (the slowloris-by-idleness ADR-0005 promises against). The proof is the
/// *timing of the answer while the peer says nothing*: this connection sends
/// part of a head once and then stays silent for its whole life — if the
/// endpoint still answers, it answered at its inactivity deadline, because no
/// other event exists that could wake it. (The old code produced no answer
/// here at all, so an assertion about "served too early" was unwritable; the
/// absence of any answer is exactly what the bug looked like.) The head's own
/// grace window (`HEAD_GRACE`, five seconds) is what cuts this peer — bytes
/// received renew it, silence does not. Generous CI bounds around it.
#[test]
fn a_silent_half_header_is_cut_at_the_deadline() {
    let Some(key) = p12() else {
        require_or_skip("testdata/certs/signer-rsa.p12 is absent");
        return;
    };
    let server = server_on(&key);
    let addr = server.addr();
    let host = format!("127.0.0.1:{}", addr.port());

    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(90)))
        .unwrap();
    // Part of a request line, then silence forever. No header terminator ever
    // arrives: the only thing that can answer is the deadline itself.
    stream
        .write_all(format!("POST /echo HTTP/1.1\r\nHost: {host}\r\nX-Pa").as_bytes())
        .unwrap();
    stream.flush().unwrap();

    let started = std::time::Instant::now();
    let mut buf = [0u8; 4096];
    let n = stream
        .read(&mut buf)
        .expect("the endpoint must cut the stall");
    let elapsed = started.elapsed();
    let head = String::from_utf8_lossy(&buf[..n]).to_string();
    assert!(
        head.starts_with("HTTP/1.1 599"),
        "a stalled request head is refused with the timeout status: {head}"
    );
    assert!(
        head.contains("request-head-timeout"),
        "the refusal names the timeout: {head}"
    );
    assert!(
        elapsed >= std::time::Duration::from_secs(4)
            && elapsed < std::time::Duration::from_secs(30),
        "the deadline fired at its own moment ({elapsed:?}); anything later \
         than 30 s is a wait, not a deadline"
    );
}

/// Finding M-2, both halves closed (round-3 re-check): the connection's total
/// budget is an absolute instant fixed at accept (`CONNECTION_TIMEOUT`), and
/// — the half this test exists to pin — it is evaluated on the *success* path
/// of every read, not only where a read would block. A peer that dribbles one
/// byte every 1.15 s never blocks long enough for the socket timeout to fire,
/// so under the previous code its trickle constantly (re)armed the grace
/// window and the budget was never consulted: an idle clock cut nothing, and
/// the ceiling existed only in prose. The dribble here is INDEFINITE — one
/// byte per interval until the endpoint itself ends the connection — never a
/// fixed finite burst: with a finite trickle the last byte hands the cut to
/// the silence rule and the test passes even with the budget removed entirely
/// (the exact non-bite the round-3 review demonstrated). Two assertions pin
/// both directions: no answer and no close before `accept + 30 s` — an
/// idle-clock rule that cut a still-talking peer is the wrong fix this test
/// rejects — and the endpoint ends the connection within one trickle interval
/// after the budget matures, with the named head timeout.
#[test]
fn a_dribbling_peer_dies_at_the_absolute_budget_not_at_its_own_trickle() {
    let Some(key) = p12() else {
        require_or_skip("testdata/certs/signer-rsa.p12 is absent");
        return;
    };
    let server = server_on(&key);
    let addr = server.addr();
    let host = format!("127.0.0.1:{}", addr.port());

    let mut stream = TcpStream::connect(addr).unwrap();
    // Poll with a short socket timeout so every event is visible; the trickle
    // cadence and the budget are what this test is about, not the poll window.
    stream
        .set_read_timeout(Some(std::time::Duration::from_millis(300)))
        .unwrap();
    let mut request = b"POST /echo HTTP/1.1\r\nHost: ".to_vec();
    request.extend_from_slice(host.as_bytes());
    // The budget fixed by the server at accept, plus the dribble's own worst
    // lateness (one interval) before its next byte lets the Ok-path notice.
    let budget = std::time::Duration::from_secs(30);
    let trickle = std::time::Duration::from_millis(1150);
    // The budget is fixed at the SERVER's accept; `started` is this thread's
    // connect, slightly earlier, and every measured instant below inherits
    // that offset. Allow it explicitly so a correct implementation is never
    // punished for microseconds of scheduling: no honest cut lands 50 ms on
    // the early side of its own deadline.
    let slack = std::time::Duration::from_millis(50);
    let started = std::time::Instant::now();
    let mut buf = [0u8; 4096];
    let mut i = 0usize;
    let (answer, elapsed) = 'dribble: loop {
        if i >= request.len() {
            // The head is still incomplete and the peer has said everything
            // it will: keep polling until the endpoint ends this by itself.
            // Nothing else can ever wake either side — pure budget clock.
            match stream.read(&mut buf) {
                Ok(0) => break 'dribble (String::new(), started.elapsed()),
                Ok(n) => {
                    break 'dribble (
                        String::from_utf8_lossy(&buf[..n]).to_string(),
                        started.elapsed(),
                    );
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    assert!(
                        started.elapsed() < budget + trickle + std::time::Duration::from_secs(10),
                        "the endpoint never ended an ever-talking dribbler on its own \
                         budget ({:?}): the ceiling is invisible to a peer that never blocks",
                        started.elapsed()
                    );
                }
                Err(e) => panic!("the dribbler's socket failed: {e}"),
            }
        } else {
            stream.write_all(&[request[i]]).unwrap();
            stream.flush().unwrap();
            i += 1;
        }
        let next = std::time::Instant::now() + trickle;
        loop {
            match stream.read(&mut buf) {
                Ok(0) => {
                    // A close BEFORE the budget (plus accept-offset slack) is
                    // the wrong fix; at or after it, this is the cut.
                    if started.elapsed() + slack < budget {
                        panic!(
                            "the endpoint closed a talking dribbler before its budget \
                     matured ({:?}): the grace must not cut a peer that is still \
                     speaking",
                            started.elapsed()
                        );
                    }
                    break 'dribble (String::new(), started.elapsed());
                }
                Ok(n) => {
                    // Same slack on an answer: at or after budget+slack this
                    // is the refusal the budget owes us, not a premature one.
                    if started.elapsed() + slack < budget {
                        panic!(
                            "the dribbler was answered before its absolute budget could \
                     mature ({:?}): {:?}",
                            started.elapsed(),
                            String::from_utf8_lossy(&buf[..n])
                        );
                    }
                    break 'dribble (
                        String::from_utf8_lossy(&buf[..n]).to_string(),
                        started.elapsed(),
                    );
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut => {}
                Err(e) => panic!("the dribbler's socket failed: {e}"),
            }
            if std::time::Instant::now() >= next {
                break;
            }
        }
    };
    assert!(
        elapsed + slack >= budget,
        "an idle-clock rule cut a talking peer before its absolute budget \
         matured ({elapsed:?})"
    );
    assert!(
        elapsed < budget + trickle + std::time::Duration::from_secs(5),
        "the endpoint did not end the dribbler promptly at its budget — it \
         kept waiting on a peer whose bytes never block the read ({elapsed:?})"
    );
    if !answer.is_empty() {
        // A refusal (rather than a bare close) must name the head timeout —
        // not a malformed-head 400: the trickle was legal, only slow.
        assert!(
            answer.starts_with("HTTP/1.1 599"),
            "the budget answers with the timeout status: {answer}"
        );
        assert!(
            answer.contains("request-head-timeout"),
            "the trickle was cut by the head deadline, not a malformed head: {answer}"
        );
    }
}

/// Finding M-2, the capacity half the round-3 review measured end to end:
/// `MAX_CONCURRENT_CONNECTIONS` ever-talking dribblers used to hold every
/// slot for as long as they liked — their trickle never let the budget be
/// consulted, so a legitimate caller with a fresh valid token starved on 503
/// indefinitely (the review watched fourteen attempts over 40 s, all 503).
/// With the budget enforced on every successful read, the first wave dies at
/// accept + 30 s whatever its rhythm, and the caller's own retries — one
/// fresh token per attempt — land in the freed slots. The bound this
/// test asserts is patience any signing flow tolerates (60 s: the budget,
/// plus a few trickle intervals of tolerance for the scheduling race between
/// the wave dying and a retry catching the freed slot), not a claim that no
/// 503 is ever possible: while every slot is honestly occupied by a peer
/// still inside its budget, 503 is the answer, and what the two ceilings
/// guarantee is that the state is bounded. The dribblers are never dropped:
/// each of the server's cuts must come from the server, not from this harness
/// handing back a slot, and every loop in here is wall-clock bounded so the
/// unfixed code fails red (measured) instead of hanging the suite.
#[test]
fn dribbling_peers_never_starve_a_tokened_caller() {
    let Some(key) = p12() else {
        require_or_skip("testdata/certs/signer-rsa.p12 is absent");
        return;
    };
    let server = server_on(&key);
    let addr = server.addr();
    let host = format!("127.0.0.1:{}", addr.port());

    // Saturate every slot with an ever-talking dribbler: one byte of a head,
    // then one byte every 2 s — always inside HEAD_GRACE, never blocking long
    // enough for the grace's WouldBlock path to speak for the budget.
    let n = openfirma_browser::serve::MAX_CONCURRENT_CONNECTIONS;
    // The caller's wall-clock bound: the budget plus slack for the wave to
    // die and a retry to catch the freed slot. Crowd threads get it plus a
    // final trickle round, so whichever assert fires, it is this test failing
    // red with an honest message — never the suite hanging (this laptop has
    // frozen once on an unbounded timing test; none may exist here).
    let patience = std::time::Duration::from_secs(60);
    // How many crowd threads the endpoint has ACCEPTED as handlers, as opposed
    // to refused at capacity. Main waits on this before timing the caller, so
    // the caller races nobody for a slot: without the barrier the caller's own
    // first connect could take the slot a crowd thread was about to claim, the
    // endpoint refuses that thread at capacity in microseconds, and the check
    // below would report a "death" that was never a budget cut at all — the
    // 244µs failure this barrier exists to make impossible.
    let accepted = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let crowd: Vec<_> = (0..n)
        .map(|_| {
            let accepted = accepted.clone();
            std::thread::spawn(move || {
                // One connection is accepted and then dribbles until the budget
                // cuts it; a connection refused at capacity answers within
                // milliseconds, so it is retried instead of being counted.
                // Silence is the acceptance signal — an accepted handler says
                // nothing until its cut, a refused one has already spoken.
                let (mut stream, started) = loop {
                    let started = std::time::Instant::now();
                    let mut stream = TcpStream::connect(addr).unwrap();
                    stream
                        .set_read_timeout(Some(std::time::Duration::from_millis(500)))
                        .unwrap();
                    stream.write_all(b"P").unwrap();
                    stream.flush().unwrap();
                    match stream.read(&mut [0u8; 64]) {
                        // Bytes this early are the capacity refusal: drop this
                        // connection and try again rather than die for a slot
                        // the caller (or a sister thread) took first.
                        Ok(_) => continue,
                        Err(e)
                            if e.kind() == std::io::ErrorKind::WouldBlock
                                || e.kind() == std::io::ErrorKind::TimedOut =>
                        {
                            break (stream, started);
                        }
                        Err(e) => panic!("dribbler probe error {e:?} at {:?}", started.elapsed()),
                    }
                };
                accepted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                // The server only ever answers this peer when it cuts it, so
                // any readable byte IS the 599 refusal at the budget. Linux
                // keeps bytes received before the peer's close readable, and
                // a write into a socket whose FIN already arrived still
                // succeeds — draining the refusal must therefore be its own
                // observable step (read until empty after seeing one byte),
                // never something inferred from a failed write. The whole
                // loop is wall-clock bounded so no protocol surprise here can
                // hang the suite; an over-budget exit fails loudly below.
                let deadline = started + patience + std::time::Duration::from_secs(5);
                loop {
                    if std::time::Instant::now() >= deadline {
                        // End this peer's loop honestly; the join bound below
                        // turns it into a failed assertion with a clear cause.
                        return started.elapsed();
                    }
                    let wrote = stream.write_all(b"O").is_ok();
                    let next = started.elapsed() + std::time::Duration::from_secs(2);
                    match stream.read(&mut [0u8; 64]) {
                        // The budget's refusal (or its EOF after the answer
                        // drained): a cut at or after the budget is exactly
                        // what this peer must die of.
                        Ok(_) => return started.elapsed(),
                        Err(e)
                            if e.kind() == std::io::ErrorKind::WouldBlock
                                || e.kind() == std::io::ErrorKind::TimedOut =>
                        {
                            // Nothing back yet (there is nothing to send us
                            // until the budget cuts). A write that failed on
                            // a closed socket means the cut's bytes died
                            // unread — a race between this poll loop and the
                            // endpoint's drain-and-close, not an early cut;
                            // report it at the join bound.
                            if !wrote {
                                return started.elapsed();
                            }
                            // Wait out the trickle interval — under HEAD_GRACE,
                            // so the grace never fires and only the absolute
                            // budget can end this.
                            while started.elapsed() < next {
                                std::thread::sleep(std::time::Duration::from_millis(50));
                            }
                        }
                        Err(e) => panic!("dribbler read error {e:?} at {:?}", started.elapsed()),
                    }
                }
            })
        })
        .collect();

    // The legitimate caller: the exact shape of a real signing call, a fresh
    // one-shot token per attempt (never re-presented — `request_on` in one
    // shot). Starvation past this bound is the finding; 503 attempts before
    // it are legal and expected while every dribbler is still inside its
    // budget. This must NOT be `ask`: under a crowd that holds capacity for
    // as long as it likes (exactly what unfixed code does), ask's twelve-at-
    // a-quarter-second rounds would burn every token in the whole saturation
    // window and its own panic would replace the honest timing assertion.
    // Wait for every crowd thread to be accepted before timing the caller.
    // Bounded by wall clock so a crowd that can never saturate (a bug in this
    // harness, or an endpoint that stopped accepting) fails loudly instead of
    // hanging the suite; on unfixed code the crowd still saturates — that was
    // never the broken half — so this bound only ever trips on a harness bug.
    {
        let saturate_by = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while accepted.load(std::sync::atomic::Ordering::Relaxed) < n {
            assert!(
                std::time::Instant::now() < saturate_by,
                "the crowd never filled every slot ({}/{} accepted): the harness \
                 could not reach the saturation this test measures",
                accepted.load(std::sync::atomic::Ordering::Relaxed),
                n
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    let t0 = std::time::Instant::now();
    loop {
        let token = server.issue_token();
        let path = format!("/sign/{token}");
        let stream = TcpStream::connect(addr).expect("the endpoint must accept connections");
        let body = uri_body(b"la firma legitima entre dribblers");
        let (status, _, payload) =
            request_on(stream, addr, "POST", &path, &host, None, body.as_bytes());
        if status == 200 {
            assert!(
                String::from_utf8_lossy(&payload).contains('|'),
                "a served caller gets the signature payload"
            );
            break;
        }
        // A connection whose answer died unread in the socket layer (the
        // harness's u16::MAX sentinel) is not a sign of health: on unfixed
        // code 503s pile up and some answers die undelivered. Retrying that
        // attempt without claiming anything keeps the honest failure the
        // timing bound below, not a discarded-read technicality — this test
        // has already demonstrated it fails red before the fix for the right
        // reason (starvation at t=60 s).
        assert!(
            status == 503 || status == u16::MAX,
            "at capacity the endpoint refuses by name instead of dying: {status}"
        );
        assert!(
            t0.elapsed() < patience,
            "the legitimate caller starved while {n} dribblers held every \
             slot: never served within {patience:?} ({:?}) — the absolute \
             budget is invisible to a peer that never blocks",
            t0.elapsed()
        );
        std::thread::sleep(std::time::Duration::from_millis(250));
    }

    // Every dribbler must have died at the server's hands, not ours: none of
    // these streams was ever dropped or closed from this side. The peer kept
    // talking, so the silence rule (5 s) cannot explain a cut and only the
    // absolute budget (30 s) can; 29 s is well clear of any honest early cut
    // on the early side. On unfixed code the caller starves at the patience
    // bound above — this loop never runs, as measured (red at t=60.1 s).
    for handle in crowd {
        let died = handle.join().expect("a dribble thread ran to its cut");
        assert!(
            died >= std::time::Duration::from_secs(29),
            "a dribbler died before its budget could mature: {died:?}"
        );
        assert!(
            died < patience + std::time::Duration::from_secs(10),
            "the endpoint never ended a dribbler on its own budget (it lived to \
             {:?}): the absolute budget is invisible to a peer that never blocks",
            died
        );
    }
    // The caller got its signature and every dribbler met the server's cut;
    // there is nothing left holding slots.
}

/// Finding M-2, second half: the request bound used to count *accepted
/// connections*, so seventeen bare connects — no request, no token, anything
/// a blind `<img>` tag burst can do — permanently killed the port before the
/// legitimate call arrived. What replaced it must not be the same wall in a
/// different place: what consumes a slot is a *live* connection, and a live
/// one dies at its silence deadline by itself, so an attacker who merely
/// holds slots pays HEAD_GRACE of threads per wave while the real flow signs
/// every free instant between the waves. The test cycles exactly that
/// schedule — saturate with stalled peers, see the named refusal at capacity,
/// sign in the first gap once the oldest handler ages out — for two deadline
/// waves.
#[test]
fn stalled_connections_age_out_and_the_endpoint_never_shuts_down() {
    let Some(key) = p12() else {
        require_or_skip("testdata/certs/signer-rsa.p12 is absent");
        return;
    };
    let server = server_on(&key);
    let addr = server.addr();
    let host = format!("127.0.0.1:{}", addr.port());

    // Two deadline waves: fill every slot, then sign in the first gap. The
    // attacker's slots age out; ours always finds one.
    for wave in 0..2 {
        let mut crowd = Vec::new();
        for _ in 0..openfirma_browser::serve::MAX_CONCURRENT_CONNECTIONS {
            let mut stream = TcpStream::connect(addr).unwrap();
            // one byte of a head: accepted, handler busy, deadline ticking.
            stream.write_all(b"P").unwrap();
            stream.flush().unwrap();
            crowd.push(stream);
        }
        // With the cap reached, the overflow refusal is what a new connection
        // gets — named, survivable, not the old silent death of the port.
        let (status, headers, _) = request(addr, "POST", "/echo", &host, None, b"");
        assert_eq!(
            status, 503,
            "wave {wave}: at capacity the endpoint refuses, it does not die"
        );
        assert_eq!(
            header(&headers, "x-openfirma-reason"),
            Some("too-many-in-flight")
        );

        // The real caller cannot post into a saturated box either — what it
        // must never get again is the old *permanently dead* behaviour. Sign
        // in the first instant a stalled handler ages out (the deadline is
        // five seconds of silence each, so well inside this test's patience).
        let signed = std::time::Instant::now();
        loop {
            // `ask`, not `request`: a wave this saturated is exactly where the
            // socket layer loses answers unread on Windows, and each of its
            // attempts must present its OWN token — see ask's header.
            let (status, _, payload) = ask(
                &server,
                addr,
                "POST",
                &host,
                None,
                uri_body(b"la sede firma entre olas de conexiones").as_bytes(),
            );
            if status == 200 {
                assert!(String::from_utf8_lossy(&payload).contains('|'));
                break;
            }
            assert_eq!(status, 503, "an available slot answers or refuses by name");
            assert!(
                signed.elapsed() < std::time::Duration::from_secs(90),
                "wave {wave}: the endpoint stayed past capacity forever — stalled \
                 connections never age out ({signed:?} waited)"
            );
        }
        // The crowd is irrelevant now: drop it and everything still works.
        drop(crowd);
        // Between waves, drain the endpoint fully — a second of pure silence
        // past what the signature needed. On Windows a closed socket's answer
        // can die in flight (ask's own header documents that race *inside* a
        // wave; this is the same race across the boundary): every handler that
        // refused or answered the moment a slot freed must have finished its
        // write, and the slot pool must stand empty before wave two fills it.
        let drained = std::time::Instant::now();
        while ask(
            &server,
            addr,
            "POST",
            &host,
            None,
            uri_body(b"el drenaje entre olas").as_bytes(),
        )
        .0 != 200
        {
            assert!(
                drained.elapsed() < std::time::Duration::from_secs(30),
                "wave {wave}: the endpoint stopped answering between waves"
            );
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        std::thread::sleep(std::time::Duration::from_millis(1200));
    }
    let token = server.issue_token();
    let (status, _, _) = request(
        addr,
        "POST",
        &format!("/sign/{token}"),
        &host,
        None,
        uri_body(b"la ultima firma despues de todo el acoso").as_bytes(),
    );
    assert_eq!(status, 200, "the endpoint outlived every wave");
}

/// Past `MAX_CONCURRENT_CONNECTIONS` *live* connections, the overflow gets a
/// named 503 while the port keeps answering: refusing one caller in a flood is
/// survivable, closing the port for the real call is not. The stalled peers
/// hold their slots by never finishing a request head; after they age out at
/// the deadline, an echo proves no state died with them.
#[test]
fn a_flood_of_live_connections_gets_503_not_a_dead_endpoint() {
    let Some(key) = p12() else {
        require_or_skip("testdata/certs/signer-rsa.p12 is absent");
        return;
    };
    let server = server_on(&key);
    let addr = server.addr();
    let host = format!("127.0.0.1:{}", addr.port());

    let mut stalled = Vec::new();
    let mut got_503 = false;
    for _ in 0..(openfirma_browser::serve::MAX_CONCURRENT_CONNECTIONS + 8) {
        let mut stream = TcpStream::connect(addr).unwrap();
        // one byte of a head: accepted, handler blocked waiting for the rest.
        stream.write_all(b"P").unwrap();
        stream.flush().unwrap();
        stalled.push(stream);

        // Probe with a complete request; any answer at all proves the loop is
        // alive (200 while slots were still free), 503 ends the fill.
        let (status, headers, _) = request(addr, "POST", "/echo", &host, None, b"");
        if status == 503 {
            assert_eq!(
                header(&headers, "x-openfirma-reason"),
                Some("too-many-in-flight"),
                "the refusal names itself"
            );
            got_503 = true;
            break;
        }
    }
    assert!(
        got_503,
        "the endpoint never answered 503 while every slot was held busy"
    );

    // The stalled crowd ages out at its silence deadline (five seconds); when
    // a slot frees, the echo answers again — no state died with the flood.
    let t0 = std::time::Instant::now();
    loop {
        let (status, _, _) = request(addr, "POST", "/echo", &host, None, b"");
        if status == 200 {
            break;
        }
        assert!(
            t0.elapsed() < std::time::Duration::from_secs(90),
            "held slots never freed: the timeout still does not fire ({t0:?})"
        );
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    drop(stalled);
}
