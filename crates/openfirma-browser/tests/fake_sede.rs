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
/// explicit here so every test decides its own headers byte for byte. A reset
/// can beat reading entirely (see the read loop's zero-byte arm): the retry is
/// one socket deep — request_on re-asks only an idempotent probe, and a probe
/// has no token to burn; if even the second answer dies unread the test panics
/// rather than looping.
fn request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    host: &str,
    origin: Option<&str>,
    body: &[u8],
) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let stream = TcpStream::connect(addr).expect("the endpoint must accept connections");
    request_on(stream, addr, method, path, host, origin, body)
}

/// The reader split from [`request`] so a reset that beat reading entirely can
/// retry on a fresh socket (see the read loop's zero-byte arm). A retry lands
/// on an endpoint whose slot just freed or whose token state has not changed
/// for an unauthenticated refusal, and both callers of `request` here tolerate
/// every answer by construction — this re-ask only recovers bytes Windows'
/// close-with-unread-data rule discarded.
fn request_on(
    mut stream: TcpStream,
    addr: SocketAddr,
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
    text.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    ));
    // Writing may fail, and that is part of the contract: when the endpoint
    // refuses a request it answers and closes while a large body may still be
    // in flight, and whether the write then succeeds is OS timing (macOS RSTs,
    // Linux buffers), not an openfirma rule. The answer gets read regardless.
    let _ = stream.write_all(text.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
    let mut raw = Vec::new();
    // The endpoint always closes; read to EOF — but a reset after a complete
    // response is also an EOF (see the read loop), because this test's answer
    // has an exact Content-Length and Windows lets the queued RST land before
    // the client ever drains the bytes its stack already delivered.
    let mut buf = [0u8; 16384];
    let mut total = 0usize;
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                total += n;
                assert!(
                    total < 64 * 1024 * 1024,
                    "the endpoint streamed without end"
                );
                raw.extend_from_slice(&buf[..n]);
                // Stop at the response's own boundary when it has one: no EOF
                // and no reset need ever be raced for a fixed-length answer.
                if complete_response(&raw) {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            // A refusal closes while our (possibly huge, deliberately refused)
            // body may still be in flight; the OS may report the reset on read.
            // Windows adds its own twist: closing an accepted socket that
            // still holds UNREAD data discards that data and sends an RST, so
            // a client that lost the race can fail its very first read with
            // zero bytes collected. The answer then never existed for us (the
            // stack dropped it), which is why `a_answered_socket` below asks
            // the endpoint for it again instead of guessing: a reset is only
            // trusted as an EOF when we already hold bytes, and those bytes
            // must be the complete response.
            Err(e)
                if (e.kind() == std::io::ErrorKind::ConnectionReset
                    || e.kind() == std::io::ErrorKind::ConnectionAborted)
                    && !raw.is_empty() =>
            {
                assert!(
                    complete_response(&raw),
                    "the answer was cut mid-response: {:?}",
                    String::from_utf8_lossy(&raw)
                );
                break;
            }
            Err(e)
                if raw.is_empty()
                    && matches!(
                        e.kind(),
                        std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
                    ) =>
            {
                // A signed request may NOT be re-sent: the endpoint can legally
                // answer a presented token exactly once, so a retry would turn
                // Windows' lost bytes into a fake 403. The probes are idempotent
                // and re-asked on a fresh socket — the flood/stall tests read
                // them at capacity and assert on status either way, never on
                // silence; losing one to this race would fail them spuriously.
                if path.starts_with("/sign/") {
                    panic!("the unread answer was destroyed on a signing request: {e}");
                }
                let fresh =
                    TcpStream::connect(addr).expect("the endpoint must accept a re-read probe");
                return request_on(fresh, addr, method, path, host, origin, body);
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

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
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
/// test to be wrong about): a sign body contains exactly one `|` between two
/// standard-alphabet segments, and every MIME newline sits at the 78th column
/// of each encoded field, which is what AutoFirma's mime encoder produces. A
/// selectcert body has no separator at all. The byte-level truth of those
/// fields — that they *decode* to the signer's certificate and a signature
/// openssl accepts over the document — is proven by `sede_crosscheck.rs`,
/// which checks it against an independent implementation rather than against
/// another parser from this repository.
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
        // The field ends in its MIME CRLF; before it: standard-alphabet lines
        // of at most 76 characters joined by CRLF. That shape is AutoFirma's,
        // and an off-by-one line ending would fail the exact-column check.
        assert!(field.ends_with(b"\r\n"), "MIME fields end in CRLF");
        let content = &field[..field.len() - 2];
        let mut cursor: &[u8] = content;
        while let Some(pos) = cursor.windows(2).position(|w| w == b"\r\n") {
            assert!(
                pos <= 76,
                "a MIME line may not be longer than 76 characters"
            );
            assert!(
                cursor[..pos]
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || *b == b'+' || *b == b'/'),
                "the alphabet before a line ending is base64's standard one"
            );
            cursor = &cursor[pos + 2..];
        }
        assert!(
            cursor
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || *b == b'+' || *b == b'/' || *b == b'='),
            "the final line is base64 too, padding included"
        );
    }

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
        header(&headers, "x-openfirma-reason"),
        Some("malformed-uri")
    );
    let text = String::from_utf8_lossy(&body);
    assert!(
        text.contains("no dat parameter"),
        "the refusal names what the URI lacks: {text}"
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
    assert!(text.contains("not one this client implements"), "{text}");

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
        header(&headers, "x-openfirma-reason"),
        Some("unsupported-operation")
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
    assert_eq!(
        header(&headers, "x-openfirma-reason"),
        Some("malformed-uri")
    );
    let text = String::from_utf8_lossy(&body);
    assert!(
        text.contains("\"message\""),
        "names what is missing: {text}"
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
    // the *body* deadline fires (up to CONNECTION_TIMEOUT), and read_to_end on
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

/// The timeout of `CONNECTION_TIMEOUT` must actually fire: Linux reports an
/// `SO_RCVTIMEO` expiry as `WouldBlock`, and an earlier accept loop continued
/// on that error, so a connection that sent half a header and went quiet was
/// waited on forever (the slowloris-by-idleness ADR-0005 promises against).
/// The proof is the *timing of the answer while the peer says nothing*: this
/// connection sends part of a head once and then stays silent for its whole
/// life — if the endpoint still answers, it answered at the deadline, because
/// no other event exists that could wake it. (The old code produced no answer
/// here at all, so an assertion about "served too early" was unwritable; the
/// absence of any answer is exactly what the bug looked like.) Generous CI
/// bounds around a 30 s server-side timeout.
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
        elapsed >= std::time::Duration::from_secs(25)
            && elapsed < std::time::Duration::from_secs(60),
        "the deadline fired at its own moment ({elapsed:?}); anything later          than 60 s is a wait, not a deadline"
    );
}

/// Finding M-2, second half: the request bound used to count *accepted
/// connections*, so seventeen bare connects — no request, no token, anything
/// a blind `<img>` tag burst can do — permanently killed the port before the
/// legitimate call arrived. What replaced it must not be the same wall in a
/// different place: what consumes a slot is a *live* connection, and a live
/// one dies at the connection deadline by itself, so an attacker who merely
/// holds slots pays 30 s of threads per wave while the real flow signs every
/// free instant between the waves. The test cycles exactly that schedule —
/// saturate with stalled peers, see the named refusal at capacity, sign in
/// the first gap once the oldest handler ages out — for two deadline waves.
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
        // 30 s, so well inside this test's own patience).
        let signed = std::time::Instant::now();
        loop {
            let token = server.issue_token();
            let (status, _, payload) = request(
                addr,
                "POST",
                &format!("/sign/{token}"),
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
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        // The crowd is irrelevant now: drop it and everything still works.
        drop(crowd);
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

    // The stalled crowd ages out at the connection deadline (30 s); when a
    // slot frees, the echo answers again — no state died with the flood.
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
