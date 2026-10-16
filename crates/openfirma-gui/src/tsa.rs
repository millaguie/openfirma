//! The TSA client — a minimal HTTP POST with an honest transport decision.
//!
//! Transport is plain http only, and the refusal of https says why: openfirma
//! has no TLS client that obeys its own rules (a pure-Rust TLS stack does not
//! exist without C crypto), so pretending to speak https would be a lie about
//! what protects the query. This module carries the exact code `openfirma
//! sign --tsa` used before it moved here, because the GUI signs through the
//! same provider closure type (`openfirma_cades::TimestampFn`) over the same
//! wire: two implementations of one protocol is the drift this repository
//! refuses. The CLI's `main.rs` calls these functions too; nothing in this
//! file knows about windows or widgets.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;

use openfirma_cades::tsp;
use openfirma_core::Error;

/// How long the TSA may take to answer, per read or write. A signing run must
/// not hang on a black hole; 10 seconds is generous for a timestamp query.
const TSA_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// The most a TSA answer may weigh. A `TimeStampResp` with a full chain is
/// kilobytes; a megabyte is already nothing legitimate, and reading without a
/// cap hands a hostile server an unbounded allocation.
const TSA_MAX_RESPONSE: usize = 1024 * 1024;

/// The unsigned-attribute timestamp provider for one URL. Plain http only —
/// the https refusal is deliberate and tells the user what to run instead
/// (fetch by hand, pass `--timestamp-token` in a terminal). The token's own
/// signature cannot be checked from here: openfirma has no TSA trust anchors
/// of its own, so the imprint is verified and that limit is said out loud —
/// exactly like the CLI's warning.
pub fn provider(url: &str) -> Result<openfirma_cades::TimestampFn, String> {
    if !url.starts_with("http://") {
        return Err(
            "the TSA url must start with http:// (plain): an https TSA needs a TLS client, \
             which is a dependency decision of its own; until then fetch the token by hand \
             and sign in a terminal with --timestamp-token."
                .into(),
        );
    }
    let url = url.to_string();
    Ok(Arc::new(move |sig: &[u8], digest| {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let query = tsp::request(digest, sig, nonce)?;
        let response = http_post(&url, &query).map_err(|e| Error::Other(e.to_string()))?;
        let token = tsp::token_from_response(&response, digest, sig)?;
        warn_if_token_unverified(&format!("the TSA at {url}"), &token);
        Ok(vec![tsp::unsigned_attribute(&token)?])
    }))
}

/// The token about to be embedded imprints the right bytes (the verifier of
/// `token_from_response` proved that), but its own signature is unverified:
/// nothing in a signing client knows which TSA certificates to trust, and a
/// plain-http answer can be planted by anyone on the path. Say it on stderr
/// the way the CLI's warning does; the imprint still proves *what* the token
/// covers, just not *who* made it.
fn warn_if_token_unverified(source: &str, _token: &[u8]) {
    eprintln!(
        "warning: the time-stamp token from {source} was accepted on its imprint alone; \
         check the TSA's answer against its CA yourself: \
         openssl ts -verify -CAfile <tsa-ca.pem> -in <answer.tsr> -data <file>"
    );
}

/// A minimal HTTP/1.1 POST, enough for a timestamp query and nothing more.
/// std::net only: no dependency for a request that is two headers and a body.
fn http_post(url: &str, body: &[u8]) -> anyhow::Result<Vec<u8>> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| anyhow::anyhow!("only http:// TSA urls are supported"))?;
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (
            h,
            p.parse::<u16>()
                .map_err(|_| anyhow::anyhow!("the TSA url port {p:?} is not a number"))?,
        ),
        None => (authority, 80),
    };
    let mut stream: Option<TcpStream> = None;
    let mut last_error = None;
    for addr in (host, port)
        .to_socket_addrs()
        .map_err(|e| anyhow::anyhow!("the TSA host {host} does not resolve: {e}"))?
    {
        match TcpStream::connect_timeout(&addr, TSA_TIMEOUT) {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(e) => last_error = Some(e),
        }
    }
    let mut stream = stream.ok_or_else(|| {
        anyhow::anyhow!(
            "cannot reach the TSA at {host}:{port}: {}",
            last_error
                .map(|e| e.to_string())
                .unwrap_or_else(|| "no address to connect to".into())
        )
    })?;
    stream
        .set_read_timeout(Some(TSA_TIMEOUT))
        .map_err(|e| anyhow::anyhow!("cannot arm the TSA read timeout: {e}"))?;
    stream
        .set_write_timeout(Some(TSA_TIMEOUT))
        .map_err(|e| anyhow::anyhow!("cannot arm the TSA write timeout: {e}"))?;
    stream
        .write_all(
            format!(
                "POST /{path} HTTP/1.1\r\nHost: {authority}\r\n\
                 Content-Type: application/timestamp-query\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .as_bytes(),
        )
        .map_err(|e| anyhow::anyhow!("cannot send the timestamp query: {e}"))?;
    stream
        .write_all(body)
        .map_err(|e| anyhow::anyhow!("cannot send the timestamp query: {e}"))?;
    let mut raw = Vec::new();
    // one byte over the cap so an answer exactly at the cap still parses and
    // anything past it is provably past it
    (&mut stream)
        .take(TSA_MAX_RESPONSE as u64 + 1)
        .read_to_end(&mut raw)
        .map_err(|e| anyhow::anyhow!("the TSA closed the connection without answering: {e}"))?;
    if raw.len() > TSA_MAX_RESPONSE {
        anyhow::bail!(
            "the TSA sent more than {TSA_MAX_RESPONSE} bytes without finishing; a \
             timestamp answer is kilobytes, so this server is not a TSA"
        );
    }
    split_http_response(&raw)
}

/// The body of an HTTP answer, with the status line read as a status line:
/// version, then the three digit code as its own token. A substring match on
/// " 200" also accepts "HTTP/1.1 2006 ...", and the server picks the reason
/// phrase; that is why this parses instead of searching.
fn split_http_response(raw: &[u8]) -> anyhow::Result<Vec<u8>> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| anyhow::anyhow!("the TSA answer has no header/body separator"))?;
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let status = head.lines().next().unwrap_or_default();
    let mut parts = status.split_whitespace();
    let version = parts.next().unwrap_or_default();
    let code = parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/1.") || code != "200" {
        anyhow::bail!("the TSA answered {status:?}, expected an HTTP/1.x 200");
    }
    let mut body_out = raw[split + 4..].to_vec();
    // honour Content-Length when present; otherwise the connection close was
    // the terminator and everything after the headers is the body
    if let Some(line) = head
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
    {
        let n: usize = line[15..].trim().parse().unwrap_or(body_out.len());
        body_out.truncate(n);
    }
    Ok(body_out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_is_refused_with_the_way_out() {
        let err = match provider("https://tsa.example/tsa") {
            Ok(_) => panic!("https must be refused, never wired"),
            Err(e) => e,
        };
        assert!(err.contains("http://"), "{err}");
        assert!(err.contains("--timestamp-token"), "{err}");
    }

    /// The same shape checks the CLI's moved code carried: a status line is
    /// parsed as one, and an oversized answer stops at the cap.
    #[test]
    fn the_tsa_status_line_is_parsed_not_substring_matched() {
        let (addr, srv) = fake_tsa(b"HTTP/1.1 2006 evil\r\nContent-Length: 2\r\n\r\nhi".to_vec());
        let err = http_post(&format!("http://{addr}/tsa"), b"query")
            .expect_err("2006 is not 200")
            .to_string();
        srv.join().unwrap();
        assert!(err.contains("expected an HTTP/1.x 200"), "{err}");

        let (addr, srv) = fake_tsa(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi".to_vec());
        let body = http_post(&format!("http://{addr}/tsa"), b"query")
            .expect("a real 200 answer must be accepted");
        srv.join().unwrap();
        assert_eq!(body, b"hi");

        let (addr, srv) = fake_tsa(b"HTTP/1.1 500 Internal Server Error\r\n\r\nx".to_vec());
        let err = http_post(&format!("http://{addr}/tsa"), b"query")
            .expect_err("a 500 is not a timestamp")
            .to_string();
        srv.join().unwrap();
        assert!(err.contains("500"), "{err}");
    }

    #[test]
    fn the_tsa_answer_is_capped() {
        let mut answer = Vec::from(&b"HTTP/1.1 200 OK\r\n\r\n"[..]);
        answer.resize(TSA_MAX_RESPONSE + 100, b'x');
        let (addr, srv) = fake_tsa(answer);
        let err = http_post(&format!("http://{addr}/tsa"), b"query")
            .expect_err("a megabyte of x is not a TimeStampResp")
            .to_string();
        srv.join().unwrap();
        assert!(err.contains("1048576 bytes"), "{err}");
    }

    /// One answer TCP server, so `http_post` can be pointed at something that
    /// behaves like a hostile TSA without leaving the machine. (Identical to
    /// the CLI's test helper on purpose: the behaviour being pinned is the
    /// same one.)
    fn fake_tsa(answer: Vec<u8>) -> (std::net::SocketAddr, std::thread::JoinHandle<()>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("cannot bind");
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                // Drain the request until a short read timeout expires; see
                // the CLI's copy of this comment for why closing early RSTs.
                stream
                    .set_read_timeout(Some(std::time::Duration::from_millis(100)))
                    .ok();
                let mut buf = [0u8; 8192];
                loop {
                    match stream.read(&mut buf) {
                        Ok(0) => break,
                        Ok(_) => continue,
                        Err(_) => break,
                    }
                }
                let _ = stream.write_all(&answer);
            }
        });
        (addr, handle)
    }
}
