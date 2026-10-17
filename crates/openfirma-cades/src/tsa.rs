//! The TSA transport both frontends share — one minimal HTTP POST, not two
//! implementations that can drift (review 06, M-9).
//!
//! Transport is plain http only, and the refusal of https says why: openfirma
//! has no TLS client that obeys its own rules (a pure-Rust TLS stack does not
//! exist without C crypto), so pretending to speak https would be a lie about
//! what protects the query. `openfirma sign --tsa` and the GUI's TSA field
//! both come through [`http_post`] and [`provider`] here: the CLI used to
//! carry a line-for-line copy, and every fix (the status-line parsing that a
//! " 2006" reason phrase once fooled, the response cap that bounds a hostile
//! server's allocation) had to be made twice.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;

use crate::tsp;
use openfirma_core::{Error, Result};

/// How long the TSA may take to answer, per read or write. A signing run must
/// not hang on a black hole; 10 seconds is generous for a timestamp query.
pub const TSA_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// The most a TSA answer may weigh. A `TimeStampResp` with a full chain is
/// kilobytes; a megabyte is already nothing legitimate, and reading without a
/// cap hands a hostile server an unbounded allocation.
pub const TSA_MAX_RESPONSE: usize = 1024 * 1024;

/// The plain-http TSA provider both frontends hand to the signer: build a
/// query with a fresh nonce, POST it, check the token answers THAT query, and
/// wrap it as the unsigned attribute. `on_token` sees every token about to be
/// embedded — the CLI passes its `--validation-cert` verdict there, the GUI
/// its "accepted on the imprint alone" notice; that difference is a frontend
/// decision, so it stays a callback instead of being averaged away.
pub fn provider(
    url: &str,
    https_refusal: &str,
    on_token: impl Fn(&str, &[u8]) + Send + Sync + 'static,
) -> Result<crate::TimestampFn> {
    if !url.starts_with("http://") {
        return Err(Error::Other(https_refusal.to_string()));
    }
    let url = url.to_string();
    Ok(Arc::new(move |sig: &[u8], digest| {
        let nonce = tsp::random_nonce()?;
        let query = tsp::request(digest, sig, nonce)?;
        let response = http_post(&url, &query)?;
        let token = tsp::token_from_response(&response, digest, sig, Some(&query))?;
        on_token(&format!("the TSA at {url}"), &token);
        Ok(vec![tsp::unsigned_attribute(&token)?])
    }))
}

/// A minimal HTTP/1.1 POST, enough for a timestamp query and nothing more.
/// std::net only: no dependency for a request that is two headers and a body.
pub fn http_post(url: &str, body: &[u8]) -> Result<Vec<u8>> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| Error::Other("only http:// TSA urls are supported".into()))?;
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (
            h,
            p.parse::<u16>()
                .map_err(|_| Error::Other(format!("the TSA url port {p:?} is not a number")))?,
        ),
        None => (authority, 80),
    };
    let mut stream: Option<TcpStream> = None;
    let mut last_error = None;
    let addrs = (host, port)
        .to_socket_addrs()
        .map_err(|e| Error::Other(format!("the TSA host {host} does not resolve: {e}")))?;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, TSA_TIMEOUT) {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(e) => last_error = Some(e),
        }
    }
    let mut stream = stream.ok_or_else(|| {
        Error::Other(format!(
            "cannot reach the TSA at {host}:{port}: {}",
            last_error
                .map(|e| e.to_string())
                .unwrap_or_else(|| "no address to connect to".into())
        ))
    })?;
    stream
        .set_read_timeout(Some(TSA_TIMEOUT))
        .map_err(|e| Error::Other(format!("cannot arm the TSA read timeout: {e}")))?;
    stream
        .set_write_timeout(Some(TSA_TIMEOUT))
        .map_err(|e| Error::Other(format!("cannot arm the TSA write timeout: {e}")))?;
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
        .map_err(|e| Error::Other(format!("cannot send the timestamp query: {e}")))?;
    stream
        .write_all(body)
        .map_err(|e| Error::Other(format!("cannot send the timestamp query: {e}")))?;
    let mut raw = Vec::new();
    // one byte over the cap so an answer exactly at the cap still parses and
    // anything past it is provably past it
    (&mut stream)
        .take(TSA_MAX_RESPONSE as u64 + 1)
        .read_to_end(&mut raw)
        .map_err(|e| {
            Error::Other(format!(
                "the TSA closed the connection without answering: {e}"
            ))
        })?;
    if raw.len() > TSA_MAX_RESPONSE {
        return Err(Error::Other(
            "the TSA sent more than a megabyte without finishing; a timestamp answer is \
             kilobytes, so this server is not a TSA"
                .into(),
        ));
    }
    split_http_response(&raw)
}

/// The body of an HTTP answer, with the status line read as a status line:
/// version, then the three digit code as its own token. A substring match on
/// " 200" also accepts "HTTP/1.1 2006 ...", and the server picks the reason
/// phrase; that is why this parses instead of searching.
pub fn split_http_response(raw: &[u8]) -> Result<Vec<u8>> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| Error::Other("the TSA answer has no header/body separator".into()))?;
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let status = head.lines().next().unwrap_or_default();
    let mut parts = status.split_whitespace();
    let version = parts.next().unwrap_or_default();
    let code = parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/1.") || code != "200" {
        return Err(Error::Other(format!(
            "the TSA answered {status:?}, expected an HTTP/1.x 200"
        )));
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

    /// One answer TCP server, so `http_post` can be pointed at something that
    /// answers exactly the bytes a test chooses, on a port nobody else holds.
    /// The request must be drained before answering (the CLI's fake_tsa learned
    /// it the hard way over 13 Windows commits): closing with unread request
    /// bytes in the receive buffer makes the kernel RST the connection, and
    /// the client's read_to_end then fails even though the answer was written.
    fn answering_server(reply: Vec<u8>) -> std::net::SocketAddr {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                use std::io::{Read, Write};
                stream
                    .set_read_timeout(Some(std::time::Duration::from_millis(100)))
                    .ok();
                let mut sink = [0u8; 8192];
                loop {
                    match stream.read(&mut sink) {
                        Ok(0) => break,
                        Ok(_) => continue,
                        Err(_) => break, // timeout: the request is fully in
                    }
                }
                let _ = stream.write_all(&reply);
                let _ = stream.flush();
            }
        });
        addr
    }

    #[test]
    fn https_is_refused_by_name_not_responded_to() {
        let err = http_post("https://tsa.example/tsa", b"q").unwrap_err();
        assert!(err.to_string().contains("http://"), "{err}");
    }

    #[test]
    fn a_2006_status_is_not_a_200() {
        // the substring-matching bug this parser replaced: " 200" appears in
        // "HTTP/1.1 2006 ...", and a hostile server chooses reason phrases.
        let reply = b"HTTP/1.1 2006 Fine\r\n\r\nbody";
        let err = split_http_response(reply).unwrap_err();
        assert!(err.to_string().contains("2006"), "{err}");
    }

    #[test]
    fn content_length_truncates_the_body() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nTRAILING";
        assert_eq!(split_http_response(raw).unwrap(), b"TRAI");
    }

    #[test]
    fn the_post_reaches_the_server_and_the_answer_comes_back() {
        let body = b"token-bytes".to_vec();
        let reply = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/timestamp-reply\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes()
        .into_iter()
        .chain(body.iter().copied())
        .collect::<Vec<_>>();
        let addr = answering_server(reply);
        let got = http_post(&format!("http://{addr}/tsa"), b"query").unwrap();
        assert_eq!(got, body);
    }

    #[test]
    fn a_refusing_status_travels_verbatim() {
        let reply = b"HTTP/1.1 503 later\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let addr = answering_server(reply.to_vec());
        let err = http_post(&format!("http://{addr}/tsa"), b"query").unwrap_err();
        assert!(err.to_string().contains("503 later"), "{err}");
    }
}
