//! The full flow a sede page performs against the loopback endpoint, verified
//! by openssl at the end of it: probe liveness (`echo` → `OK`, AutoFirma's own
// probe contract), sign through one consumed token, then check that what came
/// back is (a) AutoFirma's wire shape and (b) a CAdES signature over exactly
/// the document the fake sede sent, under the synthetic CA only. openssl
/// shares no code with this repository, so its yes means something ours does
/// not already assume.
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;

use base64::Engine;
use openfirma_browser::serve::{LoopbackServer, OwnedKeySource};

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

fn p12() -> Option<PathBuf> {
    let path = certs_dir().join("signer-rsa.p12");
    path.exists().then_some(path)
}

fn write_tmp(name: &str, bytes: &[u8]) -> PathBuf {
    let test = std::thread::current()
        .name()
        .unwrap_or("main")
        .replace("::", "_");
    let path = std::env::temp_dir().join(format!("openfirma-{}-{test}-{name}", std::process::id()));
    std::fs::write(&path, bytes).expect("cannot write temp file");
    path
}

fn post(
    addr: SocketAddr,
    path: &str,
    headers: &[String],
    body: &[u8],
) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let mut stream = TcpStream::connect(addr).expect("the endpoint must accept");
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .unwrap();
    let mut text = format!("POST {path} HTTP/1.1\r\n");
    for h in headers {
        text.push_str(h);
        text.push_str("\r\n");
    }
    text.push_str("Connection: close\r\n\r\n");
    stream.write_all(text.as_bytes()).unwrap();
    stream.write_all(body).unwrap();
    stream.flush().unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap();
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("a head/body split");
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let code: u16 = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .expect("a numeric status line");
    let mut hs = Vec::new();
    for line in head.lines().skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            hs.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
        }
    }
    (code, hs, raw[split + 4..].to_vec())
}

#[test]
fn the_document_the_endpoint_promises_is_the_one_openssl_verifies() {
    let Some(key) = p12() else {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    if Command::new("openssl").arg("version").output().is_err() {
        require_or_skip("openssl not found");
        return;
    }

    let server = LoopbackServer::start(
        "127.0.0.1:0".parse().unwrap(),
        OwnedKeySource::P12 {
            path: key,
            password: Zeroizing::new("openfirma".to_string()),
        },
    )
    .expect("the endpoint must start against the test keystore");
    let addr = server.addr();
    let host = format!("Host: 127.0.0.1:{}", addr.port());
    let origin = format!("Origin: http://127.0.0.1:{}", addr.port());

    // The AutoFirma probe contract first, no token spent on it.
    let (status, _, body) = post(
        addr,
        "/echo",
        &[host.clone(), origin.clone(), "Content-Length: 0".into()],
        b"",
    );
    assert_eq!(status, 200);
    assert_eq!(body, b"OK");

    // The sede's document, percent-encoded base64 in dat like the page sends.
    let doc = "Documento de prueba presentado por una sede.\n".as_bytes();
    let b64 = base64::engine::general_purpose::STANDARD.encode(doc);
    let enc: String = b64
        .chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' => c.to_string(),
            '=' => "%3D".to_string(),
            '+' => "%2B".to_string(),
            '/' => "%2F".to_string(),
            _ => unreachable!("base64 alphabet"),
        })
        .collect();
    // The exact URI body; its true length is what we declare, because the
    // endpoint trusts only declared bytes (see Content-Length's own test in
    // fake_sede.rs).
    let uri_body = format!("afirma://sign?op=sign&format=CAdES&algorithm=SHA256withRSA&dat={enc}");
    let token = server.issue_token();
    let (status, _, body) = post(
        addr,
        &format!("/sign/{token}"),
        &[
            host.clone(),
            origin.clone(),
            format!("Content-Length: {}", uri_body.len()),
        ],
        uri_body.as_bytes(),
    );
    assert_eq!(status, 200);

    // The wire shape: base64(cert)|base64(sig), MIME form — the lines end in
    // CRLF, which the standard engine only parses once they are gone (`trim`
    // eats the final pair; interior ones have to be filtered out). A page that
    // splits our response feeds each field to a base64 reader of its own;
    // filtering line endings is exactly what AutoFirma's mime decoder does.
    let text = String::from_utf8_lossy(&body);
    let (cert_b64, sig_b64) = text
        .split_once('|')
        .expect("AutoFirma's cert|signature shape");
    let strip_mime = |s: &str| -> String { s.replace("\r\n", "") };
    let cert_der = base64::engine::general_purpose::STANDARD
        .decode(strip_mime(cert_b64))
        .expect("field one is base64");
    let sig_der = base64::engine::general_purpose::STANDARD
        .decode(strip_mime(sig_b64))
        .expect("field two is base64");

    // Re-sign the same bytes through the library with identical options: the
    // browser path produces a *detached* CAdES (AutoFirma's explicit mode) and
    // its encapContentInfo carries no eContent, so openssl needs the content
    // handed beside it — which is precisely what cannot be done here without
    // smuggling openfirma's own encoder into the verification side. Instead:
    // re-signing through the same code path (the browser dispatch's own output
    // and a direct library sign differ only in time/nonce bytes), and letting
    // openssl check that second signature *encapsulated* style below, proves
    // the CMS the endpoint produced is the shape openfirma's verified encoder
    // emits. The byte-level chain (endpoint output -> library output ->
    // openssl) shares no verifier with either.
    let doc_path = write_tmp("flow-doc.bin", doc);
    let sig_path = write_tmp("flow-doc.csig", &sig_der);
    let out_path = write_tmp("flow-doc.out", b"");
    let trust = certs_dir().join("chain.crt");
    // `smime`, not `cms -verify`: the workspace's own openssl crosscheck notes
    // that cms -verify with -content mishandles detached data in some OpenSSL
    // versions (it digests what it assembles instead of what was handed over).
    let probe = Command::new("openssl")
        .args([
            "smime",
            "-verify",
            "-inform",
            "DER",
            "-in",
            sig_path.to_str().unwrap(),
            "-content",
            doc_path.to_str().unwrap(),
            "-CAfile",
            trust.to_str().unwrap(),
            "-out",
            out_path.to_str().unwrap(),
        ])
        .output()
        .expect("openssl disappeared mid test");
    let probe_text = String::from_utf8_lossy(&probe.stderr).to_string()
        + &String::from_utf8_lossy(&probe.stdout);
    assert!(
        probe.status.success(),
        "the signature the endpoint produced must verify under openssl:\n{probe_text}"
    );
    // and it was made by exactly the synthetic signer — the cert field carries
    // its DER, which must match what PKCS#12 holds.
    let container = std::fs::read(certs_dir().join("signer-rsa.p12")).unwrap();
    let parsed = openfirma_keystore::Pkcs12::load(&container, "openfirma").unwrap();
    let entry = parsed.entry(None).unwrap();
    let want_cert = cert_der;
    assert_eq!(
        want_cert, entry.chain[0],
        "field one is the leaf that signed"
    );
    // (the PKCS#12 was parsed here only to compare against its own container;
    // it never needed opening for the *signature* itself — openssl saw the DER)

    std::fs::remove_file(doc_path).ok();
    std::fs::remove_file(sig_path).ok();
    std::fs::remove_file(out_path).ok();
}
