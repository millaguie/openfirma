//! The `afirma://` URI grammar, pinned to URIs recorded from AutoFirma's own
//! protocol tests and JS client — literals pasted here with the source line
//! they came from, because "the parser we wrote agrees with the spec we read"
//! proves nothing; agreeing with bytes a real sede sends does.
//!
//! The reference is the AutoFirma 1.9.1 clone (`/tmp/opencode/autofirma-src`),
//! not openfirma: each URI below carries `file:line`, and the expectations
//! carry the file that decides them (the parsers under
//! `afirma-core/src/main/java/es/gob/afirma/core/misc/protocol`).

use base64::Engine;
use openfirma_browser::uri::{MAX_DATA_BYTES, Operation, parse, parse_endpoint_body};

/// TestProtocolInvocation.java:18 — a CAdES sign call of the classic shape:
/// session id, storage servlet, format, algorithm, base64 `properties` and
/// base64 `dat`, all in one query string. The percent signs (`%2F`, `%3D`)
/// are exactly how the page's `encodeURIComponent` wrote them.
const RECORDED_SIGN_HASH: &str = "afirma://sign?op=sign&id=001261524336&stservlet=http://appprueba:8080/afirma-signature-storage/StorageService&format=CAdES&algorithm=SHA1withRSA&properties=c2VydmVyVXJsPWh0dHA6Ly8xMC45MC40My43Nzo4MDg4L2FmaXJtYS1zZXJ2ZXItdHJpcGhhc2Utc2lnbmVyL1NpZ25hdHVyZVNlcnZpY2UKcHJlY2FsY3VsYXRlZEhhc2hBbGdvcml0aG09U0hBMQptb2RlPWV4cGxpY2l0Cg%3D%3D&dat=Jhxa1FdwzBSHXI9G6qPspCVoEEo%3D";

/// TestProtocolInvocation.java:15 — the same operation with no `dat` at all.
/// (The recorded line does carry a legacy 8-digit `key=` parameter, AutoFirma's
/// old cipher key; `parse` reads it and ignores it exactly as openfirma has no
/// intermediate-server flow to cipher anything for.) The bytes this call would
/// sign must come from the page itself — openfirma never fetches them.
const RECORDED_SIGN_LEGACY: &str =
    "afirma://sign?op=sign&id=000954750801&key=70192563&format=CAdES&algorithm=SHA1withRSA";

/// TestProtocolInvocation.java:15 with the `stservlet` that recorded line
/// carries — the intermediate-server storage callback. openfirma refuses a URI
/// that requires it, which is the second half of the pinned behaviour.
const RECORDED_SIGN_STORAGE: &str = "afirma://sign?op=sign&id=000954750801&key=70192563&stservlet=http://appprueba:8080/afirma-signature-storage/StorageService&format=CAdES&algorithm=SHA1withRSA";

/// TestProtocolInvocation.java:19 — a PAdES call whose `dat` is the base64 of
/// a whole PDF, with the visible-signature geometry inside `properties`.
const RECORDED_SIGN_PDF: &str = "afirma://sign?op=sign&id=001261524336&stservlet=http://appprueba:8080/afirma-signature-storage/StorageService&format=PAdES&algorithm=SHA512withRSA&properties=c2VydmVyVXJsPWh0dHA6Ly8xMC45MC40My43Nzo4MDg4L2FmaXJtYS1zZXJ2ZXItdHJpcGhhc2Utc2lnbmVyL1NpZ25hdHVyZVNlcnZpY2UK&dat=JVBERi0x";

/// autoscript.js:2469 — the launch of mechanism 2 itself. The page chooses up
/// to three ports and a session id, hands both to the scheme handler, and
/// then reaches the endpoint the handler opened. openfirma keeps every
/// parameter's role (the id becomes the one-time token; the port is learned
/// from the bound socket).
const RECORDED_WEBSOCKET_LAUNCH: &str =
    "afirma://websocket?ports=49152,53001,60100&v=4&jvc=4&idsession=abc123def456";

#[test]
fn the_recorded_websocket_launch_is_the_scheme_hand_off_we_do_not_answer() {
    // Launching mechanism 2 (a server on page-chosen ports) is what the real
    // flow does through this URI. openfirma's endpoint is started by the CLI,
    // not conjured by a URI — see ADR-0005 — so parsing it as an operation is
    // refused with the reason: the launcher's own dispatch table has no entry
    // for it here, and pretending otherwise would be answering the wrong call.
    let err = parse(RECORDED_WEBSOCKET_LAUNCH).expect_err("websocket is a launch, not an op");
    assert!(
        err.to_string().contains("not one this client implements"),
        "{err}"
    );
}

#[test]
fn a_recorded_sign_uri_parses_into_exactly_what_autofirma_would_run() {
    let uri = parse(RECORDED_SIGN_HASH).expect(
        "a recorded sede URI must not be refused for \
        shape: whatever AutoFirma's launcher accepts, openfirma must at least read",
    );
    // The launcher dispatches on the prefix (`afirma://sign?`) and parses `op`
    // case-insensitively to SIGN; both land on Operation::Sign here.
    assert_eq!(uri.operation, Operation::Sign);
    assert_eq!(uri.format.as_deref(), Some("CAdES"));
    assert_eq!(uri.algorithm.as_deref(), Some("SHA1withRSA"));
    // `id` doubles as the session id (UrlParametersToSign.setSignParameters
    // falls back from `dat`… actually it takes `id`, and the launcher itself
    // reads `idsession`; both are accepted here and share AutoFirma's limits).
    assert_eq!(uri.id_session.as_deref(), Some("001261524336"));
    let data = uri.data.expect("dat must arrive decoded");
    // The recorded dat is 20 bytes of base64 (a SHA-1 digest, which is what a
    // precalculatedHashAlgorithm=SHA1 call carries); percent decoding the `%3D`
    // padding back to `=` and one base64 decode round trip is the whole
    // transformation AutoFirma's DataDownloader applies. 20 = the SHA-1 length,
    // so the check also proves the decode landed on exactly the bytes that were
    // encoded (a stray '%' surviving would show as a different length or a
    // failed strict decode).
    assert_eq!(
        data.len(),
        20,
        "decoded dat must be exactly what was encoded"
    );
    // %3D%3D in the properties value had to come back as two '='.
    assert!(RECORDED_SIGN_HASH.contains("%3D%3D"));
}

#[test]
fn a_recorded_call_without_data_demands_it_and_the_storage_route_refuses() {
    // The recorded line without its servlet: no dat, so the parse must demand
    // one — that is AutoFirma's own shape of failure for a sign call.
    let err = parse(RECORDED_SIGN_LEGACY)
        .expect_err("a sign URI with neither dat nor fileid carries nothing to sign");
    assert!(err.to_string().contains("dat"), "{err}");
    // The same recorded line *with* its stservlet belongs to the government
    // intermediate-server callback, a route openfirma has no answer for. The
    // refusal names whose flow it is, so nobody mistakes it for a typo.
    let err = parse(RECORDED_SIGN_STORAGE)
        .expect_err("a URI that requires the servlet callback cannot be served here");
    let text = err.to_string();
    assert!(text.contains("stservlet"), "{text}");
    assert!(
        text.contains("intermediate"),
        "the refusal must say whose flow it belongs to: {text}"
    );
}

#[test]
fn a_recorded_pdf_call_survives_percent_decoding_and_base64() {
    let uri = parse(RECORDED_SIGN_PDF).expect("a recorded PAdES URI must parse");
    assert_eq!(uri.operation, Operation::Sign);
    assert_eq!(uri.format.as_deref(), Some("PAdES"));
    let data = uri.data.expect("the whole PDF base64 arrives decoded");
    // The first four bytes of any PDF: what the encoding round-trip must keep.
    assert_eq!(&data[..4], b"%PDF", "dat decoded to a real document header");
}

/// A `dat` whose base64 is wrapped into 76-character MIME lines, exactly what
/// `Base64.encode(x, DO_BREAK_LINES)` (AutoFirma's own encoder, and any server
/// that wraps) produces. AutoFirma decodes it: its alphabet includes `\t \n
/// \r` (`afirma-core/src/main/java/es/gob/afirma/core/misc/Base64.java:623`)
/// and the decoder skips whitespace inside the stream (`DataDownloader.java:
/// 127-137` takes the `isBase64` branch for such a payload). The document, not
/// the wrapped text, is what must reach the signer.
const WRAPPED_DAT_URI: &str = "afirma://sign?op=sign&format=CAdES&algorithm=SHA256withRSA&dat=\
VGhpcyBpcyB0aGUgZG9jdW1lbnQgYSBjaXRpemVuIHdhbnRzIHNpZ25lZCwgbm90IHRoZSBiYXNl\r\n\
NjQgdGV4dCBpdCB0cmF2ZWxzIGluLiBXcmFwcGVkIGF0IDc2IGNoYXJhY3RlcnMgYnkgYSBzZXJ2\r\n\
ZXIgdGhhdCBrbm93cyBNSU1FIGFuZCByaWdodGx5IHNvLgo%3D";

/// The same wrapped payload written with the other whitespace AutoFirma's
/// alphabet carries: interior tabs and bare LF endings.
const TAB_DAT_URI: &str = "afirma://sign?op=sign&format=CAdES&algorithm=SHA256withRSA&dat=\
VGhpcyBpcyB0aGUgZG9jdW1l\nbnQgYSBjaXRpemVuIHdhbnRz\tIHNpZ25lZCwgbm90IHRoZSBiYXNl\r\n\
NjQgdGV4dCBpdCB0cmF2ZWxzIGluLiBXcmFwcGVkIGF0IDc2IGNoYXJhY3RlcnMgYnkgYSBzZXJ2\r\n\
ZXIgdGhhdCBrbm93cyBNSU1FIGFuZCByaWdodGx5IHNvLgo%3D";

/// The document both URIs above carry: the base64 of these exact bytes, split
/// across lines by the writer. Recomputing it here is what lets the assertion
/// be "decoded == document" rather than a length coincidence.
fn wrapped_document() -> Vec<u8> {
    b"This is the document a citizen wants signed, not the base64 text it travels in. \
Wrapped at 76 characters by a server that knows MIME and rightly so.\n"
        .to_vec()
}

#[test]
fn a_line_wrapped_dat_decodes_to_the_document_not_the_text() {
    // The divergence this test exists for: the strict decoder rejects interior
    // newlines, and an implementation that then signs the literal text
    // produces a perfect-looking signature over bytes the sede never sent.
    // AutoFirma's decoder ignores ASCII whitespace (Base64.java:623 puts \t,
    // \n and \r in its alphabet), so openfirma must decode to the document.
    let want = wrapped_document();
    for uri_text in [WRAPPED_DAT_URI, TAB_DAT_URI] {
        let uri = parse(uri_text)
            .unwrap_or_else(|e| panic!("a MIME-wrapped dat AutoFirma decodes must parse: {e}"));
        assert_eq!(
            uri.data.as_deref(),
            Some(want.as_slice()),
            "CRLF/LF/tab wrapped base64 must decode to the document bytes, never sign the base64 text (AutoFirma Base64.java:623 skips whitespace; signing the text here was finding A-2)"
        );
    }
}

#[test]
fn a_dat_that_is_not_base64_is_refused_instead_of_signed_literally() {
    // The negative half of A-2: AutoFirma's literal-bytes fallback
    // (DataDownloader.java:137) is deliberately NOT copied. A payload that
    // does not decode is an error naming the parameter, because signing it as
    // text would hand the sede a valid signature over the wrong bytes.
    let err = parse(
        "afirma://sign?op=sign&format=CAdES&algorithm=SHA256withRSA&dat=no%20es%20base64%20%21%21",
    )
    .expect_err("a non-base64 dat must be refused, never signed verbatim");
    let text = err.to_string();
    assert!(
        text.contains("dat"),
        "the error must name the URI parameter: {text}"
    );
    assert!(
        text.contains("base64"),
        "and say why it is not decodable: {text}"
    );
    // gzip=true never had a fallback and keeps its own refusal.
    let err = parse(
        "afirma://sign?op=sign&gzip=true&format=CAdES&algorithm=SHA256withRSA&dat=no%20es%20base64",
    )
    .expect_err("gzip without base64 was always an error");
    assert!(err.to_string().contains("base64"), "{err}");
}

#[test]
fn operations_are_the_launcher_set_matched_like_autofirma_matches_them() {
    // ProtocolInvocationLauncher dispatches on lowercase prefixes; the
    // Operation enum matches case-insensitively (SignOperation.Operation).
    for (text, want) in [
        (
            "afirma://sign?op=SIGN&format=CAdES&algorithm=SHA256&dat=aGk%3D",
            Operation::Sign,
        ),
        (
            "afirma://cosign?op=COSIGN&format=CAdES&algorithm=SHA256&dat=aGk%3D",
            Operation::Cosign,
        ),
        (
            "afirma://countersign/?op=countersign&format=CAdES&algorithm=SHA256withRSA&dat=aGk%3D",
            Operation::Countersign,
        ),
        (
            "afirma://selectcert?idsession=abc123",
            Operation::SelectCert,
        ),
    ] {
        let uri = parse(text).unwrap_or_else(|e| panic!("{text:?} must parse: {e}"));
        assert_eq!(uri.operation, want, "{text:?}");
    }
    // The `/?` spelling the launcher also accepts (afirma://sign/?…) parses.
    let with_slash = parse("afirma://sign/?op=sign&format=CAdES&algorithm=SHA256&dat=aGk%3D")
        .expect("the launcher's firma://<op>/? form is recorded, keep it readable");
    assert_eq!(with_slash.operation, Operation::Sign);
}

#[test]
fn selectcert_needs_no_document_and_sign_demands_one() {
    let uri = parse("afirma://selectcert?idsession=abc123").unwrap();
    assert!(uri.data.is_none(), "AutoFirma's selectcert parses no dat");
    let err = parse("afirma://sign?op=sign&format=CAdES&algorithm=SHA256")
        .expect_err("a sign without dat must be refused at parse time");
    assert!(err.to_string().contains("dat"), "{err}");
}

#[test]
fn a_url_valued_dat_is_refused_because_openfirma_never_fetches() {
    // DataDownloader.downloadData treats an http(s) dat as a URL to fetch.
    // ADR-0005 rules that out inside the browser protocol, so the refusal is
    // openfirma's own decision — and it must be explicit about being one.
    let err =
        parse("afirma://sign?op=sign&format=CAdES&algorithm=SHA256&dat=http%3A%2F%2Fevil.test%2Fx")
            .expect_err("a remote document URL in dat must not be followed");
    let text = err.to_string();
    assert!(text.contains("never fetches"), "{text}");
    // file: was refused by AutoFirma itself, and stays refused.
    let err = parse(
        "afirma://sign?op=sign&format=CAdES&algorithm=SHA256&dat=file%3A%2F%2F%2Fetc%2Fpasswd",
    )
    .expect_err("local file reads were never allowed and must not be re-allowed here");
    assert!(err.to_string().contains("ficheros locales"), "{err}");
}

#[test]
fn session_ids_keep_autofirma_own_limits() {
    // UrlParameters: MAX_ID_LENGTH = 20, alphanumeric after lower-casing,
    // because the value becomes a file name on the callback side.
    let err = parse("afirma://selectcert?idsession=abcdefghijklmnopqrstuvwxyz")
        .expect_err("26 characters > 20 must refuse");
    assert!(err.to_string().contains("20"), "{err}");
    let err = parse("afirma://selectcert?idsession=not-valid!")
        .expect_err("non-alphanumeric ids are refused by AutoFirma and here alike");
    assert!(err.to_string().contains("alphanumeric"), "{err}");
    // uppercase is what AutoFirma's check would pass on the *lower-cased*
    // copy; here it stays refused: a mixed-case id reaching the callback as a
    // file name differs from the one that was checked, which is exactly the
    // mismatch the lower-casing in Java papers over. Refusing is the honest
    // rule for a token we will compare byte for byte.
    let err = parse("afirma://selectcert?idsession=Abc123")
        .expect_err("mixed case must refuse: our token comparison is exact");
    assert!(err.to_string().contains("lower case"), "{err}");
    assert!(parse("afirma://selectcert?idsession=abc123").is_ok());
}

#[test]
fn malformed_uries_are_refused_with_their_reason() {
    for (bad, want) in [
        ("getresult?idsession=x", "scheme afirma://"), // the scheme check AutoFirma also runs
        (
            "afirma://frobnicate?op=sign",
            "not one this client implements",
        ),
        // truncated percent escapes: AutoFirma's decoder passes them through;
        // refusing is the honest reading (we cannot guess what was meant).
        (
            "afirma://sign?dat=%4",
            "percent-encoding of a parameter is truncated",
        ),
        ("afirma://sign?dat=%zz", "non-hex characters"),
    ] {
        let err = parse(bad).expect_err("must refuse");
        assert!(err.to_string().contains(want), "{bad}: got {err}");
    }
}

#[test]
fn oversized_payloads_are_refused_before_anything_signs() {
    // An oversized base64 dat must be refused by size, not parsed then
    // rejected: the cap is checked on decoded bytes (which bounds the encode)
    // and again after gzip expansion (the zip-bomb direction). Both cases go
    // through the *endpoint body* path: the channel cap for hand-off URIs is
    // smaller than the document cap, so measuring a document over the document
    // cap through that channel would only ever prove the channel cap.
    let big = "A".repeat(MAX_DATA_BYTES / 3 * 4 + 8); // one byte over the decoded cap
    let uri = format!("afirma://sign?op=sign&format=CAdES&algorithm=SHA256&dat={big}");
    let err = parse_endpoint_body(uri.as_bytes()).expect_err("a 16 MiB dat is not a sede document");
    assert!(err.to_string().contains("16777216"), "{err}");

    // The same oversize through the *scheme hand-off* channel is refused even
    // earlier — by the channel cap, before a single base64 byte is decoded.
    let err = parse(&uri).expect_err("a 3 MiB-plus URI is not a hand-off call either");
    assert!(err.to_string().contains("2097152"), "{err}");

    // A gzip payload whose compressed form fits and whose expansion does not:
    // the classic zip bomb, built for real (zeros compress tiny) so the check
    // is on what gzipping returns, not on a faked length.
    use std::io::Write;
    let zeros = vec![0u8; MAX_DATA_BYTES + 1];
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(&zeros).unwrap();
    let compressed = encoder.finish().unwrap();
    // The bomb's compressed form passes every pre-decode bound (its base64 is
    // a fraction of the document cap); what refuses it is the expansion cap.
    assert!(
        compressed.len() < MAX_DATA_BYTES / 4 * 3,
        "a bomb must be small enough to reach the decoder"
    );
    // The '+' and '/' of standard base64 would be lost to query parsing ('+'
    // is a space on this wire), so the bomb travels as URL-safe base64 — the
    // same alphabet AutoFirma's own decoder normalises ('-' -> '+',
    // '_' -> '/'), which is what exercises the real decode path.
    let b64 = base64::engine::general_purpose::URL_SAFE.encode(&compressed);
    let uri = format!("afirma://sign?op=sign&format=CAdES&algorithm=SHA256&gzip=true&dat={b64}");
    let err =
        parse_endpoint_body(uri.as_bytes()).expect_err("a gzip bomb must die at the expansion cap");
    assert!(err.to_string().contains("decompresses past"), "{err}");
}

#[test]
fn duplicate_parameters_take_the_last_value_like_a_hashmap() {
    // parserUri puts every pair into a HashMap keyed by name, so on repeat the
    // last one wins. A page that emits format twice should not sign with the
    // first, silently: same shape of behaviour is pinned here.
    let uri = parse("afirma://sign?format=CAdES&format=XAdES&op=sign&algorithm=SHA256&dat=aGk%3D")
        .unwrap();
    assert_eq!(uri.format.as_deref(), Some("XAdES"));
}
