//! Dispatching a parsed `afirma://` URI onto the same operations the CLI
//! exposes, and returning the result in AutoFirma's wire shape.
//!
//! The two response shapes are read off AutoFirma 1.9, not invented:
//!
//! - signing (`NativeSignDataProcessor.postProcess`, afirma-simple):
//!   `base64(signing certificate DER) + "|" + base64(signature)` — the comment
//!   there says the double base64 (cert as one field, signature as the next)
//!   is what the page splits on. `Base64.encode(x, true)` in AutoFirma is MIME
//!   base64 with a trailing newline, so the separator arrives after that
//!   newline; we keep the same shape.
//! - certificate selection (`ProtocolInvocationLauncherSelectCert`, line 234):
//!   the leaf certificate DER base64'd on its own, nothing else.
//! - errors (`ProtocolInvocationLauncherErrorManager.getErrorMessage`): the
//!   new-protocol form `err-00:=AF<code> - <description>`, the cancellation
//!   form `err-11:=AF<code> - ...`, and the old form for callers that never
//!   announced a protocol version. We emit the new form with our own numeric
//!   codes named in this file, because nothing outside openfirma assigns us
//!   codes — AutoFirma's table is its own error catalogue, not a standard.

use std::path::Path;

use base64::Engine;

use openfirma_core::alg::DigestAlg;
use openfirma_core::cert::CertificateHandle;
use openfirma_core::signer::{Signer, SoftwareSigner};
use openfirma_keystore::Pkcs12;

use crate::uri::{AfirmaUri, Operation};

/// The separator AutoFirma's `NativeSignDataProcessor` uses between the base64
/// certificate and the base64 signature in one sign response.
const RESULT_SEPARATOR: char = '|';

/// How the result leaves this process. The scheme call itself cannot carry a
/// return value to the page (a browser hand-off to an external handler has no
/// reply channel), so AutoFirma's pages always read the result from somewhere
/// else: its loopback endpoint, or the government intermediate server. This
/// client answers the loopback connection it is serving (`serve.rs`); the
/// intermediate-server callback is refused at parse time — see `uri.rs` and
/// docs/adr/0005-browser-protocol.md.
///
/// The result of one browser-protocol operation, in wire form already so the
/// loopback server and the CLI emit byte-identical answers.
pub struct BrowserResult {
    /// `base64(cert)|base64(signature)` or plain `base64(cert)`, AutoFirma's
    /// shapes; never an error string (errors come back as `Err`).
    pub payload: Vec<u8>,
    /// What was produced, for the CLI to report and tests to assert on.
    pub kind: ResultKind,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ResultKind {
    Signature { format: String },
    CertificateSelected,
}

/// Everything a browser call needs that the URI does not carry: the key.
/// AutoFirma opens its keystore dialog at this point of the flow; openfirma
/// names the keystore up front, exactly like `sign --p12/--store` does, and a
/// headless client has no dialog to fall back on.
pub enum KeySource<'a> {
    P12 { path: &'a Path, password: &'a str },
}

/// Errors that stop an operation before it produces bytes. The loopback server
/// turns these into the `err-00:=...` text AutoFirma's pages parse; the CLI
/// prints them with exit status 1.
#[derive(Debug)]
pub struct BrowserError {
    /// Machine-readable reason, part of what the page sees after `AF`.
    pub code: &'static str,
    pub message: String,
}

impl std::fmt::Display for BrowserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for BrowserError {}

impl BrowserError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        BrowserError {
            code,
            message: message.into(),
        }
    }

    /// The AutoFirma error wire form (`err-00:=AF<code> - <description>`),
    /// with openfirma's own codes. Numbers are assigned here and documented;
    /// they mean nothing to anyone but us, and inventing AutoFirma's numbers
    /// would be worse than admitting ours.
    pub fn wire(&self) -> String {
        format!("err-00:=AF{} - {}", self.code, self.message)
    }
}

/// Runs one parsed URI to completion. `key` is where the signing key lives;
/// the document always comes from the URI itself (or nowhere, for selectcert).
/// Execute a browser call handed over in URI text (the scheme channel).
pub fn handle_uri_text(uri: &str, key: &KeySource<'_>) -> Result<BrowserResult, BrowserError> {
    execute(&crate::uri::parse(uri)?, key)
}

/// Execute a browser call delivered as one loopback endpoint body. The body
/// never travelled through a URI hand-off, so the channel cap does not apply
/// to it — only the document-size caps do.
pub fn handle_endpoint_body(
    body: &[u8],
    key: &KeySource<'_>,
) -> Result<BrowserResult, BrowserError> {
    execute(&crate::uri::parse_endpoint_body(body)?, key)
}

impl From<crate::uri::UriError> for BrowserError {
    fn from(e: crate::uri::UriError) -> Self {
        // A URI that cannot be parsed is a malformed call on the wire; through
        // the endpoint it still arrives over a valid, authenticated request, so
        // like every other operation failure it answers with the err wire form.
        Self::new("malformed-uri", e.to_string())
    }
}

pub fn execute(uri: &AfirmaUri, key: &KeySource<'_>) -> Result<BrowserResult, BrowserError> {
    let signer = load_signer(key)?;
    match uri.operation {
        Operation::SelectCert => Ok(BrowserResult {
            payload: base64_mime(signer.certificate().der()),
            kind: ResultKind::CertificateSelected,
        }),
        op => sign_from_uri(uri, &*signer, op),
    }
}

fn load_signer(key: &KeySource<'_>) -> Result<Box<dyn Signer>, BrowserError> {
    match key {
        KeySource::P12 { path, password } => {
            let bytes = std::fs::read(path).map_err(|e| {
                BrowserError::new(
                    "keystore-unreadable",
                    format!("cannot read {}: {e}", path.display()),
                )
            })?;
            let container = Pkcs12::load(&bytes, password).map_err(|e| {
                BrowserError::new(
                    "keystore-error",
                    format!("{} is not a readable PKCS#12: {e}", path.display()),
                )
            })?;
            let entry = container
                .entry(None)
                .map_err(|e| BrowserError::new("keystore-ambiguous", e.to_string()))?;
            let leaf = CertificateHandle::from_der(&entry.chain[0]).map_err(|e| {
                BrowserError::new(
                    "keystore-error",
                    format!("the PKCS#12 leaf is not a valid certificate: {e}"),
                )
            })?;
            let mut chain = Vec::with_capacity(entry.chain.len().saturating_sub(1));
            for der in &entry.chain[1..] {
                chain.push(
                    CertificateHandle::from_der(der)
                        .map_err(|e| BrowserError::new("keystore-error", e.to_string()))?,
                );
            }
            let signer =
                SoftwareSigner::from_pkcs8_der(leaf.der(), &entry.key_pkcs8).map_err(|e| {
                    BrowserError::new(
                        "keystore-error",
                        format!("the PKCS#12 key does not match its certificate: {e}"),
                    )
                })?;
            Ok(Box::new(signer.with_chain(chain)))
        }
    }
}

/// The format strings AutoFirma's launcher maps to real signers, and the four
/// this client can actually produce (`afirma-core`'s AOSignConstants list is
/// longer: trifásica forms and ASiC-S ship with servlet trips openfirma does
/// not have). Unknown formats are refused by name — AutoFirma's own behaviour
/// when its signer map misses.
fn resolve_format(text: &str) -> Result<Format, BrowserError> {
    // A sede sends "CAdES" (AutoFirma's spelling), and a client testing this
    // seam — or copying the format out of `--help` — may well send the shared
    // table's own id. Both spellings are one format: matching accepts both,
    // so the wire list and `crate::signing::all_formats()` cannot drift apart.
    let head = text.split('-').next().unwrap_or(text);
    if text.eq_ignore_ascii_case("auto") || head.eq_ignore_ascii_case("CAdES") {
        return Ok(Format::Cades);
    }
    if head.eq_ignore_ascii_case("PAdES") {
        return Ok(Format::Pades);
    }
    if head.eq_ignore_ascii_case("XAdES") {
        return Ok(Format::Xades);
    }
    Err(BrowserError::new(
        "unsupported-format",
        format!(
            "the format {text:?} cannot be served: openfirma produces CAdES, PAdES and XAdES \
             through the browser protocol (format=auto picks CAdES, as AutoFirma's does for a \
             file); the trifásica and ASiC-S formats need their server-side partners"
        ),
    ))
}

#[derive(Clone, Copy)]
enum Format {
    Cades,
    Pades,
    Xades,
}

/// The request the protocol builds for one format name — the exact front door
/// both `execute` paths walk through, so a sede's format= text and the shared
/// table can never again mean different signatures (finding M-4). This is what
/// every browser signing call goes through: dispatch resolves the wire name
/// here, fills in the digest parameter, and hands the request to
/// `crate::signing`.
pub fn protocol_request_for(
    text: &str,
    digest: openfirma_core::alg::DigestAlg,
) -> Result<crate::signing::SignRequest<'static>, BrowserError> {
    let mut req = protocol_request_for_format(resolve_format(text)?);
    req.digest = digest;
    Ok(req)
}

fn protocol_request_for_format(format: Format) -> crate::signing::SignRequest<'static> {
    crate::signing::SignRequest::new(
        match format {
            Format::Cades => "cades-b-b",
            Format::Pades => "pades-b-b",
            Format::Xades => "xades-b-b",
        },
        // The digest is the protocol's other parameter; the request starts at
        // the shared default and resolve_algorithm overwrites it.
        openfirma_core::alg::DigestAlg::Sha256,
    )
}

/// The `algorithm` list of AutoFirma's protocol (`UrlParametersToSign`:
/// SHA1/256/384/512 and their withRSA / withECDSA spellings). The digest is
/// what matters to us; the key half must agree with the loaded certificate,
/// which the signer's own algorithm selection then does or refuses.
fn resolve_algorithm(text: &str) -> Result<DigestAlg, BrowserError> {
    let head = text.split("with").next().unwrap_or(text);
    match head.to_ascii_uppercase().as_str() {
        "SHA1" => Ok(DigestAlg::Sha1),
        // AutoFirma accepts SHA224 nowhere in the protocol list, so its own
        // table is the boundary here too.
        "SHA256" => Ok(DigestAlg::Sha256),
        "SHA384" => Ok(DigestAlg::Sha384),
        "SHA512" => Ok(DigestAlg::Sha512),
        _ => Err(BrowserError::new(
            "unsupported-algorithm",
            format!(
                "the algorithm {text:?} is not one AutoFirma's protocol lists (SHA1/SHA256/\
                 SHA384/SHA512, bare or withRSA/withECDSA)"
            ),
        )),
    }
}

fn sign_from_uri(
    uri: &AfirmaUri,
    signer: &dyn Signer,
    op: Operation,
) -> Result<BrowserResult, BrowserError> {
    // cosign and countersign both need an already-signed document to work on;
    // openfirma has no co-signature or counter-signature function yet (a plain
    // `sign` call produces a single SignerInfo over the content, which is not
    // the same operation), and there is no golden proof for what a sede's page
    // expects back from either, so they are named and refused rather than
    // guessed at.
    if op != Operation::Sign {
        return Err(BrowserError::new(
            "unsupported-operation",
            format!(
                "{} over the browser protocol needs its own golden first: openfirma signs but \
                 does not yet co-sign or counter-sign through a browser call, see \
                 docs/adr/0005-browser-protocol.md",
                op.name()
            ),
        ));
    }
    let content = uri.data.as_deref().ok_or_else(|| {
        BrowserError::new("missing-data", "a sign call arrived without a dat payload")
    })?;
    // AutoFirma requires both parameters (setSignParameters throws on each
    // miss), so the refusal here is its own behaviour, not ours.
    let format_text = uri.format.as_deref().ok_or_else(|| {
        BrowserError::new(
            "format-missing",
            "no format parameter: AutoFirma's protocol requires one and so does this client",
        )
    })?;
    let algo_text = uri.algorithm.as_deref().ok_or_else(|| {
        BrowserError::new(
            "algorithm-missing",
            "no algorithm parameter: AutoFirma's protocol requires one and so does this client",
        )
    })?;
    let format = resolve_format(format_text)?;
    let digest = resolve_algorithm(algo_text)?;

    // A call against a certificate whose key cannot use that digest is refused
    // the same way `sign` refuses it (SignatureAlg::for_key).
    signer.signature_alg(digest).map_err(|e| {
        BrowserError::new(
            "algorithm-mismatch",
            format!("the algorithm {algo_text:?} does not fit this certificate: {e}"),
        )
    })?;

    // The browser protocol is one more frontend over the ONE dispatcher
    // (finding M-4): a sede's format= names the shared shape, and everything
    // else — options, refusals, label table — is `crate::signing`'s.
    let mut req = protocol_request_for(format_text, digest)?;
    // AutoFirma's default is explicit, which for it means the content stays
    // outside — the same measured default as the CLI. The protocol carries no
    // more knobs than this; see docs/adr/0005.
    let produced: Vec<u8> =
        crate::signing::execute_with_detection(&mut req, content, signer).map_err(map_core)?;

    Ok(BrowserResult {
        payload: sign_response(signer.certificate(), &produced),
        kind: ResultKind::Signature {
            format: match format {
                Format::Cades => "CAdES".to_string(),
                Format::Pades => "PAdES".to_string(),
                Format::Xades => "XAdES".to_string(),
            },
        },
    })
}

fn map_core(e: openfirma_core::Error) -> BrowserError {
    BrowserError::new("signing-error", e.to_string())
}

/// AutoFirma's sign response: `base64(certificate) | base64(signature)`, MIME
/// base64 with the trailing newline its `Base64.encode(x, true)` adds after
/// each field. The pages split on the separator; our fake-sede tests assert it.
pub fn sign_response(cert: &CertificateHandle, signature: &[u8]) -> Vec<u8> {
    let mut out = base64_mime(cert.der());
    out.push(RESULT_SEPARATOR as u8);
    out.extend_from_slice(&base64_mime(signature));
    out
}

/// `Base64.encode(_, true)` in AutoFirma is MIME base64, and RFC 2045 says its
/// lines end in CRLF (Java's mime encoder uses `\r\n`; the shipped jar's own
/// protocol round-trips prove it: `new String(Base64.decode(resp.split("\\|")[0]))`
/// must parse our field one). We encode with those terminators and document
/// that AutoFirma's *non*-mime strict decoder (used for `dat`) tolerates bare
/// `\n` as well, so both shapes survive either direction.
pub fn base64_mime(bytes: &[u8]) -> Vec<u8> {
    let engine = base64::engine::general_purpose::STANDARD;
    let text = engine.encode(bytes);
    // MIME line wrapping: 76 characters per line, CRLF, one final CRLF.
    let mut out = Vec::with_capacity(text.len() + (text.len() / 76 + 1) * 2);
    for chunk in text.as_bytes().chunks(76) {
        out.extend_from_slice(chunk);
        out.extend_from_slice(b"\r\n");
    }
    out
}
