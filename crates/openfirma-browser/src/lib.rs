//! The browser protocol of openfirma: how a sede electronica's web page reaches
//! the signing client on the user's machine, and what comes back.
//!
//! AutoFirma offers its pages two mechanisms, both measured here from the 1.9
//! source clone before a single line below was written:
//!
//! 1. **The `afirma://` URI scheme** ([`uri`] + [`dispatch`]). The page hands
//!    the browser an `afirma://<operation>?<query>` URL; the OS launches the
//!    registered handler with it (the installer's `.desktop` / registry entries,
//!    which openfirma reproduces in [`scheme`]). The operation travels as the
//!    host part of the URI, the payload in query parameters — all recorded in
//!    `tests/uri_parse.rs` against literal URIs from AutoFirma's own test suite.
//!    A scheme call has no reply channel to the page: whatever returns must
//!    reach the page through a side channel openfirma does not own (AutoFirma's
//!    old flow posts it to a government intermediate server named in the URI).
//! 2. **The loopback endpoint** ([`serve`]). The page first launches
//!    `afirma://websocket?ports=…&idsession=…`, AutoFirma opens a TLS WebSocket
//!    (`wss://127.0.0.1:<port>`) on one of the ports *the page chose*, and every
//!    subsequent operation is the full `afirma://` URI posted as a WebSocket
//!    message over that socket, authenticated by nothing more than the peer IP
//!    being 127.0.0.1 and the `idsession=` string the page itself minted. The
//!    certificate behind that wss endpoint is a shipped self-signed PKCS#12
//!    (`autofirma.pfx`, password hardcoded in `SecureSocketUtils`) that no CA
//!    vouches for; browsers accept it because WebSocket TLS failures are silent.
//!
//! openfirma implements the protocol without the fake half of the transport:
//! plain HTTP on loopback behind an ephemeral port, a one-time token, strict
//! Host/Origin checks and POST-only writes — the mitigations and their exact
//! limits, including when TLS becomes worth revisiting, are [`docs/adr/0005`]
//! ('docs/adr/0005-browser-protocol.md' in the repository), which is a part of
//! this crate's contract, not commentary.

pub mod dispatch;
pub mod scheme;
pub mod serve;
pub mod token;
pub mod uri;
