# ADR-0005: the browser protocol speaks AutoFirma's wire, over plain HTTP on loopback — TLS stays out until a pure-Rust stack can carry it honestly

Date: 2026-10-16
Status: accepted

## Context

A sede electrónica signs documents in the browser by talking to a program on
the user's machine. AutoFirma 1.9 is that program, and its protocol was read
off the shipped sources (`/tmp/opencode/autofirma-src`, AF 1.7.0+ sources that
match the 1.9 wire behaviour) rather than guessed:

1. **Scheme hand-off.** The page navigates to `afirma://<operation>?…`
   (`ProtocolInvocationUriParser.parserUri`). The *host* part of the URI is the
   operation — `sign`, `cosign`, `countersign`, `selectcert`, `save`,
   `signandsave`, `batch`, `websocket`, `service`. Parameters ride in the
   query: `dat`, `format`, `algorithm`, `idsession`, `gzip`, `rtservlet`,
   `stservlet`, `key`, `cipher`, `fileid`, `properties`, `mcv`. The scheme
   itself has no reply channel; results leave through another mechanism.
2. **The websocket mechanism.** `afirma://websocket?ports=…&v=4&jvc=…&idsession=…`
   (`ProtocolInvocationLauncherWebSocketV4`) makes AutoFirma start a **wss**
   server on 127.0.0.1 at page-chosen ports in 49152–65535 (up to three,
   tried in random order). The TLS material is a self-signed PKCS#12 generated
   on the fly (`SecureSocketUtils.java:22-24`: hardcoded password `654321`),
   which the page's websocket client accepts by pinning — no CA, no hostname,
   nothing verifiable. Authentication of each message is: peer IP equals
   127.0.0.1 and a session id (`idsession`) previously announced. The probe
   contract is `echo=` → `OK`; a sign answer is
   `base64(cert)|base64(signature)` (`NativeSignDataProcessor.postProcess`);
   `selectcert` answers plain base64 of the leaf DER
   (`ProtocolInvocationLauncherSelectCert.java:234`); errors ride a healthy
   socket as `err-00:=AF<code> - <desc>` and cancellations as `err-11:=`.

Real sedes' autoscript.js opens `wss://127.0.0.1:<port>`, so the TLS leg is
not decoration for them — but what it protects is only wire confidentiality
on the loopback interface, because everything that authenticates a message is
the IP check and the session id on top of it. A browser page can make the
user's machine connect to any port; any local process can connect to any
loopback port. The attack model for *our* endpoint must assume both.

The project rule (README, ADR-0001) is pure Rust: no C crypto, and by the
same reading no vendored TLS stack pretending to be one. rustls depends on
`ring` or `aws-lc-rs`, both native; adding it would break that rule silently.

## Decision

1. openfirma implements the **URI parsing and dispatch** of the scheme
   exactly (crate `openfirma-browser`, `uri.rs`/`dispatch.rs`) with the three
   measured response shapes above, and refuses at parse time what it cannot
   prove (`cosign`/`countersign` — no golden evidence of the wire a page
   expects; `rtservlet`/`stservlet` callbacks — openfirma does not post
   results to remote servers; URL-valued or `file:`-valued `dat`).
2. The **loopback endpoint** (`serve.rs`) is plain HTTP on 127.0.0.1, not wss:
   `POST /sign/<token>` (body = one afirma:// URI, the message form AutoFirma's
   socket accepts; a JSON object with that URI under `"message"` is also read),
   `POST /echo` → `OK`, ephemeral port learned out of
   band, plus the mitigations below. A real sede pointing its autoscript at it
   will fail the TLS handshake — this endpoint is for openfirma's own pages,
   tests, and integrations that opt in explicitly; §Reasons states exactly
   what a real sede still needs.
3. Scheme registration ships as **generated fragments plus instructions**
   (`scheme.rs`: a `.desktop` file + `xdg-mime` command on Linux, a `.reg`
   file on Windows, a `.plist` fragment + `swiftdefault`/manual import on
   macOS); openfirma never edits a system registration by itself.
4. TLS is revisited **when** either (a) a pure-Rust TLS stack without native
   crypto lands (e.g. rustls on a pure-Rust feature, or `fussel`-class
   stacks mature enough to trust), or (b) the deployment requires answering a
   real sede's `wss://` client — in which case the cert must still be
   generated per session, but the pinning model of AutoFirma is what has to
   be reproduced, not improved on. Until then this ADR records the gap
   instead of papering over it.

## Mitigations implemented (serve.rs)

The threat: any local process, and any page the browser visits, can reach a
loopback port. What stops an uninvited caller here:

- **One-time token in the path.** Each launch mints a 128-bit token
  (`token.rs`, getrandom); it is consumed by its first request (`take`). A
  page that guesses the port still has to guess the token, and cannot replay
  it into a second operation.
- **Strict Host and Origin.** `Host` must be exactly `127.0.0.1:<port>` or
  `localhost:<port>` (defeats DNS rebinding: a rebound domain names itself in
  Host). Any `Origin` header must equal the endpoint's own origin; its absence
  is tolerated only because curl and tests send none — browsers always send
  it, so every cross-site fetch is refused by name (`bad-origin`, 403).
- **POST-only.** GET/HEAD/OPTIONS answer 405 with no `Access-Control-Allow-*`
  anywhere (`post-only`); a form navigation or `<img>` from another site
  cannot even reach the operation path, and the CORS preflight is refused.
- **Body shape enforced.** `Transfer-Encoding` is refused outright
  (chunked bodies have no cap before arriving); `Content-Length` is required,
  finite, exact; declared bodies over 8 MiB are refused before being read
  (413 from the header alone); more bytes than declared is a refusal
  (`content-length-mismatch`) so request smuggling cannot ride a connection.
- **Caps in three levels**: socket body 8 MiB, hand-off URI channel 2 MiB,
  decoded document 16 MiB (checked on base64 *character counts* before
  decoding, and again bounded during gzip expansion so a bomb is refused at
  limit+1 rather than inflated).
- **Operation failures are not transport failures.** A valid request whose
  operation fails answers 200 with AutoFirma's `err-00:=…` wire text and an
  `X-Openfirma-Reason` header — the same split a healthy AutoFirma socket
  makes, so no page can be tricked into reading a refusal as a signing error
  of *its* document.
- Process limits: ≤16 concurrent connections (refused with 503 past that, and
  refused *while* at capacity — the endpoint never shuts itself down because a
  crowd was knocking), an absolute request budget of 30 s per connection plus
  a 5 s silence window per read — bytes received renew the silence window, so
  the defence cuts peers that stop talking and never a caller whose bytes keep
  arriving on a loaded machine (no slowloris-by-idleness: Linux reports a
  socket read timeout as `WouldBlock`, so the limit cannot be delegated to the
  platform's error kind), bind refuses any non-loopback address. The token is
  consumed only when a complete request has arrived, so a client that dies
  mid-request costs the session a refusal, not its only signing opportunity.
  *(Amended 2026-10-16 after the adversarial review, finding M-2: the previous
  text's "30 s per connection" and an implied request-count shutdown were not
  what the code did — the timeout never fired on Linux and the accept loop
  died at 17 bare connections. The ADR always stated the intended promise;
  the code now enforces it, and the shutdown-by-request-count is replaced by
  the concurrency refusal because killing a launch's endpoint from unauthenticated
  empty connects served no threat model this ADR has.)*

## Reasons

- **Plain HTTP instead of wss, and why it is not weaker than AutoFirma's
  TLS on this threat model.** The loopback interface is not a network an
  off-machine attacker can sniff; what attacks exist here are *other code on
  the machine* — a page's script or a local process — and neither is stopped
  by TLS: AutoFirma accepts its own self-signed cert from any connecting peer
  whose IP is 127.0.0.1, so a malicious local process gets the same channel
  TLS "protects". Our token + Host/Origin + POST-only rules are strictly
  stronger authentication of *who may ask*, which is what actually matters;
  confidentiality on loopback buys little against the only reachable enemies.
- **No fake TLS.** Wrapping plain HTTP in a self-signed rustls-with-native-crypto
  handshake would copy AutoFirma's theatre while breaking the project's pure
  Rust rule, so it is the worst of both options and explicitly rejected.
- **HTTP/1.x subset by hand, not a crate.** axum/hyper are pure Rust and
  allowed, but an HTTP server that must refuse malformed requests *by named
  reason* is where their abstractions hide the refusals; ~400 lines of
  read-parse-refuse with tests naming each attack beat that. (Revisit if an
  HTTP/1.1 keep-alive or pipelining requirement ever appears — there is none:
  one request per connection, no keep-alive.)
- **cosign/countersign refused despite parsing them.** AutoFirma implements
  them through UI dialogs whose result wire we could read but never see a
  sede consume; inventing a response shape would make openfirma *look*
  compatible while being wrong in production. A refusal that names itself is
  honest; a guessed payload is worse than no implementation (ADR-0001's rule).
- **rtservlet/stservlet refused when the operation needs them.** Fetching or
  posting to government intermediate servers would make openfirma a client of
  infrastructure whose contract we have not measured, and gives a page's URI
  a server-side request forgery lever through our process. The recorded URIs
  that carry `stservlet` alongside `dat` still parse (the parameter is simply
  unused) because real sedes send both.

## Consequences

- openfirma answers its own pages and test sedes end-to-end today, with
  refusals that name themselves; the recorded-autofirma golden suite stays
  green because both sides run through one parser (ADR-0001 method).
- A production deployment against a *real* sede still needs the TLS leg per
  §Decision 4 — until then, `docs/validation.md` labels browser integration
  as protocol-complete but transport-partial, and README says so.
- The hardcoded port range (49152–65535), ephemeral bind and one-time token
  mean an sede that *caches* an openfirma endpoint across launches will get
  `bad-token` — by design; each launch is a new session, exactly as AutoFirma
  treats each `afirma://websocket` invocation.
