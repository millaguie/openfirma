# ADR-0005 — The browser protocol (afirma://) and its loopback endpoint

**Status:** accepted, amended 2026-10-17 by wave 4d's review findings (C-1, A-1..A-5, M-1..M-9, B-1..B-6 from `/tmp/review/05-browser.md`), and again 2026-10-19 by round two's browser findings (04-N1: `--register` asks the OS who holds the scheme now; 04-N3: the endpoint takes its standing consent from the config file; 04-N5: the config stores paths the handler can find; 04-N7: `--unregister` removes its own association line; 04-N9: `dat=` is refused; 04-N10: the desktop entry escapes for the file and for `Exec`; 04-N6: this file no longer promises a tty prompt an argv key never gets; 04-N8: a refusal for want of consent travels as the cancellation pair, not as "operation not supported"; B-4, B-6 and M-7: the head parser refuses what it cannot honour, the token's entropy is written as what it is, and the wss transport's premise is the corrected one). Every rule below is recorded line-by-line against the AutoFirma 1.9.1 sources (`tools/fetch-autofirma.sh`, corpus location in `docs/validation.md`).

## Context

A sede electrónica's page cannot talk to a local process through a socket of
its own making: browsers only hand an `afirma://…` URI to a registered OS
handler, and AutoFirma answers the page from there through a loopback endpoint
it listens on. openfirma replaces that client, so it has to be byte-compatible
with what millions of sedes' pages (`autoscript.js`) already send, with the
wire forms those pages parse, and with the security properties AutoFirma's
users actually get — nothing may be silently weaker than the original even
where the original is only convention.

## Decision

### The URI parser mirrors `ProtocolInvocationUriParser` / `UrlParameters*`

Operation from the host part; parameters per AutoFirma's own tables (`id`/
`idsession`, `v`/`ver`/`mcv`, `dat`, `gzip`, `format`, `algorithm`, `appname`,
`properties`, `rtservlet`/`stservlet`). Percent-decoding once, like Java's
URLDecoder. The bounds that exist (URI bytes, decoded document, session-id
length 20 after lower-casing) are AutoFirma's own.

**A-5.** `checkIdSession` tests `id.toLowerCase().matches("([a-z0-9])+")`:
the *test* is case-folded, the *value* keeps its case (`setSessionId(sessionId)`
takes the original). Mixed-case ids parse and stay verbatim — a follow-up
matching against them is byte-exact. Refusals carry AutoFirma's own pair for
a bad session: AF620010 / SAF_46 (`INVALID_SESSION_ID`).

**Percent escapes.** A `%` escape at the very end of a value (a padded base64
ending `%3D%3D`, exactly what `encodeURIComponent` produces) is legal; an
early off-by-one in the truncation test refused precisely those URIs. Pinned
by `uri_parse`'s recorded-shape tests and by A-4's full round trip below.

### The wire forms of answers — findings M-1, M-2, M-3

* **M-1 (sign/selectcert payload).** `Base64.encode(x, true)` in the shipped
  jar is URL-safe alphabet, `=` padding, a single line (measured: 200 bytes →
  268 chars). The payload is `base64url(cert)|base64url(signature)` and every
  page-side consumer folds `-`/`_` back (`processSignResponse`, recorded at
  autoscript.js's own lines); `dispatch::base64_url` is the single door, and
  both fake_sede and sede_crosscheck pin the fold round trip with recorded
  literals.

* **M-2 (error wire).** One door in serve.rs (`write_error_wire`) answers every
  refusal: protocol ≥ 4.1 → `err-00:=AF<code> - <descripción>` (cancellations
  `err-11:=`), below it or on a broken version → the legacy `SAF_xx: <mensaje>`
  table (`CANCEL` alone for cancellations). The description strings are AutoFirma's
  own Spanish catalogue texts (`getErrorMessage` quotes `getDescription()`);
  the legacy form quotes the ERRORS-table message, not the catalogue. Every
  AF↔SAF pairing is line-recorded from `ProtocolInvocationLauncherErrorManager`
  (`OLD_ERRORS_ASSOCIATION`, lines ~40–290): CANCELLED 500001/CANCEL, URI_NOT_FOUND
  620012/SAF_01, UNSUPPORTED_SCHEME 620009/SAF_02, UNSUPPORTED_OPERATION
  600002/SAF_04, INVALID_SESSION_ID 620010/SAF_46, MALFORMED_SOCKET_PARAMS
  620016/SAF_03, DATA_NOT_FOUND 600100/SAF_03, UNSUPPORTED_FORMAT 600105/SAF_06,
  UNSUPPORTED_ALGORITHM 600107/SAF_03, INVALID_SIGNING_KEY 200110/SAF_51,
  SIGNING_FAILED 200115/**SAF_03** (the unlisted-codes group — an earlier draft
  said SAF_09, the recorded table does not), SELECT_CERT_FAILED 200201/SAF_03,
  KEYSTORE_ERROR 201101/SAF_08, DATA_LOAD_FAILED **200600**/SAF_00,
  UNSUPPORTED_HASH_ALGORITHM 200118/SAF_53 (the fallback group),
  UNSUPPORTED_PROTOCOL_VERSION 620011/SAF_21.

  The page reads these bodies through a recorded predicate (autoscript.js
  2642-2659): after `:=` the body must carry `" - "` at index **8** and start
  with `AF` + six digits. `tests/autoscript_wire.rs` re-implements that
  predicate verbatim and runs every catalogue entry through it — no test here
  agrees with itself about what an error looks like, it agrees with the page.

* **Deliberate deviation — a URI without any `ver`/`v`.** AutoFirma's launcher
  treats a missing version as VERSION_0 (the legacy wire). openfirma answers
  such a call on the MODERN form: no recorded sede omits the parameter (every
  recorded invocation carries one), and answering an unknown caller with the
  oldest form would hide exactly the catalogue page-side consumers already
  parse. Pinned by `wire_target` tests; a deliberate, visible choice, not an
  oversight.

* **B-6.** The endpoint's reason header carries AutoFirma's catalogue number
  for the refusal (`dispatch::error_reason_header` → `e.wire.af_code`), so a
  log line, a curl run and the wire text a page parses quote one and the same
  number.

* **M-3 (formats).** The dispatcher accepts AutoFirma's format-name table and
  refuses by name everything it cannot produce identically (trifásica names,
  ASiC-S, CMS/PKCS#7, FacturaE, ODF/OOXML/SOAP, XAdES Detached/Enveloping).
  `auto` resolves on the bytes like AutoFirma's AUTO. The browser protocol runs
  through the SAME shared dispatcher as the CLI (M-4): one door for every
  frontend, no second signing policy living in serve.rs.

### `properties` is applied or refused by name — finding A-4

`AOUtil.base642Properties` + a Java-faithful `Properties.load`. The gate
(`execute_gate`) runs **before anything touches the keystore**: cosign/
countersign and the storage-servlet route refuse, then every `properties` key
is consulted against one closed table.

* `precalculatedHashAlgorithm` — implemented for CAdES: AutoFirma's
  `CAdESParameters.load` (lines 119–155) sets `dataDigest = data; contentData
  = null` and lets the property OVERRIDE the URI's digest algorithm. openfirma
  signs the payload verbatim as the CMS message imprint via
  `openfirma_cades::sign_with_digest` (whose length check locks the imprint to
  the named algorithm — a SHA-256-size hash can never ride a SHA-1 identifier),
  detached only (`contentData = null`; an imprint encapsulating bytes it did
  not compute is refused). `tests/prehash_golden.rs` proves both directions:
  openssl accepts the signature over the sede's hash bytes while the signed
  messageDigest equals the payload verbatim and NOT a re-hash of it (a raw DER
  walk, independent of openfirma's verifier); the no-property twin signs
  exactly one sha256 over the document; naming SHA-1 hits the workspace-wide
  conservative signing policy — proof the algorithm half was APPLIED at
  dispatch, which is precisely what a client ignoring the property cannot
  produce.

* `mode=explicit` passes (the protocol default already IS detached/explicit);
  every other value refuses. Unknown or unimplemented members (visiblePdfSignature
  and the PdfExtraParams geometry, signatureVersion, onlyRealSigners, policy*/
  filter*, serverUrl/presign/postsign) refuse by name with their key in the
  message — never a silent drop, because "could not load" must mean "nothing
  was asked", never "something was quietly ignored". An unreadable hash-algorithm
  name refuses too (AutoFirma's own getDigestAlgorithmName throws).

### Consent over the user's key — finding A-3

Nobody ever proves to a signing client that the human in front of the screen
asked for this signature; AutoFirma's answer is its certificate dialog + PIN at
exactly the moment of signing. openfirma keeps that invariant headlessly:

* `dispatch::execute_with_consent` is the door. A key arrives either as an
  explicit `P12` (somebody standing here said sign) or as an `UnattendedKey`.
  An unattended key signs only with its owner's per-key `allow_unattended`
  opt-in plus a stored password, or through a consent callback that answered
  yes; otherwise refusal, never silence. The refusal travels as AutoFirma's
  cancellation pair — 500001/CANCEL, `err-11:=` — because that is what its own
  dialog produces when it is dismissed: no signature, and a page that must not
  retry. It answered 600002/SAF_04 ("La operacion no esta soportada") until
  round two's 04-N8, which sent a sedes' users to look for an upgrade over a
  key that merely had no opt-in. The machine code (`consent-required`) and the
  message keep it apart from a user who actually answered no (`cancelled`), and
  the person at the desktop is told what happened through the notifier where
  one exists (04-N8; the CLI's `tell_the_user_about_the_refusal`).
* The CLI scheme path (`afirma-uri`) can prompt on a terminal (operation, app
  name, digest and size of the exact bytes) — AutoFirma's dialog, in text. The
  prompt belongs to the door that still has a question: a **config-file** key
  whose file says nothing (`allow_unattended` absent), where the human at the
  terminal is the authority the file withheld. A key handed over **argv**
  carries its own consent and never prompts, not even on a tty: the person who
  typed the command supplied the key and its secret, so the invocation IS the
  yes. (Review 04, N6 measured exactly that — a real tty, the prompt answered
  "n", and the call signed anyway; an earlier revision of this bullet claimed
  the opposite, "(and still prompts when a tty exists)".) A page cannot use
  that rule to launder its own key: the OS hands a scheme handler the URI and
  nothing else, so argv keys exist only where a human typed them. A
  **config-file** key without `allow_unattended = true` IN THE FILE never signs
  quietly — the file's own declaration is the only standing authority; a CLI
  flag alone cannot launder a config key.
* The endpoint (`afirma-serve`) refuses to start over an argv key without
  `--allow-unattended`, and over a config key whose file lacks
  `allow_unattended = true` (the flag alone is not enough — deliberate, the
  opt-in must belong to the key's owner, not to whoever restarted the server).

### Scheme registration — findings A-1, A-2, B-2

* The XDG desktop entry mirrors AutoFirma's registered shape:
  `Exec="<absolute path>" afirma-uri %u` — the PATH quoted (G_TOKEN_STRING
  escaping), `%u` OUTSIDE quotes (a quoting bug here was C-1's sibling: paths
  with spaces or hashes broke hand-off). No `\s`, no `Categories=Signature`.
* `--register` IS the registration (desktop file + `update-desktop-database`
  + `xdg-mime default openfirma-afirma.desktop x-scheme-handler/afirma`); it
  refuses when AutoFirma is installed unless `--acknowledge-autofirma` says
  the human knows ("no se instalan dos clientes a la vez" — two handlers fight
  for the scheme). It writes the browser config at 0600, and BOTH the config
  and the password file must be private (`check_private` refuses mode&0o077 ≠
  0) — B-2: key material is never world-readable. `--unregister` removes only
  what openfirma itself wrote. XDG_DATA_HOME is honored end to end.

### The loopback endpoint stays localhost-only and never posts

serve.rs binds 127.0.0.1 (refuses non-loopback before binding, and refuses the
IPv6 loopback `[::1]` by name — it is loopback, so the address check passed it,
but the Host/Origin rules below only know 127.0.0.1 and localhost and every
request that reached such a socket would have been a 403), validates Host and
Origin against rebinding (case-insensitively: a host name is one), and issues
one-shot tokens from a CSPRNG. The transport is HTTP/1.0 or HTTP/1.1 and nothing
else — `HTTP/1.9` is answered 505 rather than parsed as if this endpoint
implemented it — and it is deliberately WITHOUT keep-alive: one request per
connection, `Connection: close` on every answer, so an idle socket is never a
slowloris surface. Every handler still enforces an absolute deadline, and a peer
that stalls or dribbles is answered `599 Request Timeout` with the reason
`request-head-timeout` (599 rather than 408 because a head that never finished
has no method to refuse yet, and every refusal on that path would lose the
distinction); a port past `MAX_CONCURRENT_CONNECTIONS` answers `503` and keeps
accepting — a refusal, never a dead endpoint. A request carrying two
`Content-Length` fields is refused (400) instead of one of them being believed:
a recipient may do either under RFC 9112, and two lengths are how a smuggling
pair is built. **openfirma never POSTs to any server**: `stservlet`/
`rtservlet` URIs that need the intermediate-server route are refused by name
(M-5: signing without delivering is worse than not signing), and the answer
travels only over the connection the page itself opened.

**The honest gap (why wss is NOT here).** Current sedes speak to AutoFirma's
HTTPS/WebSocket endpoint (`AfirmaWebSocketServerV4Sup`, `wss://localhost:port/
servicios`). Both clients inside autoscript.js are TLS: the WebSocket one builds
`wss://127.0.0.1:<port>` and the older HTTPS one `https://127.0.0.1:<port>`
(corpus copy, `afirma-ui-miniapplet-deploy/src/main/webapp/js/autoscript.js`,
lines 2053 and 3006), so there is **no plain-HTTP branch for a page to take**.
The "plain-socket path in its compatibility branches" an earlier revision of
this ADR pointed at does not exist, and that revision overstated what runs
today: openfirma's endpoint (plain TCP + one-shot token in the URL path, above)
is a channel THIS project's callers speak — `fake_sede`, the crosscheck tools,
and `afirma-serve --issue-token` plus curl as the README shows — and no shipped
page builds that request. Said plainly: with `--register` run on a machine that
has AutoFirma installed, a real sede's page gets no answer from openfirma at
all; the scheme handler is what a person or a script invokes. Making wss work
requires (a) serving TLS with the CA AutoFirma's configurator generates —
`CN=Autofirma ROOT`, plus a `127.0.0.1` leaf (see M-7 below: NOT "silent
self-signed acceptance", Firefox gets the cert imported by the configurator),
and (b) shipping that CA into each browser's trust store, which is exactly the
installer behavior this project has not yet reviewed for its own security
properties. ADR-0005 therefore keeps the endpoint on plain TCP + one-shot
token, refuses nothing the plain channel can honestly answer, and names the wss
gap openly: a real sede that demands wss gets no answer from openfirma until an
ADR amends this section with a reviewed TLS design. This is a recorded
limitation, not an accident.

### M-7 — what AutoFirma actually does about TLS (correcting the old premise)

The previous revision of this ADR described AutoFirma as "silently accepting
its own self-signed certificate". The sources say otherwise: the configurator
generates a CA (`CN=Autofirma ROOT`) and a `127.0.0.1` leaf signed by it
(CertUtil / ConfiguratorFirefoxLinux), and IMPORTS the CA into the browser's
trust store, so the page's wss connection verifies normally. openfirma neither
does that today (gap above) nor trusts such certificates on verification paths:
its CMS verifier is unchanged. Correcting the premise changes no code; it
matters because a future TLS ADR must decide about exactly this installer step.

## Consequences

* `cargo test --workspace` pins all of the above, file by file: the crate's lib
  tests, `autoscript_wire` (recorded page predicates, the error parser and the
  session-id rules), `fake_sede` end-to-end (URL-safe shapes, wire texts,
  consent and the endpoint's own limits), `prehash_golden` (A-4 in both
  directions, plus gate ordering), `uri_parse` (recorded URIs, byte-exact),
  `format_auto` (the shape `auto` resolves to, read off the signed bytes),
  `empty_payload` (04-N9: `dat=` is not a document), `desktop_entry` (04-N10:
  GLib loads the entry a quoted path produces), and `sede_crosscheck` (openssl
  at the end of a full flow). Counts are deliberately not written here — the
  run's own result lines are the count, and the numbers in this bullet were
  stale within a wave. The golden suite stays 12/12 MATCH against AutoFirma's
  jar output.
* Any error path added later must go through `write_error_wire` with a table
  entry; autoscript_wire's predicate test fails if someone writes an error form
  the page cannot parse, so drifting is loud, not silent.
* cosign/countersign, the storage servlet, PAdES/XAdES pre-hash, visible PDF
  signatures and the trifásica flow remain refused-by-name with their wave in
  `DEFERRED.md` — each refusal names itself and this file.
