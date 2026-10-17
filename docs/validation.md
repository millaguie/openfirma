# Validation strategy

The acceptance criterion for this project is not "our tests pass". It is: a file
signed by openfirma is accepted by VALIDe, by the ETSI reference validators, by
Adobe Acrobat, and by the government portals, in the same way as a file signed
by AutoFirma.

Four layers, cheapest first.

## 1. Golden corpus, diffed structurally

The official AutoFirma 1.9 Linux package is the reference. `tools/fetch-autofirma.sh`
downloads and extracts it, and `tools/golden-diff.sh` signs a fixed set of
inputs with it through `tools/golden/AutofirmaGolden.java`, using the same test
certificate openfirma uses, then compares. Point it at a jar you already have
with `AUTOFIRMA_JAR=/path/to/autofirma.jar`. Nothing it writes is committed:
`testdata/golden/` is in `.gitignore`, so the corpus is always regenerated
against whatever AutoFirma version is on the machine.

The comparison is structural, not byte level. Raw bytes cannot match, because
the signing time and therefore the signature value differ on every run. What
must match:

- the set of signed attributes and their OIDs,
- the DER encoding of each attribute value,
- the digest algorithm identifiers and whether `parameters` is NULL or absent,
- the `version` of `SignedData` and of `SignerInfo`,
- the presence and ordering of `certificates` / `crls`,
- for PAdES: `/SubFilter`, `/Filter`, the shape of `/ByteRange`, the AcroForm
  field and its flags, which optional dictionary entries are absent, and the CMS
  inside `/Contents`. See `docs/pades.md` for the measured reference.
- for XAdES: the `SignedInfo` transforms and every algorithm URI, the
  `QualifyingProperties` layout down to the empty `IssuerSerialV2` and the
  namespace declarations each element carries, and which references baseline
  signs. See `docs/xades.md` for the measured reference.

For CAdES the normalizer is `openfirma inspect`, our own DER dumper, which is
safe to use as the oracle because it only walks TLV and understands no
signature format: it cannot be wrong in a way that favours our encoder.

For PAdES it is deliberately **not** our code. `tools/golden/pdf-normalize.py`
runs both sides through `qpdf --qdf --object-streams=disable` and reports the
result, because openfirma has its own PDF parser and a bug in it would then
appear on both sides of the diff and cancel out. qpdf is an independent
implementation, so it is the one that decompresses iText's object streams and
collapses revisions. The same script recomputes the digest over `/ByteRange`
and checks it against the CMS `messageDigest`, which is the property that
actually makes the file a signature.

There is **no golden for PAdES B-LT/B-LTA**: AutoFirma's default PAdES output
carries no `/DSS` — its enhancer, the mechanism that would add long-term
validation data, ships commented out in `enhancer.properties` — so there is
nothing to diff against and the long-term levels are proven by the verifiers
of layer 2 instead. See docs/pades.md.

For XAdES it is `tools/golden/xml-normalize.py`, again deliberately not our
code: openfirma has its own XML reader and its own canonicalizer, so the dump
is built with Python's `xml.etree` (expat), the reference digests are
recomputed with `lxml`'s C14N, and the `SignatureValue` is verified by
`xmlsec1` — three implementations that share nothing with ours. The volatile
values it neutralizes are exactly the four classes measured in `docs/xades.md`
(the uuids, `SigningTime`, and the two values that cover them); the data
reference digest, the certificate digest and the certificate bytes are kept
because they must match. Before the dumps are diffed, both files must pass
their own integrity check, so a MATCH means both sides are also internally
sound signatures.

This is the layer that catches most of the problems. It caught four real bugs
in the CAdES encoder that OpenSSL tolerated: a missing `SigningCertificateV2`
wrapper level, an unsorted `certificates` set, `sha256WithRSAEncryption` where
RFC 3370 requires `rsaEncryption`, and encapsulating content by default.

The CAdES cases the driver runs today, each one measuring a specific shape
against the jar rather than arguing about it:

| case | what it pins | finding |
|---|---|---|
| `simple` | advanced-profile defaults: detached, signingTime, V2 with issuerAndSerialNumber, contentHint "binary" | — |
| `sha1` | v1 `signingCertificate` for SHA-1 (the dump drives every mirrored knob), and the openfirma refusal unless `--allow-weak-algorithms` | M1, M5 |
| `ecdsa` | `SEQUENCE { OID ecdsa-withSHA256, NULL }` — BouncyCastle's parameters shape | B1 |
| `policies` | the certificate's certificatePolicies copied into ESSCertIDv2, flattened exactly as BouncyCastle encodes them (no wrapper tag) | M2 |
| `policy_commit` | signaturePolicyIdentifier with the sede's published sigPolicyHash (`AQI=` travels to both sides) and commitmentTypeIndication | M9 |
| `mime` | mime-type as UTF8String under 0.4.0.1733.2.1 | M3 |

The hint description in every case is read back from AutoFirma's own dump
rather than guessed, because its Spanish per-type descriptions come from a
jmimemagic database openfirma does not ship by design; the jar writes "binary"
on this driver's classpath and openfirma mirrors exactly that. The `mime`
case therefore also documents what is *not* diffed: AutoFirma's jmimemagic
probe attribute when MIME detection is on and no type was pinned. Every case
skips cleanly when the certificate it needs (`signer-policy`, `signer-ec`) is
not generated, and the whole set prints MATCH on a machine with the jar, the
test PKI and cargo built.

## 2. Independent verifiers in cargo test

Five independent implementations are wired into `cargo test`, each checking a
different property, and each skipped with a message when it is not installed:

- **OpenSSL** (`crates/openfirma-cades/tests/openssl_crosscheck.rs` and
  `crates/openfirma-pades/tests/openssl_crosscheck.rs`) verifies the CMS
  cryptographically: for PAdES it is handed exactly the bytes `/ByteRange`
  names, so a signature that verifies is a signature over the right bytes.
  It also catches malformed DER, wrong tags, bad lengths and broken `SET OF`
  ordering. For the long-term levels (`crates/openfirma-pades/tests/ltv.rs`)
  it additionally runs `openssl crl -verify -CAfile` on the CRLs *as embedded
  in the document* — with the negative control that the same CRL under the
  wrong CA's certificate must fail, so the check is known to bite — and
  `openssl ts -verify -token_in -data` on the document time-stamp token
  against exactly the bytes its own `/ByteRange` names.
- **poppler's `pdfsig`** verifies the PDF-level signature and reports whether
  it covers the whole document. It is a third implementation of the PAdES
  reading path, with its own ASN.1 and its own PDF parser, so agreement with
  it is strong evidence. It cannot trust the synthetic test chain, and saying
  "Certificate issuer isn't Trusted" is the correct answer there, so only the
  cryptographic verdict is asserted. Since B-LT/B-LTA it also proves the
  crucial non-regression property: on a co-signed document whose second
  signature carries the archive and the document time-stamp, every earlier
  signature must still come back "Signature is Valid" — adding long-term
  data must not invalidate what was already signed.
- **qpdf** checks the container: cross-reference offsets, object structure,
  stream lengths. A signature can be cryptographically perfect in a PDF that
  no reader can open, so this is checked separately.
- **xmlsec1** (`crates/openfirma-xades/tests/xmlsec_crosscheck.rs`) verifies
  the XAdES signatures with its own C14N 1.0 and the openssl backend: every
  `ds:Reference` digest and the `SignatureValue` over the canonicalized
  `SignedInfo`. It is the only independent verdict the ECDSA path gets,
  because AutoFirma headless cannot sign EC XAdES on this JVM
  (`docs/xades.md`, deviation 5), and a tampered document test proves the
  check bites.
- **AutoFirma's own validator**
  (`crates/openfirma-xades/tests/autofirma_verify.rs`) runs the official
  jar's `ValidateXMLSignature` — the validator behind the GUI's "validate
  signature" — against files openfirma signed, RSA and ECDSA, and against a
  tampered copy that must be refused. The jar comes from
  `tools/fetch-autofirma.sh` and is not a CI dependency, so this test skips
  with a message when java or the jar is absent, the same treatment qpdf
  gets; when the jar is present and the driver misbehaves, it fails.

The XAdES canonicalizer additionally runs against known-answer vectors hand
written from the examples of the C14N 1.0 specification
(`crates/openfirma-xades/tests/c14n_kat.rs`), every expected value
cross-checked against Apache Santuario and libxml2 while the crate was
written.

The browser endpoint's signing path gets the same independent treatment
(`crates/openfirma-browser/tests/sede_crosscheck.rs`): a fake sede POSTs a
recorded-style `afirma://sign?dat=…` URI to the real loopback server, and what
comes back — AutoFirma's `base64(cert)|base64(signature)` wire shape — is
split apart and verified by `openssl smime -verify -content` as a detached
CAdES signature over exactly the document that went in. So the endpoint is not
only shape-checked against the measured AutoFirma contract; its cryptographic
output is judged by an independent implementation too.

The protocol parsing itself (`crates/openfirma-browser/tests/uri_parse.rs`)
works from recorded `afirma://` URIs with the AutoFirma source line each form
comes from, and the attack surface has tests that assert refusal *by named
reason*: cross-site Origin, rebound Host, GET-as-CSRF, token replay, chunked
and oversized bodies (`crates/openfirma-browser/tests/fake_sede.rs`). The
threat model and why the transport is plain HTTP on loopback rather than the
self-signed wss AutoFirma uses is docs/adr/0005-browser-protocol.md.

Gotcha found while setting this up: **`openssl cms -verify -content` is broken
for detached signatures in 3.6.5**. It rejects detached CMS produced by openssl
itself with `CMS_SignerInfo_verify_content: verification failure`, even though
the `messageDigest` attribute matches the file exactly. `openssl smime -verify
-content` does the same job and works, so the detached tests go through
`smime`. Encapsulated signatures verify fine with `cms -verify`.

The GUI is tested at the same standard as far as a headless suite reaches:
`crates/openfirma-gui/tests/ui.rs` drives the *real* `App` under egui_kittest
(no display, AccessKit widget tree), and its end-to-end test signs through
the GUI's own code path and verifies the written file with
`openfirma_cades::verify`/`openfirma_pades::pades_verify` — the CLI's own
verifiers. What a headless suite cannot reach is the OS furniture (a real
file picker, drag-and-drop from a real desktop, closing a real window, the
glow renderer itself); those are the manual checklist of section 5 below.

For B-T, `crates/openfirma-cades/tests/tsp_crosscheck.rs` answers the RFC 3161
query with `openssl ts -reply` and a synthetic TSA certificate, so the token
embedded in our signature is one a real responder produced; openssl then
verifies that token against the signature value it imprints, and the test
refuses a token that imprints anything else. The same offline responder
mechanism drives the B-LTA document time-stamp in
`crates/openfirma-pades/tests/ltv.rs`, including the refusal of a token whose
imprint does not match the document.

For B-LT the test PKI itself provides the revocation data, generated by
`tools/gen-testcert.sh`: an empty CRL per CA (`openssl ca -gencrl` over a
minimal throwaway database — an empty CRL is a complete statement, it says
nothing that CA issued is revoked), and a **real OCSP response** produced
offline by `openssl ocsp` in one-shot responder mode (`-reqin`/`-respout`)
with a delegate responder certificate carrying the OCSPSigning EKU. The OCSP
material is the one optional piece: an openssl build that cannot answer a
request offline leaves it out and the affected test skips, because the CRL is
the mandatory, cryptographically checked revocation path.

What these prove today: RSA SHA-256 and SHA-512 plus ECDSA P-256, encapsulated
and detached, verify under OpenSSL with byte identical recovered content;
PAdES-B-B verifies under OpenSSL over the `/ByteRange` bytes, under poppler as
"Signature is Valid" and "Total document signed", and opens cleanly in qpdf;
PAdES B-LT/B-LTA documents carry a `/DSS` whose CRLs verify under openssl and
whose document time-stamp token verifies under `openssl ts` against exactly
the bytes its `/ByteRange` names, survive qpdf without a single warning, and
leave every earlier signature valid under pdfsig; and XAdES-B-B verifies under
xmlsec1 (all references plus the signature value, RSA and ECDSA) and under
AutoFirma's own validator. That covers the CMS
structure, the `SET OF` DER ordering, the `[0] IMPLICIT` retag rule for the
signed attributes, the `signingCertificateV2` encoding, the certificate
embedding, the PDF incremental update, and for XML the whole canonicalization
and reference machinery down to the namespace suppression rule inside
`SignedInfo`.

`openfirma verify` is the in-repo verifier, and now that it exists the OpenSSL
crosscheck also runs *against it*: `crates/openfirma-cades/tests/verify.rs`
asserts that openssl and our verifier reach the same verdict on a good and on
a tampered file. `verify` checks the `messageDigest` against the content, the
`signatureValue` over the signed attributes re-tagged as `SET OF`, the
`signingCertificateV2` reference against the embedded signer certificate, and
it builds the chain from the signer up to the trust anchors given on the
command line, verifying each link's signature with the issuer's public key and
every certificate's validity dates against a validation time (`--at`, default
now). It verifies *every* signature in a document, so a co-signed PDF passes
only when all of its signatures do. Since B-LT it also judges the archive:
when a PDF carries a `/DSS`, every archived certificate must parse, every
archived CRL must verify **under the key of the CA it names** and be current
at the validation time, every archived OCSP response must be a successful
answer, the chain of every `/VRI`-covered signature must rebuild from the
archived data alone with at least one revocation datum per CA certificate and
nothing in the chain revoked by the archived data, and every document
time-stamp token must imprint the bytes its own `/ByteRange` covers. What it
still does not do is everything that makes layers 3 and 4 necessary: no
certificate policy (key usage, basic constraints, qualification), no signature
policy, no OCSP response signature validation and no time-stamp token
signature validation (openssl does both in the crosscheck suite). A file that
passes `openfirma verify` is cryptographically sound and chains to an anchor
*you* chose; whether a regulator agrees is still a question for DSS and
VALIDe. And it shares the codebase with the encoder,
which is one more reason the independent readers above stay in the suite: a
bug in how openfirma reads ASN.1 could otherwise hide on both sides of the
verification.

On top of the cryptographic checks, `openfirma verify` refuses the shapes the
adversarial review produced against it (the two hardening waves, tests under
`crates/openfirma-pades/tests/`). The revisions gate classifies every object a
revision after a signature redefines against the whitelist of what an archive
may append (ETSI EN 319 142-1): new signature dictionaries, document
time-stamps, `/DSS` validation data, signature field plumbing — anything else,
a rewritten page or content stream included, is the incremental saving attack
and fails the document. The certification gate reports a final catalog
carrying `/Perms /DocMDP /P 1` whose certifying signature sits in an older
revision: revisions after a P=1 certification break it, and AutoFirma's own
validator says so over those same files. Signing refuses what verification
would refuse to sign: encrypted inputs (the refusal names `qpdf --decrypt` as
the way out), a P=1 certification (unless told otherwise with
`--allow-certified`), and page trees that repeat a `/Kids` child. Hostile
offsets — a `startxref` or `/Prev` past the end of the file, xref widths that
overflow, a lying `/Size`, a truncated table — are errors with the bad number
named in the sentence, never panics and never silent overwrites.

## 3. ETSI reference validator, local

The reference implementation for ETSI EN 319 102-2 and 142 is the European
Commission's **DSS** library. It is not on Maven Central; it is published on
the CEF eSignature repository, which redirects rather than serves artifacts
from some networks, so this layer is a manual step rather than a CI job:

```
# from https://ec.europa.eu/cefdigital/artifact/repository/esignaturedss/
# pull eu.europa.esig.dss:dss-pades-pdf and dss-validation, then
SignedDocumentValidator.fromDocument(doc).validateDocument()
```

Read its `SimpleReport`: `SignatureFormat` should say `PAdES-BASELINE-B`, the
`DigestMatcher` of type `MESSAGE_DIGEST` and the one of type `SIGNATURE`
should both be `TRUE`, and the qualification will be `NotAdES` or
indeterminate-on-trust because the synthetic chain is in no trust list. That
last part is the expected outcome for test material and is exactly what
`pdfsig` already reports as "issuer isn't Trusted".

VeraPDF (`verapdf/cli` on Docker Hub) is **not** a PAdES validator. It checks
PDF/A conformance, and a signed PDF that is not PDF/A fails its default
flavour for reasons that have nothing to do with the signature. It is useful
only if we ever claim PDF/A output, which we do not.

## 4. VALIDe and the real portals

VALIDe (https://valide.redsara.es/valide/) is the actual judge, and it is a
manual web upload. It needs a certificate from a trusted provider to say
"firma válida" instead of "certificado no reconocido", so this layer is run by
a person, in a scratch directory, with a real certificate that never enters the
repository. The routine:

1. in a scratch directory outside the tree, sign one document per profile:

   ```
   openfirma sign -i doc.pdf -o doc.openfirma.pdf --format pades-b-b \
       --cert fnmt.crt --key fnmt.key \
       --chain fnmt-intermediate.crt --chain fnmt-root.crt
   openfirma sign -i doc.txt -o doc.openfirma.csig \
       --cert fnmt.crt --key fnmt.key
   ```

2. sign the same documents with AutoFirma,
3. upload both to VALIDe,
4. compare the reports side by side. Any difference in the reported level or in
   the warnings is a bug in openfirma.

Only the verdict and the reported level get written down, in
`docs/validation-log.md`. The certificate, the key and the signed files stay in
the scratch directory and are deleted afterwards.

Today an exportable FNMT software certificate (a `.p12`) signs from a file, and
since the system keystores landed, so does a DNIe or a non-exportable FNMT key:
`--store pkcs11:/usr/lib/opensc-pkcs11.so:<token> --pin-env <VAR>` signs with
the key inside the card. The acceptance run against VALIDe through a reader is
still pending a physical card in CI-adjacent hands; what *is* automated is the
keystore itself, tested end to end against SoftHSM and an NSS database built by
`tools/setup-test-keystores.sh` (see `crates/openfirma-keystore/tests/pkcs11.rs`
and docs/adr/0004-system-keystores.md).

The last step is the sedes electrónicas themselves: submit a real trámite with a
document signed by openfirma. That is the only proof of protocol layer
compatibility, and it is done by hand, tracked in `docs/validation-log.md`.
For the browser path this step has an extra gap today: real sedes open a
`wss://127.0.0.1:<port>` socket (docs/adr/0005-browser-protocol.md), and the
openfirma endpoint speaks plain HTTP on loopback until a pure-Rust TLS stack
exists, so an end-to-end trámite through a real sede's autoscript is not yet
possible; what *is* proven is every layer under it — URI parsing from recorded
URIs, dispatch, wire response shapes, and the endpoint's refusals.

## 5. GUI manual checklist (what kittest cannot reach)

The window's logic — screens, routing, verdicts, error wording, the close
guard, sign-then-verify through the same files — is asserted windowless by
`crates/openfirma-gui/tests/ui.rs`. The items below need a real display and a
real desktop; they are run once per release on each platform, in a scratch
directory with the test PKI (`tools/gen-testcert.sh`) or, for full trust
wording, a real certificate that never enters the repository.

- [ ] `cargo run -p openfirma-gui` opens (glow renders; X11 and Wayland
      sessions both), title «openfirma», Spanish throughout.
- [ ] drag a PDF from the file manager onto the window → it detects and names
      the format; dropping over the *Done* screen does not disturb the result.
- [ ] "Examinar…" opens the real OS picker (rfd) on all three platforms, and
      cancels cleanly (drop zone stays where it was).
- [ ] ".p12" button → picker → password field → Firmar; a wrong password is
      one plain sentence plus details, never a dialog storm; the right one
      writes `documento.signed.pdf` next to the original before ✓ appears.
- [ ] keystores: open a DNIe/OpenSC token by descriptor + PIN (or SoftHSM via
      `pkcs11:/usr/lib/softhsm/libsofthsm2.so:openfirma test`, PIN 12345678);
      its row needs no password to sign; a wrong PIN says so on the picker.
- [ ] verify: drop a signed PDF → verdict lines with who/when; the details
      toggle shows chain and byte ranges; with no `$OPENFIRMA_TRUST` the
      window asks for an anchor and finishes from one picked file.
- [ ] close (window ✗ / Alt-F4) over an unsaved result opens the guard; "Seguir
      trabajando" keeps everything, "Cerrar sin guardar" ends the run and
      leaves written files exactly where their screen said.
- [ ] Save As writes to a second location and the path on screen follows it.
- [ ] "Abrir carpeta" opens the folder (never a document); if no opener
      exists, the failure is a red sentence on the screen.
- [ ] CLI parity spot-check: every action above reproduces with the
      equivalent `openfirma sign/verify` line from the README.

## 6. Keystore interoperability manual checklist (wave 4a)

Everything here compiles on CI but cannot run here: this development box has
no Windows, no macOS keychain contents it may touch, and no DNIe card. Each
item is what a person with that hardware runs once; findings go to
`docs/validation-log.md`.

- [ ] Windows, own login: `openfirma keystores list --store windows` shows the
      store's signing certificates with their key specs (the enumeration asks
      CNG then legacy CAPI per certificate, and refuses to call a
      non-exportable key signable when neither provider can be opened for it).
- [ ] Windows, sign: `openfirma sign -i doc.txt -o doc.csig --store windows`
      with a cert whose key is non-exportable (its "Microsoft Enhanced
      Cryptographic Provider v1.0" style CSP or a CNG key marked
      non-exportable). This exercises signing through the store's own
      certificate context: AutoFirma's Java path needs it too — a context
      rebuilt from DER has no `CERT_KEY_PROV_INFO` and `CryptAcquireCertificatePrivateKey`
      fails on it (its javap evidence is in this repo's ADR-0004 discussion).
      If the store crypto ever produced "No CAPI provider for this
      certificate's private key" for a cert that AutoFirma signs fine, that is
      exactly this bug.
- [ ] Windows, DNIe: same through the card's CSP; with a PIN, expect the card
      dialog or the prompt to be suppressible by `SILENT` only when a PIN was
      already supplied — check the interactive and the pre-authenticated case.
- [ ] macOS keychain (14+, 26): `--store macos-keychain:` listing; until it is
      tested the code refuses rather than guessing, so this box checks that the
      refusal wording is actionable, nothing else.
- [ ] DNIe card, PIN twice: a token whose keys carry
      `CKA_ALWAYS_AUTHENTICATE` (a real DNIe does; SoftHSM can simulate it by
      PKCS#11 tooling) must authenticate once for listing and again per
      signature (`C_Login(CKU_CONTEXT_SPECIFIC)`), and a card that resets its
      operation between calls gets its retry — the sequence is exactly what
      AutoFirma's `Pkcs11Mixin` does. A wrong PIN here must say so without
      burning retries beyond one.
- [ ] NSS via Firefox: with Firefox installed (deb, snap or flatpak), run
      `openfirma keystores list` with no `--store`: it should offer exactly the
      profiles Firefox itself would open — `profiles.ini` decides, including
      an install whose default differs from the global one — and every listing
      must work through libnss3 loaded read-only (no cert9.db changes: compare
      its checksum before and after).
- [ ] NSS with spaces: move a profile database to a path containing spaces and
      list it by descriptor (`nss:<path>`); quoting is unit-tested against real
      libsoftokn3 on Linux, this box confirms the vendor's own error wording.
- [ ] PKCS#12 out of Java: take one `.p12` each from a RealVNC export, a
      Google-wide-character-set keystore, and any 40-bit RC2 legacy keystore;
      `openfirma keystores list --p12 <f>` must open all three where the old
      DER walker refused. These are the exact shapes AutoFirma's Sun provider
      reads (its ASN1Parser integer/length limits were measured by javap, see
      ADR-0003); the synthetic versions of them are in CI (`pkcs12_interop`).

## Reference corpus

Byte-level evidence for the protocol-layer tests (the recorded autoscript.js
literals and `javap -c` forms that `tests/autoscript_wire.rs`,
`tests/prehash_golden.rs` and the comments in `uri.rs` / `dispatch.rs` quote)
comes from the official AutoFirma 1.9 package: `tools/fetch-autofirma.sh`
downloads and extracts it, which yields the jar (`.../usr/lib/Autofirma/
autofirma.jar`, record class bodies with `javap -c`) and the webapp resources
(`autoscript.js`). The recorded shapes that matter are pinned by tests over
the wire forms themselves — if a future AutoFirma changes one, the golden diff
and these tests go red together. Nothing from the extraction is committed.

## Test certificate material

`testdata/certs/` is gitignored except for its README. Generated on demand by
`tools/gen-testcert.sh` driving the openssl CLI, deliberately not `rcgen`, whose
dependency tree would pull a C crypto backend into the workspace: one RSA 2048
CA, one intermediate, one RSA 2048 signing
cert, one ECDSA P-256 signing cert, all with the extended key usage and key
usage AutoFirma expects (digitalSignature, nonRepudiation). Since the
long-term levels it also generates the material B-LT archives and B-LTA
stamps with: a TSA certificate, an empty CRL per CA (long-lived, so a stale
checkout does not turn tests red on an expiry that means nothing), an OCSP
responder delegate with the OCSPSigning EKU, and one real OCSP response for
the RSA signing cert produced fully offline.

## Real certificates

Layer 4 needs a certificate from a trusted provider to get a "firma válida"
verdict instead of "certificado no reconocido". That certificate, and any file
signed with it, never enter the repository:

- golden files are produced with `testdata/certs/signer-rsa.p12`, the synthetic
  test PKI, so the AutoFirma output and ours are directly comparable and both
  carry the same non trusted chain,
- the acceptance run with a real FNMT or DNIe certificate happens outside the
  tree, in a scratch directory, and only the verdict and the reported signature
  level get written into `docs/validation-log.md`,
- tests never see real personal certificate material: the PKCS#11 and NSS tests
  use the synthetic PKI imported into SoftHSM and an NSS DB under
  `/tmp/opencode/keystores` by `tools/setup-test-keystores.sh`, so a real DNIe
  card is never mounted in test infrastructure either.

`tools/check-no-real-certs.sh` blocks the whole class of mistake, including a
signature that embeds someone's certificate without anyone meaning to. See the
certificate material policy in the README.

## Definition of done for a profile

A profile (say CAdES-B-B with SHA-256 and RSA) is done when:

- the golden diff against AutoFirma is empty for structure,
- `openssl` verifies it, and for PAdES verifies it over exactly the
  `/ByteRange` bytes,
- `pdfsig` reports the signature valid and the document totally signed, and
  `qpdf --check` finds no container problem,
- DSS reports the expected level with no signature format errors, run by hand
  where the CEF repository is reachable,
- VALIDe reports the same verdict as for the AutoFirma signed equivalent,
- it builds and passes on the three OS in CI.
