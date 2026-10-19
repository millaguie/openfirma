# openfirma

Pure Rust reimplementation of [AutoFirma](https://github.com/ctt-gob-es/clienteafirma),
the electronic signature client published by the Spanish government (CTT,
Centro de Transferencia de Tecnología).

This is an **independent reimplementation**, not a port and not a fork. No Java
code is copied. The goal is bit-compatible output: files signed with openfirma
must validate in VALIDe, in the ETSI reference validators and in the government
portals exactly like files signed with AutoFirma.

Written in Rust with no C dependencies in the crypto or the signature formats.
Platform native APIs (Windows CNG, macOS Security.framework, PC/SC, PKCS#11)
are reached through Rust binding crates, see `docs/platforms.md`.

## Status

Very early, phase 1. What works today:

- **CAdES-B-B** signing, RSA and ECDSA P-256/P-384/P-521,
  SHA-1/224/256/384/512 (SHA-1 only with `--allow-weak-algorithms`: the
  ETSI TS 119 312 conservative policy refuses it by default), encapsulated
  and detached, with `signingCertificateV2` (v1 for SHA-1, AutoFirma's rule),
  `signingTime`, the ESS `contentHint` attribute, the certificatePolicies copy
  into ESSCertIDv2, and the optional `signaturePolicyIdentifier`,
  `commitmentTypeIndication` and `mime-type` attributes. Verified by OpenSSL in
  CI, and structurally identical to the official AutoFirma 1.9 output, see
  `tools/golden-diff.sh` and the measured case table in `docs/validation.md`.
- **PAdES-B-B** signing: a detached CAdES in `/Contents`, added as an
  incremental update that leaves the original document bytes untouched, with
  the AcroForm field, `/ByteRange`, and an invisible or a visible appearance.
  Co-signing a document that is already signed works, including one that
  AutoFirma signed, which means reading cross-reference streams and object
  streams. OpenSSL verifies the signature over exactly the ranges `/ByteRange`
  names, and the structure matches AutoFirma's, see `docs/pades.md`.
- **PAdES B-LT and B-LTA** (`--format pades-b-lt`, `--format pades-b-lta`):
  the ETSI EN 319 142-1 long-term levels, appended as further revisions in
  the order the specification names. B-LT writes the `/DSS` validation data —
  the full chain and one CRL or OCSP response per CA, supplied by the caller
  and never fetched, indexed per signature under `/VRI` by the SHA-1 key the
  spec and the EU's DSS validator define. B-LTA adds a document time-stamp
  (`/Type /DocTimeStamp`, RFC 3161 through the same TSA closure as B-T) over
  everything before it, the archive included. `openfirma verify` judges the
  whole archive: CRL signatures under the issuing CA's key, chains rebuilt
  from the `/DSS` alone, nothing revoked, and every document time-stamp
  imprinting exactly its `/ByteRange`. AutoFirma has no golden here — its
  enhancer ships disabled — so the crosschecks are openssl, qpdf and poppler,
  including that every earlier signature stays valid after the archive is
  appended. See `docs/pades.md`.
- **XAdES-B-B** signing (`--format xades-b-b`): an enveloped XML-DSig
  signature with the ETSI EN 319 132-1 baseline properties
  (`SigningCertificateV2`, `SigningTime`, `DataObjectFormat`), on top of a
  hand-rolled strict XML reader and Canonical XML 1.0 implementation. RSA and
  ECDSA P-256. The structure matches AutoFirma's `profile=baseline` output,
  `xmlsec1` verifies every reference and the signature value, and AutoFirma's
  own validator accepts our files, see `docs/xades.md`.
- **Verification**: `openfirma verify` cryptographically checks CAdES and
  PAdES signatures, every signature of a co-signed PDF included: the
  `messageDigest` against the content, the signature value over the signed
  attributes re-tagged as `SET OF`, the `signingCertificateV2` reference, and
  the certificate chain from the signer up to the trust anchors you supply,
  each link's signature and every validity date checked at a validation time
  of your choice. RSA and ECDSA P-256/P-384/P-521, and SKI-based signer
  identifiers (SignerInfo version 3). The default `AlgorithmPolicy` is the
  ETSI TS 119 312 conservative one: SHA-1 signature digests and RSA keys
  below 2048 bits are refused unless the caller opts out explicitly. It is
  the in-repo verifier, not a substitute for VALIDe or the ETSI validators,
  see `docs/validation.md`.
- CLI: `openfirma sign`, `openfirma verify`, `openfirma inspect` (dumping any
  DER signature as a normalized tree for diffing), and `openfirma keystores
  list`, which lists what a PKCS#11 token or NSS database holds.

The window (`openfirma-gui`) signs and verifies through the same library
calls this CLI makes — everything it does is also possible from here, and the
decisions (detection, output naming, descriptor parsing, trust anchors) are
one implementation both frontends call, not two that can drift. Not started
yet: FacturaE. The browser protocol works on its own
pages and test sedes; against a *real* sede it still lacks the TLS leg — see
docs/adr/0005-browser-protocol.md and the table row below.

| Component | Status |
|---|---|
| CAdES-B-B (RFC 5652 CMS + ETSI EN 319 122-1) | works, crosschecked with OpenSSL; measured golden cases and the not-implemented list (co-signature, counter-signature, ESS V3, EPES) in docs/cades.md |
| PAdES-B-B (PDF, ISO 32000 + ETSI EN 319 142-1) | works, crosschecked with OpenSSL and qpdf |
| Verification of CAdES and PAdES (crypto, chain, trust anchors) | works, crosschecked with OpenSSL |
| CAdES/PAdES B-T (RFC 3161 time-stamp) | works, crosschecked with openssl ts |
| PAdES B-LT (`/DSS` validation data, CRL and OCSP) | works, crosschecked with openssl crl and the DSS-shape checks in verify |
| PAdES B-LTA (document time-stamp over the archive) | works, crosschecked with openssl ts, qpdf and pdfsig |
| CAdES ES-LT / ES-LTA (validation data inside the CMS) | out of scope: the long-term path is PAdES B-LT/B-LTA, see docs/pades.md |
| Keystores: PKCS#12 | works, pure Rust: BER parser (RealVNC/Google-style indefinite-length files open), keyLength 128-bit keys and legacy RC2-40 certificates decrypt via PBES1, absent-password spellings match Java KeyStore, see docs/adr/0003-pkcs12-container.md |
| Keystores: PKCS#11 tokens (OpenSC/DNIe shape), NSS shared DB | works, FFI into the vendor module at runtime, tested against SoftHSM and libsoftokn3 with signatures double-verified by openfirma and openssl; keys whose token advertises CKA_ALWAYS_AUTHENTICATE get their per-signature context login; `keystores list` with no --store discovers Firefox/Thunderbird profile databases through profiles.ini (snap and flatpak included) |
| Keystores: Windows cert store, macOS keychain | Windows compiles on CI and is untested at runtime; macOS refuses both listing and signing until it can be tested, see docs/adr/0004-system-keystores.md |
| XAdES-B-B (XML-DSig + ETSI EN 319 132-1, enveloped) | works, crosschecked with xmlsec1 and AutoFirma's own validator |
| XAdES B-T and above, FacturaE, enveloping/detached shapes | not started |
| Browser integration (`afirma://` parsing, dispatch, loopback endpoint) | works end to end against a fake sede (openssl crosschecks the signature it produces); wire forms — the URL-safe base64 payload, the `:=` error envelope with AutoFirma's Spanish catalogue and SAF pairings — pinned against recorded autoscript.js predicates (tests/autoscript_wire.rs); precalculatedHashAlgorithm signs the sede's imprint verbatim, proven against openssl (tests/prehash_golden.rs); plain HTTP transport: real sedes need wss, refused rather than faked, see docs/adr/0005-browser-protocol.md |
| GUI (`openfirma-gui`, egui/eframe): sign, verify, keystores, .p12 | works: the same library calls as the CLI (docs/adr/0006-gui-toolkit.md); windowless kittest tests drive the real App, including an end-to-end sign-then-verify; real-display checks live in docs/validation.md's manual checklist |

## Quick start

```
./tools/gen-testcert.sh          # throwaway CA + RSA and EC signing certs
cargo run -- sign -i doc.txt -o doc.csig \
    --cert testdata/certs/signer-rsa.crt --key testdata/certs/signer-rsa.key
cargo run -- sign -i doc.pdf -o doc.signed.pdf --format pades-b-b \
    --cert testdata/certs/signer-rsa.crt --key testdata/certs/signer-rsa.key \
    --chain testdata/certs/intermediate.crt --chain testdata/certs/ca.crt
cargo run -- sign -i doc.xml -o doc.signed.xml --format xades-b-b \
    --cert testdata/certs/signer-rsa.crt --key testdata/certs/signer-rsa.key \
    --chain testdata/certs/intermediate.crt --chain testdata/certs/ca.crt
cargo run -- sign -i doc.pdf -o doc.lt.pdf --format pades-b-lt \
    --cert testdata/certs/signer-rsa.crt --key testdata/certs/signer-rsa.key \
    --chain testdata/certs/intermediate.crt --chain testdata/certs/ca.crt \
    --crl testdata/certs/intermediate.crl.der --crl testdata/certs/ca.crl.der
cargo run -- verify -i doc.csig --content doc.txt --trust testdata/certs/ca.crt
cargo run -- verify -i doc.signed.pdf --trust testdata/certs/ca.crt
cargo test                       # includes the OpenSSL crosschecks
cargo run -p openfirma-gui       # the window (Spanish UI; docs/adr/0006-gui-toolkit.md)
```

The GUI needs no flags: drop the document, pick the certificate, sign — the
result lands next to the original (`documento.signed.pdf`). Verifying is
dropping a signed file and reading the verdicts. The authorities it verifies
against are configuration, read once at startup from `$OPENFIRMA_TRUST` — the
same knob the CLI reads; the window never asks you to choose a CA (a question
nobody can answer, and the one door an impostor's own certificate could walk
through). With none configured it says, on every line, that the document's
integrity was checked and **who issued the certificate was not**. Everything
the window does has the CLI spelling above; the window never adds a capability
the terminal lacks.

Signing with a real certificate means signing from its PKCS#12 container.
The password goes in a file nobody but you can read, or in the environment —
never in argv, where `ps` and the shell history can see it:

```
cargo run -- sign -i doc.pdf -o doc.signed.pdf --format pades-b-b \
    --p12 certificado.p12 --password-file pw.txt     # chmod 600 pw.txt
OPENFIRMA_PASSWORD=... cargo run -- sign ... --p12 certificado.p12
```

`--password` still exists and reads `OPENFIRMA_PASSWORD` when not given, but
its help text says what it is: insecure.

A key held by the system or a token — smartcard, DNIe, NSS database — signs
without ever leaving its holder. The PIN travels in an environment variable,
same rule as above. `--pin-env` names a variable that must exist: an unset
one is refused before the token is touched, because trying an empty PIN
costs lockout tries on real cards. A keystore with genuinely no password is
the descriptor's own `::` marker (`--store pkcs11:/path/module.so::`), and a
plain `--store nss` needs nothing:

```
cargo run -- keystores list \
    --store pkcs11:/usr/lib/opensc-pkcs11.so:"3CM-ES..."   # what can sign
export DRIE_PIN=...        # never on the command line
cargo run -- sign -i doc.txt -o doc.csig \
    --store pkcs11:/usr/lib/opensc-pkcs11.so:"3CM-ES..." --pin-env DRIE_PIN
cargo run -- sign -i doc.txt -o doc.csig --store nss      # $HOME/.pki/nssdb
cargo run -- keystores list                              # also discovers Firefox/Thunderbird profiles
```

The module path of a `pkcs11:` descriptor must be absolute: NSS itself looks
a bare name up in the system library paths, and accepting one would sign with
some other library than the one named. `nss:<path>` passes the path to NSS
quoted when it contains spaces, read-only.

A sede's browser call answers through the same signing code. The scheme and
the loopback endpoint's rules are docs/adr/0005-browser-protocol.md; at install
time you register the scheme once, naming the key the handler signs with (it
writes only your own files — the `.desktop` entry plus a browser config under
`$XDG_CONFIG_HOME/openfirma/browser.toml` that stores paths, never a password),
then pages hand URIs to the endpoint:

```
cargo run -- afirma-uri --register \
    --p12 certificado.p12 --password-file pw.txt   # registration + handler config
cargo run -- afirma-serve \
    --p12 certificado.p12 --password-file pw.txt   # prints its port and one token
cargo run -- afirma-uri "afirma://sign?op=sign&format=CAdES&algorithm=SHA256&dat=…" \
    --p12 certificado.p12 --password-file pw.txt -o result.txt   # what the OS handler runs
```

`tools/fetch-autofirma.sh` downloads the official AutoFirma so its output can
be diffed against ours, see `docs/validation.md`.

Scripts written for AutoFirma's console (`AutoFirma.bat sign -i … -o …`) run
against openfirma through its own spelling:

```
openfirma autofirma sign -i doc.pdf -o doc.signed.pdf -format auto \
    -store pkcs12:certificado.p12 -alias "PEREZ GARCIA, ANA" -password secreto
openfirma autofirma listaliases -store pkcs12:certificado.p12 -password secreto
```

The flags are AutoFirma's single-dash spellings (`-i`, `-o`, `-format`,
`-store windows|mac|mozilla|auto|pkcs12:…|pkcs11:…`, `-alias`, `-password`,
`-xml`) and a failure exits with its code, 255 — what a calling script checks.
Two deliberate differences: an existing output is kept unless
`OPENFIRMA_COMPAT_FORCE=1` says otherwise (AutoFirma truncates without asking;
openfirma asks), and the flags whose capability openfirma does not implement
(`-gui`, `-filter`, `-dni`, …) are refused by name instead of ignored. The
`-password` on argv is AutoFirma's habit, not one a compat layer can make
safe — its own help says so; every other command takes `--password-file`.

## Layout

```
crates/
  openfirma-core     shared types: algorithms, certificates, Signer trait,
                     the frontends' one implementation of their decision rules
  openfirma-cades    CMS / CAdES
  openfirma-pades    PDF reading, incremental updates, PAdES
  openfirma-xades    XML reader, Canonical XML, XAdES-B-B
  openfirma-keystore PKCS#12 + system stores: PKCS#11/NSS FFI, Windows, macOS
  openfirma-browser  browser protocol: afirma:// URIs, dispatch, loopback endpoint
  openfirma-cli      the `openfirma` binary
  openfirma-gui      the window (`openfirma-gui`), same library calls as the CLI
docs/
  architecture.md    crate layering and data flow
  pades.md           what AutoFirma's PAdES output actually contains
  xades.md           what AutoFirma's XAdES output actually contains
  platforms.md       the multiplatform matrix
  validation.md      how we prove output validates
  validation-log.md  what has actually been run, where, with what verdict
  review-findings.md the surprise review's findings and each one's status
  adr/               decisions that are expensive to reverse
testdata/
  inputs/            documents to sign, committed because they must not change
  golden/            signatures produced by the official AutoFirma, for diffing
tools/               golden generation and external validators
```

## Build

```
cargo build
cargo test
```

## Certificate material policy

No certificate, private key, keystore, or signature produced with a real
certificate may ever enter this repository. A CAdES or PAdES signature embeds
the signer certificate and its full chain, so a single committed signature
publishes whoever the certificate identifies. That is a wider set than people
usually picture: the Spanish @firma ecosystem issues certificates against a
NIF, a NIE, a passport number, a legal person's CIF (persona jurídica and
sello de entidad) and a representative of a legal person, and each of them
carries a name and an identifier in the subject. Any of them in this
repository is someone's identity, made public.

Everything is generated locally and stays out of git:

```
./tools/gen-testcert.sh              # synthetic three level test PKI
git config core.hooksPath tools/hooks # install the pre-commit guard
```

`tools/check-no-real-certs.sh` enforces it, by content first and extension
second. It rejects banned extensions and keystore filenames wherever they
appear in a *path* — the working tree, the index, and every path a blob ever
had in history; any PEM private key block in ANY file, markdown included; and
every certificate it can read, which is EVERY PEM block in a file (`openssl`
alone reads only the first) judged on both of its name lines: a certificate is
test material only when its subject and its issuer both carry the synthetic
`openfirma Test` marker. It judges every way a signature hides one inside an
innocent-looking name too: each `/Contents` CMS of a `%PDF-` file, one per
signature and not just the first, XML carrying
`ds:SignatureValue`/`X509Certificate`, and raw CMS `SignedData` under any
extension. Allowlisted paths (`docs/`, generated fixtures) skip the extension
rule only, never the content rules. The guard tests itself against all of these
shapes, controls included (`tools/test-check-no-real-certs.sh`, run as a cargo
test). It runs on pre-commit, over every tracked file with `--tracked`, and
over every blob in history with `--history`. CI runs the last two on each push.

Its measured limits, named so that nobody reads the guard as more than it is: a
certificate whose base64 is re-wrapped across lines — the shape `xmlsec1`
writes, or a certificate body with its PEM markers stripped — is not decoded
and passes; a PKCS#12 container renamed to a free extension (`secret.dat`) is
not parsed and passes; a certificate inside a *compressed* container is not
recursed into and passes (an uncompressed one is read as text and blocked). The
guard reads one file at a time and stops where its decoders stop. What it
exists for it does: a certificate in a PEM file, a signature made here or by
AutoFirma, a `.p12` or keystore under a name it recognises, and a certificate
pasted into markdown are all blocked.

Acceptance runs against VALIDe that need a trusted certificate are done by hand
by whoever holds one, outside the repository, and only the verdict is written
down. See `docs/validation.md`.

## License

Dual licensed, same as AutoFirma: **GNU GPL version 2.0 or later** and
**EUPL version 1.1**. See `LICENSES/`.

Attribution and the relationship with the original work are described in
`NOTICE.md`. AutoFirma is copyright of the Gobierno de España. openfirma is not
endorsed by, affiliated with, or supported by the Gobierno de España or the CTT.
