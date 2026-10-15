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

- **CAdES-B-B** signing, RSA and ECDSA P-256, SHA-1/224/256/384/512,
  encapsulated and detached, with `signingCertificateV2`, `signingTime` and the
  ESS `contentHint` attribute. Verified by OpenSSL in CI, and structurally
  identical to the official AutoFirma 1.9 output, see `tools/golden-diff.sh`.
- **PAdES-B-B** signing: a detached CAdES in `/Contents`, added as an
  incremental update that leaves the original document bytes untouched, with
  the AcroForm field, `/ByteRange`, and an invisible or a visible appearance.
  Co-signing a document that is already signed works, including one that
  AutoFirma signed, which means reading cross-reference streams and object
  streams. OpenSSL verifies the signature over exactly the ranges `/ByteRange`
  names, and the structure matches AutoFirma's, see `docs/pades.md`.
- CLI: `openfirma sign` and `openfirma inspect`, the latter dumping any DER
  signature as a normalized tree for diffing.

Not started yet: XAdES, the system keystores (PKCS#11, DNIe, Windows, macOS,
NSS), the browser protocol, the GUI, and B-LT/B-LTA.

| Component | Status |
|---|---|
| CAdES-B-B (RFC 5652 CMS + ETSI EN 319 122-1) | works, crosschecked with OpenSSL |
| CAdES B-T / B-LT / B-LTA (TSA, DSS, archive timestamps) | not started |
| PAdES-B-B (PDF, ISO 32000 + ETSI EN 319 142-1) | works, crosschecked with OpenSSL and qpdf |
| CAdES/PAdES B-T (RFC 3161 time-stamp) | works, crosschecked with openssl ts |
| B-LT / B-LTA (validation data, archive timestamps) | not started |
| Keystores: PKCS#12 | works, pure Rust, MAC checked before decrypting |
| Keystores: PKCS#11, DNIe, Windows, macOS, NSS | not started |
| XAdES / FacturaE | not started |
| Browser integration (`afirma://`, wss:// localhost, AutoScript) | not started |
| GUI | not started |

## Quick start

```
./tools/gen-testcert.sh          # throwaway CA + RSA and EC signing certs
cargo run -- sign -i doc.txt -o doc.csig \
    --cert testdata/certs/signer-rsa.crt --key testdata/certs/signer-rsa.key
cargo run -- sign -i doc.pdf -o doc.signed.pdf --format pades-b-b \
    --cert testdata/certs/signer-rsa.crt --key testdata/certs/signer-rsa.key \
    --chain testdata/certs/intermediate.crt --chain testdata/certs/ca.crt
cargo test                       # includes the OpenSSL crosschecks
```

`tools/fetch-autofirma.sh` downloads the official AutoFirma so its output can
be diffed against ours, see `docs/validation.md`.

## Layout

```
crates/
  openfirma-core     shared types: algorithms, certificates, Signer trait
  openfirma-cades    CMS / CAdES
  openfirma-pades    PDF reading, incremental updates, PAdES
  openfirma-cli      the `openfirma` binary
docs/
  architecture.md    crate layering and data flow
  pades.md           what AutoFirma's PAdES output actually contains
  platforms.md       the multiplatform matrix
  validation.md      how we prove output validates
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

`tools/check-no-real-certs.sh` enforces it. It rejects banned extensions and
keystore filenames, any PEM private key block, and any file that parses as an
X.509 certificate not issued by the synthetic `openfirma Test` PKI. It runs on
pre-commit, over every tracked file with `--tracked`, and over every blob in
history with `--history`. CI runs the last two on each push.

Acceptance runs against VALIDe that need a trusted certificate are done by hand
by whoever holds one, outside the repository, and only the verdict is written
down. See `docs/validation.md`.

## License

Dual licensed, same as AutoFirma: **GNU GPL version 2.0 or later** and
**EUPL version 1.1**. See `LICENSES/`.

Attribution and the relationship with the original work are described in
`NOTICE.md`. AutoFirma is copyright of the Gobierno de España. openfirma is not
endorsed by, affiliated with, or supported by the Gobierno de España or the CTT.
