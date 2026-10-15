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

This is the layer that catches most of the problems. It caught four real bugs
in the CAdES encoder that OpenSSL tolerated: a missing `SigningCertificateV2`
wrapper level, an unsorted `certificates` set, `sha256WithRSAEncryption` where
RFC 3370 requires `rsaEncryption`, and encapsulating content by default.

## 2. OpenSSL, as an independent ASN.1 reader

Three independent implementations are wired into `cargo test`, each checking a
different property, and each skipped with a message when it is not installed:

- **OpenSSL** (`crates/openfirma-cades/tests/openssl_crosscheck.rs` and
  `crates/openfirma-pades/tests/openssl_crosscheck.rs`) verifies the CMS
  cryptographically: for PAdES it is handed exactly the bytes `/ByteRange`
  names, so a signature that verifies is a signature over the right bytes.
  It also catches malformed DER, wrong tags, bad lengths and broken `SET OF`
  ordering.
- **poppler's `pdfsig`** verifies the PDF-level signature and reports whether
  it covers the whole document. It is a third implementation of the PAdES
  reading path, with its own ASN.1 and its own PDF parser, so agreement with
  it is strong evidence. It cannot trust the synthetic test chain, and saying
  "Certificate issuer isn't Trusted" is the correct answer there, so only the
  cryptographic verdict is asserted.
- **qpdf** checks the container: cross-reference offsets, object structure,
  stream lengths. A signature can be cryptographically perfect in a PDF that
  no reader can open, so this is checked separately.

Gotcha found while setting this up: **`openssl cms -verify -content` is broken
for detached signatures in 3.6.5**. It rejects detached CMS produced by openssl
itself with `CMS_SignerInfo_verify_content: verification failure`, even though
the `messageDigest` attribute matches the file exactly. `openssl smime -verify
-content` does the same job and works, so the detached tests go through
`smime`. Encapsulated signatures verify fine with `cms -verify`.

What these prove today: RSA SHA-256 and SHA-512 plus ECDSA P-256, encapsulated
and detached, verify under OpenSSL with byte identical recovered content; and
PAdES-B-B verifies under OpenSSL over the `/ByteRange` bytes, under poppler as
"Signature is Valid" and "Total document signed", and opens cleanly in qpdf.
That covers the CMS structure, the `SET OF` DER ordering, the `[0] IMPLICIT`
retag rule for the signed attributes, the `signingCertificateV2` encoding, the
certificate embedding and the PDF incremental update.

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

Today this needs an **exportable** FNMT software certificate (a `.p12`), because
the CLI reads keys from files. A DNIe or a non-exportable FNMT key lives in a
token and cannot be used until the PKCS#11 keystore exists, so those are out of
scope for the acceptance run and in scope for the keystore work.

The last step is the sedes electrónicas themselves: submit a real trámite with a
document signed by openfirma. That is the only proof of protocol layer
compatibility, and it is done by hand, tracked in `docs/validation-log.md`.

## Test certificate material

`testdata/certs/` is gitignored except for its README. Generated on demand by
`tools/gen-testcert.sh` driving the openssl CLI, deliberately not `rcgen`, whose
dependency tree would pull a C crypto backend into the workspace: one RSA 2048
CA, one intermediate, one RSA 2048 signing
cert, one ECDSA P-256 signing cert, all with the extended key usage and key
usage AutoFirma expects (digitalSignature, nonRepudiation).

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
- a real personal certificate cannot be used from the tests anyway until the
  PKCS#11 keystore exists, because DNIe and most FNMT keys are not exportable.

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
