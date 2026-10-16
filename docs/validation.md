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

Gotcha found while setting this up: **`openssl cms -verify -content` is broken
for detached signatures in 3.6.5**. It rejects detached CMS produced by openssl
itself with `CMS_SignerInfo_verify_content: verification failure`, even though
the `messageDigest` attribute matches the file exactly. `openssl smime -verify
-content` does the same job and works, so the detached tests go through
`smime`. Encapsulated signatures verify fine with `cms -verify`.

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
