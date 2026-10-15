# PAdES: what we are implementing against

The target is the output of the **official AutoFirma 1.9** signing
`testdata/inputs/simple.pdf` with `testdata/certs/signer-rsa.p12`, PAdES-B-B,
RSA SHA-256. Measured, not read from a specification: AutoFirma's own jar was
driven headlessly by `tools/golden/AutofirmaGolden.java`, and the result was
reduced to a comparable form by `tools/golden/pdf-normalize.py`.

`testdata/golden/` is in `.gitignore`, so this file is the durable copy of what
it found. Regenerate it with `tools/golden-diff.sh pades` whenever the
reference AutoFirma version changes, and diff against this.

## The CMS inside `/Contents`

PAdES-B-B is a **detached** CMS `SignedData`. Concretely, against the CAdES-B-B
that already matches AutoFirma byte for byte in structure, exactly two things
change:

| | CAdES-B-B (file) | PAdES-B-B |
|---|---|---|
| `encapContentInfo` | `id-data`, no content | `id-data`, no content |
| `signingTime` | present | **absent** |
| `contentHint` | present | **absent** |
| `contentType` | `id-data` | `id-data` |
| `messageDigest` | digest of the file | digest of the `/ByteRange` segments |
| `signingCertificateV2` | present, with `issuerSerial` | present, with `issuerSerial` |

Three signed attributes, in this order after `SET OF` sorting:

```
1.2.840.113549.1.9.3    contentType      -> 1.2.840.113549.1.7.1 (id-data)
1.2.840.113549.1.9.4    messageDigest    -> sha256(range[0] || range[1])
1.2.840.113549.1.9.16.2.47  signingCertificateV2, ESSCertIDv2 carrying
                            certHash and issuerSerial, the issuer wrapped in
                            GeneralName [4] directoryName
```

`signingTime` is absent because the signing time lives in the signature
dictionary's `/M` entry, and having it in two places is how you end up with two
answers. `contentHint` is absent because there is nothing to hint: the content
is a PDF and the dictionary already says so.

Everything else follows the CAdES rules already established: `digestAlgorithms`
is a single-element set, `signatureAlgorithm` is `rsaEncryption` (RFC 3370 3.1,
not `sha256WithRSAEncryption`), and `certificates` is a `SET OF` sorted by
encoded bytes, holding the signer plus the whole chain from the PKCS#12.

## The PDF side

Signature dictionary:

```
/Type      /Sig
/Filter    /Adobe.PPKLite
/SubFilter /ETSI.CAdES.detached
/ByteRange [0 x y z]           two segments, see below
/Contents  <hex, zero padded to the reserved size>
/M         (D:20261015125435+02'00')
/Name      (PEREZ GARCIA, ANA)     the subject CN
```

Absent, and they must stay absent because their presence changes what a
validator expects: `/Reason`, `/Location`, `/ContactInfo`, `/Cert`,
`/Prop_Build`, `/Prop_AuthTime`, `/Prop_AuthType`, `/DocMDP`.

`/ByteRange` is `[0, x, y, z]`: two segments, `[0, x)` and `[y, y+z)`, where
`[x, y)` is exactly the `/Contents` hex string including its angle brackets and
`y + z` is the length of the file. The digest is taken over the concatenation
of the two segments. Verified against AutoFirma's own output: its
`messageDigest` equals `sha256` of that concatenation.

AcroForm and field:

```
catalog  /AcroForm << /DA (/Helv 0 Tf 0 g )
                      /DR << /Font << /Helv <Helvetica> /ZaDb <ZapfDingbats> >> >>
                      /Fields [ <field> ]
                      /SigFlags 3 >>
field    /FT /Sig /T (Signature1) /Subtype /Widget /Type /Annot
         /F 132 /Rect [0 0 0 0] /P <page> /V <sig dict>
         /AP << /N <blank form XObject, /BBox [0 0 0 0]> >> /DR << >>
page     /Annots [ <field> ] added
```

`/SigFlags 3` is `SignaturesExist | AppendOnly`. `/F 132` is `Print | Locked`.
`/Rect [0 0 0 0]` with a blank appearance is an invisible signature, which is
AutoFirma's default when no position is given. `/Helv` and `/ZaDb` are two of
the standard 14 fonts, referenced but not embedded.

## What we deliberately do differently

Recorded here so a future diff is read as a decision and not as a bug. See
`docs/adr/0003-incremental-update.md`.

- **Container.** AutoFirma rewrites the whole document through iText: one
  revision, renumbered objects, object streams, an xref stream. We append an
  incremental update: the original bytes untouched, a second revision, a
  classic xref table. Two `%%EOF` instead of one.
- **`/ITEXT (2.1.7)`.** iText's producer watermark. We do not write it, because
  it would claim a library we do not use wrote the file.
- **`/Contents` reservation.** AutoFirma reserves 27000 bytes and leaves 23400
  of zero padding. We size the reservation from the actual certificate chain
  plus headroom, so our file is smaller. The reserved size is not comparable
  and the normalizer reports the DER length separately from the container
  length.

The golden comparison runs both sides through `qpdf --qdf
--object-streams=disable`, which collapses revisions and decompresses object
streams, so the container difference disappears and what is left to compare is
the signature semantics.

## B-LT and B-LTA: the long-term levels

ETSI EN 319 142-1 defines two levels on top of B-T, and both are further
incremental updates appended **in a fixed order, which is part of the level**:
the B-B signature exists first, then the validation data (B-LT), then a
document time-stamp over everything before it (B-LTA). Appending is what makes
the levels safe: every earlier signature's `/ByteRange` addresses absolute
offsets, and none of the later revisions moves a byte of what it covered.

### Why there is no AutoFirma golden for these levels

The method of this repository is to measure AutoFirma's output, and for B-B
that is what happened. For B-LT there is nothing to measure: **AutoFirma's
default PAdES output carries no `/DSS`**. Its extension mechanism for
long-term validation data, the "enhancer", ships disabled — every line of
`afirma-crypto-pdf/src/main/resources/enhancer.properties`, including the
`enhancerClassFile` that names the `PDFEnhancer` implementation, is commented
out, and the reference 1.9 jar signs B-B (with B-T when a TSA is configured)
and stops. Rather than invent a golden, the reference for these two levels is
the specification text plus the independent verifiers of
`docs/validation.md`: `openfirma verify`'s own `/DSS` checks, `openssl crl
-verify` on the embedded CRLs, `openssl ts -verify` on the document time-stamp
token against exactly the bytes its `/ByteRange` names, `qpdf --check`, and
poppler `pdfsig` still reporting every earlier signature valid after the
long-term revisions are appended. If a future AutoFirma ships an enabled
enhancer, the golden diff is extended to cover it.

### B-LT: the `/DSS`

One more revision, adding to the catalog a `/DSS` dictionary (ISO 32000-2
12.8.4.4, ETSI EN 319 142-1 5.4.2) and the stream objects it references:

```
catalog  /DSS <dss>
dss      << /Type /DSS
           /VRI << /<HEX40> << /CRL [ <streams> ] /Cert [ <streams> ]
                               /OCSP [ <streams> ] >> ... >>
           /Certs [ one stream per DER certificate ]
           /CRLs  [ one stream per DER CertificateList ]
           /OCSPs [ one stream per DER OCSPResponse ] >>
stream   << /Length N >> stream <the DER, uncompressed> endstream
```

The details that are decisions rather than accidents:

- **The `/VRI` key** is the upper case hex of the **SHA-1 of the complete
  `/Contents` string** of each signature — the decoded bytes *including the
  zero padding*, not the DER inside and not the CMS `signatureValue`. That is
  the input ETSI EN 319 142-1 5.4.2.2 a) names ("the bytes that are hashed
  shall be those of the complete hexadecimal string in the entry with the key
  Contents") and exactly what the European Commission's DSS validator
  recomputes in `PAdESSignature.getVRIKey()`, so a validator looking for a
  signature's validation data finds it under this key and no other. The key is
  written as a **name** (`/1A2B...`), because PDF dictionary keys are names
  and qpdf flags the literal hex-string reading as a damaged object; both
  spellings are read back.
- **Nothing is fetched.** The certificates and the revocation data come from
  `PadesOptions::validation_certs` and `PadesOptions::revocation`, or from
  the signer's own chain. Where a CRL or an OCSP response came from is the
  caller's business; a signature library that quietly went to the network
  would be a different kind of program.
- **One entry per signature in the document**, not just per new one: a B-LT
  pass over a co-signed document archives the chains of every signature it can
  see, and the data for each is indexed under that signature's own key.
  Extending a document twice duplicates nothing: blobs already in the `/DSS`
  are reused by reference, and signatures already keyed in `/VRI` are skipped.
- `/TU` is left out: it is the collection time of the validation data, and
  the library only ever sees bytes, not the moment they were fetched.
- The streams are uncompressed on purpose. The point of the archive is to be
  readable decades from now, and DER is already dense.
- A signature added *after* the archive is simply not covered by it;
  `openfirma verify` reports it as uncovered rather than failing, because a
  later plain B-B signature is legal in a B-LT document.

`openfirma verify` checks the archive when one is present: every `/Certs`
entry parses as a certificate, every `/CRLs` entry parses, names a CA that is
in the archive or the trust anchors, and its **signature verifies under that
CA's key** (a CRL signed by anyone else is refused — the name is data, the
signature is the statement), its dates hold at the validation time, every
`/OCSPs` entry is a *successful* response, and for every signature the `/VRI`
covers, the chain rebuilds **from the `/DSS` contents alone** with at least
one revocation datum per CA certificate of that chain and no certificate of
the chain revoked by the archived data.

### B-LTA: the document time-stamp

One more revision, adding a new signature field appended to `/Fields` (and to
the page's `/Annots`), whose value is:

```
<< /ByteRange [0 x y z] /Contents <hex, zero padded>
   /Filter /Adobe.PPKLite /SubFilter /ETSI.RFC3161
   /Type /DocTimeStamp >>
```

Its `/ByteRange` covers everything before the hole — the signature, its B-T
token and the whole `/DSS` included — and `/Contents` holds an RFC 3161 token
imprinting exactly those bytes. The token comes through the same
`TimestampFn` closure as the B-T signature time-stamp: the library builds the
query, the caller owns the transport, and the token's imprint is checked
against the covered bytes **before** it is embedded, so a token over anything
else is refused at embed time. The field is named `TimestampN`, the first free
one, so it never collides with a `SignatureN`; there is no `/M`, because the
time of a document time-stamp lives in its token and nowhere else. The
document time-stamp requires the `/DSS` to exist first — B-LTA is B-LT plus
the stamp, and the stamp is what freezes the archive.

### Out of scope, and why

- **CAdES ES-LT / ES-LTA.** The CAdES equivalents (validation data as
  `certificate-values`/`revocation-values` unsigned attributes, archive
  time-stamp chains) are deliberately not implemented: openfirma's long-term
  path is PAdES, where the archive lives in the document's `/DSS`. The
  revocation reading they would need (`openfirma-cades::revocation`) already
  exists and is shared.
- **OCSP response signatures are not verified.** `openfirma verify` reads an
  archived OCSP response down to its `CertID`s and `certStatus` and
  associates it with the CA by the RFC 6960 hashes, but verifying the
  response's own signature needs the responder's certificate and the ESS
  matching of RFC 6960 4.2.2.2 — a chain of trust of its own. The CRL is the
  cryptographically checked revocation path; an archive that must stand
  entirely on its own should carry CRLs.
- **The time-stamp token's own signature** is not verified by
  `openfirma verify` either (openssl does it in the crosscheck suite); the
  verifier checks the imprint, which is the property the PDF layer owns.
