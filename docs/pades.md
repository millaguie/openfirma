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
