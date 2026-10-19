# XAdES: what we are implementing against

The target is the output of the **official AutoFirma 1.9** signing
`testdata/inputs/simple.xml` with `testdata/certs/signer-rsa.p12`, XAdES-B-B
(`profile=baseline`, `format=XAdES Enveloped`), RSA SHA-256. Measured, not read
from a specification: AutoFirma's own jar was driven headlessly by
`tools/golden/AutofirmaGolden.java`, and the result was reduced to a comparable
form by `tools/golden/xml-normalize.py`.

`testdata/golden/` is in `.gitignore`, so this file is the durable copy of what
it found. Regenerate with `tools/golden-diff.sh` whenever the reference
AutoFirma version changes, and diff against this.

## Which profile is "B-B"

AutoFirma's *default* profile is `advanced`, and its default XAdES output for
an XML file is the legacy XAdES-B: `SigningCertificate` **v1** (with
`IssuerSerial`: `X509IssuerName` as an RFC 2253 string plus
`X509SerialNumber` in decimal), and a third `ds:Reference` signing the
`ds:KeyInfo`. AutoFirma's own format detector
(`SignatureFormatDetectorXades`) only calls a signature XAdES-B-B when it
carries `SigningCertificateV2`, which is what `profile=baseline` produces, per
ETSI EN 319 132-1. So `--format xades-b-b` implements the **baseline** profile,
measured below. The advanced profile was measured too; both variants share
everything except the two differences named above, and the advanced variant is
not implemented (scope: B-B only).

## Document shape (enveloped)

The `ds:Signature` is appended as the **last child of the original root
element**. Serialization of the output, measured:

```
<?xml version="1.0" encoding="UTF-8"?><documento Id="doc-prueba" version="1.0">
  ...original content, byte for byte...
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="Signature-<uuid>-Signature">...</ds:Signature></documento>
```

- the declaration is normalized to exactly `<?xml version="1.0" encoding="UTF-8"?>`:
  `standalone` is dropped, a missing declaration is added, no newline follows it,
- nothing follows the root end tag: a trailing newline in the input is dropped,
- document-level nodes (anything outside the root) do **not** survive: comments
  and processing instructions alike, an `xml-stylesheet` among them. Measured
  against AutoFirma on three inputs — a prolog PI, an epilog PI, and both
  together (`testdata/inputs/pi-doc-level.xml` carries that shape) — whose
  output contained none of them and no comment either; it writes the declaration
  and the document element and stops.
  That is not only fidelity. The data reference is the **root element subtree**:
  the enveloped transform hands that to the canonicalizer, the XPath filter
  agrees, and every validator recomputes exactly that, so a document-level
  sibling is never in the bytes a digest covers — keeping one would put an
  unprotected node inside a signed file. The reader still parses prolog and
  epilog nodes (the encoding check reads them) and the input keeps them; the
  output does not, and the CLI says nothing about it, as AutoFirma says nothing.
  An earlier version of this section claimed the opposite — that the data
  transform "canonicalizes the document *including its prolog PIs*", following
  the C-1 follow-up — and the code did that, which made every PI-carrying input
  produce a signature that `xmlsec1` rejected with `REFERENCE` failure while
  AutoFirma's own signature over the same file verified. Round two found it
  where B-4's stale comment pointed; the tests that pin it are
  `sign_structure::document_level_pis_and_comments_are_not_in_the_signed_file`,
  `xmlsec_crosscheck::xmlsec_verifies_a_signature_over_a_document_with_document_level_pis`
  and `autofirma_verify::autofirma_verifies_a_signature_over_a_document_with_document_level_pis`.

## SignedInfo

```
ds:CanonicalizationMethod  http://www.w3.org/TR/2001/REC-xml-c14n-20010315
                           C14N 1.0 inclusive, without comments
ds:SignatureMethod         http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
```

References, in this order (attribute order as serialized: `Id`, `Type`, `URI`):

1. **Data reference.** `Id="Reference-<uuid>"`, `URI="#<root Id attribute>"`
   when the root element carries an attribute literally named `Id`, otherwise
   `URI=""`. Transforms, in order:
   - `http://www.w3.org/2000/09/xmldsig#enveloped-signature`
   - `http://www.w3.org/TR/2001/REC-xml-c14n-20010315`
   - `http://www.w3.org/TR/1999/REC-xpath-19991116` with
     `<ds:XPath xmlns:ds="http://www.w3.org/2000/09/xmldsig#">not(ancestor-or-self::ds:Signature)</ds:XPath>`
2. **SignedProperties reference.**
   `Type="http://uri.etsi.org/01903#SignedProperties"` (namespace *without*
   version), `URI="#<sigId>-SignedProperties"`, no `Transforms`, no `Id`.
3. **KeyInfo reference** (advanced profile only): `URI="#<sigId>-KeyInfo"`,
   no Type. In baseline the KeyInfo exists but is *not* signed.

Digest method everywhere: `http://www.w3.org/2001/04/xmlenc#sha512` — SHA-512
is AutoFirma's `referencesDigestMethod` default, independent of the signature
algorithm.

Net effect of the data reference transform chain, verified by recomputation:
**SHA-512 over the C14N 1.0 (inclusive, no comments) of the referenced element
subtree — the root for both URI shapes — with every `ds:Signature` subtree
removed and surrounding whitespace text kept**. The enveloped transform and the
XPath filter both strip signatures; for a document with no other signatures the
result is one canonicalization pass.

## SignatureValue and KeyInfo

- `ds:SignatureValue Id="<sigId>-SignatureValue"`: base64 on **one line**.
  AutoFirma installs Apache Santuario as its XML-DSig provider specifically to
  avoid line breaks in base64.
- `ds:KeyInfo Id="<sigId>-KeyInfo"`: `ds:X509Data` with the **whole chain**,
  signer first (each `ds:X509Certificate` base64 on one line), then
  `ds:KeyValue/ds:RSAKeyValue` with `Modulus` (256-byte big-endian, leading
  zero stripped) and `Exponent` (minimal encoding). **RSA keys only**: for an
  EC key AutoFirma omits `KeyValue` entirely (a FIXME in their source says
  their validator does not accept Santuario's `ECKeyValue`), which we mirror.

## Qualifying properties (the B-B level)

Inside a `ds:Object` with **no attributes at all** (no `Id`, no `MimeType`):

```
<xades:QualifyingProperties xmlns:xades="http://uri.etsi.org/01903/v1.3.2#"
    Id="<sigId>-QualifyingProperties" Target="#<sigId>-Signature"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
```

The `xmlns:ds` redeclaration on this element is what AutoFirma's jXAdES emits,
in that attribute order, and we reproduce it.

`xades:SignedProperties Id="<sigId>-SignedProperties"`:

- `xades:SignedSignatureProperties`
  - `xades:SigningTime`: `xs:dateTime`, seconds precision, local UTC offset
    (`2026-10-15T21:32:42+02:00`).
  - `xades:SigningCertificateV2` → `xades:Cert`:
    - `xades:CertDigest`: `ds:DigestMethod` SHA-512 +
      `ds:DigestValue` = SHA-512 of the signer certificate **DER**;
    - `<xades:IssuerSerialV2/>` — **empty**. Deliberate on AutoFirma's side:
      `XAdESUtil` cites ETSI EN 319 132-1 v1.1.1 §6.3 note j) (a B-Level
      signature carries only the signing certificate in
      `SigningCertificateV2`), and their jXAdES still emits the empty element.
      We reproduce the empty element, not a value.
- `xades:SignedDataObjectProperties`
  - `xades:DataObjectFormat ObjectReference="#Reference-<uuid>"` (the Id of the
    data reference):
    - `<xades:Description/>` empty — jXAdES always emits it;
    - `xades:ObjectIdentifier` →
      `<xades:Identifier Qualifier="OIDAsURN">urn:oid:1.2.840.10003.5.109.10</xades:Identifier>`
      — the OID AutoFirma's jmimemagic table assigns to `text/xml` — plus
      another empty `xades:Description`;
    - `xades:MimeType` = `text/xml`, forced for XML input;
    - `<xades:Encoding/>` empty.

Absent, and they must stay absent: `SignaturePolicyIdentifier` (no policy
configured — EPES is a different profile), `UnsignedProperties`,
`CommitmentTypeIndication`, `SignatureProductionPlace`, `SignerRole`,
`QualifyingPropertiesReference`.

The digest of the SignedProperties reference is taken over the **C14N 1.0 of
the SignedProperties element including its inherited namespace declarations**,
so the canonical form begins
`<xades:SignedProperties xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Id="...">`.
Verified by recomputation against AutoFirma's output.

**Inherited means inherited from the whole document, not from the template.**
Review 03 found (C-1) that canonicalizing SignedProperties — and SignedInfo —
over a detached fragment missed what the signed document's own root puts in
scope: with `xmlns="urn:x"` or `xml:lang` on the root, a validator re-emits it
on both elements (§2.3 re-emits every binding in scope at a subtree root;
§2.4 propagates the ancestors' `xml:` attributes), so the fragment's digest
matched nothing and every FacturaE-shaped file was invalid. AutoFirma cannot
produce that bug — Santuario canonicalizes the live DOM after `appendChild` —
and its own output proves the rule: recomputing our old fragment digests fails
against `ns-root.af.xml`, while the in-place form passes. openfirma now signs
the same way it gets read: the final bytes are spliced, reparsed, and both
elements are canonicalized at the position they occupy in that tree (see
`sign.rs`, "the template fragments"). The golden corpus carries `ns-root.xml`
for exactly this.

## Ids and what is volatile

`sigId = "Signature-<uuid4>"`, derived Ids `-Signature`, `-SignatureValue`,
`-KeyInfo`, `-QualifyingProperties`, `-SignedProperties`; the data reference
gets its own `Reference-<uuid4>`. Two signing runs of the same input are byte
identical except for exactly four value classes (measured):

1. both uuid4s — in the six `Id` attributes, in `Target`, in the
   SignedProperties reference `URI`, in `DataObjectFormat/@ObjectReference`;
2. the `xades:SigningTime` text;
3. the `DigestValue` of the SignedProperties reference (it covers the time);
4. the `ds:SignatureValue` text (it covers everything).

The normalizer neutralizes exactly those. Everything else is stable and must
match: the data reference `DigestValue`, the `CertDigest` value, the
certificate base64s, `Modulus`/`Exponent`, and every algorithm URI.

## Gotcha: canonicalizing SignedInfo

The `ds:XPath` element carries an explicit `xmlns:ds` declaration **in the
file**, but the canonicalized SignedInfo that is signed does **not** re-emit
it: C14N 1.0 suppresses a declaration when the nearest inclusive ancestor
already rendered the same prefix→URI binding (here `ds:SignedInfo` renders the
inherited `xmlns:ds`). Measured against the bytes Apache Santuario signs.
Consequences:

- lxml/libxml2 `method="c14n"` emits the redundant declaration and therefore
  cannot reproduce the signed bytes of a SignedInfo containing an XPath
  transform; `xmlsec1` (its own spec-conformant C14N) verifies fine. The
  normalizer recomputes reference digests with lxml (those subtrees carry no
  redundant redeclarations, verified to match) and delegates the
  SignatureValue check to `xmlsec1`.
- Our Rust C14N must implement the suppression rule, or our own signature
  will not verify against our own SignedInfo; both the `xmlsec1` crosscheck
  and the AutoFirma verify test would catch that.

## What we deliberately do differently

Recorded so a future diff is read as a decision and not as a bug, the standard
set by `docs/pades.md` and `docs/adr/0003`.

1. **SigningTime zone.** AutoFirma writes local time with its offset;
   openfirma writes UTC (`...Z`). std Rust has no timezone database, the
   `xs:dateTime` instant semantics are identical, and the normalizer
   neutralizes the value anyway.
2. **Serialization of the original content.** AutoFirma round-trips the whole
   document through a Java DOM: entity references come back as literal
   characters, attribute quoting is normalized, doc-level nodes are dropped.
   openfirma preserves the input bytes of the root element verbatim and splices
   the signature before the root's closing tag, the same "do not touch the
   original bytes" philosophy as the PAdES incremental update. After parsing,
   both sides are structurally identical and every C14N erases the
   serialization differences, so no digest can diverge. One measured edge:
   AutoFirma normalizes the declaration (see above), and we emit the same
   normalized declaration rather than the input's.
3. **Input encoding.** UTF-8 only, and the two ways a file can say otherwise
   are refused in two places. Bytes that do not decode as UTF-8 are refused by
   the reader, naming the cause; AutoFirma would transcode through its
   serializer. A declaration whose `encoding` names anything other than UTF-8
   (or its registered alias `utf8`, or US-ASCII) is refused too, naming what it
   declared and the `iconv` to run: signing bytes while a validator re-reads
   them through the declared encoding signs different text than what gets
   verified. A document written in UTF-16 never reaches that reader: the
   detector reads UTF-8, so a UTF-16 `<` is `<` `NUL` and the answer for those
   bytes is `Data` — deliberately, because a detached CAdES over the file as it
   stands is a signature it *can* make, and calling them `Xml` would trade a
   working option for a guaranteed error. Asking for an XML shape over them is
   therefore refused by the shared format gate, and that sentence names the
   encoding, the `iconv` and the conversion-free alternative; round two's N-6 is
   why it is that specific — until then it said "this file holds plain data"
   about a `factura.xml` the person could see was XML, while this section
   claimed the encoding was named. Same for a version other than 1.0,
   whitespace in front of the declaration, and namespace declarations that XML
   itself forbids (duplicate prefixes on one element, `xmlns:p=""`): every
   validator's parser (libxml2) refuses those documents, so signing them would
   ship bytes nobody can even re-open.
4. **DTD and entities.** Refused: a DOCTYPE is rejected before parsing (XXE
   safety, and no golden input has one) and any entity reference beyond the
   five predefined ones is an error. The error says to sign the expanded
   document.
5. **ECDSA keys.** Supported on our side (`ecdsa-sha256` URI, no `KeyValue`,
   signature value in IEEE P1363 `r||s` form as XML-DSig requires). AutoFirma
   headless *cannot sign* EC XAdES on this JVM — its installed Santuario
   provider rejects SunEC keys (`No installed provider supports this key`) —
   so there is no golden for it; the EC path is crosschecked with `xmlsec1`
   instead.
6. **Not implemented** (out of scope, one reason each): enveloping, internally
   detached and externally detached shapes (the enveloped golden covers the
   XML document case, and non-XML input is refused with an error pointing to
   CAdES); the advanced profile's `SigningCertificate` v1 + signed KeyInfo
   (legacy XAdES-B, not B-B); XSL stylesheet co-signing; manifests; ASiC
   containers; X-L/X-C/X-LTA levels; countersignatures.

## The golden case

`tools/golden-diff.sh` runs `run_xades_case`: AutoFirma signs
`testdata/inputs/simple.xml` (`SHA256withRSA`, `format=XAdES Enveloped`,
`profile=baseline`), openfirma signs the same input with
`--format xades-b-b`, both sides go through `xml-normalize.py`, and the dumps
are diffed. Before diffing, the normalizer recomputes every `ds:Reference`
digest over the canonicalized bytes and has `xmlsec1` verify the
`SignatureValue` on each side, so a MATCH also means both files satisfy their
own integrity claims.
