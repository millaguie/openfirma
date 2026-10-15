# ADR-0001: hand rolled CMS on top of `der`

Date: 2026-10-15
Status: accepted

## Context

CAdES and PAdES are both CMS `SignedData` (RFC 5652). RustCrypto publishes a
`cms` crate. We need to produce output that validates in VALIDe and matches
AutoFirma's structure attribute by attribute.

## Decision

Write the CMS layer ourselves on the `der` crate (0.8, current generation).
Do not depend on `cms`.

## Reasons

- `cms` stable (0.2.3) is pinned to the previous ASN.1 generation (`der` 0.7,
  `spki` 0.7, `sha2` 0.10). Only `cms` 0.3.0-rc.0 tracks `der` 0.8, and it
  drags `rsa` 0.10.0-rc.19 with it. Depending on release candidates for the
  core of a signature product is a bad trade.
- CAdES needs ESS attributes (`signingCertificateV2`, RFC 5035),
  `signaturePolicyIdentifier`, unsigned attributes carrying RFC 3161 tokens,
  and countersignature nesting. The `cms` crate's `SignedAttributes` API is not
  designed for arbitrary attribute injection.
- PAdES needs `certificates` and `crls` as `[0]`/`[1]` IMPLICIT sets with
  specific content for DSS/LTV, and `encapContentInfo` detached.
- DER conformance requires sorting `SET OF` by encoded value. We need that
  under our control because it is exactly the kind of thing a golden file diff
  will show.
- We need a decoder anyway for `openfirma-validate`. Writing the encoder and
  the decoder as two sides of the same module keeps them honest, and gives us
  round trip property tests.

## Consequences

Around 1200 lines of ASN.1 code to write and to get right, including the
`[0] IMPLICIT` retag rule for the signed attributes digest. Mitigated by the
golden corpus diff and by cross checking every structure against
`openssl asn1parse`.

If a mature `cms` 0.3 lands with ESS support, revisiting this is cheap: the
public API of `openfirma-cades` does not expose our DER types.
