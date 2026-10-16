# Architecture

## Layering

```
        openfirma-cli        openfirma-gui (later)
                 \              /
             openfirma-browser       <- afirma:// verbs, loopback endpoint (docs/adr/0005)
                        |
        +---------------+----------------+
        |               |                |
  openfirma-cades  openfirma-pades  openfirma-xades      <- signature formats
        \               |               /
         \              |              /
              openfirma-core                       <- algorithms, certs, Signer trait, params
                        |
              openfirma-keystore                   <- where keys live
                        |
   +--------+-----------+-----------+---------+
   | pkcs12 | pkcs11    | capi/cng  | keychain| nss  | pcsc (DNIe, Ceres)
```

Rule: format crates never talk to a keystore directly. They receive an
`openfirma_core::Signer` and a digest, and produce bytes. That keeps every
format testable with a fixed software key, and it is what makes the hardware
backends swappable.

Rule: nothing above `openfirma-core` may depend on a platform. Platform access
is confined to `openfirma-keystore`, `openfirma-browser` (loopback sockets, URL
scheme registration) and the installers.

## Crate responsibilities

- **openfirma-core**: digest and signature algorithm identifiers, OID table,
  certificate wrapper (DER plus parsed), the `Signer` trait, software signer
  backends, signature parameters and profiles shared by all formats.
- **openfirma-cades**: hand rolled CMS `SignedData` encoder/decoder on the `der`
  crate, the CAdES-B-B attribute set, RFC 3161 requests and tokens for B-T
  (transport stays with the caller), the reading and checking of revocation
  data shared with PAdES (`openfirma_cades::revocation`: CRL signature
  verification, OCSP response parsing), and the cryptographic verifier
  (`openfirma_cades::verify`): `messageDigest`, the signature value over the
  re-tagged signed attributes, `signingCertificateV2`, and chain building
  against supplied trust anchors. The CAdES long-term levels ES-LT/ES-LTA are
  deliberately out of scope: the long-term path is PAdES B-LT/B-LTA
  (`docs/pades.md`). Planned: countersignature and cofirm trees.
- **openfirma-pades**: minimal PDF reader (last trailer, classic cross-reference
  tables *and* cross-reference streams, object streams, FlateDecode with the PNG
  and TIFF predictors, dictionary surgery at the byte level so untouched objects
  are reproduced exactly), incremental update writer, `/ByteRange` and
  placeholder patching, AcroForm signature field, invisible and visible
  appearances, and the long-term levels as further appended revisions: the
  `/DSS` validation data with its per-signature `/VRI` index (B-LT) and the
  `/DocTimeStamp` field (B-LTA), plus the verifier that judges both. See
  `docs/pades.md` and `docs/adr/0003`.
- **openfirma-xades**: strict hand rolled XML reader that keeps the byte spans
  of the input (the signed output preserves the original document bytes and
  only splices the signature in), Canonical XML 1.0 inclusive with subtree
  namespace inheritance, enveloped XML-DSig and the XAdES-B-B qualifying
  properties of ETSI EN 319 132-1 as AutoFirma's baseline profile writes
  them. Planned: the other signature shapes (enveloping, detached), the
  advanced profile, XAdES 1.9 policy handling and FacturaE 3.2. See
  `docs/xades.md`.
- **openfirma-keystore**: enumeration and selection of certificates across
  stores, key operations through the platform or a token.
- **openfirma-browser**: the local service that browsers invoke: `afirma://`
  URI parsing and dispatch onto the format crates, the loopback endpoint with
  its one-time-token/Origin/Host rules, and the OS scheme registration files.
  The wire shapes are measured off AutoFirma; its self-signed wss transport is
  deliberately not reproduced — docs/adr/0005-browser-protocol.md records what
  a real sede still needs before end-to-end AutoScript compatibility.
- **openfirma-validate**: revocation, certificate policy, validation data and
  the report format VALIDe shows. The cryptographic verification of CAdES and
  PAdES already lives in the format crates, behind `openfirma verify`; PAdES
  verification extracts each signature's covered bytes and delegates to the
  CAdES verifier, so every signature of a co-signed document is checked.
- **openfirma-cli**: `openfirma sign|verify|list-certs|serve`.

## Why hand rolled CMS

The `cms` crate (RustCrypto) is stable at 0.2.x on the previous generation of
the ASN.1 stack (`der` 0.7), and only reaches the current generation in a
release candidate. More importantly, CAdES needs exact control over:

- attribute ordering inside `SET OF Attribute` (DER requires sorted encoding),
- the `[0] IMPLICIT` retag of `signedAttrs` when computing the signature,
- arbitrary ESS attributes (`signingCertificateV2`, `signaturePolicyIdentifier`),
- unsigned attributes carrying RFC 3161 tokens,
- the `certificates` and `crls` IMPLICIT sets for PAdES DSS.

Hand rolling these on `der` 0.8 is around 1200 lines and gives byte level
control, which is what the golden file diffing in `docs/validation.md` needs.
See ADR-0001.

## Signing is always a prehash operation

Real signing happens in a token, in the OS keystore or in a smartcard. Those
backends want a digest, not a document. So `Signer::sign_prehash` is the only
signing entry point, and every format computes its own digests and hands over
bytes. See ADR-0002.
