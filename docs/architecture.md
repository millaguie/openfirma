# Architecture

## Layering

```
        openfirma-cli        openfirma-gui (later)
                 \              /
             openfirma-protocol      <- afirma:// verbs, wss://localhost, AutoScript compat
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
is confined to `openfirma-keystore`, `openfirma-protocol` (sockets, URL scheme
registration) and the installers.

## Crate responsibilities

- **openfirma-core**: digest and signature algorithm identifiers, OID table,
  certificate wrapper (DER plus parsed), the `Signer` trait, software signer
  backends, signature parameters and profiles shared by all formats.
- **openfirma-cades**: hand rolled CMS `SignedData` encoder/decoder on the `der`
  crate, CAdES-B-B/B-T/B-LT/B-LTA attribute sets, TSA client, countersignature
  and cofirm trees.
- **openfirma-pades**: minimal PDF reader (last trailer, classic cross-reference
  tables *and* cross-reference streams, object streams, FlateDecode with the PNG
  and TIFF predictors, dictionary surgery at the byte level so untouched objects
  are reproduced exactly), incremental update writer, `/ByteRange` and
  placeholder patching, AcroForm signature field, invisible and visible
  appearances. Planned: document timestamp, DSS dictionary and LTV. See
  `docs/pades.md` and `docs/adr/0003`.
- **openfirma-xades**: C14N/EC14N, XML-DSig transforms, XAdES 1.9 (the profile
  the Spanish administration uses, not only ETSI Baseline), FacturaE 3.2.
- **openfirma-keystore**: enumeration and selection of certificates across
  stores, key operations through the platform or a token.
- **openfirma-protocol**: the local service that browsers invoke. Wire
  compatible with AutoScript so existing sedes electrónicas work unchanged.
- **openfirma-validate**: verification of CAdES/PAdES/XAdES, revocation, chain
  building, and the report format VALIDe shows.
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
