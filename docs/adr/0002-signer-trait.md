# ADR-0002: one crypto generation, and the Signer trait

Date: 2026-10-15
Status: accepted

## Context

Two problems at once.

RustCrypto is mid migration. `der` 0.8 / `spki` 0.8 / `x509-cert` 0.3 /
`digest` 0.11 / `signature` 3 / `sha2` 0.11 form one coherent generation.
`rsa` stable (0.9.10) is still on `digest` 0.10 / `signature` 2 / `spki` 0.7,
so mixing it in means two versions of `sha2` and `spki` in the tree and manual
DER re-encoding to cross between them.

Worse, `rsa` 0.9 carries RUSTSEC-2023-0071, the Marvin attack on PKCS#1 v1.5,
unfixed in the 0.9 line. `cargo audit` would flag the core of a signature
product on day one.

Separately, most real signing will never happen in process. DNIe, FNMT cards,
PKCS#11 tokens, Windows CNG and the macOS keychain all perform the asymmetric
operation themselves and only want a digest.

## Decision

1. Use the current RustCrypto generation everywhere: `der` 0.8, `spki` 0.8,
   `const-oid` 0.10, `x509-cert` 0.3, `digest` 0.11, `sha1`/`sha2` 0.11,
   `signature` 3, `p256` 0.14.
2. For RSA use `rsa = "=0.10.0-rc.19"`, pinned exactly. It is the only pure
   Rust RSA on this generation and it fixes the Marvin finding. The pin is
   exact so an rc bump never happens silently. Revisit when 0.10 is stable.
3. All signing goes through one trait in `openfirma-core`:

```rust
pub trait Signer {
    fn certificate(&self) -> &CertificateHandle;
    fn chain(&self) -> &[CertificateHandle];
    fn key_algorithm(&self) -> Result<KeyAlgorithm>;
    fn sign_prehash(&self, digest: DigestAlg, prehash: &[u8]) -> Result<Vec<u8>>;
}
```

Format crates depend on this trait and on nothing else in the crypto space.
Backends implement it: software RSA, software ECDSA, PKCS#11, CNG, SecKey,
PC/SC APDU.

## Consequences

- One version of every crypto crate. No DER re-encoding to cross `spki`
  versions, no duplicated `sha2`.
- `cargo audit` clean on the crypto core.
- A release candidate in the dependency tree. Accepted for now: it is pinned,
  it is 19 releases into the rc series, and the alternative is a known
  vulnerability in stable. Tracked in the README as a known risk.
- Because formats only ever see `sign_prehash`, hardware backends are the
  natural fit and the software backend stays a small, replaceable piece.
