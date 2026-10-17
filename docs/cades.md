# CAdES: measured behaviour and what is not implemented

The reference for everything here is the official AutoFirma 1.9 jar, driven
headlessly by `tools/golden/AutofirmaGolden.java` and diffed structurally by
`tools/golden-diff.sh` (case table in `docs/validation.md`). Where this file
says "measured", it means against that jar's output, not against a spec.

## Algorithm policy (finding M5)

Two knobs, one on each side of the door, both defaulting to the conservative
policy of ETSI TS 119 312 (`0.4.0.194112.1.3`):

- `CadesOptions::algorithms` gates `sign()`: a SHA-1 signature digest or an
  RSA key below `RSA_MINIMUM_BITS` (2048) is refused before any crypto runs,
  so weak output cannot leave the library by accident. The CLI exposes the
  opt-out as `--allow-weak-algorithms`, the shared browser request as
  `cades_allow_weak_algorithms`.
- `VerifyOptions::algorithms` gates `verify()`: the same refusal applies to
  the signature value, to every certificate signature along the chain and to
  CRLs. `AlgorithmPolicy::All` opts out for callers archiving old signatures,
  and takes responsibility for what it then shows as valid — which is exactly
  why it is not the default: silently reporting OK on a SHA-1 or 1024-bit-RSA
  signature is how a forgery reaches a citizen.

AutoFirma itself signs whatever it is handed (`CAdESParameters` has no policy;
its own VALIDe profile refuses what its signer produces). openfirma refuses by
default because the tool, not the user's validator, decides when the artifact
is created.

## SigningCertificate v1 vs V2 (finding M1)

Measured rule, `CAdESParameters.load`: SHA-1 signs with the v1
`signingCertificate`, SHA-2 digests with V2 — RFC 5035 defines V2 for SHA-2.
`sign()` reproduces it and `verify()` accepts:

- a V2 attribute always;
- a v1 attribute when the signature digest is SHA-1 (AutoFirma's SHA-1 files,
  and all pre-2011 CAdES-BES) or when verifying in ts_mode (RFC 3161 names
  either);
- never a v1 attribute over a SHA-2 digest — that shape no producer of the
  ecosystem writes.

The `policies` field of ESSCertIDv2 carries the signer certificate's
`certificatePolicies`, copied by default (`include_certificate_policies`,
AutoFirma's `doNotIncludePolicyOnSigningCertificate=false`). BouncyCastle
encodes the `policies` field FLATTENED — the `PolicyInformation` SEQUENCEs sit
directly at the parent level, no wrapper tag of any kind (measured against the
jar; both an implicit `[0]` and an explicit SET produce a visible golden diff).

## mime-type and contentHint (findings M3, B2)

`mime-type` is a UTF8String under `0.4.0.1733.2.1` (`id-aa-ets-mimeType`, what
BouncyCastle's `CMSAttributes` uses; the old IA5String tag was ours alone).
`contentHint` defaults to AutoFirma's generic `"binary"` description: its
Spanish per-type descriptions ("Texto plano") come from a jmimemagic database
openfirma does not ship, and shipping one would mean our magic guessing file
types. `--no-content-hint` leaves the attribute out; PAdES pins `None` (the
hint is fixed by the profile there). Because we never guess a type, openfirma
never writes AutoFirma's jmimemagic probe companion attribute — the one the
jar adds when MIME detection runs and no explicit type was given. Callers who
know the type pass it explicitly (`--mime-type`, `mimeType=` extraParam on
AutoFirma's side); the golden `mime` case pins that equivalence.

## signaturePolicyIdentifier / commitmentTypeIndication (finding M9)

`--signature-policy` writes EN 319 122-1 6.4 with the sede's OID
(`2.16.724.1.3.1.1.2.1.9` and friends). `sigPolicyHash`:

- a sede that publishes an assertion passes its digest through
  `--signature-policy-hash` (AutoFirma's `policyIdentifierHash`, base64 there,
  hex here);
- with no assertion, AutoFirma's JSON parser leaves the hash as the byte
  `0x01` and writes a DigestInfo of the signature's own digest algorithm over
  it; openfirma emits exactly that placeholder (measured: `SEQUENCE {
  SEQUENCE { OID, NULL }, OCTET STRING 01 }`).

`--commitment-type` writes EN 319 122-1 6.5 as one bare CommitmentTypeIndication
SEQUENCE around the type OID — the shape `CommitmentTypeIndicationsHelper`
produces for an unqualified indication. The golden `policy_commit` case runs
both attributes against a real jar invocation carrying the AGE parameters.

## Time-stamp nonce (finding M7)

`random_nonce()` draws the query nonce from `getrandom`; neither side may be
absent or mismatched when the query carried one: `token_from_response(..,
Some(&query))` runs `request_nonce`/`token_nonce`/`check_nonce` and refuses a
token answering someone else's query. A real openssl TSA echoes the nonce only
when the request carries one, which is what `tests/tsp_crosscheck.rs` uses to
prove both directions.

## Not implemented (documented gaps, wave 4c)

These are known absences, not oversights; each says what it would take:

- **CAdES co-signature** (`AOCAdESSigner.cosign`, a second `SignerInfo` over
  an existing SignedData). Nothing in openfirma produces or consumes one yet.
  The browser protocol names the operation and refuses it — with no golden of
  what a sede expects back, producing one would be guessing.
- **Counter-signature** (`id-ct-esConnector`, ETSI TS 102 778; AutoFirma's
  `countersign` wraps SignerInfo signedAttrs in an eContentType'd blob). Same
  situation: no golden, refused by name over the browser protocol.
- **signer-DSS / other signature-policy qualifiers**: only `sigPolicyId` +
  `sigPolicyHash` are written; `sigPolicyQualifiers` (the URI qualifier of EN
  319 122-1) has no encoder.
- **ESS signing-certificate V3** (hash of the whole certificate, TS 102 918):
  only v1/V2 exist; a verifier meeting V3 fails the check as unknown, it does
  not silently pass.
- **`signerLocation`, `signingCertificateV3`, claimed roles in
  `signedAttrs`** (AutoFirma's `_signerLocation`, `_claimedRoles`, metadata
  attributes). The encoders are absent; verification ignores the attributes it
  does not interpret rather than refusing them, except where a profile rule
  makes absence itself the violation (contentType, messageDigest, ESS cert).
- **CAdES EPES**: `approvedPolicy` and its commit-type vocabulary are out of
  scope for the same reason counter-signature is — no measured golden.
