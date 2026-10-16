# ADR-0004: system keystores speak PKCS#11 through runtime FFI, not pure Rust

Date: 2026-10-16
Status: accepted

## Context

A certificate whose private key is protected — a smartcard (DNIe, FNMT, any
PKCS#11 token), the NSS shared database, the Windows certificate store, the
macOS keychain — cannot be signed with by loading the key. Something has to
ask the holder of the key to sign. AutoFirma reaches all four through Java:
`AOKeyStore` names them (`PKCS11`, `NSS`, `WINDOWS`, `APPLE`), and the PKCS#11
ones go through SunPKCS11's native layer, which is itself a C shim loaded at
runtime (`jna` + `libj2pkcs11.so`; its `AOKeyStoreManagerHelperPkcs11`). There
is no pure-Java PKCS#11 in AutoFirma either, because none exists that could
work: a PKCS#11 module is a vendor *plugin*, not a library with a stable ABI.

Rust has the same situation and the same options: hand-written `#[repr(C)]`
FFI loaded at runtime, or nothing. Writing against `pkcs11`/`pkcs11-core`
crates was considered; they are bindings of the same kind (and the maintained
ones pull in macros and an event layer sized like the thing we actually need),
so the question reduces to *whose* hand-written FFI, and ours costs about a
thousand lines we fully control.

## Decision

1. New crate `openfirma-keystore`, one trait:

```rust
pub trait SystemStore {
    fn certificates(&self) -> Result<Vec<StoreCertificate>>;
    fn sign_prehash(&self, cert: &StoreCertificate, alg: DigestAlg, prehash: &[u8])
        -> Result<Vec<u8>>;
}
```

   `StoreSigner<'_, S>` adapts a store's certificate into the existing
   `openfirma_core::signer::Signer` (ADR-0002), so every format crate keeps
   signing through `sign_prehash` and learns nothing about keystores. The CLI
   erases the concrete store (`Arc<dyn SystemStore>`) at its own edge.
2. PKCS#11 is implemented by hand: `dlopen`/`GetProcAddress` via `libloading`,
   the v2.40 function list as `#[repr(C)]` types, compile-time asserts pinning
   every offset we read. No build-time dependency on any vendor library; the
   module path comes from the user (`--store pkcs11:/path`).
3. NSS (`libsoftokn3`) is a PKCS#11 backend with its own initialize-args
   shape, not a separate protocol (see reasons).
4. Windows (`crypt32`/advapi32) and macOS (`Security.framework`) backends are
   `cfg`-gated modules that compile on their platform's CI targets. They are
   exercised only by compilation there: no CI runner holds a user-enrolled
   certificate, so their runtime behaviour ships unproven and is labelled as
   such below.

## Reasons

- **FFI vs pure Rust.** Pure-Rust cannot reach these keys at all — the whole
  point of the token is that the key never leaves it. Any claim otherwise is
  either software-key import (defeats the purpose) or a reimplementation of
  vendor middleware that will diverge from every real reader's behaviour.
- **dlopen, not link.** The spec makes `C_GetFunctionList` the only exported
  symbol and forbids linking against PKCS#11 import libraries; vendor modules
  are built as plugins and several (NSS) actively resist being loaded twice.
  AutoFirma does exactly this through SunPKCS11's native shim. It also means
  openfirma has no NSS/OpenSC dependency at build or install time: the flag
  names a path and the library is whatever lives there.
- **The ABI facts were measured, not trusted.** Every layout below was
  confirmed against live SoftHSM 2.6 and libsoftokn3 before being relied on;
  `types.rs` asserts them at compile time and tests/pkcs11.rs re-proves the
  function-list slots (`spec function k sits at byte 8k`) against a loaded
  module:
  - slot 0 is `{major, minor}` followed by six bytes of C alignment padding,
    so every entry point is at byte `8·k` for LP64/LLP64;
  - v2.40's table has no mutex/reserved slots between the two; a 3.x module
    returns a `CK_FUNCTION_LIST_3_x`, whose identical prefix makes it safe to
    read through our layout (spec 4.12) — modules reporting < 2.0 are refused
    before any call;
  - `C_GetSlotList` takes the count pointer **last**, and `CK_ATTRIBUTE` is
    natural-order `{type, p_value, ul_value_len}`;
  - `CK_TOKEN_INFO` must be sized 192 bytes (padding after the second UTC
    string) or NSS rejects the buffer.
- **NSS specifics** (each observed live, each in `nss.rs`/`nss_args.rs`):
  softokn3 redefines the spec's reserved initialize-args field as
  `LibraryParameters` and requires the full `configDir='sql:/path'` syntax —
  a bare `sql:/path` is answered with vendor error `0xce534351`, which
  `describe()` names as "NSS rejected the database configuration" instead of
  an opaque hex code. Its first token slot is the *generic crypto* module,
  which holds no certificates and refuses user login outright
  (`CKR_USER_TYPE_INVALID`); opening defaults to trying the name
  `NSS Certificate DB` (and its FIPS-mode twin). An empty PIN means "no
  password" but still has to be *logged in with*: softokn3 hides every object
  of an otherwise-unauthenticated session.
- **RSA without double hashing.** `CKM_SHAxxx_RSA_PKCS` makes the token hash
  the input, and a pre-hashed caller would sign `RSA(SHA256(digest))`. The
  only compliant shape is `CKM_RSA_PKCS` with the RFC 8017 DigestInfo built
  by us — verified: SoftHSM's output under the SHAxxx mechanisms equals
  software RSA-over-the-digest-bytes, exactly the silent corruption this rule
  prevents. ECDSA uses `CKM_ECDSA` (already pre-hashed per spec) with its raw
  r||s converted to the DER CMS expects. Anything else is refused by name.
- **PIN policy.** The PIN comes from the environment (`--pin-env VAR`) or a
  descriptor marker (`::`), never the command line — same rule as
  `--password` for PKCS#12, and the same reason (`ps`). Login happens at open
  time so a wrong PIN fails while the reader is still in hand; token flags
  (`CKF_USER_PIN_COUNT_LOW`/`FINAL_TRY`/`LOCKED`) are read before wording the
  error so "last try" is said before the lock, not after.

## Consequences

- CLI: `sign --store <descriptor> [--pin-env VAR] [--store-alias LABEL]` and
  `keystores list --store …`. The software paths (`--p12`, `--cert/--key`)
  are unchanged; a source conflict is refused before anything opens.
- Tests (tests/pkcs11.rs) run against the real SoftHSM token and NSS DB built
  by `tools/setup-test-keystores.sh`; every signature verifies twice, once
  with openfirma's own verifier and once with the openssl CLI — both caught a
  real bug while these backends were being written (a double-hash, an undee
  ECDSA), which is why neither verifier was dropped. Missing material skips;
  present-but-failing panics (`OPENFIRMA_REQUIRE_TESTS`).
- Deliberate omissions, each testable or documented:
  - CNG/NCrypt and PC/SC APDU paths: the Windows store already speaks through
    the legacy CSP provider (`CryptAcquireCertificatePrivateKey`), which is
    what AutoFirma's own helper uses; TPM-backed keys that expose no CSP will
    need NCrypt later.
  - `macos.rs` lists and refuses to sign ("not implemented yet"): there was
    no way to test a keychain prompt, and an untested keychain write is worse
    than an honest error. Windows compiles but has never run: same honesty
    applies at the feature-table level, not in code comments only.
  - musl static binaries cannot `dlopen` later than glibc-style anyway; the
    runtime load needs a dynamic loader, which every target we ship has.
  - The version-refusal branch is unreachable naturally (no pre-2.0 module
    exists), so it has a test hook env var and an `#[ignore]`d single-threaded
    test rather than being dead code without evidence.
