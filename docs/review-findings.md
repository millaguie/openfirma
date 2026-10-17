# Review findings: what was found, and where each one stands

Seven independent reviews were run against the repository (2026-10-16/17),
one per area: CAdES/core, PAdES, XAdES, keystores, browser protocol, GUI/CLI,
and build quality/CI/documentation. The reports themselves are not in this
repository because they contain repro material (hand-built hostile inputs,
paths to local fixture trees) that must not become test data by accident;
this file is the public record: what was found, and its status here.

Statuses mean:

- **fixed** — code changed on `main`, with a test that fails without the fix
  unless noted. The commit is named.
- **documented** — the claim or document was corrected instead of the code,
  because the honest statement was the defect (or because no fix exists).
- **deferred** — real finding, work not done yet; the note says what doing
  it would take and why it waits.
- **not verifiable here** — needs a machine this project does not have
  (real Windows card reader, real sede server, signed macOS/Windows runs).
  These stay declared as untested wherever they are user-visible.

## CAdES / core (`01`)

| ID | Finding | Status |
|---|---|---|
| C1 | Chain building accepted a non-CA issuer as an anchor | fixed (`4c1d05f`: only certificates the basic-constraints/key-usage rules mark as authorities may issue others) |
| C2 | `verify_token_signature` accepted a re-written TSTInfo inside a seal token | fixed (`c3b2226`: the seal is bound to the bytes it seals; nonce per query in `b0e5a34`) |
| A1 | `verify` silently ignored `--content` when the signature embeds its own content | fixed (verify now refuses when embedded and supplied content differ — see `crates/openfirma-cades/tests/verify.rs`) |
| A2 | Report announced "B-T" from attribute presence without checking the seal | fixed (`c3b2226`, and the verdict wording says what was actually checked) |
| A3 | Hostile DER panicked the TSP parser | fixed (`a7fef32`: one bounds-checked DER cursor for the workspace; hostile bytes are errors) |
| A4 | OCSP responses counted as revocation data without verifying their signature | fixed (`c3b2226`: OCSP bound to its issuer; the window test in `tests/ocsp.rs` pins it) |
| M1 | SHA-1 handling differed from AutoFirma's (verification refused, signing differed) | fixed (`00c13b0`, `826d296`: opt-out travels on openfirma's side only, golden-pinned) |
| B1..B8 | ECDSA NULL parameter, contentHint default, stale docs, three DER cursors, malformed signed-attr encoding, dump mislabelled BMPString, minor verifier checks | fixed across `730ccaa`, `83ccfc2`, `a7fef32`, `00c13b0`; B5's attribute shape is golden-pinned |

## PAdES (`02`)

| ID | Finding | Status |
|---|---|---|
| M-1 | Orphan `/Info` object left by signing | fixed (wave 2: revisions carry the previous trailer, `7d3c732`) |
| M-2 | PDF/A: XMP not updated | fixed with the honest alternative (`e1a13b4`: PDF/A documents are refused rather than silently broken) |
| M-3 | `/ByteRange` hole not bound to its dictionary's `/Contents` | fixed (`32b797c`: say what the hole holds before calling it a signature) |
| M-4 | No check of unregistered signatures / `/Perms /UR3` removal | fixed (`e1a13b4`: document's own rules honoured before signing; `66d60e6` reports certification broken by later revisions) |
| M-5 | Page-tree walk without visited memory (exponential on hostile files) | fixed (wave 2 bounds/budget work, `753a444`, `3154e84`) |
| M-6 | Panics from offsets outside the file and from `/W` | fixed (`3154e84`: every offset the file claims is bounded; encrypted PDFs refused at the trailer) |
| B-1 | Missing `/Size` read as 0 | fixed (wave 2, bounds-checked reader) |

## XAdES (`03`)

| ID | Finding | Status |
|---|---|---|
| M-1 | Panic on an attribute with no value at end of file | fixed (`168c3a0`: a cut-off attribute value is an error) |
| M-2 | Quadratic cost in attributes/namespaces during canonicalization | fixed (`87ef144`: canonicalize in linear time) |
| M-3 | Reader accepted malformed XML and signed what nothing parses | fixed (`87ef144` refuses non-CMS bytes; `80519b2`/reader hardening; xmlsec1 cross-check installed in CI so a third party judges the output) |
| M-4 | Certificate chain never reached KeyInfo with `--p12` | fixed (wave 4: chain travels to KeyInfo; golden case `nsroot`) |
| B-1..B-4 | Empty `Id` → `URI="#"`, no NCName validation, duplicate `Id` undetected, dead code | fixed (`575380c`: the Id a signature points at is single, named, and not empty; linear-time scan) |

## Keystores (`04`)

| ID | Finding | Status |
|---|---|---|
| C1 | PKCS#11 ABI wrong on Windows (CK_ULONG=usize, unpacked structs) → memory corruption with any real card DLL | fixed in code (`0238953`, `d38568b`, `9390f9a`, `d8b097e`: cfg'd 4-byte CK_ULONG on Windows, pack(1) structs per `cryptoki.h`, slot offsets through `offset_of!`), and CI runs the PKCS#11 tests natively on i686 + x86_64 Windows. **not verifiable here**: no real card DLL ever ran against it — SoftHSM on Windows is not provisioned; declared in README/platforms docs |
| C2 | Could not open Firefox/NSS `.p12` exports (BER indefinite lengths) | fixed (`e7d5715`, `66d4a65`) |
| A1–A3 | Java-11 keyLength PBKDF2, RC2-40, empty-password containers | fixed (`66d4a65`; interop fixtures generated in CI where openssl exists — `18a6eb0`) |
| A4 | No `CKA_ALWAYS_AUTHENTICATE` context login: qualified signing keys never signed | fixed (`2ba4b3f`) |
| A5 | DNIe authentication certificate / keyUsage not filtered: would sign with an auth-only cert silently | fixed (`d3afa45`: AutoFirma's default filters in one shared rule; CLI/GUI pin it) |
| A6 | Windows CAPI store: flags wrong (CNG handle passed to legacy CSP APIs), no SILENT flag on listing | fixed in code (`356fafa`: CAPI and CNG handles kept apart, `CERT_NCRYPT_KEY_SPEC` dispatches to NCrypt; ALLOW_NCRYPT+SILENT on listing). **not verifiable here**: no Windows runner has a smart card; the runtime path is declared untested |
| A7 | NSS: no Firefox profile handling, no `pkcs11.txt` modules, library not found on common paths | fixed (`0f4f9b0`, `22b9d4d`) |
| B1–B7 | Password copy not zeroized in KDF, `key_matches` OpenSSL order, single slot only, NSS read-write opens, `dpkg-architecture` via PATH, minor FFI robustness, lying comments | fixed across `66d4a65`, `118f3c0` (read-only NSS), `34eaca8` (comments now say what the code does) |
| B8 | `open_store` duplicated between CLI and GUI | fixed (`44c4ffe`: one `open_store` in openfirma-keystore, both frontends call it) |

## Browser protocol (`05`)

The whole protocol layer was rewritten against AutoFirma 1.9.1's recorded
sources (ADR-0005 amended, `80ff70e`, `7606a6e`): response and error shapes
(M-1, M-2), accepted format-name spellings including the ones that used to
sign wrong in silence (M-3, M-4), `stservlet`/`key` behaviour (M-5), config
file private-mode rules (M-6/B-2), ADR premise corrected (M-7), one token
per request instead of per process (M-8).

| ID | Finding | Status |
|---|---|---|
| M-9 | Tests validated our own interpretation, not AutoFirma | fixed: fake_sede drives the recorded page (`ea9ce10`), and `sede_crosscheck` pins the round trip against recorded shapes |
| B-1..B-6 | `--register` broke on a fresh account and ignored `XDG_DATA_HOME`; macOS has no real registration; `algorithm` over-permissive; HTTP parser details; hand-rolled JSON extraction; comments that lied | fixed (`b2a9aea`, `05d910f`, wave 4 commits); macOS registration remains advice-to-the-user, honestly documented as such |

## GUI / CLI (`06`)

| ID | Finding | Status |
|---|---|---|
| M-1 | Drag-over loaded the file on every frame | fixed (c557f… wave 4e: `c58831a` threads + drop handling) |
| M-2 | "Who signed" printed almost the whole DN including the DNI number | fixed (`c58831a`: named per the shared signer policy) |
| M-3 | Technical details of a verdict could not be opened | fixed (`c58831a`) |
| M-4 | No back button on the password screen | fixed (`c58831a`) |
| M-5 | No visible signature / co-signing in the window | deferred: visible-segment rendering is a feature, not a defect; signing without it stays honest (the verdict panel says what was checked) |
| M-6 | Spanish only | documented: a deliberate scope decision; strings live in one `strings.rs` seam so translating is mechanical |
| M-7 | Dark-mode contrast and missing glyphs | fixed (`c58831a`) |
| M-8 | Password copies not zeroized | fixed (Zeroizing through the GUI's key paths, wave 4e) |
| M-9 | "Shared" logic duplicated while comments claimed otherwise; TSA transport copied between CLI and GUI | fixed: `open_store` (`44c4ffe`), signer policy and refuse-sign-a-signature in core (`bb01fe6`), TSA transport now `openfirma-cades::tsa`, called by both frontends (wave 5) |
| M-10 | `--trust`/`$OPENFIRMA_TRUST` did not do what the README said | fixed (`dc8cfdc`: anchors are configuration; the env variable and flag resolve through one rule, pinned by CLI tests) |
| M-11 | GUI TSA: http only, PDF only, misleading text | documented honestly (the https refusal says why — no TLS without C crypto; non-PDF formats say so in the window). The transport itself is now the shared crate module |
| M-12 | `app.rs` decided things ADR-0006 says it must not | fixed (`c58831a`: verdicts come from the library's report, the window only renders it) |
| B-1..B-8 | Dead close-guard text, wording errors, "verify" duplicating "examine", UTC hours unlabelled, silently dropped unreadable anchors, no interactive password prompt, no file argument for double-click, Spanish comments in one module | fixed across `c58831a`, `3c17bf8` (terminal can be asked; file argument); UTC label and anchor warnings in the same wave |

## Build quality / CI / documentation (`07`)

| ID | Finding | Status |
|---|---|---|
| H-1 | The poppler `pdfsig` cross-check had never run (broken tool probe) while docs claimed it did | fixed (`fd89a25`: probe corrected, CI installs poppler-utils/qpdf/xmlsec1, a missing required tool FAILS; asserts read the per-signature report instead of exit codes) |
| H-2 | `OPENFIRMA_REQUIRE_TESTS` was switched off wholesale on macOS/Windows, hiding every skip, not just keystore ones | fixed (`fd89a25`: two scoped variables — keystore tests keep `OPENFIRMA_ALLOW_SKIP`, everything else now needs `OPENFIRMA_ALLOW_NONKEYSTORE_SKIP`, which no CI job sets) |
| H-3 | The real-certificate guard missed certificates nested inside PDFs, XAdES, CMS, and PEM keys in `.md` files | fixed (`fd89a25`: content-first check — PDF `/Contents` CMS, `ds:X509Certificate`, raw SignedData, PEM anywhere; allowlist only relaxes the extension rule; `--history` applies the same rules; self-test `cert_guard_blocks_every_nested_signature_shape`) |
| H-4 | (see keystores C1) | fixed in code + i686 CI; real-card runtime **not verifiable here** |
| H-5 | The `rsa` pre-release pin was justified by a false claim (it does not fix RUSTSEC-2023-0071) | documented (`fd89a25`: Cargo.toml comment corrected; the advisory is accepted in `.cargo/audit.toml` with its reason — no fixed release exists, and openfirma has zero RSA-decrypt call sites, which is what the advisory needs to be exploitable here; a CI `audit` job enforces the register) |
| H-6 | Docs claimed the golden diff runs in CI; it never did, and cannot (the sede serves AutoFirma's jar 403 to headless clients) | documented (`fd89a25`: platforms.md and validation-log rewritten — golden is a pre-release local gate whose date must be recorded in validation-log.md) |
| H-7 | Release matrix's i686 Windows entry did not compile | fixed (wave 3: pointer-width-aware slot offsets + undecorated raw-dylib imports; the `test-i686-windows` CI job builds and runs tests natively on that target) |
| H-8 | MSRV declared 1.85 but the GUI needs 1.95, and nothing tested either floor | fixed (openfirma-gui carries its own `rust-version = "1.95"`, workspace stays 1.85; CI `msrv` job checks everything-but-GUI at 1.85 and the GUI at 1.95) |
| H-9 | clippy `-D warnings` ran only on Linux, so Windows/macOS FFI code never passed lint | fixed (`fd89a25`: per-platform clippy step in every test job) |
| H-10 | (see keystores A6) | fixed in code; **not verifiable here** at runtime |
| H-11 | No fuzzing or property tests over hand-written parsers | partially fixed (`7bf1f96`: the hostile corpus runs in CI and sweeps specimens deterministically); a cargo-fuzz harness with a dedicated corpus is deferred — `cargo fuzz` needs nightly and CI minutes that are better spent elsewhere until a real finding justifies it |
| H-12 | Third-party licence notices missing from artifacts; NOTICE.md's census was wrong (MIT-only, ISC, BSD-3, Zlib, OFL crates existed) | fixed (NOTICE rewritten with the actual census; `about.toml` + template generate `THIRD-PARTY-LICENSES.html` per release artifact via cargo-about). Generation itself first exercises on the first real release run — no tags exist yet |
| H-13 | Actions pinned by tag/branch, no `permissions:` block, release inherited write access, shared cache | fixed (`fd89a25`, `6c5d79d`: every action pinned by SHA resolved from its tag; `permissions: contents: read` globally in ci.yml; release writes only at publish). Build provenance attestation and signing (cosign/minisign/SBOM) remain deferred — they need repo-level decisions and secrets |
| H-14 | `cargo audit` failed for quick-xml via the GUI's accessibility stack too | documented (accepted in `.cargo/audit.toml`: that XML is D-Bus accessibility introspection, never user documents; reason recorded; audit job enforces) |
| H-15 | A security-relevant feature ("carrier") reached main unreviewed and was later removed; development pace concentrated reviews after the fact | documented (process finding: `1463dc6` removed it; the honest response is the review gates this wave wired in — CI lint/test/audit/cert-guard on every push). Branch protection with required PR reviews belongs to the repository host settings, not the tree, and awaits the owner |
| H-16 | README said the macOS keychain "lists"; it refuses both listing and signing | documented (`fd89a25`-era README: says plainly that macOS refuses until it can be tested) |
| H-17 | Tests moving `HOME` raced sibling threads (setenv/getenv UB); some took `HOME_LOCK`, others did not | fixed (every HOME mover in the CLI/GUI/core test modules now runs inside a locked window; `with_home` also holds a `MOVING_HOME` marker so windows cannot overlap, and `home_moves_only_inside_the_locked_window` proves it — including that locking *inside* the helper deadlocks, which is why callers lock) |
| H-18 | Duplicated front-end logic (`open_store`, four copies of `civil_from_days`) | partially fixed: `open_store` unified (keystore's `44cffe`); three local copies of `civil_from_days` remain (pades, xades, cli) — deduping them is a mechanical follow-up |
| H-19 | Layer drift: `core` does I/O, the browser crate is the signing dispatcher for both frontends, monolithic files | documented as drift in architecture.md; an `openfirma-app` extraction is deferred (mechanical but large; every wave since has touched these files) |
| H-20 | architecture.md/README/platforms.md described crates and flags that do not exist | fixed (`fd89a25` + this commit: architecture diagram, crate list, GUI layout, keystore description, rfd/GTK claim corrected) |
| H-21 | Release notes contradicted the matrix (claimed aarch64 Windows GUI, "via cross" for native arm64 runners; musl's PKCS#11 limitation unmentioned) | fixed: the publish step now states exactly the `gui: true` set and that i686/musl/aarch64-Linux artifacts carry the CLI only; musl static binaries cannot dlopen, said in platforms.md |
| H-22 | Production binary read a test-only env var whose test never ran in CI | fixed (`fd89a25`: linux jobs run the `#[ignore]`d version-guard test with `--ignored --test-threads=1`) |
| H-23 | Time-dependent browser tests (seconds-scale sleeps, 30s floors) | deferred: they pass on every CI platform after wave 4's stabilization; injecting test-configurable deadlines remains a nice-to-have |

## Info-level items (`07`, I-1..I-9)

- **I-1** `#[allow]` vs `#[expect]`: deferred (cosmetic; all five carries no
  reason and none silences clippy).
- **I-2** SPDX headers: deferred (touching 73 files for a header is best
  done once, repo-wide, with the licence decision final).
- **I-3** `#![forbid(unsafe_code)]` on the safe crates: deferred alongside
  I-1; several of these crates' "safe today" status depends on module moves.
- **I-4** `publish = false`: fixed (all eight manifests).
- **I-5/6/7/8/9**: verified true as written in the review (release profiles
  sane; no copied AutoFirma code; no personal data; pure-Rust where it
  matters; edition 2024 consistent).

## What remains unverifiable from this repository

1. **Windows runtime paths**: PKCS#11 against a real card DLL, and the CAPI
   store backend (A6/C1/H-4/H-10). CI compiles, lints, and runs SoftHSM-free
   tests natively on Windows x86_64 and i686; no reader exists in CI. The
   README's keystore table states this per row.
2. **macOS keystores**: Security.framework calls return a refusal by design
   until hardware testing is possible (H-16); documented, not implemented.
3. **Live sede behaviour** (TLS/`wss`, real portal quirks): the protocol is
   pinned against AutoFirma 1.9.1's recorded sources and its own fake sede;
   the gap against a live portal is recorded in ADR-0005 and validation.md.
4. **The golden diff in CI**: impossible today (jar served 403 headless);
   it gates every release locally, and validation-log records the date of
   its last run (12/12 MATCH on 2026-10-17).
5. **Release artifact contents** (per-platform packaging, THIRD-PARTY-LICENSES
   generation): the release workflow has never run for lack of a tag; its
   steps mirror what CI already proves per platform.
