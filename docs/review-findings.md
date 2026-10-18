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

Two adversarial rounds on the fixes themselves followed (`R1`, `R2` below):
models that had not written the code were asked to break it, with an executable
proof of concept or nothing.

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
| M-3 | Reader accepted malformed XML and signed what nothing parses | fixed (`87ef144` refuses non-CMS bytes; `80519b2`/reader hardening; xmlsec1 cross-check installed in CI so a third party judges the output; `ebbcff1`: the crosscheck and golden verifier were reading success as "Verification status: OK", which 1.2.x never prints — a bare "OK" on stderr is Ubuntu's answer — so both now fail closed on xmlsec1's exit code, assert the reference counters (2/2, printed by every version line), require the tamper test to show an actual digest miss (0/N) rather than any nonzero exit, and type the Id attribute per version: `--add-id-attr Id --verbose` on 1.3+, two-argument `--id-attr:Id <root>` on 1.2.x, which has no built-in Id knowledge at all — every flag fact measured against the real apt binary in a container) |
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
| H-3 | The real-certificate guard missed certificates nested inside PDFs, XAdES, CMS, and PEM keys in `.md` files | fixed (`fd89a25`: content-first check — PDF `/Contents` CMS, `ds:X509Certificate`, raw SignedData, PEM anywhere; allowlist only relaxes the extension rule; `--history` applies the same rules; self-test `cert_guard_blocks_every_nested_signature_shape`). The macOS five-round witness chase (39088314047→39091143744) stripped the guard to its final architecture: bash reads and scans every byte itself (`read_whole_file`: one C-locale substitution + an arithmetic LF pass, `bytes + lfs == size` tells eaten framing from hidden bytes — no child gets a text/binary verdict; the candidate scan is builtin window-globs over that variable; only decoders ever touch files), every external reader in history having gone blind on probe files at some point (BSD grep intervals, `tr`, awk RS, pipes chopping at 512 B). Verdicts travel on TWO channels — check_file re-blocks the inner scan's messages AND its exit status (`CHECK_SUBSH`), because run 39091143744 proved text without status and status without text each leak; runs also proved bash ≥5.3's NUL notice is emitted by the parent at assignment, so stderr moves to a temp file around scans, with the outer EXIT trap re-armed verbatim. The flag protocol `|<line-prefix>` binds scanner to extractor byte-for-byte — when a rewrite desynced them, openfirma's own XAdES (certificate after two 342-char digest runs, single line) walked through; self-test controls now pin that shape, UTF-8 locale currency, and the small-NUL framing equation. Windows: cli.rs tells a WSL-dispatcher `bash` apart from a guard failure and skips under the usual allowance rules Final root cause (run 39103604509, reproduced byte-for-byte in an ubuntu:24.04 container): `base64 -d`'s tolerance for an unpadded run is a coreutils VERSION trait — the XAdES certificate run is 1130 chars (mod 4 == 2), coreutils 9.12 decodes it, 9.4 refuses it silently, and the extractor certified the file clean on CI while blocking it locally; the padding is now rebuilt from the run's length by arithmetic before decoding (`bb857dc`), and the PDF CMS path left `xxd` (absent on CI runners) for python3, which the guard already requires) |
| H-4 | (see keystores C1) | fixed in code + i686 CI; real-card runtime **not verifiable here** |
| H-5 | The `rsa` pre-release pin was justified by a false claim (it does not fix RUSTSEC-2023-0071) | documented (`fd89a25`: Cargo.toml comment corrected; the advisory is accepted in `.cargo/audit.toml` with its reason — no fixed release exists, and openfirma has zero RSA-decrypt call sites, which is what the advisory needs to be exploitable here; a CI `audit` job enforces the register) |
| H-6 | Docs claimed the golden diff runs in CI; it never did, and cannot (the sede serves AutoFirma's jar 403 to headless clients) | documented (`fd89a25`: platforms.md and validation-log rewritten — golden is a pre-release local gate whose date must be recorded in validation-log.md) |
| H-7 | Release matrix's i686 Windows entry did not compile | fixed (wave 3: pointer-width-aware slot offsets + undecorated raw-dylib imports; the `test-i686-windows` CI job builds and runs tests natively on that target) |
| H-8 | MSRV declared 1.85 but the GUI needs 1.95, and nothing tested either floor | fixed (openfirma-gui carries its own `rust-version = "1.95"`, workspace stays 1.85; CI `msrv` job checks everything-but-GUI at 1.85 and the GUI at 1.95) |
| H-9 | clippy `-D warnings` ran only on Linux, so Windows/macOS FFI code never passed lint | fixed (`fd89a25`: per-platform clippy step in every test job) |
| H-10 | (see keystores A6) | fixed in code; **not verifiable here** at runtime |
| H-11 | No fuzzing or property tests over hand-written parsers | partially fixed (`7bf1f96`: the hostile corpus runs in CI and sweeps specimens deterministically); a cargo-fuzz harness with a dedicated corpus is deferred — `cargo fuzz` needs nightly and CI minutes that are better spent elsewhere until a real finding justifies it |
| H-12 | Third-party licence notices missing from artifacts; NOTICE.md's census was wrong (MIT-only, ISC, BSD-3, Zlib, OFL crates existed) | fixed (NOTICE rewritten with the actual census; `about.toml` + template generate `THIRD-PARTY-LICENSES.html` per release artifact via cargo-about). Generation first ran on 2026-10-18, and it could not run at all: the release workflow's first dispatch (run 39128074408, `workflow_dispatch`, no tag needed — the publish job stays skipped) failed in that step on all eight legs, twice over. (1) `cargo install cargo-about --locked --version "^0.9"` installs **no binary**: 0.9.x builds `cargo-about` behind `--features cli`, so `cargo about generate` dies with `error: no such command: about` (exit 101) after a successful install. (2) With the binary present, `about.toml` did not even deserialize: cargo-about parses `accepted` as a list of `spdx::Licensee` — one licence identifier, optionally `WITH <exception>` — and six entries were SPDX *expressions* (`"MIT OR Apache-2.0"`, `"(MIT OR Apache-2.0) AND OFL-1.1 AND Ubuntu-font-1.0"`, …), each rejected as `expected a WITH here` / `expected a <license> here`. Both are fixed (atomic identifiers; OR-chains need only one accepted term, AND-chains every term), along with the `[ubuntu-font-licence]` table that a crate-name config can never match and NOTICE.md's copy-paste recipe, which repeated the broken install line. Verified here: the report renders at 93 KB with `epaint_default_fonts` present, byte-identical from a warm and a cold `CARGO_HOME` (so a fresh runner's empty `registry/src` is not a factor). The gate that would have caught this — a `licences` job in ci.yml running the release step's exact commands on every push — now exists; before it, the only place these commands lived was a workflow that had never executed |
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

## Adversarial rounds on the fixes itself (`R1`, `R2`, `R3`)

The seven reviews above judge the code; these rounds judge the *fixes*. A
frozen tree was handed to a model that had not written them, with the findings
and the exact commits to falsify, and one rule: nothing closes by reading. Each
round had to break a fix with an executable proof of concept, and for every fix
had to show that the test guarding it actually fails when the fix is reverted —
a test that stops biting is worse than a test that fails. The reports are not
in this repository, for the same reason as the seven above.

| ID | Finding | Status |
|---|---|---|
| R1-C1 | Shadow attack through a hanging `/DSS`: the incremental-saving gate seeded "this object is validation data, so it may change" from EVERY object whose `/Type` is `/DSS`, referenced or not, so one appended revision that rewrote the page content stream and added an unreferenced `<< /Type /DSS /Certs [<payload> 0 R] >>` verified green over text a reader shows as substituted | fixed (`ab7e0ef`: the walk starts at the archive the catalog names, and a rewritten object claiming `/Type /DSS` is no longer excused) |
| R1-A1 | `verify` never recognised a genuine B-T signature — two bugs stacked. The unsigned attribute value was unwrapped from the inner OID instead of the whole `ContentInfo`, so every token was refused with "expected the ContentInfo (tag 0x30), found tag 0x06"; and the imprint was compared against un-hashed `cert || signature` rather than the digest of the signature value (`CMSTimestamper.java:227`) | fixed (`4995746`: the token is unwrapped whole, and the imprint is the digest of the signature value, the same input the signing side hashes) |
| R1-A2 | A `/Type /DocTimeStamp` seal signed by an attacker's self-signed TSA passed `verify` with every light green, and the window printed "nivel B-LTA: cada uno certifica todos los bytes anteriores" over zero cryptographic evidence — `tsp::verify_token_signature` was never called on the token | fixed (`2cf68c5`: the same TSA verification the B-T path uses runs against the caller's anchors, and the report and the window say which tokens were checked) |
| R1-A3 | `Cursor::sequence` returned `Cursor<'static>` and satisfied the bogus lifetime with `Box::leak(v.content.to_vec())`, leaking a copy per descent — ~25 per verification, chosen by hostile input, in the long-running window | fixed (`23a339a`: the borrow was always available; measured at 0 kB per iteration versus +6 kB/iteration with the leak restored) |
| R1-M1 | Windows PKCS#11 ABI: `slot_info_ptr` read function-table slot 6 as byte offset `6·sizeof(pointer)` while the rest of the crate goes through the packed-table rule. On LP64 Unix the two agree, so every Linux dev box and CI run was blind to it; on Windows the value read was a mix of `C_GetSlotInfo` and `C_GetTokenInfo`, transmuted to `extern "C" fn` and called | fixed (`5960edb`: the same `function_slot_offset` every other slot uses, plus `read_unaligned`) |
| R1-B1 | `openfirma verify -i signed.xml` answered "these bytes are not a CMS signature: expected the ContentInfo (tag 0x30), found tag 0x3c" — 0x3c being `<`, which reads to a citizen like a corrupted file instead of "this build does not verify XAdES yet" | fixed (`13efbf5`: XML is named, with the way out) |
| R1-X | Not a finding of the round: a PKCS#12 export with a random salt failed to load about once in 117 ("a DER length that is overlong or runs past the input") while openssl opened the same file. Pre-existing (reproduced on `fb41351`), surfaced by a flaky macOS CI job. `decrypt_pbe_all` returned the first password candidate whose PKCS#7 padding validated, and with an 8-byte block cipher a wrong candidate satisfies that padding by chance once in 256 | fixed (`b10b81a`: a decrypted bag is accepted only when its whole plaintext is one DER structure; 1000 random-salt exports, 0 failures) |
| R2-C1 | **The round-1 fix for C-1 did not close the class.** The walk followed EVERY reference from the catalog's archive, not the keys a validation-data reader consumes, so a revision that rewrote the page content stream and named it from a key no reader reads (`/Foo [<content> 0 R]`), or reached it one hop through a free object, or named it only inside a `/VRI` entry, still verified green over substituted text. Reproduced here against the reviewer's own artifacts before touching a line | fixed (`77ae89f`: the walk follows `/Certs`, `/CRLs` and `/OCSPs` only, follows nothing inside a named object, and licenses anything only as an addition — an archive pass appends, it never replaces a byte a reader rendered). Three tests, each shown to bite by reverting the fix |
| R3-C1 | **The round-2 fix still licensed a new object a page renders.** Making the walk follow only the keys a validation-data reader consumes was necessary and not sufficient: `brand_new && /Type /DSS` went on licensing any new dictionary for the claim in its own body, and what matters as much as *who names* an object is *who else points at it*. A document that names an object it does not have (`/XObject << /Xm1 100 0 R >>` in the page, `/Xm1 Do` in the content stream, both inside the signed range) shows that object the moment a later revision defines it: one appended revision defining it as a form XObject drawing a sentence of the attacker's AND claiming `/Type /DSS` put the sentence on the page, and `pdftotext` read it while `verify` answered OK. Found here, by attacking the round-2 fix, before the round-3 reviewer's report landed | fixed (`936196b`: the licensed set is a fixpoint — the archive, the objects its taxed keys name, and brand-new `/Type /DSS` dictionaries, minus every candidate something outside points at, iterated; the catalog's own `/DSS` entry is the one reference that does not count as outside). The test fails with this file reverted and passes without over-pruning the legitimate second B-LT merge, which the first attempt at the rule refused. A second shape went by the page tree instead — a covered `/Kids` entry that names an object the file does not have, filled with the page the catalog then calls its archive, drawing with a brand-new stream that also claims `/Type /DSS` — and it is the shape that makes the iteration load-bearing: with a single pass the document is refused for the page but the stream stays licensed, so the refusal stops naming it (`b826bdc`, measured) |
| R3-C2 | **The reader refused an archive the door had accepted.** Not a defeat of a fix but of `ltv`: ISO 32000 lets a value be indirect almost anywhere, so a writer may build `/Certs` and `/CRLs` as objects of their own (`/Certs 101 0 R`, 101 an array). The gate licensed exactly that shape — it says so in `collect_archive_data` — and `ltv::read_dss` answered `pdf: expected an array`, so the same hand-built archive over a B-B signature verified with the arrays inline and failed with them indirect. Stumbled on while probing the round-3 brief's own "false refusals" item (the reviewer's drained run reached the same shape) | fixed (`b0f768c`: `stream_array` resolves the one hop; the test builds that archive by hand, cert and CRL streams as brand-new objects named through indirect arrays, and fails with `pdf: expected an array` when the hop is removed) |
| R3-C3 | **A reference the gate did not see, and one it invented.** `refs_in` decides whether anything outside the archive points at a candidate, so a missed reference is a licensed object a reader renders: `100 % note` newline `0 R` is one reference to a reader (a comment is a single space) and was none to the gate — a covered page naming object 100 that way plus an appended form XObject claiming `/Type /DSS` drew "PAGUESE 9999 EUR" while verify said OK. The mirror image is a reference-looking run inside a string, which a reader resolves to nothing but which dropped the certificate stream a legitimate archive numbered 201 (found while probing the brief's own false-refusal item; the reviewer's drained run reached the same shape) | fixed (`bd74a50`: the scanner reads the syntax a reader reads — comments skipped without breaking a half-read pair and kept as separators in `gap_is_separator`, strings and hex strings skipped and resetting the pair). Two tests, each failing with the previous scanner: the comment-split attack is refused naming `100 0 R`, and the hand-built archive under a `/PieceInfo` string verifies |
| R3-C4 | **A signature attests only the bytes it was made over, and the plumbing rule never asked.** "Any object carrying a real signature value is plumbing" licensed two shapes that render: the signature's own widget rewritten (its `/AP` replaced by an appearance of the attacker's own, its `/Rect` made visible, its `/V` kept — which is all the rule looked at), and a brand-new widget filling an annotation the covered page already named with the same borrowed `/V`. Both read the attacker's sentence in `pdftotext` while verify answered OK. A byte-copy of the signature dictionary and one with a garbage `/Contents` were the two variants `verify` already caught (the `/ByteRange` hole has to be that dictionary's own `/Contents`) — the gate licensed them too, so the refusal rested on the verifier instead of on the gate | fixed (`762c321`: a field or widget is plumbing only when the `/ByteRange` of the value it carries contains the object's own bytes; a rewrite may restate nothing but `/V`; and appearance streams and fonts are plumbing only when an ATTESTED widget names them). Two tests, each failing when the file is reverted: the rewritten widget and the borrowed value, both refused naming the widget |
| R3-C5 | **The appearance a widget names was licensed for the widget's sake, and the appearance is what draws.** Attestation checked the value a widget carries against the widget's own bytes and never asked about the `/AP` target: a covered widget whose `/AP` named an object that did not exist yet was the way a later revision put its own text on the page — the widget is bytes a signature signed, the appearance is whatever comes next. Demonstrated with a REAL signature and no forgery: the crafted page's widget points `/V` at the signature the signer is about to write (its number is a function of the input) and `/AP` at object 900; one appended form XObject then drew "PAGUESE 9999 EUR" and verify answered OK. Under the previous commit it was refused, but for an accident: `/ByteRange` was read with the first number as a length, so the head range became `[0, 0)` and no object before the signature's `/Contents` ever counted as covered | fixed (`4cb73ac`: `/ByteRange` read as two (offset, length) pairs, and the appearance licensed only when the attesting signature — the widget's own `/V` — covers the appearance's own bytes, via `widget_appearance` + `signature_covers`). One test, failing with the coverage rule removed while the parse fix stays (verify answers OK), and the probe-signing trick documents the numbering it relies on |

Two observations from round 2 that are not defeats of a fix, kept here so they do
not get lost:

- The window's B-LTA wording for the mixed case (a verified signature plus a
  document time-stamp that is not) had no test of its own; the library verdict
  it renders did. Not a defect — a hole in the net around A-2, whose whole
  point was not over-claiming. Closed: the test now builds the mixed report,
  asserts the sentence names the counts, refuses the level out loud and never
  prints the claim, and fails when the branch is put back to claiming it
  (`crates/openfirma-gui/src/verdicts.rs`).
- A PKCS#12 whose MAC is HMAC-MD5 was refused as "wrong password" — openssl
  opens it. Pre-existing, low, and a compatibility gap rather than a
  vulnerability: the sentence sent the holder of a good certificate looking for
  a password they had. Fixed (`499597b`: the MD5 MAC is checked like the others,
  reading only, with the fixture's digest OID asserted before anything else).

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
   generation): the release workflow's first execution (2026-10-18) showed its
   licence step could not run at all — see H-12. It now runs end to end on
   dispatch (8/8 legs, run 39129111129) and the artifacts were downloaded,
   checksum-verified and executed here (`docs/validation-log.md`, "Release
   artifacts"). Still unproven from here: the Windows and macOS binaries on
   their own platforms (cross-built, no such host), the window on a physical
   desktop, and the `publish` job, which only a tag starts.
| R3-C6 | **The font branch of the plumbing rule never heard the fixpoint's lesson.** `936196b` taught the gate that a reference a reader resolves is a rendered object, and said it for `/XObject`, `/Contents` and the page tree; the plumbing rule went on answering `Change::SignaturePlumbing` for any brand-new `/Type /Font` whose `/BaseFont` is Helvetica or ZapfDingbats, asking nobody who points at it — and the fixpoint never reaches that branch, because a font dictionary is not a validation-data candidate. A `/Font` slot the covered bytes already named is exactly the place that hands a later revision the choice of glyphs: the covered page names `/F2 97 0 R` in its `/Resources` and its content stream sets that font for a headline, 97 does not exist, so a reader draws nothing there; signing verifies. One appended Helvetica whose `/Encoding` carries a `/Differences` array remapping every capital one letter up then renders the covered "PAGO UN CERO CERO" as "QBHP VO DFSP DFSP" — not one covered byte changed, the glyphs did — and verify answered OK over the reader's substitution | fixed (`35ec49b`: a brand-new font is plumbing when a signature's `/ByteRange` covers its bytes and nothing outside that same signature names it. A pass writes its font and the object that uses it — its appearance's `/Resources`, the AcroForm's `/DR` — inside its own range, so one signature covers both; a font nobody names renders nothing and is inert; a font a namer outside the covering signature points at is text that signature never set). The test signs a page whose `/F2` slot is empty and fails with the shape test restored (verify answers OK over the substituted text); the co-sign, whose second pass writes two fonts it does not name, keeps verifying |
| R3-C7 | **An archive the reader accepts and the gate refused.** The gate decides on what the merged state shows — an object stream's contents are resolved into the final state and classified one by one, and a cross-reference stream has always been read as the section it is — but neither container was itself licensed, and every writer that saves incrementally produces them. So the same archive passed as a classic table and was refused the moment a writer compressed its save: the same hand-built B-LT pass (same `/DSS`, same certificate stream, same catalog entry) once behind a classic table and once behind an `/ObjStm` plus an `/XRef` section, `qpdf --check` clean in both, verified green in the first form and refused in the second as "changes no archive may append: object 18 0 R" — the section itself — and 20 0 R with it, the object stream | fixed (`f8f01be`: a brand-new `/XRef` dictionary, or a brand-new object stream the resolved locations point objects into, is transport, which carries nothing a reader renders. It is licensed on the fixpoint's premise, not beside it: a container is reached through cross-reference entries that carry offsets, never through a reference, so a container some covered object DOES name is a dangling slot being filled and stays refused). Two tests: the packed archive (fails with the rule removed) and a covered page that draws `/Xm1 97 0 R` before the appended revision makes 97 the container its `/DSS` rides in (fails with only the namer condition removed) |
| R3-C8 | **A reference edge that pointed the wrong way.** The gate taxes three keys of the `/DSS` dictionary — `/Certs`, `/CRLs`, `/OCSPs`, the arrays the validator reads and verifies — and deliberately not `/VRI`: what an ENTRY names is not validation data, and the round-1 test keeps it that way. ISO 32000 12.7.4.4 lets any value in the `/DSS` dictionary be an indirect reference, though, and a writer that stores `/VRI` as an object of its own leaves an object OUTSIDE the licensed set pointing at objects inside it. The file was then refused twice over: the certificate stream the taxed `/Certs` array had already licensed, expelled because its namer sat outside the set, and the `/VRI` dictionary itself | fixed (`75a1cce`: the `/VRI` dictionary joins the set as archive bytes, and only it — an entry's own objects stay out, so the deliberate test still bites). The test builds that archive by hand and fails with the rule removed, naming exactly the two objects the measurement named |
