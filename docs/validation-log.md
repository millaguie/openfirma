# Validation log

The record of acceptance runs. Only verdicts and reported levels go here; the
certificates and signed files they were made with never enter the repository.
See `docs/validation.md` for what each layer means.

Rows below name the place the check RUNS, and the column "where" is checked
against `.github/workflows/ci.yml` — a claim that a gate runs in CI must be
findable there by grep (`grep -n <name> .github/workflows/*.yml`). This table
was rewritten on 2026-10-17 because it had claimed exactly that about checks
that did not run: the poppler `pdfsig` rows (its tool probe was broken, see
review 07 H-1 / `docs/review-findings.md`) and the golden diff (never wired
into CI, H-6). The honest shape is: automated checks are per-commit on the
platforms that provision them; the golden diff is a pre-release local gate.

## Automated in CI, every push

| Check | Where | Result | Since |
|---|---|---|---|
| `cargo fmt --all --check`, `cargo clippy -D warnings` (Linux) | lint job | pass | 2026-10-15 |
| clippy `-D warnings` on Windows and macOS targets too | test jobs, per-platform step | pass | 2026-10-17 |
| OpenSSL verifies CAdES (RSA SHA-256/512, ECDSA P-256, encapsulated and detached) | test jobs, linux/macos (openssl on PATH) | pass | 2026-10-15 |
| OpenSSL verifies PAdES over the `/ByteRange` bytes | same | pass | 2026-10-15 |
| poppler `pdfsig`: signature valid, total document signed | test jobs on linux (poppler-utils installed; a missing pdfsig now FAILS instead of skipping) | pass | probe fixed 2026-10-17 — the check had never run before that date despite this row claiming it since 10-15 |
| `pdfsig` still validates earlier signatures after B-LT/B-LTA is appended | same (`crates/openfirma-pades/tests/ltv.rs`) | pass | as above |
| `qpdf --check` on our incremental update and on the B-LT document | same (qpdf installed; missing qpdf fails) | pass | 2026-10-17 (installed in CI; before, it skipped there) |
| xmlsec1 verifies XAdES references + SignatureValue (RSA, ECDSA, namespaced roots) | test jobs on linux (xmlsec1 installed); success keys on xmlsec1's exit code + the 2/2 reference counters, never a summary string (Ubuntu's 1.2.x prints a bare "OK"; the flag dialects differ per version — measured against the real apt binary, see `ebbcff1`) | pass | 2026-10-18 (real verification only from this date: until then CI judged 1.2.39 by a string it never prints, so linux crosschecks reported failure for tool-version reasons and could have reported success the same way) |
| Co-signature: AutoFirma's signature still valid after ours is appended (`testdata/golden/*` fixtures + verify) | `crates/openfirma-pades/tests/verify.rs`, every test job | pass | 2026-10-15 |
| openssl `ts -reply` answers our B-T/B-LTA queries; tokens verified against the bytes their `/ByteRange`/message imprints | `tsp_crosscheck.rs`, `ltv.rs` on linux/macos | pass | 2026-10-15 |
| PKCS#11 + NSS keystores end to end, signatures double-verified (SoftHSM, libsoftokn3) | test jobs on linux only; macOS/Windows keystore skips are declared via the keystore-scoped `OPENFIRMA_ALLOW_SKIP` | pass | 2026-10-15 |
| PKCS#11 ABI asserts + tests natively on i686 Windows | `test-i686-windows` job | pass | 2026-10-17 |
| version-guard refusal (`#[ignore]`d test, run alone) | linux jobs, `--ignored --test-threads=1` step | pass | 2026-10-17 |
| cert-material guard over every tracked file and every blob in history, incl. nested PAdES/XAdES/CMS shapes and the guard's own self-test | `no-real-certs` job + `cert_guard_blocks_every_nested_signature_shape` | pass | 2026-10-15 (shapes extended 2026-10-17) |
| RustSec audit against `.cargo/audit.toml` (every accepted advisory documented) | `audit` job | pass, with the two documented exceptions listed there | 2026-10-17 |
| MSRV floors checked: everything but the GUI at 1.85, the GUI at 1.95 | `msrv` job | pass | 2026-10-17 |
| Third-party licence report renders with the release workflow's exact commands (`cargo install cargo-about … --features cli` + `cargo about generate`) and contains the GUI's font crates | `licences` job | pass | 2026-10-18 — the job exists because the release workflow's first dispatch (run 39128074408) showed the step could not run at all on any of its eight legs; see review 07 H-12 |

## Automated locally (pre-release), not in CI

| Check | Where | Result | Since |
|---|---|---|---|
| Golden diff, CAdES-B-B RSA SHA-256 vs AutoFirma 1.9 (cases: simple, sha1, ecdsa, policies, policy_commit, mime) | `AUTOFIRMA_JAR=… tools/golden-diff.sh`, run locally before every release | MATCH | 2026-10-15; latest full run 2026-10-17: 12/12 MATCH (CAdES, PAdES, XAdES × natural + legal person) |
| Golden diff, PAdES-B-B RSA SHA-256 vs AutoFirma 1.9 | same | MATCH | as above |
| Golden diff, XAdES-B-B vs AutoFirma 1.9 (simple, ns-root, juridical) | same | MATCH | 2026-10-17 |
| AutoFirma's own validator accepts our XAdES (`autofirma_verify.rs`) | `cargo test` when `$AUTOFIRMA_JAR` is set; skipped with a message in CI — the jar is not downloaded there (see below) | pass locally | 2026-10-17 |

The golden diff cannot run on GitHub's runners: the reference AutoFirma jar
comes from `tools/fetch-autofirma.sh`, whose source (firmaelectronica.gob.es)
serves it behind redirects that answer 403 to non-browser clients, and
redistributing the jar through a public CI cache would be its own licensing
question. The honest gate is therefore: MATCH before every release, recorded
here with its date, plus the independent verifiers (openssl, pdfsig, qpdf,
xmlsec1) that DO run per push in CI.

## Manual

| Run | Date | Verdict |
|---|---|---|
| DSS (ETSI reference) on PAdES-B-B | pending | |
| VALIDe on CAdES-B-B with a real FNMT certificate | pending | |
| VALIDe on PAdES-B-B with a real FNMT certificate | pending | |
| Real trámite in a sede electrónica | pending | |
| GUI manual checklist (docs/validation.md §5) on Windows / macOS / Linux desktop | pending per release | |
| Compat CLI side-by-side against AutoFirma's console (docs/validation.md §5a) | pending | |
| Keystore interop checklist (docs/validation.md §6): real DNIe card, Windows store signing, Firefox profiles | pending — no such hardware is reachable from CI | |
