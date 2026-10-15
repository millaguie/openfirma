# Validation log

The record of acceptance runs. Only verdicts and reported levels go here; the
certificates and signed files they were made with never enter the repository.
See `docs/validation.md` for what each layer means.

## Automated, every commit, all platforms

| Check | Result | Since |
|---|---|---|
| Golden diff, CAdES-B-B RSA SHA-256 vs AutoFirma 1.9 | MATCH | 2026-10-15 |
| Golden diff, PAdES-B-B RSA SHA-256 vs AutoFirma 1.9 | MATCH | 2026-10-15 |
| OpenSSL verifies CAdES (RSA SHA-256/512, ECDSA P-256, encapsulated and detached) | pass | 2026-10-15 |
| OpenSSL verifies PAdES over the `/ByteRange` bytes | pass | 2026-10-15 |
| poppler `pdfsig`: signature valid, total document signed | pass | 2026-10-15 |
| `qpdf --check` on our incremental update | pass | 2026-10-15 |
| Co-signature: AutoFirma's signature still valid after ours is appended | pass | 2026-10-15 |

## Manual

| Run | Date | Verdict |
|---|---|---|
| DSS (ETSI reference) on PAdES-B-B | pending | |
| VALIDe on CAdES-B-B with a real FNMT certificate | pending | |
| VALIDe on PAdES-B-B with a real FNMT certificate | pending | |
| Real trámite in a sede electrónica | pending | |
