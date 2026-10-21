# Multiplatform

AutoFirma ships for Windows (32/64), macOS (x64 and Apple Silicon), Linux
(Debian, Fedora, openSUSE) plus Android and iOS apps. openfirma targets the
same desktop matrix from a single codebase, and keeps the mobile option open
through the same core crate.

## Rule

One pure Rust core. Everything that differs per operating system sits behind a
trait and is selected at compile time with `cfg(target_os)`. No platform `if`
in format code, ever.

## Matrix

| Capability | Windows | macOS | Linux | Rust approach |
|---|---|---|---|---|
| System certificate store | CAPI/CNG via hand-written FFI (`windows.rs`) | refused until testable (`macos.rs`, see ADR-0004) | none canonical, use PKCS#11 + NSS | one `SystemStore` trait per `cfg(target_os)` backend |
| Non exportable keys, sign with OS key | CAPI CSP (`CryptSignHash`, PKCS#1 v1.5); a CNG-only key is refused by name — no NCrypt signer yet | `SecKeyCreateSignature` | PKCS#11 | platform bindings |
| PKCS#11 tokens | vendor DLL | vendor dylib | `pkcs11-module` via p11-kit | openfirma-keystore loads the module at runtime with `libloading` (hand-written Cryptoki types, no bindings crate). The musl static release binary cannot `dlopen`, so that artifact is PKCS#12-only; use the glibc build for `--store pkcs11:`/`nss`. **Windows: compiled and linted, never run against a real module** — CI provisions no SoftHSM there, so the tested module path is Linux. **macOS: never executed at runtime either** (round 3's N3-4; neither a PKCS#11 module nor an NSS database has been loaded) |
| Smartcards, DNIe | WinSCard | WinSCard equivalent (PCSC.framework) | pcsclite | `pcsc` crate, one API on all three |
| Firefox / NSS store | cert9.db | cert9.db | cert9.db | open softokn3 through PKCS#11 (loaded with `libloading`), no sqlite needed |
| Local endpoint for the browser protocol | plain HTTP on loopback (docs/adr/0005) + an `afirma://` launcher that dials it | same | same | identical code; a wss service would need a TLS client, and the pure-Rust rule keeps rustls/openssl out until that decision is made |
| `afirma://` URL scheme | registry `HKCU\Software\Classes` | Info.plist `CFBundleURLTypes` | `.desktop` + `gio`/`xdg-mime`, D-Bus on KDE | per OS installer step |
| Trust store install of local CA | `certutil` / `CertAddCertificateContextToStore` | `SecTrustSettingsSetTrustSettings` + admin auth | `update-ca-trust`, `update-ca-certificates`, NSS `certutil` | per OS, needs elevation |
| Elevation | UAC manifest / runas | `AuthorizationExecuteWithPrivileges` replaced by SMAppService or `security` with prompt | pkexec / sudo | installer only |
| Installer | NSIS or WiX | `.pkg` + `.dmg` | `.deb`, `.rpm`, AppImage | `cargo-dist` or `tauri` bundler |
| GUI | egui/eframe | same | same | one codebase, plus `tray-icon`. **Executed only on Linux**: the window has run on a virtual display (`xvfb-run`) and in the manual checklist; the Windows and macOS builds are compiled and published, never launched (round 3's N3-4) |

## Notes that will bite

- **Apple Silicon and x64**: build universal binary with `cargo lipo` or ship
  two artifacts like AutoFirma does.
- **macOS notarization** would be mandatory if the wss localhost service ever
  lands — Gatekeeper blocks it otherwise, and the trust-store modification has
  to prompt properly — which is one of the four pieces openfirma does not
  implement (ADR-0005's honest gap). Needs a Developer ID.
- **Windows 32 bit**: AutoFirma still ships it. Decide early whether we drop it,
  because it constrains the Rust target to `i686-pc-windows-msvc` and some
  crates do not build there.
- **Firefox NSS**: reading `cert9.db` needs sqlite. Avoid it: softokn3 exposes
  the same certificates over PKCS#11, and that also gives us the keys. This
  keeps the Linux path free of a C database dependency.
- **DNIe**: the official route is the vendor PKCS#11 module
  (`libDNIe_Pkcs11.so`, `DNIe_Pkcs11.dll`, `.dylib`), which we reach through
  the same runtime-loaded PKCS#11 path with zero new code. Talking raw APDUs over `pcsc` is the fallback
  for when the module is not installed, and it is a port of the jmulticard
  logic. Phase 3 decision.
- **Mobile**: the core crate must stay `no_std` friendly at the edges (no
  filesystem assumptions, no threads in the format code) so that
  `openfirma-cades` and `openfirma-pades` can be linked into Android via
  `uniffi`/JNI and into iOS via a static lib. Do not block this later.

## CI

`.github/workflows/ci.yml` runs build, test and clippy on `ubuntu-latest`,
`ubuntu-24.04-arm`, `windows-latest`, `windows-11-arm` and `macos-latest`
(both Apple and Intel targets) for every push, plus the Linux-only jobs:
lint (fmt+clippy), RustSec audit, MSRV floors (1.85 / 1.95 for the GUI), the
i686-Windows ABI tests, and the certificate-material guard over the tree and
the whole history. Keystore integration tests need real modules behind them:
they run on Linux, where SoftHSM and libsoftokn3 are installed, and declare
their skip on macOS/Windows runners through a keystore-scoped environment
opt-in — every other test keeps the panic-on-skip guarantee everywhere. The
golden diff is NOT in CI (the AutoFirma jar's download answers 403 to headless
clients); it is the pre-release local gate `docs/validation-log.md` records,
and nothing else claims otherwise.
