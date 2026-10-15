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
| System certificate store | CAPI/CNG `CertOpenSystemStoreW` | `SecItemCopyMatching`, keychain | none canonical, use PKCS#11 + NSS | `windows` crate, `security-framework` crate, `cryptoki` |
| Non exportable keys, sign with OS key | NCrypt / CAPI CSP | `SecKeyCreateSignature` | PKCS#11 | platform bindings |
| PKCS#11 tokens | vendor DLL | vendor dylib | `pkcs11-module` via p11-kit | `cryptoki` (dlopen at runtime) |
| Smartcards, DNIe | WinSCard | WinSCard equivalent (PCSC.framework) | pcsclite | `pcsc` crate, one API on all three |
| Firefox / NSS store | cert9.db | cert9.db | cert9.db | open softokn3 through PKCS#11, no sqlite needed |
| Local wss service | tokio + rustls | same | same | identical code |
| `afirma://` URL scheme | registry `HKCU\Software\Classes` | Info.plist `CFBundleURLTypes` | `.desktop` + `gio`/`xdg-mime`, D-Bus on KDE | per OS installer step |
| Trust store install of local CA | `certutil` / `CertAddCertificateContextToStore` | `SecTrustSettingsSetTrustSettings` + admin auth | `update-ca-trust`, `update-ca-certificates`, NSS `certutil` | per OS, needs elevation |
| Elevation | UAC manifest / runas | `AuthorizationExecuteWithPrivileges` replaced by SMAppService or `security` with prompt | pkexec / sudo | installer only |
| Installer | NSIS or WiX | `.pkg` + `.dmg` | `.deb`, `.rpm`, AppImage | `cargo-dist` or `tauri` bundler |
| GUI | egui/eframe | same | same | one codebase, plus `tray-icon` |

## Notes that will bite

- **Apple Silicon and x64**: build universal binary with `cargo lipo` or ship
  two artifacts like AutoFirma does.
- **macOS notarization** is mandatory for the wss localhost service to start
  without Gatekeeper blocking, and for the trust store modification to prompt
  properly. Needs a Developer ID.
- **Windows 32 bit**: AutoFirma still ships it. Decide early whether we drop it,
  because it constrains the Rust target to `i686-pc-windows-msvc` and some
  crates do not build there.
- **Firefox NSS**: reading `cert9.db` needs sqlite. Avoid it: softokn3 exposes
  the same certificates over PKCS#11, and that also gives us the keys. This
  keeps the Linux path free of a C database dependency.
- **DNIe**: the official route is the vendor PKCS#11 module
  (`libDNIe_Pkcs11.so`, `DNIe_Pkcs11.dll`, `.dylib`), which we reach through
  `cryptoki` with zero new code. Talking raw APDUs over `pcsc` is the fallback
  for when the module is not installed, and it is a port of the jmulticard
  logic. Phase 3 decision.
- **Mobile**: the core crate must stay `no_std` friendly at the edges (no
  filesystem assumptions, no threads in the format code) so that
  `openfirma-cades` and `openfirma-pades` can be linked into Android via
  `uniffi`/JNI and into iOS via a static lib. Do not block this later.

## CI

`.github/workflows/ci.yml` runs build, test and the golden diff on
`ubuntu-latest`, `windows-latest` and `macos-latest` for every push. Keystore
backends are tested behind feature flags so the matrix can exercise each one
where it exists.
