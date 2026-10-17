# Notice and attribution

## Relationship with AutoFirma

openfirma is an independent reimplementation in Rust of AutoFirma, the
electronic signature client of the Suite @firma, developed and published by the
Centro de Transferencia de Tecnología (CTT) of the Spanish government.

- Original work: **AutoFirma / Cliente @firma**
- Copyright holder of the original work: **Gobierno de España**
- Original source: https://github.com/ctt-gob-es/clienteafirma
- Original licenses: GNU GPL version 2.0 or later, and EUPL version 1.1
- Original conditions of use: `license/autofirma-LICENSE.txt` in the upstream
  repository

openfirma is distributed under the same licenses, GPL-2.0-or-later OR EUPL-1.1,
with the full texts in `LICENSES/`.

## Nature of this reimplementation

The implementation targets interoperability with the output of AutoFirma and
conformance with the public standards it implements: RFC 5652 (CMS), RFC 3161
(TSP), ETSI EN 319 122-1 (CAdES), ETSI EN 319 142-1 (PAdES), ETSI EN 319 132-1
(XAdES), ISO 32000 (PDF), RFC 5035 (ESS SigningCertificateV2).

Where the standard leaves room, the behaviour of AutoFirma is treated as the
reference and reproduced. The upstream repository is consulted to learn which
options and profiles it emits, so that its output and ours validate the same
way. Code is written from the standards and from observed output, not copied
from the Java sources.

If a future contributor does copy upstream Java code into this repository, the
result stays under GPL-2.0-or-later OR EUPL-1.1, and this file must record it.

## Not endorsed

openfirma is not endorsed by, affiliated with, sponsored by, or supported by the
Gobierno de España, the CTT, or the Secretaría General de Administración
Digital. "AutoFirma" and "@firma" are names of the original product of the
Gobierno de España and are used here only to identify what this software aims
to be compatible with.

## Third party components

openfirma statically links the crates resolved in `Cargo.lock`. MIT, Apache-2.0,
BSD, ISC, Zlib, BSL-1.0 and OFL-style licences all require shipping their
copyright notices and licence texts with the binaries — that is a condition of
distribution, not a courtesy — so every release artifact carries
`THIRD-PARTY-LICENSES.html`, generated at build time by `cargo about` from the
very lockfile the artifact was built from (`tools/ABOUT_TEMPLATE.hbs` and
`about.toml` in this repository define the report). A binary built from source
regenerates the same list with:

```
cargo install cargo-about && cargo about generate tools/ABOUT_TEMPLATE.hbs > THIRD-PARTY-LICENSES.html
```

The tree is NOT "Apache-2.0 OR MIT (RustCrypto)" as an earlier revision of this
file claimed; the lockfile's census (measured with `cargo metadata`, 495
packages) is: MIT/Apache-2.0 dual licences ~318, MIT-only 93, Unicode-3.0 18,
Apache-2.0-only 12 (`flagset`, reached through `der`, and the GUI's winit/
glutin/accesskit stack), Zlib-family ~24, plus singletons: ISC (libloading),
BSD-3-Clause (subtle), BSL-1.0, Unlicense, 0BSD, LGPL-options (never elected —
each is `OR MIT`), and the fonts (`epaint_default_fonts`: OFL-1.1 and the
Ubuntu Font Licence). Every one of these permits distribution under openfirma's
GPL-2.0-or-later OR EUPL-1.1 combined work; the per-component texts travel in
the generated report so each notice reaches the recipient wherever the binary
goes.

One honest caveat belongs here, not hidden: FSF reads Apache-2.0-only as
incompatible with GPL-2.0 (and compatible with GPL-3.0). openfirma's license is
GPL-2.0-*or-later*, so any distribution of these binaries under the GPL option
uses the "or later" (GPL-3.0), which accepts the combination; the EUPL-1.1
option accepts compatible permissive code as well. That reasoning should be
confirmed with legal counsel before a formal release; if it ever fails, the
Apache-2.0-only components above are the ones to look at first, and this file
must change accordingly.
