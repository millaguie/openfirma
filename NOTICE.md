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

Rust crates used by openfirma keep their own licenses, recorded by
`cargo about` / `cargo license`. At the time of writing the dependency tree is
Apache-2.0 OR MIT (RustCrypto), plus the crates listed in `Cargo.lock`.
