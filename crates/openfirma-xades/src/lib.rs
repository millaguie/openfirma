//! XAdES-B-B: XML signatures (XML-DSig) with the ETSI EN 319 132-1 baseline
//! qualifying properties, structurally identical to what the official
//! AutoFirma 1.9 produces with `profile=baseline, format=XAdES Enveloped`.
//!
//! The entry point is [`xades_sign`]. The measured reference this implements
//! against is recorded in `docs/xades.md`; the golden diff that keeps it
//! honest is `tools/golden-diff.sh` with `tools/golden/xml-normalize.py`.
//!
//! Like the CMS layer (docs/adr/0001), the XML side is hand rolled: a strict
//! reader in [`xml`] and Canonical XML 1.0 in [`c14n`]. No XML crate is
//! involved, so a bug in our XML cannot hide on both sides of the golden
//! diff — the normalizer is Python and the verifiers are xmlsec1 and
//! AutoFirma itself.

pub mod c14n;
pub mod sign;
pub mod xml;

pub use sign::{XadesOptions, xades_sign};
