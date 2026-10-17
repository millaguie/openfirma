//! CAdES: CMS `SignedData` (RFC 5652) with the ETSI EN 319 122-1 attributes.
//!
//! Entry point is [`sign`], which produces a complete `ContentInfo`. The same
//! machinery serves PAdES, whose `/Contents` is a detached `SignedData` built
//! with [`CadesOptions::encapsulate_content`] set to false.
//!
//! [`verify`] is the mirror image: it reads a `ContentInfo` back, checks the
//! `messageDigest`, the signature value over the re-tagged signed attributes,
//! the `signingCertificateV2` reference and the certificate chain up to the
//! supplied trust anchors, and reports what the signature carries.
//!
//! Current levels: B-B and B-T (the time-stamp token of
//! [`CadesOptions::timestamp`], crosschecked against `openssl ts`). The CAdES
//! long-term levels ES-LT/ES-LTA are deliberately not implemented: openfirma's
//! long-term path is PAdES B-LT/B-LTA, where the validation data lives in the
//! document's `/DSS` instead of in CMS attributes. [`revocation`] carries the
//! shared reading of that data, CRLs and OCSP responses.

pub mod attributes;
pub mod revocation;
pub mod signed_data;
pub mod tsp;
pub mod verify;

pub use revocation::read_ocsp_response;
pub use signed_data::{AUTOFIRMA_DEFAULT_CONTENT_DESCRIPTION, CadesOptions, TimestampFn, sign};
pub use verify::{Attributes, VerifyOptions, VerifyReport, signer_certificates, verify};
