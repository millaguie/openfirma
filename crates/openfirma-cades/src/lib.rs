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
//! Current level: B-B. Unsigned attributes can be injected through
//! [`CadesOptions::unsigned_attributes`], which is how B-T will carry the TSA
//! token.

pub mod attributes;
pub mod signed_data;
pub mod tsp;
pub mod verify;

pub use signed_data::{CadesOptions, TimestampFn, sign};
pub use verify::{Attributes, VerifyOptions, VerifyReport, verify};
