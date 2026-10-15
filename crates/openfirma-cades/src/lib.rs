//! CAdES: CMS `SignedData` (RFC 5652) with the ETSI EN 319 122-1 attributes.
//!
//! Entry point is [`sign`], which produces a complete `ContentInfo`. The same
//! machinery serves PAdES, whose `/Contents` is a detached `SignedData` built
//! with [`CadesOptions::encapsulate_content`] set to false.
//!
//! Current level: B-B. Unsigned attributes can be injected through
//! [`CadesOptions::unsigned_attributes`], which is how B-T will carry the TSA
//! token.

pub mod attributes;
pub mod signed_data;
pub mod tsp;

pub use signed_data::{CadesOptions, TimestampFn, sign};
