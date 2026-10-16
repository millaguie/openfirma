//! PAdES: PDF Advanced Electronic Signatures.
//!
//! A PAdES signature is a detached CAdES `SignedData` (see `openfirma-cades`)
//! carried in the `/Contents` of a PDF signature dictionary, over a document
//! range that excludes that value. Everything else here is the PDF plumbing
//! that puts it there: reading enough of the input to find its catalog and its
//! first page, and appending a second revision that adds the field.
//!
//! Two properties are worth stating up front, because they are the ones a
//! validator actually checks and the ones easiest to get subtly wrong:
//!
//! - `/ByteRange` describes two segments whose concatenation is the whole file
//!   minus the `/Contents` value, brackets included. The CMS `messageDigest` is
//!   the digest of exactly that concatenation.
//! - the input document's bytes are reproduced unchanged, and the signature is
//!   an incremental update after them. See
//!   docs/adr/0003-incremental-update.md.
//!
//! Levels: B-B, B-T (RFC 3161 token as an unsigned attribute of the CMS),
//! B-LT and B-LTA (ETSI EN 319 142-1). The long-term levels are further
//! revisions appended in the order the specification names — signature, then
//! the `/DSS` validation data, then the document time-stamp — see
//! [`ltv`]. Nothing in this crate touches the network: the time-stamp
//! transport and the validation data are the caller's.

pub mod appearance;
pub mod inspect;
pub mod ltv;
pub mod pdf;
pub mod revisions;
pub mod sign;
pub mod stream;
pub mod update;
pub mod verify;

pub use appearance::Appearance;
pub use ltv::{Dss, RevocationBytes, add_document_timestamp, add_validation_data, read_dss};
pub use sign::{DEFAULT_CONTENTS_RESERVED, PadesOptions};

/// Adds a PAdES signature and returns the whole signed document. The level
/// follows the options: B-B by default, B-T with
/// [`PadesOptions::timestamp`], B-LT with
/// [`PadesOptions::revocation`]/[`PadesOptions::validation_certs`], B-LTA
/// with [`PadesOptions::document_timestamp`] on top.
///
/// Named `pades_sign` on re-export because `sign` is also the module, and a
/// `use openfirma_pades::sign` that can mean either is a trap.
pub use sign::sign as pades_sign;

/// Verifies every signature in a signed PDF, each over the bytes its own
/// `/ByteRange` covers, plus — when the document carries them — the document
/// time-stamps and the `/DSS` validation data of the B-LT level. Renamed on
/// re-export for the same reason as [`pades_sign`].
pub use verify::verify as pades_verify;
pub use verify::{DocTimeStampReport, DocumentReport, DssChain, DssReport, SignatureReport};
