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
//! Current level: B-B. No timestamp, no validation data, no document timestamp
//! dictionary.

pub mod appearance;
pub mod inspect;
pub mod pdf;
pub mod sign;
pub mod stream;
pub mod update;
pub mod verify;

pub use appearance::Appearance;
pub use sign::{DEFAULT_CONTENTS_RESERVED, PadesOptions};

/// Adds a PAdES-B-B signature and returns the whole signed document.
///
/// Named `pades_sign` on re-export because `sign` is also the module, and a
/// `use openfirma_pades::sign` that can mean either is a trap.
pub use sign::sign as pades_sign;

pub use verify::SignatureReport;
/// Verifies every signature in a signed PDF, each over the bytes its own
/// `/ByteRange` covers. Renamed on re-export for the same reason as
/// [`pades_sign`].
pub use verify::verify as pades_verify;
