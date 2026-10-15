//! Cryptographic verification of a signed PDF.
//!
//! `openfirma inspect` reports the structure of every signature dictionary and
//! checks the `/ByteRange` claim, but it verifies no crypto and no chain.
//! This module closes that gap: for **every** signature in the document, not
//! just the last one, it extracts the bytes `/ByteRange` covers and the CMS in
//! `/Contents`, and hands both to [`openfirma_cades::verify`]. A co-signed
//! document therefore only verifies when each of its signatures does, each
//! over its own revision.
//!
//! Revocation, certification policy and the "does the signature cover the
//! latest revision" judgement a PDF viewer makes are not part of this, see
//! docs/validation.md for what does.

use openfirma_cades::verify::{VerifyOptions, VerifyReport};
use openfirma_core::{Error, Result};

use crate::inspect;
use crate::pdf::ObjRef;

/// One signature dictionary of the document, with its CAdES reports. A
/// dictionary normally carries exactly one `SignerInfo`, but the CMS format
/// allows more and nothing here collapses them.
#[derive(Clone, Debug)]
pub struct SignatureReport {
    /// The object holding the signature dictionary.
    pub object: ObjRef,
    /// The two ranges the signature covers.
    pub byte_range: [usize; 4],
    /// One report per `SignerInfo` of the CMS in `/Contents`.
    pub reports: Vec<VerifyReport>,
}

/// Verifies every signature in `pdf` against `opts`.
///
/// `Ok` only happens when the document carries at least one signature and all
/// of them pass every check. Otherwise the error lists each failing signature
/// and the check that failed it.
pub fn verify(pdf: &[u8], opts: &VerifyOptions) -> Result<Vec<SignatureReport>> {
    let signatures = inspect::signatures(pdf)?;
    if signatures.is_empty() {
        return Err(Error::Verification(
            "the document carries no signature dictionary".into(),
        ));
    }

    let mut out = Vec::with_capacity(signatures.len());
    let mut failures = Vec::new();
    for (i, sig) in signatures.iter().enumerate() {
        let label = format!(
            "signature {} (object {} {})",
            i + 1,
            sig.object.num,
            sig.object.generation
        );
        match verify_one(pdf, sig, opts) {
            Ok(reports) => out.push(SignatureReport {
                object: sig.object,
                byte_range: sig.byte_range,
                reports,
            }),
            Err(e) => failures.push(format!("{label}: {}", unwrap(&e))),
        }
    }
    if !failures.is_empty() {
        return Err(Error::Verification(failures.join("; ")));
    }
    Ok(out)
}

fn verify_one(
    pdf: &[u8],
    sig: &inspect::Signature,
    opts: &VerifyOptions,
) -> Result<Vec<VerifyReport>> {
    let [a, b, c, d] = sig.byte_range;
    // The structural claim first: the ranges must be inside the file and the
    // hole between them must be exactly the /Contents hex string, otherwise
    // what is extracted below is not what the signer digested.
    if a != 0 {
        return Err(Error::Verification(format!(
            "the first /ByteRange segment starts at {a}, not at 0"
        )));
    }
    if b > c || c + d > pdf.len() {
        return Err(Error::Verification(format!(
            "/ByteRange [{a} {b} {c} {d}] does not describe two segments inside the {} byte file",
            pdf.len()
        )));
    }
    let gap = &pdf[b..c];
    if gap.first() != Some(&b'<') || gap.last() != Some(&b'>') {
        return Err(Error::Verification(
            "the hole between the /ByteRange segments is not the /Contents hex string".into(),
        ));
    }
    if sig.cms.is_empty() {
        return Err(Error::Verification(
            "no CMS could be read from /Contents".into(),
        ));
    }

    let mut covered = Vec::with_capacity(b + d);
    covered.extend_from_slice(&pdf[a..a + b]);
    covered.extend_from_slice(&pdf[c..c + d]);
    openfirma_cades::verify::verify(&sig.cms, Some(&covered), opts)
}

/// The message of a verification error without the shared prefix, so the
/// per signature labels do not stack "verification:" twice.
fn unwrap(e: &Error) -> String {
    match e {
        Error::Verification(m) => m.clone(),
        other => other.to_string(),
    }
}
