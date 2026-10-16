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
//! Since B-LT it also checks what the document archives for later: when the
//! catalog carries a `/DSS`, every certificate in it has to parse, every CRL
//! has to verify under the key of the CA it names, every OCSP response has to
//! be a successful answer, and for every signature the `/VRI` covers, the
//! chain has to rebuild **from the archived data alone** — with at least one
//! revocation datum per CA certificate of that chain, and no certificate of
//! the chain revoked by the data archived for it. And since B-LTA, every
//! document time-stamp token has to imprint the bytes its own `/ByteRange`
//! covers.
//!
//! What is still *not* checked here, because it is layer 3/4 territory in
//! docs/validation.md: certificate policy (key usage, basic constraints,
//! qualification), the signature policy, the signature of an OCSP response
//! (only its structure and its `certStatus`, see
//! [`openfirma_cades::revocation`]), the signature of the time-stamp token
//! itself (that is `openssl ts -verify`'s job in the crosscheck suite), and
//! the "does the signature cover the latest revision" judgement a PDF viewer
//! makes.

use openfirma_cades::revocation::{self, CrlReport, OcspCertId};
use openfirma_cades::verify::VerifyOptions;
use openfirma_core::alg::DigestAlg;
use openfirma_core::cert::CertificateHandle;
use openfirma_core::{Error, Result};

use crate::inspect;
use crate::ltv;
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
    pub reports: Vec<openfirma_cades::VerifyReport>,
}

/// One `/Type /DocTimeStamp` dictionary of the document (B-LTA).
#[derive(Clone, Debug)]
pub struct DocTimeStampReport {
    /// The object holding the dictionary.
    pub object: ObjRef,
    /// The two ranges its token covers.
    pub byte_range: [usize; 4],
    /// The digest the token imprints under.
    pub digest: DigestAlg,
    /// The RFC 3161 token in `/Contents`, without the zero padding.
    pub token: Vec<u8>,
}

/// One signature whose chain could be rebuilt from the `/DSS` alone.
#[derive(Clone, Debug)]
pub struct DssChain {
    /// The 1-based index of the signature, in the order `verify` reports them.
    pub signature: usize,
    /// Subjects from the signer upwards, the trust anchor last.
    pub subjects: Vec<String>,
    /// Subject of the trust anchor the chain reached.
    pub trust_anchor: String,
}

/// What the document's `/DSS` carries and what the checks made of it.
#[derive(Clone, Debug)]
pub struct DssReport {
    /// Certificates archived under `/Certs`.
    pub certificates: usize,
    /// One report per CRL archived under `/CRLs`, each signature verified.
    pub crls: Vec<CrlReport>,
    /// Successful OCSP responses archived under `/OCSPs`.
    pub ocsps: usize,
    /// The `/VRI` keys: the upper case hex SHA-1 of each archived signature
    /// value.
    pub vri_keys: Vec<String>,
    /// The chains rebuilt from the archived data, per covered signature.
    pub chains: Vec<DssChain>,
    /// 1-based indices of the signatures the `/VRI` does not cover, because
    /// the validation data predates them. They verify as signatures, they
    /// just are not archived.
    pub uncovered: Vec<usize>,
}

/// The verdict over a whole document.
#[derive(Clone, Debug)]
pub struct DocumentReport {
    /// One entry per `/Type /Sig` dictionary, in object number order.
    pub signatures: Vec<SignatureReport>,
    /// One entry per `/Type /DocTimeStamp` dictionary.
    pub document_timestamps: Vec<DocTimeStampReport>,
    /// The `/DSS` report, when the document carries validation data.
    pub dss: Option<DssReport>,
}

/// Verifies every signature in `pdf` against `opts`, plus its document
/// time-stamps and its `/DSS` validation data when it carries them.
///
/// `Ok` only happens when the document carries at least one signature and all
/// of it passes every check. Otherwise the error lists each failing part and
/// the check that failed it.
pub fn verify(pdf: &[u8], opts: &VerifyOptions) -> Result<DocumentReport> {
    let signatures = inspect::signatures(pdf)?;
    if signatures.is_empty() {
        return Err(Error::Verification(
            "the document carries no signature dictionary".into(),
        ));
    }

    let mut sig_reports = Vec::with_capacity(signatures.len());
    let mut failures = Vec::new();
    for (i, sig) in signatures.iter().enumerate() {
        let label = format!(
            "signature {} (object {} {})",
            i + 1,
            sig.object.num,
            sig.object.generation
        );
        match verify_one(pdf, sig, opts) {
            Ok(reports) => sig_reports.push(SignatureReport {
                object: sig.object,
                byte_range: sig.byte_range,
                reports,
            }),
            Err(e) => failures.push(format!("{label}: {}", unwrap(&e))),
        }
    }

    let mut dts_reports = Vec::new();
    for (i, t) in inspect::document_timestamps(pdf)?.iter().enumerate() {
        let label = format!(
            "document time-stamp {} (object {} {})",
            i + 1,
            t.object.num,
            t.object.generation
        );
        if t.problems.is_empty() {
            // read_document_timestamp only leaves the digest unset when it
            // also left problems, so an empty problem list always has one
            let digest = t.digest.unwrap_or(DigestAlg::Sha256);
            dts_reports.push(DocTimeStampReport {
                object: t.object,
                byte_range: t.byte_range,
                digest,
                token: t.token.clone(),
            });
        } else {
            for p in &t.problems {
                failures.push(format!("{label}: {p}"));
            }
        }
    }

    let mut dss = None;
    match verify_dss(pdf, &signatures, opts) {
        Ok(report) => dss = report,
        Err(e) => failures.push(format!("validation data (/DSS): {}", unwrap(&e))),
    }

    if !failures.is_empty() {
        return Err(Error::Verification(failures.join("; ")));
    }
    Ok(DocumentReport {
        signatures: sig_reports,
        document_timestamps: dts_reports,
        dss,
    })
}

fn verify_one(
    pdf: &[u8],
    sig: &inspect::Signature,
    opts: &VerifyOptions,
) -> Result<Vec<openfirma_cades::VerifyReport>> {
    let [a, b, c, d] = sig.byte_range;
    // The structural claim first: the ranges must be inside the file and the
    // hole between them must be exactly the /Contents hex string, otherwise
    // what is extracted below is not what the signer digested.
    if a != 0 {
        return Err(Error::Verification(format!(
            "the first /ByteRange segment starts at {a}, not at 0"
        )));
    }
    // checked: the numbers come out of the document, and a pair whose sum
    // does not fit in an offset describes no segment of any file
    let inside = c
        .checked_add(d)
        .is_some_and(|end| end <= pdf.len() && b <= c);
    if !inside {
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

/// The `/DSS` checks. Returns `None` for a document without validation data,
/// which is the B-B case and not an error.
fn verify_dss(
    pdf: &[u8],
    signatures: &[inspect::Signature],
    opts: &VerifyOptions,
) -> Result<Option<DssReport>> {
    let Some(dss) = ltv::read_dss(pdf)? else {
        return Ok(None);
    };

    // every archived certificate has to parse: an archive nobody can read is
    // worse than none, because a validator may trust its completeness
    let mut cert_handles: Vec<CertificateHandle> = Vec::with_capacity(dss.certs.len());
    for (i, (_, der)) in dss.certs.iter().enumerate() {
        match CertificateHandle::from_der(der) {
            Ok(handle) => cert_handles.push(handle),
            Err(e) => {
                return Err(fail_dss(&format!(
                    "certificate {} archived under /Certs does not parse: {e}",
                    i + 1
                )));
            }
        }
    }

    // every CRL: parse, signature under the naming CA's key, dates
    let mut issuers = cert_handles.clone();
    issuers.extend_from_slice(&opts.trust_anchors);
    let mut crls: Vec<CrlReport> = Vec::with_capacity(dss.crls.len());
    for (i, (_, der)) in dss.crls.iter().enumerate() {
        match revocation::verify_crl(der, &issuers, opts.validation_time) {
            Ok(report) => crls.push(report),
            Err(e) => {
                return Err(fail_dss(&format!(
                    "CRL {} archived under /CRLs is not a revocation datum: {}",
                    i + 1,
                    unwrap(&e)
                )));
            }
        }
    }

    // every OCSP response: a successful answer, read down to its CertIDs
    let mut ocsp_ids: Vec<OcspCertId> = Vec::new();
    for (i, (_, der)) in dss.ocsps.iter().enumerate() {
        match revocation::parse_ocsp_response(der) {
            Ok(ids) => ocsp_ids.extend(ids),
            Err(e) => {
                return Err(fail_dss(&format!(
                    "OCSP response {} archived under /OCSPs is not a revocation datum: {}",
                    i + 1,
                    unwrap(&e)
                )));
            }
        }
    }

    let vri_keys = dss
        .vri_keys()
        .map_err(|e| fail_dss(&format!("the /VRI dictionary cannot be read: {e}")))?;

    let mut chains = Vec::new();
    let mut uncovered = Vec::new();
    for (i, sig) in signatures.iter().enumerate() {
        // a signature whose /Contents or CMS cannot be read has already
        // failed above; the /DSS check adds nothing to that verdict
        let (Some(key), Ok(signers)) = (
            ltv::vri_key(pdf, sig),
            openfirma_cades::verify::signer_certificates(&sig.cms),
        ) else {
            continue;
        };
        if !vri_keys.contains(&key) {
            uncovered.push(i + 1);
            continue;
        }

        for signer in &signers {
            if !cert_handles.iter().any(|c| c.der() == signer.der()) {
                return Err(fail_dss(&format!(
                    "the /VRI claims to cover signature {} (key {key}) but the /Certs archive \
                     does not carry its signer certificate, so the chain cannot be rebuilt \
                     from the validation data alone",
                    i + 1
                )));
            }
            let chain = openfirma_cades::verify::chain_certificates(
                signer,
                &cert_handles,
                &opts.trust_anchors,
                opts.validation_time,
            )
            .map_err(|e| {
                fail_dss(&format!(
                    "the chain of signature {} cannot be rebuilt from the /DSS contents \
                     alone: {}",
                    i + 1,
                    unwrap(&e)
                ))
            })?;

            // every CA of the chain has to have contributed at least one
            // revocation datum, and no certificate below the anchor may be
            // revoked by the data archived for it
            for ca in &chain[1..] {
                let ca_subject = ca.subject_der().map_err(|e| fail_dss(&e.to_string()))?;
                let by_crl = crls.iter().any(|r| r.issuer_der == ca_subject);
                let by_ocsp = ocsp_ids
                    .iter()
                    .any(|id| ltv::ocsp_id_names_ca(id, ca).unwrap_or(false));
                if !by_crl && !by_ocsp {
                    return Err(fail_dss(&format!(
                        "the archive carries no revocation datum issued by \"{}\", a CA of \
                         the chain of signature {}: a B-LT /DSS needs at least one CRL or \
                         OCSP response per CA certificate",
                        ca.subject(),
                        i + 1
                    )));
                }
            }
            for pair in chain.windows(2) {
                let (child, parent) = (&pair[0], &pair[1]);
                let parent_subject = parent.subject_der().map_err(|e| fail_dss(&e.to_string()))?;
                let serial = child.serial_number().as_bytes().to_vec();
                if crls
                    .iter()
                    .any(|r| r.issuer_der == parent_subject && r.revoked_serials.contains(&serial))
                {
                    return Err(fail_dss(&format!(
                        "the archived CRL issued by \"{}\" revokes \"{}\" (serial {}), a \
                         certificate of the chain of signature {}",
                        parent.subject(),
                        child.subject(),
                        hex::encode(&serial),
                        i + 1
                    )));
                }
                if ocsp_ids.iter().any(|id| {
                    id.revoked
                        && id.serial == serial
                        && ltv::ocsp_id_names_ca(id, parent).unwrap_or(false)
                }) {
                    return Err(fail_dss(&format!(
                        "an archived OCSP response answers \"revoked\" for \"{}\" (serial \
                         {}), a certificate of the chain of signature {}",
                        child.subject(),
                        hex::encode(&serial),
                        i + 1
                    )));
                }
            }

            let subjects: Vec<String> = chain.iter().map(|c| c.subject().to_string()).collect();
            let trust_anchor = subjects.last().cloned().unwrap_or_default();
            chains.push(DssChain {
                signature: i + 1,
                subjects,
                trust_anchor,
            });
        }
    }

    Ok(Some(DssReport {
        certificates: cert_handles.len(),
        crls,
        ocsps: dss.ocsps.len(),
        vri_keys,
        chains,
        uncovered,
    }))
}

fn fail_dss(detail: &str) -> Error {
    Error::Verification(detail.to_string())
}

/// The message of a verification error without the shared prefix, so the
/// per signature labels do not stack "verification:" twice.
fn unwrap(e: &Error) -> String {
    match e {
        Error::Verification(m) => m.clone(),
        other => other.to_string(),
    }
}
