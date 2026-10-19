//! The signing dispatcher every frontend shares: the terminal's `sign`, the
//! window, and the browser protocol all sign a format through this exact call
//! sequence (finding M-4: with three separate `match`es — one per frontend —
//! a renamed or retuned format signed in one place and was unknown or subtly
//! different in another, and no test could notice). The choice lives here,
//! once.
//!
//! This module is where it *can* live once: openfirma-browser already depends
//! on the three format crates and links nothing graphical, so both frontends
//! reach it without pulling UI code into each other. (openfirma-core cannot:
//! the format crates depend on core, not the reverse.)

use openfirma_cades::{CadesOptions, TimestampFn};
use openfirma_core::alg::DigestAlg;
use openfirma_core::signer::Signer;
use openfirma_core::workflow::Format;
use openfirma_core::{Error, Result};
use openfirma_pades::{Appearance, PadesOptions, RevocationBytes};

/// What a caller asks for: the format string (the same spelling the CLI's
/// `--format` takes), the digest, and an optional TSA provider already wired
/// to its transport (each frontend owns its transport; see `signer_for` docs
/// in openfirma-keystore ADR-0004 for why nothing here fetches). The CAdES
/// attribute knobs and the long-term material (CRLs, OCSP responses,
/// validation certificates) are what the terminal collects; the window and
/// the browser leave them empty, and a request that names
/// `pades-b-lt`/`pades-b-lta` without them is refused below with an honest
/// sentence instead of silently signing a weaker document: B-LT without
/// revocation data is nothing, and `openfirma verify` would say so afterwards.
pub struct SignRequest<'a> {
    pub format: &'a str,
    /// SHA-256 through [`SignRequest::new`] — every frontend's default; there
    /// is no [`Default`] for the whole request precisely so a caller cannot
    /// forget this field into some other value.
    pub digest: DigestAlg,
    pub timestamp: Option<TimestampFn>,
    pub visible: Option<Appearance>,
    pub reason: Option<String>,
    /// CAdES `encapsulatedContentInfo`: the terminal's `--encapsulate`.
    pub cades_encapsulate_content: bool,
    /// The MIME type both CMS shapes can carry: CAdES `SMimeTypes`-equivalent
    /// content info and XAdES `DataObjectFormat` (the terminal's
    /// `--mime-type`).
    pub cades_mime_type: Option<String>,
    /// CAdES `contentHint`: the terminal's advanced flag. The CAdES default is
    /// AutoFirma's generic `"binary"`; `Some(String::new())` means that same
    /// default, and only the CLI's `--no-content-hint` sets it to `None`.
    pub cades_content_hint: Option<String>,
    /// Whether the contentHint attribute is included at all — AutoFirma drops
    /// it on `includeContentHintAttribute=false`, the terminal on
    /// `--no-content-hint` (finding B2: not sending it by default was the diff).
    pub cades_include_content_hint: bool,
    /// Opt out of the conservative algorithm policy on the signing side —
    /// the terminal's `--allow-weak-algorithms`. Default false: SHA-1 digests
    /// and RSA keys below 2048 bits are refused before any crypto (finding
    /// M5); whoever sets this owns what validators make of the result.
    pub cades_allow_weak_algorithms: bool,
    /// ETSI `signaturePolicyIdentifier` as an OID string — the terminal's
    /// `--signature-policy`, AutoFirma's `policyIdentifier` extraParam. A bad
    /// OID is refused at dispatch, not silently dropped.
    pub cades_signature_policy: Option<String>,
    /// The `sigPolicyHash` bytes for [`Self::cades_signature_policy`] — the
    /// digest of the policy assertion text, AutoFirma's
    /// `policyIdentifierHash`. Empty keeps the placeholder byte.
    pub cades_signature_policy_hash: Vec<u8>,
    /// ETSI `commitmentTypeIndication` as an OID string — the terminal's
    /// `--commitment-type`, AutoFirma's `commitmentTypeIndication0Identifier`.
    pub cades_commitment_type: Option<String>,
    /// Copy the certificate's certificatePolicies into the signer-certificate
    /// attribute (AutoFirma's default; `--no-certificate-policies` off).
    pub cades_include_certificate_policies: bool,
    /// Whether the SignerInfo names the issuer and serial (`--no-issuer-serial`
    /// turns it off).
    pub cades_include_issuer_serial: bool,
    /// CAdES `signingTime`: `Some(t)` fixes it, `cades_no_signing_time` omits
    /// the attribute (the terminal's `--no-signing-time`), and neither is
    /// cades' own default of now.
    pub cades_signing_time: Option<std::time::SystemTime>,
    pub cades_no_signing_time: bool,
    /// The PAdES `/SigFlags` form field name (`--field-name`).
    pub field_name: Option<String>,
    /// Width of the `/Contents` hole to reserve (the CLI's advanced flag).
    /// `None` keeps pades' own default.
    pub contents_reserved: Option<usize>,
    /// PAdES `/Location` and `/ContactInfo` dictionary entries.
    pub location: Option<String>,
    pub contact_info: Option<String>,
    /// Certificates whose chains the /DSS archives, and that anchor the TSA
    /// token's trust (`--validation-cert`).
    pub validation_certs: Vec<openfirma_core::CertificateHandle>,
    /// Revocation material to archive (the CLI's `--crl`/`--ocsp` files).
    pub revocation: Vec<RevocationBytes>,
    /// B-LTA document time-stamp. The terminal passes `Some(stamp)` whenever
    /// it asks for the level at all — its `--format pades-b-lta` gate says a
    /// pre-fetched `--timestamp-token` cannot serve this stamp (it imprints
    /// bytes that only exist while signing), so only `--tsa` reaches here.
    pub document_timestamp: Option<TimestampFn>,
    /// Which frontend is asking, so an incomplete long-term refusal can name
    /// the flags the citizen actually has: the window offers none of the LTV
    /// material and points at the terminal instead.
    pub from_window: bool,
    /// Sign a document certified with `/Perms /DocMDP` `/P 1` anyway (the
    /// terminal's `--allow-certified`, AutoFirma's `allowSigningCertifiedPdfs`).
    /// The window never sets it: overriding an author's certification is the
    /// deliberate decision of whoever runs the command, not a default either
    /// frontend can take for them.
    pub allow_signing_certified: bool,
}

impl<'a> SignRequest<'a> {
    /// The plain shape every caller starts from: format and digest given,
    /// everything else at the shared default (detached CAdES, no appearance,
    /// no LTV material).
    pub fn new(format: &'a str, digest: DigestAlg) -> Self {
        Self {
            format,
            digest,
            timestamp: None,
            visible: None,
            reason: None,
            cades_encapsulate_content: false,
            cades_mime_type: None,
            cades_content_hint: None,
            cades_include_content_hint: true,
            cades_allow_weak_algorithms: false,
            cades_signature_policy: None,
            cades_signature_policy_hash: Vec::new(),
            cades_commitment_type: None,
            cades_include_certificate_policies: true,
            // The CAdES default both frontends sign with unless told otherwise.
            cades_include_issuer_serial: true,
            cades_signing_time: Some(std::time::SystemTime::now()),
            cades_no_signing_time: false,
            field_name: None,
            contents_reserved: None,
            location: None,
            contact_info: None,
            validation_certs: Vec::new(),
            revocation: Vec::new(),
            document_timestamp: None,
            from_window: false,
            allow_signing_certified: false,
        }
    }

    /// Mark the request as coming from the window, so an incomplete
    /// long-term refusal points at the terminal instead of at flags the
    /// citizen was never shown.
    pub fn from_window(mut self) -> Self {
        self.from_window = true;
        self
    }
}

/// Whole-second clock shared by every timestamp one signature writes.
///
/// PAdES puts the signing instant into /M at second resolution, and a CAdES
/// signingTime attribute is seconds too: an instant read from the raw clock
/// can straddle a boundary between two reads of "the same" signing, and two
/// otherwise identical signatures then differ for no reason anyone can see —
/// measured on CI's macOS runner, where the protocol front door and this
/// dispatcher disagreed by exactly one /M second. Freezing to the whole
/// second makes every read inside one second return one instant; real UTC is
/// preserved (this is a floor, never an invented time), and a signature still
/// says what its own clock said at signing time.
pub mod clock {
    use std::sync::OnceLock;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// `now()` floored to the second, resolved on first use and stable for
    /// the life of the process — tests that sign twice expect both copies
    /// byte-identical, and production signing timestamps within one process
    /// agree with themselves.
    pub fn now() -> SystemTime {
        static SECOND: OnceLock<SystemTime> = OnceLock::new();
        *SECOND.get_or_init(|| {
            let secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            UNIX_EPOCH + std::time::Duration::from_secs(secs)
        })
    }
}

/// Every format openfirma signs, in the order a UI should list them. The CLI
/// builds its `--format` values from exactly this table (the parity test
/// `every_format_is_one_table_across_terminal_window_and_dispatcher` fails if
/// either side ever renames one), and the window lists the subset its chosen
/// file supports through [`openfirma_core::workflow::Format::supported_formats`].
pub fn all_formats() -> &'static [&'static str] {
    &[
        "cades-b-b",
        "pades-b-b",
        "pades-b-lt",
        "pades-b-lta",
        "xades-b-b",
    ]
}

/// The format string's fixed display name (the labels of the CLI's `--format`
/// values; one table so both frontends print identical success lines).
pub fn format_label(format: &str) -> &'static str {
    match format {
        "cades-b-b" => "CAdES-B-B",
        "pades-b-b" => "PAdES-B-B",
        "pades-b-lt" => "PAdES-B-LT",
        "pades-b-lta" => "PAdES-B-LTA",
        "xades-b-b" => "XAdES-B-B",
        // An unknown string is echoed as given: it came from a caller's own
        // flag, and inventing a prettier lie helps nobody.
        _ => "desconocido",
    }
}

/// Produce the signature for one request against `detected`, the kind of file
/// `content` actually is. The window's simple path (format picked in the UI,
/// nothing else) arrives here; so does anything that wants the gate explicit.
pub fn execute_request(
    req: &mut SignRequest<'_>,
    detected: Format,
    content: &[u8],
    signer: &dyn Signer,
) -> Result<Vec<u8>> {
    // A *known* format that cannot carry this file shape is refused here,
    // before any signing: the citizen who picks CAdES for a PDF (or the
    // reverse) gets one sentence about what they have, not an ASN.1 stack
    // trace. A string the shared table does not know is NOT refused by this
    // gate — even one spelled like a deeper level of a shape it fits: it
    // falls through to the dispatcher, which answers "unknown signature
    // format". A renamed level reaching an old frontend must hear that
    // sentence, not a shape complaint (finding M-4).
    let allowed = detected.supported_formats();
    if !allowed.contains(&req.format) && all_formats().contains(&req.format) {
        // Round two, N-6: a UTF-16 XML is XML to the person holding the file,
        // and `Format::detect` calls it Data because Data is the only shape it
        // can honestly sign — a detached CAdES over the bytes as they stand.
        // Answering "it holds plain data" to someone who asked for XAdES over
        // `factura.xml` sent them looking for a fault in their document; the
        // cause is the encoding, and the way out is the same `iconv` the
        // reader's Latin-1 refusal prints.
        if detected == Format::Data && openfirma_core::workflow::is_utf16_xml(content) {
            return Err(Error::Other(format!(
                "{} is asked for over a document that is XML written in UTF-16. openfirma \
                 signs XML it can read as UTF-8, so convert it first: iconv -f UTF-16 -t \
                 UTF-8 in.xml > out.xml (and update its encoding declaration). Signing the \
                 bytes as they stand is possible and needs no conversion, but it is a \
                 detached CAdES (cades-b-b), not an XML signature.",
                req.format
            )));
        }
        return Err(Error::Other(format!(
            "{} is not a format this file can be signed as (it holds {}).",
            req.format,
            match detected {
                Format::Pdf => "a PDF document",
                Format::Xml => "an XML document",
                Format::Data => "plain data",
            }
        )));
    }
    dispatch(req, content, signer)
}

/// [`execute_request`] with the detection folded in, for callers that only
/// have bytes (the CLI): it gates on what the content actually holds rather
/// than what its name claims.
pub fn execute_with_detection(
    req: &mut SignRequest<'_>,
    content: &[u8],
    signer: &dyn Signer,
) -> Result<Vec<u8>> {
    execute_request(req, Format::detect(content), content, signer)
}

/// The pre-computed-hash shape of the browser protocol (`properties` key
/// `precalculatedHashAlgorithm`, finding A-4): a detached CAdES whose
/// `messageDigest` is the sede's own hash, never re-hashed — exactly AutoFirma's
/// `CAdESParameters.load` branch (`dataDigest = data`). Dispatch only reaches
/// this for format names that resolve to CAdES: XAdES and PAdES carry the hash
/// inside their own document shapes, which openfirma cannot compute from a bare
/// imprint, and the browser dispatch refuses those combinations by name instead
/// of quietly signing something else.
pub fn dispatch_prehashed_cades(
    req: &mut SignRequest<'_>,
    message_imprint: &[u8],
    signer: &dyn Signer,
) -> Result<Vec<u8>> {
    if req.format != "cades-b-b" {
        return Err(Error::Other(format!(
            "a pre-computed hash can only be signed as a detached CAdES ({} cannot carry \
             an imprint this client did not compute: AutoFirma's own signers restrict hash \
             signing to the CMS/CAdES/XMLdSig/XAdES shapes and openfirma implements the CAdES \
             one)",
            req.format
        )));
    }
    // The knob-by-knob mirror of dispatch's cades arm, with the digest replaced
    // by the caller's imprint. It MUST stay a mirror: any attribute added to
    // `dispatch`'s CAdES shape that is missing here would make pre-hashed
    // browser signatures structurally different from terminal ones (M-4 again,
    // one level down). The shared pieces are assembled once, in cades_options();
    // the only difference between the two paths is the messageDigest bytes, so
    // that stays provable by reading the two calls.
    let opts = cades_options(req)?;
    // The first argument is the (unsent) content: `sign_with_digest` never puts
    // it anywhere in a detached signature, so passing the imprint keeps one
    // value where none is read.
    openfirma_cades::sign_with_digest(message_imprint, message_imprint, signer, &opts)
}

/// The CAdES options table for one request, exactly as dispatch builds them;
/// split out so `dispatch_prehashed_cades` cannot drift from the normal path.
/// A malformed policy OID refuses with the same sentence the normal path uses
/// (never a silent drop).
fn cades_options(req: &mut SignRequest<'_>) -> Result<openfirma_cades::CadesOptions> {
    let signature_policy = parse_policy_oid(req.cades_signature_policy.as_deref())?;
    let commitment_type = parse_policy_oid(req.cades_commitment_type.as_deref())?;
    let mut opts = openfirma_cades::CadesOptions {
        digest: req.digest,
        encapsulate_content: req.cades_encapsulate_content,
        mime_type: req.cades_mime_type.clone(),
        content_hint: if req.cades_include_content_hint {
            Some(req.cades_content_hint.clone().unwrap_or_else(|| {
                openfirma_cades::AUTOFIRMA_DEFAULT_CONTENT_DESCRIPTION.to_string()
            }))
        } else {
            None
        },
        include_issuer_serial: req.cades_include_issuer_serial,
        include_certificate_policies: req.cades_include_certificate_policies,
        signature_policy,
        signature_policy_hash: req.cades_signature_policy_hash.clone(),
        commitment_type,
        algorithms: if req.cades_allow_weak_algorithms {
            openfirma_cades::verify::AlgorithmPolicy::All
        } else {
            openfirma_cades::verify::AlgorithmPolicy::Conservative
        },
        ..openfirma_cades::CadesOptions::default()
    };
    opts.timestamp = req.timestamp.clone();
    if req.cades_no_signing_time {
        opts.signing_time = None;
    } else if let Some(t) = req.cades_signing_time {
        opts.signing_time = Some(t);
    }
    Ok(opts)
}

/// [`dispatch`] with the file-shape gate lifted. The browser protocol uses
/// this (finding M-3): AutoFirma's launcher never filters a format by what the
/// document happens to be — a sede signs PDF bytes as detached CAdES every day
/// and AutoFirma signs them; only its GUI menus restrict, and openfirma's GUI
/// keeps that restriction through [`execute_request`]. A format the shared
/// dispatcher does not know still answers "unknown signature format", and a
/// shape it knows but cannot build from these bytes (PAdES over non-PDF) fails
/// inside that codec for its own true reason. Nothing here weakens a refusal:
/// it moves them where AutoFirma's are.
pub fn execute_protocol(
    req: &mut SignRequest<'_>,
    content: &[u8],
    signer: &dyn Signer,
) -> Result<Vec<u8>> {
    dispatch(req, content, signer)
}

/// Parses the optional OID strings of the two policy knobs. An empty string
/// means "not set"; anything that is not a dotted OID is an error naming the
/// value, because silently dropping it would sign without the attribute the
/// caller asked for.
fn parse_policy_oid(value: Option<&str>) -> Result<Option<const_oid::ObjectIdentifier>> {
    match value.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(None),
        Some(s) => {
            use std::str::FromStr;
            const_oid::ObjectIdentifier::from_str(s)
                .map(Some)
                .map_err(|_| Error::Other(format!("{s} is not an OID in dotted form")))
        }
    }
}

/// The dispatcher itself: format string in, signature bytes out. `pub` so the
/// browser protocol reaches it through `execute_protocol` without re-deriving
/// any rule (finding M-4: one dispatch for every frontend). Callers that must
/// gate on file shape use [`execute_request`]/[`execute_with_detection`].
pub fn dispatch(req: &mut SignRequest<'_>, content: &[u8], signer: &dyn Signer) -> Result<Vec<u8>> {
    match req.format {
        // The CLI's CAdES defaults, verbatim (docs/pades.md records why PAdES
        // pins its own shape): encapsulation is the caller's choice and the
        // GUI keeps AutoFirma's default off — detached is the citizen answer.
        "cades-b-b" => {
            // OID-string knobs are parsed here so both frontends refuse a bad
            // one identically.
            let signature_policy = parse_policy_oid(req.cades_signature_policy.as_deref())?;
            let commitment_type = parse_policy_oid(req.cades_commitment_type.as_deref())?;
            let mut opts = CadesOptions {
                digest: req.digest,
                encapsulate_content: req.cades_encapsulate_content,
                mime_type: req.cades_mime_type.clone(),
                content_hint: if req.cades_include_content_hint {
                    Some(req.cades_content_hint.clone().unwrap_or_else(|| {
                        openfirma_cades::AUTOFIRMA_DEFAULT_CONTENT_DESCRIPTION.to_string()
                    }))
                } else {
                    None
                },
                include_issuer_serial: req.cades_include_issuer_serial,
                include_certificate_policies: req.cades_include_certificate_policies,
                signature_policy,
                signature_policy_hash: req.cades_signature_policy_hash.clone(),
                commitment_type,
                algorithms: if req.cades_allow_weak_algorithms {
                    openfirma_cades::verify::AlgorithmPolicy::All
                } else {
                    openfirma_cades::verify::AlgorithmPolicy::Conservative
                },
                ..CadesOptions::default()
            };
            opts.timestamp = req.timestamp.clone();
            if req.cades_no_signing_time {
                opts.signing_time = None;
            } else if let Some(t) = req.cades_signing_time {
                opts.signing_time = Some(t);
            }
            openfirma_cades::sign(content, signer, &opts)
        }
        // PAdES fixes the CAdES shape itself: detached, no signingTime (the
        // time lives in /M), no contentHint. B-LT/B-LTA add revisions over
        // material only the CLI collects; when a request names those levels
        // without it, the refusal below is the one both frontends give.
        "pades-b-b" | "pades-b-lt" | "pades-b-lta" => {
            let ltv = matches!(req.format, "pades-b-lt" | "pades-b-lta");
            if ltv && req.timestamp.is_none() {
                // The same honest refusal `openfirma sign` prints for the LTA
                // level: the document time-stamp imprints bytes that exist
                // only while signing, so a pre-fetched token cannot serve it.
                return Err(Error::Other(
                    "the long-term levels need a TSA url (advanced options): their \
                     time-stamps imprint bytes that only exist while signing."
                        .into(),
                ));
            }
            if ltv && req.revocation.is_empty() {
                // B-LT without any revocation material is half a level, and
                // `openfirma verify` would report the archive as incomplete
                // afterwards. The window collects none, so it hears the CLI's
                // pointer; a terminal request says which flag is missing.
                return Err(Error::Other(if req.from_window {
                    "PAdES B-LT archives revocation data (CRLs or OCSP responses) that \
                     openfirma never downloads, and this window collects none: use \
                     `openfirma sign --format pades-b-lt --crl …` from a terminal for the \
                     long-term level."
                        .into()
                } else {
                    "PAdES B-LT archives revocation data and none was given: pass at least \
                     one --crl or --ocsp, certificates alone are only half of B-LT."
                        .into()
                }));
            }
            openfirma_pades::pades_sign(
                content,
                signer,
                &PadesOptions {
                    // Both timestamps of one signature come from one instant
                    // (the shared `clock::now()`, floored to the whole second)
                    // — /M and the document's /ModDate then describe the same
                    // clock tick even when signing straddles a second boundary.
                    // Real terminal signing keeps its own honest default here;
                    // this line only makes the browser frontend self-consistent.
                    sign_time: crate::signing::clock::now(),
                    digest: req.digest,
                    reason: req.reason.clone(),
                    location: req.location.clone(),
                    contact_info: req.contact_info.clone(),
                    field_name: req.field_name.clone(),
                    contents_reserved: req
                        .contents_reserved
                        .unwrap_or(openfirma_pades::DEFAULT_CONTENTS_RESERVED),
                    visible: req.visible.take(),
                    timestamp: req.timestamp.clone(),
                    validation_certs: std::mem::take(&mut req.validation_certs),
                    revocation: std::mem::take(&mut req.revocation),
                    document_timestamp: req.document_timestamp.clone(),
                    allow_signing_certified: req.allow_signing_certified,
                },
            )
        }
        // XAdES-B-B is enveloped and signs XML, see docs/xades.md. --digest
        // picks the signature algorithm; the reference digests stay SHA-512,
        // AutoFirma's default. signingTime is not optional here: the baseline
        // profile requires it, so the CAdES attribute knobs do not apply, and
        // --mime-type feeds DataObjectFormat instead.
        "xades-b-b" => openfirma_xades::xades_sign(
            content,
            signer,
            &openfirma_xades::XadesOptions {
                digest: req.digest,
                mime_type: req.cades_mime_type.clone(),
                ..Default::default()
            },
        ),
        other => Err(Error::Other(format!("unknown signature format {other:?}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The dispatcher must refuse a mismatched format *before* touching the
    /// signer: the same guard runs whether bytes were read by file, drag or
    /// paste. `none` stands for any signer — it is never called on a refusal.
    #[test]
    fn a_format_that_cannot_hold_the_file_is_refused() {
        let signer: &dyn Signer = &Mock;
        let mut req = SignRequest::new("cades-b-b", DigestAlg::Sha256).from_window();
        let err = execute_request(&mut req, Format::Pdf, b"%PDF-1.4\n", signer).unwrap_err();
        assert!(
            err.to_string()
                .contains("not a format this file can be signed as"),
            "{err}"
        );
        let mut req = SignRequest::new("pades-b-b", DigestAlg::Sha256).from_window();
        let err = execute_request(&mut req, Format::Data, b"hello", signer).unwrap_err();
        assert!(err.to_string().contains("plain data"), "{err}");
    }

    /// Round two, N-6: the same gate, over the file shape it described wrongly.
    /// A `factura.xml` saved as UTF-16 detects as Data (the XML reader speaks
    /// UTF-8), so asking for XAdES answered "it holds plain data" — a sentence
    /// about a document the person can see is XML, with no hint of the encoding
    /// or of the way out, while `docs/xades.md` §3 promised the encoding is
    /// named. Both halves belong in the refusal: what the file actually is, and
    /// that it can still be signed as it stands.
    #[test]
    fn xml_in_utf16_is_refused_naming_the_encoding_and_the_way_out() {
        let utf16: Vec<u8> = "\u{feff}<?xml version=\"1.0\" encoding=\"UTF-16\"?><facturae/>"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert_eq!(
            Format::detect(&utf16),
            Format::Data,
            "the premise of the finding: the detector cannot call these Xml"
        );
        let mut req = SignRequest::new("xades-b-b", DigestAlg::Sha256).from_window();
        let err = execute_request(&mut req, Format::Data, &utf16, &Mock).unwrap_err();
        let said = err.to_string();
        for needed in ["UTF-16", "iconv", "cades-b-b"] {
            assert!(said.contains(needed), "{said} never mentions {needed}");
        }
        assert!(
            !said.contains("plain data"),
            "the sentence N-6 was about is back: {said}"
        );
        // A plain text file still gets the generic sentence: this recognizes one
        // byte shape, it does not soften any other refusal.
        let mut req = SignRequest::new("xades-b-b", DigestAlg::Sha256).from_window();
        let err =
            execute_request(&mut req, Format::Data, b"contrato en texto plano", &Mock).unwrap_err();
        assert!(err.to_string().contains("plain data"), "{err}");
        // Neither refusal reached a signer: `Mock` panics the moment the
        // dispatcher asks who signs, so had the gate let a request through this
        // test would have aborted rather than got to assert. That the offer the
        // sentence makes is real — a detached CAdES over bytes as they stand —
        // is what `crates/openfirma-cli/tests/cli.rs` produces for `cades-b-b`.
    }

    #[test]
    fn half_a_long_term_level_is_refused() {
        // Without a TSA even B-LT cannot seal anything, so the first refusal
        // is the missing url…
        let mut req = SignRequest::new("pades-b-lt", DigestAlg::Sha256).from_window();
        let err = execute_request(&mut req, Format::Pdf, b"%PDF-1.4\n", &Mock).unwrap_err();
        assert!(err.to_string().contains("TSA url"), "{err}");
        // …and with one, the missing CRL/OCSP collection is still refused —
        // with the CLI's pointer to the terminal for a window request (the
        // GUI collects none)…
        let tsa: TimestampFn = std::sync::Arc::new(|_, _| Ok(vec![vec![0u8; 2]]));
        let mut req = SignRequest::new("pades-b-lt", DigestAlg::Sha256).from_window();
        req.timestamp = Some(tsa.clone());
        let err = execute_request(&mut req, Format::Pdf, b"%PDF-1.4\n", &Mock).unwrap_err();
        assert!(err.to_string().contains("openfirma sign"), "{err}");
        // …and with the missing flag named for a terminal request.
        let mut req = SignRequest::new("pades-b-lt", DigestAlg::Sha256);
        req.timestamp = Some(tsa);
        let err = execute_request(&mut req, Format::Pdf, b"%PDF-1.4\n", &Mock).unwrap_err();
        assert!(err.to_string().contains("--crl"), "{err}");
    }

    #[test]
    fn labels_are_the_clis_table() {
        assert_eq!(format_label("pades-b-lta"), "PAdES-B-LTA");
        assert_eq!(format_label("cades-b-b"), "CAdES-B-B");
    }

    /// The list every UI builds from, in listing order. The CLI's parity test
    /// compares its clap `--format` values against this exact set.
    #[test]
    fn all_formats_lists_every_level_once() {
        assert_eq!(
            all_formats(),
            &[
                "cades-b-b",
                "pades-b-b",
                "pades-b-lt",
                "pades-b-lta",
                "xades-b-b"
            ]
        );
        // every listed format has a label: an unnamed entry in the shared
        // table would print "desconocido" on a signing that just worked
        for f in all_formats() {
            assert_ne!(format_label(f), "desconocido", "{f}");
        }
    }

    /// The browser protocol is the third frontend (its own `Format` enum used
    /// to be its own dispatch): whatever format a sede's page names, it must
    /// reach exactly this dispatcher's signature for those bytes. A divergence
    /// here is M-4 reappearing through the wire.
    #[test]
    fn the_browser_dispatch_signs_what_this_dispatcher_signs() {
        use openfirma_core::signer::SoftwareSigner;
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata");
        let read = |name: &str| std::fs::read_to_string(dir.join(name));
        let (Ok(cert), Ok(key)) = (read("certs/signer-rsa.crt"), read("certs/signer-rsa.key"))
        else {
            eprintln!("skipped, test PKI missing, run tools/gen-testcert.sh");
            return;
        };
        let signer = SoftwareSigner::from_pkcs8_pem(&cert, &key).expect("the test PKI is usable");
        let pdf_path = dir.join("inputs/simple.pdf");
        let Ok(pdf) = std::fs::read(&pdf_path) else {
            eprintln!("skipped, the test PDF is missing, run tools/gen-testpdf.py");
            return;
        };

        // The three shapes the protocol can name, over documents they accept.
        for (format, doc) in [
            (
                "cades-b-b",
                b"plain bytes for the dispatcher test".as_slice(),
            ),
            ("pades-b-b", pdf.as_slice()),
            ("xades-b-b", b"<a/>".as_slice()),
        ] {
            // A detached shape with no signing-time attribute is byte-for-byte
            // reproducible: same content, key, digest -> same CMS. That is the
            // strongest equality two dispatchers can be held to without a
            // clock mock — except PAdES, whose /M and /ModDate do read the
            // clock: both sides take it from `clock::now()`, floored to the
            // whole second, so the two sign here cannot land on different
            // seconds. Before that floor existed, CI's macOS runner measured a
            // straddle and this equality went red over one /M second; the
            // straddle test right after the loop keeps that honest.
            let mut req = SignRequest::new(format, DigestAlg::Sha256);
            req.cades_no_signing_time = true;
            let expected = execute_with_detection(&mut req, doc, &signer)
                .expect("each pair is a shape the dispatcher accepts");
            // The protocol's own front door: format text as a sede writes it ->
            // the request its dispatch builds. Reaching the same bytes through
            // this module's `execute_with_detection` proves one dispatch.
            let mut protocol = crate::dispatch::protocol_request_for(format, DigestAlg::Sha256)
                .expect("a served format");
            protocol.cades_no_signing_time = true;
            let via_protocol = execute_with_detection(&mut protocol, doc, &signer)
                .expect("the protocol request is a shape the dispatcher accepts");
            // XAdES embeds fresh UUIDs in its element Ids, so only the CMS
            // shapes are byte-reproducible; the XML one is held to equality
            // of shape (same envelope size class) instead.
            if format == "xades-b-b" {
                assert_eq!(
                    expected.len(),
                    via_protocol.len(),
                    "{format}: the browser and the terminal disagree in shape"
                );
                assert!(expected.starts_with(b"<?xml") && via_protocol.starts_with(b"<?xml"));
            } else {
                assert_eq!(
                    expected, via_protocol,
                    "{format}: the browser's request and the shared one disagree"
                );
            }
        }
    }

    use openfirma_core::CertificateHandle;
    struct Mock;
    impl Signer for Mock {
        fn certificate(&self) -> &CertificateHandle {
            unreachable!("a refusal never asks who signs")
        }
        fn chain(&self) -> &[CertificateHandle] {
            &[]
        }
        fn key_algorithm(&self) -> openfirma_core::Result<openfirma_core::KeyAlgorithm> {
            Ok(openfirma_core::KeyAlgorithm::Rsa)
        }
        fn sign_prehash(&self, _: DigestAlg, _: &[u8]) -> openfirma_core::Result<Vec<u8>> {
            unreachable!("a refusal never signs")
        }
    }
}

#[cfg(test)]
mod clock_tests {
    use super::clock;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn the_shared_clock_is_one_whole_second_and_honest_utc() {
        // Stable across reads (two signatures of one process timestamp with
        // one tick) and inside what the raw clock says (a floor, never a
        // jump): an invented constant would pass stability alone.
        let before = SystemTime::now();
        let t = clock::now();
        let after = SystemTime::now();
        assert_eq!(t, clock::now(), "one process, one second");
        assert_eq!(
            t.duration_since(UNIX_EPOCH).unwrap().as_secs(),
            t.duration_since(UNIX_EPOCH).unwrap().as_secs(),
            "floored value is a whole second"
        );
        let secs = t.duration_since(UNIX_EPOCH).unwrap().as_secs();
        assert_eq!(
            secs,
            before.duration_since(UNIX_EPOCH).unwrap().as_secs().max(
                after
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    .saturating_sub(1)
            ),
            "the floored instant belongs to the second the raw clock showed"
        );
    }

    #[test]
    fn a_second_boundary_crossing_changes_no_single_byte() {
        // The straddle CI measured: two signatures built on either side of a
        // real second boundary used to differ in /M (and /ModDate) alone. With
        // the whole-second floor, wait past the boundary and sign again — any
        // difference at all is the flake back. Signer RNG adds nothing here:
        // RSA PKCS#1 v1.5 is deterministic, so bytes are comparable directly.
        use std::time::{Duration, SystemTime, UNIX_EPOCH};
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata");
        let read = |name: &str| std::fs::read_to_string(dir.join(name));
        let (Ok(cert), Ok(key)) = (read("certs/signer-rsa.crt"), read("certs/signer-rsa.key"))
        else {
            eprintln!("skipped, test PKI missing, run tools/gen-testcert.sh");
            return;
        };
        let signer = openfirma_core::signer::SoftwareSigner::from_pkcs8_pem(&cert, &key)
            .expect("the test PKI is usable");
        // The same fixture every PAdES crosscheck signs (it has no /Info, so
        // the first signing writes the one whose /ModDate this pins).
        let Ok(pdf) = std::fs::read(dir.join("inputs/simple.pdf")) else {
            eprintln!("skipped, the test PDF is missing, run tools/gen-testpdf.py");
            return;
        };
        let sign_once = || {
            let opts = crate::signing::PadesOptions {
                // The same instant every production path hands pades_sign:
                // the shared clock, nothing else may write /M.
                sign_time: clock::now(),
                ..crate::signing::PadesOptions::default()
            };
            openfirma_pades::pades_sign(&pdf, &signer, &opts).expect("the mini PDF signs")
        };
        let first = sign_once();
        // Leave the second the floor resolved to (worst case: one instant
        // after resolution was nearly a full second old).
        let floor_secs = clock::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        loop {
            let raw = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            if raw != floor_secs {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let second = sign_once();
        assert_eq!(
            first, second,
            "a signature must not depend on the second its signing call crossed"
        );
    }
}
