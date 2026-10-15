use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use openfirma_cades::{CadesOptions, sign};
use openfirma_core::alg::DigestAlg;
use openfirma_core::cert::CertificateHandle;
use openfirma_core::signer::{Signer, SoftwareSigner};
use openfirma_pades::{Appearance, PadesOptions};

#[derive(Parser)]
#[command(
    name = "openfirma",
    version,
    about = "Pure Rust signing client compatible with AutoFirma"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Sign a document
    Sign(Box<SignArgs>),
    /// Verify a CAdES or PAdES signature against trust anchors
    Verify(VerifyArgs),
    /// Dump the DER structure of a signature in normalized, diffable form
    Inspect {
        #[arg(long, short = 'i')]
        input: PathBuf,
    },
}

/// Every flag of `verify`. The format of the input is detected, not declared:
/// a file that starts with `%PDF-` is PAdES, anything else is a CAdES
/// `ContentInfo`.
#[derive(Args)]
struct VerifyArgs {
    /// Signature to verify: a signed PDF, or a CAdES signature
    #[arg(long, short = 'i')]
    input: PathBuf,

    /// The signed content, for a detached CAdES signature. Not needed for an
    /// encapsulated one, where the content travels inside the signature and
    /// this flag is ignored, and ignored for a PDF, where each signature
    /// covers the bytes its own /ByteRange names.
    #[arg(long)]
    content: Option<PathBuf>,

    /// Trust anchor certificate, PEM or DER, repeatable. The signer's chain
    /// has to reach one of them, and at least one is required.
    #[arg(long, required = true)]
    trust: Vec<PathBuf>,

    /// Validation time for the certificate validity dates, as an RFC 3339
    /// time (2026-10-15T13:36:00Z, offsets and fractions allowed, a bare
    /// date means midnight UTC). Defaults to now.
    #[arg(long)]
    at: Option<String>,
}

/// Every flag of `sign`, in its own struct because the variant is far larger
/// than `Inspect` and an enum should not make every match pay for it.
#[derive(Args)]
struct SignArgs {
    /// File to sign
    #[arg(long, short = 'i')]
    input: PathBuf,

    /// Where to write the signature
    #[arg(long, short = 'o')]
    output: PathBuf,

    #[arg(long, value_enum, default_value = "cades-b-b")]
    format: Format,

    #[arg(long, value_enum, default_value = "sha256")]
    digest: Digest,

    /// Signer certificate, PEM or DER. Required unless --p12 is given.
    #[arg(long)]
    cert: Option<PathBuf>,

    /// PKCS#8 private key, PEM or DER. Required unless --p12 is given.
    #[arg(long)]
    key: Option<PathBuf>,

    /// Issuing certificates to embed, PEM or DER, repeatable
    #[arg(long)]
    chain: Vec<PathBuf>,

    /// PKCS#12 container holding the key and its whole chain, the shape a real
    /// certificate arrives in. Replaces --cert and --key.
    #[arg(long)]
    p12: Option<PathBuf>,

    /// Password of the --p12 container
    #[arg(long)]
    password: Option<String>,

    /// friendlyName of the entry to use when the --p12 holds more than one key
    #[arg(long)]
    alias: Option<String>,

    /// Include the content inside the signature. AutoFirma leaves it out by
    /// default: its mode is "explicit", and in @firma vocabulary explicit
    /// means digest only. Use mode=implicit there, or this flag here, to
    /// encapsulate.
    #[arg(long)]
    encapsulate: bool,

    /// Value for the ETSI mime-type attribute
    #[arg(long)]
    mime_type: Option<String>,

    /// Description for the ESS contentHint attribute
    #[arg(long)]
    content_hint: Option<String>,

    /// Omit the RFC 5652 signingTime attribute. AutoFirma includes it by
    /// default in the advanced profile, so we do too.
    #[arg(long)]
    no_signing_time: bool,

    /// Omit issuer and serial from signingCertificateV2. AutoFirma carries
    /// them by default, so we do too.
    #[arg(long)]
    no_issuer_serial: bool,

    /// Reason for signing, PAdES only. AutoFirma leaves it out unless the
    /// user fills it in, and so do we.
    #[arg(long)]
    reason: Option<String>,

    /// Where the document was signed, PAdES only
    #[arg(long)]
    location: Option<String>,

    /// Contact information of the signer, PAdES only
    #[arg(long)]
    contact_info: Option<String>,

    /// Name of the AcroForm signature field. Defaults to the next free
    /// SignatureN in the document.
    #[arg(long)]
    field_name: Option<String>,

    /// Rectangle of a visible signature, as llx,lly,urx,ury in PDF user space
    /// units. The origin is the bottom left corner of the page, so the y values
    /// run upwards. Without this the signature is invisible, which is what
    /// AutoFirma produces when no position is given. PAdES only.
    #[arg(long, value_parser = parse_rect)]
    rect: Option<[f64; 4]>,

    /// Page to put a visible signature on, counting from 1. PAdES only.
    #[arg(long, default_value = "1")]
    page: usize,

    /// Line drawn above the signer's name in a visible signature. PAdES only.
    #[arg(long)]
    label: Option<String>,

    /// URL of a TSA to raise the signature to B-T with a time-stamp token.
    /// Plain http only: HTTPS needs a TLS client, which is a dependency
    /// decision of its own, not something to slip in here. For an https TSA,
    /// fetch the token by hand and pass --timestamp-token.
    #[arg(long)]
    tsa: Option<String>,

    /// A TimeStampResp file, as `openssl ts -reply` writes one, to embed as
    /// the B-T token instead of asking a TSA live. The token imprints the
    /// signature value, which for RSA PKCS#1 v1.5 is deterministic, so the flow
    /// is: sign once, stamp the signature value, sign again with this flag.
    /// ECDSA signatures are randomised, so for those use --tsa. The imprint is
    /// checked against the signature value and a mismatch is an error.
    #[arg(long)]
    timestamp_token: Option<PathBuf>,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    #[value(name = "cades-b-b")]
    CadesBb,
    #[value(name = "pades-b-b")]
    PadesBb,
}

impl Format {
    fn label(self) -> &'static str {
        match self {
            Format::CadesBb => "CAdES-B-B",
            Format::PadesBb => "PAdES-B-B",
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum Digest {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl From<Digest> for DigestAlg {
    fn from(d: Digest) -> Self {
        match d {
            Digest::Sha1 => DigestAlg::Sha1,
            Digest::Sha256 => DigestAlg::Sha256,
            Digest::Sha384 => DigestAlg::Sha384,
            Digest::Sha512 => DigestAlg::Sha512,
        }
    }
}

/// Builds the B-T timestamp provider, or None when neither flag is given.
fn timestamp_provider(
    tsa: Option<String>,
    token_file: Option<PathBuf>,
) -> Result<Option<openfirma_cades::TimestampFn>> {
    use openfirma_cades::tsp;
    use std::sync::Arc;
    match (tsa, token_file) {
        (Some(_), Some(_)) => {
            anyhow::bail!("--tsa and --timestamp-token are alternatives, not companions")
        }
        (Some(url), None) => {
            if !url.starts_with("http://") {
                anyhow::bail!(
                    "--tsa only speaks plain http today. An https TSA needs a TLS client, \
                     which is a dependency decision recorded separately; until then fetch \
                     the token by hand and pass --timestamp-token."
                );
            }
            Ok(Some(Arc::new(move |sig: &[u8], digest| {
                let nonce = std::time::SystemTime::now()
                    .duration_since(std::time::SystemTime::UNIX_EPOCH)
                    .map(|d| d.as_nanos() as u64)
                    .unwrap_or(0);
                let query = tsp::request(digest, sig, nonce)?;
                let response = http_post(&url, &query)
                    .map_err(|e| openfirma_core::Error::Other(e.to_string()))?;
                let token = tsp::token_from_response(&response, digest, sig)?;
                Ok(vec![tsp::unsigned_attribute(&token)?])
            })))
        }
        (None, Some(path)) => {
            let response =
                std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
            Ok(Some(Arc::new(move |sig: &[u8], digest| {
                let token = tsp::token_from_response(&response, digest, sig)?;
                Ok(vec![tsp::unsigned_attribute(&token)?])
            })))
        }
        (None, None) => Ok(None),
    }
}

/// A minimal HTTP/1.1 POST, enough for a timestamp query and nothing more.
/// std::net only: no dependency for a request that is two headers and a body.
fn http_post(url: &str, body: &[u8]) -> Result<Vec<u8>> {
    use std::io::{Read, Write};
    let rest = url
        .strip_prefix("http://")
        .context("only http:// TSA urls are supported")?;
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    let host = if authority.contains(':') {
        authority.to_string()
    } else {
        format!("{authority}:80")
    };
    let mut stream = std::net::TcpStream::connect(&host)
        .with_context(|| format!("cannot reach the TSA at {host}"))?;
    stream
        .write_all(
            format!(
                "POST /{path} HTTP/1.1\r\nHost: {authority}\r\n\
                 Content-Type: application/timestamp-query\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .as_bytes(),
        )
        .context("cannot send the timestamp query")?;
    stream
        .write_all(body)
        .context("cannot send the timestamp query")?;
    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .context("the TSA closed the connection without answering")?;

    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .context("the TSA answer has no header/body separator")?;
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let status = head.lines().next().unwrap_or_default();
    if !status.contains(" 200") {
        anyhow::bail!("the TSA answered {status:?}");
    }
    let mut body_out = raw[split + 4..].to_vec();
    // honour Content-Length when present; otherwise the connection close was
    // the terminator and everything after the headers is the body
    if let Some(line) = head
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
    {
        let n: usize = line[15..].trim().parse().unwrap_or(body_out.len());
        body_out.truncate(n);
    }
    Ok(body_out)
}

/// Parses `llx,lly,urx,ury`, accepting commas or spaces as separators.
fn parse_rect(text: &str) -> std::result::Result<[f64; 4], String> {
    let parts: Vec<&str> = text
        .split([',', ';', ' '])
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .collect();
    if parts.len() != 4 {
        return Err(format!(
            "{text:?} has {} numbers, a rectangle needs four: llx,lly,urx,ury",
            parts.len()
        ));
    }
    let mut out = [0.0; 4];
    for (i, part) in parts.iter().enumerate() {
        out[i] = part
            .parse::<f64>()
            .map_err(|e| format!("{part:?} is not a number: {e}"))?;
    }
    Ok(out)
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Sign(args) => {
            let SignArgs {
                input,
                output,
                format,
                digest,
                cert,
                key,
                chain,
                encapsulate,
                mime_type,
                content_hint,
                no_signing_time,
                no_issuer_serial,
                reason,
                location,
                contact_info,
                field_name,
                rect,
                page,
                label,
                p12,
                password,
                alias,
                tsa,
                timestamp_token,
            } = *args;
            let content =
                std::fs::read(&input).with_context(|| format!("reading {}", input.display()))?;
            let signer = match (&p12, &password) {
                (Some(container), Some(pw)) => load_p12(container, pw, alias.as_deref())?,
                (Some(_), None) => {
                    anyhow::bail!("--p12 needs --password with the container's password")
                }
                (None, Some(_)) => anyhow::bail!("--password only makes sense together with --p12"),
                (None, None) => {
                    let cert = cert.context("--cert is required unless --p12 is given")?;
                    let key = key.context("--key is required unless --p12 is given")?;
                    load_signer(&cert, &key, &chain)?
                }
            };
            let digest_alg: DigestAlg = digest.into();

            let stamp = timestamp_provider(tsa, timestamp_token)?;
            let mut opts = CadesOptions {
                digest: digest_alg,
                encapsulate_content: encapsulate,
                mime_type,
                content_hint,
                include_issuer_serial: !no_issuer_serial,
                timestamp: stamp.clone(),
                ..CadesOptions::default()
            };
            if no_signing_time {
                opts.signing_time = None;
            }

            let signature = match format {
                Format::CadesBb => sign(&content, &signer, &opts)?,
                // PAdES fixes the CAdES shape itself: detached, no signingTime
                // because the time is in /M, and no contentHint. The knobs
                // above only apply to CAdES, see docs/pades.md.
                Format::PadesBb => openfirma_pades::pades_sign(
                    &content,
                    &signer,
                    &PadesOptions {
                        digest: digest_alg,
                        reason,
                        location,
                        contact_info,
                        field_name,
                        visible: rect.map(|r| Appearance {
                            page,
                            rect: r,
                            label: label.clone(),
                        }),
                        timestamp: stamp,
                        ..PadesOptions::default()
                    },
                )?,
            };

            std::fs::write(&output, &signature)
                .with_context(|| format!("writing {}", output.display()))?;

            let cn = signer
                .certificate()
                .subject_cn()
                .unwrap_or_else(|| "<no CN>".into());
            println!(
                "signed {} -> {} ({} bytes, {}, {})",
                input.display(),
                output.display(),
                signature.len(),
                format.label(),
                cn,
            );
        }
        Command::Verify(args) => {
            let VerifyArgs {
                input,
                content,
                trust,
                at,
            } = args;
            let bytes =
                std::fs::read(&input).with_context(|| format!("reading {}", input.display()))?;

            let mut anchors = Vec::with_capacity(trust.len());
            for t in &trust {
                let anchor =
                    std::fs::read(t).with_context(|| format!("reading {}", t.display()))?;
                anchors.push(parse_certificate(&anchor).with_context(|| {
                    format!("{} is not a valid X.509 certificate", t.display())
                })?);
            }
            let validation_time = match &at {
                Some(text) => parse_rfc3339(text)
                    .map_err(|e| anyhow::anyhow!("--at {text:?} is not an RFC 3339 time: {e}"))?,
                None => std::time::SystemTime::now(),
            };
            let opts = openfirma_cades::VerifyOptions {
                trust_anchors: anchors,
                validation_time,
            };
            println!("validation time: {}", fmt_system_time(validation_time));

            if bytes.starts_with(b"%PDF-") {
                if content.is_some() {
                    eprintln!(
                        "note: --content is ignored for a PDF, every signature covers the \
                         bytes its own /ByteRange names"
                    );
                }
                let signatures = openfirma_pades::pades_verify(&bytes, &opts)?;
                for (i, sig) in signatures.iter().enumerate() {
                    let [a, b, c, d] = sig.byte_range;
                    println!(
                        "signature {} (object {} {}), /ByteRange [{a} {b} {c} {d}]:",
                        i + 1,
                        sig.object.num,
                        sig.object.generation
                    );
                    for report in &sig.reports {
                        print_report(report);
                    }
                }
                println!(
                    "OK: all {} signature(s) verify against the supplied trust anchors",
                    signatures.len()
                );
            } else {
                let external = match &content {
                    Some(path) => Some(
                        std::fs::read(path)
                            .with_context(|| format!("reading {}", path.display()))?,
                    ),
                    None => None,
                };
                let reports = openfirma_cades::verify(&bytes, external.as_deref(), &opts)?;
                for (i, report) in reports.iter().enumerate() {
                    if reports.len() > 1 {
                        println!("signature {}:", i + 1);
                    }
                    print_report(report);
                }
                println!(
                    "OK: all {} signature(s) verify against the supplied trust anchors",
                    reports.len()
                );
            }
        }
        Command::Inspect { input } => {
            let bytes =
                std::fs::read(&input).with_context(|| format!("reading {}", input.display()))?;
            if bytes.starts_with(b"%PDF-") {
                // a signed PDF has more to report than its CMS: what the
                // signature claims to cover, and whether that claim holds
                print!("{}", openfirma_pades::inspect::render(&bytes)?);
            } else {
                print!(
                    "{}",
                    openfirma_core::der_dump(&bytes)
                        .with_context(|| format!("{} is not valid DER", input.display()))?
                );
            }
        }
    }
    Ok(())
}

/// Reads a PKCS#12 and takes one entry from it: the key, the leaf certificate
/// and whatever chain the container carried.
fn load_p12(path: &PathBuf, password: &str, alias: Option<&str>) -> Result<SoftwareSigner> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let container = openfirma_keystore::Pkcs12::load(&bytes, password)
        .with_context(|| format!("{} is not a readable PKCS#12", path.display()))?;
    let entry = container.entry(alias)?;
    let leaf = parse_certificate(&entry.chain[0])
        .context("the PKCS#12 leaf is not a valid X.509 certificate")?;
    let mut chain = Vec::with_capacity(entry.chain.len().saturating_sub(1));
    for der in &entry.chain[1..] {
        chain.push(parse_certificate(der)?);
    }
    let signer = SoftwareSigner::from_pkcs8_der(leaf.der(), &entry.key_pkcs8)
        .context("the PKCS#12 key does not match its certificate")?;
    Ok(signer.with_chain(chain))
}

/// Reads a certificate and a PKCS#8 key, accepting PEM or DER for both.
fn load_signer(cert: &PathBuf, key: &PathBuf, chain: &[PathBuf]) -> Result<SoftwareSigner> {
    let cert_bytes = std::fs::read(cert).with_context(|| format!("reading {}", cert.display()))?;
    let key_bytes = std::fs::read(key).with_context(|| format!("reading {}", key.display()))?;

    let handle = parse_certificate(&cert_bytes)
        .with_context(|| format!("{} is not a valid X.509 certificate", cert.display()))?;
    let mut signer = build_signer(&handle, &key_bytes)
        .with_context(|| format!("cannot use {} as a signing key", key.display()))?;

    let mut chain_handles = Vec::with_capacity(chain.len());
    for c in chain {
        let bytes = std::fs::read(c).with_context(|| format!("reading {}", c.display()))?;
        chain_handles.push(parse_certificate(&bytes)?);
    }
    signer = signer.with_chain(chain_handles);
    Ok(signer)
}

fn parse_certificate(bytes: &[u8]) -> openfirma_core::Result<CertificateHandle> {
    if bytes.starts_with(b"-----BEGIN") {
        CertificateHandle::from_pem(
            std::str::from_utf8(bytes).map_err(|e| {
                openfirma_core::Error::Certificate(format!("invalid PEM text: {e}"))
            })?,
        )
    } else {
        CertificateHandle::from_der(bytes)
    }
}

fn build_signer(
    cert: &CertificateHandle,
    key_bytes: &[u8],
) -> openfirma_core::Result<SoftwareSigner> {
    if key_bytes.starts_with(b"-----BEGIN") {
        let pem = std::str::from_utf8(key_bytes)
            .map_err(|e| openfirma_core::Error::PrivateKey(format!("invalid PEM text: {e}")))?;
        SoftwareSigner::from_pkcs8_pem(&cert_to_pem(cert)?, pem)
    } else {
        SoftwareSigner::from_pkcs8_der(cert.der(), key_bytes)
    }
}

fn cert_to_pem(cert: &CertificateHandle) -> openfirma_core::Result<String> {
    use base64::Engine;
    use openfirma_core::Error;
    let b64 = base64::engine::general_purpose::STANDARD.encode(cert.der());
    if b64.is_empty() {
        return Err(Error::Certificate("empty certificate".into()));
    }
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        let text = std::str::from_utf8(chunk)
            .map_err(|e| Error::Certificate(format!("base64 is not ASCII: {e}")))?;
        pem.push_str(text);
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    Ok(pem)
}

/// One `VerifyReport` as the lines a person reads. Failures never reach this:
/// they come back as an error naming the check, and anyhow prints it.
fn print_report(r: &openfirma_cades::VerifyReport) {
    println!("  signer:         {}", r.signer_subject);
    println!("  digest:         {}", r.digest.name());
    println!("  signature:      {}", r.signature_alg);
    println!("  chain:");
    for (i, s) in r.chain_subjects.iter().enumerate() {
        println!("    {}. {s}", i + 1);
    }
    println!("  trust anchor:   {}", r.trust_anchor);
    let (signed, unsigned) = attribute_names(&r.attributes);
    println!("  signed attrs:   {}", signed.join(", "));
    if !unsigned.is_empty() {
        println!("  unsigned attrs: {}", unsigned.join(", "));
    }
    println!("  checks passed:  {}", r.passed.join(", "));
}

/// Human names for the attribute OIDs the report carries.
fn attribute_names(a: &openfirma_cades::Attributes) -> (Vec<String>, Vec<String>) {
    use openfirma_core::oid;
    let mut signed = Vec::new();
    if a.content_type.is_some() {
        signed.push("contentType".to_string());
    }
    if a.signing_time.is_some() {
        signed.push("signingTime".to_string());
    }
    if a.message_digest {
        signed.push("messageDigest".to_string());
    }
    if a.signing_certificate_v2 {
        signed.push("signingCertificateV2".to_string());
    }
    if a.mime_type.is_some() {
        signed.push("mimeType".to_string());
    }
    if a.content_hint.is_some() {
        signed.push("contentHint".to_string());
    }
    for o in &a.other_signed {
        signed.push(o.to_string());
    }
    let unsigned = a
        .unsigned_attributes
        .iter()
        .map(|o| {
            if *o == oid::ID_SIGNATURE_TIME_STAMP_TOKEN {
                "signatureTimeStampToken".to_string()
            } else {
                o.to_string()
            }
        })
        .collect();
    (signed, unsigned)
}

/// An RFC 3339 time to a `SystemTime`. Handwritten like the rest of the time
/// handling in this workspace: a date parser is not worth a dependency, and
/// the only crate that would do it properly drags in a C backend or a
/// timezone database.
///
/// Accepts `YYYY-MM-DDTHH:MM:SS` with `Z` or a `±HH:MM` offset, an optional
/// fraction of a second (which is dropped, the validity dates are second
/// granularity anyway), `T`/`t`/space as the separator, and a bare
/// `YYYY-MM-DD`, meaning midnight UTC.
fn parse_rfc3339(text: &str) -> std::result::Result<std::time::SystemTime, String> {
    let t = text.trim();
    if t.len() == 10 {
        // a full date on its own, RFC 3339's full-date
        let (y, m, d) = parse_date(t)?;
        return civil_to_system_time(y, m, d, 0, 0, 0, 0);
    }
    let (datetime, offset_secs) = if let Some(head) = t.strip_suffix(['Z', 'z']) {
        (head, 0i64)
    } else if t.len() > 6 {
        let (head, tail) = t.split_at(t.len() - 6);
        let sign = match tail.as_bytes()[0] {
            b'+' => 1i64,
            b'-' => -1i64,
            _ => return Err("the time ends with neither Z nor a ±HH:MM offset".into()),
        };
        if tail.as_bytes()[3] != b':' {
            return Err("the UTC offset is not shaped ±HH:MM".into());
        }
        let oh: i64 = tail[1..3]
            .parse()
            .map_err(|_| "the offset hours are not a number".to_string())?;
        let om: i64 = tail[4..6]
            .parse()
            .map_err(|_| "the offset minutes are not a number".to_string())?;
        if oh > 23 || om > 59 {
            return Err("the UTC offset is out of range".into());
        }
        (head, sign * (oh * 3600 + om * 60))
    } else {
        return Err("too short to be an RFC 3339 date-time".into());
    };

    let (date, time) = datetime
        .split_once(['T', 't', ' '])
        .ok_or_else(|| "the date and the time are not separated by a T".to_string())?;
    let (y, m, d) = parse_date(date)?;
    let (hh, mm, ss) = parse_time(time)?;
    // local time = UTC + offset, so UTC = local - offset
    civil_to_system_time(y, m, d, hh, mm, ss, -offset_secs)
}

fn parse_date(s: &str) -> std::result::Result<(i64, u32, u32), String> {
    let b = s.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return Err(format!("{s:?} is not shaped YYYY-MM-DD"));
    }
    let y: i64 = s[0..4]
        .parse()
        .map_err(|_| "the year is not a number".to_string())?;
    let m: u32 = s[5..7]
        .parse()
        .map_err(|_| "the month is not a number".to_string())?;
    let d: u32 = s[8..10]
        .parse()
        .map_err(|_| "the day is not a number".to_string())?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return Err(format!("month {m} or day {d} is out of range"));
    }
    Ok((y, m, d))
}

fn parse_time(s: &str) -> std::result::Result<(u32, u32, u32), String> {
    let b = s.as_bytes();
    if b.len() < 8 || b[2] != b':' || b[5] != b':' {
        return Err(format!("{s:?} is not shaped HH:MM:SS"));
    }
    if b.len() > 8 {
        // an optional fraction, digits only, dropped
        if b[8] != b'.' || b[9..].is_empty() || !b[9..].iter().all(u8::is_ascii_digit) {
            return Err(format!(
                "{s:?} has trailing characters that are not .fraction"
            ));
        }
    }
    let hh: u32 = s[0..2]
        .parse()
        .map_err(|_| "the hour is not a number".to_string())?;
    let mm: u32 = s[3..5]
        .parse()
        .map_err(|_| "the minute is not a number".to_string())?;
    let ss: u32 = s[6..8]
        .parse()
        .map_err(|_| "the second is not a number".to_string())?;
    if hh > 23 || mm > 59 || ss > 60 {
        return Err("the time of day is out of range".into());
    }
    Ok((hh, mm, ss))
}

fn civil_to_system_time(
    y: i64,
    m: u32,
    d: u32,
    hh: u32,
    mm: u32,
    ss: u32,
    extra_secs: i64,
) -> std::result::Result<std::time::SystemTime, String> {
    let secs = days_from_civil(y, m, d) * 86_400
        + i64::from(hh) * 3600
        + i64::from(mm) * 60
        + i64::from(ss)
        + extra_secs;
    if secs < 0 {
        return Err("times before 1970 cannot be represented".into());
    }
    Ok(std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs as u64))
}

/// Days since 1970-01-01 from a proleptic Gregorian date. Howard Hinnant's
/// `days_from_civil`, the inverse of the `civil_from_days` the PAdES writer
/// uses, and exact over the whole range.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let doy = (153 * (i64::from(m) + if m > 2 { -3 } else { 9 }) + 2) / 5 + i64::from(d) - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

/// Days since the epoch to a proleptic Gregorian date, Howard Hinnant's
/// `civil_from_days`, the same one openfirma-pades uses for PDF dates.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (y + i64::from(m <= 2), m, d)
}

/// `2026-10-15T13:36:00Z`, for echoing the validation time.
fn fmt_system_time(t: std::time::SystemTime) -> String {
    let Ok(d) = t.duration_since(std::time::UNIX_EPOCH) else {
        return format!("{t:?}");
    };
    let secs = d.as_secs() as i64;
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    let rem = secs.rem_euclid(86_400);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    fn epoch(t: SystemTime) -> u64 {
        t.duration_since(SystemTime::UNIX_EPOCH)
            .expect("before 1970")
            .as_secs()
    }

    #[test]
    fn rfc3339_utc() {
        // cross-checked against `date -u -d 2026-10-15T13:36:00Z +%s`
        assert_eq!(
            epoch(parse_rfc3339("2026-10-15T13:36:00Z").unwrap()),
            1_792_071_360
        );
        assert_eq!(epoch(parse_rfc3339("1970-01-01T00:00:00Z").unwrap()), 0);
    }

    #[test]
    fn rfc3339_shapes_that_mean_the_same_instant() {
        let base = parse_rfc3339("2026-10-15T13:36:00Z").unwrap();
        assert_eq!(parse_rfc3339("2026-10-15T15:36:00+02:00").unwrap(), base);
        assert_eq!(parse_rfc3339("2026-10-15T08:06:00-05:30").unwrap(), base);
        assert_eq!(parse_rfc3339("2026-10-15T13:36:00.500Z").unwrap(), base);
        assert_eq!(parse_rfc3339("2026-10-15t13:36:00z").unwrap(), base);
        assert_eq!(
            parse_rfc3339("2026-10-15").unwrap(),
            parse_rfc3339("2026-10-15T00:00:00Z").unwrap()
        );
    }

    #[test]
    fn rfc3339_rejects_rubbish() {
        for bad in [
            "",
            "now",
            "15/10/2026",
            "2026-10-15T13:36:00",      // no zone
            "2026-10-15T25:00:00Z",     // hour out of range
            "2026-13-15T00:00:00Z",     // month out of range
            "2026-10-15T13:36:00+2:00", // malformed offset
            "2026-10-15T13:36:00ZZ",
            "1960-01-01T00:00:00Z", // before 1970
        ] {
            assert!(parse_rfc3339(bad).is_err(), "{bad:?} was accepted");
        }
    }

    #[test]
    fn the_two_civil_conversions_are_inverses() {
        for days in [-100_000i64, -1, 0, 1, 20_741, 100_000] {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days, "{days} did not round trip");
        }
        assert_eq!(
            fmt_system_time(SystemTime::UNIX_EPOCH),
            "1970-01-01T00:00:00Z"
        );
    }
}
