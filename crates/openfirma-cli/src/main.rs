use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use openfirma_cades::{CadesOptions, sign};
use openfirma_core::alg::DigestAlg;
use openfirma_core::cert::CertificateHandle;
use openfirma_core::signer::{Signer, SoftwareSigner};
use openfirma_pades::{Appearance, PadesOptions};
use zeroize::Zeroizing;

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

    /// Password of the --p12 container. INSECURE: everything on the command
    /// line is readable by every process on the machine (ps) and lands in the
    /// shell history. Prefer --password-file or the OPENFIRMA_PASSWORD
    /// environment variable, which this flag also reads when it is not given.
    #[arg(long, env = "OPENFIRMA_PASSWORD", hide_env_values = true)]
    password: Option<std::ffi::OsString>,

    /// File whose first line is the password of the --p12 container, one
    /// trailing newline ignored. The safe way to pass a password: chmod 600
    /// the file and nothing on the command line or in the environment names
    /// it. Wins over --password and OPENFIRMA_PASSWORD when both are given.
    #[arg(long)]
    password_file: Option<PathBuf>,

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
    /// fetch the token by hand and pass --timestamp-token. The token's
    /// imprint is always checked; its own signature is only verified when
    /// the TSA's chain is supplied through --validation-cert, and a warning
    /// on stderr says so when it was not.
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

    /// Certificate to archive in the PDF /DSS validation data on top of the
    /// signer's own chain (a co-signer's, the TSA's), PEM or DER, repeatable.
    /// PAdES B-LT and B-LTA only.
    #[arg(long)]
    validation_cert: Vec<PathBuf>,

    /// CRL to archive in the PDF /DSS, PEM or DER, repeatable. Nothing is
    /// fetched: the URL a CRL comes from is in the crlDistributionPoints of
    /// the certificates it covers. PAdES B-LT and B-LTA only.
    #[arg(long)]
    crl: Vec<PathBuf>,

    /// OCSP response to archive in the PDF /DSS, PEM or DER, repeatable.
    /// Obtained by the caller, like the CRLs. PAdES B-LT and B-LTA only.
    #[arg(long)]
    ocsp: Vec<PathBuf>,

    /// Bytes reserved for the /Contents hole of a PAdES signature or
    /// document time-stamp, which the value is zero padded to fill. The
    /// default is what AutoFirma reserves through iText; raise it for a
    /// signature that does not fit (a long TSA chain, an unusual
    /// certificate), because too small a reservation is a hard failure.
    #[arg(long, default_value_t = openfirma_pades::DEFAULT_CONTENTS_RESERVED)]
    contents_reserved: usize,

    /// Allow the output to be the input file itself. Without it,
    /// `sign -i f.pdf -o f.pdf` is refused: replacing the document being
    /// signed is one typo away and never the common case.
    #[arg(long)]
    force: bool,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    #[value(name = "cades-b-b")]
    Cades,
    #[value(name = "pades-b-b")]
    Pades,
    /// PAdES with the B-LT validation data archived in the document's /DSS.
    /// Combine with --tsa for the signature time-stamp the full B-LT level
    /// asks for.
    #[value(name = "pades-b-lt")]
    PadesLt,
    /// PAdES B-LT plus a document time-stamp over everything before it.
    /// Needs --tsa: the token imprints bytes that exist only while signing.
    #[value(name = "pades-b-lta")]
    PadesLta,
    #[value(name = "xades-b-b")]
    Xades,
}

impl Format {
    fn label(self) -> &'static str {
        match self {
            Format::Cades => "CAdES-B-B",
            Format::Pades => "PAdES-B-B",
            Format::PadesLt => "PAdES-B-LT",
            Format::PadesLta => "PAdES-B-LTA",
            Format::Xades => "XAdES-B-B",
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
///
/// `tsa_trust` is what the token's own signature is checked against: the TSA
/// fetch is plain http (a TLS client is a separate dependency decision, its
/// own ADR), so a token that cannot be verified against a supplied anchor is
/// accepted on its imprint alone — with a warning saying exactly that, because
/// anyone on the path could have planted it.
fn timestamp_provider(
    tsa: Option<String>,
    token_file: Option<PathBuf>,
    tsa_trust: Vec<CertificateHandle>,
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
                warn_if_token_unverified(&format!("the TSA at {url}"), &token, &tsa_trust);
                Ok(vec![tsp::unsigned_attribute(&token)?])
            })))
        }
        (None, Some(path)) => {
            let response =
                std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
            let source = format!("{}", path.display());
            Ok(Some(Arc::new(move |sig: &[u8], digest| {
                let token = tsp::token_from_response(&response, digest, sig)?;
                warn_if_token_unverified(&format!("the token file {source}"), &token, &tsa_trust);
                Ok(vec![tsp::unsigned_attribute(&token)?])
            })))
        }
        (None, None) => Ok(None),
    }
}

/// The token about to be embedded imprints the right bytes, but its own
/// signature is only as trusted as the anchors supplied for it. When it
/// cannot be verified, say so on stderr instead of letting the B-T level
/// imply a trust nobody checked.
fn warn_if_token_unverified(source: &str, token: &[u8], tsa_trust: &[CertificateHandle]) {
    use openfirma_cades::tsp;
    if let Err(e) = tsp::verify_token_signature(token, tsa_trust, std::time::SystemTime::now()) {
        eprintln!(
            "warning: the time-stamp token from {source} was accepted on its imprint alone: {e}.\n\
             warning: the imprint proves what the token covers, not who made it, and a \
             plain-http TSA answer can be planted by anyone on the path.\n\
             warning: pass the TSA's certificate chain with --validation-cert (PAdES B-LT \
             and B-LTA) to have it checked here, or check the TSA's answer against its CA \
             yourself: openssl ts -verify -CAfile <tsa-ca.pem> -in <answer.tsr> -data <file>"
        );
    }
}

/// How long the TSA may take to answer, per read or write. A signing run must
/// not hang on a black hole; 10 seconds is generous for a timestamp query.
const TSA_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// The most a TSA answer may weigh. A `TimeStampResp` with a full chain is
/// kilobytes; a megabyte is already nothing legitimate, and reading without a
/// cap hands a hostile server an unbounded allocation.
const TSA_MAX_RESPONSE: usize = 1024 * 1024;

/// A minimal HTTP/1.1 POST, enough for a timestamp query and nothing more.
/// std::net only: no dependency for a request that is two headers and a body.
fn http_post(url: &str, body: &[u8]) -> Result<Vec<u8>> {
    use std::io::{Read, Write};
    use std::net::{TcpStream, ToSocketAddrs};
    let rest = url
        .strip_prefix("http://")
        .context("only http:// TSA urls are supported")?;
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (
            h,
            p.parse::<u16>()
                .with_context(|| format!("the TSA url port {p:?} is not a number"))?,
        ),
        None => (authority, 80),
    };
    let mut stream: Option<TcpStream> = None;
    let mut last_error = None;
    for addr in (host, port)
        .to_socket_addrs()
        .with_context(|| format!("the TSA host {host} does not resolve"))?
    {
        match TcpStream::connect_timeout(&addr, TSA_TIMEOUT) {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(e) => last_error = Some(e),
        }
    }
    let mut stream = stream.ok_or_else(|| {
        anyhow::anyhow!(
            "cannot reach the TSA at {host}:{port}: {}",
            last_error
                .map(|e| e.to_string())
                .unwrap_or_else(|| "no address to connect to".into())
        )
    })?;
    stream
        .set_read_timeout(Some(TSA_TIMEOUT))
        .context("cannot arm the TSA read timeout")?;
    stream
        .set_write_timeout(Some(TSA_TIMEOUT))
        .context("cannot arm the TSA write timeout")?;
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
    // one byte over the cap so an answer exactly at the cap still parses and
    // anything past it is provably past it
    (&mut stream)
        .take(TSA_MAX_RESPONSE as u64 + 1)
        .read_to_end(&mut raw)
        .context("the TSA closed the connection without answering")?;
    if raw.len() > TSA_MAX_RESPONSE {
        anyhow::bail!(
            "the TSA sent more than {TSA_MAX_RESPONSE} bytes without finishing; a \
             timestamp answer is kilobytes, so this server is not a TSA"
        );
    }
    split_http_response(&raw)
}

/// The body of an HTTP answer, with the status line read as a status line:
/// version, then the three digit code as its own token. A substring match on
/// " 200" also accepts "HTTP/1.1 2006 ...", and a hostile server gets to pick
/// the reason phrase.
fn split_http_response(raw: &[u8]) -> Result<Vec<u8>> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .context("the TSA answer has no header/body separator")?;
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let status = head.lines().next().unwrap_or_default();
    let mut parts = status.split_whitespace();
    let version = parts.next().unwrap_or_default();
    let code = parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/1.") || code != "200" {
        anyhow::bail!("the TSA answered {status:?}, expected an HTTP/1.x 200");
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

/// Refuses `sign -i f -o f` unless `--force` says the overwrite is meant.
///
/// Both paths are compared before any reading happens, and twice: the plain
/// absolute spelling catches `-o ./f` and `-o dir/../f`, and the canonical
/// one catches an output that is a symlink or a hard link to the input. The
/// input is read whole before the output is written, so nothing is lost
/// mechanically — what is refused is the silent case, where one typo turns a
/// signature into a replacement of the only copy of a document.
fn check_not_in_place(
    input: &std::path::Path,
    output: &std::path::Path,
    force: bool,
) -> Result<()> {
    if force {
        return Ok(());
    }
    let absolute_same = match (std::path::absolute(input), std::path::absolute(output)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    };
    let canonical_same = match (std::fs::canonicalize(input), std::fs::canonicalize(output)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    };
    if absolute_same || canonical_same {
        anyhow::bail!(
            "{} is both the input and the output: signing would replace the document \
             itself. Choose a different -o, or pass --force to overwrite it anyway",
            input.display()
        );
    }
    Ok(())
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
                password_file,
                alias,
                tsa,
                timestamp_token,
                validation_cert,
                crl,
                ocsp,
                contents_reserved,
                force,
            } = *args;
            check_not_in_place(&input, &output, force)?;
            let ltv = matches!(format, Format::PadesLt | Format::PadesLta);
            if !ltv && (!validation_cert.is_empty() || !crl.is_empty() || !ocsp.is_empty()) {
                anyhow::bail!(
                    "--validation-cert, --crl and --ocsp archive validation data in the PDF \
                     /DSS, which only --format pades-b-lt and pades-b-lta have a place for"
                );
            }
            if ltv && crl.is_empty() && ocsp.is_empty() {
                anyhow::bail!(
                    "{} archives revocation data and none was given: pass at least one --crl \
                     or --ocsp, certificates alone are only half of B-LT",
                    format.label()
                );
            }
            if matches!(format, Format::PadesLta) && tsa.is_none() {
                anyhow::bail!(
                    "--format pades-b-lta needs --tsa: the document time-stamp imprints the \
                     bytes of the document itself, which exist only while signing, so a token \
                     fetched in advance cannot imprint them. --timestamp-token serves the B-T \
                     signature time-stamp only."
                );
            }

            let content =
                std::fs::read(&input).with_context(|| format!("reading {}", input.display()))?;
            let password = p12_password(password, password_file)?;
            let signer = match (&p12, &password) {
                (Some(container), Some(pw)) => load_p12(container, pw, alias.as_deref())?,
                (Some(_), None) => {
                    anyhow::bail!(
                        "--p12 needs the container's password: --password-file (the safe \
                         input), the OPENFIRMA_PASSWORD environment variable, or --password \
                         (insecure, visible in ps and in shell history)"
                    )
                }
                (None, Some(_)) => {
                    anyhow::bail!("a password only makes sense together with --p12")
                }
                (None, None) => {
                    let cert = cert.context("--cert is required unless --p12 is given")?;
                    let key = key.context("--key is required unless --p12 is given")?;
                    load_signer(&cert, &key, &chain)?
                }
            };
            let digest_alg: DigestAlg = digest.into();

            // The validation certificates double as the TSA's trust anchors:
            // a B-LT signing run that archives the TSA's chain usually passes
            // it here, and that is exactly what the embedded token's own
            // signature gets checked against before it is accepted.
            let mut validation_certs = Vec::with_capacity(validation_cert.len());
            for c in &validation_cert {
                let bytes = std::fs::read(c).with_context(|| format!("reading {}", c.display()))?;
                validation_certs.push(parse_certificate(&bytes).with_context(|| {
                    format!("{} is not a valid X.509 certificate", c.display())
                })?);
            }

            let stamp = timestamp_provider(tsa, timestamp_token, validation_certs.clone())?;
            let mut opts = CadesOptions {
                digest: digest_alg,
                encapsulate_content: encapsulate,
                mime_type: mime_type.clone(),
                content_hint,
                include_issuer_serial: !no_issuer_serial,
                timestamp: stamp.clone(),
                ..CadesOptions::default()
            };
            if no_signing_time {
                opts.signing_time = None;
            }

            let signature = match format {
                Format::Cades => sign(&content, &signer, &opts)?,
                // PAdES fixes the CAdES shape itself: detached, no signingTime
                // because the time is in /M, and no contentHint. The knobs
                // above only apply to CAdES, see docs/pades.md. B-LT and
                // B-LTA add revisions after the signature: the /DSS with the
                // validation data, then the document time-stamp.
                Format::Pades | Format::PadesLt | Format::PadesLta => {
                    let mut revocation = Vec::with_capacity(crl.len() + ocsp.len());
                    for c in &crl {
                        revocation.push(openfirma_pades::RevocationBytes::Crl(read_der_blob(
                            c, "CRL",
                        )?));
                    }
                    for o in &ocsp {
                        revocation.push(openfirma_pades::RevocationBytes::Ocsp(read_der_blob(
                            o,
                            "OCSP response",
                        )?));
                    }
                    openfirma_pades::pades_sign(
                        &content,
                        &signer,
                        &PadesOptions {
                            digest: digest_alg,
                            reason,
                            location,
                            contact_info,
                            field_name,
                            contents_reserved,
                            visible: rect.map(|r| Appearance {
                                page,
                                rect: r,
                                label: label.clone(),
                            }),
                            // B-LTA is B-LT is B-T: the same TSA stamps the
                            // signature value and then the document
                            timestamp: stamp.clone(),
                            validation_certs,
                            revocation,
                            document_timestamp: if matches!(format, Format::PadesLta) {
                                stamp.clone()
                            } else {
                                None
                            },
                            ..PadesOptions::default()
                        },
                    )?
                }
                // XAdES-B-B is enveloped and signs XML, see docs/xades.md.
                // --digest picks the signature algorithm; the reference
                // digests stay SHA-512, AutoFirma's default. signingTime is
                // not optional here: the baseline profile requires it, so
                // --no-signing-time and the CAdES attribute knobs do not
                // apply, and --mime-type feeds DataObjectFormat instead.
                Format::Xades => openfirma_xades::xades_sign(
                    &content,
                    &signer,
                    &openfirma_xades::XadesOptions {
                        digest: digest_alg,
                        mime_type,
                        ..Default::default()
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
            // the flags are judged before any file is read: a --at that is
            // not a time is the user's first mistake, not the certificate's
            let validation_time = match &at {
                Some(text) => parse_rfc3339(text)
                    .map_err(|e| anyhow::anyhow!("--at {text:?} is not an RFC 3339 time: {e}"))?,
                None => std::time::SystemTime::now(),
            };
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
                let document = openfirma_pades::pades_verify(&bytes, &opts)?;
                for (i, sig) in document.signatures.iter().enumerate() {
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
                for (i, t) in document.document_timestamps.iter().enumerate() {
                    let [a, b, c, d] = t.byte_range;
                    println!(
                        "document time-stamp {} (object {} {}): the token imprints {} of \
                         the bytes its /ByteRange [{a} {b} {c} {d}] covers",
                        i + 1,
                        t.object.num,
                        t.object.generation,
                        t.digest.name()
                    );
                }
                if let Some(dss) = &document.dss {
                    println!(
                        "validation data (/DSS): {} certificate(s), {} CRL(s), {} OCSP \
                         response(s), all of them readable and every CRL signature verified",
                        dss.certificates,
                        dss.crls.len(),
                        dss.ocsps
                    );
                    for crl in &dss.crls {
                        println!(
                            "  CRL issued by {}: {} revoked, next update {}",
                            crl.issuer,
                            crl.revoked_serials.len(),
                            match crl.next_update {
                                Some(t) => fmt_system_time(t),
                                None => "none".to_string(),
                            }
                        );
                    }
                    for chain in &dss.chains {
                        println!(
                            "  signature {}: chain rebuilt from the /DSS alone: {}",
                            chain.signature,
                            chain.subjects.join(" -> ")
                        );
                    }
                    for n in &dss.uncovered {
                        println!(
                            "  signature {n}: no /VRI entry, the archived validation data \
                             does not cover it"
                        );
                    }
                }
                println!(
                    "OK: all {} signature(s) verify against the supplied trust anchors",
                    document.signatures.len()
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

/// The password of the `--p12` container: `--password-file` first, then
/// `--password` or the `OPENFIRMA_PASSWORD` environment variable clap feeds
/// it from. The file is the safe input — argv is world readable through ps
/// and lands in shell history — and wins so that an exported environment
/// variable cannot quietly override what the user typed a path to.
fn p12_password(
    flag: Option<std::ffi::OsString>,
    file: Option<PathBuf>,
) -> Result<Option<Zeroizing<String>>> {
    if let Some(path) = file {
        let bytes = Zeroizing::new(
            std::fs::read(&path)
                .with_context(|| format!("reading the password file {}", path.display()))?,
        );
        // the first line, with one CRLF or LF ending ignored: `echo secret >
        // file` must not sign with a newline in the password
        let line = bytes.split(|b| *b == b'\n').next().unwrap_or(&[]);
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let text = std::str::from_utf8(line).map_err(|_| non_utf8_secret_error())?;
        return Ok(Some(Zeroizing::new(text.to_string())));
    }
    match flag {
        Some(value) => Ok(Some(Zeroizing::new(
            value.into_string().map_err(|_| non_utf8_secret_error())?,
        ))),
        None => Ok(None),
    }
}

/// Why a password that is not UTF-8 cannot be used, and what to do about it.
fn non_utf8_secret_error() -> anyhow::Error {
    anyhow::anyhow!(
        "the password is not valid UTF-8: it may contain non-ASCII characters in an \
         encoding openfirma cannot represent. PKCS#12 encodes passwords as UTF-16 \
         BMPStrings and openfirma re-encodes them from UTF-8; supply the password as \
         UTF-8, or re-export the container with an ASCII password: \
         `openssl pkcs12 -in old.p12 -out new.p12`"
    )
}

/// Reads a certificate and a PKCS#8 key, accepting PEM or DER for both.
fn load_signer(cert: &PathBuf, key: &PathBuf, chain: &[PathBuf]) -> Result<SoftwareSigner> {
    let cert_bytes = std::fs::read(cert).with_context(|| format!("reading {}", cert.display()))?;
    // a key file on disk is secret material like a decrypted PKCS#12, and the
    // buffer that held it is zeroed on the way out rather than freed as-is
    let key_bytes =
        Zeroizing::new(std::fs::read(key).with_context(|| format!("reading {}", key.display()))?);

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

/// Reads a DER blob, accepting the PEM wrapping around it. What gets
/// archived in a /DSS is the DER, and a CRL or an OCSP response arrives in
/// either shape depending on how the caller fetched it.
fn read_der_blob(path: &PathBuf, what: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    if !bytes.starts_with(b"-----BEGIN") {
        return Ok(bytes);
    }
    let text = String::from_utf8_lossy(&bytes);
    let b64: String = text
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .map(|l| l.trim())
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .with_context(|| {
            format!(
                "{} is PEM but its base64 body does not decode to a DER {what}",
                path.display()
            )
        })
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
    if !(1..=12).contains(&m) {
        return Err(format!("month {m} is out of range"));
    }
    // a validation time of 2026-02-31 is not a time at all: the day has to
    // exist in its month, leap years included, or the caller typoed and the
    // certificate dates get judged against an instant that never happens
    let days_in_month = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => u32::from(is_leap_year(y)) + 28,
        _ => unreachable!("the month was range checked above"),
    };
    if d < 1 || d > days_in_month {
        return Err(format!(
            "{s:?} is not a calendar date: month {m} of year {y} has {days_in_month} days"
        ));
    }
    Ok((y, m, d))
}

/// The proleptic Gregorian leap year rule, the same calendar
/// `days_from_civil` below converts through.
fn is_leap_year(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
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

    /// Temp file named after the running test, because cargo runs the tests
    /// of one binary in parallel threads.
    fn write_tmp(name: &str, bytes: &[u8]) -> PathBuf {
        let test = std::thread::current()
            .name()
            .unwrap_or("main")
            .replace("::", "_");
        let path =
            std::env::temp_dir().join(format!("openfirma-{}-{test}-{name}", std::process::id()));
        std::fs::write(&path, bytes).expect("cannot write temp file");
        path
    }

    /// A one answer TCP server, so `http_post` can be pointed at something
    /// that behaves like a hostile TSA without leaving the machine.
    fn fake_tsa(answer: Vec<u8>) -> (std::net::SocketAddr, std::thread::JoinHandle<()>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("cannot bind");
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                // Drain the request until a short read timeout expires.
                // Closing with unread bytes in the receive buffer makes the
                // kernel send a RST, and the client's read_to_end then fails
                // even though the answer arrived: the request is two writes
                // and the first read races the second segment.
                stream
                    .set_read_timeout(Some(std::time::Duration::from_millis(100)))
                    .ok();
                let mut buf = [0u8; 8192];
                loop {
                    match stream.read(&mut buf) {
                        Ok(0) => break,
                        Ok(_) => continue,
                        Err(_) => break, // timeout or reset: nothing more is coming
                    }
                }
                let _ = stream.write_all(&answer);
                // the handler's drop closes the connection, which is what
                // "Connection: close" promised the client
            }
        });
        (addr, handle)
    }

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

    /// --at is the instant certificate validity is judged at, so a date that
    /// never existed must not quietly become one that does: 2026-02-31 used
    /// to be accepted and normalized to March 3.
    #[test]
    fn calendar_impossible_dates_are_refused() {
        for bad in [
            "2026-02-31",
            "2026-02-30",
            "2026-02-29", // 2026 is not a leap year
            "1900-02-29", // divisible by 100, not by 400: not a leap year
            "2026-04-31",
            "2026-00-10",
            "2026-01-00",
            "2026-02-31T12:00:00Z",
        ] {
            assert!(parse_rfc3339(bad).is_err(), "{bad:?} was accepted");
        }
        // and the day-in-month refusals say they are calendar refusals
        for bad in ["2026-02-31", "2026-02-29", "2026-04-31", "2026-01-00"] {
            let err = parse_rfc3339(bad).err().unwrap();
            assert!(err.contains("not a calendar date"), "{bad}: {err}");
        }
        // the leap years that are real stay usable
        assert!(parse_rfc3339("2024-02-29").is_ok());
        assert!(parse_rfc3339("2000-02-29").is_ok());
        assert!(parse_rfc3339("2026-02-28").is_ok());
    }

    /// Signing a document onto itself replaces the only copy the user named;
    /// it takes an explicit --force to mean that.
    #[test]
    fn signing_a_file_onto_itself_needs_force() {
        let input = write_tmp("in-place.pdf", b"%PDF-1.4\n");
        check_not_in_place(&input, &input, true).expect("--force is the explicit yes");
        let err = check_not_in_place(&input, &input, false)
            .expect_err("the same file twice is the accident --force exists for")
            .to_string();
        assert!(err.contains("--force"), "{err}");

        // the same file spelled differently is still the same file
        let dotted = input
            .parent()
            .unwrap()
            .join(".")
            .join(input.file_name().unwrap());
        assert!(check_not_in_place(&input, &dotted, false).is_err());

        // a different output is the normal case
        let other = write_tmp("in-place-out.pdf", b"");
        check_not_in_place(&input, &other, false).expect("different files are fine");
        std::fs::remove_file(&other).ok();

        // and an output that does not exist yet cannot be the input
        let missing = input.with_file_name("definitely-not-the-input.pdf");
        check_not_in_place(&input, &missing, false).expect("a new file is fine");
    }

    #[test]
    fn the_contents_reservation_is_a_flag_with_the_itext_default() {
        let cli = Cli::try_parse_from(["openfirma", "sign", "-i", "a.pdf", "-o", "b.pdf"]).unwrap();
        let Command::Sign(args) = cli.command else {
            panic!("sign");
        };
        assert_eq!(args.contents_reserved, 27_000);
        assert_eq!(
            args.contents_reserved,
            openfirma_pades::DEFAULT_CONTENTS_RESERVED
        );
        assert!(!args.force);

        let cli = Cli::try_parse_from([
            "openfirma",
            "sign",
            "-i",
            "a.pdf",
            "-o",
            "b.pdf",
            "--contents-reserved",
            "40000",
            "--force",
        ])
        .unwrap();
        let Command::Sign(args) = cli.command else {
            panic!("sign");
        };
        assert_eq!(args.contents_reserved, 40_000);
        assert!(args.force);
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

    /// --password-file is the safe input: the first line, one trailing LF or
    /// CRLF ignored, and it wins over --password when both are given.
    #[test]
    fn the_password_file_is_read_and_one_newline_ignored() {
        let path = write_tmp("pw.txt", b"secret\n");
        let got = p12_password(None, Some(path.clone())).unwrap().unwrap();
        assert_eq!(&*got, "secret");

        let crlf = write_tmp("pw-crlf.txt", b"secret\r\n");
        let got = p12_password(None, Some(crlf)).unwrap().unwrap();
        assert_eq!(&*got, "secret");

        // the file wins over the flag, and the flag works on its own
        let got = p12_password(Some("flagvalue".into()), Some(path))
            .unwrap()
            .unwrap();
        assert_eq!(&*got, "secret");
        let got = p12_password(Some("flagvalue".into()), None)
            .unwrap()
            .unwrap();
        assert_eq!(&*got, "flagvalue");
        assert!(p12_password(None, None).unwrap().is_none());
    }

    /// A password file that is not UTF-8 used to arrive as a clap error
    /// about invalid UTF-8 and nothing else. PKCS#12 passwords are UTF-16
    /// BMPStrings; the error has to say that the password may contain
    /// non-ASCII characters this tool cannot represent, and what to run.
    #[test]
    fn a_password_that_is_not_utf8_says_what_might_be_wrong() {
        let path = write_tmp("pw-latin1.txt", b"caf\xe9\n");
        let err = p12_password(None, Some(path)).unwrap_err().to_string();
        assert!(err.contains("not valid UTF-8"), "{err}");
        assert!(err.contains("non-ASCII"), "{err}");
        assert!(err.contains("openssl pkcs12"), "{err}");
    }

    /// The status line is parsed as a status line: version token, then the
    /// code token. Matching the substring " 200" anywhere in the line also
    /// matched "HTTP/1.1 2006 ...", and the server picks the reason phrase.
    #[test]
    fn the_tsa_status_line_is_parsed_not_substring_matched() {
        let (addr, srv) = fake_tsa(b"HTTP/1.1 2006 evil\r\nContent-Length: 2\r\n\r\nhi".to_vec());
        let err = http_post(&format!("http://{addr}/tsa"), b"query")
            .expect_err("2006 is not 200")
            .to_string();
        srv.join().unwrap();
        assert!(err.contains("expected an HTTP/1.x 200"), "{err}");

        let (addr, srv) = fake_tsa(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi".to_vec());
        let body = http_post(&format!("http://{addr}/tsa"), b"query")
            .expect("a real 200 answer must be accepted");
        srv.join().unwrap();
        assert_eq!(body, b"hi");

        let (addr, srv) = fake_tsa(b"HTTP/1.1 500 Internal Server Error\r\n\r\nx".to_vec());
        let err = http_post(&format!("http://{addr}/tsa"), b"query")
            .expect_err("a 500 is not a timestamp")
            .to_string();
        srv.join().unwrap();
        assert!(err.contains("500"), "{err}");
    }

    /// A timestamp answer is kilobytes; a server that keeps sending is
    /// refused at one megabyte instead of being read into memory.
    #[test]
    fn the_tsa_answer_is_capped() {
        let mut answer = Vec::from(&b"HTTP/1.1 200 OK\r\n\r\n"[..]);
        answer.resize(TSA_MAX_RESPONSE + 100, b'x');
        let (addr, srv) = fake_tsa(answer);
        let err = http_post(&format!("http://{addr}/tsa"), b"query")
            .expect_err("a megabyte of x is not a TimeStampResp")
            .to_string();
        srv.join().unwrap();
        assert!(err.contains("1048576 bytes"), "{err}");
    }
}
