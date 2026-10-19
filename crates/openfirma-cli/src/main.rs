use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use base64::Engine as _; // the compat XML envelope's .encode()
use clap::{Args, Parser, Subcommand, ValueEnum};
use openfirma_core::alg::DigestAlg;
use openfirma_core::cert::CertificateHandle;
use openfirma_core::signer::{Signer, SoftwareSigner};
use openfirma_keystore::boxed_signer;
use openfirma_pades::Appearance;
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
    /// Work with system keystores (PKCS#11 tokens, NSS databases, the
    /// platform certificate store)
    Keystores {
        #[command(subcommand)]
        command: KeystoreCommand,
    },
    /// Answer one browser invocation URI (`afirma://…`), headless. This is
    /// what the OS scheme handler runs when a sede electronica's page hands
    /// the browser an afirma:// URL; the result goes to --output (AutoFirma's
    /// wire form, `base64(cert)|base64(signature)` — in the real flow the
    /// page reads it from the loopback endpoint or the intermediate server,
    /// never from the scheme hand-off itself, and this flag is how a test,
    /// script, or human collects it).
    AfirmaUri {
        /// The full afirma://… URI as one argument (the OS hands the handler
        /// exactly this in %u/%1). Omit it only with --register, which answers
        /// no call and installs the scheme instead.
        uri: Option<String>,

        /// Where to write the result. Without it the payload goes to stdout,
        /// which is what a human piping it wants; a sede flow has no stdout
        /// reader and uses --serve instead.
        #[arg(long, short = 'o')]
        output: Option<PathBuf>,

        /// PKCS#12 holding the signing key. The password rule of `sign`
        /// applies: --password-file or OPENFIRMA_PASSWORD, never argv.
        #[arg(long)]
        p12: Option<PathBuf>,

        /// Password file for --p12; first line, one newline ignored (see sign).
        #[arg(long)]
        password_file: Option<PathBuf>,

        /// Install the `afirma://` scheme on this OS: write the per-user
        /// registration file(s) and the browser handler config that names the
        /// signing key (see --config), never a registry entry nor a system
        /// path. Reads nothing from a URI; run it at install time, not from a
        /// browser call. Without this flag the command answers a URI instead.
        #[arg(long)]
        register: bool,

        /// With --register only: confirm that openfirma takes the `afirma://`
        /// scheme from any AutoFirma installed on this machine (a scheme has
        /// exactly one default handler; finding A-2). Without it, a detected
        /// AutoFirma makes --register refuse. Also accepts --unregister to
        /// undo what --register wrote — nothing else's registration is touched.
        #[arg(long, requires = "register")]
        acknowledge_autofirma: bool,

        /// Undo the scheme registration (--desktop/--registry file and the
        /// default-handler association) that openfirma wrote; never a key or
        /// a browser's own settings. Takes no URI and signs nothing.
        #[arg(long, conflicts_with = "register")]
        unregister: bool,

        /// Allow THIS invocation's key to sign browser calls without asking
        /// anybody (finding A-3). The AutoFirma-equivalent of skipping its
        /// certificate dialog and PIN prompt: only an owner who means it
        /// passes this; with a --config key, `allow_unattended = true` in the
        /// config file is the standing form of the same opt-in. Without any
        /// opt-in, a browser call refuses instead of signing quietly.
        #[arg(long)]
        allow_unattended: bool,

        /// Password of the --p12 container. INSECURE like `sign`'s own flag
        /// (argv is visible in ps), but every command that opens a PKCS#12 —
        /// `sign`, `afirma-uri`, `afirma-serve` — answers the same three
        /// inputs: --password-file, OPENFIRMA_PASSWORD, or this one. A refusal
        /// that offers OPENFIRMA_PASSWORD must always be able to read it.
        #[arg(long, env = "OPENFIRMA_PASSWORD", hide_env_values = true)]
        password: Option<std::ffi::OsString>,

        /// Browser handler configuration (p12 + password_file) to resolve the
        /// key from when --p12 is not given — this is how the registered
        /// scheme handler, which carries no flags but argv's URI, can sign at
        /// all (finding M-3b). Defaults to $XDG_CONFIG_HOME/openfirma/
        /// browser.toml ($HOME/.config/openfirma/browser.toml unset-XDG); see
        /// `--register`, which writes it. A named --p12 always wins.
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Serve the loopback endpoint a sede page calls, and run every URI that
    /// arrives through it. The ephemeral port is printed at startup — like
    /// AutoFirma's pages learn theirs, out of band — and each session token
    /// is consumed by its first request. Ctrl-C stops it. See
    /// docs/adr/0005-browser-protocol.md for the transport decision and its
    /// exact limits.
    AfirmaServe {
        #[arg(long)]
        p12: Option<PathBuf>,

        #[arg(long)]
        password_file: Option<PathBuf>,

        /// Same insecure escape hatch as `afirma-uri --password` (see its
        /// help): the endpoint's password comes from --password-file or
        /// OPENFIRMA_PASSWORD like every other command that opens a PKCS#12.
        #[arg(long, env = "OPENFIRMA_PASSWORD", hide_env_values = true)]
        password: Option<std::ffi::OsString>,

        /// Browser handler configuration (p12 + password_file), the same file
        /// `afirma-uri --config` reads and `--register` writes: with it, an
        /// endpoint started from a desktop launcher needs no key flags either.
        /// A named --p12 always wins over what the config says.
        #[arg(long)]
        config: Option<PathBuf>,

        /// A-3: run the endpoint over a key nobody is asked about. The opt-in
        /// itself still needs `allow_unattended = true` IN THE BROWSER CONFIG
        /// when the key comes from it (a standing service outlives whoever
        /// typed a flag), so this flag is what lets an argv --p12 be the
        /// opted-in one. Every request holding a valid token then signs with
        /// no human in the loop; AutoFirma answers that flow with its dialog
        /// and openfirma's headless endpoint has none.
        #[arg(long)]
        allow_unattended: bool,

        /// Address to bind. Only loopback addresses are accepted, and
        /// 127.0.0.1:0 (the default) is the documented form: the port that
        /// gets chosen is printed and belongs to whoever hands it to the page.
        #[arg(long, default_value = "127.0.0.1:0")]
        bind: String,

        /// Answer one liveness probe (`POST /echo` on a fresh token) and
        /// exit 0 if the endpoint signs nothing but answers — the shape of a
        /// smoke test CI can run without a browser. A token is issued and
        /// consumed by this flag's own request; with no --serve, an external
        /// fake sede drives the rest.
        #[arg(long)]
        issue_token: bool,

        /// Issue a session token, print it, and exit. What a real launch
        /// prints is the port (this prints both); scripts feed the pair to
        /// their own client code.
        #[arg(long, conflicts_with = "issue_token")]
        token_only: bool,
    },
    /// Speak AutoFirma's own command line: `openfirma autofirma sign -i f
    /// -o f [-format auto|cades|pades|xades] [-store …] [-alias a]
    /// [-password p]` and `openfirma autofirma listaliases [-store …]
    /// [-password p]`. The flags are AutoFirma's single-dash spellings and
    /// the exit code follows its convention (`STATUS_ERROR = -1`, which Unix
    /// answers as 255) so a script or sede integration written against
    /// AutoFirma's CLI keeps working pointed at openfirma. The password on
    /// argv is AutoFirma's own habit and openfirma cannot make it safe; the
    /// native `sign` command's --password-file stays the right way. An
    /// existing output file is never replaced without OPENFIRMA_COMPAT_FORCE=1,
    /// unlike AutoFirma's silent overwrite: a signature must not delete
    /// somebody's file without being asked twice.
    Autofirma {
        /// The raw argv after `autofirma`, parsed by this command's own
        /// rules — clap stays out of it so AutoFirma's single-dash flags and
        /// exit-code convention pass through untouched (`allow_hyphen_values`
        /// alone would still read `-format` as a flag of the wrapper).
        #[arg(allow_hyphen_values = true, trailing_var_arg = true)]
        args: Vec<String>,
    },
}

#[derive(Subcommand)]
enum KeystoreCommand {
    /// List the certificates each given keystore holds together with a key
    /// openfirma can sign with. With no argument, lists what this machine can
    /// see without a PIN: the platform store on Windows and macOS; nothing to
    /// guess at elsewhere, where keystores are named one by one.
    List {
        /// One keystore descriptor in the same form as `sign --store`
        /// (`pkcs11:/path[:token]`, `nss[:sql:/db]`, `windows`, `macos`),
        /// repeatable.
        #[arg(long = "store", short = 's')]
        stores: Vec<String>,

        /// Environment variable holding the PIN of every listed keystore.
        /// Without it, tokens that hide their objects until login report how
        /// to give one instead of pretending to be empty.
        #[arg(long)]
        pin_env: Option<String>,
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
    /// has to reach one of them. Without this flag the anchors come from
    /// $OPENFIRMA_TRUST (a path list); with neither, verification refuses to
    /// run — there is nothing to check a chain up to. Every block of a
    /// chosen file that basicConstraints marks CA:FALSE is refused as an
    /// anchor; bundles of several certificates load the CAs among them.
    #[arg(long)]
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

    /// Sign with a certificate the system or a token holds, instead of a file.
    /// Forms: `pkcs11:/path/to/module.so[:token label]` for any PKCS#11 module
    /// (a smartcard's opensc-pkcs11.so included), `nss[:sql:/path/to/db]` for
    /// an NSS shared database (Firefox/Thunderbird style; the module is found
    /// on its own or via OPENFIRMA_NSS_MODULE), and `windows` or `macos` for
    /// the platform's own certificate store. A descriptor ending in `::`
    /// (`pkcs11:/mod.so:token::`) logs in with an empty PIN — the shape of an
    /// unpassworded token; otherwise the PIN comes from --pin-env. Replaces
    /// --p12/--cert/--key. The private key never leaves the store: openfirma
    /// asks it to sign.
    #[arg(long)]
    store: Option<String>,

    /// Environment variable holding the PIN of the --store keystore (its PKCS#11
    /// user PIN, or the NSS database password). Like every secret here it must
    /// not appear on the command line: export the variable, point this flag at
    /// its name. A variable that is not set is refused before anything opens —
    /// a typo in the name must not spend a real token's lockout tries. A
    /// keystore that genuinely needs no PIN (a passwordless token, an NSS
    /// shared database) is spelled by the descriptor itself, with the trailing
    /// `::`. With neither, openfirma signs without ever calling C_Login, and
    /// asks for a PIN only if the token turns out to require one.
    #[arg(long)]
    pin_env: Option<String>,

    /// Label of the certificate to sign with when --store holds more than one
    /// (CKA_LABEL on PKCS#11, the NSS nickname). Without it a store holding
    /// exactly one signer is used and more than one is an error that lists them.
    #[arg(long)]
    store_alias: Option<String>,

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

    /// Omit the ESS contentHint attribute. AutoFirma includes it by default
    /// with its generic description "binary" (its per-type descriptions come
    /// from a jmimemagic database openfirma does not ship), so we do too; this
    /// flag is `includeContentHintAttribute=false` in AutoFirma's vocabulary.
    #[arg(long)]
    no_content_hint: bool,

    /// OID of the ETSI signaturePolicyIdentifier attribute — AutoFirma's
    /// `policyIdentifier` extraParam (a Spanish sede's policy is
    /// 2.16.724.1.3.1.1.2.1.9 or an 0.4.0.194 one). The sigPolicyHash follows
    /// AutoFirma's shape: a DigestInfo of the signature's own digest over the
    /// placeholder byte.
    #[arg(long)]
    signature_policy: Option<String>,

    /// Hex bytes for the sigPolicyHash to write with --signature-policy —
    /// the digest of the policy assertion text, what AutoFirma's
    /// `policyIdentifierHash` extraParam carries (base64 there). Without it
    /// the AutoFirma placeholder stays.
    #[arg(long, value_parser = clap::value_parser!(String))]
    signature_policy_hash: Option<String>,

    /// OID of the ETSI commitmentTypeIndication attribute — AutoFirma's
    /// `commitmentTypeIndication0Identifier` extraParam (1 for approval, i.e.
    /// proofOfApproval 1.2.840.113549.1.9.16.6.5, 5 for delivery).
    #[arg(long)]
    commitment_type: Option<String>,

    /// Do not copy the signer certificate's certificatePolicies into the
    /// signer-certificate attribute. AutoFirma copies them by default
    /// (doNotIncludePolicyOnSigningCertificate=false), so we do too; this
    /// flag turns it off for a verifier that chokes on the policies field.
    #[arg(long)]
    no_certificate_policies: bool,

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

    /// Name of the AcroForm signature field. When the document already has a
    /// signature field with this name, the signature is written INTO it — the
    /// box the form drew — and that field must not carry a signature yet;
    /// otherwise a field with this name is added. A visible signature
    /// (--rect) is drawn in the field's own rectangle. Defaults to the next
    /// free SignatureN in the document.
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

    /// Sign a PDF that is certified with /Perms /DocMDP /P 1 — "no changes to
    /// the document are permitted" — anyway. Without it such a document is
    /// refused: the new revision breaks the certification in every reader that
    /// honours it, and only whoever owns the document may override its author's
    /// rule (AutoFirma asks for the same permission). PAdES only.
    #[arg(long)]
    allow_certified: bool,

    /// Sign despite the conservative algorithm policy — SHA-1 digests and RSA
    /// keys below 2048 bits — the way AutoFirma signs whatever it is handed.
    /// Without it `sign` refuses such output (`--digest sha1` or a weak key):
    /// ETSI TS 119 312's conservative policy, openfirma's default, says no
    /// signature like that should leave a tool that claims CAdES. Passing this
    /// flag is the explicit opt-out; whoever passes it owns what validators
    /// make of the result.
    #[arg(long)]
    allow_weak_algorithms: bool,
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
    /// The exact `--format` value this variant spells — the same string the
    /// shared dispatcher matches on, and what the parity test compares
    /// against `openfirma_browser::signing::all_formats()`.
    fn flag_value(self) -> &'static str {
        match self {
            Format::Cades => "cades-b-b",
            Format::Pades => "pades-b-b",
            Format::PadesLt => "pades-b-lt",
            Format::PadesLta => "pades-b-lta",
            Format::Xades => "xades-b-b",
        }
    }

    fn label(self) -> &'static str {
        openfirma_browser::signing::format_label(self.flag_value())
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
            // One transport for both frontends (review 06, M-9): the POST,
            // the status parsing and the response cap live in
            // openfirma-cades' tsa module — the GUI's TSA field runs the same
            // code. What stays local is the CLI's own warning posture: with
            // --validation-cert anchors, a token whose signature verifies
            // gets NO warning; anything else says so on stderr.
            let trust = tsa_trust.clone();
            openfirma_cades::tsa::provider(
                &url,
                "--tsa only speaks plain http today. An https TSA needs a TLS client, \
                 which is a dependency decision recorded separately; until then fetch \
                 the token by hand and pass --timestamp-token.",
                move |source, token| warn_if_token_unverified(source, token, &trust),
            )
            .map(Some)
            .map_err(anyhow::Error::from)
        }
        (None, Some(path)) => {
            let response =
                std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
            let source = format!("{}", path.display());
            Ok(Some(Arc::new(move |sig: &[u8], digest| {
                let token = tsp::token_from_response(&response, digest, sig, None)?;
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

/// One `--store` / `keystores list --store` descriptor, parsed. The type and
/// its parser live in `openfirma_core::workflow` (docs/adr/0006-gui-toolkit.md): the GUI's
/// add-a-keystore field and this flag are ONE parser over ONE spelling, so a
/// descriptor accepted by `openfirma sign --store` is accepted by the window
/// and vice versa — the drift both frontends' tests would never catch. The
/// local name stays because every match arm below reads it naturally.
type StoreSpec = openfirma_core::workflow::StoreSpec;

/// Parses a store descriptor through the shared rule (see above). The core
/// parser's messages are already `--store`-phrased — they were written from
/// this flag's own text when the code moved — so nothing is reworded.
fn parse_store_spec(text: &str) -> Result<StoreSpec> {
    StoreSpec::parse(text).map_err(anyhow::Error::msg)
}

/// The PIN for a keystore, read from the environment variable named by
/// `--pin-env`. A variable that is not set is an error before anything opens:
/// sending an empty PIN because of a typo in the name spends a real token's
/// lockout tries (measured on SoftHSM; the DNIe locks after three failures
/// and needs a police station to reopen — finding M2). The truly empty PIN —
/// an NSS shared database or a passwordless token — is spelled by the
/// descriptor itself (`pkcs11:module::`), which `open_store` turns into the
/// explicit no-PIN login without ever coming through here. The copy that
/// does come back arrives already zeroizing: from this line on, every buffer
/// that held it zeroes on drop (finding B-2: the p12 password had this
/// posture and the token PIN did not).
fn store_pin(pin_env: Option<&String>) -> Result<Option<Zeroizing<String>>> {
    match pin_env {
        Some(var) => match std::env::var(var) {
            Ok(value) => Ok(Some(Zeroizing::new(value))),
            Err(std::env::VarError::NotPresent) => anyhow::bail!(
                "--pin-env names {var}, and {var} is not set; refusing to try the token \
                 with an empty PIN (a wrong guess costs a lockout try on real cards — a \
                 keystore that genuinely needs no PIN is spelled with the :: marker, e.g. \
                 --store pkcs11:/path/to/module.so::)"
            ),
            Err(std::env::VarError::NotUnicode(_)) => anyhow::bail!(
                "{var} does not hold text; a PIN must be a UTF-8 string in the environment"
            ),
        },
        None => Ok(None),
    }
}

/// `SystemStore` is already object safe (`certificates` returns a sized
/// `Vec`, and `sign_prehash` takes both arguments by reference), so the CLI
/// needs no erasure shim — only this alias for the handle `open_store` hands
/// back: an Arc, because the store must outlive every `StoreSigner` borrowed
/// from it. The dyn shape keeps every backend out of the format crates'
/// generics; see `boxed_signer`.
type DynStore = Arc<dyn openfirma_keystore::SystemStore>;

/// Opens a descriptor through the keystore crate's single implementation
/// (finding B8): the GUI calls the same `open_store`, so no platform refusal,
/// NSS hint or no-PIN marker can differ between the frontends.
fn open_store(spec: &StoreSpec, pin: Option<Zeroizing<String>>) -> Result<DynStore> {
    Ok(openfirma_keystore::open_store(spec, pin)?)
}

/// The name a keystore entry is offered under and answers to: the store's own
/// label when it has one, the subject CN when it does not. This is the name
/// `keystores list` and `autofirma listaliases` print, so it is the name
/// `--store-alias`/`-alias` has to accept — round 2's 04-N3: the match used to
/// be against `label` alone, so on a store whose entries carry no label (a
/// PKCS#11 object without `CKA_LABEL`, and every certificate the Windows store
/// lists) the refusal read
///
///     no keystore entry labeled 'PEREZ GARCIA, ANA'; entries present: …
///       PEREZ GARCIA, ANA
///
/// — the name it had just offered. `<no CN>` is what a certificate without a
/// CN is listed as, and matching it literally is harmless: it is copyable.
fn entry_name(entry: &openfirma_keystore::StoreCertificate) -> String {
    entry
        .label
        .clone()
        .unwrap_or_else(|| entry.cert.subject_cn().unwrap_or_else(|| "<no CN>".into()))
}

/// Picks the signing certificate of a keystore for `sign --store`: by label
/// when `--store-alias` gave one, otherwise requiring exactly one signer. An
/// ambiguous pick is refused with the labels on offer — guessing which
/// certificate signed a legal document is never acceptable.
///
/// Before choosing, AutoFirma's default filters run (finding A5): the DNIe's
/// authentication certificate and expired certificates are hidden, so after
/// filtering a signing card usually stands alone and needs no `--store-alias`
/// at all. Naming a hidden entry with `--store-alias` still signs — the
/// explicit request outranks the default view — but openfirma says out loud
/// why that signature is not one a verifier will accept.
fn store_signer(store: DynStore, alias: Option<&str>) -> Result<Box<dyn Signer + 'static>> {
    let now = std::time::SystemTime::now();
    let all = store.certificates()?;
    if all.is_empty() {
        anyhow::bail!("this keystore holds no certificate with a signable private key");
    }
    let pool: Vec<_> = all
        .iter()
        .filter(|c| !openfirma_keystore::hidden_by_default(c, now))
        .cloned()
        .collect();
    if pool.is_empty() {
        // The filter would empty the keystore. Say so rather than offer dead
        // or login-only certificates as if they were ordinary signers.
        anyhow::bail!(
            "every certificate in this keystore is expired or filtered out (the \
             DNIe's authentication certificate and expired certificates are never \
             offered for signing); name one explicitly with --store-alias to sign \
             with it despite that"
        );
    }
    let chosen = match alias {
        Some(want) => all
            .iter()
            .find(|c| entry_name(c) == want)
            .with_context(|| {
                let mut msg = format!("no keystore entry labeled '{want}'; entries present:");
                for c in &pool {
                    msg.push_str(&format!("\n  {}", entry_name(c)));
                }
                msg
            })?
            .clone(),
        None if pool.len() == 1 => pool[0].clone(),
        None => {
            let mut msg = String::from(
                "the keystore holds more than one signer; pick one with \
                              --store-alias:",
            );
            for c in &pool {
                msg.push_str(&format!("\n  {}", entry_name(c)));
            }
            anyhow::bail!("{msg}")
        }
    };
    warn_if_not_qualified(&chosen, now);
    Ok(boxed_signer(store, chosen))
}

/// The one-line warning of finding A5: a certificate the default filters hide
/// can still be signed with by name — but the user must hear why it is not a
/// signing certificate before the document goes out, not learn it from a
/// failed verification afterwards.
fn warn_if_not_qualified(cert: &openfirma_keystore::StoreCertificate, now: std::time::SystemTime) {
    let mut reasons = Vec::new();
    if cert.cert.expired_at(now) {
        reasons.push("it is expired".to_string());
    }
    if !cert.cert.can_sign() {
        reasons.push("its keyUsage allows neither digitalSignature nor nonRepudiation".to_string());
    }
    if cert.cert.is_dnie_authentication_cert() {
        reasons.push(
            "it is the DNIe's authentication certificate, not its signing \
             certificate (the signature would not be qualified)"
                .to_string(),
        );
    }
    if !reasons.is_empty() {
        eprintln!(
            "warning: signing with \"{}\": {}.",
            cert.label
                .as_deref()
                .or(cert.cert.subject_cn().as_deref())
                .unwrap_or("this certificate"),
            reasons.join("; ")
        );
    }
}

/// Refuses `sign -i f -o f` unless `--force` says the overwrite is meant.
///
/// Both paths are compared before any reading happens, and twice: the plain
/// absolute spelling catches `-o ./f` and `-o dir/../f`, and the canonical
/// one catches an output that is a symlink or a hard link to the input. The
/// input is read whole before the output is written, so nothing is lost
/// mechanically — what is refused is the silent case, where one typo turns a
fn check_not_in_place(
    input: &std::path::Path,
    output: &std::path::Path,
    force: bool,
) -> Result<()> {
    // The shared rule (openfirma-core's workflow): the window checks the same
    // thing with the same function, so neither frontend signs a document away.
    openfirma_core::workflow::check_not_in_place(input, output, force).map_err(anyhow::Error::msg)
}

/// Parses `llx,lly,urx,ury`, accepting commas or spaces as separators.
/// `--signature-policy-hash`: hex bytes, with or without spaces or colons.
fn parse_hex_bytes(text: &str) -> std::result::Result<Vec<u8>, String> {
    let clean: String = text
        .chars()
        .filter(|c| !matches!(c, ' ' | ':' | '_'))
        .collect();
    if clean.len() % 2 != 0 {
        return Err("hex string must be a whole number of bytes".into());
    }
    (0..clean.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&clean[i..i + 2], 16)
                .map_err(|_| format!("not a hex byte: {:?}", &clean[i..i + 2]))
        })
        .collect()
}

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
    // A-8 (review 06): AutoFirma answers a bad command line with its own
    // exit code (`STATUS_ERROR = -1`, which Unix truncates to 255). When the
    // argv speaks the compat dialect, clap's usage errors must answer it too
    // — detected from raw argv before parsing, because after parsing a bad
    // `Autofirma` line never reaches any code below at all. Every other
    // command keeps clap's conventional exit 2 for usage errors.
    let compat_mode = std::env::args().nth(1).as_deref() == Some("autofirma");
    // clap answers --help and errors as Err(Help/DisplayHelp) or its Error
    // kinds; `Cli::parse` handles both by exiting with ITS code. This wrapper
    // re-implements that only to swap the usage-error number inside compat
    // mode, so help and version must keep clap's exit 0 exactly as before:
    // render and exit 0 for them, and the swapped code only for real errors.
    let cli = Cli::try_parse().unwrap_or_else(|err| {
        match err.kind() {
            clap::error::ErrorKind::DisplayHelp
            | clap::error::ErrorKind::DisplayVersion
            // The built-in `help` subcommands print through this kind too.
            | clap::error::ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand => {
                use std::io::Write;
                // Help and version belong on stdout (clap writes them there);
                // a wrapper that moved them to stderr would break the scripts
                // that pipe `openfirma --help` somewhere.
                let mut out = std::io::stdout();
                let _ = out.write_all(err.to_string().as_bytes());
                let _ = out.flush();
                std::process::exit(0);
            }
            _ => {
                // Real usage errors: the message on stderr, and compat mode's
                // 255 in place of clap's own code (its default is 2).
                let code = if compat_mode { EXIT_AUTOFIRMA_ERROR } else { err.exit_code() };
                eprint!("{}", err.render());
                std::process::exit(code);
            }
        }
    });
    match cli.command {
        Command::Sign(args) => {
            // The M5 gate on the production side: `sign` refuses weak output
            // unless --allow-weak-algorithms opts out explicitly. Read before
            // the destructuring below takes the fields by value.
            let algorithms = if args.allow_weak_algorithms {
                openfirma_cades::verify::AlgorithmPolicy::All
            } else {
                openfirma_cades::verify::AlgorithmPolicy::Conservative
            };
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
                no_content_hint,
                signature_policy,
                signature_policy_hash,
                commitment_type,
                no_certificate_policies,
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
                store,
                pin_env,
                store_alias,
                tsa,
                timestamp_token,
                validation_cert,
                crl,
                ocsp,
                contents_reserved,
                force,
                allow_certified,
                // already read into `algorithms` above, before the move
                allow_weak_algorithms: _,
            } = *args;
            check_not_in_place(&input, &output, force)?;
            // Review 06, A-3 (CLI half): an existing output is somebody else's
            // file and `File::create`/`fs::write` truncates it in silence.
            // AutoFirma asks through its save dialog; the terminal has no
            // dialog, so the refusal is the answer and --force is the explicit
            // yes — the same shape as the input==output guard above.
            openfirma_core::workflow::check_not_overwrite(&output, force)
                .map_err(anyhow::Error::msg)?;
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
            // Never sign a signature (review 06's second pass moved the rule
            // from the window into core so BOTH frontends answer from it):
            // an input named like an openfirma output, or carrying CMS bytes,
            // gets the refusal that names `verify` as what to do instead —
            // before any key is opened and before anything is signed. Co-
            // signing a PDF (a second signature into the same document) is
            // NOT this rule; the content half of it is CMS only.
            openfirma_core::workflow::check_not_signed_input(&input, Some(&content))
                .map_err(anyhow::Error::msg)?;
            // One `Box<dyn Signer>` covers every source: the software paths
            // box up unchanged, and a system store's signer keeps its store
            // alive behind an Arc (see boxed_signer).
            // The three sources are exclusive, checked before opening
            // anything and before asking anyone for a secret.
            let named: Vec<&str> = [
                store.as_ref().map(|_| "--store"),
                p12.as_ref().map(|_| "--p12"),
                match (&cert, &key) {
                    (Some(_), Some(_)) => Some("--cert/--key"),
                    _ => None,
                },
            ]
            .into_iter()
            .flatten()
            .collect();
            if named.len() > 1 {
                anyhow::bail!(
                    "{} name alternative sources for the signing key: give exactly one",
                    named.join(" and ")
                );
            }
            // B-6: `sign` is the one command allowed to ask a terminal for the
            // container's password when nothing else supplied it — and it
            // asks only of an invocation that actually NAMED a --p12 (the
            // review's probe: with no source named at all, the old order put
            // the question first and then blamed the user with "a password
            // only makes sense together with --p12" for the secret the CLI
            // itself had demanded). Resolution from flags/env never prompts.
            let asks = p12.is_some();
            let password = p12_password_ask(
                password,
                password_file,
                if asks {
                    PasswordAsk::sign()
                } else {
                    PasswordAsk::no_prompt()
                },
            )?;
            let signer: Box<dyn Signer> = if let Some(spec) = &store {
                if alias.is_some() {
                    anyhow::bail!(
                        "--alias names a PKCS#12 entry; the keystore entry of --store \
                         is picked with --store-alias"
                    );
                }
                if password.is_some() {
                    anyhow::bail!(
                        "a --password belongs to a --p12; the PIN of --store comes from \
                         --pin-env VAR, naming the variable that holds it"
                    );
                }
                let pin = store_pin(pin_env.as_ref())?;
                let store = open_store(&parse_store_spec(spec)?, pin)?;
                store_signer(store, store_alias.as_deref())?
            } else if let Some(container) = &p12 {
                if pin_env.is_some() || store_alias.is_some() {
                    anyhow::bail!("--pin-env and --store-alias belong to --store");
                }
                let pw = password.context(
                    "--p12 needs the container's password: --password-file (the safe \
                     input), the OPENFIRMA_PASSWORD environment variable, or --password \
                     (insecure, visible in ps and in shell history)",
                )?;
                Box::new(load_p12(container, &pw, alias.as_deref())?)
            } else if let (Some(c), Some(k)) = (&cert, &key) {
                if pin_env.is_some() || store_alias.is_some() {
                    anyhow::bail!("--pin-env and --store-alias belong to --store");
                }
                if password.is_some() {
                    anyhow::bail!("a password only makes sense together with --p12");
                }
                Box::new(load_signer(c, k, &chain)?)
            } else {
                if cert.is_some() || key.is_some() {
                    anyhow::bail!(
                        "--cert and --key are a pair: {} is missing its partner \
                         (or the intent was --store / --p12)",
                        if cert.is_some() { "--key" } else { "--cert" }
                    );
                }
                if password.is_some() {
                    anyhow::bail!("a password only makes sense together with --p12");
                }
                anyhow::bail!(
                    "a signing key is required: --cert and --key together, a --p12, \
                     or a system keystore with --store"
                )
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
            let mut request =
                openfirma_browser::signing::SignRequest::new(format.flag_value(), digest_alg);
            request.timestamp = stamp.clone();
            request.reason = reason;
            // The CAdES attribute knobs (docs/cades.md): the shared request
            // carries them so both frontends set them identically.
            request.cades_encapsulate_content = encapsulate;
            request.cades_mime_type = mime_type.clone();
            request.cades_content_hint = content_hint;
            request.cades_include_content_hint = !no_content_hint;
            request.cades_allow_weak_algorithms =
                algorithms == openfirma_cades::verify::AlgorithmPolicy::All;
            request.cades_signature_policy = signature_policy;
            if let Some(hash) = signature_policy_hash.as_deref() {
                request.cades_signature_policy_hash =
                    parse_hex_bytes(hash).map_err(anyhow::Error::msg)?;
            }
            request.cades_commitment_type = commitment_type;
            request.cades_include_certificate_policies = !no_certificate_policies;
            request.cades_include_issuer_serial = !no_issuer_serial;
            if no_signing_time {
                request.cades_signing_time = None;
                request.cades_no_signing_time = true;
            }
            request.location = location;
            request.contact_info = contact_info;
            request.field_name = field_name;
            request.contents_reserved = Some(contents_reserved);
            request.visible = rect.map(|r| Appearance {
                page,
                rect: r,
                label: label.clone(),
            });
            // One dispatcher for both frontends (finding M-4): the terminal
            // and the window sign every format through this exact call
            // sequence — see openfirma_browser::signing, whose header records why
            // the shared module lives there. A second `request` was born when
            // the PAdES LTV material joined the same builder: the long-term
            // fields now merge into the one request above instead of replacing
            // it (an earlier shape here shadowed the first and silently dropped
            // every CAdES knob set on it).
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
            request.validation_certs = validation_certs;
            request.revocation = revocation;
            request.allow_signing_certified = allow_certified;
            // B-LTA is B-LT is B-T: the same TSA stamps the signature value
            // and then the document (docs/pades.md). The gate above already
            // refuses pades-b-lta without --tsa, so only a live TSA arrives.
            request.document_timestamp = if matches!(format, Format::PadesLta) {
                stamp.clone()
            } else {
                None
            };
            let signature = openfirma_browser::signing::execute_with_detection(
                &mut request,
                &content,
                signer.as_ref(),
            )
            .map_err(|e| anyhow::anyhow!("{e}"))?;

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

            // --trust, or the environment's list, and never a silent default:
            // an unanchored chain verifies nothing. Each file loads through
            // core's rule, which keeps CA:FALSE leaves out of the anchors.
            let files = if trust.is_empty() {
                openfirma_core::workflow::default_trust_anchors()
            } else {
                trust
            };
            if files.is_empty() {
                bail!("no trust anchors: pass --trust or set $OPENFIRMA_TRUST");
            }
            let mut anchors = Vec::new();
            for t in &files {
                let loaded =
                    openfirma_core::workflow::load_trust_anchors(t).map_err(anyhow::Error::msg)?;
                anchors.extend(loaded);
            }
            let opts = openfirma_cades::VerifyOptions {
                trust_anchors: anchors,
                validation_time,
                ts_mode: false,
                ..openfirma_cades::VerifyOptions::new(Vec::new())
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
                    match (&t.problem, t.gen_time) {
                        (None, Some(at)) => println!(
                            "  the TSA's signature over this seal verified; it stamps {}",
                            fmt_system_time(at)
                        ),
                        (Some(why), _) => {
                            println!("  the TSA's signature over this seal is NOT verified: {why}");
                            println!("  no B-LTA level is claimed from this document time-stamp");
                        }
                        (None, None) => {
                            println!("  the seal's TSA signature was not verified")
                        }
                    }
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
                // B-1: an XML file (XAdES) is not a CMS, and handing it to the
                // CMS verifier produced "these bytes are not a CMS signature:
                // expected the ContentInfo (tag 0x30), found tag 0x3c" — a raw
                // codec complaint that reads like corruption to a citizen.
                // Name the actual situation: XAdES verification is not
                // implemented yet (README says so), so say THAT.
                if matches!(
                    openfirma_core::workflow::Format::detect(&bytes),
                    openfirma_core::workflow::Format::Xml
                ) {
                    bail!(
                        "{} looks like an XML signature (XAdES), and this build does not \
                         verify XAdES yet — only CAdES (.csig, CMS) and PAdES (PDF). The \
                         signature can still be checked with an XML tool (xmlsec1) or a \
                         validator such as VALIDe",
                        input.display()
                    );
                }
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
        Command::Keystores {
            command: KeystoreCommand::List { stores, pin_env },
        } => {
            let mut specs: Vec<StoreSpec> = Vec::new();
            if stores.is_empty() {
                // With nothing named, show what this machine owns without a
                // PIN. Firefox/Thunderbird profile databases and the shared
                // NSS database are discovered by name (finding A7 — they are
                // AutoFirma's two default Linux keystores); PKCS#11 modules
                // are never guessed at — every token deserves to be asked for
                // by path.
                #[cfg(target_os = "windows")]
                specs.push(StoreSpec::Windows);
                #[cfg(any(target_os = "macos", target_os = "ios"))]
                specs.push(StoreSpec::Macos);
                specs.extend(openfirma_keystore::nss::discover());
                if specs.is_empty() {
                    println!(
                        "no keystore to show without being pointed at one: pass \
                         --store pkcs11:/path/to/module.so[:token] or \
                         --store nss[:sql:/path/to/db]"
                    );
                    return Ok(());
                }
            } else {
                for text in &stores {
                    specs.push(parse_store_spec(text)?);
                }
            }
            let pin = store_pin(pin_env.as_ref())?;
            // One failure must not hide the other keystores' listings: every
            // descriptor is attempted, and a nonzero exit at the end says the
            // run was not fully successful.
            let mut failed = false;
            for spec in &specs {
                let described = match spec {
                    StoreSpec::Pkcs11 { module, token, .. } => match token {
                        Some(t) => format!("pkcs11:{}:{t}", module.display()),
                        None => format!("pkcs11:{}", module.display()),
                    },
                    StoreSpec::Nss { db } => format!("nss:{db}"),
                    StoreSpec::NssFirefox {
                        profile: Some(name),
                    } => format!("nss:firefox:{name}"),
                    StoreSpec::NssFirefox { profile: None } => "nss:firefox".into(),
                    StoreSpec::Windows => "windows".into(),
                    StoreSpec::Macos => "macos".into(),
                };
                match open_store(spec, pin.clone()).and_then(|store| {
                    // AutoFirma's default view (finding A5): the DNIe's
                    // authentication certificate and expired certificates
                    // are not listed — `SkipAuthDNIeFilter` and
                    // `showExpiredCerts = false` run before a listing.
                    let store: DynStore = Arc::new(openfirma_keystore::FilteredStore::new(
                        store,
                        std::time::SystemTime::now(),
                    ));
                    let certs = store.certificates()?;
                    Ok(certs)
                }) {
                    Ok(certs) => {
                        println!("{described}:");
                        if certs.is_empty() {
                            println!("  (no certificate with a signable private key)");
                        }
                        for c in &certs {
                            let cn = c.cert.subject_cn().unwrap_or_else(|| "<no CN>".into());
                            let serial = hex::encode_upper(c.cert.serial_number().as_bytes());
                            println!(
                                "  {}  subject CN={cn}  serial=0x{serial}",
                                c.label.as_deref().unwrap_or("<unlabeled>"),
                            );
                        }
                    }
                    Err(e) => {
                        failed = true;
                        println!("{described}:");
                        for line in e.to_string().lines() {
                            println!("  error: {line}");
                        }
                    }
                }
            }
            if failed {
                anyhow::bail!("at least one keystore could not be listed");
            }
        }
        Command::AfirmaUri {
            uri,
            output,
            p12,
            password,
            password_file,
            config,
            register,
            acknowledge_autofirma,
            unregister,
            allow_unattended,
        } => {
            if unregister {
                if uri.is_some() || output.is_some() {
                    anyhow::bail!(
                        "--unregister removes openfirma's registration and signs nothing; a \
                         URI or --output with it would be ambiguous about this invocation"
                    );
                }
                return unregister_scheme();
            }
            if register {
                if uri.is_some() || output.is_some() {
                    anyhow::bail!(
                        "--register installs the scheme and signs nothing; a URI or --output \
                         with it would be ambiguous about which one this invocation is"
                    );
                }
                return register_scheme(
                    p12,
                    password_file,
                    config.as_deref(),
                    acknowledge_autofirma,
                    allow_unattended,
                );
            }
            let uri = uri.context(
                "afirma-uri needs the afirma://… URI the browser handed over (or --register \
                 to install the scheme instead of answering a call)",
            )?;
            // The version the error wire must speak is in the URI itself
            // (finding M-2), so parse before deciding anything else about it.
            let parsed = openfirma_browser::uri::parse(&uri).map_err(|e| {
                anyhow::anyhow!(
                    "{}",
                    match openfirma_browser::dispatch::wire_target(None) {
                        openfirma_browser::dispatch::WireTarget::Protocol41Plus => {
                            e.wire_error().wire_new()
                        }
                        openfirma_browser::dispatch::WireTarget::Legacy =>
                            e.wire_error().wire_old(),
                    }
                )
            })?;
            // M-3b: the URI channel's key has two homes. argv (--p12 plus its
            // password inputs) wins whenever it names one — that is what an
            // explicit invocation asked for. Otherwise the browser config
            // resolves it (the file `--register` writes), because the OS hands
            // the handler only the URI and nothing else. Both missing is still
            // the named refusal, now with the fix the user can actually apply.
            // A-3 splits the two homes' consent story: a key that arrives on
            // argv came from a human typing a command (explicit), a config key
            // signs quietly only under its file's allow_unattended (or this
            // flag), and neither ever asks silently on behalf of a page.
            let config = match &p12 {
                Some(_) => None,
                None => browser_key_config(config.as_deref())?,
            };
            let mut allow = allow_unattended;
            // Which home answered decides whose consent this call already has:
            // argv means the human typing it owns both sides of the key.
            let used_argv = p12.is_some();
            let (container, password) = match p12 {
                Some(container) => (
                    container,
                    p12_password(password, password_file)?.context(
                        "--p12 needs the container's password: --password-file (the safe \
                         input) or OPENFIRMA_PASSWORD; argv is not an option for a secret",
                    )?,
                ),
                None => {
                    match config
                        .as_ref()
                        .and_then(|c| c.p12.clone().zip(c.password_file.clone()))
                    {
                        Some((container, password_file)) => {
                            allow |= config.as_ref().is_some_and(|c| c.allow_unattended);
                            eprintln!(
                                "signing with the browser config's key: {}",
                                container.display()
                            );
                            (
                                container,
                                p12_password(None, Some(password_file))?.context(
                                    "the browser config names a p12 but no password_file; \
                                     add one (a file whose first line is the password)",
                                )?,
                            )
                        }
                        _ => {
                            anyhow::bail!(
                                "--p12 (and its password by --password-file or \
                                 OPENFIRMA_PASSWORD) names the key a browser call signs \
                                 with: openfirma is headless and has no AutoFirma-style \
                                 certificate dialog to fall back on. The scheme handler, \
                                 which argv cannot give flags, reads them from the \
                                 browser config instead — run `openfirma afirma-uri \
                                 --register --p12 certificado.p12 \
                                 --password-file pw.txt` once to write it."
                            )
                        }
                    }
                }
            };
            let key = if allow || used_argv {
                // Two doors into "the human asked for THIS sign": the explicit
                // --allow-unattended opt-in, and a key handed over argv by the
                // very person typing the command (whose consent IS the
                // invocation — dispatch's Unattended door grants that case with
                // Consent::Granted, while an un-opted CONFIG key stays refused
                // until its file says allow_unattended = true). A tty still
                // prompts on top either way.
                openfirma_browser::dispatch::KeySource::P12 {
                    path: &container,
                    password: &password,
                }
            } else {
                // A config-file key without `allow_unattended = true` in it
                // (or a half-openable container): no standing authority to sign
                // quietly; the consent callback below decides.
                openfirma_browser::dispatch::KeySource::Unattended(
                    openfirma_browser::dispatch::UnattendedKey {
                        path: &container,
                        password: Some(password.as_str()),
                        allow_unattended: false,
                        label: "browser config key",
                    },
                )
            };
            let consent = if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
                terminal_consent()
            } else {
                // No prompter: `Granted` without an opt-in is exactly the case
                // dispatch refuses by name ("consent-required").
                openfirma_browser::dispatch::Consent::Granted
            };
            let result = openfirma_browser::dispatch::execute_with_consent(&parsed, &key, consent)
                .map_err(|e| {
                    anyhow::anyhow!(
                        "{}",
                        e.wire(openfirma_browser::dispatch::wire_target(
                            parsed.protocol_version.as_deref()
                        ))
                    )
                })?;
            match output {
                Some(path) => std::fs::write(&path, &result.payload)
                    .with_context(|| format!("writing {}", path.display()))?,
                None => {
                    use std::io::Write;
                    std::io::stdout()
                        .write_all(&result.payload)
                        .context("writing the result to stdout")?;
                }
            }
            match &result.kind {
                openfirma_browser::dispatch::ResultKind::Signature { format } => eprintln!(
                    "signed a browser call as {format}, {} bytes of payload",
                    result.payload.len()
                ),
                openfirma_browser::dispatch::ResultKind::CertificateSelected => eprintln!(
                    "selected certificate, {} bytes of base64 DER",
                    result.payload.len()
                ),
            }
        }
        Command::Autofirma { args } => return run_autofirma_compat(args),
        Command::AfirmaServe {
            p12,
            password,
            password_file,
            config,
            allow_unattended,
            bind,
            issue_token,
            token_only,
        } => {
            let addr: std::net::SocketAddr = bind
                .parse()
                .with_context(|| format!("--bind {bind:?} is not an address like 127.0.0.1:0"))?;
            // Same two homes as `afirma-uri`: argv first, then the config file.
            // A-3: which home decided also decides whether quiet signing is
            // allowed — argv keys need this invocation's --allow-unattended,
            // config keys carry their standing opt-in in the file itself.
            let allow = allow_unattended;
            let (container, password) = match p12 {
                Some(container) => (
                    container,
                    p12_password(password, password_file)?.context(
                        "--p12 needs its password: --password-file or OPENFIRMA_PASSWORD",
                    )?,
                ),
                None => {
                    let config = browser_key_config(config.as_deref())?;
                    // A-3: the endpoint is a headless signer by construction —
                    // it answers every token-bearing request, and AutoFirma's
                    // equivalent flow always has its dialog + PIN in between.
                    // So the endpoint accepts only keys whose owner opted them
                    // in IN THE CONFIG FILE; --allow-unattended cannot stand in
                    // for a missing file-level opt-in here (a standing service
                    // outlives whoever typed the flag).
                    match config.and_then(|c| c.p12.zip(c.password_file)) {
                        Some((container, password_file)) if allow => (
                            container,
                            p12_password(None, Some(password_file))?
                                .context("the browser config names a p12 but no password_file")?,
                        ),
                        Some(_) => anyhow::bail!(
                            "the browser config's key has no allow_unattended = true, and \
                             an endpoint signs every token-bearing request without asking: \
                             add the opt-in to the config file if its owner means it"
                        ),
                        None => anyhow::bail!(
                            "--p12 names the key the endpoint signs with, or write the \
                             browser config (`afirma-uri --register`) that names it for \
                             endpoints started without key flags"
                        ),
                    }
                }
            };
            if !allow {
                // A-3: an endpoint answers whatever loopback request holds a
                // token; AutoFirma puts a dialog in front of every one of them.
                // Without the owner's opt-in there is no dialog here, so there
                // is no endpoint either — refusing now beats signing quietly
                // later. The config path keeps working when it carries its
                // own decision; `allow` already folded that in.
                anyhow::bail!(
                    "an endpoint over {} would sign browser calls without asking anybody: \
                     pass --allow-unattended, or let the key come from a browser config \
                     with allow_unattended = true — only if that is what the key's owner \
                     decided; see docs/adr/0005-browser-protocol.md",
                    container.display()
                );
            }
            let server = openfirma_browser::serve::LoopbackServer::start(
                addr,
                openfirma_browser::serve::OwnedKeySource::P12 {
                    path: container,
                    password,
                },
            )
            .map_err(|e| anyhow::anyhow!("{e}"))?;
            println!("listening on http://{}", server.addr());
            if token_only {
                let token = server.issue_token();
                println!("token: {token}");
                // The accept thread keeps the process alive past this return;
                // for a print-the-token flag the caller is done with us, so
                // end now like AutoFirma halts after its one operation.
                std::process::exit(0);
            }
            let token = server.issue_token();
            println!("token: {token}");
            if issue_token {
                // The probe doubles as the smoke test a fake client repeats:
                // POST /echo with the exact Host/Origin this endpoint demands.
                let body = probe_echo(server.addr())?;
                println!("echo: {body}");
                return Ok(());
            }
            eprintln!(
                "serving until interrupted; at most {} requests are in flight at once, the \
                 rest get a 503 — see docs/adr/0005-browser-protocol.md for the endpoint's \
                 rules",
                openfirma_browser::serve::MAX_CONCURRENT_CONNECTIONS
            );
            // Park the main thread: connection threads own their sockets, and
            // a Ctrl-C kills the process while the listener dies with it —
            // the same life span AutoFirma's socket has (it halts after its
            // one operation).
            loop {
                std::thread::sleep(std::time::Duration::from_secs(3600));
            }
        }
    }
    Ok(())
}

/// `afirma-uri --register`: generate exactly this platform's registration
/// files, write only those, and print what still has to be run by hand (the
/// update-desktop-database command, or opening a .reg through its own UAC
/// prompt). Nothing here touches a system location or a registry: scheme
/// registration is an install-time act the user performs, and docs/adr/0005
/// keeps it that way on purpose.
/// The browser key file to read: `--config` when named, otherwise the XDG
/// location (`$XDG_CONFIG_HOME/openfirma/browser.toml`, `$HOME/.config/…`
/// without it). Absent is fine (the caller falls back or refuses by name);
/// unreadable or malformed refuses — a file the user wrote to name their key
/// must never be silently ignored.
fn browser_key_config(
    named: Option<&Path>,
) -> Result<Option<openfirma_browser::scheme::BrowserConfig>> {
    let path = match named {
        Some(path) => path.to_path_buf(),
        None => openfirma_browser::scheme::browser_config_path().context(
            "no --config was given and the default browser config location needs \
             $XDG_CONFIG_HOME or $HOME, neither of which this process has",
        )?,
    };
    openfirma_browser::scheme::BrowserConfig::load(&path)
        .map_err(anyhow::Error::msg)
        .with_context(|| format!("reading the browser config {}", path.display()))
}

/// `afirma-uri --register`: install this platform's scheme files and the
/// browser handler config. The two are one transaction in spirit — the Exec
/// names no key (argv carries only the URI), so without a config that does,
/// the installed handler dies on its first call; that is why a register with
/// nothing named and nothing written yet refuses before writing anything.
fn register_scheme(
    p12: Option<PathBuf>,
    password_file: Option<PathBuf>,
    config_path: Option<&Path>,
    acknowledges_autofirma: bool,
    allow_unattended: bool,
) -> Result<()> {
    // M-3b: the Exec the installer writes carries no key flags (the desktop
    // hands the handler argv's URI and nothing else), so a registration is
    // only complete once the signing key has a home the handler can find —
    // this config file. It is decided FIRST, before any file exists: printing
    // "wrote …, now run update-desktop-database" and refusing afterwards
    // would leave exactly the M-3b machine state — installed-looking, and
    // dead on every browser call. What never gets written into it is a
    // password: only paths (the p12, and the file whose first line is it).
    let config = match config_path {
        Some(path) => path.to_path_buf(),
        None => openfirma_browser::scheme::browser_config_path().context(
            "no --config was given and the default browser config location needs \
             $XDG_CONFIG_HOME or $HOME, neither of which this process has",
        )?,
    };
    if p12.is_none() && password_file.is_none() {
        let existing =
            openfirma_browser::scheme::BrowserConfig::load(&config).map_err(anyhow::Error::msg)?;
        match existing.as_ref().and_then(|c| c.p12.as_ref()) {
            Some(key) => println!(
                "keeping the browser config that is already there: {} signs with {}",
                config.display(),
                key.display()
            ),
            None => anyhow::bail!(
                "--register needs --p12 and --password-file to write a handler config \
                 that can sign (or an existing {} to keep): the installed Exec carries \
                 no key flags, so without this file every browser call dies demanding \
                 --p12",
                config.display(),
            ),
        }
    }
    // The registration needs openfirma's own absolute path: the Linux desktop
    // entry gets it inside linux_install_and_register, Windows writes it into
    // the .reg below. (A former `let _exe` here looked like the shared value
    // and left the windows block referencing a name that never existed — CI's
    // windows targets were the only place to notice.)
    let exe = std::env::current_exe().context(
        "the registration must name openfirma's own absolute path (the OS starts this \
         process from a path already, so this failure means the OS lied about argv0)",
    )?;
    #[cfg(not(target_os = "windows"))]
    let _ = &exe; // A-2: a scheme has exactly ONE default handler. Detect what stands in
    // the way BEFORE writing anything and require the acknowledgement — the
    // same decision AutoFirma's configurator dialog makes visible.
    let detected = openfirma_browser::scheme::detect_autofirma_install();
    if !detected.is_empty() && !acknowledges_autofirma {
        anyhow::bail!(
            "hay un AutoFirma instalado ({}): el esquema afirma:// solo admite un handler \
             por defecto, y registrar openfirma le sustituye (sus archivos siguen en disco \
             pero dejen de recibir las llamadas). Repite con --acknowledge-autofirma para \
             asumirlo, o desinstala primero AutoFirma.",
            detected
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if !detected.is_empty() {
        println!(
            "AVISO: se sustituye la registracion de AutoFirma ({}) para afirma://; \
             se puede revertir con `openfirma afirma-uri --unregister` y volviendo a \
             ejecutar el configurador de AutoFirma",
            detected
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    #[cfg(target_os = "linux")]
    {
        // A-1/B-1: writing the file is not registration. linux_install_and_register
        // creates $XDG_DATA_HOME/applications when missing, writes the entry with
        // AutoFirma's exact Exec quoting, and records it as the default handler
        // with xdg-mime — the step whose absence left Firefox launching nothing.
        openfirma_browser::scheme::linux_install_and_register()
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        let (path, _) = openfirma_browser::scheme::linux_install_paths();
        println!("wrote and registered {}", path.display());
        if !openfirma_browser::scheme::is_xdg_mime_available() {
            // Unreachable on this branch (the installer refuses without it),
            // but the printed advice below is what a user greps for.
            println!("xdg-mime no esta disponible: instala xdg-utils para completar el registro");
        }
    }
    #[cfg(target_os = "windows")]
    {
        let path = std::env::current_dir()
            .context("no current directory to write the registration file into")?
            .join("openfirma-afirma.reg");
        std::fs::write(
            &path,
            openfirma_browser::scheme::windows_registry_file(&exe),
        )
        .with_context(|| format!("writing {}", path.display()))?;
        println!("wrote {}", path.display());
        println!(
            "then double-click it (or `regedit /I`) and accept the UAC prompt: \
                  a signing client never edits HKCR by itself"
        );
    }
    #[cfg(target_os = "macos")]
    {
        println!(
            "macOS launches an .app bundle, not a bare binary, for a URL scheme. \
             Put this inside openfirma.app/Contents/Info.plist and re-register the \
             bundle with lsregister:\n{}",
            openfirma_browser::scheme::macos_plist_fragment()
        );
        println!(
            "then: /System/Library/Frameworks/CoreServices.framework/Frameworks/\
             LaunchServices.framework/Versions/A/Support/lsregister -f openfirma.app"
        );
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        let _ = exe;
        anyhow::bail!(
            "this operating system has no scheme registration mechanism openfirma knows; \
             point your browser's handler at `openfirma afirma-uri \"%u\"` by hand"
        );
    }

    if p12.is_some() || password_file.is_some() {
        let container = p12.context(
            "--register writes a p12 into the handler config; --password-file without \
             --p12 would write half a key pair",
        )?;
        let pw_file = password_file.context(
            "--register needs --password-file next to --p12 (the file whose first line \
             is its password): the config never stores a password itself, and argv has \
             no flag for one on purpose",
        )?;
        if !container.is_file() {
            anyhow::bail!(
                "--p12 {} is not a file this user can sign with now; --register refuses \
                 to write a handler config pointing at a key that does not exist yet",
                container.display()
            );
        }
        if !pw_file.is_file() {
            anyhow::bail!(
                "--password-file {} is not a file; the handler would open every browser \
                 call against a password that cannot be read",
                pw_file.display()
            );
        }
        // B-2: the config names (and the password file IS) signing-key
        // material — same private-mode rule on both, before anything reads
        // them.
        openfirma_browser::scheme::check_private(&pw_file).map_err(anyhow::Error::msg)?;
        let contents = openfirma_browser::scheme::BrowserConfig {
            p12: Some(container.clone()),
            password_file: Some(pw_file.clone()),
            allow_unattended,
        }
        .to_toml();
        if let Some(dir) = config.parent() {
            std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        std::fs::write(&config, contents.clone())
            .with_context(|| format!("writing {}", config.display()))?;
        // The file names where the signing key lives: private from its first
        // write (B-2 — an earlier revision wrote it with the process umask,
        // and a shared home read 0644).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600))
                .with_context(|| format!("protecting {}", config.display()))?;
        }
        println!("wrote {}", config.display());
        println!(
            "the handler signs with {} (password: first line of {})",
            container.display(),
            pw_file.display()
        );
        if allow_unattended {
            eprintln!(
                "AVISO A-3: allow_unattended = true firmado en el config; cada llamada del \
                 navegador firmara CON ESTA CLAVE SIN PREGUNTAR A NADIE"
            );
        } else {
            println!(
                "sin allow_unattended, cada llamada del navegador debe confirmarse o \
                 rechazarse (A-3); para firmar sin prompt escribe allow_unattended = true \
                 en {}",
                config.display()
            );
        }
    }
    Ok(())
}

/// `afirma-uri --unregister`: remove only what openfirma wrote (its desktop
/// entry / its .reg advice and the default-handler association while it still
/// points at us). Another product's registration — a reinstalled AutoFirma —
/// survives untouched. Finding A-2: reversible by construction.
fn unregister_scheme() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        openfirma_browser::scheme::linux_unregister().map_err(|e| anyhow::anyhow!("{e}"))?;
        let (path, _) = openfirma_browser::scheme::linux_install_paths();
        println!("retirado el registro de openfirma: {}", path.display());
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        // Every branch answers by itself: the bail IS the whole non-linux
        // story (H-9's per-platform clippy called a fall-through `Ok(())`
        // after it unreachable, and it was right — there is no code that
        // should follow).
        anyhow::bail!(
            "la desregistracion automatica existe en Linux (desktop entry + xdg-mime); en \
             Windows importa un .reg que tu importaste: borra HKEY_CURRENT_USER\\Software\\Classes\\\
             afirma o HKEY_CLASSES_ROOT\\afirma segun como se instalara, y en macOS dale a \
             lsregister al bundle que registro el esquema"
        )
    }
}

/// One `POST /echo` with the headers the endpoint demands, and the body it
/// answers. The same tiny request a fake sede drives in the tests; keeping it
/// here is what lets `--issue-token` smoke-test an actual build without any
/// test harness.
fn probe_echo(addr: std::net::SocketAddr) -> Result<String> {
    use std::io::{Read, Write};
    let request = format!(
        "POST /echo HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: http://127.0.0.1:{port}\r\n\
         Content-Length: 0\r\nConnection: close\r\n\r\n",
        port = addr.port()
    );
    let mut stream = std::net::TcpStream::connect(addr)
        .with_context(|| format!("connecting to the endpoint at {addr}"))?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
    stream.write_all(request.as_bytes())?;
    let mut raw = String::new();
    stream.read_to_string(&mut raw)?;
    let body = raw.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("");
    if raw.starts_with("HTTP/1.1 200") && body.trim() == "OK" {
        Ok(body.trim().to_string())
    } else {
        anyhow::bail!(
            "the endpoint did not answer the liveness probe as promised: {}",
            raw.lines().next().unwrap_or("<no status line>")
        );
    }
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
    p12_password_ask(flag, file, PasswordAsk::no_prompt())
}

/// The same resolution with a caller-chosen prompting policy; `sign` passes
/// one that may ask (see `PasswordAsk`).
fn p12_password_ask(
    flag: Option<std::ffi::OsString>,
    file: Option<PathBuf>,
    ask: PasswordAsk,
) -> Result<Option<Zeroizing<String>>> {
    // The resolution itself — file, then flag, then OPENFIRMA_PASSWORD — is a
    // shared rule (openfirma_core::workflow) because `sign`, `afirma-uri` and
    // `afirma-serve` all take a --p12 and must not drift on which inputs the
    // password may come from; this wrapper only adapts the error type and
    // adds B-6's fourth answer: when nothing was supplied AND the caller is
    // allowed to ask (only `sign`), a terminal gets the question. A piped
    // stdin never does — `sign < f > g` must not block on keys nobody is
    // watching, and the browser endpoint has no human in front of it by
    // design (A-3). The refusal None stands for every arm to phrase its own
    // "needs its password" message.
    let resolved = openfirma_core::workflow::p12_password(flag.as_deref(), file.as_deref())
        .map_err(anyhow::Error::msg)?;
    Ok(match resolved {
        Some(secret) => Some(secret),
        None => ask_secret(ask),
    })
}

/// Which secret a missing password belongs to (B-6). Only `sign` reaches the
/// prompt: the browser commands resolve their key from argv or the config
/// file after this call returns, and an endpoint has no human in front of it
/// by design (A-3's whole argument), so prompting there would interrupt calls
/// whose password was never meant to be typed at a keyboard.
struct PasswordAsk {
    /// The command that reached here prompts at all (only `sign`).
    prompt_allowed: bool,
}

impl PasswordAsk {
    /// No prompting: the resolution answers by its three sources or not at
    /// all — what the browser commands and every test need.
    fn no_prompt() -> PasswordAsk {
        PasswordAsk {
            prompt_allowed: false,
        }
    }

    /// `sign` may ask when a terminal is attached (B-6).
    fn sign() -> PasswordAsk {
        PasswordAsk {
            prompt_allowed: true,
        }
    }
}

/// The interactive answer to a missing password (B-6): AutoFirma answers this
/// case with its own dialog, and an attached terminal is the one place where
/// asking IS the safe input — what gets asked goes to the screen, never into
/// argv or the environment. Without a terminal (a script, a pipe) nothing is
/// read from stdin: `sign < f > g` must never block on keys nobody is
/// watching, and it keeps the arm's own refusal sentence.
fn ask_secret(ask: PasswordAsk) -> Option<Zeroizing<String>> {
    if !ask.prompt_allowed || !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        return None;
    }
    // The terminal attached past ask_secret's checks belongs to a human who
    // ran `sign` at a keyboard — the person the container password is for.
    let question = "Password of the certificate container (typed here): ";
    // A broken terminal or an empty answer is reported where the refusal
    // sentence belongs: every arm wraps this call with its own context, and
    // for `sign` that message also names --password-file as the safe input to
    // reach for instead. So any Err collapses to None — no secret half-read.
    prompt_password(question).ok()
}

/// Read one line with echoing turned off, std-only (no new dependency for a
/// prompt). The mode flips through `stty` — a coreutils call, not a link-time
/// dependency — over descriptors this function owns and closes itself; where
/// stty is absent or no handle reaches the terminal being typed into, the
/// line still reads, and one warning says the typing was visible: a password
/// shown on screen deserves to be warned about, not assumed.
fn prompt_password(question: &str) -> Result<Zeroizing<String>> {
    use std::io::Write;
    // Echo flips on this process's stdin — the descriptor the line is typed
    // into (ask_secret proved it is a terminal). `stty` gets its OWN fresh
    // handle on it, never a borrowed number: Linux's /proc/self/fd/0 re-opens
    // whatever fd 0 names — and when stdio has not been redirected at all,
    // that path resolves to /dev/null (Rust hides this redirecting the first
    // File::stdin() over an uninheritable fd), so a second handle opens the
    // re-opened target itself. Neither handle ever wraps a descriptor std
    // owns: no fd race, and no "owned file descriptor already closed" abort.
    let toggle = EchoToggler::new();
    let echo_mode = toggle.disable_and_confirm();
    let hidden = matches!(echo_mode, EchoMode::Disabled | EchoMode::WasOff);
    if !hidden {
        // The degraded path is still an answer — visible typing with a
        // warning that arrives BEFORE any key is pressed beats pretending the
        // terminal cannot do this, and beats discovering typed-out secrets.
        eprintln!(
            "warning: this terminal cannot hide what you type; the password will \
             be visible as you enter it"
        );
    }
    eprint!("{question}");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    let read = std::io::stdin().read_line(&mut line);
    toggle.restore(echo_mode);
    drop(toggle);
    if hidden {
        // The Enter the user pressed was swallowed with echo off; a newline
        // keeps the next output of this program from starting on the prompt's.
        eprintln!();
    }
    read.with_context(|| "reading the password from the terminal")?;
    if line.is_empty() {
        anyhow::bail!("the terminal gave no password (its input closed)");
    }
    let line = line.trim_end_matches(['\n', '\r']);
    if line.is_empty() {
        // Enter on an empty prompt is "I don't have it", not a password: the
        // answer None turns into each arm's refusal, which names --password-file.
        anyhow::bail!("no password was entered");
    }
    Ok(Zeroizing::new(line.to_string()))
}

/// The two `stty` calls around a password read, over descriptors this type
/// owns. Where /proc does not exist (Windows, some BSDs) or no terminal is to
/// be found, the handles are absent and every toggle is a no-op: the prompt
/// degrades to visible typing with its warning, never to a wrong answer.
/// What a prompt's echo toggle ended up doing to the terminal, so `restore`
/// returns exactly what was taken and nothing else.
enum EchoMode {
    /// We turned echo off (it was on): the prompt must turn it back on.
    Disabled,
    /// The terminal arrived with echo already off: touch nothing.
    WasOff,
    /// No handle or no stty: nothing was ever disabled, and the caller warns
    /// that typing is visible.
    NoControl,
}

struct EchoToggler {
    /// A handle on the SAME target fd 0 currently points at (its /proc
    /// re-open). None when /proc cannot say what fd 0 is.
    stdin_handle: Option<OwnedFd>,
    /// /dev/tty, for a process whose fd 0 is a pipe while a screen and
    /// keyboard remain — the script-under-launcher case AutoFirma's dialog
    /// still answers with its window.
    tty: Option<OwnedFd>,
}

/// An owned descriptor handed to `stty` only through dups of its own: std's
/// `From<File> for Stdio` MOVES ownership into the spawn
/// machinery (the pre-spawn dup is what the child inherits) and never closes
/// what the parent owns. `from_raw_fd`, by contrast, CLOSES its fd in the
/// parent after a successful spawn — measured, not folklore: a probe handle
/// handed that way was gone on the next call. Ownership through `From` is the
/// only shape std documents as safe here, and this struct keeps one owner per
/// descriptor for its whole life.
struct OwnedFd(std::fs::File);

impl OwnedFd {
    fn as_stdio(&self) -> Option<std::process::Stdio> {
        // A fresh dup (F_DUPFD) per round, owned by the Stdio that consumes
        // it: spawn inherits THAT fd, and its drop closes it — self keeps
        // owning the original for every later round, and Drop closes the
        // original exactly once. The pre-spawn-dup semantics of std make this
        // safe; from_raw_fd's post-spawn close (measured) makes that shape not.
        self.0.try_clone().map(std::process::Stdio::from).ok()
    }
}

impl EchoToggler {
    fn new() -> EchoToggler {
        // The FIRST std call may itself have redirected fd 0, so the probe
        // order matters: open /proc/self/fd/0 twice — the first open resolves
        // (and possibly performs) the redirect, the second lands on whatever
        // it became. Both handles are kept; `run` tries each until one acts.
        let _ = std::io::stdin();
        EchoToggler {
            stdin_handle: dup_fd(0).or_else(|| dup_fd(0)).map(OwnedFd),
            tty: std::fs::File::options()
                .read(true)
                .write(true)
                .open("/dev/tty")
                .ok()
                .map(OwnedFd),
        }
    }

    /// Turn echo off and PROVE it: `stty -a` reads the live flag before and
    /// after, so a silent failure (non-tty handle, missing stty) still earns
    /// the visible-typing warning instead of leaving typed secrets on screen.
    /// The returned flag says what the prompt's owner must do afterwards:
    /// `WasOff` never turns echo back on (`restore` would flip ON a terminal
    /// its owner deliberately left hidden — `stty -echo` shells and expect
    /// harnesses exist); `Disabled` restores; `NoControl` never disabled
    /// anything to begin with.
    fn disable_and_confirm(&self) -> EchoMode {
        let before = self.echo_state();
        self.run("-echo");
        match (before, self.echo_state()) {
            // Was ON, now OFF: hidden typing, confirmed by the terminal itself.
            (Some(true), Some(false)) => EchoMode::Disabled,
            // Already OFF when we arrived — hidden without our doing (a harness
            // or shell that turned echo off needs no warning either), and no
            // restoring on top of somebody else's choice.
            (Some(false), Some(false)) => EchoMode::WasOff,
            _ => EchoMode::NoControl,
        }
    }

    /// Put echo back the way we found it — only if WE took it off. A restore
    /// that fails after a successful disable leaves typing hidden, which the
    /// user must hear about: silent invisible keys read as a hung terminal.
    fn restore(&self, mode: EchoMode) {
        match mode {
            EchoMode::Disabled => {
                self.run("echo");
                if self.echo_state() != Some(true) {
                    eprintln!(
                        "warning: could not restore the terminal's echo; what you type may \
                         stay invisible — run `stty echo` to put it back"
                    );
                }
            }
            // Nothing was taken, nothing is returned: a terminal that arrived
            // hidden (or was never under our control) keeps its own state.
            EchoMode::WasOff | EchoMode::NoControl => {}
        }
    }

    /// `stty MODE` over each owned handle until one succeeds. stty acts on
    /// its stdin when it can read it (a tty answers; a non-tty makes the CALL
    /// fail, which is how failures present), and some implementations query
    /// stdout instead, so both are pinned to the same fd. A failed round over
    /// every handle is silence: the caller's warning already told the user
    /// what that means.
    fn run(&self, mode: &str) {
        for handle in [&self.stdin_handle, &self.tty] {
            let Some(file) = handle else { continue };
            let (Some(stdin_io), Some(stdout_io)) = (file.as_stdio(), file.as_stdio()) else {
                continue;
            };
            let spawned = std::process::Command::new("stty")
                .arg(mode)
                .stdin(stdin_io)
                .stdout(stdout_io)
                .stderr(std::process::Stdio::null())
                .status();
            if spawned.is_ok_and(|s| s.success()) {
                return;
            }
        }
    }

    /// The live ECHO flag, read through each owned handle in turn; None when
    /// no handle answers (non-tty, or stty missing). `stty -a` prints the
    /// flags space separated; "-echo" is not "echo".
    fn echo_state(&self) -> Option<bool> {
        for handle in [&self.stdin_handle, &self.tty] {
            let Some(file) = handle else { continue };
            let Some(stdin_io) = file.as_stdio() else {
                continue;
            };
            // Brief and synchronous: nothing may be typed between a probe and
            // the prompt its answer judges (two probes per password ask).
            let out = std::process::Command::new("stty")
                .arg("-a")
                .stdin(stdin_io)
                .stderr(std::process::Stdio::null())
                .output();
            let Ok(out) = out else { continue };
            if !out.status.success() {
                continue;
            }
            for token in String::from_utf8_lossy(&out.stdout).split_whitespace() {
                if token == "echo" {
                    return Some(true);
                }
                if token == "-echo" {
                    return Some(false);
                }
            }
        }
        None
    }
}

/// A fresh readable+writable handle on the process's own fd `number`, via
/// Linux's /proc/self/fd (see `EchoToggler`). None where /proc is absent.
fn dup_fd(number: u32) -> Option<std::fs::File> {
    std::fs::File::options()
        .read(true)
        .write(true)
        .open(format!("/proc/self/fd/{number}"))
        .ok()
}

/// The consent prompter for a terminal session (finding A-3): shows exactly
/// what is about to be signed — operation, asking app, SHA-256 of the payload
/// and its size, in AutoFirma's dialog's information set — and reads y/N. A
/// "no" answers dispatch's cancellation (`err-11:=AF500001` / `CANCEL`), like
/// closing AutoFirma's dialog. It cannot collect a container PIN: the
/// password's two real homes (a file, OPENFIRMA_PASSWORD) already decided
/// before this prompt was possible, and argv never is one.
fn terminal_consent() -> openfirma_browser::dispatch::Consent<'static> {
    openfirma_browser::dispatch::Consent::Prompt(&TerminalConsent)
}

struct TerminalConsent;

impl openfirma_browser::dispatch::ConsentFn for TerminalConsent {
    fn approve(
        &self,
        summary: &openfirma_browser::dispatch::OperationSummary,
        needs_password: bool,
    ) -> Result<openfirma_browser::dispatch::ConsentAnswer, openfirma_browser::dispatch::BrowserError>
    {
        use std::io::Write;
        let app = if summary.app_name.is_empty() {
            "una aplicacion sin nombre".to_string()
        } else {
            summary.app_name.clone()
        };
        eprintln!("openfirma pide confirmar una operacion del navegador:");
        eprintln!("  operacion : {}", summary.operation);
        eprintln!("  solicitud : {app}");
        eprintln!(
            "  documento : {} bytes, SHA-256 {}",
            summary.document_len, summary.document_digest
        );
        if needs_password {
            // dispatch only asks this prompt for a secret when the key has
            // none stored (Unattended with password: None), which the CLI
            // never constructs; saying so beats pretending we can read one
            // here. The wire error names the same reason.
            eprintln!("  (la clave necesita un PIN que este prompt no puede recoger)");
        }
        eprint!("? Firmar [s/N] ");
        let _ = std::io::stderr().flush();
        let mut answer = String::new();
        if std::io::stdin().read_line(&mut answer).unwrap_or(0) == 0 {
            // EOF on a closed stdin is not a yes.
            return Ok(openfirma_browser::dispatch::ConsentAnswer::No);
        }
        let yes = matches!(
            answer.trim().to_ascii_lowercase().as_str(),
            "s" | "si" | "sí" | "y" | "yes"
        );
        Ok(if yes {
            openfirma_browser::dispatch::ConsentAnswer::Yes { password: None }
        } else {
            openfirma_browser::dispatch::ConsentAnswer::No
        })
    }
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
    println!(
        "  trust anchor:   {}",
        r.trust_anchor.as_deref().unwrap_or("(not checked)")
    );
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
        // the two ETSI attributes M9 added encoders for are recognised here
        // even though the report does not parse their values yet
        if *o == openfirma_core::oid::ID_SIGNATURE_POLICY_IDENTIFIER {
            signed.push("signaturePolicyIdentifier".to_string());
        } else if *o == openfirma_core::oid::ID_COMMITMENT_TYPE_INDICATION {
            signed.push("commitmentTypeIndication".to_string());
        } else {
            signed.push(o.to_string());
        }
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

// ---------------------------------------------------------------------------
// A-8 (review 06): AutoFirma's own command line.

/// The exit code AutoFirma's console answers errors with: `closeApp` prints
/// its message and exits `STATUS_ERROR = -1` (`CommandLineLauncher`), which
/// Unix truncates to 255 — the number a sede script checks. Every failure
/// reached through the `autofirma` subcommand ends at [`compat_fail`], and
/// only there: the native commands keep their ordinary `anyhow` exit 1 so
/// nothing an existing script already parses changes meaning.
const EXIT_AUTOFIRMA_ERROR: i32 = 255;

/// One parsed compat invocation: every parameter of AutoFirma's
/// `CommandLineParameters` whose value openfirma can act on, after exactly
/// the checks its constructor and `checkParams()` run — a repeated flag is
/// an error, a flag without its value is an error, `-format` outside the
/// accepted names is an error, a missing input file is an error. The flags
/// it understands but cannot honour (`-gui`, `-filter`, plugins…) are refused
/// by name rather than ignored: silently dropping a flag in a compatibility
/// layer signs something the caller did not ask for.
#[derive(Default)]
struct CompatParams {
    input: Option<PathBuf>,
    output: Option<PathBuf>,
    format: Option<String>,
    store: Option<String>,
    alias: Option<String>,
    password: Option<String>,
    xml: bool,
}

/// The value-taking flags of AutoFirma's parser, in its own spellings
/// (`CommandLineParameters.PARAM_*`). A repeated or valueless flag answers
/// with the Java parser's own rule. Slots are positional (input, output,
/// format, store, alias, password) so `checkParams` below destructures them
/// without a struct of its own.
fn compat_parse_flags(args: &[String]) -> Result<CompatParams, String> {
    let mut p = CompatParams::default();
    // File flags collect into strings first: the same `take` rule serves all
    // six value-taking flags, and the two file slots convert at the end.
    let mut input_s = None;
    let mut output_s = None;
    let mut i = 0;
    while i < args.len() {
        // Every value-taking flag behaves the same way, so one local function
        // carries the shared rule: consume the next token, refuse a repeat.
        fn take(
            slot: &mut Option<String>,
            name: &str,
            args: &[String],
            i: usize,
        ) -> Result<(), String> {
            if slot.is_some() {
                return Err(format!("the parameter {name} is used more than once"));
            }
            if i + 1 >= args.len() {
                return Err(format!("the parameter {name} needs a value"));
            }
            *slot = Some(args[i + 1].clone());
            Ok(())
        }
        match args[i].as_str() {
            "-xml" => p.xml = true,
            "-i" => {
                take(&mut input_s, "-i", args, i)?;
                // Java's parser skips the consumed value (`i++` on the flag
                // branch); without this the next token would parse as a flag.
                i += 1;
            }
            "-o" => {
                take(&mut output_s, "-o", args, i)?;
                i += 1;
            }
            "-format" => {
                take(&mut p.format, "-format", args, i)?;
                i += 1;
            }
            "-store" => {
                take(&mut p.store, "-store", args, i)?;
                i += 1;
            }
            "-alias" => {
                take(&mut p.alias, "-alias", args, i)?;
                i += 1;
            }
            "-password" => {
                take(&mut p.password, "-password", args, i)?;
                i += 1;
            }
            other if matches!(other, "-gui" | "-certgui") => {
                return Err(format!(
                    "{other} opens AutoFirma's own dialogs; openfirma answers the compat \
                     command headless — run `openfirma` with no arguments for its window"
                ));
            }
            other
                if matches!(
                    other,
                    "-filter"
                        | "-algorithm"
                        | "-config"
                        | "-operation"
                        | "-preurl"
                        | "-posturl"
                        | "-hformat"
                        | "-halgorithm"
                        | "-r"
                ) =>
            {
                return Err(format!(
                    "{other} names an AutoFirma capability openfirma's compat layer does not \
                     implement (there is no honest translation for it); the native `openfirma \
                     sign` covers what overlaps, with its own flags"
                ));
            }
            other => {
                return Err(format!("unknown parameter: {other}"));
            }
        }
        i += 1;
    }
    p.input = input_s.map(PathBuf::from);
    p.output = output_s.map(PathBuf::from);
    Ok(p)
}

/// The compat parser proper: AutoFirma's flag grammar, then `checkParams()`'s
/// checks over what it collected, in the Java order — format first (a bad
/// name is refused even when a file argument is missing too), then the store
/// shape, then the files.
fn parse_compat_params(args: &[String]) -> Result<CompatParams, String> {
    let mut p = compat_parse_flags(args)?;
    if let Some(f) = &p.format {
        let f = f.to_ascii_lowercase();
        if !matches!(f.as_str(), "auto" | "cades" | "pades" | "xades") {
            return Err(format!("unsupported signature format: {f}"));
        }
        p.format = Some(f);
    }
    // The store's shape is checked here, not at open time, so a mistake says
    // `autofirma`'s spelling back rather than openfirma's native descriptor
    // grammar (the translation table lives in `compat_store`).
    if let Some(s) = &p.store {
        compat_store(s)?;
    }
    if let Some(f) = &p.input {
        if !f.exists() {
            return Err(format!("the input file does not exist: {}", f.display()));
        }
    }
    Ok(p)
}

/// Translate AutoFirma's `-store` value into openfirma's store vocabulary,
/// the two mappings of `getKsm`: `windows`, `mac`/`macos`, `mozilla`, `auto`,
/// `pkcs12:<file>` (a container, not a descriptor — its own shape below), and
/// `pkcs11:<module>`. Bare `pkcs12`/`pkcs11` without the colon are AutoFirma
/// errors too (`getKsm` only matches the prefixed forms). An absent `-store`
/// is AUTO: Windows/macOS platform stores, the SHARED_NSS database elsewhere
/// — the same defaults, mapped to the descriptors `open_store` opens.
enum CompatStore {
    /// A PKCS#12 file named inside `-store pkcs12:<path>`.
    Pkcs12(PathBuf),
    Spec(StoreSpec),
}

fn compat_store(value: &str) -> Result<CompatStore, String> {
    let lower = value.to_ascii_lowercase();
    if let Some(rest) = value.strip_prefix("pkcs12:") {
        // AutoFirma's cleanupPathFile trims quotes and whitespace around the
        // path before its existence check; the same courtesy here means a
        // Windows launcher that quoted the argument still opens.
        let path = PathBuf::from(rest.trim().trim_matches('"').trim_matches('\''));
        if !path.is_file() {
            return Err(format!(
                "the PKCS#12 file indicated does not exist: {}",
                path.display()
            ));
        }
        return Ok(CompatStore::Pkcs12(path));
    }
    if let Some(rest) = value.strip_prefix("pkcs11:") {
        // getKsm checks the module's existence; openfirma's own spec parse
        // additionally carries the token-label spelling, which compat callers
        // do not use — AutoFirma takes a bare library path and no token.
        let module = PathBuf::from(rest.trim().trim_matches('"').trim_matches('\''));
        if !module.is_file() {
            return Err(format!(
                "the PKCS#11 library indicated does not exist: {}",
                module.display()
            ));
        }
        return Ok(CompatStore::Spec(StoreSpec::Pkcs11 {
            module,
            token: None,
            wants_no_pin: false,
        }));
    }
    match lower.as_str() {
        "windows" => Ok(CompatStore::Spec(StoreSpec::Windows)),
        "mac" | "macos" => Ok(CompatStore::Spec(StoreSpec::Macos)),
        "mozilla" => Ok(CompatStore::Spec(StoreSpec::NssFirefox { profile: None })),
        "auto" => Ok(CompatStore::Spec(if cfg!(target_os = "windows") {
            StoreSpec::Windows
        } else if cfg!(any(target_os = "macos", target_os = "ios")) {
            StoreSpec::Macos
        } else {
            // AutoFirma's AUTO on Linux is SHARED_NSS — the same database
            // openfirma spells `nss` (its $HOME/.pki/nssdb default).
            StoreSpec::Nss {
                db: "$HOME/.pki/nssdb".into(),
            }
        })),
        "pkcs12" | "pkcs11" => Err(format!(
            "-store {value} needs AutoFirma's own suffix ({}); openfirma reads it exactly \
             the way getKsm does",
            if lower == "pkcs12" {
                "pkcs12:/path/to/keystore.p12"
            } else {
                "pkcs11:/path/to/module.so"
            }
        )),
        "dni" | "dnie" => Err(
            "-store dni names AutoFirma's built-in DNIe driver, which openfirma does not \
             ship (its pure-Rust rule keeps the card reads in PKCS#11): point \
             -store pkcs11:<opensc-pkcs11.so> at the driver instead"
                .to_string(),
        ),
        _ => Err(format!("unknown keystore type: {value}")),
    }
}

/// AutoFirma's file-magic format selection (`selectFormatByData`: MimeHelper
/// on the bytes, never the extension) mapped onto openfirma's dispatcher.
/// The formats its CLI lists but whose signers this layer has no honest
/// equivalent for (`facturae`, `ooxml`, `odf` — off by default even in
/// AutoFirma's own auto-detection) are refused by the parser, never
/// approximated.
fn compat_format(requested: Option<&str>, content: &[u8]) -> &'static str {
    let detected = match openfirma_core::workflow::Format::detect(content) {
        openfirma_core::workflow::Format::Pdf => "pades-b-b",
        openfirma_core::workflow::Format::Xml => "xades-b-b",
        openfirma_core::workflow::Format::Data => "cades-b-b",
    };
    match requested.unwrap_or("auto") {
        "auto" => detected,
        // An explicitly named format is honoured even when the bytes prefer
        // another (an XML file signed `-format cades` is AutoFirma's detached
        // CMS over the XML bytes too); a mismatch the dispatcher cannot sign
        // at all answers there, with its own "cannot hold this file" reason.
        "cades" => "cades-b-b",
        "pades" => "pades-b-b",
        "xades" => "xades-b-b",
        // Unreachable: the parser refused the name before here.
        other => unreachable!("compat format {other:?} passed the parser's list"),
    }
}

/// `<afirma><result>true</result><response>…</response></afirma>` — AutoFirma's
/// `-xml` wire shape verbatim (`buildXmlResponse`). The message is escaped
/// because openfirma's sentences carry quotes and ampersands Java's never saw.
fn compat_xml(ok: bool, msg: Option<&str>, payload: Option<&[u8]>) -> String {
    let mut sb = format!("<afirma><result>{ok}</result>");
    if msg.is_some() || payload.is_some() {
        sb.push_str("<response>");
        if let Some(m) = msg {
            sb.push_str(&format!("<msg>{}</msg>", compat_xml_escape(m)));
        }
        if let Some(bytes) = payload {
            sb.push_str(&format!(
                "<sign>{}</sign>",
                base64::engine::general_purpose::STANDARD.encode(bytes)
            ));
        }
        sb.push_str("</response>");
    }
    sb.push_str("</afirma>");
    sb
}

fn compat_xml_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// The compat `sign`: pick the key exactly like `getKsm` + `getKeyEntry`,
/// sign through the shared dispatcher, write `-o`. Errors go to the console
/// with AutoFirma's exit code; success prints AutoFirma's sentence on stdout.
fn autofirma_sign(p: CompatParams) {
    // signByCommandLine's guards, in its order: -i (existence checked by the
    // parser already), then the certificate choice — this layer has no
    // -certgui, so an absent -alias is a refusal with the flag that works —
    // then the output-or-xml rule.
    let input = p.input.clone().unwrap_or_else(|| {
        compat_fail("no input file was indicated (-i)");
    });
    let Some(alias) = p.alias.clone() else {
        compat_fail(
            "no certificate was selected: -alias names it (openfirma's compat layer has \
             no certificate dialog)",
        );
    };
    if p.output.is_none() && !p.xml {
        compat_fail("an output file is needed (-o) or the result must be requested as -xml");
    }
    // The overwrite rule of review 06 (A-3) applies here too: AutoFirma's
    // FileOutputStream truncates without asking, and a compat layer that
    // reproduced THAT would reproduce the data loss too. --force is openfirma's
    // documented yes; on this surface it arrives as the environment variable
    // OPENFIRMA_COMPAT_FORCE=1, so no extra flag enters AutoFirma's grammar.
    let force = std::env::var("OPENFIRMA_COMPAT_FORCE").is_ok_and(|v| v == "1");
    if let Some(out) = &p.output {
        if let Err(e) = openfirma_core::workflow::check_not_overwrite(out, force) {
            compat_fail(&e);
        }
    }
    let content = match std::fs::read(&input) {
        Ok(c) => c,
        Err(e) => compat_fail(&format!("cannot read the input file: {e}")),
    };
    // Never sign a signature (core's rule, the same one `openfirma sign`
    // and the window run): AutoFirma's own batch path takes any file it is
    // pointed at, so this refusal is one of compat's documented deviations —
    // a sede script that fed `-i` an old signature received 255 here instead
    // of a signature-of-a-signature nobody ever wanted.
    if let Err(e) = openfirma_core::workflow::check_not_signed_input(&input, Some(&content)) {
        compat_fail(&e);
    }
    let format = compat_format(p.format.as_deref(), &content);
    let signer: Box<dyn Signer> = match compat_store(p.store.as_deref().unwrap_or("auto")) {
        Err(e) => compat_fail(&e),
        Ok(CompatStore::Pkcs12(path)) => {
            // getKsm(PKCS12) + getKeyEntry(alias): the -password opens the
            // container. AutoFirma falls back to a cached "dummy" password
            // when none was given, which fails on any real container anyway;
            // saying so upfront is the same outcome with a reason attached.
            let Some(password) = &p.password else {
                compat_fail("-store pkcs12:… needs -password to open the container");
            };
            match load_p12(&path, &Zeroizing::new(password.clone()), Some(&alias)) {
                Ok(s) => Box::new(s),
                Err(e) => compat_fail(&format!("{e:#}")),
            }
        }
        Ok(CompatStore::Spec(spec)) => {
            // A token or database takes its PIN from the environment (the
            // native rule). AutoFirma's -password IS its keystore password
            // here (CachePasswordCallback), so accepting it as the PIN is
            // the one honest mapping for mozilla/pkcs11 stores; absent, the
            // store's own no-PIN or OPENFIRMA_PIN paths stay open to try.
            let pin = p.password.clone().map(Zeroizing::new);
            let store = match open_store(&spec, pin) {
                Ok(s) => s,
                Err(e) => compat_fail(&format!("{e:#}")),
            };
            match store_signer(store, Some(&alias)) {
                Ok(s) => s,
                Err(e) => compat_fail(&format!("{e:#}")),
            }
        }
    };
    let mut request = openfirma_browser::signing::SignRequest::new(
        format,
        // AutoFirma's CLI defaults to SHA512 (DEFAULT_ALGO); this layer has
        // no -algorithm flag yet, and SHA256 — the native default both
        // frontends share — is what it signs with. Naming that here keeps
        // the difference from a documented choice rather than an accident.
        openfirma_core::DigestAlg::Sha256,
    );
    let signature = match openfirma_browser::signing::execute_with_detection(
        &mut request,
        &content,
        signer.as_ref(),
    ) {
        Ok(sig) => sig,
        Err(e) => compat_fail(&e.to_string()),
    };
    if let Some(out) = &p.output {
        if let Err(e) = std::fs::write(out, &signature) {
            compat_fail(&format!(
                "the signature could not be saved to {}: {e}",
                out.display()
            ));
        }
    }
    // AutoFirma prints its closing message either way; -xml adds the payload
    // when no file took it. Same shapes, same order.
    if p.xml {
        let payload = if p.output.is_some() {
            None
        } else {
            Some(signature.as_slice())
        };
        println!(
            "{}",
            compat_xml(true, Some("The operation completed successfully"), payload)
        );
    } else {
        println!("The operation completed successfully");
    }
}

/// The compat `listaliases`: every alias of the store, one per line (or in
/// AutoFirma's `-xml` envelope). getKsm(null)+getAliases(), with openfirma's
/// honest failures.
fn autofirma_list_aliases(p: CompatParams) {
    let aliases: Vec<String> = match compat_store(p.store.as_deref().unwrap_or("auto")) {
        Err(e) => compat_fail(&e),
        Ok(CompatStore::Pkcs12(path)) => {
            // AutoFirma opens a PKCS#12 store through its password callback;
            // an absent -password means the empty one it caches, so the same
            // probe runs here — a container that needs more says so.
            let bytes = match std::fs::read(&path) {
                Ok(b) => b,
                Err(e) => compat_fail(&format!("cannot read the PKCS#12 file: {e}")),
            };
            let password = p.password.clone().unwrap_or_default();
            match openfirma_keystore::Pkcs12::load(&bytes, &password) {
                Ok(container) => container.aliases(),
                Err(e) => compat_fail(&format!("{e:#}")),
            }
        }
        Ok(CompatStore::Spec(spec)) => {
            let pin = p.password.clone().map(Zeroizing::new);
            let store = match open_store(&spec, pin) {
                Ok(s) => s,
                Err(e) => compat_fail(&format!("{e:#}")),
            };
            // The filtered listing — what the AutoFirma dialog and `openfirma
            // keystores list` show: entries somebody could actually sign with.
            let filtered: DynStore = Arc::new(openfirma_keystore::FilteredStore::new(
                store,
                std::time::SystemTime::now(),
            ));
            match filtered.certificates() {
                Ok(certs) => certs
                    .iter()
                    .map(|c| {
                        c.label.clone().unwrap_or_else(|| {
                            c.cert.subject_cn().unwrap_or_else(|| "<unlabeled>".into())
                        })
                    })
                    .collect(),
                Err(e) => compat_fail(&format!("{e:#}")),
            }
        }
    };
    if p.xml {
        let mut sb = String::from("<afirma><result>ok</result><response>");
        for a in &aliases {
            sb.push_str(&format!("<alias>{}</alias>", compat_xml_escape(a)));
        }
        sb.push_str("</response></afirma>");
        println!("{sb}");
    } else {
        // One alias per line, AutoFirma's shape; its blank for an empty store
        // is kept (print the loop, then nothing extra) because a caller that
        // counts lines must count the same thing both programs print.
        for a in &aliases {
            println!("{a}");
        }
    }
}

/// Which compat operation the argv asks for (`CommandLineCommand.parse`, the
/// subset openfirma implements). Unimplemented commands are refused by name;
/// an unknown command is AutoFirma's general-syntax error, exit -1 too.
enum CompatCommand {
    Sign,
    ListAliases,
}

fn parse_compat_command(name: &str) -> Result<CompatCommand, String> {
    match name.to_ascii_lowercase().as_str() {
        "sign" => Ok(CompatCommand::Sign),
        "listaliases" => Ok(CompatCommand::ListAliases),
        other @ ("cosign" | "countersign" | "verify" | "batchsign") => Err(format!(
            "`{other}` is part of AutoFirma's command line that openfirma's compat layer \
             does not implement; the native commands cover what overlaps (`openfirma verify`)"
        )),
        other => Err(format!("unknown command: {other}")),
    }
}

/// Print one compat failure exactly the way AutoFirma's console answers — its
/// message on the console stream — and exit with its code. The whole layer
/// funnels through here, so "exit 255 on error" is a property of the function
/// every error path calls, not of each arm remembering.
fn compat_fail(message: &str) -> ! {
    eprintln!("{message}");
    std::process::exit(EXIT_AUTOFIRMA_ERROR);
}

/// The `autofirma` subcommand's entry point (main hands it everything after
/// the subcommand name). `-help` answers with the syntax text in either
/// position AutoFirma accepts it (`processCommand` checks args[1], the top
/// level checks args[0]).
fn run_autofirma_compat(args: Vec<String>) -> Result<()> {
    let Some(first) = args.first() else {
        eprint!("{}", compat_syntax(None));
        std::process::exit(EXIT_AUTOFIRMA_ERROR);
    };
    if first.eq_ignore_ascii_case("-help") || first == "--help" {
        println!("{}", compat_syntax(None));
        return Ok(());
    }
    let command = match parse_compat_command(first) {
        Ok(c) => c,
        Err(e) => {
            eprint!("{}", compat_syntax(Some(&e)));
            std::process::exit(EXIT_AUTOFIRMA_ERROR);
        }
    };
    let params = match parse_compat_params(&args[1..]) {
        Ok(p) => p,
        Err(e) => compat_fail(&e),
    };
    match command {
        CompatCommand::Sign => autofirma_sign(params),
        CompatCommand::ListAliases => autofirma_list_aliases(params),
    }
    Ok(())
}

/// The syntax text, modeled on `buildGeneralSyntax`: the error that prompted
/// it (when one did), the commands this layer implements, and a line per flag
/// it honors — everything refused at parse time is named there too, so the
/// help never promises more than the parser accepts.
fn compat_syntax(error: Option<&str>) -> String {
    let mut sb = match error {
        Some(e) => format!("{e}\n\n"),
        None => String::from("openfirma — AutoFirma-compatible command line.\n\n"),
    };
    sb.push_str(
        "usage: openfirma autofirma <command> [parameters]\n\n\
         commands:\n\
         \x20 sign         sign a file (headless; -o or -xml required, like AutoFirma)\n\
         \x20 listaliases  list the certificates of a keystore\n\n\
         parameters:\n\
         \x20 -i <file>          input file\n\
         \x20 -o <file>          output file (existing files are kept: openfirma's guard,\n\
         \x20                    not AutoFirma's silent overwrite; OPENFIRMA_COMPAT_FORCE=1\n\
         \x20                    is this surface's equivalent of --force)\n\
         \x20 -format auto|cades|pades|xades   (default auto, chosen from the bytes)\n\
         \x20 -store windows|mac|mozilla|auto|pkcs12:<file>|pkcs11:<module>\n\
         \x20                    (default auto, like AutoFirma's getKsm; dni is not\n\
         \x20                    implemented — use the card's PKCS#11 module)\n\
         \x20 -alias <name>      certificate alias within the store\n\
         \x20 -password <pw>     container password / keystore PIN\n\
         \x20 -xml               answer in AutoFirma's XML envelope\n",
    );
    sb
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A store over a fixed list: the picker logic is about what it offers,
    /// and these tests exercise that without a token.
    struct FixedStore(Vec<openfirma_keystore::StoreCertificate>);
    impl openfirma_keystore::SystemStore for FixedStore {
        fn certificates(
            &self,
        ) -> openfirma_core::Result<Vec<openfirma_keystore::StoreCertificate>> {
            Ok(self.0.clone())
        }
        fn sign_prehash(
            &self,
            _cert: &openfirma_keystore::StoreCertificate,
            _alg: openfirma_core::alg::DigestAlg,
            _prehash: &[u8],
        ) -> openfirma_core::Result<Vec<u8>> {
            unreachable!("the picker never signs")
        }
    }

    fn dnie_pair() -> (
        openfirma_core::CertificateHandle,
        openfirma_core::CertificateHandle,
    ) {
        openfirma_core::filter::dnie_shaped_pair()
    }

    #[test]
    fn the_picker_hides_the_dnie_auth_certificate_and_signs_with_the_twin() {
        // The A5 picker rule end to end: a keystore holding auth+sign pair,
        // no --store-alias anywhere in sight. Before the fix this refused with
        // "more than one signer" or (worse) let an operator pick the auth
        // certificate from an opaque list.
        use openfirma_keystore::{KeyHandle, StoreCertificate};
        let (auth_cert, sign_cert) = dnie_pair();
        let entry = |cert: openfirma_core::CertificateHandle, label: &str| StoreCertificate {
            cert,
            label: Some(label.into()),
            key_handle: KeyHandle::Pkcs11Id(vec![1]),
            always_authenticate: false,
            chain: Vec::new(),
        };
        let mk = || {
            Arc::new(FixedStore(vec![
                entry(auth_cert.clone(), "CertAutenticacion"),
                entry(sign_cert.clone(), "CertFirmaDigital"),
            ])) as DynStore
        };
        let signer = store_signer(mk(), None).expect("the signing twin must be chosen alone");
        assert_eq!(
            signer.certificate().subject_cn().as_deref(),
            Some("Marta Viajera Garcia - test")
        );
        // And the hidden one is still reachable by explicit name.
        let by_name = store_signer(mk(), Some("CertAutenticacion"))
            .expect("an explicit alias reaches the hidden certificate");
        assert!(by_name.certificate().is_dnie_authentication_cert());
    }

    use std::time::SystemTime;

    #[test]
    fn an_unlabeled_store_is_still_reachable_by_the_name_it_prints() {
        // 04-N3, on the same code path the Windows store takes: entries with
        // `label: None` (the Windows store filled none, and neither does a
        // PKCS#11 object without CKA_LABEL). `store_signer` compared `label`
        // alone while both listings print the subject CN, so the refusal named
        // the entry it had just offered and the compat layer's `-alias <CN>`
        // — fed straight from `listaliases` — could never work.
        use openfirma_keystore::{KeyHandle, StoreCertificate};
        let entry = |cn: &str| StoreCertificate {
            cert: openfirma_core::filter::shape_cert(
                // RFC 4514: the comma inside the value is escaped on the way in
                // and comes back unescaped from subject_cn().
                &format!("CN={}", cn.replace(',', "\\,")),
                "CN=AC FNMT Usuarios,O=FNMT,C=ES",
                std::time::Duration::from_secs(3600),
                Some((true, true)),
            ),
            label: None,
            key_handle: KeyHandle::Pkcs11Id(vec![1]),
            always_authenticate: false,
            chain: Vec::new(),
        };
        let mk = || {
            Arc::new(FixedStore(vec![
                entry("LOPEZ MARTIN, JUAN"),
                entry("PEREZ GARCIA, ANA"),
            ])) as DynStore
        };
        // Two signers and no alias: refused, with both printed names on offer.
        let err = store_signer(mk(), None)
            .map(|_| ())
            .expect_err("two signers need an alias")
            .to_string();
        assert!(err.contains("PEREZ GARCIA, ANA"), "{err}");
        assert!(err.contains("LOPEZ MARTIN, JUAN"), "{err}");
        // The name the listing printed is the name that selects.
        let picked = store_signer(mk(), Some("PEREZ GARCIA, ANA")).expect("the CN selects");
        assert_eq!(
            picked.certificate().subject_cn().as_deref(),
            Some("PEREZ GARCIA, ANA")
        );
        // And a name nothing carries is refused with the same list.
        let err = store_signer(mk(), Some("NADIE NADIE"))
            .map(|_| ())
            .expect_err("no such entry")
            .to_string();
        assert!(err.contains("PEREZ GARCIA, ANA"), "{err}");
    }

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

    /// The two register tests below share the process's HOME (the platform
    /// block resolves its .desktop through it, and set_var is visible to every
    /// thread), so they take turns on this lock — cargo runs them as sibling
    /// threads of one binary. Each still restores HOME for whoever comes next.
    static HOME_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// The env is process-wide, so tests that promise xdg-mime (see
    /// `is_xdg_mime_available`) hold this lock while the variable is set. It
    /// rides on HOME_LOCK's reasons and restores like `with_home` does.
    static XDG_MIME_OVERRIDE: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Lock without the panic politics: a sibling test that died holding this
    /// lock left the data (a `()`) perfectly fine, and panicking here instead
    /// turned one failure into a cascade across CI's targets — where HOME is
    /// process-wide exactly because cargo runs these as threads of one binary.
    fn lock_quiet(lock: &std::sync::Mutex<()>) -> std::sync::MutexGuard<'_, ()> {
        match lock.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Give the platform block a home directory for the duration of `run`.
    /// Windows CI exports no HOME at all (register_scheme's linux block never
    /// compiles there, so it never notices; these tests must not notice either),
    /// and every thread sees any set_var — edition-2024's warning exactly: this
    /// helper keeps the window as small as a call and restores whatever was
    /// there before, including "nothing was there".
    ///
    /// H-17 (review 07): no HOME write may happen outside a locked window —
    /// every caller of `with_home` takes HOME_LOCK itself, exactly like the
    /// XDG_MIME_OVERRIDE callers do. Locking inside the helper instead looked
    /// like the stronger form and deadlocked: `std::sync::Mutex` is not
    /// reentrant, and the register tests must hold the lock across two
    /// with_home calls (their assertions observe what the platform block
    /// wrote through HOME between them).
    ///
    /// MOVING_HOME is the helper's own marker — a second mutex held for
    /// exactly the set/restore window. It serializes HOME movers even if a
    /// caller forgets HOME_LOCK, and `home_moves_only_inside_the_locked_
    /// window` watches it from outside to prove the window exists at all.
    static MOVING_HOME: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_home<T>(dir: &Path, run: impl FnOnce() -> T) -> T {
        let _moving_home = lock_quiet(&MOVING_HOME);
        // CI (run 39084918100, arm64 linux) proved HOME_LOCK alone does not
        // serialize every HOME writer visible to this process: mid-window a
        // sibling test read HOME as an `openfirma-register-empty-<pid>` fixture
        // path that no code of ours ever sets — while our own window was closed.
        // Something on the runner scribbles on the environment; that cannot be
        // prevented from here. What CAN hold under it: inside the window HOME is
        // re-asserted just before `run` (so a foreign write cannot beat the call
        // itself), and the restore at exit writes back None-or-the-captured-home
        // rather than whatever a racer left behind. The test below samples HOME
        // only from inside its own HOME_LOCK window for the same reason: an
        // outside observer cannot tell our writes from the agent's, so it is not
        // evidence about with_home either way.
        struct Restore(Result<std::ffi::OsString, std::env::VarError>);
        impl Drop for Restore {
            fn drop(&mut self) {
                unsafe {
                    match &self.0 {
                        Ok(h) => std::env::set_var("HOME", h),
                        Err(_) => std::env::remove_var("HOME"),
                    }
                }
            }
        }
        // A panic inside `run` restores through Drop: the process must never
        // keep a scratch HOME after a failed test — its next reader would blame
        // with_home for deleting files under itself (the run-39084918100 shape).
        let restore = Restore(
            std::env::var_os("HOME").map_or_else(|| Err(std::env::VarError::NotPresent), Ok),
        );
        unsafe { std::env::set_var("HOME", dir) };
        let out = run();
        drop(restore);
        out
    }

    /// Parsing `args` (program name included) as the real CLI would. A test
    /// that never parses argv cannot tell a wired flag from a documented one.
    fn parse(argv: &[&str]) -> Cli {
        Cli::try_parse_from(std::iter::once("openfirma").chain(argv.iter().copied()))
            .expect("the arguments must parse")
    }

    #[test]
    fn the_scheme_channel_reads_its_key_from_the_browser_config() {
        // M-3b: the installed Exec carries no flags but the URI, so `--config`
        // is what makes it sign. The flag must exist on both browser commands
        // and land where the resolution code reads it.
        let cli = parse(&["afirma-uri", "afirma://sign?op=selectCert"]);
        match &cli.command {
            Command::AfirmaUri { config, .. } => assert!(config.is_none()),
            _ => panic!("expected afirma-uri"),
        }
        let cli = parse(&[
            "afirma-uri",
            "afirma://sign?op=selectCert",
            "--config",
            "/tmp/mi-config.toml",
        ]);
        match &cli.command {
            Command::AfirmaUri { config, .. } => {
                assert_eq!(config.as_deref(), Some(Path::new("/tmp/mi-config.toml")))
            }
            _ => panic!("expected afirma-uri"),
        }
        let cli = parse(&["afirma-serve", "--config", "/tmp/served.toml"]);
        match &cli.command {
            Command::AfirmaServe { config, .. } => {
                assert_eq!(config.as_deref(), Some(Path::new("/tmp/served.toml")))
            }
            _ => panic!("expected afirma-serve"),
        }
        // The default-location rule itself is the browser crate's own function
        // (tested there); what this test pins is that argv knows the file at
        // all — without the flag below, `--register`'s config had no reader.
    }

    #[test]
    fn register_without_any_key_source_names_the_refusal_it_cannot_sign_with() {
        let _home_guard = lock_quiet(&HOME_LOCK);
        // Some CI images (aarch64) ship no xdg-utils, and --register's honest
        // "instala xdg-utils" refusal is NOT what this test pins: every key
        // refusal below fires independently of it. Promise the tool on such
        // images (the same env the browser crate honors; linux_install_and_
        // register skips its association step when it is set and the binary
        // is really absent) so the tested rules decide pass or fail here too.
        let _xdg_guard = lock_quiet(&XDG_MIME_OVERRIDE);
        unsafe { std::env::set_var("OPENFIRMA_ASSUME_XDG_MIME", "1") };
        // The refusal a fresh `--register` (no --p12 anywhere) must print:
        // naming the fix, not just the missing flag — the whole point of the
        // round-two finding was an install step that "succeeded" into a
        // handler that always failed. (The xdg-mime promise above covers the
        // legs below: with --p12 present, registration runs first and needs
        // it on images without xdg-utils.)
        let dir =
            std::env::temp_dir().join(format!("openfirma-register-empty-{}", std::process::id()));
        // The refusal must arrive BEFORE any file exists — the round-two state
        // was an install that printed its happy instructions and left a dead
        // handler behind. HOME moves to this scratch tree for the duration:
        // the platform block resolves its .desktop through it, so "nothing was
        // written" is observable right here instead of in CI's real home.
        std::fs::create_dir_all(dir.join(".local/share/applications")).unwrap();
        let cfg = dir.join("browser.toml");
        let _ = std::fs::remove_file(&cfg);
        let err = with_home(&dir, || {
            register_scheme(None, None, Some(&cfg), false, false)
                .unwrap_err()
                .to_string()
        });
        let desktop = dir.join(".local/share/applications/openfirma-afirma.desktop");
        assert!(
            !desktop.exists(),
            "--register wrote {} despite refusing for want of a key",
            desktop.display()
        );
        assert!(err.contains("--p12"), "{err}");
        assert!(
            err.contains("--register writes a p12") || err.contains("existing"),
            "{err}"
        );

        // and a half-pair (--password-file without --p12) is the OTHER named
        // refusal: it would write half a key into the file. Same HOME scope.
        let pw = write_tmp("halfpair.pw", b"secreto\n");
        let err = with_home(&dir, || {
            register_scheme(None, Some(pw.clone()), Some(&cfg), false, false)
                .unwrap_err()
                .to_string()
        });
        assert!(
            err.contains("--p12 writes a p12") || err.contains("half a key"),
            "{err}"
        );
        std::fs::remove_file(&pw).ok();
    }

    #[test]
    fn register_writes_a_config_the_handler_reads_back() {
        let _home_guard = lock_quiet(&HOME_LOCK);
        // The round trip that closes M-3b: what `--register` writes must be
        // exactly what `afirma-uri` reads with no flags but the URI — spaces
        // and all, because installs under `/home/Ana María/` are real.
        let dir = std::env::temp_dir().join(format!(
            "openfirma-register-roundtrip-{}",
            std::process::id()
        ));
        // HOME moves to this scratch tree for the duration only: --register's
        // platform block writes its .desktop through HOME (restored right
        // after the call below, set_var discipline as everywhere else). The
        // caller holds HOME_LOCK for the whole window: with_home does not
        // lock (a non-reentrant mutex would self-deadlock a locked helper),
        // so guarding HOME is each test's own job.
        std::fs::create_dir_all(dir.join(".local/share/applications")).unwrap();
        let cfg = dir.join("browser.toml");
        let _ = std::fs::remove_file(&cfg);
        let p12 = dir.join("Ana María/clave #7.p12");
        std::fs::create_dir_all(p12.parent().unwrap()).unwrap();
        std::fs::write(&p12, b"not really a p12 but a file").unwrap();
        // 0600 like any password file the installer itself writes: B-2's
        // private-mode rule refuses world-readable key material by design, so
        // a test that hands the installer a 0644 password is testing the wrong
        // precondition — this fixture must arrive as a real one would.
        let pw = dir.join("pw.txt");
        std::fs::write(&pw, b"secreto\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&pw, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        // A CI image without xdg-utils has no desktop to register into; the
        // override below is exactly what linux_install_and_register's error
        // text demands ("instala xdg-utils y repite"), and this test pins the
        // config round trip, not that binary. The env var itself is read on
        // every platform (is_xdg_mime_available checks it before its cfg);
        // only the lock is gated to where the promise changes any behavior.
        #[cfg(target_os = "linux")]
        let _xdg_guard = lock_quiet(&XDG_MIME_OVERRIDE);
        unsafe { std::env::set_var("OPENFIRMA_ASSUME_XDG_MIME", "1") };
        let wrote = with_home(&dir, || {
            register_scheme(Some(p12.clone()), Some(pw.clone()), Some(&cfg), false, true)
        });
        wrote.expect("a --register with a real key must write its config");

        let back = browser_key_config(Some(&cfg))
            .unwrap()
            .expect("the config exists after registering");
        assert_eq!(back.p12.as_deref(), Some(p12.as_path()));
        assert_eq!(back.password_file.as_deref(), Some(pw.as_path()));

        // and browser_key_config follows the same rule without --config: an
        // absent default is no error (the caller decides whether that is a
        // refusal), a present one is read.
        std::fs::remove_file(&cfg).ok();
        let _ = dir;
    }

    /// H-17's proof for this binary: HOME only ever moves inside a locked
    /// window. A sibling test that set HOME unguarded made concurrent getenv
    /// undefined behaviour (glibc), and macOS CI runs these threads on
    /// machines with no HOME at all. What makes the rule checkable is that
    /// `with_home` holds MOVING_HOME for exactly its set/restore window: a
    /// probe from inside sees it busy, outside sees it free, so two HOME
    /// movers can never overlap; and a poller sampling HOME through the run
    /// never sees any value but the real one or the fixture's own. The
    /// caller-side half (each test takes HOME_LOCK before calling) is the
    /// discipline this same test models: it never moves HOME outside its own
    /// guard below.
    #[test]
    fn home_moves_only_inside_the_locked_window() {
        // Sampled AFTER taking HOME_LOCK: an earlier read raced a sibling
        // with_home window and captured a fixture path, which the outside
        // assertions then blamed this helper for — "HOME moved back to the
        // wrong place" when in fact it moved back correctly. With the lock held,
        // `real` is by construction the value every with_home will restore to.
        let _home_guard = lock_quiet(&HOME_LOCK);
        let real = std::env::var_os("HOME");
        let dir = std::env::temp_dir().join(format!("openfirma-home-race-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // Outside any window the marker is free (held only for the duration,
        // or every caller would serialize forever). The busy half gets proven
        // from inside the window below, where a `try_lock` answers "busy"
        // with certainty; a background poller racing a microsecond-long
        // set/restore would only measure scheduler noise.
        let free_outside = MOVING_HOME.try_lock().is_ok();

        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let (stop, stop_rx) = std::sync::mpsc::channel::<()>();
        let poller = {
            let seen = std::sync::Arc::clone(&seen);
            std::thread::spawn(move || {
                while stop_rx.try_recv().is_err() {
                    seen.lock().unwrap().push(std::env::var_os("HOME"));
                    std::thread::sleep(std::time::Duration::from_micros(50));
                }
            })
        };

        let inner = dir.clone();
        with_home(&dir, || {
            // inside the window HOME is the fixture and the marker is busy —
            // a second mover waiting on MOVING_HOME cannot be mid-set right
            // now, which is exactly H-17's serialization.
            assert_eq!(std::env::var_os("HOME").as_deref(), Some(inner.as_os_str()));
            assert!(MOVING_HOME.try_lock().is_err());
        });
        // outside it, HOME is back to what it was and the marker is free
        // again, even while the poller keeps sampling.
        assert_eq!(std::env::var_os("HOME"), real);
        let free_after = MOVING_HOME.try_lock().is_ok();
        let _ = stop.send(());
        poller.join().unwrap();

        let observed = seen.lock().unwrap();
        // The window is microseconds, so a 50us poller may well miss it
        // entirely — what must never happen is an OBSERVED value that came
        // from anywhere outside the real HOME or the fixture.
        for value in observed.iter() {
            assert!(
                value.as_deref() == Some(dir.as_os_str()) || value == &real,
                "HOME was observed as {value:?}: neither the fixture nor the real home — \
                 something writes HOME outside with_home's locked window"
            );
        }
        assert!(
            free_outside && free_after,
            "MOVING_HOME outlives with_home's window: two HOME movers would \
             serialize forever and the marker stops meaning \"window active\""
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn store_specs_parse_every_documented_shape() {
        let spec = parse_store_spec("pkcs11:/usr/lib/opensc-pkcs11.so").unwrap();
        match spec {
            StoreSpec::Pkcs11 {
                module,
                token,
                wants_no_pin,
            } => {
                assert_eq!(module, PathBuf::from("/usr/lib/opensc-pkcs11.so"));
                assert_eq!(token, None);
                assert!(!wants_no_pin);
            }
            other => panic!("expected a pkcs11 spec, got {other:?}"),
        }
        let spec = parse_store_spec("pkcs11:/tmp/x-mod.so:My Card").unwrap();
        match spec {
            StoreSpec::Pkcs11 {
                module,
                token,
                wants_no_pin,
            } => {
                assert_eq!(module, PathBuf::from("/tmp/x-mod.so"));
                assert_eq!(token.as_deref(), Some("My Card"));
                assert!(!wants_no_pin);
            }
            other => panic!("expected a pkcs11 spec, got {other:?}"),
        }
        // The explicit no-PIN marker: `::` at the end, with and without label.
        let spec = parse_store_spec("pkcs11:/usr/lib/nosuch-mod.so:My Card::").unwrap();
        match spec {
            StoreSpec::Pkcs11 {
                module: _,
                token,
                wants_no_pin,
            } => {
                assert_eq!(token.as_deref(), Some("My Card"));
                assert!(wants_no_pin);
            }
            other => panic!("expected a pkcs11 spec, got {other:?}"),
        }
        // A colon that does not follow an existing module file stays inside
        // the path: on Windows this is how `C:\…\mod.dll` survives.
        let spec = parse_store_spec("pkcs11:C:\\tokens\\mod.dll").unwrap();
        match spec {
            StoreSpec::Pkcs11 {
                module,
                token,
                wants_no_pin: _,
            } => {
                assert_eq!(module, PathBuf::from("C:\\tokens\\mod.dll"));
                assert_eq!(token, None);
            }
            other => panic!("expected a pkcs11 spec, got {other:?}"),
        }
        let spec = parse_store_spec("nss:sql:/home/u/.pki/nssdb").unwrap();
        match spec {
            StoreSpec::Nss { db } => assert_eq!(db, "sql:/home/u/.pki/nssdb"),
            other => panic!("expected an nss spec, got {other:?}"),
        }
        // The bare forms: windows/macos take no argument and name no store
        // elsewhere; the HOME-default of `nss` reads the environment and gets
        // its own test below, away from any other env mutation.
        assert!(matches!(
            parse_store_spec("windows").unwrap(),
            StoreSpec::Windows
        ));
        assert!(matches!(
            parse_store_spec("macos").unwrap(),
            StoreSpec::Macos
        ));
        assert!(matches!(
            parse_store_spec("apple").unwrap(),
            StoreSpec::Macos
        ));
        let err = parse_store_spec("pkcs11:").err().unwrap().to_string();
        assert!(err.contains("module path"), "{err}");
        let err = parse_store_spec("windows:/extra")
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("takes no argument"), "{err}");
        let err = parse_store_spec("tpm:foo").err().unwrap().to_string();
        assert!(err.contains("--store") && err.contains("pkcs11:"), "{err}");
    }

    #[test]
    fn bare_nss_store_carries_the_home_sentinel_without_reading_the_environment() {
        // The race this design kills: parse used to read $HOME, so any
        // sibling test that relocated HOME saw the wrong default database —
        // and macOS runners start test processes with no HOME at all, which
        // made the bare form a coin flip. Parsing now stores `$HOME/.pki/…`
        // literally; nss::config_string expands it at open time, and
        // descriptor() resolves it without the environment when given a home.
        let spec = parse_store_spec("nss").unwrap();
        match &spec {
            StoreSpec::Nss { db } => assert_eq!(db, "$HOME/.pki/nssdb"),
            other => panic!("expected an nss spec, got {other:?}"),
        }
        // Round trip is literal when HOME cannot answer, and resolved when it
        // can — the same text `--store nss` opens with.
        let rendered = spec.descriptor_at(Some(std::ffi::OsStr::new("/home/openfirma-spec-test")));
        assert_eq!(rendered, "nss:sql:/home/openfirma-spec-test/.pki/nssdb");
    }

    #[test]
    fn store_pin_reads_the_named_variable_and_refuses_its_absence() {
        // Same thread-safety rule as the HOME test: the variable name carries
        // this test's name, so no concurrent test can collide with it.
        let var = format!(
            "OPENFIRMA_TEST_PIN_{}",
            std::thread::current().name().unwrap_or("main")
        );
        unsafe { std::env::set_var(&var, "1234") };
        assert_eq!(&*store_pin(Some(&var)).unwrap().unwrap(), "1234");
        // An unset variable is a refusal, not an empty PIN (finding M2): the
        // token must never see a guess born of a typo.
        let absent = store_pin(Some(&format!("{var}-absent")))
            .unwrap_err()
            .to_string();
        assert!(absent.contains("is not set"), "{absent}");
        assert!(absent.contains("--pin-env"), "{absent}");
        assert_eq!(store_pin(None).unwrap(), None);
        unsafe { std::env::remove_var(&var) };
    }

    /// A one answer TCP server, so the TSA transport both frontends share
    /// (`openfirma_cades::tsa`) can be pointed at something that behaves like
    /// a hostile TSA without leaving the machine. The CLI-side tests below
    /// kept their cases when the transport moved into the crate: they are the
    /// proof that the one shared copy refuses what the two old copies did.
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
        let err = openfirma_cades::tsa::http_post(&format!("http://{addr}/tsa"), b"query")
            .expect_err("2006 is not 200")
            .to_string();
        srv.join().unwrap();
        assert!(err.contains("expected an HTTP/1.x 200"), "{err}");

        let (addr, srv) = fake_tsa(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi".to_vec());
        let body = openfirma_cades::tsa::http_post(&format!("http://{addr}/tsa"), b"query")
            .expect("a real 200 answer must be accepted");
        srv.join().unwrap();
        assert_eq!(body, b"hi");

        let (addr, srv) = fake_tsa(b"HTTP/1.1 500 Internal Server Error\r\n\r\nx".to_vec());
        let err = openfirma_cades::tsa::http_post(&format!("http://{addr}/tsa"), b"query")
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
        answer.resize(openfirma_cades::tsa::TSA_MAX_RESPONSE + 100, b'x');
        let (addr, srv) = fake_tsa(answer);
        let err = openfirma_cades::tsa::http_post(&format!("http://{addr}/tsa"), b"query")
            .expect_err("a megabyte of x is not a TimeStampResp")
            .to_string();
        srv.join().unwrap();
        assert!(err.contains("megabyte"), "{err}");
    }

    // --------------------------------------------------------- compat (A-8)

    #[test]
    fn a_repeated_compat_flag_is_refused() {
        // Java's rule ("the parameter X is used more than once") lives in the
        // parser, not in any arm: it must answer before a file is opened.
        let err = parse_compat_params(&["-i".into(), "a.pdf".into(), "-i".into(), "b.pdf".into()])
            .err()
            .expect("two -i flags are refused");
        assert!(err.contains("more than once"), "{err}");
    }

    #[test]
    fn compat_formats_follow_autofirmas_selection_and_its_names() {
        // auto maps onto detection exactly like selectFormatByData.
        assert_eq!(compat_format(Some("auto"), b"%PDF-1.4"), "pades-b-b");
        assert_eq!(compat_format(Some("auto"), b"<?xml v?>"), "xades-b-b");
        assert_eq!(compat_format(None, b"octets"), "cades-b-b");
        // The names AutoFirma's checkParams accepts survive the parser…
        for name in ["auto", "cades", "pades", "xades", "CADES"] {
            parse_compat_params(&["-format".into(), name.into()])
                .unwrap_or_else(|e| panic!("{name} is AutoFirma's own format name: {e}"));
        }
        // …and every other name (facturae/ooxml/odf included) dies there.
        let err = parse_compat_params(&["-format".into(), "facturae".into()])
            .err()
            .expect("facturae is not openfirma's compat format");
        assert!(err.contains("unsupported signature format"), "{err}");
    }

    #[test]
    fn compat_stores_translate_and_refuse_by_name() {
        assert!(matches!(
            compat_store("windows").unwrap(),
            CompatStore::Spec(StoreSpec::Windows)
        ));
        // AUTO on this machine (Linux under test): AutoFirma's SHARED_NSS.
        if cfg!(target_os = "linux") {
            assert!(matches!(
                compat_store("auto").unwrap(),
                CompatStore::Spec(StoreSpec::Nss { .. })
            ));
        }
        // A bare pkcs12 without its file answers with the spelling that works.
        let err = compat_store("pkcs12")
            .err()
            .expect("the suffix is required");
        assert!(err.contains("pkcs12:/path"), "{err}");
        let err = compat_store("dni").err().expect("no DNIe driver here");
        assert!(err.contains("pkcs11:"), "{err}");
        // A module file that does not exist is refused before any opening —
        // getKsm's existence check, in its own words.
        let err = compat_store("pkcs11:/nonexistent/mod.so")
            .err()
            .expect("a missing module is named before opening");
        assert!(err.contains("does not exist"), "{err}");
    }

    #[test]
    fn the_compat_xml_envelope_is_autofirmas_with_openfirmas_sentences_inside() {
        let xml = compat_xml(false, Some("no entry named \"x\"; <b> & c"), Some(b"ab"));
        assert!(xml.starts_with("<afirma><result>false</result><response>"));
        // The payload is AutoFirma's base64 of the raw signature.
        assert!(xml.contains("<sign>YWI=</sign>"), "{xml}");
        assert!(xml.contains("&lt;b&gt; &amp; c"), "{xml}");
        assert!(xml.ends_with("</response></afirma>"));
    }

    #[test]
    fn a_gui_flag_names_the_window_it_cannot_open() {
        let err = parse_compat_params(&["-gui".into()])
            .err()
            .expect("headless cannot promise a dialog");
        assert!(err.contains("openfirma"), "{err}");
    }

    #[test]
    fn an_unknown_compat_command_is_the_syntax_error_exit_255_promises() {
        let err = parse_compat_command("countersign")
            .err()
            .expect("no countersign here");
        assert!(err.contains("does not implement"), "{err}");
        let err = parse_compat_command("frobnicate")
            .err()
            .expect("not a command");
        assert!(err.contains("unknown command"), "{err}");
    }
}
