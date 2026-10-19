//! Dispatching a parsed `afirma://` URI onto the same operations the CLI
//! exposes, and returning the result in AutoFirma's wire shape.
//!
//! The two response shapes are read off AutoFirma 1.9, not invented — and,
//! unlike the first revision of this file, each was also *measured against the
//! shipped jar* (the method AGENT-BRIEF demands):
//!
//! - signing (`NativeSignDataProcessor.postProcess`, afirma-simple):
//!   `base64(signing certificate DER) + "|" + base64(signature)` — the comment
//!   there says the double base64 (cert as one field, signature as the next)
//!   is what the page splits on. Both fields are produced by
//!   `es.gob.afirma.core.misc.Base64.encode(x, true)`, which is **URL-safe**
//!   base64, padded, in a SINGLE line (recorded against `autofirma.jar` itself
//!   for finding M-1: 200 bytes encode to 268 characters with `-`/`_`, no
//!   `\r\n` anywhere; the iharder encoder's line-breaking option is not set by
//!   this call — `Base64.java:293-295`). An earlier revision of openfirma
//!   emitted MIME base64 with CRLF here on the theory that the second argument
//!   meant "break lines"; the jar proves that theory wrong, and every page's
//!   success path rewrites `-`/`_` back to `+`/`/` (autoscript.js:2892-2898),
//!   which only makes sense for URL-safe fields.
//! - certificate selection (`ProtocolInvocationLauncherSelectCert`, line 234):
//!   the leaf certificate DER base64'd URL-safe on its own, nothing else.
//! - errors (`ProtocolInvocationLauncherErrorManager.getErrorMessage`): two
//!   forms, selected by protocol version. Protocol 4.1 and above (and plain
//!   HTTP calls without `v=` fall into it, see `WireTarget`) answer
//!   `err-00:=AF<code> - <description>`, cancellations with the `err-11:=`
//!   prefix; below 4.1 the answer is the old `SAF_xx: mensaje`, and a user
//!   cancellation is literally `CANCEL`. The codes are AutoFirma's own six
//!   digits from its error catalogues (finding M-2: a page reads exactly eight
//!   characters before `" - "` — autoscript.js:2651-2659 — so openfirma's own
//!   names could not be read by anyone; every refusal below now carries the
//!   AutoFirma counterpart it matches).

use std::path::Path;

use base64::Engine;

use openfirma_core::alg::{DigestAlg, KeyAlgorithm};
use openfirma_core::cert::CertificateHandle;
use openfirma_core::signer::{Signer, SoftwareSigner};
use openfirma_keystore::Pkcs12;

use crate::uri::{AfirmaUri, Operation, ProtocolVersion};

/// The separator AutoFirma's `NativeSignDataProcessor` uses between the base64
/// certificate and the base64 signature in one sign response.
const RESULT_SEPARATOR: char = '|';

/// How the result leaves this process. The scheme call itself cannot carry a
/// return value to the page (a browser hand-off to an external handler has no
/// reply channel), so AutoFirma's pages always read the result from somewhere
/// else: its loopback endpoint, or the government intermediate server. This
/// client answers the loopback connection it is serving (`serve.rs`); a call
/// that can only deliver through the intermediate server is refused by name —
/// see `uri.rs`, `crate::signing` and docs/adr/0005-browser-protocol.md.
///
/// The result of one browser-protocol operation, in wire form already so the
/// loopback server and the CLI emit byte-identical answers.
#[derive(Debug)]
pub struct BrowserResult {
    /// `base64URL(cert)|base64URL(signature)` or plain `base64URL(cert)`,
    /// AutoFirma's shapes; never an error string (errors come back as `Err`).
    pub payload: Vec<u8>,
    /// What was produced, for the CLI to report and tests to assert on.
    pub kind: ResultKind,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ResultKind {
    Signature { format: String },
    CertificateSelected,
}

/// The reason header the loopback endpoint sends with an error payload. The
/// name is openfirma's own (a page never reads headers from a cross-origin
/// fetch anyway); its VALUE is AutoFirma's catalogue number for the refusal —
/// what autoscript.js's error parser reads as `AFxxxxxx` out of the `err-00:=`
/// body (lines 2651-2659) — so a log, a curl run, and the wire text a page
/// parses all quote the same number. `[WireError::af_code]`.
pub fn error_reason_header(e: &BrowserError) -> &'static str {
    e.wire.af_code
}

/// Who answers a browser call, and with what authority over the user's key.
/// The consent rule (finding A-3): AutoFirma shows its certificate dialog and
/// asks the PIN at exactly this point of every flow — nobody ever proved to it
/// that the human in front of the screen asked for this signature except by
/// operating the dialog. openfirma keeps that invariant: a headless session
/// (the browser handler, the loopback endpoint) carries keys inside an
/// [`UnattendedKey`] whose password was stored on disk, and signing with such
/// a key requires either the user having opted into it per key
/// (`allow_unattended`) or consent being granted through the callback — which
/// is also where the PIN prompt of a hardware key belongs. Without one of
/// those two, nothing signs: a refusal that names itself, never a silent
/// signature (any page can reach `afirma://` once the scheme is registered).
pub enum KeySource<'a> {
    P12 {
        path: &'a Path,
        password: &'a str,
    },
    /// A key no human is standing behind unless consent says so. Carries a
    /// human-facing label for the consent prompt (AutoFirma's dialogs show the
    /// certificate's subject; the prompt must name *something*).
    Unattended(UnattendedKey<'a>),
}

/// The material and policy of an unattended key: see [`KeySource::Unattended`].
pub struct UnattendedKey<'a> {
    pub path: &'a Path,
    /// The container password. `None` means nobody has it — the PKCS#12 cannot
    /// be opened without one, so a call against it needs consent that will
    /// provide the password through the callback (the PIN flow).
    pub password: Option<&'a str>,
    /// Whether the owner of this key told openfirma that signing without a
    /// prompt is acceptable for it (an explicit config/flag, never a default).
    pub allow_unattended: bool,
    /// The label the consent prompt shows next to the certificate subject.
    pub label: &'a str,
}

impl std::fmt::Debug for KeySource<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeySource::P12 { path, .. } => f.debug_struct("P12").field("path", path).finish(),
            KeySource::Unattended(k) => f
                .debug_struct("Unattended")
                .field("path", &k.path)
                .field("password", &"[hidden]")
                .field("allow_unattended", &k.allow_unattended)
                .finish(),
        }
    }
}

/// What a page asked for, in the words a consent prompt must show. Built
/// before anything signs; see [`Consent`] and finding A-3.
#[derive(Debug, Clone)]
pub struct OperationSummary {
    /// "sign CAdES-B-B", "select certificate" — what operation runs.
    pub operation: String,
    /// The sede's `appname` parameter when it sent one (autoscript.js puts the
    /// page's domain there: `createSignRequest`, line 2274), else empty.
    pub app_name: String,
    /// SHA-256 fingerprint of the document bytes that will be signed (lowercase
    /// hex), or "no document" for selectcert. The user must see WHAT is being
    /// signed, not only that something is.
    pub document_digest: String,
    /// Length in bytes of the document.
    pub document_len: usize,
}

/// The consent callback: given what is about to be signed, say yes or no (and,
/// for keys needing a fresh secret, optionally return the PIN/password — that
/// is AutoFirma's dialog collecting the container password at sign time).
pub trait ConsentFn: Send + Sync {
    /// Show the summary and ask. `needs_password` says the key cannot be
    /// opened without a secret collected now (AutoFirma's PIN dialog). The
    /// returned password is used once and zeroed by its consumer.
    fn approve(
        &self,
        summary: &OperationSummary,
        needs_password: bool,
    ) -> Result<ConsentAnswer, BrowserError>;
}

/// What a consent callback answered.
pub enum ConsentAnswer {
    Yes {
        password: Option<zeroize::Zeroizing<String>>,
    },
    No,
}

impl std::fmt::Debug for ConsentAnswer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConsentAnswer::Yes { password } => f
                .debug_struct("Yes")
                .field("password", &password.as_ref().map(|_| "[hidden]"))
                .finish(),
            ConsentAnswer::No => write!(f, "No"),
        }
    }
}

/// The consent a caller hands to [`execute_with_consent`]. `'a` is the prompt's
/// lifetime; `Granted` carries none.
pub enum Consent<'a> {
    /// Show a prompt and ask. `Ok(true)` lets the operation run;
    /// `Ok(false)`, or an error, stops it — and a stop entered by the user is
    /// AutoFirma's cancellation (`err-11:=AF500001`, code 500001 =
    /// `ErrorCode.Functional.CANCELLED_OPERATION`).
    Prompt(&'a dyn ConsentFn),
    /// Already granted (the unattended opt-in): no prompt, the key's owner
    /// decided once. Tests and deliberate integrations use this variant; the
    /// browser handler reaches it only through `allow_unattended`.
    Granted,
}

impl<'a> Consent<'a> {
    pub fn granted() -> Self {
        Consent::Granted
    }
}

/// Errors that stop an operation before it produces bytes. The loopback server
/// turns these into the `err-00:=...` text AutoFirma's pages parse; the CLI
/// prints them with exit status 1.
#[derive(Debug)]
pub struct BrowserError {
    /// Machine-readable reason, for logs and the endpoint's reason header.
    pub code: &'static str,
    pub message: String,
    /// The AutoFirma wire error this refusal corresponds to (its own catalogue
    /// number), which is what the `err-00:=`/`SAF_xx` text carries.
    pub wire: WireError,
}

impl std::fmt::Display for BrowserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for BrowserError {}

/// AutoFirma's own error catalogue, restricted to the entries an openfirma
/// refusal actually corresponds to — recorded from the 1.9.1 sources at their
/// exact lines: `SimpleErrorCode.java` (Request/Inner codes), afirma-core's
/// `ErrorCode.java` (200xxx/5xxxxx/6xxxxx), `KeyStoreErrorCode.java` (the
/// 201xxx store codes), and the two response tables of
/// `ProtocolInvocationLauncherErrorManager`: `ERRORS` (SAF_xx → Spanish text,
/// lines 100-146) and `OLD_ERRORS_ASSOCIATION` (catalogue code → SAF_xx,
/// lines 152-290; an unmapped code answers SAF_53). Keeping the pairs here is
/// what stops a refusal from quoting a number that means something else to
/// the page reading it. The descriptions are AutoFirma's own Spanish strings:
/// for the 4.1+ form, `getErrorMessage` quotes `errorCode.getDescription()` —
/// verbatim from the catalogues (jar-verified); for the legacy form it quotes
/// the `ERRORS` table (protocolmessages_es_ES.properties). The SAF note in
/// each doc-comment is the entry's recorded legacy association.
#[derive(Debug, Clone, Copy)]
pub struct WireError {
    /// The six-digit AutoFirma code.
    pub af_code: &'static str,
    /// Its `SAF_xx` counterpart for pre-4.1 callers (`ERRORS` table keys).
    pub old_code: &'static str,
    /// AutoFirma's own user-facing description (see above).
    pub description: &'static str,
}

impl WireError {
    /// Every entry, so a test can pin the whole table against AutoFirma's
    /// catalogues without reflecting Java from Rust.
    pub const ALL: [WireError; 16] = [
        WireError::CANCELLED,
        WireError::URI_NOT_FOUND,
        WireError::UNSUPPORTED_SCHEME,
        WireError::UNSUPPORTED_OPERATION,
        WireError::INVALID_SESSION_ID,
        WireError::MALFORMED_SOCKET_PARAMS,
        WireError::DATA_NOT_FOUND,
        WireError::UNSUPPORTED_FORMAT,
        WireError::UNSUPPORTED_ALGORITHM,
        WireError::INVALID_SIGNING_KEY,
        WireError::SIGNING_FAILED,
        WireError::SELECT_CERT_FAILED,
        WireError::KEYSTORE_ERROR,
        WireError::DATA_LOAD_FAILED,
        WireError::UNSUPPORTED_HASH_ALGORITHM,
        WireError::UNSUPPORTED_PROTOCOL_VERSION,
    ];
}

impl WireError {
    /// `ErrorCode.Functional.CANCELLED_OPERATION` — "Operacion cancelada por
    /// el usuario" (ErrorCode.java:174). Cancellation travels as the literal
    /// `CANCEL` on the old protocol (`OLD_ERRORS_ASSOCIATION`, line 152, to
    /// `CANCEL_RESPONSE`).
    pub const CANCELLED: WireError = WireError {
        af_code: "500001",
        old_code: "CANCEL",
        description: "Operacion cancelada por el usuario",
    };
    /// `SimpleErrorCode.Request.REQUEST_URI_NOT_FOUND` (SimpleErrorCode.java:
    /// 117) → SAF_01 "La URL recibida es nula" (recorded association, line 154).
    pub const URI_NOT_FOUND: WireError = WireError {
        af_code: "620012",
        old_code: "SAF_01",
        description: "No se ha proporcionado la URI de invocacion",
    };
    /// `SimpleErrorCode.Request.UNSUPPORTED_REQUEST_SCHEME` (line 114) →
    /// SAF_02 "Protocolo no soportado" (recorded association, line 155).
    pub const UNSUPPORTED_SCHEME: WireError = WireError {
        af_code: "620009",
        old_code: "SAF_02",
        description: "El esquema de la URL de invocacion no esta soportado",
    };
    /// `SimpleErrorCode.Request.UNSUPPORTED_OPERATION` (line 110) → SAF_04
    /// "Operacion no soportada. Compruebe que dispone de la ultima version
    /// de Autofirma." (recorded association, line 192). openfirma's refusals
    /// of routes it does not implement — cosign, the servlet flow, a key
    /// without consent — answer exactly this pair, because that is what the
    /// launcher answers for an operation it cannot run.
    pub const UNSUPPORTED_OPERATION: WireError = WireError {
        af_code: "600002",
        old_code: "SAF_04",
        description: "La operacion no esta soportada",
    };
    /// `SimpleErrorCode.Request.INVALID_SESSION_ID` (line 115) → SAF_46 "Id de
    /// sesion invalido" (recorded association, line 231).
    pub const INVALID_SESSION_ID: WireError = WireError {
        af_code: "620010",
        old_code: "SAF_46",
        description: "El identificador de sesion del websocket es incorrecto",
    };
    /// `SimpleErrorCode.Request.MALFORMED_REQUEST_TO_SOCKET` (line 119) →
    /// SAF_03 "Error en los parametros de entrada" (recorded association,
    /// line 191): the shape a URI the client cannot parse takes in AutoFirma's
    /// socket flow.
    pub const MALFORMED_SOCKET_PARAMS: WireError = WireError {
        af_code: "620016",
        old_code: "SAF_03",
        description: "Los parametros recibidos en el socket no son correctos",
    };
    /// `ErrorCode.Request.DATA_NOT_FOUND` (ErrorCode.java:198) → SAF_03
    /// (recorded association, line 159): a sign call that carries neither the
    /// data nor a file id to download.
    pub const DATA_NOT_FOUND: WireError = WireError {
        af_code: "600100",
        old_code: "SAF_03",
        description: "No se ha recibido los datos en la peticion ni el id del fichero a descargar para la operacion de firma",
    };
    /// `ErrorCode.Request.UNSUPPORTED_SIGNATURE_FORMAT` (line 203) → SAF_06
    /// "Formato de firma no soportado" (recorded association, line 195). Its
    /// sibling for a MISSING format is 600104 (`SIGNATURE_FORMAT_NOT_FOUND`,
    /// also SAF_03, line 185); openfirma quotes the missing/not-found codes
    /// where they apply.
    pub const UNSUPPORTED_FORMAT: WireError = WireError {
        af_code: "600105",
        old_code: "SAF_06",
        description: "El formato de firma indicado en la operacion de firma no esta soportado",
    };
    /// `ErrorCode.Request.UNSUPPORTED_SIGNATURE_ALGORITHM` (line 205) → SAF_03
    /// (recorded association, line 190). A MISSING algorithm is 600106
    /// (`SIGNATURE_ALGORITHM_NOT_FOUND`, also SAF_03, line 184).
    pub const UNSUPPORTED_ALGORITHM: WireError = WireError {
        af_code: "600107",
        old_code: "SAF_03",
        description: "El algoritmo de firma indicado en la operacion de firma no esta soportado",
    };
    /// `ErrorCode.Internal.INVALID_SIGNING_KEY` (line 91) → SAF_51 "Clave de
    /// firma incompatible" (recorded association, line 232): the code a sede
    /// sees when the key cannot carry the algorithm it asked for.
    pub const INVALID_SIGNING_KEY: WireError = WireError {
        af_code: "200110",
        old_code: "SAF_51",
        description: "La clave de firma no es valida o no es compatible con el algoritmo seleccionado",
    };
    /// `ErrorCode.Internal.UNKNOWN_SIGNING_ERROR` (line 96) → SAF_03 in the
    /// recorded table ("Codigos sin asociacion directa, pero que se devolvian
    /// antes", line 270). NOT SAF_09: SAF_09 is the SIGNING_FAILED pair — a
    /// first mapping here read it off the `ERRORS` name instead of the
    /// association map.
    pub const SIGNING_FAILED: WireError = WireError {
        af_code: "200115",
        old_code: "SAF_03",
        description: "Error desconocido durante la operacion de firma",
    };
    /// `SimpleErrorCode.Internal.UNKNOWN_SELECTING_CERT_ERROR` (line 20) →
    /// SAF_03, the same unlisted-codes group, recorded at line 271.
    pub const SELECT_CERT_FAILED: WireError = WireError {
        af_code: "200201",
        old_code: "SAF_03",
        description: "Error desconocido durante la operacion de seleccion de certificado",
    };
    /// `KeyStoreErrorCode.Internal.LOADING_KEYSTORE_INTERNAL_ERROR`
    /// (KeyStoreErrorCode.java:15) → SAF_08 "Error accediendo al almacen de
    /// claves y certificados" (recorded association, line 196). PKCS#12 detail
    /// code `201110` exists for the same store failure; the launcher answers
    /// the generic one it records here.
    pub const KEYSTORE_ERROR: WireError = WireError {
        af_code: "201101",
        old_code: "SAF_08",
        description: "Error generico al cargar el almacen de certificados",
    };
    /// `ErrorCode.Internal.LOADING_DATA_ERROR` → SAF_00 "No se han podido leer
    /// los datos a firmar" (recorded association, line 153). A `dat` payload
    /// that will not decode is exactly this load failure; the catalogue spells
    /// its number 2006xx range, and its user text comes from SAF_00's entry —
    /// both halves recorded, none invented.
    pub const DATA_LOAD_FAILED: WireError = WireError {
        af_code: "200600",
        old_code: "SAF_00",
        description: "Error general durante la operacion de carga de fichero",
    };
    /// `ErrorCode.Internal.UNSUPPORTED_HASH_ALGORITHM` (line 98). Unmapped in
    /// the recorded table, so pre-4.1 callers get SAF_53 "Error desconocido"
    /// (the fallback at line 341 of the error manager), and openfirma answers
    /// the same fallback rather than inventing a pair.
    pub const UNSUPPORTED_HASH_ALGORITHM: WireError = WireError {
        af_code: "200118",
        old_code: "SAF_53",
        description: "No se soporta un algoritmo de hash establecido internamente",
    };
    /// `SimpleErrorCode.Request.UNSUPPORTED_PROTOCOL_VERSION` (line 116) →
    /// SAF_21 "Version del procedimiento no soportada" (recorded association,
    /// line 275). openfirma's refusal of a minimum-version it does not meet
    /// answers this pair.
    pub const UNSUPPORTED_PROTOCOL_VERSION: WireError = WireError {
        af_code: "620011",
        old_code: "SAF_21",
        description: "Version de protocolo de comunicacion con el navegador no soportada",
    };
}

impl WireError {
    /// The AutoFirma wire text for a 4.1-or-newer caller: prefix by kind
    /// (cancellations are `err-11:=`, everything else `err-00:=` — recorded in
    /// `getErrorMessage`: the prefix depends ONLY on the code being the
    /// cancellation one), then `AF` + six digits, then `" - "`, then the
    /// description. autoscript.js reads exactly those 8 characters before the
    /// separator (lines 2642-2659: the separator sits at index 8 of what follows `:=`, `indexOf(" - ") != 8` keeps it as prose otherwise).
    pub fn wire_new(&self) -> String {
        let prefix = if matches!(self.af_code, "500001") {
            "err-11:="
        } else {
            "err-00:="
        };
        format!("{prefix}AF{} - {}", self.af_code, self.description)
    }

    /// The pre-4.1 form: `SAF_xx: <message from the ERRORS table>` — where the
    /// message is SAF_xx's entry in `ERRORS` (protocolmessages_es_ES), NOT the
    /// catalogue description, which only the 4.1+ form quotes; and for a
    /// cancellation literally `CANCEL` (the CANCEL_RESPONSE branch returns the
    /// code itself with no message).
    pub fn wire_old(&self) -> String {
        if matches!(self.af_code, "500001") {
            return "CANCEL".to_string();
        }
        format!("{}: {}", self.old_code, self.legacy_message())
    }

    /// The `ERRORS`-table text of the entry's SAF_xx key (recorded from
    /// protocolmessages_es_ES.properties through ErrorManager lines 103-146).
    /// An SA_F53-carrying entry quotes SAF_53's message, matching the fallback
    /// `getErrorMessage` takes for an unmapped code.
    fn legacy_message(&self) -> &'static str {
        match self.old_code {
            "SAF_00" => "No se han podido leer los datos a firmar",
            "SAF_01" => "La URL recibida es nula",
            "SAF_02" => "Protocolo no soportado",
            "SAF_03" => "Error en los parametros de entrada",
            "SAF_04" => {
                "Operacion no soportada. Compruebe que dispone de la ultima version de Autofirma."
            }
            "SAF_06" => "Formato de firma no soportado",
            "SAF_08" => "Error accediendo al almacen de claves y certificados",
            "SAF_09" => "Error realizando la firma electronica",
            "SAF_21" => "Version del procedimiento no soportada",
            "SAF_46" => "Id de sesion invalido",
            "SAF_53" => "Error desconocido",
            // Every SAF_xx this table can name is listed above; anything else
            // falls to SAF_53's text, the error manager's own fallback.
            _ => "Error desconocido",
        }
    }
}

impl BrowserError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        // A refusal that does not name its AutoFirma counterpart is a generic
        // malformed-parameters error — the one shape every protocol version
        // agrees on. Call sites with an exact counterpart construct through
        // `with_wire` instead; new refusals must choose deliberately.
        Self::with_wire(WireError::MALFORMED_SOCKET_PARAMS, code, message)
    }

    pub fn with_wire(wire: WireError, code: &'static str, message: impl Into<String>) -> Self {
        BrowserError {
            code,
            message: message.into(),
            wire,
        }
    }

    /// The AutoFirma error wire form for a given protocol version. 4.1+ (and
    /// every caller that never announced an older one — `WireTarget`) gets the
    /// new shape; below that the legacy `SAF_xx` text.
    pub fn wire(&self, target: WireTarget) -> String {
        match target {
            WireTarget::Protocol41Plus => self.wire.wire_new(),
            WireTarget::Legacy => self.wire.wire_old(),
        }
    }
}

/// Which error wire form a call expects, decided from its protocol version
/// exactly like `getErrorMessage` decides (see [`WireError`] for the source).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireTarget {
    Protocol41Plus,
    Legacy,
}

/// Resolving the target from an operation's protocol parameters. AutoFirma's
/// own fallback chain (`getVersion` → VERSION_0 on absent/broken `v`) would map
/// a bare scheme call onto LEGACY — but a legacy answer only exists to serve
/// autoscript clients older than 1.10, whose pages cannot read `AFxxxxxx` at
/// all. A URI with NO version parameter announces nothing; openfirma answers it
/// the way AutoFirma answers an autoscript-1.10 client (which always sends
/// `ver=4`, upgraded in-memory to 4.1 by `reviewProtocolVersion`): modern form.
/// Only a URI that EXPLICITLY names a version below 4.1 — v/ver of "4", "3",
/// "2", "1" or a broken value (AutoFirma's VERSION_0 fallback) — is answered in
/// the legacy text, because then the page has told us it lives down there. The
/// deviation from AutoFirma's mapping of an *absent* `ver` is deliberate and
/// recorded here: absent means "unknown client", and an unknown client gets the
/// same form every current page uses; a sede that pins v= still gets its form.
pub fn wire_target(protocol_version: Option<&str>) -> WireTarget {
    match protocol_version {
        None => WireTarget::Protocol41Plus,
        Some(text) if ProtocolVersion::parse(text).supports_error_codes() => {
            WireTarget::Protocol41Plus
        }
        Some(_) => WireTarget::Legacy,
    }
}

/// Execute a browser call delivered as one loopback endpoint body. The body
/// never travelled through a URI hand-off, so the channel cap does not apply
/// to it — only the document-size caps do. The refusal stays a structured
/// `BrowserError`: the version that selects the wire form is re-read from the
/// body by `serve.rs`'s single error writer (`endpoint_message_version`, same
/// extraction rule), so no caller ever receives pre-rendered text it could
/// second-guess (finding M-2's one door). The scheme-hand-off variant, if a
/// CLI ever needs it again, is `parse` + `execute` in the caller's hands.
pub fn handle_endpoint_body(
    body: &[u8],
    key: &KeySource<'_>,
) -> Result<BrowserResult, BrowserError> {
    let parsed = crate::uri::parse_endpoint_body(body)?;
    execute(&parsed, key)
}

/// Execute one parsed URI with a consent policy in play (finding A-3). This is
/// what the browser handler and the loopback endpoint run: an unattended key
/// only signs when its owner opted it in or the consent callback approved the
/// operation summary (and supplied the password when the key has none).
pub fn execute_with_consent(
    uri: &AfirmaUri,
    key: &KeySource<'_>,
    consent: Consent<'_>,
) -> Result<BrowserResult, BrowserError> {
    // Same gate as `execute`: refuse by name before anything asks the key.
    execute_gate(uri)?;
    let signer = match key {
        // A P12 arrives consented: the caller held the container's password and
        // handed it over, which is the whole of what a prompt would establish
        // (04-N6: the CLI's argv key takes this arm and signs without asking,
        // even on a tty — argv IS the yes). The prompt below belongs to the
        // Unattended door, whose key has no such vouching behind it.
        KeySource::P12 { path, password } => load_p12(path, Some(password))?,
        KeySource::Unattended(u) => {
            let summary = summarize(uri);
            let needs_password = u.password.is_none();
            if !u.allow_unattended && !matches!(consent, Consent::Prompt(_)) {
                // Granted (or any consent that cannot ask a human) without the
                // owner's opt-in is not authority to sign quietly.
                return Err(BrowserError::with_wire(
                    WireError::UNSUPPORTED_OPERATION,
                    "consent-required",
                    format!(
                        "the key {} may not sign a browser call without the user's \
                         consent and has no allow_unattended opt-in: openfirma never \
                         signs quietly (see docs/adr/0005-browser-protocol.md)",
                        u.path.display()
                    ),
                ));
            }
            // With the opt-in AND a stored password, nothing needs asking; any
            // other combination runs through the prompt. `Granted` never
            // supplies a missing secret: an owner opt-in cannot conjure the
            // PIN AutoFirma's dialog would ask for.
            let skip_prompt = u.allow_unattended && !needs_password;
            let password: Option<zeroize::Zeroizing<String>> = if skip_prompt {
                None
            } else {
                match &consent {
                    Consent::Prompt(prompt) => match prompt.approve(&summary, needs_password)? {
                        ConsentAnswer::No => {
                            return Err(user_cancelled());
                        }
                        ConsentAnswer::Yes { password } => {
                            if needs_password && password.is_none() {
                                // The user agreed but the secret never arrived;
                                // AutoFirma's dialog would have retried or failed —
                                // a refusal naming the reason beats guessing none.
                                return Err(BrowserError::with_wire(
                                    WireError::KEYSTORE_ERROR,
                                    "keystore-error",
                                    format!(
                                        "no password was provided for {} and it is \
                                         required to open it",
                                        u.path.display()
                                    ),
                                ));
                            }
                            password
                        }
                    },
                    Consent::Granted => None,
                }
            };
            // A prompt may answer Yes without a password when the key already
            // stores one (consent alone, no new secret); in every other case
            // the callback's password — or the stored one — opens the PKCS#12.
            let effective = match &password {
                Some(p) => Some(p.as_str()),
                None => u.password,
            };
            load_p12(
                u.path,
                Some(effective.ok_or_else(|| {
                    BrowserError::with_wire(
                        WireError::KEYSTORE_ERROR,
                        "keystore-error",
                        format!(
                            "{} needs a password and none was available",
                            u.path.display()
                        ),
                    )
                })?),
            )?
        }
    };
    execute_with(uri, &*signer)
}

/// Runs one parsed URI against an already-resolved signer (the consent gate,
/// when there is one, lives in [`execute_with_consent`]).
fn execute_with(uri: &AfirmaUri, signer: &dyn Signer) -> Result<BrowserResult, BrowserError> {
    match uri.operation {
        // Certificate selection answers the leaf DER base64-url on its own
        // (`ProtocolInvocationLauncherSelectCert`, line 234).
        Operation::SelectCert => Ok(BrowserResult {
            payload: base64_url(signer.certificate().der()),
            kind: ResultKind::CertificateSelected,
        }),
        _ => sign_from_uri(uri, signer),
    }
}

/// A user saying "no" is AutoFirma's cancellation everywhere: the new wire
/// answers `err-11:=AF500001 - …`, old protocol answers plain `CANCEL`.
fn user_cancelled() -> BrowserError {
    BrowserError::with_wire(
        WireError::CANCELLED,
        "cancelled",
        "the operation was cancelled at the confirmation prompt",
    )
}

/// The consent summary for one parsed call (what the prompt shows): operation,
/// app name, digest and size of exactly the bytes that will be signed. A
/// pre-computed-hash call signs THAT hash as its message imprint, so the
/// summary digests the payload as delivered — the same bytes a sede sent —
/// while stating the mode in `operation` so the user reads "sign CAdES-B-B
/// (pre-computed SHA-1 hash)" and not a lie.
pub fn summarize(uri: &AfirmaUri) -> OperationSummary {
    let prehash = prehash_digest(&uri.properties);
    let operation = match uri.operation {
        Operation::SelectCert => "select certificate".to_string(),
        Operation::Sign => match (uri.format.as_deref(), prehash) {
            (Some(f), Some(alg)) => format!("sign {f} (pre-computed {} hash)", alg.name()),
            (Some(f), None) => format!("sign {f}"),
            (None, _) => "sign".to_string(),
        },
        op => op.name().to_string(),
    };
    let app_name = uri
        .app_name
        .clone()
        .or_else(|| uri.properties.get("appname").map(str::to_string))
        .unwrap_or_default();
    let document_digest = match &uri.data {
        Some(d) => hex::encode(DigestAlg::Sha256.digest(d)),
        None => "no document".to_string(),
    };
    OperationSummary {
        operation,
        app_name,
        document_digest,
        document_len: uri.data.as_ref().map(|d| d.len()).unwrap_or(0),
    }
}

/// The properties key that turns a payload into a pre-computed message imprint
/// (`CAdESExtraParams.PRECALCULATED_HASH_ALGORITHM`, `CAdESExtraParams.java:28`
/// — recorded from 1.9.1 sources), or None when absent. Shared by the summary
/// (it must tell the truth about what gets signed) and by signing itself.
fn prehash_digest(props: &crate::uri::Properties) -> Option<DigestAlg> {
    let text = props.get("precalculatedHashAlgorithm")?;
    // AutoFirma's own mapping (`CAdESParameters.load` feeds the value through
    // `AOSignConstants.getDigestAlgorithmName`): "SHA-1"/"SHA1"/"SHA-256"… all
    // read as the same algorithm name.
    digest_name(text)
}

/// The gate of refusals a call must pass BEFORE anything is asked of the key:
/// unsupported operations (cosign/countersign — no golden yet), the storage
/// servlet route (openfirma never posts, finding M-5), and every `properties`
/// member openfirma does not implement (finding A-4: an extraParams decision is
/// a decision about WHAT gets signed, and it must be refused by name even when
/// the keystore does not exist). Pure over the parsed URI, so every entry point
/// runs it first — `execute`, `execute_with_consent` — and no key is ever
/// opened for a call that cannot be honoured.
fn execute_gate(uri: &AfirmaUri) -> Result<(), BrowserError> {
    if uri.operation != Operation::Sign && uri.operation != Operation::SelectCert {
        return Err(BrowserError::with_wire(
            WireError::UNSUPPORTED_OPERATION,
            "unsupported-operation",
            format!(
                "{} over the browser protocol needs its own golden first: openfirma signs but \
                 does not yet co-sign or counter-sign through a browser call, see \
                 docs/adr/0005-browser-protocol.md",
                uri.operation.name()
            ),
        ));
    }
    if uri.storage_callback {
        return Err(BrowserError::with_wire(
            WireError::UNSUPPORTED_OPERATION,
            "storage-route-unsupported",
            "the stservlet parameter says the sede expects the result at its storage \
             service; openfirma never posts to servers (docs/adr/0005-browser-protocol.md), \
             so this call can only fail — and fails here instead of signing without \
             delivering anything",
        ));
    }
    apply_properties(uri)
}

/// Runs one parsed URI against an already-resolved signer; the consent gate is
/// the caller's (see [`execute_with_consent`]).
pub fn execute(uri: &AfirmaUri, key: &KeySource<'_>) -> Result<BrowserResult, BrowserError> {
    // Property/storage/operation gates refuse by name before the keystore is
    // opened: a decision about WHAT gets signed never depends on the key being
    // readable (finding A-4). `execute_with` runs the gate; running it here
    // first would load a key for a call that cannot be honoured.
    execute_gate(uri)?;
    let key_source_signer = match key {
        KeySource::P12 { path, password } => load_p12(path, Some(password))?,
        // A headless key without an explicit opt-in never signs through a bare
        // `execute` either: the consent rule is about what reaches this crate's
        // dispatch, and forgetting it in one of two entry points is exactly how
        // finding A-3 happened the first time.
        KeySource::Unattended(u) if u.allow_unattended => load_p12(u.path, u.password)?,
        // A non-interactive `execute` of a key without the opt-in: the same
        // refusal either way. The difference between the two shapes would
        // invite exactly the caller bug this finding is about (treating "no
        // password yet" as "no consent needed"). Consent belongs to
        // `execute_with_consent`.
        KeySource::Unattended(u) => {
            return Err(BrowserError::with_wire(
                WireError::UNSUPPORTED_OPERATION,
                "consent-required",
                format!(
                    "the key {} may not sign a browser call without the user's consent \
                     (no allow_unattended opt-in and no consent callback at this entry \
                     point; see docs/adr/0005-browser-protocol.md)",
                    u.path.display()
                ),
            ));
        }
    };
    execute_with(uri, &*key_source_signer)
}

fn load_p12(path: &Path, password: Option<&str>) -> Result<Box<dyn Signer>, BrowserError> {
    let bytes = std::fs::read(path).map_err(|e| {
        BrowserError::with_wire(
            WireError::KEYSTORE_ERROR,
            "keystore-unreadable",
            format!("cannot read {}: {e}", path.display()),
        )
    })?;
    let container = Pkcs12::load(
        &bytes,
        password.ok_or_else(|| {
            BrowserError::with_wire(
                WireError::KEYSTORE_ERROR,
                "keystore-error",
                format!(
                    "{} needs a password none was given: openfirma asks the user for it, \
                     it does not guess one",
                    path.display()
                ),
            )
        })?,
    )
    .map_err(|e| {
        BrowserError::with_wire(
            WireError::KEYSTORE_ERROR,
            "keystore-error",
            format!("{} is not a readable PKCS#12: {e}", path.display()),
        )
    })?;
    let entry = container
        .entry(None)
        .map_err(|e| BrowserError::new("keystore-ambiguous", e.to_string()))?;
    let leaf = CertificateHandle::from_der(&entry.chain[0]).map_err(|e| {
        BrowserError::with_wire(
            WireError::KEYSTORE_ERROR,
            "keystore-error",
            format!("the PKCS#12 leaf is not a valid certificate: {e}"),
        )
    })?;
    let mut chain = Vec::with_capacity(entry.chain.len().saturating_sub(1));
    for der in &entry.chain[1..] {
        chain.push(
            CertificateHandle::from_der(der)
                .map_err(|e| BrowserError::new("keystore-error", e.to_string()))?,
        );
    }
    let signer = SoftwareSigner::from_pkcs8_der(leaf.der(), &entry.key_pkcs8).map_err(|e| {
        BrowserError::with_wire(
            WireError::INVALID_SIGNING_KEY,
            "keystore-error",
            format!("the PKCS#12 key does not match its certificate: {e}"),
        )
    })?;
    Ok(Box::new(signer.with_chain(chain)))
}

/// The format strings a page sends (`AOSignConstants`), mapped to what this
/// client produces. Finding M-4: an exact table, matched on the WHOLE name —
/// the old code took everything before the first `-`, so `CAdES-ASiC-S` became
/// plain CAdES and a sede received "the thing it asked for" in a shape it did
/// not ask for. Formats AutoFirma has and openfirma cannot produce are refused
/// BY NAME (AutoFirma's own behaviour when its signer map misses:
/// `AOSignerFactory.getSigner` returns null and the launcher answers 600105).
///
/// The names below were recorded from `AOSignConstants.java` (all spellings)
/// and `AOSignerFactory.SIGNERS_CLASSES` (which spelling reaches which signer):
/// every alternative that reaches a NON-trifásica signer is accepted; trifásica,
/// ASiC-S, FacturaE, ODF/OOXML and SOAP are refused because openfirma's
/// signature code cannot produce those shapes and their server-side partners do
/// not exist for it (ADR-0005). `auto` resolves by content like AutoFirma's
/// `ProtocolInvocationLauncherUtil.identifyFormatFromData` — PDF → PAdES, XML →
/// XAdES, anything else CAdES.
fn resolve_format(text: &str) -> Result<Format, BrowserError> {
    // Case-insensitive whole-name matching is AutoFirma's rule: its factory
    // compares `format[0].equalsIgnoreCase(signFormat)` (AOSignerFactory.java:160).
    let eq = |name: &str| text.trim().eq_ignore_ascii_case(name);
    if eq("auto") {
        return Ok(Format::Auto);
    }
    // CAdES family spellings that reach the CAdES signer. "CMS/PKCS#7" reaches
    // a CMS signer of its own in AutoFirma whose output openfirma has never
    // golden-compared, so it is refused below rather than silently signed as
    // CAdES — a refusal the sede can act on beats a signature of another shape.
    if eq("CAdES") {
        return Ok(Format::Cades);
    }
    // PAdES family: "PAdES", "Adobe PDF" (and AutoFirma's other spelling of the
    // same signer).
    if eq("PAdES") || eq("Adobe PDF") || eq("PDF") {
        return Ok(Format::Pades);
    }
    // XAdES family. AutoFirma's map sends "XAdES", "XAdES Detached",
    // "XAdES Enveloped" and "XAdES Enveloping" to ONE signer (the mode is what
    // distinguishes their output); openfirma currently produces the enveloped
    // baseline shape only, so the spellings whose output it cannot guarantee —
    // Detached/Enveloping — are refused by name rather than answered with an
    // Enveloped signature nobody asked for (the M-4 bug in its other direction:
    // accepting a name and then not honouring it is worse than refusing it).
    if eq("XAdES") {
        return Ok(Format::Xades);
    }
    let refused = |note: &str| {
        Err(BrowserError::with_wire(
            WireError::UNSUPPORTED_FORMAT,
            "unsupported-format",
            format!(
                "the format {text:?} cannot be served: {note} (openfirma produces CAdES, PAdES \
                 and XAdES through the browser protocol; unknown names are refused, never \
                 downgraded: docs/adr/0005-browser-protocol.md)"
            ),
        ))
    };
    if eq("XAdES Detached")
        || eq("XAdES Externally Detached")
        || eq("XAdES Enveloped")
        || eq("XAdES Enveloping")
    {
        // "XAdES Enveloped" is what openfirma's XAdES actually IS (docs/xades.md);
        // AutoFirma spells the default nameless, so a sede that named this one
        // gets our shape — refusing it while accepting "XAdES" would be the same
        // silent-wrongness finding M-4 complained about, in reverse.
        if eq("XAdES Enveloped") {
            return Ok(Format::Xades);
        }
        return refused("openfirma's XAdES is enveloped only and cannot answer this mode");
    }
    if text.eq_ignore_ascii_case("CAdES-ASiC-S") || eq("XAdES-ASiC-S") {
        return refused(
            "the ASiC container levels need their document packaging, which openfirma does not produce yet",
        );
    }
    if eq("CAdEStri")
        || eq("PAdEStri")
        || eq("XAdEStri")
        || eq("Adobe PDF TriPhase")
        || eq("CAdES-ASiC-S-tri")
        || eq("XAdES-ASiC-S-tri")
    {
        return refused("the trifásica flow needs its presign/post-sign servers");
    }
    if eq("CMS/PKCS#7")
        || eq("FacturaE")
        || eq("Factura-e")
        || eq("FacturaEtri")
        || eq("ODF")
        || eq("ODF (Open Document Format)")
        || eq("OOXML")
        || eq("OOXML (Office Open XML)")
        || eq("SOAP")
    {
        return refused("that format's signature shape is one openfirma does not produce");
    }
    refused("it is not one of AutoFirma's format names")
}

#[derive(Clone, Copy)]
enum Format {
    Cades,
    Pades,
    Xades,
    /// Resolved by document content at signing time, like AutoFirma's
    /// `identifyFormatFromData`: PDF → PAdES, XML → XAdES, else CAdES.
    Auto,
}

/// The request the protocol builds for one format name — the exact front door
/// both `execute` paths walk through, so a sede's format= text and the shared
/// table can never again mean different signatures (finding M-4). This is what
/// every browser signing call goes through: dispatch resolves the wire name
/// here, fills in the digest parameter, and hands the request to
/// `crate::signing`.
/// A sede's format name or one of openfirma's own level ids. The protocol's
/// closed table (`resolve_format`) answers the AutoFirma spellings; `signing`'s
/// shared label table answers ours ("cades-b-b", "pades-b-b", …), which real
/// CLI invocations and this crate's tests use. A name neither table knows is
/// refused by both, with its own error.
pub fn protocol_request_for(
    text: &str,
    digest: openfirma_core::alg::DigestAlg,
) -> Result<crate::signing::SignRequest<'static>, BrowserError> {
    // The protocol's wire names first: they are what a sede sends, and none of
    // them is a shared-table id, so the order cannot shadow one.
    let mut req = match resolve_format(text) {
        Ok(format) => protocol_request_for_format(format),
        Err(protocol_err) => {
            // openfirma's own level ids ("cades-b-b", …): the same closed table
            // every UI lists, so a test or CLI-shaped call through this front
            // door reaches exactly the request that table means.
            match crate::signing::all_formats()
                .iter()
                .find(|label| label.eq_ignore_ascii_case(text))
            {
                Some(l) => crate::signing::SignRequest::new(l, digest),
                None => return Err(protocol_err),
            }
        }
    };
    req.digest = digest;
    Ok(req)
}

fn protocol_request_for_format(format: Format) -> crate::signing::SignRequest<'static> {
    crate::signing::SignRequest::new(
        match format {
            Format::Cades => "cades-b-b",
            Format::Pades => "pades-b-b",
            Format::Xades => "xades-b-b",
            // `auto` cannot be a shared-table id: the resolution needs the
            // document, which signing has and this table lookup does not.
            // resolve_format's callers never hand Auto here except through
            // sign_from_uri, which resolves first.
            Format::Auto => "cades-b-b",
        },
        // The digest is the protocol's other parameter; the request starts at
        // the shared default and resolve_algorithm overwrites it.
        openfirma_core::alg::DigestAlg::Sha256,
    )
}

/// The `algorithm` list of AutoFirma's protocol — recorded from
/// `UrlParametersToSign.SUPPORTED_SIGNATURE_ALGORITHMS` (the literal twelve
/// entries: SHA1/256/384/512 bare and withRSA / withECDSA, no other spelling).
/// Finding B-3: the old code took everything before "with" and accepted
/// `SHA256withFOO`, lower case, and `SHA256withECDSA` against an RSA key.
/// AutoFirma's membership test is EXACT (the set above), and the signature it
/// then builds comes from that same string, so a mismatch between algorithm and
/// key fails there too. openfirma matches exactly, treats bare names the way
/// AutoFirma does after its `getDigestAlgorithmName` step (a bare SHAxxx is a
/// digest hint only; AutoFirma's signers then pick RSA/ECDSA from the key), and
/// refuses an explicit withRSA/withECDSA that contradicts the loaded key.
fn resolve_algorithm(text: &str, key_alg: Option<KeyAlgorithm>) -> Result<DigestAlg, BrowserError> {
    const LIST: [&str; 12] = [
        "SHA1",
        "SHA256",
        "SHA384",
        "SHA512",
        "SHA1withRSA",
        "SHA256withRSA",
        "SHA384withRSA",
        "SHA512withRSA",
        "SHA1withECDSA",
        "SHA256withECDSA",
        "SHA384withECDSA",
        "SHA512withECDSA",
    ];
    let known = LIST.contains(&text);
    if !known {
        return Err(BrowserError::with_wire(
            WireError::UNSUPPORTED_ALGORITHM,
            "unsupported-algorithm",
            format!(
                "the algorithm {text:?} is not one AutoFirma's protocol lists (SHA1/SHA256/\
                 SHA384/SHA512, bare or withRSA/withECDSA, exactly those twelve spellings)"
            ),
        ));
    }
    // AutoFirma normalises the accepted name through `getDigestAlgorithmName`,
    // whose SHA1 branch matches a name STARTING with "SHA1"/"SHA-1" (recorded
    // above: `"SHA1".equals || upper.startsWith("SHA1") … → "SHA1"`), so after
    // dropping the `with…` half, both bare names and their prefixes reach the
    // right digest. Every name on the closed list above resolves here; nothing
    // else can (the membership test ran first).
    let compact = text
        .replace("with", "")
        .trim()
        .replace('-', "")
        .to_ascii_uppercase();
    let digest = if compact.starts_with("SHA512") {
        DigestAlg::Sha512
    } else if compact.starts_with("SHA384") {
        DigestAlg::Sha384
    } else if compact.starts_with("SHA256") {
        DigestAlg::Sha256
    } else if compact.starts_with("SHA1") || compact == "SHA" {
        DigestAlg::Sha1
    } else {
        unreachable!("resolve_algorithm only reaches here with a name from the closed list")
    };
    // The key half only contradicts when BOTH sides named one: AutoFirma's
    // `SHA256withECDSA` against an RSA certificate reaches Cipher.getSignature
    // ("SHA256withRSA and EC key" style failures) — i.e. it refuses; the bare
    // name carries no claim to contradict, and there the key decides alone.
    if let (Some(key), Some(claimed)) = (key_alg, text.split_once("with")) {
        let wants_rsa = claimed.1.eq_ignore_ascii_case("RSA");
        let wants_ec = claimed.1.eq_ignore_ascii_case("ECDSA");
        let ok = match key {
            KeyAlgorithm::Rsa => wants_rsa,
            KeyAlgorithm::EcPrimeField(_) => wants_ec,
        };
        if !ok {
            return Err(BrowserError::with_wire(
                WireError::INVALID_SIGNING_KEY,
                "algorithm-mismatch",
                format!(
                    "the algorithm {text:?} names {} but the signing key is {key:?}",
                    if wants_rsa { "RSA" } else { "ECDSA" }
                ),
            ));
        }
    }
    Ok(digest)
}

/// `AOSignConstants.getDigestAlgorithmName` on the algorithm-shape names:
/// accept "SHA-256"/"SHA256"/case-insensitive, refuse anything else.
fn digest_name(text: &str) -> Option<DigestAlg> {
    match text.trim().replace('-', "").to_ascii_uppercase().as_str() {
        "SHA1" => Some(DigestAlg::Sha1),
        "SHA256" => Some(DigestAlg::Sha256),
        "SHA384" => Some(DigestAlg::Sha384),
        "SHA512" => Some(DigestAlg::Sha512),
        _ => None,
    }
}

fn sign_from_uri(uri: &AfirmaUri, signer: &dyn Signer) -> Result<BrowserResult, BrowserError> {
    // The gates (operation, storage route, properties) ran in `execute_gate`
    // before the key was touched; see findings A-4 and M-5.
    let content = match uri.data.as_deref() {
        Some(data) if !data.is_empty() => data,
        // AutoFirma's own name for a sign call carrying no data: 600100 /
        // SAF_03 (ErrorCode.Request.DATA_NOT_FOUND). A pre-4.1 caller reads
        // "SAF_03: Error en los parametros de entrada" — the exact text the
        // recorded ERRORS table answers for that shape.
        //
        // 04-N9: `dat=` and no `dat` at all are one refusal, not two. An empty
        // value decodes to zero bytes, which every frontend below will happily
        // sign: the result is a structurally valid signature over nothing, and
        // it opens in a viewer as a document the user never signed. A page that
        // sent `dat=` meant a payload it failed to attach; the honest answer is
        // the one its own protocol has for a missing one. Nothing legitimately
        // wants the empty document signed through this door — a caller that
        // really has zero bytes to sign is signing a file, and says so.
        Some(_) => {
            return Err(BrowserError::with_wire(
                WireError::DATA_NOT_FOUND,
                "empty-data",
                "a sign call arrived with an EMPTY dat payload (`dat=`): the zero-byte \
                 document is not what its sender meant, and signing it would answer with \
                 a signature over nothing",
            ));
        }
        None => {
            return Err(BrowserError::with_wire(
                WireError::DATA_NOT_FOUND,
                "missing-data",
                "a sign call arrived without a dat payload",
            ));
        }
    };
    // AutoFirma requires both parameters (setSignParameters throws on each
    // miss), so the refusal here is its own behaviour, not ours.
    let format_text = uri.format.as_deref().ok_or_else(|| {
        BrowserError::with_wire(
            WireError::UNSUPPORTED_FORMAT,
            "format-missing",
            "no format parameter: AutoFirma's protocol requires one and so does this client",
        )
    })?;
    let algo_text = uri.algorithm.as_deref().ok_or_else(|| {
        BrowserError::with_wire(
            WireError::UNSUPPORTED_ALGORITHM,
            "algorithm-missing",
            "no algorithm parameter: AutoFirma's protocol requires one and so does this client",
        )
    })?;
    // A name the closed table refuses is tried against openfirma's own level
    // ids (the same fallthrough `protocol_request_for` performs): a call shaped
    // like the CLI's — "cades-b-b", in any spelling — reaches exactly the
    // request that table means instead of dying on the wire-name list. The
    // protocol error is kept for names neither table knows.
    let format = match resolve_format(format_text) {
        Ok(Format::Auto) => Format::Auto,
        Ok(other) => other,
        Err(protocol_err) => {
            let id = crate::signing::all_formats()
                .iter()
                .find(|id| id.eq_ignore_ascii_case(format_text.trim()))
                .ok_or(protocol_err)?;
            match *id {
                "cades-b-b" => Format::Cades,
                "pades-b-b" | "pades-b-lt" | "pades-b-lta" => Format::Pades,
                _ => Format::Xades,
            }
        }
    };
    // `auto` resolves on the bytes exactly like AutoFirma's AUTO (finding M-3):
    // PDF → PAdES, FacturaE refused by name (openfirma has no FacturaE), XML →
    // XAdES, anything else CAdES. A PDF asked as format=AUTO therefore signs as
    // PAdES instead of dying on the file-shape gate.
    //
    // Whether the caller asked for `auto` has to survive this match, because
    // the resolved shape is what the REQUEST must be built from (04-N2): the
    // raw text went back through `protocol_request_for`, whose table entry for
    // Auto is CAdES, so a PDF or an XML asked as `auto` was signed as a
    // detached CMS — while the answer, and the CLI's own line, named the
    // resolved shape. Both halves now come from one resolution.
    let asked_auto = matches!(format, Format::Auto);
    let format = match format {
        Format::Auto => {
            if content.starts_with(b"%PDF-") {
                Format::Pades
            } else if openfirma_core::workflow::Format::detect(content)
                == openfirma_core::workflow::Format::Xml
            {
                Format::Xades
            } else {
                Format::Cades
            }
        }
        other => other,
    };
    let digest = resolve_algorithm(algo_text, signer.key_algorithm().ok())?;

    // A call against a certificate whose key cannot use that digest is refused
    // the same way `sign` refuses it (SignatureAlg::for_key).
    signer.signature_alg(digest).map_err(|e| {
        BrowserError::with_wire(
            WireError::INVALID_SIGNING_KEY,
            "algorithm-mismatch",
            format!("the algorithm {algo_text:?} does not fit this certificate: {e}"),
        )
    })?;

    // The browser protocol is one more frontend over the ONE dispatcher
    // (finding M-4): a sede's format= names the shared shape, and everything
    // else — options, refusals, label table — is `crate::signing`'s. Its own
    // level ids ("pades-b-lt") go through the raw-text door so the level the
    // caller named is the level that gets built; `auto` goes through the
    // resolution above, which is the only place the document is known.
    let mut req = if asked_auto {
        protocol_request_for_format(format)
    } else {
        protocol_request_for(format_text, digest)?
    };
    req.digest = digest;
    // `precalculatedHashAlgorithm` was applied to the request before anything
    // read the payload: it names the hash algorithm that produced `dat`, and by
    // AutoFirma's rule (`CAdESParameters.load`) that algorithm IS the
    // signature's digest algorithm.
    if let Some(hash_alg) = prehash_digest(&uri.properties) {
        req.digest = hash_alg;
    }
    // M-3: a sede asks for CAdES over a PDF every day (a detached container
    // around any bytes is legal), and AutoFirma signs it — the launcher never
    // filters formats by file type, only the GUI does. The protocol therefore
    // calls the SHARED dispatcher without the file-shape gate (`execute_protocol`
    // → `dispatch`). A PAdES request over non-PDF still fails inside
    // openfirma-pades for its own real reason; a CAdES or XAdES request no
    // longer dies on a detection built for the GUI's menus. And A-4: a call
    // carrying a pre-computed hash runs through the imprint entry point, which
    // only accepts the CAdES shape that can honestly carry one.
    let produced: Vec<u8> = match prehash_digest(&uri.properties) {
        Some(hash_alg) => {
            // The algorithm half of AutoFirma's precalculated rule was applied
            // above (req.digest = hash_alg). The format half is checked here by
            // dispatch_prehashed_cades, whose refusal names itself.
            if digest != hash_alg {
                // A sede that names SHA256withRSA in `algorithm` while hashing
                // the payload with another algorithm under
                // precalculatedHashAlgorithm: AutoFirma signs with the HASH's
                // algorithm — recorded, and openfirma follows it; the mismatch
                // is worth a log because a sede making it has two ideas about
                // what it asked for.
                eprintln!(
                    "openfirma: the properties precalculatedHashAlgorithm={hash_alg:?} \
                     overrides the URI's algorithm {algo_text:?}, as AutoFirma does"
                );
            }
            crate::signing::dispatch_prehashed_cades(&mut req, content, signer).map_err(map_core)?
        }
        None => crate::signing::execute_protocol(&mut req, content, signer).map_err(map_core)?,
    };

    Ok(BrowserResult {
        payload: sign_response(signer.certificate(), &produced),
        kind: ResultKind::Signature {
            // `Format::Auto` cannot reach here: the resolution above replaced
            // it, and it is the same match the request was built from (04-N2),
            // so the format this answer names is the format in the payload.
            format: match format {
                Format::Cades | Format::Auto => "CAdES".to_string(),
                Format::Pades => "PAdES".to_string(),
                Format::Xades => "XAdES".to_string(),
            },
        },
    })
}

/// Every `properties` key AutoFirma's signers read, and openfirma's stance on
/// it. The rule (finding A-4): apply what openfirma produces identically to how
/// AutoFirma would; REFUSE by name anything that changes what gets signed or
/// where the answer goes and is not implemented. Silence is never an option:
/// a key outside this list refuses too, because an unknown key is a sede asking
/// for behaviour nobody verified.
fn apply_properties(uri: &AfirmaUri) -> Result<(), BrowserError> {
    let props = &uri.properties;
    for key in props.keys() {
        let handled = match key {
            // AutoFirma's CAdES signer treats the payload as the message
            // imprint when present; openfirma implements it for the shapes
            // whose CMS signedAttribute can carry an honest imprint (see
            // `prehash_format_ok`). An unreadable algorithm name is NOT a drop:
            // AutoFirma would fail on getDigestAlgorithmName too ("El algoritmo
            // de huella no es valido"), so this refuses rather than sign the
            // payload as a document nobody described.
            "precalculatedHashAlgorithm" => match props.get("precalculatedHashAlgorithm") {
                Some(_) => prehash_digest(props).is_some() && prehash_format_ok(uri),
                None => true,
            },
            // `mode`: AutoFirma's explicit/implicit switches content inclusion.
            // openfirma's protocol default is explicit (detached) already — the
            // shared dispatcher's own default, docs/pades.md — so an explicit
            // "explicit" matches and nothing else can be honoured: implicit
            // would change the container shape the sede expects.
            "mode" => uri
                .properties
                .get("mode")
                .is_none_or(|m| m.eq_ignore_ascii_case("explicit")),
            // serverUrl / presign/post-sign URLs: the trifásica route, refused.
            "serverUrl" | "presignServerUrl" | "postsignServerUrl" => false,
            // Visible PAdES signature geometry (PdfExtraParams): openfirma's
            // protocol path has no appearance yet (the CLI's does); accepting it
            // and skipping the visual would sign something other than what the
            // sede asked for.
            "visiblePdfSignature"
            | "logo"
            | "signaturePositionPage"
            | "signatureBox"
            | "fontSize"
            | "documentName"
            | "observation" => false,
            // policy* (XAdES/CAdES signature policy), filter*, and every other
            // AutoFirma behaviour-changing key: not implemented through this
            // channel yet, so refused.
            _ => false,
        };
        if !handled {
            return Err(BrowserError::with_wire(
                WireError::UNSUPPORTED_FORMAT,
                "properties-unsupported",
                format!(
                    "the properties parameter carries {key:?}, which changes what openfirma \
                     would sign and is not implemented through the browser protocol: a \
                     signature that ignores it would be over bytes or a shape the sede did \
                     not ask for, so this call refuses (finding A-4's rule; AutoFirma would \
                     apply this key)"
                ),
            ));
        }
    }
    Ok(())
}

/// `precalculatedHashAlgorithm` is honoured for CAdES only (the shape whose
/// message imprint the shared dispatcher can carry pre-computed). The decision
/// reads the URI's own format name — AutoFirma's same restriction comes from
/// which signer receives the payload, and openfirma's CAdES is the matching one.
fn prehash_format_ok(uri: &AfirmaUri) -> bool {
    // The shapes that can honestly carry an imprint this client did not
    // compute: AutoFirma's own "CAdES" and "auto" (which resolves to CAdES for
    // the data a sede would pre-hash), and openfirma's closed level ids whose
    // id begins with "cades" — the very table `protocol_request_for` accepts on
    // its fallthrough, so gate and signer read format names through one door.
    let Some(text) = uri.format.as_deref().map(str::trim) else {
        return false;
    };
    if text.eq_ignore_ascii_case("CAdES") || text.eq_ignore_ascii_case("auto") {
        return true;
    }
    crate::signing::all_formats()
        .iter()
        .any(|id| id.eq_ignore_ascii_case(text) && id.starts_with("cades"))
}

fn map_core(e: openfirma_core::Error) -> BrowserError {
    BrowserError::with_wire(WireError::SIGNING_FAILED, "signing-error", e.to_string())
}

/// AutoFirma's sign response: `base64(certificate) | base64(signature)`, both
/// fields URL-safe alphabet, padded, single-line — what
/// `Base64.encode(x, true)` of the shipped jar produces (recorded at the top
/// of this file; finding M-1 corrected the MIME-with-CRLF theory with the jar).
pub fn sign_response(cert: &CertificateHandle, signature: &[u8]) -> Vec<u8> {
    let mut out = base64_url(cert.der());
    out.push(RESULT_SEPARATOR as u8);
    out.extend_from_slice(&base64_url(signature));
    out
}

/// AutoFirma's `Base64.encode(_, true)`: RFC 4648 §5 URL-safe alphabet
/// (`-`/`_`), '=' padding, no line breaks (jar-verified). Every page-side
/// consumer converts `-`/`_` back to `+`/`/` before use (autoscript.js does it
/// in processSignResponse/processSelectCertificateResponse), and AutoFirma's
/// own decoder applies the same fold on input (`Base64.decode`'s URL-safe
/// alphabet), so this form round-trips through everything a real sede is.
pub fn base64_url(bytes: &[u8]) -> Vec<u8> {
    base64::engine::general_purpose::URL_SAFE
        .encode(bytes)
        .into_bytes()
}
