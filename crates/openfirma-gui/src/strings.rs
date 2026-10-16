//! The strings of openfirma's window, in one place (brief rule: every
//! user-visible string lives here).
//!
//! Spanish is the interface language on purpose: this tool signs documents
//! for citizens dealing with a Spanish-government ecosystem, and AutoFirma —
//! what it replaces — ships only in Spanish. English identifiers, comments
//! and docs stay everywhere else.
//!
//! How this would be translated (this module is the whole translation
//! surface): every user-visible text is an entry of [`Tr`], and a second
//! `impl Tr` block would return the same keys with different values — one
//! struct, two constructors (`Tr::es()`, `Tr::en()`), selected at startup
//! from the locale; the widgets already take `&Tr` and never literal text.
//! When a real second language is ever needed, replace this with a tiny
//! generated lookup (a `tr(key)` over const maps) — no widget changes.

/// Every user-visible string of the window.
#[derive(Clone, Debug)]
pub struct Tr {
    pub app_title: String,
    // --- first screen -------------------------------------------------
    pub drop_here: String,
    pub drop_hint: String,
    pub paste_path: String,
    pub browse: String,
    pub verify_verb: String,
    pub sign_verb: String,
    // --- detection ----------------------------------------------------
    pub detected_pdf: String,
    pub detected_xml: String,
    pub detected_data: String,
    pub formats_for: String,
    // --- certificate picker -------------------------------------------
    pub choose_certificate: String,
    pub no_certificates: String,
    pub p12_button: String,
    pub password_label: String,
    pub open_keystore: String,
    pub keystore_pin: String,
    // --- signing -------------------------------------------------------
    pub sign_button: String,
    pub advanced_show: String,
    pub advanced_hide: String,
    pub adv_tsa: String,
    pub adv_digest: String,
    pub adv_reason: String,
    // --- result ---------------------------------------------------------
    pub signed_ok: String,
    pub open_folder: String,
    pub save_as: String,
    pub sign_another: String,
    // --- verify -----------------------------------------------------------
    pub verdict_valid: String,
    pub verdict_invalid: String,
    pub verdict_unsigned: String,
    pub signer_line: String,
    pub signed_at_line: String,
    pub chain_line: String,
    pub no_trust_anchors: String,
    pub verify_another: String,
    // --- errors --------------------------------------------------------------
    pub error_title: String,
    pub details_toggle: String,
    pub try_again: String,
    // --- closing guard -------------------------------------------------------
    pub close_unsaved: String,
    pub keep_working: String,
    pub discard_result: String,
    // --- window titles / dialogs -------------------------------------------
    pub dialog_open_file: String,
    pub dialog_open_cert: String,
    pub dialog_save_sig: String,
}

impl Tr {
    /// The Spanish interface — the one this tool ships with (see above).
    pub fn es() -> Self {
        Tr {
            app_title: "openfirma".into(),
            drop_here: "Arrastra aquí el documento que quieras firmar".into(),
            drop_hint: "o escribe su ruta y pulsa Enter".into(),
            paste_path: "Ruta del documento…".into(),
            browse: "Examinar…".into(),
            verify_verb: "Verificar una firma".into(),
            sign_verb: "Firmar un documento".into(),
            detected_pdf: "Es un PDF. Se firmará como PAdES (firma dentro del propio PDF).".into(),
            detected_xml: "Es un XML. Se firmará como XAdES (firma dentro del propio XML).".into(),
            detected_data:
                "Es un documento de texto o datos. Se firmará como CAdES (firma aparte, `.csig`)."
                    .into(),
            formats_for: "Formato".into(),
            choose_certificate: "Elige el certificado con el que firmar".into(),
            no_certificates: "No se ha encontrado ningún certificado con el que firmar.".into(),
            p12_button: "Abrir un archivo de certificado (.p12)…".into(),
            password_label: "Contraseña del certificado".into(),
            open_keystore: "Abrir un repositorio del sistema…".into(),
            keystore_pin: "PIN (se usa solo para abrir el repositorio)".into(),
            sign_button: "Firmar".into(),
            advanced_show: "Opciones avanzadas".into(),
            advanced_hide: "Ocultar opciones avanzadas".into(),
            adv_tsa: "Sellar el tiempo con un servidor de sellado (para que la firma siga siendo \
                      válido dentro de años; necesita la URL del servidor)"
                .into(),
            adv_digest: "Algoritmo de resumen".into(),
            adv_reason: "Motivo de la firma (opcional, queda dentro del PDF)".into(),
            signed_ok: "Firma guardada".into(),
            open_folder: "Abrir carpeta".into(),
            save_as: "Guardar en otra parte…".into(),
            sign_another: "Firmar otro documento".into(),
            verdict_valid: "Firma válida".into(),
            verdict_invalid: "La firma NO es válida".into(),
            verdict_unsigned: "Este archivo no tiene ninguna firma".into(),
            signer_line: "Quién firmó".into(),
            signed_at_line: "Cuándo".into(),
            chain_line: "Cadena de confianza hasta".into(),
            no_trust_anchors:
                "No sabes en quién confiar todavía: openfirma no verifica contra raíz alguna \
                 por defecto. Elige el certificado de la entidad en la que confías."
                    .into(),
            verify_another: "Verificar otro archivo".into(),
            error_title: "No se ha podido continuar".into(),
            details_toggle: "Ver detalles técnicos".into(),
            try_again: "Intentar de nuevo".into(),
            close_unsaved: "La firma que acabas de hacer aún no está guardada. ¿Quieres cerrarla \
                            sin guardarla?"
                .into(),
            keep_working: "Seguir trabajando".into(),
            discard_result: "Cerrar sin guardar".into(),
            dialog_open_file: "Elige el documento".into(),
            dialog_open_cert: "Elige tu certificado".into(),
            dialog_save_sig: "Guardar la firma".into(),
        }
    }
}

impl Default for Tr {
    fn default() -> Self {
        Tr::es()
    }
}
