//! The strings of openfirma's window, in one place (brief rule: every
//! user-visible string lives here — a literal inside a widget is the drift
//! review 06, M-6 measured).
//!
//! Spanish is the default interface language on purpose: this tool signs
//! documents for citizens dealing with a Spanish-government ecosystem. The
//! review's point stands though — AutoFirma ships six locales (es, ca, gl,
//! eu, va, en), so the seam here is real and not aspirational: every text is
//! an entry of [`Tr`], [`Tr::for_locale`] picks one from `$LANG`, and a new
//! language is one more `impl` block returning the same keys — no widget
//! changes. English ships today (the second locale AutoFirma's installs fall
//! back to); Catalan, Galician, Basque and Valencian are the same one-block
//! step whenever someone competent in them contributes the wording.

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
    /// The friendly card names the picker offers with one click (A-6): a
    /// DNIe is not a module path.
    pub store_dnie: String,
    pub store_opensc: String,
    pub store_fnmt: String,
    /// 06-N-11: a Firefox/Chromium profile's NSS database is named by what it
    /// IS. It used to borrow the "type its path" instruction as its label, so
    /// the picker offered links all reading "another keystore" instead of the
    /// browser they open.
    pub store_firefox: String,
    /// Per-row badges under the certificate name (A-7).
    pub cert_issuer_line: String,
    pub cert_valid_until_line: String,
    pub cert_expired: String,
    pub cert_auth_only: String,
    // --- signing -------------------------------------------------------
    pub sign_button: String,
    pub advanced_show: String,
    pub advanced_hide: String,
    pub adv_tsa: String,
    pub adv_digest: String,
    pub adv_reason: String,
    pub back_button: String,
    /// The reason the sign button is grey (M-4): under the field, not lost.
    pub password_wrong: String,
    pub password_missing: String,
    // --- result ---------------------------------------------------------
    pub signed_ok: String,
    pub open_folder: String,
    pub save_as: String,
    /// Copy the written file's path to the system clipboard (A-2).
    pub copy_path: String,
    pub sign_another: String,
    /// Shown while the background thread signs (A-1): what it is waiting for.
    pub signing_in_progress: String,
    /// 06-N-10: opening a keystore (module load + login) runs on the worker,
    /// so the window says what it is waiting for instead of freezing.
    pub opening_store: String,
    // --- verify -----------------------------------------------------------
    pub verdict_valid: String,
    pub verdict_invalid: String,
    pub verdict_unknown: String,
    pub verdict_unsigned: String,
    /// 06-N-3: the headline of a failure that belongs to the DOCUMENT and to
    /// no single signature. No line under it may read "Firma válida".
    pub verdict_document_invalid: String,
    /// What a signature line may say at most once that headline stands: its
    /// own checks passed, the document did not.
    pub verdict_document_signature_alone: String,
    /// The certification refusal of the document, in plain language (the
    /// library's own sentence rides behind the notes).
    pub reason_document_certified: String,
    /// A drop refused while a finished signature still stands unacknowledged
    /// on the Done screen (M-8's never-lose rule in its drop form).
    pub drop_while_done: String,
    pub signer_line: String,
    pub signed_at_line: String,
    /// The honest qualifier of a signingTime nobody confirmed with a TSA
    /// stamp (B-4).
    pub declared_time_note: String,
    pub chain_line: String,
    /// Shown while verifying when no authority is configured: what was
    /// checked and what was not (06-C-1).
    pub no_trust_anchors: String,
    /// The qualifier of a verdict line every check passed EXCEPT the one that
    /// names the issuer, because no authority is configured (06-C-1). Its
    /// status is amber: green is the claim that the chain reached an
    /// authority the user trusts.
    pub integrity_without_issuer: String,
    pub verify_another: String,
    // --- plain-language verification reasons (A-5) --------------------------
    /// The document was modified after signing.
    pub reason_digest: String,
    /// The certificate chain does not reach any anchor the user supplied.
    pub reason_chain: String,
    /// The certificate's validity window had passed at validation time.
    pub reason_expired: String,
    /// Not a signature file at all / unreadable structure.
    pub reason_not_signature: String,
    /// A detached signature whose original document was not found.
    pub reason_detached_content: String,
    /// The certificate revoked or otherwise refused by name (prefix + cause).
    pub reason_generic_prefix: String,
    // --- errors --------------------------------------------------------------
    pub error_title: String,
    /// Per-line details control when the technical block is closed (M-3):
    /// open and closed need different words on the button so its label says
    /// which way the click goes.
    pub details_show: String,
    pub details_hide: String,
    pub try_again: String,
    // --- closing guard -------------------------------------------------------
    pub close_unsaved: String,
    pub close_signing: String,
    pub keep_working: String,
    pub discard_result: String,
    // --- window titles / dialogs -------------------------------------------
    pub dialog_open_file: String,
    pub dialog_open_cert: String,
    /// Title of the anchor picker (review C-1): the file it asks for is a
    /// certification authority to trust, not the user's own certificate.
    pub dialog_save_sig: String,
    pub dialog_content_for_detached: String,
    // --- failures the library writes in English but the window must show
    //     in this language (B-2's jargon ban): each is a wrapper prefix that
    //     errors.rs weaves over the technical cause.
    pub fail_wrong_password: String,
    pub fail_anchor_read: String,
    pub fail_no_anchors_internal: String,
    pub fail_tsa_unverified: String,
    // --- strings review 06's second pass found outside the table (A-7's
    //     "every string through one Tr table" completed) ---------------------
    /// Drop refused while a job runs (the one-slot rule speaks out loud).
    pub drop_while_working: String,
    /// The close guard's words while a VERIFY job holds the slot (B-1: exact
    /// words for the state; "la firma se está haciendo" is a sign job's).
    pub close_verifying: String,
    /// The dead-worker answer (a job whose thread died without an answer).
    pub fail_worker_died: String,
    /// Buttons of the add-keystore form.
    pub add_store_open: String,
    pub add_store_cancel: String,
    /// Instructions of the add-keystore form.
    pub add_store_help: String,
    /// Folder-reveal failed (its own sentence; the OS error rides behind it).
    pub fail_open_folder: String,
    /// Saving to a chosen name failed (its own sentence).
    pub fail_save_as: String,
    /// A keystore with no signable certificate (catalog error line tail).
    pub store_no_private_key: String,
    /// 06-N-10: the lead of a picker line about a store that refused to open.
    /// Spanish, like every other sentence the window authors; the store's own
    /// reason (often the library's English) rides after it, never instead.
    pub store_open_failed: String,
    // --- verdict notes (M-6/N-11): sentences about a whole document, with
    //     named holes ({total}, {chain}) instead of `format!` placeholders, so
    //     a translation can never break the build and a hole left unfilled is
    //     visible on screen rather than a panic. `Tr::fill` is the one filler.
    /// Every document time-stamp verified.
    pub note_lta_all: String,
    /// No document time-stamp verified: no B-LTA claim.
    pub note_lta_none: String,
    /// Some document time-stamps verified: no B-LTA claim.
    pub note_lta_some: String,
    /// The `/DSS` the document carries, everything checked.
    pub note_dss_checked: String,
    /// Tail of the same sentence when some archived datum could not be checked
    /// (06-C-1: no authority configured).
    pub note_dss_unchecked: String,
    /// One rebuilt chain, from the archived data alone.
    pub note_dss_chain: String,
    /// The reason shown when nothing said why a token could not be checked.
    pub note_unchecked_reason: String,
    /// 06-N-11: the Done screen now names its lines — which one is the
    /// DOCUMENT and which is the file this run wrote.
    pub output_line: String,
    /// Closing while a keystore opens (its own sentence: nothing is being
    /// signed yet).
    pub close_opening_store: String,
}

impl Tr {
    /// The locale `$LANG` asks for, Spanish for anything unknown (AutoFirma's
    /// own fallback is its base bundle).
    pub fn for_locale() -> Self {
        Self::from_locale(&std::env::var("LANG").unwrap_or_default())
    }

    /// The pure half of [`Tr::for_locale`]: the `$LANG` text in, one `Tr` out.
    /// A test can hold no environment race this way.
    pub fn from_locale(lang: &str) -> Self {
        let code = lang
            .split(['.', '@'])
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        if code.starts_with("en") {
            Tr::en()
        } else {
            Tr::es()
        }
    }

    /// The Spanish interface — the one this tool ships by default.
    pub fn es() -> Self {
        Tr {
            app_title: "openfirma".into(),
            drop_here: "Arrastra aquí el documento que quieras firmar".into(),
            drop_hint: "o escribe su ruta y pulsa Enter".into(),
            paste_path: "Ruta del documento…".into(),
            browse: "Examinar…".into(),
            verify_verb: "Verificar una firma".into(),
            detected_pdf: "Es un PDF. Se firmará como PAdES (firma dentro del propio PDF).".into(),
            detected_xml: "Es un XML. Se firmará como XAdES (firma dentro del propio XML).".into(),
            detected_data:
                "Es un documento de texto o datos. Se firmará como CAdES (firma aparte, archivo \
                 «.csig» junto al original)."
                    .into(),
            formats_for: "Formato".into(),
            choose_certificate: "Elige el certificado con el que firmar".into(),
            no_certificates: "No se ha encontrado ningún certificado con el que firmar.".into(),
            p12_button: "Abrir un archivo de certificado (.p12)…".into(),
            password_label: "Contraseña del certificado".into(),
            open_keystore: "Otro almacén (escribe su ruta o nombre)…".into(),
            keystore_pin: "PIN (se recuerda durante esta sesión)".into(),
            store_dnie: "DNI electrónico".into(),
            store_opensc: "Tarjeta criptográfica (OpenSC)".into(),
            store_fnmt: "Certificado de la FNMT (AC CFv3)".into(),
            store_firefox: "Firefox".into(),
            cert_issuer_line: "Emitido por".into(),
            cert_valid_until_line: "Válido hasta".into(),
            cert_expired: "caducado".into(),
            cert_auth_only: "solo sirve para identificarse, no para firmar".into(),
            sign_button: "Firmar".into(),
            advanced_show: "Opciones avanzadas".into(),
            advanced_hide: "Ocultar opciones avanzadas".into(),
            adv_tsa: "Añadir sello de tiempo: demuestra a qué hora existía la firma (necesita la \
                      URL del servidor de sellado)"
                .into(),
            adv_digest: "Algoritmo de resumen".into(),
            adv_reason: "Motivo de la firma (opcional, queda dentro del PDF)".into(),
            back_button: "Elegir otro documento".into(),
            password_wrong: "Contraseña incorrecta. Vuelve a escribirla.".into(),
            password_missing: "Falta la contraseña del certificado.".into(),
            signed_ok: "Firma guardada".into(),
            open_folder: "Abrir carpeta".into(),
            save_as: "Guardar en otra parte…".into(),
            copy_path: "Copiar ruta".into(),
            sign_another: "Firmar otro documento".into(),
            signing_in_progress: "Firmando. Si usas una tarjeta, tenla a mano…".into(),
            opening_store: "Abriendo el almacén de certificados. Si usas una tarjeta, tenla a \
                            mano…"
                .into(),
            verdict_valid: "Firma válida".into(),
            verdict_invalid: "La firma NO es válida".into(),
            verdict_unknown: "No se puede confirmar la validez de esta firma".into(),
            verdict_unsigned: "Este archivo no tiene ninguna firma".into(),
            verdict_document_invalid: "El documento NO se puede dar por válido".into(),
            verdict_document_signature_alone: "la firma en sí es correcta, pero el documento NO"
                .into(),
            reason_document_certified:
                "está certificado con la restricción «no se permiten cambios» (/Perms /DocMDP \
                 /P 1) y hay firmas o cambios posteriores a esa certificación: ningún lector \
                 conforme da por buena una certificación rota"
                    .into(),
            drop_while_done: "Termina primero con la firma que tienes en pantalla: guarda o \
                              descarta su resultado antes de abrir otro archivo."
                .into(),
            signer_line: "Quién firmó".into(),
            signed_at_line: "Cuándo".into(),
            declared_time_note: "hora indicada por el firmante, sin sello de tiempo que la \
                                 confirme"
                .into(),
            chain_line: "Confía en la autoridad".into(),
            no_trust_anchors:
                "No hay ninguna autoridad de confianza configurada: se comprueba que el \
                 documento no haya cambiado desde la firma, pero NO quién emitió el \
                 certificado. Para comprobarlo también, pon en la variable OPENFIRMA_TRUST el \
                 fichero de la autoridad (por ejemplo, la raíz de la FNMT)."
                    .into(),
            integrity_without_issuer:
                "la firma es correcta sobre el documento, pero NO se ha comprobado quién \
                 emitió el certificado: no hay ninguna autoridad de confianza configurada"
                    .into(),
            verify_another: "Verificar otro archivo".into(),
            reason_digest:
                "El documento cambió después de firmarse: lo que se firmó no es lo que hay ahora."
                    .into(),
            reason_chain:
                "No se llega a ninguna autoridad en la que confíes: falta el certificado de la \
                 autoridad que emitió la del firmante."
                    .into(),
            reason_expired:
                "El certificado del firmante había caducado en el momento de comprobarla.".into(),
            reason_not_signature: "Este archivo no tiene una firma que openfirma pueda leer."
                .into(),
            reason_detached_content:
                "Esta es una firma separada del documento (un «.csig»): hay que abrir también el \
                 documento que firmó."
                    .into(),
            reason_generic_prefix: "Motivo".into(),
            error_title: "No se ha podido continuar".into(),
            details_show: "Ver detalles técnicos".into(),
            details_hide: "Ocultar detalles técnicos".into(),
            try_again: "Intentar de nuevo".into(),
            close_unsaved: "Hay una firma cuyo resultado no has visto todavía. ¿Quieres cerrarla \
                            sin más?"
                .into(),
            close_signing: "La firma se está haciendo todavía. ¿Quieres cancelarla y cerrar?"
                .into(),
            keep_working: "Seguir trabajando".into(),
            discard_result: "Cerrar sin esperar".into(),
            dialog_open_file: "Elige el documento".into(),
            dialog_open_cert: "Elige tu certificado".into(),
            dialog_save_sig: "Guardar la firma".into(),
            dialog_content_for_detached: "Elige el documento que se firmó".into(),
            fail_wrong_password:
                "La contraseña del certificado no es correcta o el archivo está dañado.".into(),
            fail_anchor_read: "No se ha podido usar el archivo elegido como autoridad:".into(),
            fail_no_anchors_internal:
                "El verificador no tiene ninguna autoridad de confianza con la que comprobar \
                 esta firma: configura la variable OPENFIRMA_TRUST."
                    .into(),
            fail_tsa_unverified:
                "El sello de tiempo no se ha podido comprobar: demuestra la hora solo si \
                 confías en quien lo emitió."
                    .into(),
            close_verifying: "La comprobación de firmas sigue en marcha. ¿Quieres cancelarla \
                 y cerrar?"
                .into(),
            drop_while_working:
                "Termina primero la operación que está en marcha: esta ventana hace una sola \
                 cosa cada vez para no perder ningún resultado."
                    .into(),
            fail_worker_died:
                "La operación se ha interrumpido porque el proceso que la hacía ha dejado de \
                 responder. No se ha guardado nada; vuelve a intentarlo."
                    .into(),
            add_store_open: "Abrir".into(),
            add_store_cancel: "Cancelar".into(),
            add_store_help:
                "Escribe el descriptor del almacén: pkcs11:/ruta/modulo.so[:token], nss (la \
                 base de Firefox/Chromium), o los almacenes del sistema."
                    .into(),
            fail_open_folder: "No se pudo abrir la carpeta:".into(),
            fail_save_as: "No se pudo guardar:".into(),
            store_no_private_key: "no contiene ningún certificado con clave privada".into(),
            store_open_failed: "no se ha podido abrir el almacén".into(),
            note_lta_all: "El documento lleva {total} sello(s) de tiempo de documento (nivel \
                           B-LTA): la firma de la autoridad de sellado de cada uno se ha \
                           verificado, y cada sello certifica todos los bytes anteriores al \
                           momento del sellado."
                .into(),
            note_lta_none: "El documento lleva {total} sello(s) de tiempo de documento, pero la \
                            firma de su autoridad de sellado NO se ha podido verificar ({why}). \
                            NO se afirma el nivel B-LTA: un sello sin verificar no certifica \
                            nada."
                .into(),
            note_lta_some: "El documento lleva {total} sello(s) de tiempo de documento, de los \
                            que {verified} tienen la firma de su autoridad verificada. NO se \
                            afirma el nivel B-LTA mientras alguno quede sin verificar."
                .into(),
            note_dss_checked: "El documento guarda datos de validación ({certs} certificados, \
                               {crls} CRLs, {ocsps} respuestas OCSP). {checked} dato(s) se han \
                               comprobado (legibles, y cada uno firmado por la autoridad que lo \
                               emite){unchecked}"
                .into(),
            note_dss_unchecked: "; {unchecked} NO se han podido comprobar, porque los emitió una \
                                 autoridad que no está entre las configuradas."
                .into(),
            note_dss_chain: "La cadena de la firma {n} se reconstruye solo con los datos del \
                             documento: {chain}."
                .into(),
            note_unchecked_reason: "no se pudo comprobar".into(),
            output_line: "Fichero firmado".into(),
            close_opening_store: "El almacén de certificados se está abriendo todavía. ¿Quieres \
                                  cancelarlo y cerrar?"
                .into(),
        }
    }

    /// English — AutoFirma's `en_US` counterpart, and the fallback locale of
    /// its installs (second one here for the same reason).
    pub fn en() -> Self {
        Tr {
            app_title: "openfirma".into(),
            drop_here: "Drop the document you want to sign here".into(),
            drop_hint: "or type its path and press Enter".into(),
            paste_path: "Document path…".into(),
            browse: "Browse…".into(),
            verify_verb: "Verify a signature".into(),
            detected_pdf: "It is a PDF. It will be signed as PAdES (inside the PDF itself).".into(),
            detected_xml: "It is an XML. It will be signed as XAdES (inside the XML itself)."
                .into(),
            detected_data: "It is a text or data document. It will be signed as CAdES (a separate \
                 \".csig\" file beside it)."
                .into(),
            formats_for: "Format".into(),
            choose_certificate: "Choose the certificate to sign with".into(),
            no_certificates: "No certificate to sign with was found.".into(),
            p12_button: "Open a certificate file (.p12)…".into(),
            password_label: "Certificate password".into(),
            open_keystore: "Another keystore (type its path or name)…".into(),
            keystore_pin: "PIN (remembered for this session)".into(),
            store_dnie: "Electronic ID card (DNIe)".into(),
            store_opensc: "Smart card (OpenSC)".into(),
            store_fnmt: "FNMT certificate (AC CFv3)".into(),
            store_firefox: "Firefox".into(),
            cert_issuer_line: "Issued by".into(),
            cert_valid_until_line: "Valid until".into(),
            cert_expired: "expired".into(),
            cert_auth_only: "identification only, cannot sign".into(),
            sign_button: "Sign".into(),
            advanced_show: "Advanced options".into(),
            advanced_hide: "Hide advanced options".into(),
            adv_tsa:
                "Add a time-stamp: proves when the signature existed (needs the TSA server URL)"
                    .into(),
            adv_digest: "Digest algorithm".into(),
            adv_reason: "Reason for signing (optional, stays inside the PDF)".into(),
            back_button: "Choose another document".into(),
            password_wrong: "Wrong password. Type it again.".into(),
            password_missing: "The certificate's password is missing.".into(),
            signed_ok: "Signature saved".into(),
            open_folder: "Open folder".into(),
            save_as: "Save as…".into(),
            copy_path: "Copy path".into(),
            sign_another: "Sign another document".into(),
            signing_in_progress: "Signing. If you use a card, have it ready…".into(),
            opening_store: "Opening the certificate store. If you use a card, have it ready…"
                .into(),
            verdict_valid: "Signature is valid".into(),
            verdict_invalid: "The signature is NOT valid".into(),
            verdict_unknown: "The signature's validity cannot be confirmed".into(),
            verdict_unsigned: "This file carries no signature".into(),
            verdict_document_invalid: "The document cannot be held valid".into(),
            verdict_document_signature_alone: "the signature itself is sound, but the document \
                                              is NOT"
                .into(),
            reason_document_certified:
                "it is certified with «no changes permitted» (/Perms /DocMDP /P 1) and carries \
                 signatures or changes after that certification: no conforming reader holds a \
                 broken certification sound"
                    .into(),
            drop_while_done: "Finish with the signature on screen first: save or discard its \
                              result before opening another file."
                .into(),
            signer_line: "Who signed".into(),
            signed_at_line: "When".into(),
            declared_time_note: "time declared by the signer, no stamp confirms it".into(),
            chain_line: "Trusts the authority".into(),
            no_trust_anchors:
                "No trust authority is configured: what is checked is that the document has \
                 not changed since it was signed, but NOT who issued the certificate. To check \
                 that too, set OPENFIRMA_TRUST to the authority's file (the FNMT root, for \
                 instance)."
                    .into(),
            integrity_without_issuer:
                "the signature is sound over the document, but WHO issued the certificate was \
                 NOT checked: no trust authority is configured"
                    .into(),
            verify_another: "Verify another file".into(),
            reason_digest:
                "The document changed after signing: what was signed is not what is there now."
                    .into(),
            reason_chain:
                "It does not reach any authority you trust: the certificate of the authority \
                 that issued the signer's is missing."
                    .into(),
            reason_expired: "The signer's certificate had expired at validation time.".into(),
            reason_not_signature: "This file holds no signature openfirma can read.".into(),
            reason_detached_content:
                "This is a signature kept apart from its document (a \".csig\"): the document \
                 it signed must be opened too."
                    .into(),
            reason_generic_prefix: "Reason".into(),
            error_title: "Could not continue".into(),
            details_show: "Show technical details".into(),
            details_hide: "Hide technical details".into(),
            try_again: "Try again".into(),
            close_unsaved:
                "A signature's result has not been seen yet. Close and discard it anyway?".into(),
            close_signing: "The signature is still being made. Cancel it and close?".into(),
            keep_working: "Keep working".into(),
            discard_result: "Close without waiting".into(),
            dialog_open_file: "Choose the document".into(),
            dialog_open_cert: "Choose your certificate".into(),
            dialog_save_sig: "Save the signature".into(),
            dialog_content_for_detached: "Choose the document that was signed".into(),
            fail_wrong_password: "The certificate's password is wrong, or the file is damaged."
                .into(),
            fail_anchor_read: "The chosen authority file could not be used:".into(),
            fail_no_anchors_internal:
                "The verifier has no trust authority to check this signature against: set \
                 OPENFIRMA_TRUST."
                    .into(),
            fail_tsa_unverified:
                "The time-stamp could not be checked: it proves the time only if you trust \
                 who issued it."
                    .into(),
            close_verifying: "The signature check is still running. Cancel it and close?".into(),
            drop_while_working:
                "Finish the operation already running first: this window does one thing at a \
                 time so that no result gets lost."
                    .into(),
            fail_worker_died: "The operation was interrupted because the process doing it stopped \
                 answering. Nothing was saved; please try again."
                .into(),
            add_store_open: "Open".into(),
            add_store_cancel: "Cancel".into(),
            add_store_help:
                "Type the keystore descriptor: pkcs11:/path/module.so[:token], nss (the \
                 Firefox/Chromium database), or the system keystores."
                    .into(),
            fail_open_folder: "The folder could not be opened:".into(),
            fail_save_as: "Could not save:".into(),
            store_no_private_key: "contains no certificate with a private key".into(),
            store_open_failed: "the store could not be opened".into(),
            note_lta_all: "The document carries {total} document time-stamp(s) (level B-LTA): \
                           the sealing authority's signature was verified for each one, and \
                           each stamp covers every byte before the moment it was made."
                .into(),
            note_lta_none: "The document carries {total} document time-stamp(s), but the \
                            sealing authority's signature could NOT be verified ({why}). Level \
                            B-LTA is NOT claimed: an unverified stamp certifies nothing."
                .into(),
            note_lta_some: "The document carries {total} document time-stamp(s), of which \
                            {verified} have their authority's signature verified. Level B-LTA \
                            is NOT claimed while any is left unverified."
                .into(),
            note_dss_checked: "The document carries validation data ({certs} certificates, \
                               {crls} CRLs, {ocsps} OCSP responses). {checked} datum(a) were \
                               checked (readable, and each one signed by the authority that \
                               issued it){unchecked}"
                .into(),
            note_dss_unchecked: "; {unchecked} could NOT be checked, because the authority that \
                                 issued them is not among the configured ones."
                .into(),
            note_dss_chain: "The chain of signature {n} rebuilds from the document's own data \
                             alone: {chain}."
                .into(),
            note_unchecked_reason: "it could not be checked".into(),
            output_line: "Signed file".into(),
            close_opening_store: "The certificate store is still opening. Cancel it and close?"
                .into(),
        }
    }

    /// Fill a table sentence's named holes (`{total}`, `{chain}`). The table
    /// holds sentences with named holes rather than `format!` templates: a
    /// translation can never break the build with a stray brace, and a hole
    /// left unfilled stays visible on screen (`{total}`) instead of panicking.
    /// `tests::every_hole_of_every_note_gets_filled` holds the other side —
    /// each sentence is filled with exactly the holes it declares.
    pub fn fill(template: &str, holes: &[(&str, &str)]) -> String {
        let mut out = template.to_string();
        for (name, value) in holes {
            out = out.replace(&format!("{{{name}}}"), value);
        }
        out
    }
}

impl Default for Tr {
    fn default() -> Self {
        Tr::es()
    }
}

impl Tr {
    /// Every user-visible sentence of this language, in one list (A-3/M-6).
    /// The completeness test walks it, and so does the glyph test in
    /// `tests/ui.rs`: a sentence the window promises to show must exist in both
    /// languages AND be paintable by the fonts a build carries.
    pub fn every_string(&self) -> Vec<&String> {
        vec![
            &self.app_title,
            &self.drop_here,
            &self.drop_hint,
            &self.paste_path,
            &self.browse,
            &self.verify_verb,
            &self.detected_pdf,
            &self.detected_xml,
            &self.detected_data,
            &self.formats_for,
            &self.choose_certificate,
            &self.no_certificates,
            &self.p12_button,
            &self.password_label,
            &self.open_keystore,
            &self.keystore_pin,
            &self.store_dnie,
            &self.store_opensc,
            &self.store_fnmt,
            &self.store_firefox,
            &self.cert_issuer_line,
            &self.cert_valid_until_line,
            &self.cert_expired,
            &self.cert_auth_only,
            &self.sign_button,
            &self.advanced_show,
            &self.advanced_hide,
            &self.adv_tsa,
            &self.adv_digest,
            &self.adv_reason,
            &self.back_button,
            &self.password_wrong,
            &self.password_missing,
            &self.signed_ok,
            &self.open_folder,
            &self.save_as,
            &self.sign_another,
            &self.signing_in_progress,
            &self.opening_store,
            &self.verdict_valid,
            &self.verdict_invalid,
            &self.verdict_unknown,
            &self.verdict_unsigned,
            &self.verdict_document_invalid,
            &self.verdict_document_signature_alone,
            &self.reason_document_certified,
            &self.signer_line,
            &self.signed_at_line,
            &self.declared_time_note,
            &self.chain_line,
            &self.no_trust_anchors,
            &self.integrity_without_issuer,
            &self.verify_another,
            &self.reason_digest,
            &self.reason_chain,
            &self.reason_expired,
            &self.reason_not_signature,
            &self.reason_detached_content,
            &self.reason_generic_prefix,
            &self.error_title,
            &self.details_show,
            &self.try_again,
            &self.close_unsaved,
            &self.close_signing,
            &self.keep_working,
            &self.discard_result,
            &self.dialog_open_file,
            &self.dialog_open_cert,
            &self.dialog_save_sig,
            &self.dialog_content_for_detached,
            &self.fail_wrong_password,
            &self.fail_anchor_read,
            &self.fail_no_anchors_internal,
            &self.fail_tsa_unverified,
            &self.copy_path,
            &self.drop_while_done,
            &self.details_hide,
            &self.close_verifying,
            &self.drop_while_working,
            &self.fail_worker_died,
            &self.add_store_open,
            &self.add_store_cancel,
            &self.add_store_help,
            &self.fail_open_folder,
            &self.fail_save_as,
            &self.store_no_private_key,
            &self.store_open_failed,
            &self.note_lta_all,
            &self.note_lta_none,
            &self.note_lta_some,
            &self.note_dss_checked,
            &self.note_dss_unchecked,
            &self.note_dss_chain,
            &self.note_unchecked_reason,
            &self.output_line,
            &self.close_opening_store,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A-3/M-6: every key ships in every language — an entry missing from one
    /// `impl` is a compile error, but the values must also all be non-empty,
    /// which a field added to the struct and filled for es only would not be.
    #[test]
    fn every_string_ships_in_every_language() {
        let check = |tr: &Tr, lang: &str| {
            for f in tr.every_string() {
                assert!(!f.trim().is_empty(), "{lang} has an empty string");
            }
        };
        let es = Tr::es();
        let en = Tr::en();
        check(&es, "es");
        check(&en, "en");
        // The two languages are not the same text by copy-paste accident.
        assert_ne!(es.verdict_valid, en.verdict_valid);
    }

    #[test]
    fn locale_selection_falls_back_to_spanish() {
        // Unknown and empty locales are Spanish (AutoFirma's own base bundle).
        for probe in ["", "es_ES.UTF-8", "ca_ES@valencia", "en_US.UTF-8"] {
            let picked = Tr::from_locale(probe);
            assert_eq!(
                picked.verdict_valid,
                if probe.starts_with("en") {
                    Tr::en().verdict_valid
                } else {
                    Tr::es().verdict_valid
                },
                "{probe}"
            );
        }
    }

    /// M-2: the review's concrete privacy failure — the DN dump that leaked a
    /// DNI number on the verdict screen — is a pure function now, and pinned.
    #[test]
    fn the_signer_line_never_carries_the_dn() {
        assert_eq!(
            crate::verdicts::signer_display("CN=\"PEREZ GARCIA, ANA\",SERIALNUMBER=IDCES-12345678Z,OU=AC openfirma Usuarios,O=openfirma test,C=ES").as_deref(),
            Some("PEREZ GARCIA, ANA"),
        );
        // No CN at all: the organisation signs for itself (sello de entidad).
        assert_eq!(
            crate::verdicts::signer_display("SERIALNUMBER=IDCES-12345678Z,O=openfirma test,C=ES")
                .as_deref(),
            Some("openfirma test"),
        );
        // Nothing recognisable: no name at all — never a DN, which is what
        // printed the DNI number.
        assert_eq!(
            crate::verdicts::signer_display("OU=cosas,C=ES").as_deref(),
            None,
        );
    }

    /// A-7/M-6: the table is the ONE place the window's sentences live, and a
    /// field nobody reads is a sentence the window promises and never says.
    /// Review 06 found ten of them — three hardcoded in the add-keystore form
    /// while the table held their translations, two failures spelled out in
    /// the Done screen, and five with no reader at all. This walks the crate's
    /// own sources (`src/` minus this file, plus `tests/`) and fails on any
    /// field name that is read nowhere else.
    #[test]
    fn every_string_in_the_table_is_used_by_the_window() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut used = String::new();
        for dir in [root.join("src"), root.join("tests")] {
            for entry in std::fs::read_dir(&dir).expect("the crate's own sources") {
                let path = entry.expect("a source entry").path();
                let is_strings = path.file_name().is_some_and(|n| n == "strings.rs");
                let is_rust = path.extension().is_some_and(|e| e == "rs");
                if is_strings || !is_rust {
                    continue;
                }
                used.push_str(&std::fs::read_to_string(&path).expect("readable source"));
            }
        }
        let table = std::fs::read_to_string(root.join("src/strings.rs")).expect("the table");
        let mut fields = 0;
        for line in table.lines() {
            let Some(rest) = line.trim_start().strip_prefix("pub ") else {
                continue;
            };
            let Some(name) = rest.strip_suffix(": String,") else {
                continue;
            };
            if name.contains(' ') {
                continue;
            }
            fields += 1;
            // `.field` and not a bare substring: a mention of the name in a
            // comment is not a reader, and the window reads through `tr.`.
            assert!(
                used.contains(&format!(".{name}")),
                "Tr::{name} is declared and read nowhere (A-7)"
            );
        }
        assert!(fields > 80, "the scanner found only {fields} fields");
    }

    /// M-6/N-11: the verdict NOTES were hardcoded Spanish inside `verdicts.rs`
    /// even in an English window. They are table sentences now, and this holds
    /// it: every note ships in both languages, the English one is not the
    /// Spanish one, and the declared holes are the ones filled — nothing on
    /// screen is left looking like `{total}`.
    #[test]
    fn every_document_note_is_written_in_both_languages() {
        let es = Tr::es();
        let en = Tr::en();
        let notes: [(&str, &str, &str, &[&str]); 5] = [
            (
                "note_lta_all",
                &es.note_lta_all,
                &en.note_lta_all,
                &["total"],
            ),
            (
                "note_lta_none",
                &es.note_lta_none,
                &en.note_lta_none,
                &["total", "why"],
            ),
            (
                "note_lta_some",
                &es.note_lta_some,
                &en.note_lta_some,
                &["total", "verified"],
            ),
            (
                "note_dss_checked",
                &es.note_dss_checked,
                &en.note_dss_checked,
                &["certs", "crls", "ocsps", "checked", "unchecked"],
            ),
            (
                "note_dss_chain",
                &es.note_dss_chain,
                &en.note_dss_chain,
                &["n", "chain"],
            ),
        ];
        for (name, es_sentence, en_sentence, holes) in notes {
            assert_ne!(
                es_sentence, en_sentence,
                "{name}: the English sentence is the Spanish one"
            );
            for (locale, text) in [("es", es_sentence), ("en", en_sentence)] {
                let with: Vec<(&str, &str)> = holes.iter().map(|h| (*h, "7")).collect();
                let filled = Tr::fill(text, &with);
                assert!(
                    !filled.contains('{'),
                    "{name}/{locale}: a hole is left unfilled: {filled}"
                );
                assert!(
                    filled.contains('7'),
                    "{name}/{locale}: the sentence has no hole to fill"
                );
            }
            // The English column is English. A Spanish sentence pasted there
            // is exactly the defect this test exists for.
            for marker in ["El documento", "La cadena", "no se pudo", "de los que"] {
                assert!(
                    !en_sentence.contains(marker),
                    "{name}: the English note says {marker:?}"
                );
            }
        }
        // The tail rides inside the DSS sentence and is a note of its own.
        assert!(es.note_dss_unchecked.contains("{unchecked}"));
        assert!(en.note_dss_unchecked.contains("{unchecked}"));
        assert_ne!(es.note_dss_unchecked, en.note_dss_unchecked);
    }
}
