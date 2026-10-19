# ADR-0006: the window is egui/eframe on glow, a thin layer over the library calls the CLI makes — every decision lives in openfirma-core

Date: 2026-10-16
Status: accepted

## Context

openfirma's second frontend has one job: be *easier to use than AutoFirma*
for the two tasks a citizen actually does — sign a document, check a
signature — without ever becoming a second implementation of anything. The
brief's structural rule (and this project's oldest failure mode) is that a
GUI which re-decides what the library decided drifts: one format signing one
way in the terminal and another way in the window is worse than no window.

The comparison target was measured, not imagined, from the AutoFirma 1.9.1
sources (`/tmp/opencode/autofirma-src`, `principal/Firma.java`,
`principal/Validacion.java`) and the shipped jar's behaviour:

* **AutoFirma, simple sign** (the "Firma" tab): Examinar + open-dialog accept
  = 2 clicks; certificate dialog ≥ 1 (more when a keystore needs its PIN
  dialog first); format combo click + item = 2; the CAdES "include the
  original content?" yes/no prompt = 1; the informational result dialog OK =
  1; the save dialog (navigate + save) ≈ 2–3; final OK = 1. **≈ 8–9 clicks**,
  several of them on questions ("¿formato?, ¿encapsular?") a person cannot
  answer without reading help.
* **AutoFirma, verify** (the "Validación" tab): it wants the *signature*
  file — an exported `.csig` — and offers a separate "documento firmado"
  slot; what a citizen holds is one signed PDF, so the flow starts with an
  export most people cannot perform. The result screen is a certificate
  tree, not an answer.

The counted target for openfirma follows from that measurement: **drop the
file (drag — zero clicks), pick the certificate (1), press Firmar (1)**; the
result is written next to the original and its path is on the screen with an
open-folder link. Verify is **drop, read** — one file, plain-language lines.

## Decision

1. **Toolkit: egui + eframe 0.37, glow backend.** Chosen against the other
   candidates on this project's rules (README: pure Rust, no C toolchains):
   * Tauri/Electron/webview — a whole browser or a webkit C dependency per
     platform; out by the same reading that kept rustls' `ring` out of
     ADR-0005.
   * GTK/Qt bindings — C libraries under every Rust crate around them.
   * Iced, Slint — viable pure-Rust; egui won on two concrete points: its
     immediate-mode tree is directly assertable without a display through
     `egui_kittest` (point 5), and its default build needs no GPU stack beyond
     OpenGL (`glow`) that every target already has, while keeping x11 *and*
     wayland alive.
   The version (0.37) is the current release of the egui family; eframe and
   egui_kittest move together — pinning them apart breaks AccessKit's tree.
2. **The crate `openfirma-gui` is a layer, not an implementation.** Every
   action its widgets take calls either a library function the CLI also calls
   (`openfirma_cades::sign`, `openfirma_pades::pades_sign`,
   `openfirma_xades::xades_sign`, `openfirma_cades::verify`,
   `openfirma_pades::pades_verify`, `openfirma_keystore::*`) or a shared rule
   that lives in `openfirma_core::workflow` (format detection and default
   output name, the store-descriptor grammar, trust-anchor loading, the
   in-place refusal, friendly names, the calendar behind printed dates) or in
   this crate's own non-window modules (`signing`: the format dispatcher;
   `tsa`: the http TSA provider; `verdicts`: the verify report rendered;
   `errors`: plain sentence vs technical detail). The UI file (`app.rs`)
   decides nothing; if it looks like a decision, it moves to core and both
   frontends call it. The CLI was refactored in the same commit that added
   core::workflow, so this is checked by construction, not intention:
   `openfirma sign --store`, its in-place refusal and its date output now
   *are* the window's functions.
3. **Spanish interface, one strings module.** `strings.rs` holds every
   user-visible sentence (`Tr`, built by `Tr::es()`); a second language is a
   second constructor over the same keys, never an edited widget. Code,
   comments and docs stay in English like the rest of the repository. The
   library's own refusal texts (the RC2 refusal, the descriptor errors) stay
   in their authored English rather than forked into two translations — one
   shared sentence beats a prettier duplicated one.
4. **Deliberate deviations from AutoFirma** (each one is a click-count or
   honesty claim this ADR owes):
   * verify the document itself; no `.csig` export step (AutoFirma's tab
     cannot read what most citizens have);
   * the output name is the library's rule — `documento.signed.pdf` next to
     the original, written *before* the word "guardada" appears and synced
     to disk first; AutoFirma's save dialog (2–3 clicks) is replaced by a
     path on screen plus "Guardar en otra parte…" for anyone who wants it;
   * no co-signing in v1: adding a signature beside one nobody has read is
     how bad paperwork starts, and the browser protocol (ADR-0005) refuses
     `cosign`/`countersign` for the same measured reason;
   * the long-term levels (B-LT/B-LTA) are not silently offered: they embed
     CRLs/OCSP responses openfirma never downloads, so the dispatcher refuses
     them with the CLI's pointer to `openfirma sign --format pades-b-lt
     --crl …` instead of signing a weaker document under a long-term label;
   * "Abrir carpeta" opens only the folder, never the signed document:
     handing the PDF to whatever viewer answers would outsource the trust
     decision this window just made;
   * no B-LT/B-LTA UI, no CRL/OCSP collection in the window: same reason —
     half a level collected by hand is how archived-validation-data lies get
     made.
5. **Tests are windowless and end-to-end.** `egui_kittest` drives the same
   `App` the binary runs (`tests/ui.rs`: 8 tests — first screen, detection
   routing, .p12 three-click sign, store-style row without a second password,
   dropped-file entry, verdicts (including the amber "issuer not checked" of a
   machine with no configured authority), plain-vs-
   technical errors, and the close button bouncing off an unsaved result).
   File pickers are fixture answers behind `Dialogs` (their real behaviour is
   OS furniture: it belongs to the manual checklist, docs/validation.md). The
   end-to-end clause — a file signed through the GUI's code path verifies with
   `openfirma_cades::verify`/`openfirma_pades::pades_verify`, the CLI's own
   verifiers — runs inside the kittest tests.
6. **Never a silent success** (the brief's rule, made mechanical): while the
   window holds an unsaved result or a signing in flight, `close_decision`
   says Warn; the close request answers itself with `CancelClose` and a two-
   button guard (Seguir trabajando / Cerrar sin guardar), so no OS gesture
   closes over a result nobody saw. The first write is synced before ✓ shows,
   Save-As replaces the path only after its own sync, and every failure is a
   plain sentence with "Ver detalles técnicos" behind it — never a DER dump
   in front, never a spinner without an owner.
7. **Advanced options stay advanced**: off by default; TSA url (with the
   http-only refusal explained), digest, format radios (B-LTA greyed until a
   TSA exists to seal with), PDF reason — each labelled by what it does for
   the document, not by its flag name.

## Consequences

* Everything the GUI does is also possible from the CLI (README says so and
  tests hold both sides to the shared functions); the reverse gains nothing
  from this ADR.
* `$OPENFIRMA_TRUST` becomes the one trust-anchoring knob both frontends
  read. ~~with no anchors, verify asks for one certificate file instead of
  guessing (an unfounded ✓ is exactly the failure this project bans)~~ — see
  the update below.

> **Update (2026-10-19, review 06 finding C-1):** the ask-for-an-anchor step is
> gone. Asking the citizen which CA to trust is a question they cannot answer,
> and the review walked the wrong answer through it: an impostor's own root,
> chosen after seeing the document, made the screen read "Firma válida". The
> window now reads `$OPENFIRMA_TRUST` ONCE at startup and verifies under
> `AnchorPolicy::IntegrityWithoutAnchors` when that list is empty: every check
> that needs no authority runs (the signature over its digest, the signer
> certificate's own profile and key strength, its validity dates, the algorithm
> policy), the chain step does not, and each line is amber and says so. Nothing
> in the window can turn "nobody checked who issued this" into a green line.
* The GUI ships on the targets a windowing system builds for (Linux x86_64,
  macOS, Windows); cross-compilations without one build the workspace with
  `--exclude openfirma-gui` / `--no-default-features` (the reason stands in
  .github/workflows/release.yml next to the flag).
* A real translation, when it comes, is `Tr::en()` and a locale lookup —
  widgets already take `&Tr` and no literal text.
