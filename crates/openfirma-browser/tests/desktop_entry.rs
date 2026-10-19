//! Finding 04-N10, measured with the parser that refused the file: GLib itself.
//!
//! `linux_desktop_entry` writes the entry `--register` installs. A path with a
//! `"` in it used to be escaped once (`\"` in the file), which is not a GLib
//! key-file escape at all: glib refuses the entire entry — `gio launch` answers
//! "Unable to load application information" — while `desktop-file-validate`
//! prints nothing, so the registration looked healthy and the scheme was dead
//! in GNOME. Our own escaping is not what gets asserted below: the entry goes to
//! `gio`, and what is required is that the program actually STARTS, from a
//! directory whose name holds a quote and a backslash, and that its argument
//! reaches it.

#[cfg(target_os = "linux")]
mod linux {
    use std::path::Path;
    use std::process::Command;

    use openfirma_browser::scheme::linux_desktop_entry;

    /// CI sets OPENFIRMA_REQUIRE_TESTS so a missing tool fails instead of
    /// skipping; only the keystore-scoped opt-out relaxes it.
    fn require_or_skip(reason: &str) {
        let required = std::env::var("OPENFIRMA_REQUIRE_TESTS").is_ok();
        let allowed = std::env::var("OPENFIRMA_ALLOW_NONKEYSTORE_SKIP").is_ok();
        if required && !allowed {
            panic!("cannot run the test: {reason}");
        }
        eprintln!("skipped, {reason}");
    }

    fn gio_launch(entry: &Path) -> std::process::Output {
        Command::new("gio")
            .arg("launch")
            .arg(entry)
            .output()
            .expect("gio must run")
    }

    /// The directory the handler lives in, spelled with everything the two
    /// escaping layers have to agree about: a quote, a backslash next to it,
    /// spaces and a non-ASCII letter.
    const AWKWARD: &str = "los \"jefes\" \\ Ana María";

    #[test]
    fn gio_loads_and_runs_the_entry_a_quoted_path_produces() {
        if Command::new("gio").arg("--version").output().is_err() {
            require_or_skip("gio is absent (libglib2.0-bin), the desktop's own parser");
            return;
        }
        let root = std::env::temp_dir().join(format!("openfirma-entry-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let awkward = root.join(AWKWARD);
        std::fs::create_dir_all(&awkward).unwrap();
        let marker = root.join("args.txt");
        let script = awkward.join("openfirma");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\n",
                marker.display()
            ),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        // Exactly the file --register installs, for a binary at that path.
        let entry = linux_desktop_entry(&script).expect("the path is writable as an entry");
        let desktop = root.join("openfirma-afirma.desktop");
        std::fs::write(&desktop, &entry).unwrap();

        let out = gio_launch(&desktop);
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        assert!(
            !stderr.contains("Unable to load application information"),
            "GLib refused the entry our register writes:\n{entry}\n{stderr}"
        );
        let args = std::fs::read_to_string(&marker).unwrap_or_else(|e| {
            panic!("the handler never started ({e}); gio said: {stderr}\nentry was:\n{entry}")
        });
        assert_eq!(
            args.lines().collect::<Vec<_>>(),
            ["afirma-uri"],
            "%u expands to nothing without a URI, and the marker argument arrives whole;\n\
             entry was:\n{entry}"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// The same claim from the other side: the entry for a path with a `"` in
    /// it must differ from the entry for the same path with the quote removed
    /// only where the quote is. A writer that dropped or mangled the quote
    /// would otherwise still "produce an entry", and `gio` above is the only
    /// thing that would notice.
    #[test]
    fn the_quote_survives_into_the_quoted_argument() {
        let with = linux_desktop_entry(Path::new("/opt/a\"b/openfirma")).unwrap();
        let without = linux_desktop_entry(Path::new("/opt/ab/openfirma")).unwrap();
        assert_ne!(with, without);
        // File-level: the quote reaches glib's value as an Exec-level `\"`,
        // which in the key file is written `\\"` (finding 04-N10).
        assert!(
            with.contains(r#"Exec="/opt/a\\"b/openfirma" afirma-uri %u"#),
            "{with}"
        );
        // And the shape AutoFirma's own registration has is untouched by that:
        // a path with no quote and no backslash is written verbatim.
        assert!(without.contains(r#"Exec="/opt/ab/openfirma" afirma-uri %u"#));
    }
}
