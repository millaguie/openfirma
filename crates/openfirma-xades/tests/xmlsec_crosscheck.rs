//! xmlsec1 as an independent verifier: its own XML parser, its own C14N 1.0
//! and its own XML-DSig reference machinery, with openssl as the crypto
//! backend. When it says OK, our canonicalized SignedInfo, our digests and
//! our signature value agree with an implementation that shares no code with
//! ours. This is the layer that would catch a canonicalizer that is
//! self-consistent but wrong, which the structure tests cannot see.
//!
//! The EC case matters twice: AutoFirma headless cannot even *sign* EC XAdES
//! on this JVM (docs/xades.md, deviation 5), so xmlsec1 is the only
//! independent verdict our ECDSA path gets.

use std::path::{Path, PathBuf};
use std::process::Command;

use openfirma_core::cert::CertificateHandle;
use openfirma_core::signer::SoftwareSigner;
use openfirma_xades::{XadesOptions, xades_sign};

const INPUT: &[u8] = include_bytes!("../../../testdata/inputs/simple.xml");

fn certs_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/certs")
}

/// CI sets OPENFIRMA_REQUIRE_TESTS so a missing tool or a missing test PKI
/// fails the build instead of quietly skipping. Only the keystore-scoped
/// opt-out (OPENFIRMA_ALLOW_SKIP, read exclusively by openfirma-keystore's
/// tests) may relax this; every other skip stays mandatory — review 07, H-2:
/// one flag for everything let a broken PKI step go green with nothing
/// verified on macOS and Windows.
fn require_or_skip(reason: &str) {
    let required = std::env::var("OPENFIRMA_REQUIRE_TESTS").is_ok();
    let allowed = std::env::var("OPENFIRMA_ALLOW_NONKEYSTORE_SKIP").is_ok();
    if required && !allowed {
        panic!("cannot run the crosscheck: {reason}");
    }
    eprintln!("skipped, {reason}");
}

fn xmlsec_available() -> bool {
    Command::new("xmlsec1")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Name of the document's root element — `ns:name` when prefixed, the bare local
/// name otherwise — which is exactly what `--id-attr:Id <root>` expects on 1.2.x
/// (a prefixed root measured working with its prefix). None if not parseable.
fn root_element_name(doc: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(doc).ok()?;
    // the first element-start tag: anything else beginning with `<` is a
    // comment, processing instruction or doctype, not the root element
    let mut rest: &str = text;
    while let Some(open) = rest.find('<').map(|i| &rest[i..]) {
        if let Some(name_end) = open.find([' ', '>', '/', '\t', '\r', '\n']) {
            let name = &open[1..name_end];
            if !name.starts_with(['?', '!']) && !name.is_empty() {
                return Some(name.to_string());
            }
        }
        rest = &rest[1.min(rest.len())..];
    }
    None
}

/// Whether this xmlsec1 understands `option`. Unknown flags answer
/// `parameter "--x" is not supported` on stderr AND dump their usage banner on
/// stdout — measured against the real 1.2.39, where an earlier version of this probe
/// read only one stream and got it backwards (H-1's lesson, third time). Pass flag
/// prefixes without a value suffix: 1.2.x names the prefix (`--id-attr`, not
/// `--id-attr:Id`). The probe runs with a nonexistent document so nothing is
/// verified either way.
fn xmlsec_accepts(option: &str) -> bool {
    Command::new("xmlsec1")
        .arg("--verify")
        .arg(option)
        .arg("/nonexistent-no-such-file.xml")
        .output()
        .is_ok_and(|o| !String::from_utf8_lossy(&o.stderr).contains("is not supported"))
}

/// The flags that make xmlsec1 resolve `URI="#Id"` references, per version. Both
/// forms measured against real binaries (Arch 1.3.12, Ubuntu 24.04's 1.2.39), not
/// just man pages:
/// - 1.3+: `--add-id-attr Id --verbose`. The tool knows `Id` internally since 1.3,
///   but an explicit statement is what makes the flag self-documenting across
///   versions, and on this line it pairs with `--verbose`.
/// - 1.2.x: `--id-attr:Id <root>` as TWO arguments — appended to one,
///   `--id-attr:Id<root>`, 1.2.39 reads only `<root>` as a second file and parses
///   it (measured: the PEM trust anchor then fails as "Start tag expected"). This
///   line has no built-in knowledge of `Id` — the same document that verifies OK
///   with the flag fails its `xpointer(id(…))` lookup without it, review 07's CI
///   run said so — and it knows neither `--add-id-attr` nor `--verbose`, though it
///   still prints the reference counters these tests assert.
fn id_flags(doc: &[u8]) -> Vec<String> {
    if xmlsec_accepts("--add-id-attr") {
        vec!["--add-id-attr".into(), "Id".into(), "--verbose".into()]
    } else if let Some(root) = root_element_name(doc) {
        vec!["--id-attr:Id".into(), root]
    } else {
        Vec::new()
    }
}

/// xmlsec1 needs the trust anchor for the chain, and the Id must be typed with the
/// flags from `id_flags` for it to resolve the `URI="#…"` references through id():
/// without them a 1.3 fails the XPointer lookup outright and a 1.2 verifies zero
/// references. Both lines print "SignedInfo References (ok/all): n/m" on verify, so
/// callers assert 2/2 unconditionally — tampering demonstrably breaks it, which
/// `xmlsec_notices_a_tampered_document` proves with this exact invocation.
fn xmlsec_verify(file: &Path) -> (bool, String) {
    let doc = std::fs::read(file).unwrap_or_default();
    let mut cmd = Command::new("xmlsec1");
    cmd.args(["--verify", "--enabled-key-data", "x509"])
        .args(id_flags(&doc))
        .args([
            "--trusted-pem",
            certs_dir().join("ca.crt").to_str().unwrap(),
        ])
        .arg(file);
    let out = cmd.output().expect("xmlsec1 disappeared mid test");
    // Fail closed on the exit status: 1.2.39 answers a bare "OK" on stderr while
    // 1.3.x says "Verification status: OK" (measured, both streams). The counters
    // below then say HOW MUCH was actually verified; either way, a nonzero exit is
    // never ok regardless of what the summary lines happen to contain.
    let text =
        String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
    (out.status.success(), text)
}

fn load_signer(cert: &str, key: &str, chain: &[&str]) -> Option<SoftwareSigner> {
    let dir = certs_dir();
    let (Ok(cert_pem), Ok(key_pem)) = (
        std::fs::read_to_string(dir.join(cert)),
        std::fs::read_to_string(dir.join(key)),
    ) else {
        return None;
    };
    let signer = SoftwareSigner::from_pkcs8_pem(&cert_pem, &key_pem).unwrap_or_else(|e| {
        panic!("{cert} / {key} are present but unusable: {e}, rerun tools/gen-testcert.sh")
    });
    let handles = chain
        .iter()
        .map(|c| {
            let pem = std::fs::read_to_string(dir.join(c))
                .unwrap_or_else(|e| panic!("{c} cannot be read: {e}"));
            CertificateHandle::from_pem(&pem).unwrap_or_else(|e| panic!("{c}: {e}"))
        })
        .collect();
    Some(signer.with_chain(handles))
}

fn write_tmp(name: &str, bytes: &[u8]) -> PathBuf {
    // Kept in a fixed directory under TEMP: the CI's macOS runners showed an
    // external verifier rejecting a freshly written file that our own checks had
    // just passed, which is what a race with per-directory temp cleanup looks
    // like. A path we own and do not delete until the next run removes that
    // variable from the diagnosis; tamper tests still clean up right away.
    let dir = std::env::temp_dir().join("openfirma-xades-crosscheck");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}

#[test]
fn xmlsec_verifies_the_rsa_signature() {
    if !xmlsec_available() {
        require_or_skip("xmlsec1 not found, install xmlsec1");
        return;
    }
    let Some(signer) = load_signer(
        "signer-rsa.crt",
        "signer-rsa.key",
        &["intermediate.crt", "ca.crt"],
    ) else {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    let signed = xades_sign(INPUT, &signer, &XadesOptions::default()).expect("signing");
    let path = write_tmp("rsa.xml", &signed);

    let (ok, text) = xmlsec_verify(&path);
    assert!(ok, "xmlsec1 rejected our XAdES-B-B signature:\n{text}");
    // Both versions print the per-reference counters on verify (measured on
    // 1.2.39 and 1.3.12), so requiring them never depends on the flavor.
    assert!(
        text.contains("SignedInfo References (ok/all): 2/2"),
        "not both references verified:\n{text}"
    );
    std::fs::remove_file(&path).ok();
}

/// Review 03, C-1: SignedInfo and SignedProperties used to be canonicalized
/// as detached fragments, so every namespace the DOCUMENT root declares (and
/// its xml:* attributes) was missing from what we digested, while validators
/// compute them over the elements hanging off that root. The signature was
/// then invalid for any document whose root carries an xmlns or an xml:lang —
/// FacturaE and nearly all administrative XML. These are the reviewer's own
/// three shapes; each must have BOTH references verified by xmlsec1's own
/// parser, canonicalizer and digest machinery.
#[test]
fn xmlsec_verifies_signatures_over_documents_with_namespaced_roots() {
    if !xmlsec_available() {
        require_or_skip("xmlsec1 not found, install xmlsec1");
        return;
    }
    let Some(signer) = load_signer(
        "signer-rsa.crt",
        "signer-rsa.key",
        &["intermediate.crt", "ca.crt"],
    ) else {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    let cases: &[(&str, &[u8])] = &[
        // a prefixed root declaring its own ds prefix, the FacturaE shape
        ("ns-root.xml", br#"<fe:Facturae xmlns:fe="http://www.facturae.es/FacturaE/2011/namespaces/facturae" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><Header>x</Header></fe:Facturae>"#),
        // a default namespace on the root: the canonical SignedProperties
        // must carry xmlns="urn:x", which only inherited-context
        // canonicalization prints
        ("defns.xml", br#"<doc xmlns="urn:x"><a>x</a></doc>"#),
        // an xml:lang on the root propagates into both canonical subtrees
        // per C14N 1.0 §2.4
        ("xmllang.xml", br#"<doc xml:lang="es"><a>x</a></doc>"#),
    ];
    for (name, input) in cases {
        let signed = xades_sign(input, &signer, &XadesOptions::default())
            .unwrap_or_else(|e| panic!("signing {name}: {e}"));
        let path = write_tmp(name, &signed);
        let (ok, text) = xmlsec_verify(&path);
        assert!(ok, "xmlsec1 rejected the signature over {name}:\n{text}");
        assert!(
            text.contains("SignedInfo References (ok/all): 2/2"),
            "not both references verified for {name}:\n{text}"
        );
        std::fs::remove_file(&path).ok();
    }
}

#[test]
fn xmlsec_verifies_the_ecdsa_signature() {
    if !xmlsec_available() {
        require_or_skip("xmlsec1 not found, install xmlsec1");
        return;
    }
    let Some(signer) = load_signer(
        "signer-ec.crt",
        "signer-ec.key",
        &["intermediate.crt", "ca.crt"],
    ) else {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    let signed = xades_sign(INPUT, &signer, &XadesOptions::default()).expect("signing");
    let path = write_tmp("ec.xml", &signed);

    let (ok, text) = xmlsec_verify(&path);
    assert!(
        ok,
        "xmlsec1 rejected our ECDSA XAdES-B-B signature:\n{text}"
    );
    std::fs::remove_file(&path).ok();
}

/// A crosscheck that cannot fail is not a crosscheck: one changed character
/// of signed content has to be noticed.
#[test]
fn xmlsec_notices_a_tampered_document() {
    if !xmlsec_available() {
        require_or_skip("xmlsec1 not found, install xmlsec1");
        return;
    }
    let Some(signer) = load_signer(
        "signer-rsa.crt",
        "signer-rsa.key",
        &["intermediate.crt", "ca.crt"],
    ) else {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    let signed = xades_sign(INPUT, &signer, &XadesOptions::default()).expect("signing");
    let text = std::str::from_utf8(&signed).unwrap().to_string();
    let tampered = text.replacen("1234.56", "9999.99", 1);
    assert_ne!(tampered, text, "the tamper point must exist in the output");
    let path = write_tmp("tampered.xml", tampered.as_bytes());

    let (ok, text) = xmlsec_verify(&path);
    assert!(!ok, "xmlsec1 accepted a document whose content was changed");
    // not merely a nonzero exit: the reference digest itself must have failed,
    // or a broken pipeline (missing file, bad flag) would look like detection
    assert!(
        text.contains("SignedInfo References (ok/all): 0/"),
        "xmlsec1 rejected the tampered document without reporting a failed \
         reference — cannot tell detection from breakage:\n{text}"
    );
    std::fs::remove_file(&path).ok();
}
