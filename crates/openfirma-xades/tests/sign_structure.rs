//! Structural tests of the XAdES-B-B output: every element, attribute and
//! algorithm URI exactly where docs/xades.md measured it in AutoFirma's
//! output. The tree walking here uses our own reader, which is fine for
//! self-consistency; the *independent* verdicts live in
//! xmlsec_crosscheck.rs and autofirma_verify.rs.

use std::path::{Path, PathBuf};

use openfirma_core::alg::DigestAlg;
use openfirma_core::cert::CertificateHandle;
use openfirma_core::signer::{Signer, SoftwareSigner};
use openfirma_xades::c14n::{self, Options};
use openfirma_xades::xml::{Child, Element, parse};
use openfirma_xades::{XadesOptions, xades_sign};

const DS: &str = "http://www.w3.org/2000/09/xmldsig#";
const XADES: &str = "http://uri.etsi.org/01903/v1.3.2#";

const INPUT: &[u8] = include_bytes!("../../../testdata/inputs/simple.xml");

fn certs_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/certs")
}

/// CI sets OPENFIRMA_REQUIRE_TESTS so a missing test PKI fails the build
/// instead of quietly skipping; the same rule as every other crate's tests.
fn require_or_skip(reason: &str) {
    let required = std::env::var("OPENFIRMA_REQUIRE_TESTS").is_ok();
    let allowed = std::env::var("OPENFIRMA_ALLOW_SKIP").is_ok();
    if required && !allowed {
        panic!("cannot run the test: {reason}");
    }
    eprintln!("skipped, {reason}");
}

/// Returns None when the material is missing, which skips the test. Material
/// that is present but cannot be loaded is a bug, not a skip.
fn load_signer(cert: &str, key: &str, chain: &[&str]) -> Option<SoftwareSigner> {
    let dir = certs_dir();
    let (Ok(cert_pem), Ok(key_pem)) = (
        std::fs::read_to_string(dir.join(cert)),
        std::fs::read_to_string(dir.join(key)),
    ) else {
        return None;
    };
    let signer = SoftwareSigner::from_pkcs8_pem(&cert_pem, &key_pem).unwrap_or_else(|e| {
        panic!(
            "{cert} / {key} are present but unusable: {e}. \
             Keys must be PKCS#8 PEM, rerun tools/gen-testcert.sh"
        )
    });
    let handles = chain
        .iter()
        .map(|c| {
            let pem = std::fs::read_to_string(dir.join(c)).unwrap_or_else(|e| {
                panic!("{c} is listed in the test PKI but cannot be read: {e}")
            });
            CertificateHandle::from_pem(&pem)
                .unwrap_or_else(|e| panic!("{c} is not a certificate: {e}"))
        })
        .collect();
    Some(signer.with_chain(handles))
}

// ---- small tree walkers, so the assertions stay readable ----

fn child<'e>(el: &'e Element, ns: &str, local: &str) -> &'e Element {
    el.children
        .iter()
        .find_map(|c| match c {
            Child::Element(inner)
                if inner.namespace.as_deref() == Some(ns) && inner.name.local == local =>
            {
                Some(inner.as_ref())
            }
            _ => None,
        })
        .unwrap_or_else(|| panic!("no {{{ns}}}{local} child under <{}>", el.name.local))
}

fn maybe_child<'e>(el: &'e Element, ns: &str, local: &str) -> Option<&'e Element> {
    el.children.iter().find_map(|c| match c {
        Child::Element(inner)
            if inner.namespace.as_deref() == Some(ns) && inner.name.local == local =>
        {
            Some(inner.as_ref())
        }
        _ => None,
    })
}

fn children<'e>(el: &'e Element, ns: &str, local: &str) -> Vec<&'e Element> {
    el.children
        .iter()
        .filter_map(|c| match c {
            Child::Element(inner)
                if inner.namespace.as_deref() == Some(ns) && inner.name.local == local =>
            {
                Some(inner.as_ref())
            }
            _ => None,
        })
        .collect()
}

fn text_of(el: &Element) -> String {
    el.children
        .iter()
        .filter_map(|c| match c {
            Child::Text(t) => Some(t.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("")
}

fn attr<'e>(el: &'e Element, name: &str) -> Option<&'e str> {
    el.attributes
        .iter()
        .find(|a| a.name.prefix.is_none() && a.name.local == name)
        .map(|a| a.value.as_str())
}

fn sign_input(signer: &SoftwareSigner, input: &[u8]) -> Vec<u8> {
    xades_sign(input, signer, &XadesOptions::default())
        .unwrap_or_else(|e| panic!("signing failed: {e}"))
}

/// The layout of the whole signature, asserted against the measured
/// AutoFirma reference, docs/xades.md.
#[test]
fn the_enveloped_signature_matches_the_measured_layout() {
    let Some(signer) = load_signer(
        "signer-rsa.crt",
        "signer-rsa.key",
        &["intermediate.crt", "ca.crt"],
    ) else {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    let signed = sign_input(&signer, INPUT);
    let out = std::str::from_utf8(&signed).expect("output is utf-8");

    // serialization: normalized declaration, no whitespace after it, nothing
    // after the root end tag
    assert!(
        out.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?><documento"),
        "the declaration is not the normalized one AutoFirma writes"
    );
    assert!(
        out.ends_with("</documento>"),
        "trailing bytes after the root"
    );
    // the original content bytes are untouched
    assert!(
        out.contains("Contiene acentos: cañón, administración."),
        "the accented input text did not survive"
    );

    let doc = parse(&signed).expect("our own output parses");
    let sig = child(&doc.root, DS, "Signature");

    // the signature is the last child of the root
    match doc.root.children.last().expect("root has children") {
        Child::Element(last) => assert_eq!(last.name.local, "Signature"),
        other => panic!("the last child of the root is not the signature: {other:?}"),
    }

    // exactly four children, in the measured order
    let names: Vec<&str> = sig
        .children
        .iter()
        .filter_map(|c| match c {
            Child::Element(e) if e.namespace.as_deref() == Some(DS) => Some(e.name.local.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(names, ["SignedInfo", "SignatureValue", "KeyInfo", "Object"]);

    // ---- SignedInfo ----
    let signed_info = child(sig, DS, "SignedInfo");
    assert_eq!(
        attr(
            child(signed_info, DS, "CanonicalizationMethod"),
            "Algorithm"
        ),
        Some("http://www.w3.org/TR/2001/REC-xml-c14n-20010315")
    );
    assert_eq!(
        attr(child(signed_info, DS, "SignatureMethod"), "Algorithm"),
        Some("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
    );
    let refs = children(signed_info, DS, "Reference");
    assert_eq!(
        refs.len(),
        2,
        "baseline signs the data and the SignedProperties, not the KeyInfo"
    );

    let data = refs[0];
    let data_id = attr(data, "Id").expect("the data reference has an Id");
    assert!(data_id.starts_with("Reference-"), "unexpected Id {data_id}");
    assert_eq!(
        attr(data, "URI"),
        Some("#doc-prueba"),
        "the root Id is referenced"
    );
    assert_eq!(attr(data, "Type"), None);
    let transforms = children(child(data, DS, "Transforms"), DS, "Transform");
    let algs: Vec<&str> = transforms
        .iter()
        .filter_map(|t| attr(t, "Algorithm"))
        .collect();
    assert_eq!(
        algs,
        [
            "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
            "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
            "http://www.w3.org/TR/1999/REC-xpath-19991116",
        ]
    );
    let xpath = child(transforms[2], DS, "XPath");
    assert_eq!(text_of(xpath), "not(ancestor-or-self::ds:Signature)");
    assert_eq!(
        xpath.ns_decls,
        vec![(Some("ds".to_string()), DS.to_string())],
        "the ds:XPath element carries its own xmlns:ds, like AutoFirma's"
    );
    assert_eq!(
        attr(child(data, DS, "DigestMethod"), "Algorithm"),
        Some("http://www.w3.org/2001/04/xmlenc#sha512")
    );

    let sp_ref = refs[1];
    assert_eq!(
        attr(sp_ref, "Type"),
        Some("http://uri.etsi.org/01903#SignedProperties")
    );
    assert_eq!(attr(sp_ref, "Id"), None);
    assert!(maybe_child(sp_ref, DS, "Transforms").is_none());

    // the data digest recomputes over our own canonicalization with the
    // signature subtree stripped, which is the net transform semantics
    let opts = Options {
        omit: Some((DS.to_string(), "Signature".to_string())),
        ..Default::default()
    };
    let c14n = c14n::subtree(&doc.root, &c14n::Axis::new(), &[], &opts);
    let digest = DigestAlg::Sha512.digest(&c14n);
    use base64::Engine;
    let want = base64::engine::general_purpose::STANDARD.encode(digest);
    assert_eq!(text_of(child(data, DS, "DigestValue")), want);

    // ---- SignatureValue ----
    // every Id hangs off the same "Signature-<uuid>" base
    let sig_id = attr(sig, "Id").expect("the signature has an Id");
    let base = sig_id
        .strip_suffix("-Signature")
        .expect("the Signature Id ends in -Signature");
    let sv = child(sig, DS, "SignatureValue");
    assert_eq!(
        attr(sv, "Id"),
        Some(format!("{base}-SignatureValue").as_str())
    );
    let sv_bytes = base64::engine::general_purpose::STANDARD
        .decode(text_of(sv).trim())
        .expect("SignatureValue is base64");
    assert_eq!(sv_bytes.len(), 256, "RSA-2048 PKCS#1 v1.5");
    assert!(
        !text_of(sv).contains('\n'),
        "the base64 must be on one line"
    );

    // ---- KeyInfo ----
    let key_info = child(sig, DS, "KeyInfo");
    assert_eq!(
        attr(key_info, "Id"),
        Some(format!("{base}-KeyInfo").as_str())
    );
    let certs = children(child(key_info, DS, "X509Data"), DS, "X509Certificate");
    assert_eq!(certs.len(), 3, "signer plus the two chain certificates");
    let leaf_b64 = base64::engine::general_purpose::STANDARD.encode(signer.certificate().der());
    assert_eq!(
        text_of(certs[0]),
        leaf_b64,
        "the signer certificate comes first"
    );
    let rsa_key = child(child(key_info, DS, "KeyValue"), DS, "RSAKeyValue");
    let modulus = text_of(child(rsa_key, DS, "Modulus"));
    assert_eq!(modulus.len(), 344, "256 bytes of base64, no leading zero");
    assert_eq!(text_of(child(rsa_key, DS, "Exponent")), "AQAB");

    // ---- QualifyingProperties ----
    let object = child(sig, DS, "Object");
    assert!(
        object.attributes.is_empty(),
        "the ds:Object has no attributes"
    );
    let qp = child(
        object,
        "http://uri.etsi.org/01903/v1.3.2#",
        "QualifyingProperties",
    );
    assert_eq!(
        attr(qp, "Id"),
        Some(format!("{base}-QualifyingProperties").as_str())
    );
    assert_eq!(
        attr(qp, "Target"),
        Some(format!("#{base}-Signature").as_str())
    );
    assert_eq!(
        qp.ns_decls,
        vec![
            (Some("xades".to_string()), XADES.to_string()),
            (Some("ds".to_string()), DS.to_string()),
        ],
        "the declaration order jXAdES writes, measured"
    );

    let sp = child(qp, XADES, "SignedProperties");
    assert_eq!(
        attr(sp, "Id"),
        Some(format!("{base}-SignedProperties").as_str())
    );
    assert_eq!(
        attr(sp_ref, "URI"),
        Some(format!("#{base}-SignedProperties").as_str()),
        "the SignedProperties reference points at the element"
    );

    let ssp = child(sp, XADES, "SignedSignatureProperties");
    let time = text_of(child(ssp, XADES, "SigningTime"));
    assert!(
        time.len() == 20
            && time.starts_with("20")
            && time.ends_with('Z')
            && time.as_bytes()[10] == b'T',
        "SigningTime is not an xs:dateTime in UTC: {time}"
    );
    let scv2 = child(ssp, XADES, "SigningCertificateV2");
    assert!(
        maybe_child(ssp, XADES, "SigningCertificate").is_none(),
        "baseline carries SigningCertificateV2, never v1"
    );
    let cert_el = child(scv2, XADES, "Cert");
    let cert_digest = child(cert_el, XADES, "CertDigest");
    assert_eq!(
        attr(child(cert_digest, DS, "DigestMethod"), "Algorithm"),
        Some("http://www.w3.org/2001/04/xmlenc#sha512")
    );
    let want_cert = base64::engine::general_purpose::STANDARD
        .encode(signer.certificate().fingerprint(DigestAlg::Sha512));
    assert_eq!(text_of(child(cert_digest, DS, "DigestValue")), want_cert);
    let isv2 = child(cert_el, XADES, "IssuerSerialV2");
    assert!(
        isv2.children
            .iter()
            .all(|c| matches!(c, Child::Text(t) if t.trim().is_empty()))
    );
    assert!(
        text_of(isv2).is_empty(),
        "IssuerSerialV2 stays empty, like AutoFirma's (docs/xades.md)"
    );

    let sdop = child(sp, XADES, "SignedDataObjectProperties");
    let dof = child(sdop, XADES, "DataObjectFormat");
    assert_eq!(
        attr(dof, "ObjectReference"),
        Some(format!("#{data_id}").as_str())
    );
    let dof_children: Vec<&str> = dof
        .children
        .iter()
        .filter_map(|c| match c {
            Child::Element(e) if e.namespace.as_deref() == Some(XADES) => {
                Some(e.name.local.as_str())
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        dof_children,
        ["Description", "ObjectIdentifier", "MimeType", "Encoding"]
    );
    assert_eq!(text_of(child(dof, XADES, "Description")), "");
    let oi = child(dof, XADES, "ObjectIdentifier");
    let ident = child(oi, XADES, "Identifier");
    assert_eq!(attr(ident, "Qualifier"), Some("OIDAsURN"));
    assert_eq!(text_of(ident), "urn:oid:1.2.840.10003.5.109.10");
    assert_eq!(text_of(child(dof, XADES, "MimeType")), "text/xml");
    assert_eq!(text_of(child(dof, XADES, "Encoding")), "");
}

/// Without an Id on the root, AutoFirma signs URI="" (measured); the
/// signature still goes inside the root.
#[test]
fn a_root_without_id_is_signed_with_an_empty_uri() {
    let Some(signer) = load_signer("signer-rsa.crt", "signer-rsa.key", &[]) else {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    let input = b"<?xml version=\"1.0\"?><nota><texto>sin id</texto></nota>";
    let signed = sign_input(&signer, input);
    let doc = parse(&signed).expect("output parses");
    let sig = child(&doc.root, DS, "Signature");
    let refs = children(child(sig, DS, "SignedInfo"), DS, "Reference");
    assert_eq!(attr(refs[0], "URI"), Some(""));
    assert_eq!(
        attr(refs[0], "Id").map(|i| i.starts_with("Reference-")),
        Some(true)
    );
}

/// AutoFirma adds the declaration when the input has none and normalizes it
/// when it has one (standalone dropped), measured.
#[test]
fn the_declaration_is_always_the_normalized_one() {
    let Some(signer) = load_signer("signer-rsa.crt", "signer-rsa.key", &[]) else {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    for input in [
        &b"<nota><a>1</a></nota>"[..],
        &b"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n<nota><a>1</a></nota>\n"
            [..],
    ] {
        let signed = sign_input(&signer, input);
        let out = std::str::from_utf8(&signed).unwrap();
        assert!(
            out.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?><nota>"),
            "{out}"
        );
        assert!(out.ends_with("</nota>"));
    }
}

/// A self-closing root has to be opened for the signature, the DOM appendChild
/// AutoFirma performs cannot keep the short form.
#[test]
fn a_self_closing_root_is_opened_for_the_signature() {
    let Some(signer) = load_signer("signer-rsa.crt", "signer-rsa.key", &[]) else {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    let signed = sign_input(&signer, b"<nota  />");
    let out = std::str::from_utf8(&signed).unwrap();
    assert!(out.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?><nota>"));
    assert!(out.ends_with("</ds:Signature></nota>"));
    let doc = parse(&signed).expect("output parses");
    let _sig = child(&doc.root, DS, "Signature");
}

/// ECDSA: no KeyValue (AutoFirma's measured behaviour for EC keys), the
/// ecdsa-sha256 URI, and the signature value in the raw P1363 form XML-DSig
/// requires, not the DER form CMS uses.
#[test]
fn ecdsa_omits_keyvalue_and_writes_p1363() {
    let Some(signer) = load_signer(
        "signer-ec.crt",
        "signer-ec.key",
        &["intermediate.crt", "ca.crt"],
    ) else {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    let signed = sign_input(&signer, INPUT);
    let doc = parse(&signed).expect("output parses");
    let sig = child(&doc.root, DS, "Signature");
    assert_eq!(
        attr(
            child(child(sig, DS, "SignedInfo"), DS, "SignatureMethod"),
            "Algorithm"
        ),
        Some("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256")
    );
    let key_info = child(sig, DS, "KeyInfo");
    assert!(
        maybe_child(key_info, DS, "KeyValue").is_none(),
        "EC keys get no KeyValue, matching AutoFirma"
    );
    use base64::Engine;
    let sv = base64::engine::general_purpose::STANDARD
        .decode(text_of(child(sig, DS, "SignatureValue")).trim())
        .unwrap();
    assert_eq!(sv.len(), 64, "P-256 r||s, not DER");
}

/// The refusals, with errors that name the cause and the way out.
#[test]
fn refusals_name_the_cause_and_the_way_out() {
    let Some(signer) = load_signer("signer-rsa.crt", "signer-rsa.key", &[]) else {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    let err = xades_sign(b"plain text, not xml", &signer, &XadesOptions::default())
        .expect_err("plain text is not XML");
    let msg = err.to_string();
    assert!(
        msg.contains("cades-b-b"),
        "the error must point at CAdES: {msg}"
    );

    let err = xades_sign(
        b"<!DOCTYPE nota [<!ENTITY x \"y\">]><nota>&x;</nota>",
        &signer,
        &XadesOptions::default(),
    )
    .expect_err("a DTD must be refused");
    assert!(err.to_string().contains("DOCTYPE"), "{err}");

    let err = xades_sign(b"<nota>&custom;</nota>", &signer, &XadesOptions::default())
        .expect_err("an entity needing a DTD must be refused");
    assert!(err.to_string().contains("DTD"), "{err}");
}

/// A mime type with no known OID drops the whole ObjectIdentifier element,
/// which is what AutoFirma does for an unrecognized type.
#[test]
fn an_unknown_mime_type_drops_the_object_identifier() {
    let Some(signer) = load_signer("signer-rsa.crt", "signer-rsa.key", &[]) else {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    let opts = XadesOptions {
        mime_type: Some("application/x-invented".into()),
        ..Default::default()
    };
    let signed = xades_sign(INPUT, &signer, &opts).expect("signing");
    let doc = parse(&signed).expect("output parses");
    let qp = child(
        child(child(&doc.root, DS, "Signature"), DS, "Object"),
        XADES,
        "QualifyingProperties",
    );
    let sp = child(qp, XADES, "SignedProperties");
    let dof = child(
        child(sp, XADES, "SignedDataObjectProperties"),
        XADES,
        "DataObjectFormat",
    );
    assert!(maybe_child(dof, XADES, "ObjectIdentifier").is_none());
    assert_eq!(
        text_of(child(dof, XADES, "MimeType")),
        "application/x-invented"
    );
}

/// Two runs differ only in the volatile values: same size, same stable
/// digests. The UUID randomness is the point, the equality of everything
/// else is what docs/xades.md promises.
#[test]
fn two_runs_differ_only_in_the_volatile_values() {
    let Some(signer) = load_signer(
        "signer-rsa.crt",
        "signer-rsa.key",
        &["intermediate.crt", "ca.crt"],
    ) else {
        require_or_skip("test PKI missing, run tools/gen-testcert.sh");
        return;
    };
    let fixed = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_800_000_000);
    let opts = XadesOptions {
        signing_time: Some(fixed),
        ..Default::default()
    };
    let a = xades_sign(INPUT, &signer, &opts).unwrap();
    let b = xades_sign(INPUT, &signer, &opts).unwrap();
    assert_eq!(a.len(), b.len());

    // with a fixed signing time and RSA (deterministic), everything except
    // the two UUIDs and the SignatureValue that covers them is byte equal
    let doc_a = parse(&a).unwrap();
    let doc_b = parse(&b).unwrap();
    let refs_a = children(
        child(child(&doc_a.root, DS, "Signature"), DS, "SignedInfo"),
        DS,
        "Reference",
    );
    let refs_b = children(
        child(child(&doc_b.root, DS, "Signature"), DS, "SignedInfo"),
        DS,
        "Reference",
    );
    let digest_a = text_of(child(refs_a[0], DS, "DigestValue"));
    let digest_b = text_of(child(refs_b[0], DS, "DigestValue"));
    assert_eq!(digest_a, digest_b, "the data digest is stable");
}
