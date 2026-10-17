//! Finding A-4 (precalculatedHashAlgorithm / extraParams) — pre-hash applied,
//! not ignored, and the gate refuses by name everything else.
//!
//! autoscript.js ships a `precalculateHash()` helper that hashes the document
//! in the page and sends only the digest with `precalculatedHashAlgorithm=…`
//! (recorded: lines 990–1058, 2157–2243 of docs/validation.md#reference-corpus/…/
//! autoscript.js). AutoFirma's side is recorded in `CAdESParameters.load`
//! (lines 119–155): the payload becomes `dataDigest` verbatim, `contentData`
//! is null, and the property's name OVERRIDES the URI's digest algorithm.
//! Ignoring that property while signing the digest bytes as if they were the
//! document produces a structurally valid signature over the wrong content —
//! it opens cleanly in no viewer, but only after someone trusts it. These
//! tests pin the opposite: openfirma puts the payload into the message imprint
//! (openssl's verdict below follows the HASH bytes, never the document), and
//! every property it does not implement is refused by name before anything is
//! asked of the key.

use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

/// DER object-identifier encoding of sha256WithRSAEncryption (1.2.840.113549.1.1.11).
const SHA256_RSA_OID: &[u8] = &[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
];

fn certs_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/certs")
}

fn require_or_skip(reason: &str) {
    let required = std::env::var("OPENFIRMA_REQUIRE_TESTS").is_ok();
    let allowed = std::env::var("OPENFIRMA_ALLOW_SKIP").is_ok();
    if required && !allowed {
        panic!("cannot run the test: {reason}");
    }
    eprintln!("skipped, {reason}");
}

fn p12() -> Option<PathBuf> {
    let path = certs_dir().join("signer-rsa.p12");
    path.exists().then_some(path)
}

/// Percent-encode like `encodeURIComponent` does for the characters base64 can
/// produce — how a real page's URI carries `dat` and `properties` (fake_sede's
/// uri_body mirrors the same rule).
fn enc(text: &str) -> String {
    let mut out = String::new();
    for b in text.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn url_safe(bytes: &[u8]) -> String {
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE, bytes)
}

/// One sign URI in the shape a sede's page builds: `dat` as percent-encoded
/// base64. The returned string is what `uri::parse` receives; tests name their
/// own extra parameters on top of it so nothing about the recorded shape hides
/// between helper and assertion.
fn sign_uri(dat: &str, format: &str) -> String {
    format!(
        "afirma://sign?dat={}&format={format}&algorithm=SHA256withRSA",
        enc(dat)
    )
}

/// The page's getProperties(): a Java properties file, base64 as the shipped
/// jar encodes it (`Base64.encode(x, true)`), percent-encoded by
/// encodeURIComponent. Appended as `properties=`.
fn with_properties(uri: String, props: &[u8]) -> String {
    let b64 = url_safe(props);
    format!("{uri}&properties={}", enc(&b64))
}

/// The page-side half of the contract: autoscript.js's processSignResponse
/// folds `-`/`_` back to `+`/`/` and splits on `|`. Returning the signature
/// field as DER is what a sede actually feeds its verification.
fn signature_der(result: &openfirma_browser::dispatch::BrowserResult) -> Vec<u8> {
    let folded: Vec<u8> = result
        .payload
        .iter()
        .map(|b| match b {
            // The page-side fold is what autoscript.js records; the only
            // '-'/'_' a correct payload can carry came from the URL-safe
            // alphabet (dispatch::base64_url pins that form).
            b'-' => b'+',
            b'_' => b'/',
            other => *other,
        })
        .collect();
    let text = String::from_utf8(folded).expect("the wire payload is ASCII");
    let (_, sig) = text
        .split_once('|')
        .expect("cert|signature, AutoFirma's shape");
    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, sig)
        .expect("the folded signature field is standard base64 DER")
}

/// The signed `messageDigest` bytes of a CMS blob, by raw DER walk. OID
/// 1.2.840.113549.1.9.4 is `…01 09 04`; its attribute is
/// `SEQUENCE { OID, SET OF attrValues }` and the single attrValue here is the
/// OCTET STRING carrying the imprint (`31 <len> 04 <len> <digest>`, measured
/// against the producer's output). The ESS signingCertificateV2 attribute
/// embeds a CertID whose digest is ANOTHER SHA-256 (of the signer cert); it
/// rides inside that attribute as raw OCTET STRING data (`… 04 20 …`), never
/// as `OID followed by 0x31`, which is what pins the real messageDigest and
/// refuses every collision a certificate hash could produce. Two attributes
/// claiming about the content mean no single claim: None-verdict false below.
fn claimed_message_digest(der: &[u8]) -> Option<Vec<u8>> {
    const MESSAGE_DIGEST_OID: &[u8] = &[
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04,
    ];
    /// Read one DER length at b[0..]: (header bytes, value length).
    fn der_len(b: &[u8]) -> Option<(usize, usize)> {
        let first = *b.first()?;
        if first < 0x80 {
            Some((1, first as usize))
        } else {
            let n = (first & 0x7f) as usize;
            if n == 0 || n > 4 || b.len() < 1 + n {
                return None;
            }
            let mut len = 0usize;
            for byte in &b[1..1 + n] {
                len = len * 256 + *byte as usize;
            }
            Some((1 + n, len))
        }
    }
    let mut claimed: Option<Vec<u8>> = None;
    let mut at = 0;
    while let Some(rel) = der[at..]
        .windows(MESSAGE_DIGEST_OID.len())
        .position(|w| w == MESSAGE_DIGEST_OID)
    {
        let i = at + rel;
        let rest = der.get(i + MESSAGE_DIGEST_OID.len()..)?;
        if rest.first() == Some(&0x31) {
            if let Some((set_hdr, set_len)) = der_len(rest.get(1..)?) {
                if let Some(set_body) = rest.get(1 + set_hdr..1 + set_hdr + set_len) {
                    if set_body.first() == Some(&0x04) {
                        if let Some((oct_hdr, oct_len)) = der_len(set_body.get(1..)?) {
                            if let Some(value) = set_body.get(1 + oct_hdr..1 + oct_hdr + oct_len) {
                                if claimed.is_some() {
                                    // Two messageDigest attributes: no single
                                    // claim exists to match against anything.
                                    return None;
                                }
                                claimed = Some(value.to_vec());
                            }
                        }
                    }
                }
            }
        }
        at = i + 1;
    }
    claimed
}

/// `openssl smime -verify` a detached CMS against `content`, the synthetic
/// chain as trust. openssl shares no code with this repository, so its verdict
/// means what it says (sede_crosscheck's own lesson: `-binary` belongs to the
/// signature side; here every file is written exactly, and the content is the
/// whole story).
fn openssl_verdict(der: &[u8], content: &[u8], tag: &str) -> bool {
    let dir = TempDir::new().unwrap();
    let cms = dir.path().join("blob.der");
    let cnt = dir.path().join("content.bin");
    std::fs::write(&cms, der).unwrap();
    std::fs::write(&cnt, content).unwrap();
    let out = Command::new("openssl")
        .args(["smime", "-verify", "-inform", "DER"])
        .arg("-in")
        .arg(&cms)
        .arg("-content")
        .arg(&cnt)
        .arg("-CAfile")
        .arg(certs_dir().join("chain.crt"))
        .arg("-noout")
        .output()
        .expect("openssl");
    if !out.status.success() {
        let text = String::from_utf8_lossy(&out.stderr);
        // A failure naming the messageDigest is the informative case for a
        // pre-hash test (it quotes both hashes), so surface it on success too.
        eprintln!("openssl refused {tag}: {}", text.trim());
    }
    out.status.success()
}

#[test]
fn the_test_helper_itself_round_trips_the_page_shape() {
    // sign_uri's `properties` leg mirrors getProperties(): base64 of one
    // properties line, percent-encoded by encodeURIComponent. If this tiny
    // round-trip ever broke, every A-4 assertion below would be vacuous.
    let built = with_properties(
        sign_uri("aGVsbG8=", "CAdES-B-B"),
        b"precalculatedHashAlgorithm=SHA-256\n",
    );
    let parsed = openfirma_browser::uri::parse(&built).expect("the recorded shape parses");
    assert_eq!(
        parsed.properties.get("precalculatedHashAlgorithm"),
        Some("SHA-256"),
        "the helper must reproduce the page's properties encoding exactly"
    );
}

#[test]
fn a_precalculated_hash_is_signed_as_the_imprint_and_verification_follows_the_hash() {
    let Some(key) = p12() else {
        require_or_skip("testdata/certs/signer-rsa.p12 is missing");
        return;
    };
    if Command::new("openssl").arg("version").output().is_err() {
        require_or_skip("openssl not found");
        return;
    }
    // A sede that pre-hashes sends THE HASH as dat (autoscript.js's
    // precalculateHash posts the digest, not the document). These are its
    // bytes and the document they came from.
    let document = b"documento que la sede pre-hashea".to_vec();
    let sha256 = openfirma_core::DigestAlg::Sha256.digest(&document);
    let ks = KeySource::P12 {
        path: &key,
        password: "openfirma",
    };

    // The parser reads the properties parameter and keeps its members (A-4).
    let parsed = openfirma_browser::uri::parse(&with_properties(
        sign_uri(&url_safe(&sha256), "CAdES-B-B"),
        b"precalculatedHashAlgorithm=SHA-256\n",
    ))
    .expect("the recorded shape parses");
    assert_eq!(
        parsed.properties.get("precalculatedHashAlgorithm"),
        Some("SHA-256"),
        "A-4: the properties parameter is READ, not ignored"
    );

    // The property selects the signature's DIGEST ALGORITHM (AutoFirma's rule:
    // CAdESParameters.load line 134 feeds it through getDigestAlgorithmName).
    // With SHA-1 named, the core's conservative signing policy refuses — a
    // client that IGNORED the property would have signed SHA256withRSA and
    // stayed silent. The message is the policy's own sentence about SHA-1.
    let parsed_sha1 = openfirma_browser::uri::parse(&with_properties(
        sign_uri(&url_safe(&sha256), "CAdES-B-B"),
        b"precalculatedHashAlgorithm=SHA-1\n",
    ))
    .expect("the recorded shape parses");
    let err = execute(&parsed_sha1, &ks).expect_err("a SHA-1 imprint hits the signing policy");
    assert!(
        err.message.to_lowercase().contains("sha-1"),
        "A-4 applied means the HASH ALGORITHM GOVERNS the sign, not just the \
         payload: {err}"
    );

    // The positive door: dispatch puts THE PAYLOAD ITSELF (the sede's hash)
    // into messageDigest — `dataDigest = data` (CAdESParameters.load:135), no
    // second hashing. Two independent verifiers say so:
    //   * openssl checks the SIGNATURE VALUE over the signed attributes; the
    //     imprint rides inside them, and its `-verify` passes against a content
    //     whose digest matches the signed messageDigest (openssl does not re-
    //     hash when eContent is absent — that gap belongs to the check below);
    //   * `message_digest_matches`, a raw DER walk using no openfirma code.
    let result = execute(&parsed, &ks).expect("a SHA-256 imprint signs");
    let der = signature_der(&result);
    assert!(
        der.windows(SHA256_RSA_OID.len())
            .any(|w| w == SHA256_RSA_OID),
        "the signature announces sha256WithRSAEncryption"
    );
    assert!(
        openssl_verdict(&der, &sha256, "pre-hash against the hash"),
        "openssl must accept the pre-hash signature against the sede's hash bytes"
    );
    // A detached pre-hash CMS carries NO eContent (contentData = null, line
    // 136), so messageDigest holds the imprint verbatim — no OCTET STRING
    // wraps a re-hashed payload. Scanning for the sede's hash in the DER is
    // the claim "the payload was placed, not hashed again"; its absence would
    // mean the digest of something else signed (which openssl above proves was
    // NOT sha256(document), and what the no-property twin below pins too).
    let imprint_hex: String = sha256.iter().map(|b| format!("{b:02x}")).collect();
    let hexed: String = der.iter().map(|b| format!("{b:02x}")).collect();
    assert!(
        hexed.contains(&imprint_hex),
        "the sede's hash bytes must sit in the CMS verbatim (dataDigest = data, \
         no second hashing)"
    );

    // The walk form of the same claim — attribute-precise, via the helper that
    // extracts the SIGNED messageDigest bytes directly. For a pre-hash CMS the
    // imprint equals the payload itself (dataDigest = data), so `claimed` is
    // exactly the sede's hash; and it is NOT sha256(document) — the client
    // that hashed-the-hash (or ignored the property and hashed the payload
    // twice) fails here, which is the exact A-4 bug.
    assert_eq!(
        claimed_message_digest(&der).as_deref(),
        Some(sha256.as_slice()),
        "the signed messageDigest is THE PAYLOAD ITSELF (AutoFirma's dataDigest = \
         data, no second hashing)"
    );
    // And the negative twin states itself: for a pre-hash signature there is
    // no "other content" whose digest could have ridden in place of the
    // payload — the property made the bytes themselves the imprint and
    // openfirma hashed nothing (the hex scan above pins the verbatim presence;
    // openssl pins that a re-hash of the document did NOT sign). The
    // discriminating comparison lives in the no-property twin below, where the
    // claimed value separates an applied property from an ignored one.

    // And the same payload WITHOUT the property: it is then an ordinary
    // document (the sede's 32 hash bytes as raw content), so its imprint is
    // sha256 OF THOSE BYTES — one hashing over exactly what arrived. That
    // value (`sha256`) is the same buffer the pre-hash twin carries verbatim,
    // and it differs from a hypothetical re-hash sha256(sha256) = the second-
    // order digest; so across the two twins this pins: with the property, zero
    // hashings (payload verbatim); without it, exactly one over the document.
    let plain = openfirma_browser::uri::parse(&sign_uri(&url_safe(&sha256), "CAdES-B-B"))
        .expect("the recorded shape parses");
    let r = execute(&plain, &ks).expect("without the property the payload is a document");
    let der_plain = signature_der(&r);
    assert!(
        openssl_verdict(&der_plain, &sha256, "no-property against the payload"),
        "without the property the payload IS the document: openssl closes against it"
    );
    // The discriminator: one hashing over the document that arrived (not zero,
    // not two — both alternatives fail this byte-for-byte).
    assert_eq!(
        claimed_message_digest(&der_plain).as_deref(),
        Some(openfirma_core::DigestAlg::Sha256.digest(&sha256).as_slice()),
        "without the property the payload IS a document and its imprint is sha256 \
         OF IT: one hashing, over exactly the bytes that arrived"
    );
}

#[test]
fn a_precalculated_hash_over_pades_refuses_by_name() {
    // The recorded parameter is CAdES-specific (CAdESExtraParams). Accepting it
    // over PAdES — where the imprint lives in a byte range, not a CMS
    // signedAttribute — would be guessing; A-4 says refuse by name. The refusal
    // must come from the property gate itself, never from the keystore (an
    // unsupported property is refused before anything is asked of the key).
    let parsed = openfirma_browser::uri::parse(&with_properties(
        sign_uri("ZmFrZSBkb2N1bWVudAo=", "PADES"),
        b"precalculatedHashAlgorithm=SHA-256\n",
    ))
    .expect("the recorded shape parses");
    let ks = KeySource::P12 {
        path: Path::new("/nonexistent/there-is-no-key.p12"),
        password: "x",
    };
    let err = execute(&parsed, &ks).expect_err("pre-hash over PAdES is refused");
    assert_eq!(err.code, "properties-unsupported");
    assert_eq!(err.wire.af_code, "600105");
    assert!(
        err.message.contains("precalculatedHashAlgorithm"),
        "the refusal names the property: {err}"
    );

    // An unreadable algorithm name is refused too (AutoFirma's own
    // getDigestAlgorithmName throws on it — CAdESParameters.load:143 catches
    // NoSuchAlgorithmException and aborts; openfirma refuses by name at the
    // gate instead of signing the payload as a document).
    let parsed = openfirma_browser::uri::parse(&with_properties(
        sign_uri("ZmFrZSBkb2N1bWVudAo=", "CAdES-B-B"),
        b"precalculatedHashAlgorithm=MD5-ish\n",
    ))
    .expect("the recorded shape parses");
    let err = execute(&parsed, &ks).expect_err("an unreadable hash algorithm refuses");
    assert_eq!(err.code, "properties-unsupported");

    // mode=explicit is implemented and therefore NOT refused (recording that
    // the gate is selective, not a blanket rejection of everything).
    let parsed = openfirma_browser::uri::parse(&with_properties(
        sign_uri("ZmFrZSBkb2N1bWVudAo=", "PADES"),
        b"mode=explicit\n",
    ))
    .expect("the recorded shape parses");
    let err = execute(&parsed, &ks).expect_err("this key does not exist");
    assert_ne!(
        err.code, "properties-unsupported",
        "mode=explicit passes the property gate: {err}"
    );
}

#[test]
fn an_unknown_property_refuses_by_name_before_anything_is_asked_of_the_key() {
    // The keystore does not exist on purpose: whatever happens next, the
    // FIRST refusal must name the property, never the key (finding A-4 — a
    // sede's extraParams are a decision about WHAT gets signed and must not
    // depend on the key being readable).
    let ks = KeySource::P12 {
        path: Path::new("/nonexistent/there-is-no-key.p12"),
        password: "x",
    };

    // Unknown member, refused with its name in the message.
    let parsed = openfirma_browser::uri::parse(&with_properties(
        sign_uri("ZmFrZSBkb2N1bWVudAo=", "CAdES-B-B"),
        b"visiblePdfSignature=true\n",
    ))
    .expect("the recorded shape parses");
    let err = execute(&parsed, &ks).expect_err("an unknown member refuses");
    assert_eq!(err.code, "properties-unsupported");
    assert!(
        err.message.contains("visiblePdfSignature"),
        "the refusal names the unknown property: {err}"
    );

    // A known-but-unimplemented one also refuses by name (never a silent drop)
    // and carries AutoFirma's UNSUPPORTED_FORMAT pair on the wire.
    let parsed = openfirma_browser::uri::parse(&with_properties(
        sign_uri("ZmFrZSBkb2N1bWVudAo=", "PADES"),
        b"signatureVersion=PAdES-B-LT\n",
    ))
    .expect("the recorded shape parses");
    let err = execute(&parsed, &ks).expect_err("an unimplemented member refuses");
    assert_eq!(err.code, "properties-unsupported");
    assert_eq!(err.wire.old_code, "SAF_06");

    // Another recorded CAdESExtraParams member openfirma does not implement.
    let parsed = openfirma_browser::uri::parse(&with_properties(
        sign_uri("ZmFrZSBkb2N1bWVudAo=", "CAdES-B-B"),
        b"onlyRealSigners=true\n",
    ))
    .expect("the recorded shape parses");
    let err = execute(&parsed, &ks).expect_err("onlyRealSigners is unimplemented");
    assert_eq!(err.code, "properties-unsupported");
}

use openfirma_browser::dispatch::{KeySource, execute};
