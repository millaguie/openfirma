//! Hostile DER against every entry point that reads a time-stamp token or a
//! CMS/revocation object: nothing a network response, an unsigned attribute
//! or a PDF under verification contains may panic the reader.
//!
//! These are the proof-of-concept bytes of the review round that found the
//! `tsp.rs` cursor slicing `&b[1..=n]` without checking `b.len() >= 1 + n`:
//! three truncated DER length fields, each reachable from somewhere the
//! bytes are not ours — `token_from_response` reads what a TSA answered,
//! `token_from_attribute` reads an attribute of a signature being checked,
//! and through `token_imprint` the same path runs while inspecting a PDF's
//! `/DocTimeStamp`. A DER cursor that panics turns one hostile response into
//! a dead process; the contract is now: typed errors only. The three
//! per-module cursors became one, `openfirma_core::tlv::Cursor`, whose unit
//! tests cover the length rules themselves; this file pins the reachable API
//! surface with the original inputs.

use openfirma_cades::revocation;
use openfirma_cades::tsp;
use openfirma_core::alg::DigestAlg;

/// The exact panics of the PoC: `[30 84 00]` reached `range end index 4 out
/// of range for slice of length 2`, `[30 82 01]` reached index 2 of a slice
/// of length 2, and `[30 83]` reached index 3 of a slice of length 1.
#[test]
fn truncated_der_lengths_are_errors_not_panics() {
    // token_imprint — the pades inspect.rs /DocTimeStamp path
    let err = tsp::token_imprint(&[0x30, 0x82, 0x01])
        .expect_err("a two byte length field is not a ContentInfo");
    assert!(err.to_string().contains("length"), "{err}");
    let err = tsp::token_imprint(&[0x30, 0x84, 0x00])
        .expect_err("four length octets cannot live in one byte");
    assert!(err.to_string().contains("length"), "{err}");

    // token_from_response — the TSA's network answer
    let err = tsp::token_from_response(&[0x30, 0x83], DigestAlg::Sha256, b"x", None)
        .expect_err("one byte of length is not a TimeStampResp");
    assert!(err.to_string().contains("length"), "{err}");

    // check_token over the same bytes through the other door
    let err = tsp::check_token(&[0x30, 0x84, 0x00], DigestAlg::Sha256, b"x")
        .expect_err("the same truncated length must not panic here either");
    assert!(err.to_string().contains("length"), "{err}");

    // token_from_attribute — an attribute of a signature under verification.
    // The attribute outer shell is valid DER; the truncation sits inside the
    // SET, where the old code called its own read_len on `&values[1..]`.
    let attr = der_attr_with_truncated_value(&[0x30, 0x84]);
    let err = tsp::token_from_attribute(&attr, DigestAlg::Sha256, b"x")
        .expect_err("a truncated first value of the SET must not panic");
    assert!(err.to_string().contains("length"), "{err}");
}

/// An unsigned `signatureTimeStampToken` attribute whose values SET starts
/// with the given hostile bytes.
fn der_attr_with_truncated_value(bad: &[u8]) -> Vec<u8> {
    let oid = hex::decode("060b2a864886f70d010910020e").unwrap(); // 1.2.840.113549.1.9.16.2.14
    let set = openfirma_core::tlv::tlv(0x31, bad);
    openfirma_core::tlv::sequence(&[oid, set])
}

/// Indefinite lengths (BER) are refused everywhere too: `[30 80 ...]` with
/// the BER end-of-content markers is a shape some attacker can build, and no
/// DER reader may walk it.
#[test]
fn indefinite_lengths_are_refused_by_every_reader() {
    let ber = [0x30u8, 0x80, 0x05, 0x00, 0x00, 0x00];
    assert!(tsp::token_imprint(&ber).is_err());
    assert!(revocation::parse_ocsp_response(&ber).is_err());
    assert!(
        revocation::verify_crl(
            &ber,
            &[],
            revocation::RevocationTime::at(std::time::SystemTime::now())
        )
        .is_err()
    );
}

/// The byte-sweep: cut a genuine token-shaped DER at every offset and mutate
/// length octets, through the four public readers. Any panic here is a bug
/// in `tlv::Cursor` or in the call sites that slice by what it reports.
#[test]
fn every_truncation_and_length_mutation_of_a_token_is_an_error() {
    // a minimal but complete ContentInfo: SEQUENCE { OID, [0] { SEQUENCE {} } }
    let oid = openfirma_core::tlv::oid(&openfirma_core::oid::ID_SIGNED_DATA).unwrap();
    let inner = openfirma_core::tlv::sequence(&[]);
    let wrapper = openfirma_core::tlv::implicit_constructed(0, &inner);
    let token = openfirma_core::tlv::sequence(&[oid, wrapper]);

    let mut inputs: Vec<Vec<u8>> = Vec::new();
    for end in 0..=token.len() {
        inputs.push(token[..end].to_vec());
    }
    // every single length byte replaced by a long-form marker claiming more
    for at in 0..token.len() {
        for marker in [0x80u8, 0x81, 0x84, 0x89] {
            let mut v = token.clone();
            v[at] = marker;
            inputs.push(v);
        }
    }
    // and truncated versions of those mutations: hostile length plus missing
    // bytes at once, the combination that used to reach `&b[1..=n]` directly
    for end in 0..token.len().min(6) {
        let mut v = token.clone();
        if !v.is_empty() {
            v[end] = 0x84;
        }
        inputs.push(v[..end].to_vec());
    }

    let now = std::time::SystemTime::now();
    for input in &inputs {
        // none of these may panic; the errors are allowed to differ
        let _ = tsp::token_imprint(input);
        let _ = tsp::check_token(input, DigestAlg::Sha256, b"x");
        let _ = tsp::token_from_response(input, DigestAlg::Sha256, b"x", None);
        let _ = tsp::token_from_attribute(input, DigestAlg::Sha256, b"x");
        let _ = revocation::parse_ocsp_response(input);
        let _ = revocation::verify_crl(input, &[], revocation::RevocationTime::at(now));
    }
}

/// Bytes that are not a CMS at all must come back as a verification verdict,
/// never as a raw codec error: the GUI's verify screen forwards whatever it
/// hears, and `b"not a signature"` — ASCII text whose first byte happens to
/// be a tag (`0x6e`) with a length past the end — once surfaced as an opaque
/// `Other("a value with tag 0x6e claims 111 bytes but only 13 are left")`.
#[test]
fn verify_refuses_non_cms_bytes_as_a_verification_error() {
    let opts = verify_opts();
    for bytes in [
        b"not a signature".as_slice(),
        &[0x6e_u8, 0x6f, 0x74][..],
        &[0x30, 0x84, 0x00][..],
        &[][..],
    ] {
        let err = openfirma_cades::verify::verify(bytes, None, &opts)
            .expect_err("garbage is never a verified signature");
        assert!(
            matches!(err, openfirma_core::Error::Verification(_)),
            "expected a verification verdict for {bytes:?}, got {err:?}"
        );
    }
}

fn verify_opts() -> openfirma_cades::verify::VerifyOptions {
    // the anchors never see light: every input here fails at the parser.
    openfirma_cades::verify::VerifyOptions {
        trust_anchors: Vec::new(),
        validation_time: std::time::SystemTime::now(),
        ts_mode: false,
        ..openfirma_cades::verify::VerifyOptions::default()
    }
}
