//! The committed hostile corpus plus a deterministic mutation sweep (H-11).
//!
//! `testdata/hostile/` collects crash-bait bytes the review rounds found or
//! that protocol probing kept: truncated DER length fields, XML cut off in an
//! attribute, PKCS#12 headers whose SEQ promises more file than exists. The
//! files exist so a failure reproduces byte-identically outside this repo —
//! `cp testdata/hostile/der-seq-eol.der .` and feed it anywhere. Every file
//! must produce a clean typed error from every entry point that can receive
//! foreign bytes of its kind; a panic fails the test.
//!
//! The corpus is deterministic: `tools/gen-hostile-corpus.py` regenerates it
//! byte for byte, and `testdata/hostile/README.md` explains each file. Below
//! the fixed corpus, valid specimens shipped under `testdata/` are swept with
//! reproducible single-byte mutations (fixed seed, fixed count), so deep
//! parser paths get hostile input on every CI run without pulling a fuzzing
//! crate into the dependency set — the seam for a future cargo-fuzz target is
//! the same call list the sweep already runs (`feed_all`).

use std::path::{Path, PathBuf};

use openfirma_cades::revocation;
use openfirma_cades::tsp;
use openfirma_cades::verify::{VerifyOptions, verify};
use openfirma_core::alg::DigestAlg;
use openfirma_keystore::Pkcs12;
use openfirma_xades::{c14n, xml};

fn hostile_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/hostile")
}

fn read(name: &str) -> Vec<u8> {
    let path = hostile_dir().join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("corpus file {} missing: {e}", path.display()))
}

#[test]
fn der_corpus_refuses_through_every_cms_and_tsp_entry_point() {
    for name in [
        "der-contentinfo-trunc.der",
        "der-longlen-huge.der",
        "der-seq-eol.der",
        "der-null-len.der",
    ] {
        let bytes = read(name);
        // The outer parse must refuse as a verification verdict (the relabel
        // wave 3 established): no panic, no raw codec error escaping.
        let text = match verify(&bytes, None, &VerifyOptions::new(Vec::new())) {
            Ok(_) => panic!("{name} verified?! it is a handful of bytes of DER bait"),
            Err(e) => e.to_string(),
        };
        assert!(
            !text.is_empty(),
            "{name}: refusal must carry a message (got none)"
        );
        // The same bytes through the TSA-response door: refusing is required,
        // and only refusing — panicking fails this test by unwinding.
        let _ = tsp::token_from_response(&bytes, DigestAlg::Sha256, b"x", None)
            .expect_err("{name} cannot be a TimeStampResp");
        let _ = tsp::token_imprint(&bytes);
        // CRL/OCSP readers may refuse however they like — they must only
        // never panic, so the results are dropped.
        let _ = revocation::verify_crl(&bytes, &[], std::time::SystemTime::now());
        let _ = revocation::parse_ocsp_response(&bytes);
    }
}

#[test]
fn xml_corpus_never_panics_and_names_the_truncation() {
    let bytes = read("xml-truncated-tag.xml");
    let err = xml::parse(&bytes).expect_err("an attribute cut at EOF is not a document");
    // The refusal names what went missing where the input stopped; any of
    // the parser's EOF-family wordings qualifies, an empty one does not.
    let text = err.to_string().to_lowercase();
    assert!(
        text.contains("expected") || text.contains("end") || text.contains("eof"),
        "the truncation refusal must name the missing syntax: {text}"
    );

    // An undeclared prefix may be refused by the parser (as an error) or
    // carried through for signature code to resolve — but must never reach
    // canonicalization as a panic. Both outcomes are exercised here.
    let bytes = read("xml-undeclared-prefix.xml");
    if let Ok(doc) = xml::parse(&bytes) {
        let _ = c14n::document(&doc, &c14n::Options::default());
    }

    // Deep but legal nesting must parse (MAX_DEPTH is 512; 140 is inside it).
    let bytes = read("xml-deep-nesting.xml");
    xml::parse(&bytes).expect("140 nested elements are within the parser's depth limit");

    // Invalid UTF-8 inside text content: refused or tolerated, never panicked.
    let bytes = read("xml-bad-utf8.xml");
    let _ = xml::parse(&bytes);
}

#[test]
fn pkcs12_corpus_refuses_with_an_error() {
    for name in ["p12-garbage-head.p12", "p12-truncated-header.p12"] {
        let bytes = read(name);
        let err =
            Pkcs12::load(&bytes, "anything").expect_err("a truncated or junked PFX must not load");
        assert!(!err.to_string().is_empty(), "{name}: empty error text");
    }
}

/// xorshift64* — deterministic, seeded, and dependency-free by ADR-0004's
/// rule; the corpus sweep only needs repeatable pseudo-random choices.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// Every parser that legitimately receives foreign bytes of one family, run
/// over one input. Nothing here may panic; return values are the parsers'
/// business. Kept as a single call list so this sweep and any future libfuzzer
/// target share it — a crash found by either reproduces through this exact
/// sequence (finding names: cades::verify, tsp, revocation, xml/c14n, Pkcs12).
fn feed_all(family: &str, bytes: &[u8]) {
    match family {
        "cms" => {
            let _ = verify(bytes, None, &VerifyOptions::new(Vec::new()));
            let _ = tsp::token_imprint(bytes);
            let _ = tsp::token_from_response(bytes, DigestAlg::Sha256, b"sweep", None);
            let _ = revocation::verify_crl(bytes, &[], std::time::SystemTime::now());
            let _ = revocation::parse_ocsp_response(bytes);
        }
        "xml" => {
            if let Ok(doc) = xml::parse(bytes) {
                let _ = c14n::document(&doc, &c14n::Options::default());
            }
        }
        "p12" => {
            let _ = Pkcs12::load(bytes, "sweep");
        }
        other => panic!("unknown sweep family {other}"),
    }
}

#[test]
fn mutation_sweep_of_shipped_specimens_never_panics() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata");
    // DER specimens: the golden CMS blobs — real signed data whose every byte
    // an attacker could flip in transit. XML: the golden XADES envelope.
    // P12: the test container (it is machine-generated throwaway material,
    // present wherever tools/gen-testcert.sh ran; absent elsewhere simply
    // shortens the sweep, like the other keystore tests' skips).
    let mut specs: Vec<(&str, Vec<u8>)> = Vec::new();
    for p in [
        ("cms", "golden/juridical.openfirma.csig"),
        ("cms", "golden/juridical.autofirma.csig"),
        ("xml", "golden/juridical.openfirma.xades.xml"),
        ("p12", "certs/signer-rsa.p12"),
    ] {
        if let Ok(bytes) = std::fs::read(root.join(p.1)) {
            specs.push((p.0, bytes));
        }
    }
    assert!(!specs.is_empty(), "testdata/golden must ship its specimens");

    // Three mutation kinds, each a fixed number of samples per specimen:
    // byte flips (hostile structure stays mostly valid — reaches the deepest
    // checks), truncations at every order of magnitude (the classic off-by-
    // end family), and full sweeps for small files.
    let mut rng = Rng(0x07E1_1C1A_2026_1017);
    for (family, spec) in &specs {
        assert!(!spec.is_empty(), "a shipped specimen is empty");
        // byte flips: 40% of the file's length, capped so big golden PDFs do
        // not dominate CI time — depth matters more than sheer count.
        let flips = (spec.len() / 5).clamp(64, 2_000);
        for _ in 0..flips {
            let i = rng.below(spec.len());
            let mut mutated = spec.clone();
            // XOR with a random non-zero byte: flips at least one bit.
            let mask = (rng.next() % 255) as u8 + 1;
            mutated[i] ^= mask;
            feed_all(family, &mutated);
        }
        // truncations: every prefix at ~200 logarithmic steps, plus a dense
        // scan of the first 256 bytes and the last 256 (length fields cluster
        // at the start; trailers carry their own claims).
        let mut cuts: Vec<usize> = (1..=spec.len().min(256)).collect();
        cuts.extend((0..200).map(|i| spec.len() * (i + 1) / 200));
        cuts.extend(spec.len().saturating_sub(256)..spec.len());
        for cut in cuts.into_iter().filter(|c| *c < spec.len()) {
            feed_all(family, &spec[..cut]);
        }
    }
}
