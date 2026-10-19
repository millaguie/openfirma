//! Quadratic-cost regressions: the parser and the canonicalizer must scale
//! linearly with what a document contains, because both are handed files and
//! browser payloads nobody vouches for.
//!
//! Review 03 M-2 measured the old behaviour on these very shapes: an element
//! with 10 000 attributes took 0.65 s and one with 4 000 namespace prefixes
//! over 400 children took 26.7 s in a *debug* binary, quadrupling per doubling
//! of the input — a megabyte of the second pattern was hours. The fixes are a
//! set for duplicate-attribute detection in `xml.rs` and a push/pop scope
//! stack in `c14n.rs`. A generous wall-clock bound (seconds where the bug
//! needed minutes) turns that into a regression test that cannot flake on a
//! loaded runner but fails immediately if either scan comes back.

use std::time::Instant;

use openfirma_xades::{c14n, xml};

fn c14n_of(input: &[u8]) -> Vec<u8> {
    let doc = xml::parse(input).expect("the synthetic document must parse");
    c14n::document(&doc, &c14n::Options::default())
}

#[test]
fn ten_thousand_attributes_parse_and_canonicalize_in_linear_time() {
    let mut doc = String::from("<doc");
    for i in 0..10_000 {
        doc.push_str(&format!(" a{i}=\"v{i}\""));
    }
    doc.push_str("/>");
    let started = Instant::now();
    let out = c14n_of(doc.as_bytes());
    let took = started.elapsed();
    // all attributes survive, in c14n's own order (sorted by namespace-less
    // local name, so the lexicographically last one is at the end of the tag)
    assert!(out.ends_with(b"a9999=\"v9999\"></doc>"));
    assert!(
        took < std::time::Duration::from_secs(5),
        "10 000 attributes took {took:?}: the quadratic scan is back"
    );
}

#[test]
fn thousands_of_namespace_prefixes_canonicalize_in_linear_time() {
    // the exact shape of the review's measurement: one root declaring k
    // prefixes and k children, none of which redeclare anything — the worst
    // case for an implementation that clones the inherited table per element
    let mut doc = String::from("<root");
    for i in 0..4_000 {
        doc.push_str(&format!(" xmlns:p{i}=\"urn:p{i}\""));
    }
    doc.push('>');
    for i in 0..400 {
        doc.push_str(&format!("<p{i}:c xmlns:p{i}=\"urn:p{i}\">x</p{i}:c>"));
    }
    doc.push_str("</root>");
    let started = Instant::now();
    let out = c14n_of(doc.as_bytes());
    let took = started.elapsed();
    assert!(took < std::time::Duration::from_secs(10), "{took:?}");
    // the inherited axis renders exactly once at the root: children that do
    // not change a binding print nothing
    let text = String::from_utf8(out).unwrap();
    assert_eq!(
        text.matches("xmlns:p3=\"urn:p3\"").count(),
        1,
        "a prefix must be rendered once, not per child"
    );
}

#[test]
fn thousands_of_inherited_prefixes_do_not_cost_elements_times_prefixes() {
    // Round two, N-5: the same finding on the READER's side, which the M-2 fix
    // had left open. `xml::parse` handed every child a CLONE of the namespace
    // scope and resolved each name by scanning it back to front, so the cost
    // was elements × prefixes-in-scope. The reviewer's debug binary needed
    // 37.4 s for 4 000 prefixes over 20 000 children and 126 s for
    // 20 000 × 20 000 — and this is the shape a generated file really has
    // (a schema's worth of prefixes on the root, thousands of untouched
    // children). `xml::Scope` is a stack with an innermost table now, so
    // descending costs one push per declaration, ascending one pop, and a name
    // one lookup; the same two shapes take 126 ms and 409 ms end to end
    // through `openfirma sign` (docs/validation-log.md), and parse in about
    // 130 ms together here. The budget below is ~15x that, which is what the
    // two halves of the old code need to be caught by: with the per-child
    // clone put back the first shape costs 14.4 s, and with the linear
    // back-to-front scan put back the second costs 2.6 s.
    //
    // That is also why no "at most N prefixes per document" cap was added:
    // with the cost proportional to the file, a cap would only refuse large
    // legitimate documents, and `MAX_DEPTH` already bounds the recursion.
    for (prefixes, children) in [(4_000usize, 20_000usize), (20_000, 20_000)] {
        let mut doc = String::from("<root");
        for i in 0..prefixes {
            doc.push_str(&format!(" xmlns:p{i}=\"urn:p{i}\""));
        }
        doc.push('>');
        for _ in 0..children {
            doc.push_str("<c/>");
        }
        doc.push_str("</root>");
        let started = Instant::now();
        let parsed = xml::parse(doc.as_bytes()).expect("the synthetic document must parse");
        let took = started.elapsed();
        assert_eq!(parsed.root.ns_decls.len(), prefixes);
        assert!(
            took < std::time::Duration::from_secs(2),
            "{prefixes} prefixes over {children} children ({} bytes) took {took:?}: \
             the reader is copying or scanning its namespace scope per element again",
            doc.len()
        );
    }
}

#[test]
fn a_deep_inheritance_chain_does_not_re_render_unchanged_bindings() {
    // a chain of elements, each inheriting everything and declaring nothing:
    // linear in depth at both the scope push and the render decision
    // deep, but not at MAX_DEPTH: xml::parse, c14n and the tree's own drop
    // all recurse once per level, so a stack-hungry debug test thread would
    // overflow before anything quadratic could be measured; 200 levels show
    // the render behaviour without leaning on the stack
    let mut doc = String::from("<r xmlns:a=\"urn:a\">");
    for _ in 0..150 {
        doc.push_str("<x>");
    }
    doc.push('t');
    for _ in 0..150 {
        doc.push_str("</x>");
    }
    doc.push_str("</r>");
    let started = Instant::now();
    let out = c14n_of(doc.as_bytes());
    let took = started.elapsed();
    assert!(took < std::time::Duration::from_secs(5), "{took:?}");
    let text = String::from_utf8(out).unwrap();
    assert_eq!(text.matches("xmlns:a=\"urn:a\"").count(), 1);
}

/// M-1: the two-byte PoCs `<a b=` and `<a b= ` panicked with an index past
/// the source; a hostile attribute cut at end of document is an error.
#[test]
fn an_attribute_cut_at_end_of_document_is_an_error() {
    for hostile in [b"<a b=".as_slice(), b"<a b= ".as_slice()] {
        let err = xml::parse(hostile).expect_err("a value never arrived");
        assert!(!err.to_string().is_empty());
    }
}

/// The sweep review 03 asked for: cut a valid signed-shape document at every
/// byte; no prefix may panic, however it lands inside a name, a value or a
/// delimiter.
#[test]
fn every_truncation_of_a_document_parses_or_errors() {
    let doc = br#"<?xml version="1.0"?>
<root xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="r"><a x="1">t&#65;<!--c--></a><![CDATA[y]]></root>"#;
    for end in 0..=doc.len() {
        let _ = xml::parse(&doc[..end]);
    }
}

/// Every single-byte insertion into a small document: the same contract —
/// errors, never panics.
#[test]
fn byte_insertions_never_panic_the_reader() {
    let doc = br#"<root a="1"><b>t</b></root>"#;
    for at in 0..=doc.len() {
        for byte in [0u8, b'<', b'>', b'&', b'"', b'\'', b'=', b':', 0x80, b'\r'] {
            let mut v = doc[..at].to_vec();
            v.push(byte);
            v.extend_from_slice(&doc[at..]);
            let _ = xml::parse(&v);
        }
    }
}
