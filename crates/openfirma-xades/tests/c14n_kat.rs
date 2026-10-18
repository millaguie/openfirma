//! Known-answer vectors for the canonicalizer, hand written from the examples
//! of the C14N 1.0 specification (W3C Recommendation 2001-03-15, section 3)
//! and from the shapes docs/xades.md measured in AutoFirma's output.
//!
//! Every expected value here was additionally run through two independent
//! canonicalizers while the crate was written (Apache Santuario, the one
//! AutoFirma signs with, and libxml2/lxml): both produce exactly these bytes
//! for every vector. Where the printed canonical form of the specification
//! itself differs, the comment says so and why.

use openfirma_xades::c14n::{self, Options};
use openfirma_xades::xml::parse;

fn doc_c14n(input: &[u8], with_comments: bool) -> String {
    let doc = parse(input).expect("vector input must parse");
    let out = c14n::document(
        &doc,
        &Options {
            with_comments,
            ..Default::default()
        },
    );
    String::from_utf8(out).expect("c14n output is utf-8")
}

/// Spec §3.1, PIs, comments, and outside of document element. The DTD line of
/// the spec input is dropped: openfirma refuses DTDs, and the canonical form
/// never contains one anyway.
#[test]
fn spec_3_1_pis_comments_and_outside_of_document_element() {
    let input = b"<?xml version=\"1.0\"?>\n\
        <?xml-stylesheet   href=\"doc.xsl\"\n   type=\"text/xsl\"   ?>\n\
        <doc>Hello, world!<!-- Comment 1 --></doc>\n\
        <?pi-without-data     ?>\n\
        <!-- Comment 2 -->\n\
        <!-- Comment 3 -->";
    assert_eq!(
        doc_c14n(input, false),
        "<?xml-stylesheet href=\"doc.xsl\"\n   type=\"text/xsl\"   ?>\n\
         <doc>Hello, world!</doc>\n\
         <?pi-without-data?>"
    );
    assert_eq!(
        doc_c14n(input, true),
        "<?xml-stylesheet href=\"doc.xsl\"\n   type=\"text/xsl\"   ?>\n\
         <doc>Hello, world!<!-- Comment 1 --></doc>\n\
         <?pi-without-data?>\n\
         <!-- Comment 2 -->\n\
         <!-- Comment 3 -->"
    );
}

/// Spec §3.2, whitespace in document content: the canonical form is the
/// input, byte for byte, both ending with '>'.
#[test]
fn spec_3_2_whitespace_in_document_content() {
    let input = "<doc>\n   <clean>   </clean>\n   <dirty>   A   B   </dirty>\n   <mixed>\n      A\n      <clean>   </clean>\n      B\n      <dirty>   A   B   </dirty>\n      C\n   </mixed>\n</doc>";
    assert_eq!(doc_c14n(input.as_bytes(), false), input);
}

/// Spec §3.3, start and end tags: empty element expansion, attribute and
/// namespace sorting, superfluous declaration removal.
///
/// Two differences from the printed canonical form of the spec, both shared
/// by Apache Santuario and libxml2, which produce exactly this:
/// - `e9` has no `attr="default"`: that value comes from a DTD default
///   attribute, and no non-validating processor invents it;
/// - `e9` has no `xmlns:a`: §2.3 ignores a namespace node when the nearest
///   ancestor in the node set carries the same binding, and `e8` does. The
///   printed example disagrees with the printed rule; every implementation
///   measured follows the rule.
#[test]
fn spec_3_3_start_and_end_tags() {
    let input = b"<doc>\n   \
        <e1   />\n   \
        <e2   ></e2>\n   \
        <e3   name = \"elem3\"   id=\"elem3\"   />\n   \
        <e4   name=\"elem4\"   id=\"elem4\"   ></e4>\n   \
        <e5 a:attr=\"out\" b:attr=\"sorted\" attr2=\"all\" attr=\"I'm\"\n      \
          xmlns:b=\"http://www.ietf.org\"\n      \
          xmlns:a=\"http://www.w3.org\"\n      \
          xmlns=\"http://example.org\"/>\n   \
        <e6 xmlns=\"\" xmlns:a=\"http://www.w3.org\">\n      \
          <e7 xmlns=\"http://www.ietf.org\">\n         \
            <e8 xmlns=\"\" xmlns:a=\"http://www.w3.org\">\n            \
              <e9 xmlns=\"\" xmlns:a=\"http://www.w3.org\"/>\n         \
            </e8>\n      \
          </e7>\n   \
        </e6>\n\
        </doc>";
    assert_eq!(
        doc_c14n(input, false),
        "<doc>\n   \
         <e1></e1>\n   \
         <e2></e2>\n   \
         <e3 id=\"elem3\" name=\"elem3\"></e3>\n   \
         <e4 id=\"elem4\" name=\"elem4\"></e4>\n   \
         <e5 xmlns=\"http://example.org\" xmlns:a=\"http://www.w3.org\" xmlns:b=\"http://www.ietf.org\" attr=\"I'm\" attr2=\"all\" b:attr=\"sorted\" a:attr=\"out\"></e5>\n   \
         <e6 xmlns:a=\"http://www.w3.org\">\n      \
         <e7 xmlns=\"http://www.ietf.org\">\n         \
         <e8 xmlns=\"\">\n            \
         <e9></e9>\n         \
         </e8>\n      \
         </e7>\n   \
         </e6>\n\
         </doc>"
    );
}

/// Spec §3.4, character modifications and character references. The DOCTYPE
/// of the spec input only declares attribute types and is dropped, which
/// changes nothing in the canonical form of a non-validating processor.
#[test]
fn spec_3_4_character_modifications_and_character_references() {
    let input = b"<doc>\n   \
        <text>First line&#x0d;&#10;Second line</text>\n   \
        <value>&#x32;</value>\n   \
        <compute><![CDATA[value>\"0\" && value<\"10\" ?\"valid\":\"error\"]]></compute>\n   \
        <compute expr='value>\"0\" &amp;&amp; value&lt;\"10\" ?\"valid\":\"error\"'>valid</compute>\n   \
        <norm attr=' &apos;   &#x20;&#13;&#xa;&#9;   &apos; '/>\n   \
        <normNames attr='   A   &#x20;&#13;&#xa;&#9;   B   '/>\n   \
        <normId id=' &apos;   &#x20;&#13;&#xa;&#9;   &apos; '/>\n\
        </doc>";
    assert_eq!(
        doc_c14n(input, false),
        "<doc>\n   \
         <text>First line&#xD;\nSecond line</text>\n   \
         <value>2</value>\n   \
         <compute>value&gt;\"0\" &amp;&amp; value&lt;\"10\" ?\"valid\":\"error\"</compute>\n   \
         <compute expr=\"value>&quot;0&quot; &amp;&amp; value&lt;&quot;10&quot; ?&quot;valid&quot;:&quot;error&quot;\">valid</compute>\n   \
         <norm attr=\" '    &#xD;&#xA;&#x9;   ' \"></norm>\n   \
         <normNames attr=\"   A    &#xD;&#xA;&#x9;   B   \"></normNames>\n   \
         <normId id=\" '    &#xD;&#xA;&#x9;   ' \"></normId>\n\
         </doc>"
    );
}

/// Spec §3.6, UTF-8 encoding: a character reference above U+007F comes out
/// as its UTF-8 bytes (C2 A9 for the copyright sign).
#[test]
fn spec_3_6_utf8_encoding() {
    let out = doc_c14n(b"<doc>&#169;</doc>", false);
    assert_eq!(out, "<doc>\u{a9}</doc>");
    assert!(out.as_bytes().windows(2).any(|w| w == [0xC2, 0xA9]));
}

/// The subtree rule the whole format rests on, docs/xades.md: a subtree root
/// renders every binding in scope, inherited ones included, which is why the
/// canonical SignedProperties starts with the xmlns:ds and xmlns:xades that
/// are declared one level up, on QualifyingProperties. And a redundant
/// redeclaration inside the subtree is suppressed, which is why the
/// canonical SignedInfo carries no xmlns:ds on ds:XPath even though the file
/// does. Both behaviours verified against the digests AutoFirma writes.
#[test]
fn subtree_canonicalization_carries_the_xades_namespace_layout() {
    let fragment = format!(
        "<xades:QualifyingProperties xmlns:xades=\"{x}\" Id=\"Q\" Target=\"T\" xmlns:ds=\"{d}\">\
         <xades:SignedProperties Id=\"SP\">\
         <xades:SignedSignatureProperties><xades:SigningTime>2026-10-15T00:00:00Z</xades:SigningTime></xades:SignedSignatureProperties>\
         </xades:SignedProperties>\
         </xades:QualifyingProperties>",
        x = "http://uri.etsi.org/01903/v1.3.2#",
        d = "http://www.w3.org/2000/09/xmldsig#",
    );
    let doc = parse(fragment.as_bytes()).unwrap();
    let out = c14n::subtree_from(
        &doc.root,
        |el| el.name.local == "SignedProperties",
        &Options::default(),
    )
    .expect("SignedProperties found");
    let text = String::from_utf8(out).unwrap();
    assert!(
        text.starts_with(
            "<xades:SignedProperties xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" \
             xmlns:xades=\"http://uri.etsi.org/01903/v1.3.2#\" Id=\"SP\">"
        ),
        "inherited declarations missing or misordered: {text}"
    );

    let signed_info = "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\
         <ds:SignedInfo><ds:Transform Algorithm=\"http://www.w3.org/TR/1999/REC-xpath-19991116\">\
         <ds:XPath xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">not(ancestor-or-self::ds:Signature)</ds:XPath>\
         </ds:Transform></ds:SignedInfo></ds:Signature>";
    let doc = parse(signed_info.as_bytes()).unwrap();
    let out = c14n::subtree_from(
        &doc.root,
        |el| el.name.local == "SignedInfo",
        &Options::default(),
    )
    .expect("SignedInfo found");
    let text = String::from_utf8(out).unwrap();
    assert!(
        text.contains("<ds:XPath>not(ancestor-or-self::ds:Signature)</ds:XPath>"),
        "the redundant xmlns:ds on ds:XPath must be suppressed: {text}"
    );
    assert!(
        text.starts_with("<ds:SignedInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">"),
        "the subtree root must render the inherited xmlns:ds: {text}"
    );
}

/// Round 2, N-1 — a regression of the M-2 fix, and a panic on plain XML.
///
/// `Scope::ascend` restored the *visibility* of the entry an element had
/// shadowed but not the `innermost` index of the prefix, so that map kept
/// pointing at the entry it had just removed. The next sibling that declared
/// the same prefix read `visible[that index]`: usually past the truncated
/// stack, which aborted the process (`index out of bounds`), and — when a
/// declaration in the same element put the stale index back inside the stack —
/// silently marked an unrelated binding invisible and dropped it from the
/// canonical form. The auto-invoicing shape that reaches it is ordinary: a root
/// with a default namespace and several children that declare `xmlns=""`
/// (AutoFirma's own `sample-facturae.xml` is exactly this, and so are hundreds
/// of generated namespace documents).
///
/// Every expected value below is libxml2's (`xmllint --c14n`), so this also
/// pins the canonical form, not only the absence of the panic.
#[test]
fn a_sibling_that_redeclares_a_prefix_leaves_no_dangling_index() {
    let cases: &[(&str, &str)] = &[
        // the plain panic: no declaration in between
        (
            "<a xmlns=\"urn:1\"><b xmlns=\"urn:2\"/><c xmlns=\"urn:3\"/></a>",
            "<a xmlns=\"urn:1\"><b xmlns=\"urn:2\"></b><c xmlns=\"urn:3\"></c></a>",
        ),
        (
            "<a xmlns:p=\"urn:1\"><b xmlns:p=\"urn:2\"/><c xmlns:p=\"urn:3\"/></a>",
            "<a xmlns:p=\"urn:1\"><b xmlns:p=\"urn:2\"></b><c xmlns:p=\"urn:3\"></c></a>",
        ),
        // the silent half: q is declared before p inside c, so the stale index
        // lands on q's entry and used to hide it, losing xmlns:q entirely
        (
            "<a xmlns:p=\"urn:1\"><b xmlns:p=\"urn:2\"/><c xmlns:q=\"urn:9\" xmlns:p=\"urn:3\"/></a>",
            "<a xmlns:p=\"urn:1\"><b xmlns:p=\"urn:2\"></b><c xmlns:p=\"urn:3\" \
             xmlns:q=\"urn:9\"></c></a>",
        ),
        // and one hop deeper, so the exit happens inside a nested subtree
        (
            "<a xmlns:p=\"urn:1\"><b xmlns:p=\"urn:2\"><d xmlns:p=\"urn:4\"/></b>\
             <c xmlns:p=\"urn:3\"/></a>",
            "<a xmlns:p=\"urn:1\"><b xmlns:p=\"urn:2\"><d xmlns:p=\"urn:4\"></d></b>\
             <c xmlns:p=\"urn:3\"></c></a>",
        ),
        // the invoicing shape: root default namespace, siblings undeclaring it
        (
            "<Facturae xmlns=\"urn:facturae\" xmlns:xsd=\"urn:xsd\">\
             <FileHeader xmlns=\"\"><Version>3.1</Version></FileHeader>\
             <Parties xmlns=\"\"><Seller/></Parties>\
             <Invoices xmlns=\"\"><Invoice/></Invoices></Facturae>",
            "<Facturae xmlns=\"urn:facturae\" xmlns:xsd=\"urn:xsd\">\
             <FileHeader xmlns=\"\"><Version>3.1</Version></FileHeader>\
             <Parties xmlns=\"\"><Seller></Seller></Parties>\
             <Invoices xmlns=\"\"><Invoice></Invoice></Invoices></Facturae>",
        ),
    ];
    for (input, expected) in cases {
        assert_eq!(
            doc_c14n(input.as_bytes(), false),
            *expected,
            "canonical form of {input}"
        );
    }
}
