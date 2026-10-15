//! Canonical XML (C14N 1.0, W3C Recommendation 2001-03-15), inclusive,
//! without and with comments.
//!
//! This is the only canonicalization variant AutoFirma's measured XAdES
//! output uses (`http://www.w3.org/TR/2001/REC-xml-c14n-20010315`), both as
//! the SignedInfo `CanonicalizationMethod`, as the data reference transform,
//! and implicitly for every `ds:Reference` without transforms. Exclusive
//! C14N and C14N 1.1 appear nowhere in it, so they are not implemented; a
//! validator that demanded them would be validating a different profile.
//!
//! The rules that matter, in the order they bite:
//!
//! - a subtree root re-emits every namespace binding in scope, inherited
//!   ones included: this is why the canonical `xades:SignedProperties`
//!   starts with `xmlns:ds` and `xmlns:xades` that are declared on
//!   `xades:QualifyingProperties`, one level up (docs/xades.md);
//! - a descendant re-emits a binding only when the nearest ancestor has a
//!   *different* value for that prefix: this is why the `xmlns:ds` written on
//!   `ds:XPath` in the file disappears from the canonical SignedInfo that is
//!   signed. Both Apache Santuario and libxml2 do it this way, measured
//!   against the C14N spec's own §3.3 example, whose printed canonical form
//!   of `e9` reflects DTD default attributes no implementation applies
//!   without a DTD (and we refuse DTDs);
//! - namespace declarations sort by prefix, default first, and precede all
//!   attributes; attributes sort by namespace URI, then local name, with no
//!   namespace sorting first;
//! - empty elements become start-end tag pairs, `>` in text becomes `&gt;`,
//!   literal CR becomes `&#xD;`, and tabs/newlines/CRs in attribute values
//!   become `&#x9;`/`&#xA;`/`&#xD;` in uppercase hex.
//!
//! [`subtree_from`] additionally implements §2.4 of the spec: `xml:`
//! attributes of ancestors outside the canonicalized subtree propagate to
//! its root unless the root overrides them.

use crate::xml;
use crate::xml::{Child, DocLevelNode, Document, Element};

pub const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";

/// In-scope namespace bindings: `(prefix, uri)`, `None` prefix is the default
/// namespace. A default namespace that was undeclared with `xmlns=""` is
/// absent from the axis, which is how the XPath data model represents it and
/// what the "emit `xmlns=""`" rule below keys off.
pub type Axis = Vec<(Option<String>, String)>;

#[derive(Clone, Debug, Default)]
pub struct Options {
    /// Canonical XML with comments. AutoFirma signs without.
    pub with_comments: bool,
    /// Omit the subtree of every element with this namespace and local name,
    /// leaving the surrounding text nodes alone. This is the net effect of
    /// the enveloped-signature transform plus AutoFirma's
    /// `not(ancestor-or-self::ds:Signature)` XPath filter on the data
    /// reference (docs/xades.md).
    pub omit: Option<(String, String)>,
}

/// Canonicalizes a whole document: prolog PIs and comments, the root, the
/// epilog, no declaration, no DTD, nothing outside the root that is
/// whitespace.
pub fn document(doc: &Document, opts: &Options) -> Vec<u8> {
    let mut out = Vec::new();
    for node in &doc.prolog {
        if write_doc_level(node, opts, &mut out) {
            out.push(b'\n');
        }
    }
    element(&doc.root, &Axis::new(), true, &[], opts, &mut out);
    for node in &doc.epilog {
        // the leading newline separates the node from whatever came before,
        // even when that was a comment this mode drops
        let at = out.len();
        out.push(b'\n');
        if !write_doc_level(node, opts, &mut out) {
            out.truncate(at);
        }
    }
    out
}

/// Canonicalizes one element as a subtree root: `inherited` is the namespace
/// axis in scope at the element from ancestors *outside* the output, and
/// `xml_attrs` the `xml:` attributes to propagate per §2.4.
pub fn subtree(
    el: &Element,
    inherited: &Axis,
    xml_attrs: &[xml::Attribute],
    opts: &Options,
) -> Vec<u8> {
    let mut out = Vec::new();
    element(el, inherited, true, xml_attrs, opts, &mut out);
    out
}

/// Walks down from `root` and canonicalizes the first element matching
/// `pred` as a subtree, with the namespace axis and `xml:` attributes its
/// ancestors in this tree put in scope. This is how the signing code
/// canonicalizes `xades:SignedProperties` inside its
/// `xades:QualifyingProperties` wrapper exactly the way a validator will.
pub fn subtree_from<F: Fn(&Element) -> bool>(
    root: &Element,
    pred: F,
    opts: &Options,
) -> Option<Vec<u8>> {
    fn walk<F: Fn(&Element) -> bool>(
        el: &Element,
        axis: &Axis,
        xml_attrs: &[xml::Attribute],
        pred: &F,
        opts: &Options,
    ) -> Option<Vec<u8>> {
        if pred(el) {
            return Some(subtree(el, axis, xml_attrs, opts));
        }
        let child_axis = extend_axis(axis, el);
        let child_xml = extend_xml_attrs(xml_attrs, el);
        for child in &el.children {
            if let Child::Element(inner) = child {
                if let Some(out) = walk(inner, &child_axis, &child_xml, pred, opts) {
                    return Some(out);
                }
            }
        }
        None
    }
    if pred(root) {
        return Some(subtree(root, &Axis::new(), &[], opts));
    }
    let axis = extend_axis(&Axis::new(), root);
    let xml_attrs = extend_xml_attrs(&[], root);
    for child in &root.children {
        if let Child::Element(inner) = child {
            if let Some(out) = walk(inner, &axis, &xml_attrs, &pred, opts) {
                return Some(out);
            }
        }
    }
    None
}

fn extend_axis(parent: &Axis, el: &Element) -> Axis {
    if el.ns_decls.is_empty() {
        return parent.clone();
    }
    let mut axis = parent.clone();
    for (prefix, uri) in &el.ns_decls {
        axis.retain(|(p, _)| p != prefix);
        if !uri.is_empty() || prefix.is_some() {
            // xmlns="" removes the default binding instead of adding an
            // empty one, per the XPath data model
            axis.push((prefix.clone(), uri.clone()));
        }
    }
    axis
}

fn extend_xml_attrs(parent: &[xml::Attribute], el: &Element) -> Vec<xml::Attribute> {
    let mut out: Vec<xml::Attribute> = parent
        .iter()
        .filter(|a| {
            !el.attributes.iter().any(|own| {
                own.name.prefix.as_deref() == Some("xml") && own.name.local == a.name.local
            })
        })
        .cloned()
        .collect();
    for attr in &el.attributes {
        if attr.name.prefix.as_deref() == Some("xml") {
            out.push(attr.clone());
        }
    }
    out
}

/// The axis rule of §2.3: which bindings does this element render?
fn render_decls(
    axis: &Axis,
    parent_axis: &Axis,
    subtree_root: bool,
) -> Vec<(Option<String>, String)> {
    let mut decls: Vec<(Option<String>, String)> = Vec::new();
    for (prefix, uri) in axis {
        if prefix.as_deref() == Some("xml") && uri == XML_NS {
            continue;
        }
        if !subtree_root && parent_axis.iter().any(|(p, u)| p == prefix && u == uri) {
            continue;
        }
        decls.push((prefix.clone(), uri.clone()));
    }
    if !subtree_root
        && !axis.iter().any(|(p, _)| p.is_none())
        && parent_axis.iter().any(|(p, _)| p.is_none())
    {
        // the nearest rendered ancestor has a default namespace and this
        // element has none: the undeclaration has to be printed
        decls.push((None, String::new()));
    }
    decls.sort_by(|a, b| match (&a.0, &b.0) {
        (None, None) => std::cmp::Ordering::Equal,
        (None, Some(_)) => std::cmp::Ordering::Less,
        (Some(_), None) => std::cmp::Ordering::Greater,
        (Some(x), Some(y)) => x.cmp(y),
    });
    decls
}

fn element(
    el: &Element,
    parent_axis: &Axis,
    subtree_root: bool,
    xml_attrs: &[xml::Attribute],
    opts: &Options,
    out: &mut Vec<u8>,
) {
    let axis = extend_axis(parent_axis, el);
    out.push(b'<');
    write_qname(&el.name, out);

    for (prefix, uri) in render_decls(&axis, parent_axis, subtree_root) {
        match &prefix {
            Some(p) => {
                out.extend_from_slice(b" xmlns:");
                out.extend_from_slice(p.as_bytes());
                out.extend_from_slice(b"=\"");
            }
            None => out.extend_from_slice(b" xmlns=\""),
        }
        escape_attr(&uri, out);
        out.push(b'"');
    }

    // own attributes plus the propagated xml: ones, sorted by (uri, local)
    let mut attrs: Vec<&xml::Attribute> = el.attributes.iter().collect();
    for inherited in xml_attrs {
        if !attrs
            .iter()
            .any(|a| a.namespace == inherited.namespace && a.name.local == inherited.name.local)
        {
            attrs.push(inherited);
        }
    }
    attrs.sort_by(|a, b| {
        (a.namespace.as_deref().unwrap_or(""), &a.name.local)
            .cmp(&(b.namespace.as_deref().unwrap_or(""), &b.name.local))
    });
    for attr in attrs {
        out.push(b' ');
        write_qname(&attr.name, out);
        out.extend_from_slice(b"=\"");
        escape_attr(&attr.value, out);
        out.push(b'"');
    }
    out.push(b'>');

    let omit = opts
        .omit
        .as_ref()
        .map(|(ns, local)| (ns.as_str(), local.as_str()));
    for child in &el.children {
        match child {
            Child::Text(t) => escape_text(t, out),
            Child::Comment(c) => {
                if opts.with_comments {
                    out.extend_from_slice(b"<!--");
                    out.extend_from_slice(c.as_bytes());
                    out.extend_from_slice(b"-->");
                }
            }
            Child::Pi { target, data } => write_pi(target, data, out),
            Child::Element(inner) => {
                if let Some((ns, local)) = omit {
                    if inner.namespace.as_deref() == Some(ns) && inner.name.local == local {
                        continue;
                    }
                }
                element(inner, &axis, false, &[], opts, out);
            }
        }
    }

    out.extend_from_slice(b"</");
    write_qname(&el.name, out);
    out.push(b'>');
}

fn write_doc_level(node: &DocLevelNode, opts: &Options, out: &mut Vec<u8>) -> bool {
    match node {
        DocLevelNode::Pi { target, data } => {
            write_pi(target, data, out);
            true
        }
        DocLevelNode::Comment(text) => {
            if opts.with_comments {
                out.extend_from_slice(b"<!--");
                out.extend_from_slice(text.as_bytes());
                out.extend_from_slice(b"-->");
                true
            } else {
                false
            }
        }
    }
}

fn write_pi(target: &str, data: &str, out: &mut Vec<u8>) {
    out.extend_from_slice(b"<?");
    out.extend_from_slice(target.as_bytes());
    if !data.is_empty() {
        out.push(b' ');
        out.extend_from_slice(data.as_bytes());
    }
    out.extend_from_slice(b"?>");
}

fn write_qname(name: &xml::QName, out: &mut Vec<u8>) {
    if let Some(p) = &name.prefix {
        out.extend_from_slice(p.as_bytes());
        out.push(b':');
    }
    out.extend_from_slice(name.local.as_bytes());
}

fn escape_text(text: &str, out: &mut Vec<u8>) {
    for c in text.chars() {
        match c {
            '&' => out.extend_from_slice(b"&amp;"),
            '<' => out.extend_from_slice(b"&lt;"),
            '>' => out.extend_from_slice(b"&gt;"),
            '\r' => out.extend_from_slice(b"&#xD;"),
            _ => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
}

fn escape_attr(value: &str, out: &mut Vec<u8>) {
    for c in value.chars() {
        match c {
            '&' => out.extend_from_slice(b"&amp;"),
            '<' => out.extend_from_slice(b"&lt;"),
            '"' => out.extend_from_slice(b"&quot;"),
            '\t' => out.extend_from_slice(b"&#x9;"),
            '\n' => out.extend_from_slice(b"&#xA;"),
            '\r' => out.extend_from_slice(b"&#xD;"),
            _ => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xml::parse;

    fn doc_c14n(input: &[u8]) -> String {
        let doc = parse(input).expect("test input parses");
        String::from_utf8(document(&doc, &Options::default())).expect("c14n is utf-8")
    }

    #[test]
    fn empty_elements_expand_and_attributes_sort() {
        assert_eq!(doc_c14n(b"<a   />"), "<a></a>");
        assert_eq!(
            doc_c14n(br#"<e b="2" a="1"   c:x="3" xmlns:c="urn:c"  ></e>"#),
            r#"<e xmlns:c="urn:c" a="1" b="2" c:x="3"></e>"#
        );
    }

    #[test]
    fn attributes_sort_by_namespace_uri_not_prefix() {
        // the spec's e5: b (ietf) before a (w3.org) because the URI is the key
        assert_eq!(
            doc_c14n(
                br#"<e5 a:attr="out" b:attr="sorted" attr2="all" attr="I'm"
                       xmlns:b="http://www.ietf.org"
                       xmlns:a="http://www.w3.org"
                       xmlns="http://example.org"/>"#
            ),
            r#"<e5 xmlns="http://example.org" xmlns:a="http://www.w3.org" xmlns:b="http://www.ietf.org" attr="I'm" attr2="all" b:attr="sorted" a:attr="out"></e5>"#
        );
    }

    #[test]
    fn superfluous_declarations_are_suppressed_and_undeclarations_printed() {
        assert_eq!(
            doc_c14n(
                br#"<e6 xmlns="" xmlns:a="http://www.w3.org">
                      <e7 xmlns="http://www.ietf.org">
                         <e8 xmlns="" xmlns:a="http://www.w3.org">
                            <e9 xmlns="" xmlns:a="http://www.w3.org"/>
                         </e8>
                      </e7>
                   </e6>"#
            ),
            r#"<e6 xmlns:a="http://www.w3.org">
                      <e7 xmlns="http://www.ietf.org">
                         <e8 xmlns="">
                            <e9></e9>
                         </e8>
                      </e7>
                   </e6>"#
        );
    }

    #[test]
    fn text_and_attribute_escaping() {
        assert_eq!(
            doc_c14n(b"<t>a &amp; b &lt; c > d &#xD; e</t>"),
            "<t>a &amp; b &lt; c &gt; d &#xD; e</t>"
        );
        assert_eq!(
            doc_c14n(br#"<t a="&quot;x&quot; &lt;y&gt; &#x9;&#xA;&#xD;z"/>"#),
            r#"<t a="&quot;x&quot; &lt;y> &#x9;&#xA;&#xD;z"></t>"#
        );
        assert_eq!(
            doc_c14n(b"<t><![CDATA[<raw> & ]]></t>"),
            "<t>&lt;raw&gt; &amp; </t>"
        );
    }

    #[test]
    fn subtree_root_inherits_and_renders_the_axis() {
        let doc = parse(br#"<a xmlns:x="urn:x" xmlns:y="urn:y"><b><c/></b></a>"#).unwrap();
        // c14n of the <b> subtree must carry both inherited declarations,
        // used or not: this is the SignedProperties rule
        let out = subtree_from(&doc.root, |el| el.name.local == "b", &Options::default())
            .expect("b found");
        assert_eq!(
            String::from_utf8(out).unwrap(),
            r#"<b xmlns:x="urn:x" xmlns:y="urn:y"><c></c></b>"#
        );
    }

    #[test]
    fn descendants_do_not_rerender_an_inherited_binding() {
        // the ds:XPath case from docs/xades.md: the declaration exists in the
        // file but must not exist in the canonical form
        let doc =
            parse(br#"<s xmlns:ds="urn:ds"><ds:i><ds:x xmlns:ds="urn:ds">t</ds:x></ds:i></s>"#)
                .unwrap();
        let out = subtree_from(&doc.root, |el| el.name.local == "i", &Options::default())
            .expect("i found");
        assert_eq!(
            String::from_utf8(out).unwrap(),
            r#"<ds:i xmlns:ds="urn:ds"><ds:x>t</ds:x></ds:i>"#
        );
    }

    #[test]
    fn xml_attributes_propagate_into_a_subtree() {
        let doc = parse(br#"<a xml:lang="es"><b xml:space="preserve"><c/></b></a>"#).unwrap();
        let out = subtree_from(&doc.root, |el| el.name.local == "c", &Options::default())
            .expect("c found");
        assert_eq!(
            String::from_utf8(out).unwrap(),
            r#"<c xml:lang="es" xml:space="preserve"></c>"#
        );
    }

    #[test]
    fn omit_strips_a_subtree_but_keeps_surrounding_text() {
        let doc =
            parse(br#"<d>x<s:Signature xmlns:s="urn:sig"><s:v/></s:Signature>y</d>"#).unwrap();
        let opts = Options {
            omit: Some(("urn:sig".into(), "Signature".into())),
            ..Default::default()
        };
        let mut out = Vec::new();
        crate::c14n::element(&doc.root, &Axis::new(), true, &[], &opts, &mut out);
        assert_eq!(String::from_utf8(out).unwrap(), "<d>xy</d>");
    }
}
