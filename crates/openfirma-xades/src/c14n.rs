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

/// The walking scope: a shadowing stack of every namespace declaration on
/// the path to the current element (innermost last) plus a side stack
/// marking which of them are still visible — an entry is hidden when a later
/// one declares the same prefix. Descending pushes one element's
/// declarations, leaving truncates both stacks: that is all it ever costs to
/// move down or up the tree, and `live` walks only what is visible instead
/// of re-compacting thousands of shadowed declarations at every subtree
/// root. Building an [`Axis`] per node — what this whole design replaced —
/// made canonicalization quadratic in the number of declarations times the
/// number of elements (review 03, M-2): a document with thousands of
/// prefixes on the root and thousands of untouched children took minutes.
#[derive(Debug, Default)]
struct Scope {
    stack: Vec<(Option<String>, String)>,
    /// one flag per entry of `stack`: false once a deeper entry shadows it.
    visible: Vec<bool>,
    /// for each prefix in scope, its innermost still-visible entry.
    innermost: std::collections::HashMap<Option<String>, usize>,
    undo: Vec<(Option<String>, Option<usize>)>,
}

impl Scope {
    /// Enter an element: push its declarations, return the mark `ascend`
    /// truncates back to. Nothing else is touched — no clone of any table.
    fn push_element(&mut self, el: &Element) -> usize {
        self.push_decls(&el.ns_decls)
    }

    /// Enter an element by declaration only — for callers (the subtree-root
    /// seed below) that must replay a namespace context without re-pushing
    /// the element itself.
    fn push_decls(&mut self, decls: &[(Option<String>, String)]) -> usize {
        let mark = self.stack.len();
        for (prefix, uri) in decls {
            // shadow the innermost outer binding of this prefix; `live` and
            // `innermost_default` skip entries marked invisible. A duplicate
            // within the same element (an xml parser rejects those, but a
            // hand-built tree could carry them) shadows the earlier one too.
            if let Some(&at) = self.innermost.get(prefix) {
                self.visible[at] = false;
            }
            self.undo.push((
                prefix.clone(),
                self.innermost.insert(prefix.clone(), self.stack.len()),
            ));
            self.stack.push((prefix.clone(), uri.to_string()));
            self.visible.push(true);
        }
        mark
    }

    fn ascend(&mut self, mark: usize) {
        // undo in reverse push order and truncate the stack; one record per
        // declaration pushed below the mark.
        let mut n = self.stack.len();
        while n > mark {
            let (prefix, outer) = self.undo.pop().expect("one undo per pushed decl");
            match outer {
                Some(at) => self.visible[at] = true,
                None => {
                    self.innermost.remove(&prefix);
                }
            }
            n -= 1;
        }
        self.stack.truncate(mark);
        self.visible.truncate(mark);
    }

    /// The live axis of the current path: every prefix's innermost binding,
    /// sorted by prefix for §2.3's print order, with `xmlns=""` removing the
    /// default instead of adding an empty binding (the XPath data model).
    /// Only an element that declared something ever pays to build it — the
    /// render path calls it once per declaring element and at subtree roots,
    /// so paths through thousands of *prefixed* declarations stay linear
    /// (review 03, M-2). Cost: one probe per distinct prefix in scope.
    fn live(&self) -> Axis {
        let mut axis: Axis = self
            .innermost
            .iter()
            .filter_map(|(prefix, at)| {
                let (p, uri) = &self.stack[*at];
                if p.is_none() && uri.is_empty() {
                    return None; // an undeclaration is not a binding
                }
                Some((prefix.clone(), uri.clone()))
            })
            .collect();
        axis.sort_by(|a, b| a.0.cmp(&b.0));
        axis
    }

    /// The innermost declaration of the default namespace on the path:
    /// `Some("")` for an explicit `xmlns=""`, `Some(uri)` for a default in
    /// scope, `None` when no default was ever declared above. This is the
    /// only question about the axis that an element without declarations can
    /// ask (§2.3's undeclaration rule), and it is a single map probe now —
    /// paths through thousands of prefixed declarations pay nothing for it.
    fn innermost_default(&self) -> Option<&str> {
        self.innermost
            .get(&None)
            .map(|at| self.stack[*at].1.as_str())
    }

    /// Whether a non-empty default is in scope on the path.
    fn has_default(&self) -> bool {
        matches!(self.innermost_default(), Some(u) if !u.is_empty())
    }
}

/// What an element's children compare their bindings against: the axis that
/// element rendered (§2.3 renders the full in-scope set at a root and the
/// live set below one — they agree, because every ancestor binding stays in
/// scope), plus whether that rendering had a default namespace: §2.3 makes a
/// descendant without one print `xmlns=""`. The axis is reference-counted so
/// handing it down the tree costs nothing (review 03, M-2): an element that
/// declared nothing reuses its parent's exactly, and children pay only for
/// their own declarations against it.
#[derive(Debug)]
struct Rendered {
    axis: std::rc::Rc<Axis>,
    had_default: bool,
}

impl Clone for Rendered {
    fn clone(&self) -> Rendered {
        Rendered {
            axis: std::rc::Rc::clone(&self.axis),
            had_default: self.had_default,
        }
    }
}

impl Rendered {
    fn of(axis: Axis) -> Rendered {
        let had_default = axis.iter().any(|(p, u)| p.is_none() && !u.is_empty());
        Rendered {
            axis: std::rc::Rc::new(axis),
            had_default,
        }
    }
}

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
    // `render_decls` with a `None` parent prints the live axis — exactly
    // what the spec's §3.3 example (`e6`: an `xmlns=""` cancelling nothing
    // prints nothing) requires at a whole-document root, where there is no
    // rendering ancestor to owe an undeclaration to. Children get the root's
    // live axis as their parent view below.
    let mut scope = Scope::default();
    let mark = scope.push_element(&doc.root);
    element_with_context(&doc.root, &mut scope, mark, None, &[], opts, &mut out);
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
    // A subtree root prints its whole context: what ancestors outside the
    // output declared (`inherited`, already including this element's own
    // declarations when a walk computed it from its scope) overridden by the
    // element's own. Re-declared prefixes must not be shadowed against the
    // identical inherited value — that would hide it — so they are dropped
    // from `inherited` first; an `xmlns=""` on the root shadows nothing and
    // prints as §2.3's undeclaration owed to the ancestors' default.
    let mut scope = Scope::default();
    let mut context: Axis = Vec::new();
    for (prefix, uri) in inherited {
        if !el.ns_decls.iter().any(|(p, u)| p == prefix && u == uri) {
            context.push((prefix.clone(), uri.clone()));
        }
    }
    let mark = scope.push_decls(&context);
    element_with_context(el, &mut scope, mark, None, xml_attrs, opts, &mut out);
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
    // Descending pushes/pops the Scope alone — no axis per level, nothing
    // proportional to the declarations already in scope (review 03, M-2).
    // When the predicate matches, the path's live axis is exactly what §2.3
    // makes the subtree root re-render, and `subtree` prints it in full.
    fn walk<F: Fn(&Element) -> bool>(
        el: &Element,
        scope: &mut Scope,
        xml_attrs: &[xml::Attribute],
        pred: &F,
        opts: &Options,
    ) -> Option<Vec<u8>> {
        let mark = scope.push_element(el);
        if pred(el) {
            let inherited = scope.live();
            scope.ascend(mark);
            return Some(subtree_with_inherited(el, &inherited, xml_attrs, opts));
        }
        let child_xml = extend_xml_attrs(xml_attrs, el);
        let found = el.children.iter().find_map(|child| {
            if let Child::Element(inner) = child {
                walk(inner, scope, &child_xml, pred, opts)
            } else {
                None
            }
        });
        scope.ascend(mark);
        found
    }

    let mut scope = Scope::default();
    if pred(root) {
        // the root's context is its own declarations; `subtree`'s fresh
        // scope re-pushes them, so pass an empty inherited axis and let the
        // subtree-root rule print them in full.
        return Some(subtree(
            root,
            &Axis::new(),
            &extend_xml_attrs(&[], root),
            opts,
        ));
    }
    let mark = scope.push_element(root);
    let xml_attrs = extend_xml_attrs(&[], root);
    let found = root.children.iter().find_map(|child| {
        if let Child::Element(inner) = child {
            walk(inner, &mut scope, &xml_attrs, &pred, opts)
        } else {
            None
        }
    });
    scope.ascend(mark);
    found
}

/// Like [`subtree`], but `inherited` came from a walk's scope and already
/// includes the element's own declarations; seeding them into a fresh scope
/// (minus exact duplicates of what it re-declares) gives exactly the context
/// a subtree root prints.
fn subtree_with_inherited(
    el: &Element,
    inherited: &Axis,
    xml_attrs: &[xml::Attribute],
    opts: &Options,
) -> Vec<u8> {
    let mut out = Vec::new();
    let mut scope = Scope::default();
    let context: Axis = inherited
        .iter()
        .filter(|(p, u)| !el.ns_decls.iter().any(|(q, v)| q == p && v == u))
        .cloned()
        .collect();
    let mark = scope.push_decls(&context);
    element_with_context(el, &mut scope, mark, None, xml_attrs, opts, &mut out);
    out
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

/// The axis rule of §2.3: which bindings does this element render? At a root
/// (a whole document or a subtree) that is its full context — every binding
/// in scope, inherited ones included, which is why canonical
/// `xades:SignedProperties` starts with an `xmlns:ds` declared on its parent.
/// Below one, only the bindings that differ from what the nearest rendering
/// ancestor rendered (`parent`), plus the default undeclaration owed when
/// that rendering had a default and this element's scope has none — the one
/// thing an element without declarations can still print. `parent.axis` is
/// sorted and prefix-unique, so the diff scans in linear time of two sorted
/// lists; an element that declared nothing pays one cheap default scan and
/// builds no axis at all (review 03, M-2).
fn render_decls(
    scope: &Scope,
    el: &Element,
    parent: Option<&Rendered>,
) -> Vec<(Option<String>, String)> {
    let mut decls: Axis = match parent {
        // at a root every binding of the context prints.
        None => scope.live(),
        Some(_) if el.ns_decls.is_empty() => {
            // an element that declared nothing changed no binding; it builds
            // no axis (review 03, M-2). The one thing it can still print —
            // the owed `xmlns=""` — needs only the default probe below.
            Vec::new()
        }
        Some(view) => {
            // Below a root only own declarations can differ from what the
            // nearest rendering ancestor rendered, so the candidates are its
            // own prefixes and nothing else: each live binding costs one map
            // probe and one binary search in `view.axis`. A re-declaration of
            // the exact in-scope uri suppresses; a shadowing of the same
            // prefix to a different uri prints the new binding; a prefix that
            // shadowed nothing below the ancestor (identical pair) drops out.
            let mut decls = Axis::new();
            for (prefix, _) in &el.ns_decls {
                let Some(at) = scope.innermost.get(prefix) else {
                    continue;
                };
                let uri = scope.stack[*at].1.clone();
                // An `xmlns=""` is a namespace node only while it cancels a
                // default that was in scope; cancelling nothing prints
                // nothing (the spec's own §3.3 example, element `e6`).
                if prefix.is_none() && uri.is_empty() {
                    continue;
                }
                match view.axis.binary_search_by(|(q, _)| q.cmp(prefix)) {
                    Ok(v) if view.axis[v].1 == uri => {}
                    _ => decls.push((prefix.clone(), uri)),
                }
            }
            decls.sort_by(|a, b| a.0.cmp(&b.0));
            decls
        }
    };
    if parent.is_some_and(|view| view.had_default) && !scope.has_default() {
        // the nearest rendered ancestor has a default namespace and this
        // element's scope has none: the undeclaration has to be printed (an
        // own `xmlns=""` shows up as the missing binding here, not above).
        if !decls.iter().any(|(p, u)| p.is_none() && u.is_empty()) {
            decls.insert(0, (None, String::new()));
        }
    }
    decls.retain(|(p, u)| !(p.as_deref() == Some("xml") && u == XML_NS));
    decls
}

/// Renders one element with its path already pushed onto `scope` up to and
/// including itself (`mark` is the push to undo on the way out). `parent` is
/// what the nearest rendering ancestor rendered, or `None` at a root, where
/// the whole context lives in the scope's live axis.
fn element_with_context(
    el: &Element,
    scope: &mut Scope,
    mark: usize,
    parent: Option<&Rendered>,
    xml_attrs: &[xml::Attribute],
    opts: &Options,
    out: &mut Vec<u8>,
) {
    // Recurses one stack frame per nesting level, and so does the drop of the
    // tree afterwards. That is safe without a cap of its own because every
    // tree that reaches this module came out of xml::parse, which refuses
    // documents nested deeper than xml::MAX_DEPTH; a tree deeper than the
    // canonicalizer's stack therefore cannot exist.
    out.push(b'<');
    write_qname(&el.name, out);

    for (prefix, uri) in render_decls(scope, el, parent) {
        match prefix {
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

    // what this element hands its children. At a root (no parent) it printed
    // its whole live axis and hands that down. Below one, the rule to keep is
    // "children compare against what the nearest rendering ancestor
    // rendered", and two shapes are possible. An element that declared
    // something renders a superset of its parent's set (the superset rule),
    // so it hands down its live axis — the pairs it printed included, the
    // cancelled default removed by the data model, which is exactly what
    // turns `had_default` off for descendants. An element that declared
    // nothing changes no binding at all and hands the parent's record down
    // untouched; below it children compare against the same axis in O(own
    // size), never re-cloning or rebuilding a table of thousands of prefixes
    // (review 03, M-2 — that per-child rebuild was the quadratic cost). The
    // one fact such an element can still change is whether a rendered default
    // remains in scope below it: an `xmlns=""` on an *ancestor between here
    // and the parent* cannot exist without having changed `parent.had_default`
    // itself, so within a no-declaration stretch nothing touches the flag.
    let child_context: Rendered = match parent {
        None => Rendered::of(scope.live()),
        Some(view) if el.ns_decls.is_empty() => view.clone(),
        Some(view) => {
            // the printed set below this element is its parent's pairs with
            // every own prefix replaced by the live binding (an undeclared
            // default removes it): same superset rule, linear in own size.
            let mut axis: Axis = (*view.axis).clone();
            for (prefix, _) in &el.ns_decls {
                axis.retain(|(q, _)| q != prefix);
                if let Some(at) = scope.innermost.get(prefix) {
                    let uri = scope.stack[*at].1.clone();
                    match axis.binary_search_by(|(q, _)| q.cmp(prefix)) {
                        Ok(v) => axis[v].1 = uri,
                        Err(v) => axis.insert(v, (prefix.clone(), uri)),
                    }
                }
            }
            Rendered::of(axis)
        }
    };

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
                let mark = scope.push_element(inner);
                element_with_context(inner, scope, mark, Some(&child_context), &[], opts, out);
                scope.ascend(mark);
            }
        }
    }

    scope.ascend(mark);
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
        assert_eq!(doc_c14n_with(&doc, &opts), "<d>xy</d>");
    }

    fn doc_c14n_with(doc: &Document, opts: &Options) -> String {
        String::from_utf8(document(doc, opts)).expect("c14n is utf-8")
    }
}
