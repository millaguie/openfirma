//! A small, strict XML reader.
//!
//! Hand rolled on purpose, see the workspace rule that new dependencies need
//! a justification: every published Rust XML crate either drags in a parser
//! combinator stack we do not need or is lenient in ways that hide the errors
//! a signature format must not hide. What XAdES needs from a reader is small
//! and precise:
//!
//! - reject anything it does not fully understand (DTDs, entity references
//!   beyond the five predefined ones, undeclared prefixes, duplicate
//!   attributes), because a signature over a document we misparsed is worse
//!   than an error;
//! - keep the byte spans of the root element, because the enveloped output
//!   preserves the input bytes verbatim and only splices the signature in
//!   (docs/xades.md, "Serialization of the original content");
//! - resolve namespaces and expand entities into the parsed values, because
//!   the canonicalizer works on the parsed form, exactly like the DOM
//!   Santuario works on.
//!
//! The parser is a byte scanner. Every delimiter it looks for is ASCII, and
//! ASCII bytes cannot appear inside a UTF-8 multi byte sequence, so scanning
//! bytes is safe for the whole UTF-8 repertoire.

use std::collections::HashSet;

use openfirma_core::{Error, Result};

/// A qualified name as written in the document. The prefix is kept because
/// canonicalization prints names exactly as they were written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QName {
    pub prefix: Option<String>,
    pub local: String,
}

impl QName {
    pub fn new(prefix: Option<&str>, local: &str) -> Self {
        QName {
            prefix: prefix.map(str::to_string),
            local: local.to_string(),
        }
    }

    /// The name as written, `prefix:local` or `local`.
    pub fn to_string_with_prefix(&self) -> String {
        match &self.prefix {
            Some(p) => format!("{p}:{}", self.local),
            None => self.local.clone(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Attribute {
    pub name: QName,
    /// The resolved namespace of the attribute. Plain attributes have none:
    /// an unprefixed attribute is never in the default namespace, which is
    /// the rule people get wrong most often.
    pub namespace: Option<String>,
    /// Entity expanded and, for attribute values, whitespace collapsed the
    /// way the XML specification prescribes (tab, newline and carriage return
    /// become spaces).
    pub value: String,
}

#[derive(Clone, Debug)]
pub enum Child {
    Element(Box<Element>),
    /// Character data with entities expanded and line ends normalized
    /// (CRLF and lone CR become LF), which is what the XML specification says
    /// every parser does before anything else looks at the text. A CDATA
    /// section becomes indistinguishable from text, exactly like in a DOM,
    /// and canonicalization prints it escaped.
    Text(String),
    Comment(String),
    Pi {
        target: String,
        data: String,
    },
}

#[derive(Clone, Debug)]
pub struct Element {
    pub name: QName,
    /// The resolved namespace of the element: what the prefix binds to at
    /// this point, or none for a name with no prefix and no default
    /// declaration.
    pub namespace: Option<String>,
    /// Namespace declarations written on this element, in document order.
    /// `(None, uri)` is `xmlns="uri"`, `(None, "")` is `xmlns=""`.
    pub ns_decls: Vec<(Option<String>, String)>,
    /// The attributes that are not namespace declarations, in document order.
    pub attributes: Vec<Attribute>,
    pub children: Vec<Child>,
    /// Byte span of the start tag, `<name ... >` or `<name ... />`.
    pub open_tag: (usize, usize),
    /// Byte span between the start tag and the end tag; `None` for a
    /// self closing element.
    pub content: Option<(usize, usize)>,
    /// Byte span of the end tag, `</name>`.
    pub close_tag: (usize, usize),
    pub self_closing: bool,
}

impl Element {
    /// The attribute literally named `attr` with no prefix, which is how
    /// AutoFirma reads `Id` (a plain `getAttribute`, no XML ID typing).
    pub fn attr(&self, attr: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|a| a.name.prefix.is_none() && a.name.local == attr)
            .map(|a| a.value.as_str())
    }
}

#[derive(Clone, Debug)]
pub enum DocLevelNode {
    Comment(String),
    Pi { target: String, data: String },
}

#[derive(Clone, Debug)]
pub struct Document {
    /// Byte span of the `<?xml ...?>` declaration, when the input has one.
    pub decl: Option<(usize, usize)>,
    /// Comments and PIs before the root element. The signed output drops
    /// them (the measured AutoFirma behaviour), but document level
    /// canonicalization needs them.
    pub prolog: Vec<DocLevelNode>,
    pub root: Element,
    /// Byte span of the root element, start tag through end tag.
    pub root_span: (usize, usize),
    /// Comments and PIs after the root element.
    pub epilog: Vec<DocLevelNode>,
}

/// The deepest element nesting openfirma accepts.
///
/// The parser, the canonicalizer and the drop of a parsed tree each recurse
/// once per level, so an uncapped document aborts the process with a stack
/// overflow instead of failing to parse: 100 000 nested elements are enough.
/// 512 is far deeper than any real administrative XML (FacturaE nests a
/// handful of levels) and shallow enough that the three recursions stay well
/// inside the 8 MiB stack of the main thread the CLI runs on, in debug
/// builds included; a caller on a thread with a smaller stack should budget
/// roughly 4 KiB per level in the worst case.
pub const MAX_DEPTH: usize = 512;

/// Parses a well formed UTF-8 XML document.
pub fn parse(input: &[u8]) -> Result<Document> {
    let text = std::str::from_utf8(input).map_err(|e| {
        Error::Xml(format!(
            "the input is not valid UTF-8 ({e}). openfirma only signs UTF-8 XML; \
             convert the document first (iconv -f <encoding> -t UTF-8)"
        ))
    })?;
    let mut p = Parser {
        // not `input`: `text.as_bytes()` is byte-identical to it (from_utf8
        // succeeded), and tying the two together means every position in src
        // is also a character boundary of text, which all its slicing needs
        src: text.as_bytes(),
        text,
        pos: 0,
    };
    p.parse_document()
}

struct Parser<'a> {
    src: &'a [u8],
    text: &'a str,
    pos: usize,
}

/// In scope namespace bindings while descending: (prefix, uri). The default
/// namespace is the entry with prefix None.
type Scope = Vec<(Option<String>, String)>;

impl<'a> Parser<'a> {
    fn parse_document(&mut self) -> Result<Document> {
        self.skip_bom();
        let decl = self.parse_declaration()?;

        let mut root: Option<Element> = None;
        let mut root_span = (0usize, 0usize);
        let mut prolog = Vec::new();
        let mut epilog = Vec::new();
        let mut scope: Scope = Vec::new();
        loop {
            self.skip_space();
            if self.pos >= self.src.len() {
                break;
            }
            if self.starts_with(b"<!--") {
                let text = self.parse_comment()?;
                if root.is_some() {
                    epilog.push(DocLevelNode::Comment(text));
                } else {
                    prolog.push(DocLevelNode::Comment(text));
                }
                continue;
            }
            if self.starts_with(b"<?") {
                let (target, data) = self.parse_pi()?;
                let node = DocLevelNode::Pi { target, data };
                if root.is_some() {
                    epilog.push(node);
                } else {
                    prolog.push(node);
                }
                continue;
            }
            if self.starts_with(b"<!DOCTYPE") || self.starts_with(b"<!doctype") {
                return Err(Error::Xml(
                    "the document has a DOCTYPE. openfirma refuses DTDs: entity \
                     expansion is how XXE attacks work, and a signature over a \
                     document whose content depends on a DTD is a signature over \
                     something the file does not contain. Sign the expanded \
                     document instead"
                        .into(),
                ));
            }
            if self.starts_with(b"<") && !self.starts_with(b"</") {
                if root.is_some() {
                    return Err(Error::Xml(
                        "the document has more than one root element".into(),
                    ));
                }
                let start = self.pos;
                let el = self.parse_element(&mut scope, 1)?;
                root_span = (start, self.pos);
                root = Some(el);
                continue;
            }
            return Err(self.err("unexpected content at the document level"));
        }
        let root = root.ok_or_else(|| Error::Xml("the document has no root element".into()))?;
        Ok(Document {
            decl,
            prolog,
            root,
            root_span,
            epilog,
        })
    }

    fn skip_bom(&mut self) {
        if self.src.starts_with(&[0xEF, 0xBB, 0xBF]) {
            self.pos = 3;
        }
    }

    /// The `<?xml ... ?>` declaration. Its raw bytes are recorded but the
    /// output always carries the normalized declaration AutoFirma writes, so
    /// nothing here is validated beyond "it parses".
    fn parse_declaration(&mut self) -> Result<Option<(usize, usize)>> {
        self.skip_space();
        if !self.starts_with(b"<?xml") {
            return Ok(None);
        }
        let start = self.pos;
        // must be <?xml followed by space or ?>, not <?xmlfoo
        let next = self.src.get(self.pos + 5).copied().unwrap_or(b'?');
        if !(next.is_ascii_whitespace() || next == b'?') {
            return Ok(None);
        }
        self.expect(b"<?xml")?;
        self.skip_until_pi_end()?;
        Ok(Some((start, self.pos)))
    }

    fn parse_element(&mut self, scope: &mut Scope, depth: usize) -> Result<Element> {
        if depth > MAX_DEPTH {
            return Err(Error::Xml(format!(
                "the document nests elements more than {MAX_DEPTH} levels deep, which \
                 openfirma refuses: the parser, the canonicalizer and the tree's own drop \
                 recurse once per level and a deeper document would overflow the stack. \
                 Flattening the document is the only way to sign it"
            )));
        }
        let open_start = self.pos;
        self.expect(b"<")?;
        let name = self.parse_qname()?;

        let mut ns_decls = Vec::new();
        let mut attributes = Vec::new();
        // a set, not a scanned Vec: checking "attribute seen before" by
        // linear search made one element with thousands of attributes cost
        // the square of their count (99 KB of attributes took 0.65 s debug,
        // and c14n then quadratic on top)
        let mut seen_names: HashSet<(Option<String>, String)> = HashSet::new();

        // the declarations of this element apply to its own name, so they are
        // collected first and pushed onto the scope before anything is checked
        let mut pending_attrs: Vec<(QName, String)> = Vec::new();
        loop {
            self.skip_space();
            if self.pos >= self.src.len() {
                return Err(self.err("the start tag is never closed"));
            }
            let c = self.src[self.pos];
            if c == b'/' || c == b'>' {
                break;
            }
            let attr_name = self.parse_qname()?;
            self.skip_space();
            self.expect(b"=")?;
            self.skip_space();
            let value = self.parse_attr_value()?;

            // attribute value normalization first, entity expansion second:
            // a literal tab or newline becomes a space, but &#x9; stays a
            // tab, which canonicalization then prints as a reference again
            let expanded = self.expand_entities(&collapse_space(&value))?;
            if attr_name.prefix.is_none() && attr_name.local == "xmlns" {
                ns_decls.push((None, expanded));
            } else if attr_name.prefix.as_deref() == Some("xmlns") {
                ns_decls.push((Some(attr_name.local.clone()), expanded));
            } else {
                pending_attrs.push((attr_name, expanded));
            }
        }

        let pushed = scope.len();
        for (prefix, uri) in &ns_decls {
            if prefix.as_deref() == Some("xml") && uri != "http://www.w3.org/XML/1998/namespace" {
                return Err(self.err("the xml prefix cannot be rebound"));
            }
            if prefix.as_deref() == Some("xmlns") {
                return Err(self.err("the xmlns prefix cannot be declared"));
            }
            if let Some(p) = prefix {
                if !is_ncname(p) {
                    return Err(self.err(&format!("xmlns:{p} is not a valid prefix")));
                }
            }
            // no shadow removal here: resolve_ns scans back to front, so the
            // last declaration of a prefix wins, and the truncate at the end
            // of the element restores the outer scope exactly
            scope.push((prefix.clone(), uri.clone()));
        }

        let element_ns = match name.prefix.as_deref() {
            // a prefixed name must have its prefix declared; an unprefixed
            // one simply takes the default namespace, which may be none
            Some(_) => Some(
                resolve_ns(scope, name.prefix.as_deref(), true).ok_or_else(|| {
                    self.err(&format!(
                        "the prefix {:?} of <{}> is not declared",
                        name.prefix,
                        name.to_string_with_prefix()
                    ))
                })?,
            ),
            None => resolve_ns(scope, None, true),
        };

        for (attr_name, value) in pending_attrs {
            let attr_ns = match &attr_name.prefix {
                None => None,
                Some(p) => {
                    let ns = resolve_ns(scope, Some(p), false).ok_or_else(|| {
                        self.err(&format!(
                            "the prefix {p:?} of the attribute {} on <{}> is not declared",
                            attr_name.to_string_with_prefix(),
                            name.to_string_with_prefix()
                        ))
                    })?;
                    Some(ns)
                }
            };
            let key = (attr_ns.clone(), attr_name.local.clone());
            if !seen_names.insert(key) {
                return Err(self.err(&format!(
                    "the attribute {} appears twice on <{}>",
                    attr_name.to_string_with_prefix(),
                    name.to_string_with_prefix()
                )));
            }
            attributes.push(Attribute {
                name: attr_name,
                namespace: attr_ns,
                value,
            });
        }

        let self_closing = self.src[self.pos] == b'/';
        if self_closing {
            self.expect(b"/>")?;
        } else {
            self.expect(b">")?;
        }
        let open_end = self.pos;

        let mut children = Vec::new();
        let content_start;
        let close_tag;
        if self_closing {
            content_start = None;
            close_tag = (open_end, open_end);
        } else {
            content_start = Some(open_end);
            loop {
                if self.pos >= self.src.len() {
                    return Err(self.err(&format!(
                        "<{}> is never closed",
                        name.to_string_with_prefix()
                    )));
                }
                if self.starts_with(b"</") {
                    break;
                }
                if self.starts_with(b"<!--") {
                    let text = self.parse_comment()?;
                    children.push(Child::Comment(text));
                    continue;
                }
                if self.starts_with(b"<?") {
                    let (target, data) = self.parse_pi()?;
                    children.push(Child::Pi { target, data });
                    continue;
                }
                if self.starts_with(b"<![CDATA[") {
                    let text = self.parse_cdata()?;
                    if !text.is_empty() {
                        children.push(Child::Text(text));
                    }
                    continue;
                }
                if self.src[self.pos] == b'<' {
                    let mut inner_scope = scope.clone();
                    let el = self.parse_element(&mut inner_scope, depth + 1)?;
                    children.push(Child::Element(Box::new(el)));
                    continue;
                }
                let text = self.parse_text()?;
                if !text.is_empty() {
                    children.push(Child::Text(text));
                }
            }
            let close_start = self.pos;
            self.expect(b"</")?;
            let end_name = self.parse_qname()?;
            if end_name != name {
                return Err(self.err(&format!(
                    "<{}> is closed by </{}>",
                    name.to_string_with_prefix(),
                    end_name.to_string_with_prefix()
                )));
            }
            self.skip_space();
            self.expect(b">")?;
            close_tag = (close_start, self.pos);
        }

        scope.truncate(pushed);

        Ok(Element {
            name,
            namespace: element_ns,
            ns_decls,
            attributes,
            children,
            open_tag: (open_start, open_end),
            content: content_start.map(|s| (s, close_tag.0)),
            close_tag,
            self_closing,
        })
    }

    fn parse_qname(&mut self) -> Result<QName> {
        let start = self.pos;
        while self.pos < self.src.len() && is_name_byte(self.src[self.pos]) {
            self.pos += 1;
        }
        if self.pos == start {
            return Err(self.err("a name is expected"));
        }
        let raw = &self.text[start..self.pos];
        let (prefix, local) = match raw.split_once(':') {
            Some((p, l)) => (Some(p), l),
            None => (None, raw),
        };
        if !is_qname_parts(prefix, local) {
            return Err(self.err(&format!("{raw:?} is not a valid XML name")));
        }
        Ok(QName::new(prefix, local))
    }

    fn parse_attr_value(&mut self) -> Result<String> {
        // `<a b=` cut at the end of the document used to index one past the
        // source here: an attribute value is expected, so that is the error
        let quote = match self.src.get(self.pos) {
            Some(q) => *q,
            None => return Err(self.err("an attribute value is expected")),
        };
        if quote != b'"' && quote != b'\'' {
            return Err(self.err("an attribute value must be quoted"));
        }
        self.pos += 1;
        let start = self.pos;
        loop {
            if self.pos >= self.src.len() {
                return Err(self.err("an attribute value is never closed"));
            }
            let c = self.src[self.pos];
            if c == quote {
                let value = self.text[start..self.pos].to_string();
                self.pos += 1;
                return Ok(value);
            }
            if c == b'<' {
                return Err(self.err("'<' is not allowed in an attribute value"));
            }
            self.pos += 1;
        }
    }

    fn parse_text(&mut self) -> Result<String> {
        let start = self.pos;
        while self.pos < self.src.len() && self.src[self.pos] != b'<' {
            self.pos += 1;
        }
        let raw = &self.text[start..self.pos];
        self.expand_entities(&normalize_line_ends(raw))
    }

    fn parse_cdata(&mut self) -> Result<String> {
        self.expect(b"<![CDATA[")?;
        let start = self.pos;
        let end = self
            .find(b"]]>")
            .ok_or_else(|| self.err("a CDATA section is never closed"))?;
        let raw = &self.text[start..end];
        self.pos = end + 3;
        Ok(normalize_line_ends(raw))
    }

    fn parse_comment(&mut self) -> Result<String> {
        self.expect(b"<!--")?;
        let start = self.pos;
        let end = self
            .find(b"-->")
            .ok_or_else(|| self.err("a comment is never closed"))?;
        let raw = &self.text[start..end];
        self.pos = end + 3;
        if raw.contains("--") || raw.ends_with('-') {
            return Err(Error::Xml("'--' is not allowed inside a comment".into()));
        }
        Ok(raw.to_string())
    }

    fn parse_pi(&mut self) -> Result<(String, String)> {
        self.expect(b"<?")?;
        let name = self.parse_qname()?;
        let target = name.to_string_with_prefix();
        if target.eq_ignore_ascii_case("xml") {
            return Err(self.err("a processing instruction cannot be named xml"));
        }
        let start = self.pos;
        self.skip_until_pi_end()?;
        // the whitespace between the target and the data is not part of the
        // data: canonicalization prints one space, and every implementation
        // measured (libxml2, Apache Santuario) agrees with the spec example
        let data = self.text[start..self.pos - 2]
            .trim_start_matches([' ', '\t', '\r', '\n'])
            .to_string();
        Ok((target, data))
    }

    fn skip_until_pi_end(&mut self) -> Result<()> {
        let end = self
            .find(b"?>")
            .ok_or_else(|| self.err("a processing instruction is never closed"))?;
        self.pos = end + 2;
        Ok(())
    }

    /// Expands the five predefined entities and character references. Any
    /// other entity reference is an error: resolving it would need a DTD, and
    /// DTDs are refused.
    fn expand_entities(&self, raw: &str) -> Result<String> {
        let mut out = String::with_capacity(raw.len());
        let mut rest = raw;
        while let Some(amp) = rest.find('&') {
            out.push_str(&rest[..amp]);
            rest = &rest[amp + 1..];
            let semi = rest
                .find(';')
                .filter(|p| *p <= 10)
                .ok_or_else(|| Error::Xml(format!("'&' in {raw:?} starts no entity")))?;
            let entity = &rest[..semi];
            rest = &rest[semi + 1..];
            match entity {
                "amp" => out.push('&'),
                "lt" => out.push('<'),
                "gt" => out.push('>'),
                "quot" => out.push('"'),
                "apos" => out.push('\''),
                numeric if numeric.starts_with('#') => {
                    let c = parse_char_ref(numeric).ok_or_else(|| {
                        Error::Xml(format!("&{numeric}; is not a valid character reference"))
                    })?;
                    out.push(c);
                }
                other => {
                    return Err(Error::Xml(format!(
                        "the entity &{other}; needs a DTD, which openfirma refuses \
                         (docs/xades.md); replace it with the literal character or a \
                         character reference"
                    )));
                }
            }
        }
        out.push_str(rest);
        Ok(out)
    }

    // ---- byte helpers ----

    fn starts_with(&self, prefix: &[u8]) -> bool {
        self.src[self.pos..].starts_with(prefix)
    }

    fn find(&self, needle: &[u8]) -> Option<usize> {
        self.src[self.pos..]
            .windows(needle.len())
            .position(|w| w == needle)
            .map(|p| self.pos + p)
    }

    fn expect(&mut self, prefix: &[u8]) -> Result<()> {
        if !self.starts_with(prefix) {
            return Err(self.err(&format!("{:?} expected", String::from_utf8_lossy(prefix))));
        }
        self.pos += prefix.len();
        Ok(())
    }

    fn skip_space(&mut self) {
        while self.pos < self.src.len() && self.src[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
    }

    fn err(&self, what: &str) -> Error {
        let line = self.text[..self.pos.min(self.text.len())]
            .bytes()
            .filter(|b| *b == b'\n')
            .count()
            + 1;
        Error::Xml(format!("{what} (line {line})"))
    }
}

fn resolve_ns(scope: &Scope, prefix: Option<&str>, is_element: bool) -> Option<String> {
    match prefix {
        Some("xml") => Some("http://www.w3.org/XML/1998/namespace".to_string()),
        Some(p) => scope
            .iter()
            .rev()
            .find(|(declared, _)| declared.as_deref() == Some(p))
            .map(|(_, uri)| uri.clone()),
        // an unprefixed attribute is in no namespace at all
        None if !is_element => None,
        // an unprefixed element is in the default namespace, when one is
        // declared; xmlns="" declares none
        None => scope
            .iter()
            .rev()
            .find(|(declared, _)| declared.is_none())
            .map(|(_, uri)| uri.clone())
            .filter(|uri| !uri.is_empty()),
    }
}

fn parse_char_ref(numeric: &str) -> Option<char> {
    let digits = &numeric[1..];
    let code = if let Some(hex) = digits.strip_prefix(['x', 'X']) {
        u32::from_str_radix(hex, 16).ok()?
    } else {
        digits.parse::<u32>().ok()?
    };
    // surrogates and out of range values are not characters
    if (0xD800..=0xDFFF).contains(&code) || code > 0x10_FFFF {
        return None;
    }
    char::from_u32(code)
}

/// The XML line end rule, applied before anything else reads the text: CRLF
/// and a lone CR become LF. A CR that arrived through `&#xD;` is expanded
/// later and survives, which is why canonicalization still has to escape it.
fn normalize_line_ends(raw: &str) -> String {
    if !raw.contains('\r') {
        return raw.to_string();
    }
    raw.replace("\r\n", "\n").replace('\r', "\n")
}

/// Attribute value normalization: a literal tab, newline or carriage return
/// in the source becomes a space.
fn collapse_space(raw: &str) -> String {
    if !raw.contains(['\t', '\n', '\r']) {
        return raw.to_string();
    }
    raw.chars()
        .map(|c| {
            if c == '\t' || c == '\n' || c == '\r' {
                ' '
            } else {
                c
            }
        })
        .collect()
}

fn is_name_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.' || b == b':' || b >= 0x80
}

fn is_ncname(name: &str) -> bool {
    is_qname_parts(None, name)
}

/// Whether `id` can serve as an XML `Id` attribute value — a spec-conformant
/// ID must be an NCName, and `ds:Reference URI="#…"`, which is a *URI*, can
/// only resolve it back when nothing in it needs percent-encoding. The
/// signing code refuses anything else before producing a signature nobody
/// but us could resolve.
pub fn is_valid_id(id: &str) -> bool {
    is_ncname(id)
}

/// Name start and name characters, ASCII plus "any non ASCII byte", which is
/// the pragmatic subset of the enormous NameChar production of the XML
/// specification: real documents use letters, and the exotic ranges would
/// need tables nobody signing a FacturaE is waiting for.
fn is_qname_parts(prefix: Option<&str>, local: &str) -> bool {
    let ok = |part: &str| {
        let mut chars = part.chars();
        match chars.next() {
            Some(c) if is_name_start(c) => {}
            _ => return false,
        }
        chars.all(is_name_char)
    };
    if let Some(p) = prefix {
        if !ok(p) {
            return false;
        }
    }
    ok(local)
}

fn is_name_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_' || !c.is_ascii()
}

fn is_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' || !c.is_ascii()
}

/// Finds an element by its namespace and local name, depth first: the first
/// match in document order wins.
pub fn find_element<'e>(root: &'e Element, ns: &str, local: &str) -> Option<&'e Element> {
    if root.namespace.as_deref() == Some(ns) && root.name.local == local {
        return Some(root);
    }
    for child in &root.children {
        if let Child::Element(el) = child {
            if let Some(found) = find_element(el, ns, local) {
                return Some(found);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_shape_of_the_golden_fixture() {
        let input = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
                      <documento Id=\"doc-prueba\" version=\"1.0\">\n  \
                        <titulo>Documento de prueba</titulo>\n\
                      </documento>\n";
        let doc = parse(input).expect("fixture parses");
        assert!(doc.decl.is_some());
        assert_eq!(doc.root.name.local, "documento");
        assert_eq!(doc.root.attr("Id"), Some("doc-prueba"));
        // the root span covers the start tag through the end tag, and neither
        // the declaration nor the trailing newline
        let (start, end) = doc.root_span;
        let span = std::str::from_utf8(&input[start..end]).unwrap();
        assert!(span.starts_with("<documento"));
        assert!(span.ends_with("</documento>"));
    }

    #[test]
    fn expands_entities_and_normalizes_line_ends() {
        let doc = parse(b"<a>&lt;x&amp;y&gt; &#65;&#x42;\r\n</a>").unwrap();
        match &doc.root.children[0] {
            Child::Text(t) => assert_eq!(t, "<x&y> AB\n"),
            other => panic!("expected text, got {other:?}"),
        }
    }

    #[test]
    fn cdata_becomes_text() {
        let doc = parse(b"<a><![CDATA[r<&>aw]]></a>").unwrap();
        match &doc.root.children[0] {
            Child::Text(t) => assert_eq!(t, "r<&>aw"),
            other => panic!("expected text, got {other:?}"),
        }
    }

    #[test]
    fn attribute_values_collapse_whitespace() {
        let doc = parse(b"<a v=\"one\ttwo\nthree\"/>").unwrap();
        assert_eq!(doc.root.attributes[0].value, "one two three");
    }

    #[test]
    fn namespaces_resolve_and_prefixes_must_be_declared() {
        let doc = parse(
            br#"<root xmlns:x="urn:x" xmlns:y="urn:y" xmlns="urn:d"><x:c y:v="1" plain="2"/><c/></root>"#,
        )
        .unwrap();
        let Child::Element(first) = &doc.root.children[0] else {
            panic!("expected element");
        };
        assert_eq!(first.namespace.as_deref(), Some("urn:x"));
        // a prefixed attribute resolves, an unprefixed one is in no namespace
        assert_eq!(first.attributes[0].namespace.as_deref(), Some("urn:y"));
        assert_eq!(first.attributes[1].namespace, None);
        assert!(
            parse(br#"<root xmlns:x="urn:x"><x:c y:v="1"/></root>"#).is_err(),
            "undeclared prefix y must be refused"
        );
        // the default namespace applies to the unprefixed child
        let Child::Element(second) = &doc.root.children[1] else {
            panic!("expected element");
        };
        assert_eq!(second.namespace.as_deref(), Some("urn:d"));
        assert_eq!(doc.root.namespace.as_deref(), Some("urn:d"));
    }

    #[test]
    fn refuses_what_it_cannot_understand() {
        let bad: &[&[u8]] = &[
            b"<!DOCTYPE a><a/>",     // DTD
            b"<a>&custom;</a>",      // entity needing a DTD
            b"<a><b></a></b>",       // mismatched tags
            b"<a x=\"1\" x=\"2\"/>", // duplicate attribute
            b"<a>",                  // unclosed
            b"<a/><b/>",             // two roots
            b"",                     // nothing
            b"<a b=c/>",             // unquoted value
            b"\xff\xfe<a/>",         // not UTF-8
        ];
        for input in bad {
            assert!(parse(input).is_err(), "{:?} was accepted", input);
        }
    }

    #[test]
    fn self_closing_root_is_recorded_as_such() {
        let doc = parse(b"<a/>").unwrap();
        assert!(doc.root.self_closing);
        assert!(doc.root.content.is_none());
    }

    /// The parser, the canonicalizer and the drop of the tree each recurse
    /// once per nesting level. Without the cap, a document nested 100 000
    /// levels deep did not fail to parse — it aborted the process with a
    /// stack overflow, which no caller can catch.
    #[test]
    fn nesting_past_the_cap_is_refused_instead_of_overflowing_the_stack() {
        fn nested(depth: usize) -> String {
            let mut s = "<a>".repeat(depth);
            s.push('x');
            s.push_str(&"</a>".repeat(depth));
            s
        }
        // 512 frames of unoptimized parser recursion weigh more than the
        // 2 MiB a cargo test thread gets, so the probing runs on a thread
        // with a stack like the 8 MiB main thread the CLI parses on. A cap
        // that fits no stack would protect nothing; this one fits that one.
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                // the cap itself is accepted, one level past it is refused
                let at_cap = parse(nested(MAX_DEPTH).as_bytes());
                assert!(at_cap.is_ok(), "depth {MAX_DEPTH} must parse: {at_cap:?}");
                drop(at_cap);
                let err = parse(nested(MAX_DEPTH + 1).as_bytes())
                    .unwrap_err()
                    .to_string();
                assert!(err.contains(&MAX_DEPTH.to_string()), "{err}");
                // and the review's proof of concept: this used to abort the
                // process instead of returning an error
                let err = parse(nested(100_000).as_bytes()).unwrap_err().to_string();
                assert!(err.contains(&MAX_DEPTH.to_string()), "{err}");
            })
            .expect("cannot spawn the probe thread")
            .join()
            .expect("deep nesting must be an error, not an abort");
    }
}
