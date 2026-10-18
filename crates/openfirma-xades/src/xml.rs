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

/// The encoding name a declaration declares ("" when it declares none). XML
/// names encodings case-insensitively and the ASCII case folds are all inside
/// ASCII, so a byte-level fold is exact here.
fn encoding_is(declared: &str, wanted: &[u8]) -> bool {
    declared.len() == wanted.len()
        && declared
            .bytes()
            .zip(wanted)
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
}

/// The pseudo-attributes of an XML declaration, in order, each with its value
/// when it follows production [24]'s `Name Eq AttValue` (`Eq ::= S? '=' S?`,
/// so whitespace is allowed on both sides of the `=`) and `None` when it does
/// not.
///
/// A name whose value cannot be read is kept rather than dropped: round 2's
/// N-3 showed why. The old scan demanded the `=` immediately after the name,
/// so `encoding ="ISO-8859-1"` — a spelling production [25] allows — looked
/// like a declaration with no encoding at all, and the document was signed as
/// UTF-8 while every parser that obeys the declaration reads Latin-1. Callers
/// see the difference between "absent" and "present but unreadable" and can
/// fail closed on the second.
fn declaration_attributes(content: &str) -> Vec<(&str, Option<&str>)> {
    let bytes = content.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        // production [5]: NameStartChar then NameChar. The names a declaration
        // may carry are ASCII, so the ASCII subset of that production is what
        // this scan understands.
        let starts_name = bytes
            .get(i)
            .is_some_and(|b| b.is_ascii_alphabetic() || matches!(b, b'_' | b':'));
        if !starts_name {
            break;
        }
        let start = i;
        while i < bytes.len()
            && (bytes[i].is_ascii_alphanumeric() || matches!(bytes[i], b'_' | b':' | b'.' | b'-'))
        {
            i += 1;
        }
        let name = &content[start..i];
        // Name Eq AttValue, with the optional spaces [25] allows around the '='
        let rest = &content[i..];
        let after_ws = rest.trim_start_matches([' ', '\t', '\r', '\n']);
        let mut consumed = i + (rest.len() - after_ws.len());
        let value = after_ws.strip_prefix('=').and_then(|after_eq| {
            let after_ws2 = after_eq.trim_start_matches([' ', '\t', '\r', '\n']);
            let quote = *after_ws2.as_bytes().first()?;
            if quote != b'"' && quote != b'\'' {
                // production [24] requires a quoted AttValue; an unquoted one is
                // not this pseudo-attribute (and is reported as unreadable)
                return None;
            }
            let end = after_ws2[1..].find(quote as char)?;
            consumed = consumed + 1 + (after_eq.len() - after_ws2.len()) + 1 + end + 1;
            Some(&after_ws2[1..end + 1])
        });
        out.push((name, value));
        if value.is_none() {
            // whatever follows is not a declaration this reader understands
            break;
        }
        i = consumed;
    }
    out
}

impl<'a> Parser<'a> {
    fn parse_document(&mut self) -> Result<Document> {
        self.skip_bom();
        // XML 1.0 (Well-Formedness Constraint XMLDeclSpec) puts the declaration
        // at byte zero, after an optional BOM that `skip_bom` has just consumed:
        // `  <?xml ...?><doc/>` is not well formed and libxml2 refuses it
        // (reviewer finding M-3 — we used to sign it). Checked against the raw
        // bytes here, before the element loop's skip_space swallows the
        // whitespace and hides the shape from every later check.
        let mut cursor = self.pos;
        while matches!(self.src.get(cursor), Some(b' ' | b'\t' | b'\r' | b'\n')) {
            cursor += 1;
        }
        // <?xmlname is the target <?xml plus a name character, not a declaration.
        let after_target = cursor + 5;
        let is_decl = match self.src.get(after_target) {
            None => true,
            Some(&c) => matches!(c, b' ' | b'\t' | b'\r' | b'\n') || c == b'?',
        };
        if is_decl && cursor > self.pos && self.src[cursor..].starts_with(b"<?xml") {
            let line = self.src[..cursor].iter().filter(|b| **b == b'\n').count() + 1;
            return Err(Error::Xml(format!(
                "whitespace before the XML declaration makes the document not \
                 well formed: XML puts the declaration at byte zero, after an \
                 optional BOM (line {line})"
            )));
        }
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
    /// nothing here is validated beyond well-formedness and what its version
    /// and encoding pseudo-attributes claim (see `check_declaration`).
    fn parse_declaration(&mut self) -> Result<Option<(usize, usize)>> {
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
        let content_start = self.pos;
        self.skip_until_pi_end()?;
        // `<? ... ?>` closing the declaration is well-formedness, checked here
        // because production [23] demands the question marks even when the
        // attributes are refused for other reasons
        if !self.src[content_start..self.pos].starts_with(b" ") {
            return Err(self.err(
                "the XML declaration must be followed by whitespace or '?>', and its \
                 attributes separated from the target",
            ));
        }
        // `version` and `encoding` are the two pseudo-attributes that decide
        // how the bytes below mean something, so they are checked here (the
        // rest of the declaration is data no consumer of ours reads). The
        // whitespace check above makes content_start..pos start at the first
        // character after the `<?xml` target itself; trimming it lands on the
        // first pseudo-attribute.
        let content = self.text[content_start..self.pos - 2].trim();
        self.check_declaration(content)?;
        Ok(Some((start, self.pos)))
    }

    /// version="1.0" and a declared encoding we can honour. XML 1.1 changes
    /// the line-end repertoire (U+0085 becomes a line end), which would
    /// change the content between what we sign and what a 1.1 parser
    /// reads, and no administrative XML in the field declares it: refused.
    /// The encoding rule is reviewer finding A-3: declaring ISO-8859-1 over
    /// bytes that happen to also be valid UTF-8 used to sign *different text*
    /// than what every other parser reads from the same file, and write a
    /// UTF-8 declaration over it. We never re-interpret the bytes behind the
    /// declaration's back: either the name is one of the two we can read with
    /// certainty (UTF-8 itself, or US-ASCII, whose bytes are all single-char
    /// in both readings) or the document is refused with the name it declares.
    fn check_declaration(&self, content: &str) -> Result<()> {
        // production [24] puts version first; real-world producers always do,
        // and a declaration that puts something else there is not this
        // document's version at all (review 03, M-3: libxml2 refuses those).
        let attrs = declaration_attributes(content);
        let version = match attrs.first() {
            Some((name, Some(value))) if name.eq_ignore_ascii_case("version") => *value,
            _ => {
                return Err(self.err(
                    "the XML declaration does not begin with a quoted version \
                     pseudo-attribute, which XML 1.0 production [24] requires",
                ));
            }
        };
        if !encoding_is(version, b"1.0") {
            return Err(self.err(&format!(
                "the XML declaration declares version=\"{version}\"; openfirma signs \
                 version 1.0 documents (and 1.1 would redefine the line ends inside \
                 your content)"
            )));
        }
        if let Some((_, value)) = attrs
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("encoding"))
        {
            // A name we cannot read is not a name we may ignore: `encoding
            // ="ISO-8859-1"` (spaces around the `=`, which production [25]
            // allows) used to read as "declares no encoding" and be signed as
            // UTF-8 over text every other parser reads as Latin-1 (round 2,
            // N-3). Fail closed instead.
            let Some(encoding) = *value else {
                return Err(self.err(
                    "the XML declaration names an encoding it does not spell as a quoted \
                     name (XML 1.0 production [24]: Name Eq AttValue), so openfirma cannot \
                     tell which text your bytes mean and refuses the document",
                ));
            };
            // A declared UTF-8 encoding over bytes that are not valid UTF-8
            // is refused by the whole-file UTF-8 check in `parse` before this
            // method ever runs, so it cannot reach here.
            // utf8 is the IANA registered alias of UTF-8 and a shape real
            // producers write; it names exactly the bytes this reader has
            // already validated, so it is honored like the hyphenated spelling.
            if !encoding_is(encoding, b"UTF-8")
                && !encoding_is(encoding, b"utf8")
                && !encoding_is(encoding, b"US-ASCII")
            {
                return Err(Error::Xml(format!(
                    "the document declares encoding=\"{encoding}\" while its bytes are \
                     being read as UTF-8. Signing it as-is could sign different text \
                     than what a parser that obeys the declaration reads, so openfirma \
                     refuses it. Convert the document first: iconv -f {encoding} -t \
                     UTF-8 in.xml > out.xml (and update its encoding=\"{encoding}\" \
                     declaration)"
                )));
            }
        }
        Ok(())
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
        // the square of their count (review 03, M-2)
        let mut seen_names: HashSet<(Option<String>, String)> = HashSet::new();
        // namespace declarations are attributes too, and checked for repeats
        // in tag order like everything else below; kept apart because their
        // value decides scope before the other attributes are resolved
        let mut seen_decls: HashSet<Option<String>> = HashSet::new();

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
            // tab, which canonicalization then prints as a reference again.
            // Line ends are normalized before collapsing (§2.11 runs before
            // §3.3.3), so a CRLF in the source is one line end and therefore
            // exactly one space, not two (reviewer finding A-1: libxml2 reads
            // "x\r\ny" as "x y").
            let collapsed = collapse_space(&normalize_line_ends(&value));
            let expanded = self.expand_entities(&collapsed)?;
            let value = validate_chars(&expanded, "an attribute value")?;
            let decl_prefix = if attr_name.prefix.is_none() && attr_name.local == "xmlns" {
                None
            } else if attr_name.prefix.as_deref() == Some("xmlns") {
                // xmlns: with an empty local name is a namespace declaration
                // attribute only in this exact spelling; anything weirder was
                // already refused by parse_qname
                Some(attr_name.local.clone())
            } else {
                // duplicate attributes are an error even before namespace
                // resolution decides their identity (libxml2 refuses them in
                // the tag itself). All non-xmlns attributes of one element
                // carry distinct (prefix, local) names or libxml2 stops here.
                if !seen_names.insert((attr_name.prefix.clone(), attr_name.local.clone())) {
                    return Err(self.err(&format!(
                        "the attribute {} appears twice on <{}>",
                        attr_name.to_string_with_prefix(),
                        name.to_string_with_prefix()
                    )));
                }
                pending_attrs.push((attr_name, value));
                continue;
            };
            // the same prefix declared twice on one element is an error even
            // with the identical URI (libxml2: Attribute xmlns:a redefined —
            // reviewer finding M-3, we used to sign such documents and the
            // output could not even be parsed back)
            if !seen_decls.insert(decl_prefix.clone()) {
                return Err(self.err(&format!(
                    "the namespace declaration {} appears twice on the same element",
                    match &decl_prefix {
                        Some(p) => format!("xmlns:{p}"),
                        None => "xmlns".to_string(),
                    }
                )));
            }
            ns_decls.push((decl_prefix, value));
        }

        // namespace declaration well-formedness (reviewer finding M-3): a
        // document that violates one of these rules parses nowhere else, and
        // signing it would produce a file no validator can even read. The
        // duplicate check already ran with the attributes, in tag order.
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
                // an empty URI cancels the default namespace, which only plain
                // `xmlns` may do: xmlns:p="" reserves a prefix to nothing
                // (Namespaces in XML §6.2; libxml2: Empty XML namespace is not
                // allowed for a prefix)
                if uri.is_empty() {
                    return Err(self.err(&format!("xmlns:{p} cannot name an empty namespace")));
                }
            }
        }

        let pushed = scope.len();
        for (prefix, uri) in &ns_decls {
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
        // §2.5 forbids the literal sequence ']]>' in content text (reviewer
        // finding M-3): a document carrying it parses nowhere else, and both
        // ends normalizing it away is precisely the divergence a signature
        // must not paper over
        if raw.contains("]]>") {
            return Err(
                self.err("']]' is not allowed in text content unless followed by '>' outside here")
            );
        }
        let expanded = self.expand_entities(&normalize_line_ends(raw))?;
        validate_chars(&expanded, "text content")
    }

    fn parse_cdata(&mut self) -> Result<String> {
        self.expect(b"<![CDATA[")?;
        let start = self.pos;
        let end = self
            .find(b"]]>")
            .ok_or_else(|| self.err("a CDATA section is never closed"))?;
        let raw = &self.text[start..end];
        self.pos = end + 3;
        let normalized = normalize_line_ends(raw);
        validate_chars(&normalized, "a CDATA section")
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
        // §2.11 runs before anything looks at the node, so a comment keeps no
        // CR; the comment mode of canonicalization would otherwise print a
        // raw CRLF where libxml2 prints an LF
        let normalized = normalize_line_ends(raw);
        validate_chars(&normalized, "a comment")
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
        // measured (libxml2, Apache Santuario) agrees with the spec example.
        // §2.11 normalization applies to PI data too (reviewer finding A-2):
        // libxml2 canonically prints `<?pi a\r\nb?>` as `<?pi a\nb?>`, and a
        // CR reaching write_pi verbatim breaks the digest
        let data = normalize_line_ends(
            self.text[start..self.pos - 2].trim_start_matches([' ', '\t', '\r', '\n']),
        );
        let data = validate_chars(&data, "a processing instruction")?;
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

    /// The four characters XML 1.0 calls whitespace (§2.3). `u8::is_ascii_-
    /// whitespace` also counts form feed and vertical tab, which libxml2
    /// rejects between attributes (reviewer finding M-3), so it is exactly the
    /// wrong predicate here.
    fn skip_space(&mut self) {
        while self.pos < self.src.len()
            && matches!(self.src[self.pos], b' ' | b'\t' | b'\r' | b'\n')
        {
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

/// The `Char` production of XML 1.0 (§2.2), applied to expanded content: text,
/// attribute values, CDATA, comments and PI data all forbid the C0 controls
/// (only tab, LF and CR were ever legal there) and surrogates. Reviewer
/// finding M-3: a document carrying them is not XML, libxml2 refuses to parse
/// it, and signing one produced a file no validator could even read. `&#0;`
/// and friends reach here as expanded characters, which is where they are
/// caught.
fn validate_chars(text: &str, where_: &str) -> Result<String> {
    if let Some(c) = text
        .chars()
        .find(|c| matches!(c, '\0' | '\x01'..='\x08' | '\x0b' | '\x0c' | '\x0e'..='\x1f'))
    {
        return Err(Error::Xml(format!(
            "invalid XML character U+{:04X} in {where_}: the parser of every other \
             implementation (libxml2, Xerces) refuses to read this document, so it \
             would carry a signature nobody can verify; remove or encode the control \
             characters first",
            c as u32
        )));
    }
    Ok(text.to_string())
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

    /// Reviewer finding A-1: §2.11 normalizes line ends before the attribute
    /// value normalization of §3.3.3, so a CRLF in the source is one line end
    /// and becomes exactly one space. The reader used to replace CR and LF
    /// separately and produced two spaces, which made xmlsec1 report
    /// `Reference 0/1` on any document whose attribute carried a Windows line
    /// ending.
    #[test]
    fn crlf_in_an_attribute_value_becomes_one_space() {
        let doc = parse(b"<doc a=\"x\r\ny\"><b>t</b></doc>").unwrap();
        assert_eq!(doc.root.attributes[0].value, "x y");
        // a lone CR is one line end too (the reader already got this right)
        let doc = parse(b"<doc a=\"1\r2\"/>").unwrap();
        assert_eq!(doc.root.attributes[0].value, "1 2");
        // and the reference form survives untouched, per §3.3.3
        let doc = parse(b"<doc a=\"x&#xD;y\"/>").unwrap();
        assert_eq!(doc.root.attributes[0].value, "x\u{d}y");
    }

    /// Reviewer finding A-2: the line end rule of §2.11 applies to processing
    /// instruction data (and comment text) as well; libxml2 canonically prints
    /// `<?pi a\r\nb?>` with an LF, and a raw CR reaching the canonicalizer
    /// broke every digest over the document.
    #[test]
    fn line_ends_are_normalized_in_pis_and_comments() {
        let doc = parse(b"<doc><?pi a\r\nb?><b>t</b></doc>").unwrap();
        match &doc.root.children[0] {
            Child::Pi { data, .. } => assert_eq!(data, "a\nb"),
            other => panic!("expected a PI, got {other:?}"),
        }
        let doc = parse(b"<doc><!--c1\r\nc2--><b/></doc>").unwrap();
        match &doc.root.children[0] {
            Child::Comment(c) => assert_eq!(c, "c1\nc2"),
            other => panic!("expected a comment, got {other:?}"),
        }
        // document level PIs too
        let doc = parse(b"<?t x\r\ny?><doc/>").unwrap();
        match &doc.prolog[0] {
            DocLevelNode::Pi { data, .. } => assert_eq!(data, "x\ny"),
            other => panic!("expected a PI, got {other:?}"),
        }
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

    /// Reviewer finding A-3: a declaration that says something other than
    /// UTF-8 about bytes the whole pipeline reads as UTF-8 means two readers
    /// see different text, and the signature would sit over one of them. The
    /// reader refuses instead of guessing — naming what was declared and how
    /// to fix it (review 03 asked for exactly this refusal path).
    #[test]
    fn a_declaration_that_lies_about_the_bytes_is_refused() {
        // valid UTF-8 AND meaningful Latin-1 text: the divergent case where
        // obeying the declaration and ignoring it produce different strings.
        let latin1 = b"<?xml version=\"1.0\" encoding=\"iso-8859-1\"?><doc>caf\xc3\xa9</doc>";
        let e = parse(latin1.as_slice()).unwrap_err().to_string();
        // the message names the encoding exactly as the document spelled it
        assert!(e.contains("iso-8859-1"), "{e}");
        assert!(e.contains("iconv"), "{e}");
        // a declaration that puts anything before version is outside
        // production [24] and refused, whatever it declares there; the check
        // that matters (case-insensitive names) runs on the position-anchored
        // spelling too
        assert!(parse(b"<?xml standalone=\"no\"?>").is_err());
        assert!(parse(b"<?xml version=\"1.0\" ENCODING=\"ISO-8859-1\"?><doc/>").is_err());
        assert!(parse(b"<?xml version=\"1.0\" encoding=\"utf8\"?><doc/>").is_ok());
        // what we do read with certainty stays legal: UTF-8 itself and the
        // ASCII subset, spelled any way that names them
        assert!(parse(b"<?xml version=\"1.0\" encoding=\"UTF-8\"?><doc>caf\xc3\xa9</doc>").is_ok());
        assert!(parse(b"<?xml version='1.0' encoding='us-ascii'?><doc/>").is_ok());
        // and no declaration at all: nothing is declared, the bytes are UTF-8
        assert!(parse(b"<doc>x</doc>").is_ok());
    }

    /// Reviewer finding M-3: a version other than 1.0, whitespace in front of
    /// the declaration, or a version outside production [24] — documents
    /// libxml2 refuses to read, so signing them would produce a file no
    /// verifier can open (review 03).
    #[test]
    fn an_invalid_or_misplaced_declaration_is_refused() {
        let bad: &[&[u8]] = &[
            br#"<?xml version="1.1"?><doc/>"#,
            br#"  <?xml version="1.0"?><doc/>"#,
            b"\n<?xml version=\"1.0\"?><doc/>",
            br#"<?xml?><doc/>"#,                  // no version at all
            br#"<?xml version=1.0?><doc/>"#,      // production [24] requires a quoted value
            br#"<?xml encoding="UTF-8"?><doc/>"#, // and version comes first
        ];
        for input in bad {
            assert!(parse(input).is_err(), "{:?} was accepted", input);
        }
        // a comment or PI before the root with no declaration is a legal
        // prolog: it is only the declaration that may not move
        assert!(parse(b"<!--c--><doc/>").is_ok());
        assert!(parse(b"<?pi d?><doc/>").is_ok());
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
            b"<a b=",                // attribute value cut off at EOF (M-1)
            b"<a b= ",               // ... with a trailing space
            b"<doc>&#0;x</doc>",     // character reference to a non xmlChar
            b"<doc>\x01x</doc>",     // control character in text
            b"<doc>a]]>b</doc>",     // ']]>' in content text (M-3)
            b"<a v=\"x\x01y\"/>",    // control character in an attribute value
        ];
        for input in bad {
            assert!(parse(input).is_err(), "{:?} was accepted", input);
        }
    }

    /// Reviewer finding M-1: `<a b=` indexed one past the end of the source
    /// and panicked; a truncated document must fail like every other cut.
    #[test]
    fn truncated_input_fails_with_an_error_never_a_panic() {
        let cases: &[&[u8]] = &[
            b"<a b=",
            b"<a b= ",
            b"<a b=\"",
            b"<a/",
            b"<a></a",
            b"<a x=\"1\"",
            b"<a>&",
        ];
        for input in cases {
            assert!(parse(input).is_err(), "{:?} was accepted", input);
        }
        // and the systematic form: cut a valid document at every byte, none
        // may panic
        let full =
            br#"<?xml version="1.0"?><r xmlns:x="urn:x" Id="i"><x:c a="1">t</x:c><!--k--></r>"#;
        for cut in 0..full.len() {
            let _ = parse(&full[..cut]);
        }
    }

    /// Reviewer finding M-2: attribute duplicate detection and namespace
    /// resolution scanned linear structures per attribute, which cost the
    /// square of their count. One element with 10 000 attributes must parse
    /// in well under a second, debug build included.
    #[test]
    fn many_attributes_do_not_cost_quadratic_time() {
        let mut s = String::from("<doc");
        for i in 0..10_000 {
            s.push_str(&format!(" x{i}=\"urn:a\" a{i}=\"{i}\""));
        }
        s.push_str("/>");
        let start = std::time::Instant::now();
        let doc = parse(s.as_bytes()).expect("10 000 attributes must parse");
        assert_eq!(doc.root.attributes.len(), 20_000);
        let elapsed = start.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "parsing 10 000 attributes took {elapsed:?}"
        );
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
