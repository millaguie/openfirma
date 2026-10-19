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

use std::collections::{HashMap, HashSet};

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

/// The namespace bindings in scope while descending the tree: the stack of
/// declarations on the current path plus, for each prefix, the innermost entry
/// that names it.
///
/// The first version was a plain `Vec` that every child CLONED and that
/// `resolve_ns` scanned back to front, so a document carrying thousands of
/// prefixes on its root and thousands of untouched children cost the product of
/// the two: round two's N-5 measured 37 s for 4 000 prefixes × 20 000 children
/// and 126 s for 20 000 × 20 000 (288 KB and 706 KB), in a debug build. This is
/// the same shape `c14n::Scope` already used for the same finding: descending
/// costs one push per declaration, ascending one pop per declaration, and
/// resolving a name is one hash lookup. Nothing is copied per child, so no cap
/// on prefixes or elements per document was needed — the cost of a big document
/// is now proportional to the document.
#[derive(Debug, Default)]
struct Scope {
    stack: Vec<(Option<String>, String)>,
    /// innermost binding of each *prefixed* declaration: prefix → index into
    /// `stack`. A `String` key is queried by `&str`, so resolving costs no
    /// allocation; the default namespace is the field below rather than a
    /// `None` key, which no borrowed lookup could reach.
    prefixes: HashMap<String, usize>,
    /// innermost `xmlns` (the default namespace), or `None` when none is in
    /// scope. `Some(idx)` whose URI is empty is `xmlns=""`: no default.
    default: Option<usize>,
    /// what each pushed entry shadowed, in push order, so `ascend` puts the
    /// outer binding back one declaration at a time instead of rebuilding the
    /// whole table
    undo: Vec<(Prefix, Option<usize>)>,
}

/// Which of the two kinds of declaration a stack entry is.
#[derive(Debug, Clone)]
enum Prefix {
    Named(String),
    Default,
}

impl Scope {
    /// Push one element's declarations, returning the mark `ascend` unwinds to.
    fn push_element(&mut self, decls: &[(Option<String>, String)]) -> usize {
        let mark = self.stack.len();
        for (prefix, uri) in decls {
            let at = self.stack.len();
            match prefix {
                Some(p) => self.undo.push((
                    Prefix::Named(p.clone()),
                    self.prefixes.insert(p.clone(), at),
                )),
                None => self.undo.push((Prefix::Default, self.default.replace(at))),
            }
            self.stack.push((prefix.clone(), uri.clone()));
        }
        mark
    }

    /// Leave an element: undo exactly the declarations pushed above `mark`.
    fn ascend(&mut self, mark: usize) {
        while self.stack.len() > mark {
            self.stack.pop();
            let (prefix, outer) = self
                .undo
                .pop()
                .expect("one undo record per pushed declaration");
            match (prefix, outer) {
                (Prefix::Named(p), Some(at)) => {
                    self.prefixes.insert(p, at);
                }
                (Prefix::Named(p), None) => {
                    self.prefixes.remove(&p);
                }
                (Prefix::Default, outer) => self.default = outer,
            }
        }
    }

    /// The namespace a name with this prefix is in. `is_element` separates the
    /// two rules an unprefixed name follows: an element takes the default
    /// namespace when one is declared, an attribute is in no namespace at all.
    fn resolve(&self, prefix: Option<&str>, is_element: bool) -> Option<&str> {
        match prefix {
            Some("xml") => Some("http://www.w3.org/XML/1998/namespace"),
            Some(p) => self.prefixes.get(p).map(|&at| self.stack[at].1.as_str()),
            // an unprefixed attribute is in no namespace at all
            None if !is_element => None,
            // an unprefixed element is in the default namespace, when one is
            // declared; xmlns="" declares none
            None => self
                .default
                .map(|at| self.stack[at].1.as_str())
                .filter(|uri| !uri.is_empty()),
        }
    }
}

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

/// Whether `uri` carries an RFC 3986 scheme (`scheme ":"`), which is what
/// makes a namespace name absolute for Canonical XML 1.0's purposes. The
/// scheme is checked without building a parser: ASCII ALPHA, then ASCII
/// alphanumerics or `+`/`-`/`.`, then a colon. Anything else — `rel/ns`,
/// `../ns`, `/ns`, a URI whose first colon comes after a `/` — is relative.
fn has_a_scheme(uri: &str) -> bool {
    let Some(colon) = uri.find(':') else {
        return false;
    };
    let scheme = &uri.as_bytes()[..colon];
    match scheme.split_first() {
        Some((first, rest)) if first.is_ascii_alphabetic() => rest
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.')),
        _ => false,
    }
}

/// The XML declaration's pseudo-attributes, in production [24]'s order:
/// `version`, optional `encoding`, optional `standalone`. `Err` carries the
/// first reason the text is not an XMLDecl.
///
/// This parses the production instead of looking for tokens, because both
/// halves of that mistake were measured. Round two's N-3: the old scan
/// demanded `=` immediately after a name, so `encoding ="ISO-8859-1"` — which
/// production [25]'s `Eq ::= S? '=' S?` allows — looked like a declaration
/// with no encoding at all, and the bytes were signed as UTF-8 while every
/// parser that obeys the declaration reads Latin-1. Round two's N-4:
/// `<?xml version="1.0" encodi:ng="ISO-8859-1"?>` is not XML to libxml2
/// ("'?>' expected") and it was signed anyway. Names are compared
/// case-sensitively, like every XML name.
fn declaration_pseudo_attributes(content: &str) -> std::result::Result<[Option<&str>; 3], String> {
    /// `Eq AttValue` after a name, with the S production [25] allows around
    /// the `=`. Leaves `i` past the closing quote.
    fn quoted<'a>(
        content: &'a str,
        i: &mut usize,
        name: &str,
    ) -> std::result::Result<&'a str, String> {
        let bytes = content.as_bytes();
        while *i < bytes.len() && bytes[*i].is_ascii_whitespace() {
            *i += 1;
        }
        if bytes.get(*i) != Some(&b'=') {
            return Err(format!("{name} is not followed by '='"));
        }
        *i += 1;
        while *i < bytes.len() && bytes[*i].is_ascii_whitespace() {
            *i += 1;
        }
        let quote = match bytes.get(*i) {
            Some(&q @ (b'"' | b'\'')) => q,
            Some(_) => return Err(format!("{name}'s value is not quoted")),
            None => return Err(format!("{name} carries no value")),
        };
        *i += 1;
        let start = *i;
        while *i < bytes.len() && bytes[*i] != quote {
            *i += 1;
        }
        if *i == bytes.len() {
            return Err(format!("{name}'s quoted value is never closed"));
        }
        let value = &content[start..*i];
        *i += 1;
        Ok(value)
    }

    const ORDER: [&str; 3] = ["version", "encoding", "standalone"];
    let bytes = content.as_bytes();
    let mut i = 0usize;
    let mut out: [Option<&str>; 3] = [None; 3];
    for (slot, expected) in ORDER.iter().enumerate() {
        if slot > 0 {
            // production [24] separates the pseudo-attributes with S; two of
            // them side by side (`version="1.0"encoding=…`) are what libxml2
            // calls "Blank needed here"
            let before = i;
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if i == bytes.len() {
                break;
            }
            if i == before {
                return Err(format!(
                    "{expected} is not separated from the preceding pseudo-attribute by \
                     whitespace"
                ));
            }
        }
        if i >= bytes.len() {
            break;
        }
        let start = i;
        if !(bytes[i].is_ascii_alphabetic() || bytes[i] == b'_') {
            return Err(format!(
                "nothing after the {} pseudo-attribute starts a name (production [5])",
                ORDER[slot.saturating_sub(1)]
            ));
        }
        while i < bytes.len()
            && (bytes[i].is_ascii_alphanumeric() || matches!(bytes[i], b'_' | b'.' | b'-'))
        {
            i += 1;
        }
        let name = &content[start..i];
        if name != *expected {
            return Err(format!(
                "the declaration has {name:?} where production [24] allows {expected}"
            ));
        }
        out[slot] = Some(quoted(content, &mut i, expected)?);
    }
    if bytes[i..].iter().any(|b| !b.is_ascii_whitespace()) {
        return Err("the declaration carries something after its last pseudo-attribute".into());
    }
    if out[0].is_none() {
        return Err("the declaration carries no version, which production [24] requires".into());
    }
    if let Some(standalone) = out[2] {
        // SDDecl's value is exactly `yes` or `no` (production [32])
        if standalone != "yes" && standalone != "no" {
            return Err(format!(
                "standalone is {standalone:?}; production [32] accepts only \"yes\" or \"no\""
            ));
        }
    }
    Ok(out)
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
        let mut scope = Scope::default();
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
        // Everything between `<?xml` and `?>` must be the XMLDecl production
        // ([24]); there is no separate "must start with a space" rule to
        // enforce, because the production's VersionInfo carries its own S and
        // a tab is S exactly as a space is (libxml2 accepts
        // `<?xml\tversion="1.0"?>`, and the old check here refused it).
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
        // Production [24], parsed rather than searched for tokens (round two,
        // N-3 and N-4): `<?xml` S version Eq AttValue (S encoding Eq AttValue)?
        // (S standalone Eq AttValue)? S? `?>`, and nothing else. A declaration
        // no other parser can read is not a document whose bytes this reader
        // may interpret — libxml2 refuses every shape this rejects — so it is
        // refused with the reason instead of being rewritten.
        let attrs = declaration_pseudo_attributes(content).map_err(|reason| {
            self.err(&format!(
                "the XML declaration is not the XMLDecl production [24] \
                 ('<?xml' S version=… S? encoding=…? S? standalone=…? S? '?>'): \
                 {reason}. openfirma signs the document the declaration describes, so a \
                 declaration it cannot read is refused"
            ))
        })?;
        let version = attrs[0].unwrap_or_default();
        if !encoding_is(version, b"1.0") {
            return Err(self.err(&format!(
                "the XML declaration declares version=\"{version}\"; openfirma signs \
                 version 1.0 documents (and 1.1 would redefine the line ends inside \
                 your content)"
            )));
        }
        if let Some(encoding) = attrs[1] {
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
            // STag (production [40]) separates the attributes from the element
            // name and from one another with S. `<doc a="1"b="2">` is not XML
            // to any reader, and signing it wrote a file libxml2 refuses with
            // "attributes construct error" — a signature over something no
            // validator can open (round two, N-4). So whitespace is required
            // before every attribute name, not merely skipped.
            let before = self.pos;
            self.skip_space();
            let separated = self.pos > before;
            if self.pos >= self.src.len() {
                return Err(self.err("the start tag is never closed"));
            }
            let c = self.src[self.pos];
            if c == b'/' || c == b'>' {
                break;
            }
            if !separated {
                let next: String = self.text[self.pos..].chars().take(8).collect();
                return Err(self.err(&format!(
                    "the attribute starting at {next:?} is not separated from what precedes \
                     it by whitespace: XML's STag production requires S between attributes, \
                     and a document without it is not XML to any other reader"
                )));
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
            // Canonical XML 1.0 §2 makes canonicalization FAIL for a relative
            // namespace name (by decision of the W3C Plenary), libxml2 warns
            // "URI rel/ns is not absolute", xmlsec1 errors out of it, and
            // AutoFirma's canonicalizer throws — so a document carrying one
            // can be signed into something that verifies nowhere, our own
            // reader included (round two, N-7). An absolute URI is one that
            // carries an RFC 3986 scheme. Refused here, where the person can
            // still fix the document. `xmlns=""` is the one non-empty-value
            // exception and is handled above: it declares the absence of a
            // default namespace, which C14N prints as nothing.
            if !uri.is_empty() && !has_a_scheme(uri) {
                return Err(self.err(&format!(
                    "the namespace declared as {uri:?} is not an absolute URI (it has no \
                     scheme). Canonical XML 1.0 makes canonicalization fail for a relative \
                     namespace name, so a signature over this document would verify nowhere \
                     — give the declaration an absolute URI (urn:…, https:…) first"
                )));
            }
        }

        let mark = scope.push_element(&ns_decls);

        let element_ns = match name.prefix.as_deref() {
            // a prefixed name must have its prefix declared; an unprefixed
            // one simply takes the default namespace, which may be none
            Some(_) => Some(
                scope
                    .resolve(name.prefix.as_deref(), true)
                    .map(str::to_string)
                    .ok_or_else(|| {
                        self.err(&format!(
                            "the prefix {:?} of <{}> is not declared",
                            name.prefix,
                            name.to_string_with_prefix()
                        ))
                    })?,
            ),
            None => scope.resolve(None, true).map(str::to_string),
        };

        for (attr_name, value) in pending_attrs {
            let attr_ns = match &attr_name.prefix {
                None => None,
                Some(p) => {
                    let ns = scope
                        .resolve(Some(p), false)
                        .map(str::to_string)
                        .ok_or_else(|| {
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
                    // The child gets the SAME scope, not a copy of it:
                    // `parse_element` pushes its own declarations and ascends
                    // back to the mark it was handed, so the parent's bindings
                    // are exactly what they were when it returns. Cloning per
                    // child is what made a document with thousands of prefixes
                    // and thousands of children cost their product (round two,
                    // N-5).
                    let el = self.parse_element(scope, depth + 1)?;
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

        scope.ascend(mark);

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
        // Production [16]: `'<?' PITarget (S (Char* - …))? '?>'`. After the
        // target comes whitespace or the closing `?`, nothing else. This used
        // to take whatever followed as the data and re-emit it with a space
        // inserted — so `<doc><?pi!x?></doc>`, which libxml2 refuses with
        // "PI pi space expected", was signed into xmlsec1's "PI pi space
        // expected" over our own output, and the PI's data no longer matched
        // the file (round two, N-4).
        match self.src.get(self.pos) {
            Some(b' ' | b'\t' | b'\r' | b'\n' | b'?') | None => {}
            Some(_) => {
                return Err(self.err(
                    "a processing instruction's target is followed by neither whitespace \
                     nor '?>', which XML's PI production requires",
                ));
            }
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

    /// Round two, N-4: three XML shapes that used to be accepted and signed
    /// into files no reader opens. Each was measured against libxml2 first:
    /// `<doc a="1"b="2">` and `<doc xmlns="urn:d"xmlns:p="urn:p">` give
    /// "attributes construct error", and `<?pi!x?>` gives "PI pi space
    /// expected". The accepting half is pinned just as hard, because a reader
    /// that refuses legal spelling loses documents: S is any of the four
    /// whitespace characters, `<?pi?>` is a legal empty instruction, and a tab
    /// after `<?xml` is S too (libxml2 reads it; the old check demanded a
    /// literal space).
    #[test]
    fn stags_and_pis_are_separated_the_way_the_grammar_requires() {
        let refused: &[&str] = &[
            r#"<doc a="1"b="2"><x/></doc>"#,
            r#"<doc xmlns="urn:d"xmlns:p="urn:p"><a>x</a></doc>"#,
            r#"<doc><?pi!x?></doc>"#,
            r#"<doc><?pi"x"?></doc>"#,
            r#"<doc><?pi/x?></doc>"#,
        ];
        for input in refused {
            assert!(
                parse(input.as_bytes()).is_err(),
                "{input:?} is not XML to any other reader"
            );
        }
        let accepted: &[&str] = &[
            r#"<doc a="1" b="2"><x/></doc>"#,
            "<doc\n\ta=\"1\"\n\tb=\"2\"/>",
            r#"<doc><?pi?></doc>"#,
            r#"<doc><?pi data?></doc>"#,
            "<doc><?pi\tdata?></doc>",
        ];
        for input in accepted {
            assert!(parse(input.as_bytes()).is_ok(), "{input:?} must parse");
        }
    }

    /// Round two, N-7: Canonical XML 1.0 §2 makes canonicalization FAIL for a
    /// relative namespace name, so a signature over such a document verifies
    /// nowhere — xmlsec1 errors out of it and AutoFirma's own canonicalizer
    /// throws. It is refused here, where the person can still fix the
    /// document. An absolute URI is one with an RFC 3986 scheme, and
    /// `xmlns=""` is not a relative name: it declares that there is no default
    /// namespace, which is what C14N prints.
    #[test]
    fn a_relative_namespace_name_is_refused() {
        for input in [
            r#"<doc xmlns="rel/ns"><a>x</a></doc>"#,
            r#"<doc xmlns:p="../ns"><p:a>x</p:a></doc>"#,
            r#"<doc xmlns:p="/ns"><p:a>x</p:a></doc>"#,
            r#"<doc xmlns="x"><a/></doc>"#,
        ] {
            let err = parse(input.as_bytes()).expect_err("a relative namespace name is refused");
            let text = err.to_string();
            assert!(text.contains("absolute URI"), "{input:?}: {text}");
        }
        for input in [
            r#"<doc xmlns="urn:d"><a>x</a></doc>"#,
            r#"<doc xmlns="http://x.example/ns"><a>x</a></doc>"#,
            r#"<doc xmlns=""><a>x</a></doc>"#,
            r#"<doc xmlns="urn:x+1.2-3:a"><a>x</a></doc>"#,
        ] {
            assert!(
                parse(input.as_bytes()).is_ok(),
                "{input:?} carries an absolute namespace name"
            );
        }
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
        // production [24] and refused, whatever it declares there; the names
        // themselves are case-sensitive, like every other XML name (libxml2:
        // "Malformed declaration expecting version")
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

    /// The scope a child is handed is the parent's own, unwound on the way
    /// out, so a sibling's redeclaration must not leak. Round two's N-1
    /// panicked in `c14n`'s copy of this structure; the reader has its own
    /// copy now, so the same shape is pinned here: the innermost declaration
    /// wins inside its element, the outer one is back for the next sibling,
    /// and a default rebound 500 levels down unwinds to the top.
    #[test]
    fn a_siblings_redeclaration_leaves_the_outer_binding_intact() {
        let doc = parse(
            br#"<root xmlns:p="urn:outer" xmlns="urn:root">
                 <mid xmlns:p="urn:inner"><p:leaf/></mid>
                 <other xmlns:p="urn:third"><p:leaf2/></other>
                 <after xmlns="urn:own"><p:leaf3/></after>
                 <back/>
               </root>"#,
        )
        .unwrap();
        assert_eq!(doc.root.namespace.as_deref(), Some("urn:root"));
        let elements: Vec<&Element> = doc
            .root
            .children
            .iter()
            .filter_map(|c| match c {
                Child::Element(el) => Some(&**el),
                _ => None,
            })
            .collect();
        assert_eq!(elements.len(), 4, "whitespace is text, not an element");
        fn first_child(el: &Element) -> &Element {
            el.children
                .iter()
                .find_map(|c| match c {
                    Child::Element(inner) => Some(&**inner),
                    _ => None,
                })
                .expect("the element has an element child")
        }
        // an element's own name is resolved after the declarations IT writes
        // are pushed, so `mid` is in the root's default while its prefixed
        // child sees `mid`'s own binding.
        assert_eq!(elements[0].namespace.as_deref(), Some("urn:root"));
        assert_eq!(
            first_child(elements[0]).namespace.as_deref(),
            Some("urn:inner"),
            "a prefixed child takes the inner redeclaration"
        );
        assert_eq!(
            first_child(elements[1]).namespace.as_deref(),
            Some("urn:third"),
            "the second sibling rebinds `p` for itself and its children"
        );
        // `after` rebinds only the DEFAULT: its prefixed child goes back out to
        // the root's `p`, because nothing between them rebound it
        assert_eq!(elements[2].namespace.as_deref(), Some("urn:own"));
        assert_eq!(
            first_child(elements[2]).namespace.as_deref(),
            Some("urn:outer")
        );
        // the sibling that follows every redeclaration resolves against the
        // ROOT's default, not against anything a sibling declared
        assert_eq!(elements[3].namespace.as_deref(), Some("urn:root"));

        // 500 levels each rebinding the default: the innermost wins at the
        // bottom, and the root's own binding is what it always was. This is
        // also the shape the reviewer timed (0.20 s), so cost and correctness
        // are pinned by one document. It runs on a thread with a stack like the
        // CLI's main thread, for the reason `nesting_past_the_cap_…` spells
        // out: 500 frames of unoptimized parser recursion need more than a
        // test thread's 2 MiB.
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                let mut deep = String::from("<root xmlns=\"urn:top\">");
                for i in 0..500 {
                    deep.push_str(&format!("<e{i} xmlns=\"urn:level{i}\">"));
                }
                for i in (0..500).rev() {
                    deep.push_str(&format!("</e{i}>"));
                }
                deep.push_str("</root>");
                let doc = parse(deep.as_bytes()).expect("500 levels must parse");
                assert_eq!(doc.root.namespace.as_deref(), Some("urn:top"));
                let mut node = &doc.root;
                for _ in 0..500 {
                    let Child::Element(child) = &node.children[0] else {
                        panic!("the nesting stops early");
                    };
                    node = child;
                }
                assert_eq!(
                    node.namespace.as_deref(),
                    Some("urn:level499"),
                    "the innermost declaration wins at the bottom of the chain"
                );
            })
            .expect("cannot spawn the probe thread")
            .join()
            .expect("a 500-level document must parse, not abort");
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
