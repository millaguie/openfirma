#!/usr/bin/env python3
"""Normalizes an XML signature into a structural dump that two implementations
can be compared with.

Why this is a Python script and not a feature of openfirma: the golden diff is
only worth anything if the thing doing the comparing cannot be wrong in the
same way as the thing being compared. openfirma grows its own XML parser and
its own canonicalizer; if those also produced the golden dump, a bug in them
would appear on both sides and cancel out. This script reads the document with
Python's xml.etree (expat underneath), canonicalizes with lxml/libxml2 and lets
xmlsec1 verify the signature value: three independent implementations.

Two things are reported, and they answer different questions:

  structure   the document tree, every element with its namespace
              declarations and its sorted attribute set, text trimmed, and the
              volatile values (uuids, signing time, and the two values that
              depend on the time) neutralized exactly as listed in
              docs/xades.md. This is what has to match AutoFirma.
  integrity   recomputed from the file itself: every ds:Reference digest over
              the canonicalized bytes its own transforms declare, the
              signing-certificate digest against the embedded certificate, and
              the SignatureValue through xmlsec1. A file can have the right
              structure and still be a broken signature, so this is checked
              separately, on both sides, before the dumps are diffed.

Canonicalization note: lxml's C14N emits redundant namespace redeclarations
that C14N 1.0 suppresses (the ds:XPath element of an enveloped transform
carries one in AutoFirma's output), so lxml is used only for the reference
digests, whose subtrees contain no such redeclaration, and the SignatureValue
check goes through xmlsec1, whose C14N is spec conformant. See the "Gotcha"
section of docs/xades.md.

Usage: xml-normalize.py <signed.xml> [--trusted <ca.pem>]...
"""

import base64
import copy
import hashlib
import re
import shutil
import subprocess
import sys
from pathlib import Path

import xml.etree.ElementTree as ET

DS = "http://www.w3.org/2000/09/xmldsig#"
XADES132 = "http://uri.etsi.org/01903/v1.3.2#"
SIGNED_PROPERTIES_TYPE = "http://uri.etsi.org/01903#SignedProperties"

# The volatile values, docs/xades.md "Ids and what is volatile". UUIDs are
# replaced in place so that cross references (URI="#Signature-<uuid>-..."
# against Id="Signature-<uuid>-...") stay comparable.
UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)

C14N_INCLUSIVE = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
C14N_INCLUSIVE_COMMENTS = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"
C14N_EXCLUSIVE = "http://www.w3.org/2001/10/xml-exc-c14n#"
T_ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
T_XPATH = "http://www.w3.org/TR/1999/REC-xpath-19991116"
T_BASE64 = "http://www.w3.org/2000/09/xmldsig#base64"

DIGESTS = {
    "http://www.w3.org/2000/09/xmldsig#sha1": hashlib.sha1,
    "http://www.w3.org/2001/04/xmlenc#sha256": hashlib.sha256,
    "http://www.w3.org/2001/04/xmldsig-more#sha256": hashlib.sha256,
    "http://www.w3.org/2001/04/xmlenc#sha384": hashlib.sha384,
    "http://www.w3.org/2001/04/xmldsig-more#sha384": hashlib.sha384,
    "http://www.w3.org/2001/04/xmlenc#sha512": hashlib.sha512,
    "http://www.w3.org/2001/04/xmldsig-more#sha512": hashlib.sha512,
}

# the signature-stripping filter AutoFirma adds to every enveloped signature;
# any other XPath expression is beyond what this normalizer pretends to do
XPATH_STRIP_SIGNATURES = re.compile(r"^not\(ancestor-or-self::(\w+):Signature\)$")


def neutralize(value):
    return UUID_RE.sub("<uuid>", value)


# --------------------------------------------------------------------------
# structure: a tree of our own, built from iterparse events so that namespace
# declarations, comments and processing instructions are kept, which plain
# ElementTree drops or hides
# --------------------------------------------------------------------------

class Node:
    def __init__(self, kind, tag=None, attrib=None, nsdecl=None):
        self.kind = kind            # "element" | "text" | "comment" | "pi"
        self.tag = tag
        self.attrib = attrib or {}
        self.nsdecl = nsdecl or []  # [(prefix, uri)] declared on this element
        self.text = None
        self.children = []
        self.parent = None


def build_tree(path):
    root_nodes = []
    doc_level = []
    pending = []
    stack = []

    def add(node, parent):
        node.parent = parent
        (parent.children if parent is not None else
         (root_nodes if not doc_level or stack else doc_level)).append(node)

    for event, elem in ET.iterparse(path, events=("start-ns", "start", "end",
                                                  "comment", "pi")):
        if event == "start-ns":
            pending.append((elem[0], elem[1]))
        elif event == "start":
            node = Node("element", elem.tag, dict(elem.attrib), pending)
            pending = []
            if stack:
                node.parent = stack[-1]
                stack[-1].children.append(node)
            else:
                root_nodes.append(node)
            stack.append(node)
        elif event == "end":
            node = stack.pop()
            if elem.text is not None and elem.text.strip():
                t = Node("text")
                t.text = elem.text
                t.parent = node
                node.children.insert(0, t)
            if elem.tail is not None and elem.tail.strip():
                t = Node("text")
                t.text = elem.tail
                if stack:
                    t.parent = stack[-1]
                    stack[-1].children.append(t)
                else:
                    doc_level.append(t)
        elif event == "comment":
            node = Node("comment")
            node.text = elem.text or ""
            if stack:
                node.parent = stack[-1]
                stack[-1].children.append(node)
            else:
                doc_level.append(node)
        elif event == "pi":
            node = Node("pi")
            node.tag = elem.target
            node.text = elem.text or ""
            if stack:
                node.parent = stack[-1]
                stack[-1].children.append(node)
            else:
                doc_level.append(node)
    return root_nodes, doc_level


def neutralize_nodes(nodes):
    """Replaces the volatile values in the tree, following the list in
    docs/xades.md. Everything else is kept because it must match exactly."""
    for n in nodes:
        if n.kind == "element":
            for name in list(n.attrib):
                n.attrib[name] = neutralize(n.attrib[name])
            if n.tag == "{%s}SigningTime" % XADES132:
                mark_text(n, "<time>")
            elif n.tag == "{%s}SignatureValue" % DS:
                mark_text(n, "<signature-value>")
            elif n.tag == "{%s}DigestValue" % DS:
                # only the digest that covers the SigningTime is volatile; the
                # data reference digest and the certificate digest are stable
                # and are the strongest part of the comparison, so they stay
                ref = n.parent
                if (ref is not None and ref.tag == "{%s}Reference" % DS
                        and ref.attrib.get("Type") == SIGNED_PROPERTIES_TYPE):
                    mark_text(n, "<digest>")
            neutralize_nodes(n.children)
        elif n.kind == "text":
            n.text = neutralize(n.text)
        elif n.kind in ("comment", "pi"):
            n.text = neutralize(n.text or "")


def mark_text(node, token):
    for c in node.children:
        if c.kind == "text":
            c.text = token


def show_text(text):
    """Long values (certificates, public keys) would bury the structure, so
    they are shown truncated with a digest that still turns any difference
    between the two sides into a diff."""
    text = text.strip()
    if len(text) <= 96:
        return '"%s"' % text
    h = hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
    return '"%s..." (%d chars, sha256:%s)' % (text[:40], len(text), h)


def dump(out, nodes, depth=0):
    indent = "  " * depth
    for n in nodes:
        if n.kind == "element":
            parts = ["E %s" % n.tag]
            for prefix, uri in sorted(n.nsdecl):
                parts.append("xmlns:%s=%s" % (prefix, uri))
            for name in sorted(n.attrib):
                parts.append('%s="%s"' % (name, n.attrib[name]))
            out.append(indent + " ".join(parts))
            dump(out, n.children, depth + 1)
        elif n.kind == "text":
            out.append(indent + "T " + show_text(n.text))
        elif n.kind == "comment":
            out.append(indent + "C " + show_text(n.text))
        elif n.kind == "pi":
            out.append(indent + "P %s %s" % (n.tag, show_text(n.text)))


# --------------------------------------------------------------------------
# integrity
# --------------------------------------------------------------------------

def canonicalize(state, with_comments, exclusive):
    """state is an lxml Element (subtree c14n) or an ElementTree (document
    c14n, which is what URI="" dereferences to)."""
    from lxml import etree
    return etree.tostring(state, method="c14n", with_comments=with_comments,
                          exclusive=exclusive)


def strip_signatures(state):
    from lxml import etree
    root = state.getroot() if isinstance(state, etree._ElementTree) else state
    for s in root.findall(".//{%s}Signature" % DS):
        parent = s.getparent()
        if parent is not None:
            parent.remove(s)
    return state


def recompute_reference(ref, ltree, lroot):
    """Returns (uri, ok, detail) for one ds:Reference: ok is True when the
    digest recomputes, False when it does not, None when the check does not
    apply (external reference, unsupported algorithm)."""
    uri = ref.get("URI", "")
    alg_elem = ref.find("{%s}DigestMethod" % DS)
    want = (ref.findtext("{%s}DigestValue" % DS) or "").strip()
    if alg_elem is None:
        return uri, None, "no DigestMethod"
    alg = DIGESTS.get(alg_elem.get("Algorithm"))
    if alg is None:
        return uri, None, "unsupported DigestMethod %s" % alg_elem.get("Algorithm")

    if uri and not uri.startswith("#"):
        return uri, None, "external reference, not recomputed"

    if uri == "":
        state = copy.deepcopy(ltree)
    else:
        found = lroot.xpath('//*[@Id="%s"]' % uri[1:])
        if not found:
            return uri, False, "no element carries Id=%s" % uri[1:]
        # Canonicalize the node IN ITS TREE (remove every other Signature
        # from a copy of the whole document and take the same node there):
        # C14N 1.0 makes a subtree root re-emit the bindings inherited from
        # its ancestors (§2.3), and a detached lxml copy has no ancestors to
        # inherit them from, so deep-copying the target alone digests a
        # different form than any validator does. The removed-signature
        # cleanup for enveloped/XPath transforms runs on this same attached
        # copy below (strip_signatures walks it with .//).
        whole = copy.deepcopy(ltree)
        targets = whole.xpath('//*[@Id="%s"]' % uri[1:])
        state = targets[0] if targets else copy.deepcopy(found[0])

    with_comments = False
    exclusive = False
    problems = []
    transforms = ref.find("{%s}Transforms" % DS)
    if transforms is not None:
        for t in transforms.findall("{%s}Transform" % DS):
            algo = t.get("Algorithm")
            if algo == T_ENVELOPED:
                if isinstance(state, bytes):
                    problems.append("enveloped transform over an octet stream")
                else:
                    state = strip_signatures(state)
            elif algo == T_XPATH:
                expr = (t.findtext("{%s}XPath" % DS) or "").strip()
                if not XPATH_STRIP_SIGNATURES.match(expr):
                    problems.append("unsupported XPath transform %r" % expr)
                elif not isinstance(state, bytes):
                    # over an octet stream Santuario reparses and refilters;
                    # the signatures are gone by then, so that is a no-op
                    state = strip_signatures(state)
            elif algo in (C14N_INCLUSIVE, C14N_INCLUSIVE_COMMENTS, C14N_EXCLUSIVE):
                if not isinstance(state, bytes):
                    with_comments = algo == C14N_INCLUSIVE_COMMENTS
                    exclusive = algo == C14N_EXCLUSIVE
                    state = canonicalize(state, with_comments, exclusive)
            elif algo == T_BASE64:
                if isinstance(state, bytes):
                    state = base64.b64decode(re.sub(rb"\s", b"", state))
                else:
                    text = "".join(state.itertext())
                    state = base64.b64decode(re.sub(r"\s", "", text).encode())
            else:
                problems.append("unsupported transform %s" % algo)
    if problems:
        return uri, False, "; ".join(problems)

    if not isinstance(state, bytes):
        state = canonicalize(state, with_comments, exclusive)
    got = base64.b64encode(alg(state).digest()).decode()
    if got != want:
        return uri, False, "recomputed %s, file claims %s" % (got[:24], want[:24])
    alg_name = alg_elem.get("Algorithm").rsplit("#", 1)[-1]
    if ref.get("Type") == SIGNED_PROPERTIES_TYPE:
        # the canonicalized length of SignedProperties grows and shrinks
        # with the SigningTime string (AutoFirma writes a local offset, we
        # write Z; docs/xades.md deviation 1), so only the algorithm is
        # comparable, not the byte count
        return uri, True, "%s, canonicalized length volatile with SigningTime" % alg_name
    return uri, True, "%s over %d canonicalized bytes" % (alg_name, len(state))


def integrity(path, trusted):
    from lxml import etree
    lines = []
    ltree = etree.parse(str(path))
    lroot = ltree.getroot()
    signatures = lroot.findall(".//{%s}Signature" % DS)
    if lroot.tag == "{%s}Signature" % DS:
        signatures = [lroot] + signatures
    if not signatures:
        lines.append("FAIL no ds:Signature element in the document")
        return lines

    for i, sig in enumerate(signatures, 1):
        what = "signature %d" % i if len(signatures) > 1 else "signature"
        signed_info = sig.find("{%s}SignedInfo" % DS)
        refs = signed_info.findall("{%s}Reference" % DS) \
            if signed_info is not None else []
        if not refs:
            lines.append("FAIL %s has no ds:Reference" % what)
        for ref in refs:
            uri, ok, detail = recompute_reference(ref, ltree, lroot)
            label = neutralize(uri) if uri else 'URI=""'
            if ok is True:
                lines.append("ok: %s reference %s digest recomputes (%s)"
                             % (what, label, detail))
            elif ok is None:
                lines.append("note: %s reference %s: %s" % (what, label, detail))
            else:
                lines.append("FAIL %s reference %s digest: %s"
                             % (what, label, detail))

        # the signing certificate digest must match the certificate the
        # KeyInfo embeds, or the property points at somebody else
        cert_elems = sig.findall(".//{%s}X509Data/{%s}X509Certificate" % (DS, DS))
        cd = sig.find(".//{%s}CertDigest" % XADES132)
        if cd is not None:
            alg_elem = cd.find("{%s}DigestMethod" % DS)
            want = (cd.findtext("{%s}DigestValue" % DS) or "").strip()
            alg = DIGESTS.get(alg_elem.get("Algorithm")) if alg_elem is not None else None
            if alg is None or not cert_elems:
                lines.append("FAIL %s signing-certificate digest cannot be checked"
                             % what)
            else:
                der = base64.b64decode(re.sub(r"\s", "", cert_elems[0].text or ""))
                got = base64.b64encode(alg(der).digest()).decode()
                if got == want:
                    lines.append("ok: %s signing-certificate digest matches the "
                                 "embedded signer certificate" % what)
                else:
                    lines.append("FAIL %s signing-certificate digest %s... != "
                                 "embedded certificate %s..."
                                 % (what, want[:16], got[:16]))
        else:
            lines.append("FAIL %s has no xades:CertDigest" % what)

    # the SignatureValue, through xmlsec1: its own C14N (see the module
    # docstring), the signer certificate's public key, and every reference
    xmlsec = shutil.which("xmlsec1")
    if xmlsec is None:
        lines.append("FAIL xmlsec1 is not installed, the SignatureValue cannot "
                     "be verified independently")
        return lines
    cmd = [xmlsec, "--verify", "--enabled-key-data", "x509"]
    # Typing the Id attribute so the URI="#..." references resolve through
    # id(), per xmlsec version — both forms measured against real binaries
    # (Arch 1.3.12, Ubuntu 24.04's 1.2.39): 1.3+ takes `--add-id-attr Id
    # --verbose`; 1.2.x knows only `--id-attr:Id <root>` — it has no built-in
    # knowledge of Id and gets zero references verified without it — and
    # refuses both --add-id-attr and --verbose. An unknown flag answers
    # "is not supported" on stderr; the usage banner it also dumps goes to
    # stdout, so keying off one stream reads that backwards. Counters only
    # print in verbose mode, hence refs (?,?) tolerated on 1.2.x.
    def _accepts(option: str) -> bool:
        probe = subprocess.run([xmlsec, "--verify", option, "/nonexistent.xml"],
                               capture_output=True, text=True)
        return "is not supported" not in (probe.stderr or "")

    if _accepts("--add-id-attr"):
        cmd += ["--add-id-attr", "Id", "--verbose"]
    else:
        with open(path, "rb") as fh:
            head = fh.read(4096).decode("utf-8", "replace")
        root = re.search(r"<([A-Za-z_][\w:.-]*)[ >/]", head)
        # two arguments, never one glued `--id-attr:Id<root>`: 1.2.x then reads the
        # root name as a second input file and fails parsing it (measured). The
        # probe checks `--id-attr` without the suffix — 1.2.x names unknown flags by
        # their prefix, and `--id-attr:Id` itself is accepted on both lines.
        if root and _accepts("--id-attr"):
            cmd += ["--id-attr:Id", root.group(1)]
    for t in trusted:
        cmd += ["--trusted-pem", str(t)]
    cmd.append(str(path))
    proc = subprocess.run(cmd, capture_output=True, text=True)
    out = proc.stdout + proc.stderr
    # 1.2.39 answers a bare "OK" on stderr, 1.3.x "Verification status: OK";
    # the exit code is the version-independent truth, counters say how much
    # was verified (measured on both lines)
    refs_ok = re.search(r"SignedInfo References \(ok/all\): (\d+)/(\d+)", out)
    if proc.returncode == 0:
        # both xmlsec lines print the counters on verify (measured 1.2.39 and
        # 1.3.12); "OK" without every reference verified is a FAIL, not an ok
        if not refs_ok or refs_ok.group(1) != refs_ok.group(2):
            lines.append("FAIL xmlsec1 reported OK but not every reference "
                         "verified: %s" % (refs_ok.group(0) if refs_ok else out[:200]))
        else:
            lines.append("ok: xmlsec1 verified the SignatureValue with the signer "
                         "certificate and %s/%s references" % refs_ok.groups())
    else:
        reason = "exit %d" % proc.returncode
        for line in out.splitlines():
            if "error" in line.lower() and not line.startswith("===="):
                reason += " | " + line.strip()[:160]
                break
        lines.append("FAIL xmlsec1 did not verify the signature: %s"
                     % (reason.strip(" |") or out[:200]))
    return lines


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    trusted = []
    if "--trusted" in sys.argv:
        i = sys.argv.index("--trusted")
        while i + 1 < len(sys.argv) and not sys.argv[i + 1].startswith("--"):
            trusted.append(Path(sys.argv[i + 1]))
            i += 2
    if not args:
        print(__doc__)
        return 2
    src = Path(args[0])
    data = src.read_bytes()

    print("source: %s (%d bytes)" % (src.name, len(data)))
    m = re.match(rb"^(?:\xef\xbb\xbf)?(<\?xml[^>]*\?>)", data)
    print("declaration: %s" % (m.group(1).decode() if m else "(none)"))

    root_nodes, doc_level = build_tree(src)
    neutralize_nodes(root_nodes)
    comments = sum(1 for n in doc_level if n.kind == "comment")
    pis = sum(1 for n in doc_level if n.kind == "pi")
    print("doc-level nodes outside the root: %d comment(s), %d PI(s)"
          % (comments, pis))
    print("tree:")
    out = []
    dump(out, root_nodes)
    print("\n".join(out))

    print()
    print("integrity:")
    for line in integrity(src, trusted):
        print("  " + line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
