#!/usr/bin/env python3
"""Normalizes a signed PDF into a structural dump that two implementations can
be compared with.

Why this is a Python script on top of qpdf and not a feature of openfirma: the
golden diff is only worth anything if the thing doing the comparing cannot be
wrong in the same way as the thing being compared. openfirma will grow its own
PDF parser, and if that parser also produced the golden dump, a bug in it would
appear on both sides and cancel out. qpdf is an independent implementation, so
it decompresses iText's object streams and xref streams for us and both sides
arrive at the same canonical shape.

Two things are reported, and they answer different questions:

  structure   the signature dictionary, the AcroForm field, the catalog and the
              page, with volatile values replaced. This is what has to match
              AutoFirma.
  integrity   recomputed from the raw bytes: the digest over /ByteRange has to
              equal the CMS messageDigest, and the CMS has to carry the three
              PAdES-B-B signed attributes. A file can have the right structure
              and still be a broken signature, so this is checked separately.

The container strategy is deliberately not compared. AutoFirma signs through
iText, which rewrites the whole document; openfirma appends an incremental
update. Both are conformant PDF and qpdf collapses both to the same latest
revision, which is what a validator sees. See docs/adr/0003.

Usage: pdf-normalize.py <signed.pdf> [--inspect <openfirma binary>]
"""

import re
import subprocess
import sys
import tempfile
from pathlib import Path

VOLATILE = re.compile(
    r"D:\d{14}(?:[+-]\d{2}'\d{2}')?"  # PDF date, with or without timezone
)


class Ref:
    def __init__(self, num, gen):
        self.num, self.gen = num, gen

    def __repr__(self):
        return f"{self.num} {self.gen} R"


class Stream:
    def __init__(self, dict_, data):
        self.dict, self.data = dict_, data


WS = {b"\x00", b"\t", b"\n", b"\f", b"\r", b" "}
DELIM = {b"/", b"<", b">", b"[", b"]", b"(", b")"}
# a name or a number token runs until whitespace or a delimiter
STOP = WS | DELIM


class Parser:
    """Enough of a PDF lexer to walk an object graph. QDF output is regular,
    so this does not need to cope with the full wild variety of PDF files."""

    def __init__(self, data, pos=0):
        self.d, self.p = data, pos

    def skip(self):
        while self.p < len(self.d):
            c = self.d[self.p : self.p + 1]
            if c in (b" ", b"\t", b"\n", b"\r", b"\f", b"\x00"):
                self.p += 1
            elif c == b"%":
                end = self.d.find(b"\n", self.p)
                self.p = len(self.d) if end < 0 else end + 1
            else:
                return

    def parse(self):
        self.skip()
        c = self.d[self.p : self.p + 1]
        if c == b"<" and self.d[self.p + 1 : self.p + 2] == b"<":
            return self.dict()
        if c == b"<":
            return self.hexstring()
        if c == b"(":
            return self.string()
        if c == b"[":
            return self.array()
        if c == b"/":
            return self.name()
        if c in (b"+", b"-", b".") or c.isdigit():
            return self.number_or_ref()
        for kw, val in ((b"true", True), (b"false", False), (b"null", None)):
            if self.d.startswith(kw, self.p):
                self.p += len(kw)
                return val
        raise ValueError(f"unexpected token at {self.p}: {self.d[self.p:self.p+16]!r}")

    def name(self):
        self.p += 1
        start = self.p
        while self.p < len(self.d) and self.d[self.p : self.p + 1] not in STOP:
            self.p += 1
        return "/" + self.d[start : self.p].decode("latin-1")

    def hexstring(self):
        end = self.d.index(b">", self.p)
        raw = re.sub(rb"\s", b"", self.d[self.p + 1 : end])
        self.p = end + 1
        if len(raw) % 2:
            raw += b"0"
        return bytes.fromhex(raw.decode("ascii"))

    def string(self):
        self.p += 1
        out, depth = bytearray(), 0
        while self.p < len(self.d):
            c = self.d[self.p]
            if c == 0x5C:  # backslash escape
                nxt = self.d[self.p + 1 : self.p + 2]
                table = {b"n": b"\n", b"r": b"\r", b"t": b"\t", b"b": b"\b",
                         b"f": b"\f", b"(": b"(", b")": b")", b"\\": b"\\"}
                if nxt in table:
                    out += table[nxt]
                    self.p += 2
                elif nxt.isdigit():
                    oct_ = b""
                    self.p += 1
                    while len(oct_) < 3 and self.d[self.p : self.p + 1].isdigit():
                        oct_ += self.d[self.p : self.p + 1]
                        self.p += 1
                    out.append(int(oct_, 8) & 0xFF)
                else:
                    self.p += 2
                continue
            if c == 0x28:  # (
                depth += 1
            elif c == 0x29:  # )
                if depth == 0:
                    self.p += 1
                    return bytes(out)
                depth -= 1
            out.append(c)
            self.p += 1
        raise ValueError("unterminated literal string")

    def array(self):
        self.p += 1
        items = []
        while True:
            self.skip()
            if self.d[self.p : self.p + 1] == b"]":
                self.p += 1
                return items
            items.append(self.parse())

    def dict(self):
        self.p += 2
        d = {}
        while True:
            self.skip()
            if self.d.startswith(b">>", self.p):
                self.p += 2
                break
            key = self.parse()
            if not isinstance(key, str) or not key.startswith("/"):
                raise ValueError(f"dictionary key is not a name: {key!r}")
            d[key] = self.parse()
        self.skip()
        if self.d.startswith(b"stream", self.p):
            self.p += 6
            if self.d[self.p : self.p + 2] == b"\r\n":
                self.p += 2
            elif self.d[self.p : self.p + 1] in (b"\n", b"\r"):
                self.p += 1
            length = d.get("/Length")
            if not isinstance(length, int):
                end = self.d.index(b"endstream", self.p)
                body = self.d[self.p : end]
            else:
                body = self.d[self.p : self.p + length]
                self.p += length
            self.p = self.d.index(b"endstream", self.p) + len(b"endstream")
            return Stream(d, body)
        return d

    def number_or_ref(self):
        start = self.p
        while self.p < len(self.d) and self.d[self.p : self.p + 1] not in STOP:
            self.p += 1
        tok = self.d[start : self.p]
        save = self.p
        # "N G R" is an indirect reference, not a number
        m = re.match(rb"(-?\d+)\s+(\d+)\s+R\b", self.d[start : start + 40])
        if m and not (b"." in tok):
            self.p = start + m.end()
            return Ref(int(m.group(1)), int(m.group(2)))
        self.p = save
        return float(tok) if b"." in tok else int(tok)


def load_objects(path):
    """QDF form: one revision, no object streams, objects in file order."""
    data = path.read_bytes()
    objs = {}
    for m in re.finditer(rb"(?m)^(\d+) (\d+) obj\b", data):
        num, gen = int(m.group(1)), int(m.group(2))
        try:
            objs[(num, gen)] = Parser(data, m.end()).parse()
        except (ValueError, IndexError) as e:
            print(f"# warning: object {num} {gen} did not parse: {e}", file=sys.stderr)
    return data, objs


def resolve(objs, value):
    seen = 0
    while isinstance(value, Ref) and seen < 64:
        value = objs.get((value.num, value.gen))
        seen += 1
    return value


def show(value, objs, depth=0):
    """Renders a value with references followed, so the dump reads the same
    whichever object numbers each implementation happened to use."""
    value = resolve(objs, value)
    if isinstance(value, Stream):
        return f"<stream {len(value.data)} bytes>"
    if isinstance(value, bytes):
        if len(value) > 120:
            # a /Contents string is 27000 bytes of hex decoded; printing it
            # would bury the structure this dump exists to show
            return f"<bytes {len(value)}>"
        text = value.decode("latin-1")
        return f"({VOLATILE.sub('<TIME>', text)})"
    if isinstance(value, dict):
        if depth >= 1:
            return "<dict>"
        # /ITEXT is iText's producer watermark, written because AutoFirma signs
        # through a full document rewrite. It is not PAdES structure and we
        # have no reason to claim iText wrote the file, so it is not compared.
        items = {k: v for k, v in value.items() if k != "/ITXT"}
        return "<< " + " ".join(
            f"{k} {show(v, objs, depth + 1)}" for k, v in sorted(items.items())
        ) + " >>"
    if isinstance(value, list):
        return "[" + " ".join(show(v, objs, depth + 1) for v in value) + "]"
    if isinstance(value, str):
        return value
    if isinstance(value, float):
        return f"{value:g}"
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def dict_summary(title, d, objs, keys):
    """Prints the keys that matter, in a fixed order, and says which of the
    optional ones are absent. Absence is information: AutoFirma leaves out
    /Cert, /Prop_Build, /Reason and /Location, and we must too."""
    print(f"{title}:")
    if d is None:
        print("  <missing>")
        return
    for k in keys:
        if k in d:
            v = d[k]
            if k == "/Contents" and isinstance(v, bytes):
                print(f"  {k} <CMS {cms_length(v)} bytes, container {len(v)} bytes>")
            elif k == "/M" and isinstance(v, bytes):
                print(f"  {k} <TIME>")
            elif k == "/ByteRange":
                print(f"  {k} <4 numbers, checked below>")
            elif k in ("/V", "/P") and isinstance(v, Ref):
                # object numbers differ between a full rewrite and an
                # incremental update, so only the fact that the link exists is
                # comparable
                target = resolve(objs, v)
                kind = target.get("/Type") if isinstance(target, dict) else None
                print(f"  {k} -> {kind or '<indirect>'}")
            elif k == "/AP":
                ap = resolve(objs, v)
                names = sorted(ap) if isinstance(ap, dict) else []
                print(f"  {k} {' '.join(names) or '<none>'}")
            else:
                print(f"  {k} {show(v, objs)}")
        else:
            print(f"  {k} (absent)")


def cms_length(contents):
    """Length of the DER inside /Contents, ignoring the zero padding that every
    implementation appends to fill the reserved container."""
    if len(contents) < 4 or contents[0] != 0x30:
        return -1
    n = contents[1] & 0x7F
    if not contents[1] & 0x80:
        return 2 + n
    value = int.from_bytes(contents[2 : 2 + n], "big")
    return 2 + n + value


def der_of(contents):
    n = cms_length(contents)
    return contents[:n] if n > 0 else b""


def integrity(data, der, digest_name):
    """Checks the two invariants that make a PAdES signature a signature."""
    import hashlib

    m = re.search(rb"/ByteRange\s*\[([^\]]*)\]", data)
    if not m:
        return ["no /ByteRange found"]
    nums = [int(x) for x in m.group(1).split()]
    if len(nums) != 4:
        return [f"/ByteRange has {len(nums)} numbers, expected 4"]
    a, b, c, d = nums
    problems = []
    if a != 0:
        problems.append(f"/ByteRange does not start at 0 (starts at {a})")
    if c + d != len(data):
        problems.append(f"/ByteRange ends at {c + d}, file is {len(data)} bytes")
    covered = data[a : a + b] + data[c : c + d]
    gap = data[a + b : c]
    if not (gap.startswith(b"<") and gap.endswith(b">")):
        problems.append("/ByteRange does not exclude exactly the /Contents string")

    alg = {"sha256": hashlib.sha256, "sha1": hashlib.sha1, "sha512": hashlib.sha512}.get(
        digest_name
    )
    if alg is None:
        problems.append(f"unknown digest {digest_name}")
        return problems
    want = alg(covered).digest()

    # messageDigest is attribute 1.2.840.113549.1.9.4; find it in the DER
    oid_md = bytes.fromhex("06092a864886f70d010904")
    at = der.find(oid_md)
    if at < 0:
        problems.append("no messageDigest attribute in the CMS")
    else:
        tail = der[at + len(oid_md) : at + len(oid_md) + 80]
        hm = re.search(rb"\x04(.)", tail, re.S)
        if hm:
            ln = hm.group(1)[0]
            got = tail[hm.end() : hm.end() + ln]
            if got != want:
                problems.append(
                    f"messageDigest {got.hex()[:16]}... != {digest_name}(/ByteRange) "
                    f"{want.hex()[:16]}..."
                )
    return problems


def normalize_dump(text):
    """Puts both sides of the comparison on equal terms.

    Three things cannot match by construction and are replaced, everything
    else is left alone because it has to match exactly:

      time            each run signs at a different instant
      long hex        the signature value, and any digest over it
      messageDigest   in PAdES this is the digest of the /ByteRange segments,
                      and the byte offsets differ between a full rewrite and an
                      incremental update, so equal structure gives unequal
                      digests. Its presence, position and length are still
                      compared; only the value is dropped.
    """
    out = []
    suppress_next_octet = False
    for line in text.splitlines():
        line = re.sub(r"(UTCTime|GeneralizedTime) .*", r"\1 <TIME>", line)
        line = re.sub(r"[0-9A-F]{48}\.\.\.\((\d+) bytes\)", r"<hex \1 bytes>", line)
        if "1.2.840.113549.1.9.4" in line:
            suppress_next_octet = True
        elif suppress_next_octet and "OCTET STRING" in line:
            line = re.sub(r"OCTET STRING .*", "OCTET STRING <messageDigest>", line)
            suppress_next_octet = False
        out.append(line)
    return "\n".join(out)


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if not args:
        print(__doc__)
        return 2
    src = Path(args[0])
    inspect = None
    if "--inspect" in sys.argv:
        inspect = Path(sys.argv[sys.argv.index("--inspect") + 1])

    data = src.read_bytes()
    print(f"source: {src.name} ({len(data)} bytes)")
    print(f"revisions: {data.count(b'%%EOF')}")
    print(f"starts with %PDF: {data[:5] == b'%PDF-'}")

    with tempfile.TemporaryDirectory() as tmp:
        qdf = Path(tmp) / "canon.pdf"
        subprocess.run(
            ["qpdf", "--qdf", "--object-streams=disable", "--no-original-object-ids",
             str(src), str(qdf)],
            check=True, capture_output=True,
        )
        _, objs = load_objects(qdf)

        # walk /Root -> /AcroForm -> /Fields -> /V
        root = None
        for obj in objs.values():
            if isinstance(obj, dict) and obj.get("/Type") == "/Catalog":
                root = obj
                break
        if root is None:
            print("no catalog found")
            return 1

        acro = resolve(objs, root.get("/AcroForm"))
        print()
        print("catalog:")
        print(f"  /AcroForm {'present' if '/AcroForm' in root else '(absent)'}")
        print(f"  /Pages {show(root.get('/Pages'), objs)}")
        if isinstance(acro, dict):
            print("acroform:")
            print(f"  /SigFlags {acro.get('/SigFlags', '(absent)')}")
            fields = resolve(objs, acro.get("/Fields"))
            print(f"  /Fields {len(fields) if isinstance(fields, list) else '?'}")
            print(f"  /DA {show(acro.get('/DA'), objs) if '/DA' in acro else '(absent)'}")
            print(f"  /NeedAppearances {acro.get('/NeedAppearances', '(absent)')}")
        else:
            print("acroform:\n  <missing>")

        field = None
        if isinstance(acro, dict):
            fields = resolve(objs, acro.get("/Fields"))
            if isinstance(fields, list) and fields:
                field = resolve(objs, fields[0])
        print()
        dict_summary("field", field, objs,
                     ["/FT", "/T", "/Subtype", "/Type", "/F", "/Rect", "/P", "/V", "/AP", "/DR"])
        if isinstance(field, dict):
            ap = resolve(objs, field.get("/AP"))
            if isinstance(ap, dict):
                nrm = resolve(objs, ap.get("/N"))
                if isinstance(nrm, Stream):
                    # only whether the appearance is blank is comparable: iText
                    # leaves a newline in it, an exact length would be noise
                    blank = "blank" if nrm.data.strip() == b"" else f"{len(nrm.data)} bytes"
                    print(f"  /AP /N form XObject, {blank}, "
                          f"/BBox {show(nrm.dict.get('/BBox'), objs)}")

        sig = resolve(objs, field.get("/V")) if isinstance(field, dict) else None
        print()
        dict_summary("signature dictionary", sig, objs,
                     ["/Type", "/Filter", "/SubFilter", "/ByteRange", "/Contents", "/M",
                      "/Name", "/Reason", "/Location", "/ContactInfo", "/Cert",
                      "/Prop_Build", "/Prop_AuthTime", "/Prop_AuthType", "/DocMDP"])

        # page annotations
        pages = resolve(objs, root.get("/Pages"))
        kids = resolve(objs, pages.get("/Kids")) if isinstance(pages, dict) else None
        if isinstance(kids, list) and kids:
            page = resolve(objs, kids[0])
            annots = resolve(objs, page.get("/Annots")) if isinstance(page, dict) else None
            print()
            print("page:")
            print(f"  /Annots {len(annots) if isinstance(annots, list) else '(absent)'}")
            print(f"  /MediaBox {show(page.get('/MediaBox'), objs)}")

        if isinstance(sig, dict) and isinstance(sig.get("/Contents"), bytes):
            der = der_of(sig["/Contents"])
            derfile = Path(tmp) / "cms.der"
            derfile.write_bytes(der)
            print()
            print("integrity:")
            for p in integrity(data, der, "sha256"):
                print(f"  FAIL {p}")
            if not integrity(data, der, "sha256"):
                print("  ok: /ByteRange covers the file except /Contents, "
                      "and messageDigest matches its digest")
            print()
            print("cms:")
            if inspect and inspect.exists():
                out = subprocess.run(
                    [str(inspect), "inspect", "-i", str(derfile)],
                    capture_output=True, text=True,
                )
                body = out.stdout.rstrip() or out.stderr.rstrip()
                print(normalize_dump(body))
            else:
                print(f"  <{len(der)} bytes, pass --inspect to dump>")
    return 0


if __name__ == "__main__":
    sys.exit(main())
