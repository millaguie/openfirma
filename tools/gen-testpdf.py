#!/usr/bin/env python3
"""Writes the minimal PDF that the PAdES golden files are built from.

Committed as a generator rather than as an opaque blob so the fixture is
reproducible and reviewable: the xref offsets are the part of a PDF that is
easy to get subtly wrong, and a hand edited binary hides that.

The document is deliberately bare. No /Info, no dates, no producer string, no
fonts beyond the standard Helvetica: anything volatile or machine specific
would land in the golden output and turn a structural diff into noise. iText,
which is what AutoFirma signs PDFs with, accepts it as is.

Usage: gen-testpdf.py [output]     (default testdata/inputs/simple.pdf)
       gen-testpdf.py --two-fields [output]  (default testdata/inputs/twofields.pdf)
"""

import sys
from pathlib import Path

CONTENT_STREAM = b"BT /F1 12 Tf 72 770 Td (openfirma PAdES test document) Tj ET\n"

# object number -> body, written in order so the xref offsets are trivial
OBJECTS = [
    b"<< /Type /Catalog /Pages 2 0 R >>",
    b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
    b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
    b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    b"<< /Length " + str(len(CONTENT_STREAM)).encode() + b" >>\nstream\n"
    + CONTENT_STREAM + b"endstream",
]

# The two-field form: an /AcroForm offering two empty signature fields, each
# with a /Rect so a signer can draw its appearance where the field says. This
# is the input of the round-6 interop measurement and of the AutoFirma co-sign
# test in openfirma-pades: AutoFirma 1.9.1 signs Firma1 and then Firma2, and the
# second pass builds the appearance chain (`/AP /N`, and what that form draws)
# that the revisions gate has to judge. Field rects differ so the two
# appearances are distinguishable, and the page names both fields in /Annots
# the way iText and Acrobat expect to find them.
TWO_FIELD_CONTENT = b"BT /F1 12 Tf 72 770 Td (openfirma two-field form) Tj ET\n"

TWO_FIELD_OBJECTS = [
    b"<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [6 0 R 7 0 R] "
    b"/SigFlags 3 /DR << /Font << /Helv 4 0 R >> >> /DA (/Helv 0 Tf 0 g) >> >>",
    b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
    b"/Resources << /Font << /Helv 4 0 R >> >> /Contents 5 0 R "
    b"/Annots [6 0 R 7 0 R] >>",
    b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    b"<< /Length " + str(len(TWO_FIELD_CONTENT)).encode() + b" >>\nstream\n"
    + TWO_FIELD_CONTENT + b"endstream",
    b"<< /Type /Annot /Subtype /Widget /FT /Sig /T (Firma1) "
    b"/Rect [72 600 400 660] /F 132 /P 3 0 R >>",
    b"<< /Type /Annot /Subtype /Widget /FT /Sig /T (Firma2) "
    b"/Rect [72 400 400 460] /F 132 /P 3 0 R >>",
]


def build(objects: list) -> bytes:
    # The binary comment marker tells every consumer the file is not text.
    # Without it some tools apply newline translation and corrupt the xref
    # offsets, which is exactly the class of bug this fixture must not have.
    out = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    offsets = []

    for i, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % i + body + b"\nendobj\n"

    xref_at = len(out)
    out += b"xref\n0 %d\n" % (len(objects) + 1)
    # every entry is exactly 20 bytes, as the spec requires
    out += b"0000000000 65535 f \n"
    for off in offsets:
        out += b"%010d 00000 n \n" % off

    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (
        len(objects) + 1,
        xref_at,
    )
    return bytes(out)


def main() -> int:
    two_fields = "--two-fields" in sys.argv
    rest = [a for a in sys.argv[1:] if not a.startswith("--")]
    default = "testdata/inputs/twofields.pdf" if two_fields else "testdata/inputs/simple.pdf"
    dest = Path(rest[0]) if rest else Path(default)
    objects = TWO_FIELD_OBJECTS if two_fields else OBJECTS
    dest.parent.mkdir(parents=True, exist_ok=True)
    pdf = build(objects)
    dest.write_bytes(pdf)
    print(f"{dest} ({len(pdf)} bytes, {len(objects)} objects)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
