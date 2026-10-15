# ADR-0003: append an incremental update, do not rewrite the PDF

Date: 2026-10-15
Status: accepted

## Context

PAdES needs a signature dictionary in the document, an AcroForm field pointing
at it, and a `/ByteRange` covering every byte of the file except the value of
`/Contents`. It does not say how those bytes get there.

AutoFirma signs PDFs through iText 2.1.7. Measured on its own output, that
means a **full document rewrite**: one `%%EOF`, objects renumbered, the page
tree re-emitted into an object stream, a cross-reference stream instead of a
table, an `/ITEXT (2.1.7)` watermark on `/Pages`, and the bytes of the input
document not preserved (they diverge from the original at byte 26).

So there is a choice to make, and the two options are not equivalent in effort:
a rewrite means reimplementing a PDF serializer, an incremental update means
appending to a file we only have to read well enough to find its trailer.

## Decision

openfirma always appends an incremental update. The bytes of the input document
are copied through unchanged and a second revision is written after them, with
a trailer carrying `/Prev` to the previous `startxref`.

## Reasons

- **Co-signatures.** A second signature must not disturb the first. The first
  signature's `/ByteRange` addresses absolute offsets in the file; a rewrite
  re-serializes everything and moves them. Appending keeps revision 1 exactly
  where it was, so its `/ByteRange` still resolves to the same bytes. This is
  why AutoFirma itself switches iText into append mode for the second
  signature. Doing it always means one code path instead of two.
- **We do not want to be a PDF rewriter.** A full rewrite has to round-trip
  every producer's output faithfully: content streams, object streams, xref
  streams, compression choices, generation numbers, and the tolerated damage in
  real-world files. That is iText's job description, and reimplementing it is a
  large surface for a signature tool where every silent corruption is a lost
  document.
- **Auditability.** A reader can diff the signed file against the original and
  see the original intact. That is a meaningful property for a legal document.
- **Both validate.** ISO 32000-2 12.8.3 constrains what the signature covers,
  not the shape of the container. VALIDe and the ETSI validators accept either.

## Consequences

- Our output has two `%%EOF` markers and a `/Prev` chain where AutoFirma's has
  one. **The golden diff therefore cannot compare containers.** It compares the
  semantics of the latest revision, which is what a validator sees: both sides
  go through `qpdf --qdf --object-streams=disable` first, which collapses
  revisions and decompresses object streams. See
  `tools/golden/pdf-normalize.py`.
- We have to parse enough of the input to find the last trailer, `/Root` and the
  target page. That includes the compressed forms a modern writer produces: a
  cross-reference stream instead of a table, and objects packed into object
  streams. Both are implemented, which is what makes it possible to add a
  signature to a document AutoFirma has already signed, because iText writes
  both. The image filters are deliberately not implemented, nothing that carries
  document structure lives in an image.
- Appending means the file grows by a second copy of the objects we touch. For
  a document signed many times this is real overhead, and it is the price of
  not invalidating earlier signatures. Adobe behaves the same way.
- Deliberate deviations from AutoFirma's output, all container artifacts rather
  than signature structure: no `/ITEXT` watermark (that would claim iText wrote
  the file), and objects keep their numbers instead of being renumbered.
