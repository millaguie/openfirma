# Hostile input fixtures

Tiny, hand-crafted malformed PDFs, kept as regression inputs for the crash
bugs a review round found in the readers. They contain no certificate
material, no signature and nothing that ever came out of a real signer:
every byte is synthetic and every file is a few hundred bytes long.

- `sig-contents-short.pdf` — a `/Type /Sig` dictionary whose `/Contents` is
  `<3084>`: a DER long-form length that claims four length octets in a value
  of two bytes. Reading the contents used to slice past the end and panic.
- `xref-at-eof.pdf` — a document whose `startxref` points into the last
  `%%EOF` line, so the object header scan runs off the end of the file. The
  error *message* for that case used to slice eight bytes past the end and
  panic before it could be returned.
- `xref-entries-bomb.pdf` — an 86 KB document whose cross-reference stream
  declares `/Size 30000000` with `/W [1 1 1]`: a ~90 MB row table behind a
  file smaller than a page. Before the entry cap it died by allocation
  inside `Vec::with_capacity`, so no error could even be returned; now the
  walk refuses the claim by name before materialising anything.

The tests that use them live in `crates/openfirma-pades/tests/hostile.rs`,
which also builds further hostile documents (impossible `/ByteRange`
numbers, truncated cross-reference tables) in memory instead of as files.
