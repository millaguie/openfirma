#!/usr/bin/env bash
# The cert guard tests itself (review 07, H-3's fix would otherwise rot in
# silence): every shape a real signature can hide in gets synthesized HERE,
# from throwaway self-signed certificates created at runtime, and the guard
# must reject each one. The negative controls — synthetic-marker material and
# plain files — must pass. Every key is generated under mktemp and discarded;
# no signature here identifies anyone (the DNI/CIF numbers are the same
# synthetic ones tools/gen-testcert.sh uses).
#
# Run directly (`tools/test-check-no-real-certs.sh`) or through `cargo test`:
# crates/openfirma-cli/tests/cli.rs execs this file as its own test case.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fails=0

# A synthetic rogue: a self-signed identity with NO openfirma marker, which is
# what "not from the test PKI" means. The other keypair carries the marker so
# the negative controls prove the rule is the marker, not certificate phobia.
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/rogue.key" \
  -out "$WORK/rogue.crt" -days 1 -subj "/CN=Guard Probe User/serialNumber=IDCES-12345678Z" 2>/dev/null
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/syn.key" \
  -out "$WORK/syn.crt" -days 1 -subj "/CN=openfirma Test Probe/serialNumber=IDCES-12345678Z" 2>/dev/null

if [ ! -x "$ROOT/target/debug/openfirma" ]; then
  echo "building openfirma for the probes…" >&2
  ( cd "$ROOT" && cargo build -q --bin openfirma )
fi
OF="$ROOT/target/debug/openfirma"

printf 'guard probe content\n' > "$WORK/doc.txt"
[ -f "$WORK/doc.pdf" ] || python3 "$ROOT/tools/gen-testpdf.py" "$WORK/doc.pdf"
cp "$WORK/rogue.key" "$WORK/notes.md"        # the H-3 markdown-key probe

# sign <flags...> — run openfirma from the repo root so relative testdata works.
sign() { ( cd "$ROOT" && "$OF" sign --force >/dev/null "$@" ); }

sign -i "$WORK/doc.txt" -o "$WORK/probe.bin" \
  --cert "$WORK/rogue.crt" --key "$WORK/rogue.key"          # CMS under any name
cp "$WORK/probe.bin" "$WORK/probe.dat"                       # same blob, new name
sign -i "$WORK/doc.pdf" -o "$WORK/probe-pdf.bin" --format pades-b-b \
  --cert "$WORK/rogue.crt" --key "$WORK/rogue.key"           # PDF /Contents CMS
sign -i testdata/inputs/simple.xml -o "$WORK/probe-xml.bin" --format xades-b-b \
  --cert "$WORK/rogue.crt" --key "$WORK/rogue.key"           # ds:SignatureValue
sign -i "$WORK/doc.pdf" -o "$WORK/synth-ok.bin" --format pades-b-b \
  --cert "$WORK/syn.crt" --key "$WORK/syn.key"               # negative control
cp "$WORK/rogue.crt" "$WORK/rogue-cert.bin"                  # bare cert, lying name

must_block() {
  local why="$1" path="$2"
  if ( cd "$ROOT" && ./tools/check-no-real-certs.sh "$path" ) >/dev/null 2>&1; then
    echo "FAIL: guard let $why through ($path)" >&2
    fails=$((fails + 1))
  else
    echo "ok, blocked: $why"
  fi
}
must_pass() {
  local why="$1" path="$2"
  if ! ( cd "$ROOT" && ./tools/check-no-real-certs.sh "$path" ) >/dev/null 2>&1; then
    echo "FAIL: guard rejected the negative control ($why): $path" >&2
    fails=$((fails + 1))
  else
    echo "ok, allowed: $why"
  fi
}

must_block "CMS SignedData under a free extension" "$WORK/probe.bin"
must_block "the same CMS under a second free extension" "$WORK/probe.dat"
must_block "PAdES PDF with /Contents carrying a foreign CMS" "$WORK/probe-pdf.bin"
must_block "XAdES XML with ds:SignatureValue + X509Certificate" "$WORK/probe-xml.bin"
must_block "PEM private key saved as markdown" "$WORK/notes.md"
must_block "bare certificate renamed .bin" "$WORK/rogue-cert.bin"

must_pass "synthetic-marker PAdES PDF (the marker is the rule, not paranoia)" "$WORK/synth-ok.bin"
must_pass "plain text file" "$WORK/doc.txt"
# a markdown copy of a benign script passes the content rules too: docs stay
# writable as long as they carry no key.
cp "$ROOT/tools/check-no-real-certs.sh" "$WORK/guard-notes.md"
must_pass "markdown with prose (docs are not exempt, just clean)" "$WORK/guard-notes.md"

if [ "$fails" -gt 0 ]; then
  echo "$fails guard self-test failure(s)" >&2
  exit 1
fi
echo "guard self-test: every leak shape blocked, every control allowed"
