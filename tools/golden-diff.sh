#!/usr/bin/env bash
# Layer 1 of docs/validation.md: sign the same inputs with the official
# AutoFirma and with openfirma, dump both through the normalizer, diff.
#
# Raw bytes can never match, the signing time and therefore the signature
# differ on every run. What must match is the structure: which attributes are
# present, how each value is encoded, the certificate set, the versions.
#
# Needs: tools/gen-testcert.sh run first, and autofirma.jar, which
# tools/fetch-autofirma.sh downloads. Override its location with AUTOFIRMA_JAR.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

JAR="${AUTOFIRMA_JAR:-${AUTOFIRMA_DIR:-/tmp/autofirma-ref}/autofirma.jar}"
CERTS="testdata/certs"
P12="$CERTS/signer-rsa.p12"
PASS="openfirma"
OUT="${GOLDEN_DIR:-testdata/golden}"
DRIVER="target/golden-driver"
INPUTS="testdata/inputs"

[ -f "$P12" ] || { echo "run tools/gen-testcert.sh first" >&2; exit 1; }
[ -f "$JAR" ] || { echo "no autofirma.jar at $JAR, run tools/fetch-autofirma.sh" >&2; exit 1; }

mkdir -p "$OUT" "$DRIVER"
javac -nowarn -cp "$JAR" -d "$DRIVER" tools/golden/AutofirmaGolden.java
cargo build -q --bin openfirma

# Volatile values, replaced so they stop producing noise. Digests and cert
# hashes are deliberately kept: those must match exactly.
normalize() {
  sed -E -e 's/(UTCTime|GeneralizedTime) .*/\1 <TIME>/' \
         -e 's/[0-9A-F]{48}\.\.\.\(([0-9]+) bytes\)/<hex \1 bytes>/'
}

# run_case <name> <input> <autofirma key=value...>
# The openfirma flags below are the equivalent of AutoFirma's advanced profile
# defaults. contentHint carries the Spanish description AutoFirma gets from its
# jmimemagic database, which we do not ship, so it is passed explicitly.
# run_case <name> <input> <cert base name> [autofirma key=value...]
run_case() {
  local name="$1" input="$2" base="$3"; shift 3
  local af="$OUT/$name.autofirma.csig" ours="$OUT/$name.openfirma.csig"

  java -Djava.awt.headless=true -cp "$JAR:$DRIVER" AutofirmaGolden \
    "$CERTS/$base.p12" "$PASS" "$input" "$af" SHA256withRSA "$@" >/dev/null 2>&1

  ./target/debug/openfirma inspect -i "$af" | normalize >"$OUT/$name.autofirma.dump"

  # The contentHint description comes from AutoFirma's jmimemagic database,
  # which we do not ship, so it is read back from its own output instead of
  # being guessed. The comparison stays structural.
  local hint
  hint="$(awk '
    /OID 1\.2\.840\.113549\.1\.9\.16\.2\.4$/ { found = 1; next }
    found && /UTF8String / { sub(/^ *UTF8String "/, ""); sub(/".*$/, ""); print; exit }
    found && /OID /        { exit }
  ' "$OUT/$name.autofirma.dump")"

  ./target/debug/openfirma sign -i "$input" -o "$ours" \
    --cert "$CERTS/$base.crt" --key "$CERTS/$base.key" \
    --chain "$CERTS/intermediate.crt" --chain "$CERTS/ca.crt" \
    ${hint:+--content-hint "$hint"} >/dev/null

  ./target/debug/openfirma inspect -i "$ours" | normalize >"$OUT/$name.openfirma.dump"

  if diff -u "$OUT/$name.autofirma.dump" "$OUT/$name.openfirma.dump" >"$OUT/$name.diff"; then
    rm -f "$OUT/$name.diff"
    echo "MATCH  $name"
  else
    echo "DIFF   $name  ($(grep -c '^[-+][^-+]' "$OUT/$name.diff") lines, see $OUT/$name.diff)"
  fi
}

run_case simple "$INPUTS/simple.txt" signer-rsa

# PAdES: same idea, but the comparison goes through qpdf and a normalizer that
# is deliberately not our own PDF parser, so a bug in it cannot appear on both
# sides and cancel out.
#
# Three lines are dropped before diffing, and they are the container, not the
# signature. Each one is a decision recorded in docs, not a difference we hope
# nobody notices:
#   source     the file names and sizes differ by construction
#   revisions  AutoFirma rewrites the document through iText, we append an
#              incremental update. docs/adr/0003-incremental-update.md
#   container  how much of /Contents is reserved for the CMS and zero padded.
#              AutoFirma reserves 27000 bytes, we size it from the chain.
#              The length of the CMS itself is compared and must match.
normalize_pades() {
  grep -vE '^(source|revisions):' | sed -E 's/container [0-9]+ bytes/container <reserved>/'
}

run_pades_case() {
  local name="$1" input="$2" base="$3"
  local af="$OUT/$name.autofirma.pdf" ours="$OUT/$name.openfirma.pdf"

  command -v qpdf >/dev/null || { echo "SKIP   $name (no qpdf to normalize with)"; return 0; }

  java -Djava.awt.headless=true -cp "$JAR:$DRIVER" AutofirmaGolden \
    "$CERTS/$base.p12" "$PASS" "$input" "$af" SHA256withRSA >/dev/null 2>&1 \
    || { echo "SKIP   $name (AutoFirma refused to sign it)"; return 0; }

  ./target/debug/openfirma sign -i "$input" -o "$ours" --format pades-b-b \
    --cert "$CERTS/$base.crt" --key "$CERTS/$base.key" \
    --chain "$CERTS/intermediate.crt" --chain "$CERTS/ca.crt" >/dev/null

  python3 tools/golden/pdf-normalize.py "$af" --inspect ./target/debug/openfirma \
    | normalize_pades >"$OUT/$name.autofirma.pades.dump"
  python3 tools/golden/pdf-normalize.py "$ours" --inspect ./target/debug/openfirma \
    | normalize_pades >"$OUT/$name.openfirma.pades.dump"

  # both sides must pass their own integrity check, or a MATCH is meaningless
  for side in autofirma openfirma; do
    if ! grep -q 'ok: /ByteRange covers the file' "$OUT/$name.$side.pades.dump"; then
      echo "FAIL   $name ($side: /ByteRange or messageDigest does not check out)"
      grep -E '^  FAIL' "$OUT/$name.$side.pades.dump" | head -4
      return 0
    fi
  done

  if diff -u "$OUT/$name.autofirma.pades.dump" "$OUT/$name.openfirma.pades.dump" \
       >"$OUT/$name.pades.diff"; then
    rm -f "$OUT/$name.pades.diff"
    echo "MATCH  $name (PAdES-B-B)"
  else
    echo "DIFF   $name  ($(grep -c '^[-+][^-+]' "$OUT/$name.pades.diff") lines, see $OUT/$name.pades.diff)"
  fi
}

[ -f "$INPUTS/simple.pdf" ] || python3 tools/gen-testpdf.py "$INPUTS/simple.pdf"
run_pades_case simple "$INPUTS/simple.pdf" signer-rsa

# A legal person is not a natural person with a different name: the subject
# carries a CIF in serialNumber and an organizationIdentifier, and there is no
# human in it at all. Both implementations must treat it as unremarkable.
run_case juridical "$INPUTS/simple.txt" signer-juridical
run_pades_case juridical "$INPUTS/simple.pdf" signer-juridical

echo
echo "dumps and signatures in $OUT"
