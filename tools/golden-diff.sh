#!/usr/bin/env bash
# Layer 1 of docs/validation.md: sign the same inputs with the official
# AutoFirma and with openfirma, dump both through the normalizer, diff.
#
# Raw bytes can never match, the signing time and therefore the signature
# differ on every run. What must match is the structure: which attributes are
# present, how each value is encoded, the certificate set, the versions.
# ECDSA adds one more class of volatile: BouncyCastle draws s with a fixed
# bit length (64 bytes for P-256) while RustCrypto writes it minimal per SEC
# 1, so signature values that differ only in leading zero bytes are the same
# shape and must not look like a diff. The normalizer below pins lengths.
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
# The CLI under test: where cargo put it. Hardcoding "$OF_BIN"
# (round two's N-6) made the script lie on any machine that sets CARGO_TARGET_DIR,
# comparing a stale binary against the jar while reporting MATCH. OPENFIRMA_BIN
# overrides; cargo metadata is the truth when the env vars differ.
OF_BIN="${OPENFIRMA_BIN:-${CARGO_TARGET_DIR:-$ROOT/target}/debug/openfirma}"
DRIVER="target/golden-driver"
INPUTS="testdata/inputs"

[ -f "$P12" ] || { echo "run tools/gen-testcert.sh first" >&2; exit 1; }
[ -x "$OF_BIN" ] || { echo "no CLI at $OF_BIN, build it (cargo build) or set OPENFIRMA_BIN" >&2; exit 1; }
[ -f "$JAR" ] || { echo "no autofirma.jar at $JAR, run tools/fetch-autofirma.sh" >&2; exit 1; }

mkdir -p "$OUT" "$DRIVER"
javac -nowarn -cp "$JAR" -d "$DRIVER" tools/golden/AutofirmaGolden.java
cargo build -q --bin openfirma

# Volatile values, replaced so they stop producing noise. Digests and cert
# hashes are deliberately kept: those must match exactly.
normalize() {
  sed -E -e 's/(UTCTime|GeneralizedTime) .*/\1 <TIME>/' \
         -e 's/[0-9A-F]{48}\.\.\.\(([0-9]+) bytes\)/<hex \1 bytes>/' \
         -e 's/^([[:space:]]*OCTET STRING) <hex (7[0-2]) bytes>/\1 <ec signature>/' \
         -e 's/^([[:space:]]*OCTET STRING) [0-9A-F]{132,}/\1 <ec signature>/' |
    # Second pass, and the reason it must be a second pass: an ECDSA blob is
    # 1-2 bytes longer (or shorter) depending on how the random s value falls,
    # so every container SEQUENCE/SET/[0] between it and the root carries a
    # length that differs by the same amount. The dump prints containers
    # top-down, so those lines come *before* the blob line proves them. Walk
    # the indentation stack: containers open at strictly deeper levels; when a
    # line confirms an EC signature, everything still on the stack shallower
    # than it — its ancestors, and nothing else — gets <ec-len>. The nesting
    # SHAPE stays under test: placeholders attach to a level, so one extra or
    # missing SEQUENCE cannot hide behind them, and RSA dumps carry no EC blob
    # line and never trigger this at all.
    sed -E 's/^(SEQUENCE|SET) \(([0-9]+)\)$/\1 (\2)/' | awk '
      { lines[NR] = $0 }
      /<ec signature>/ { blob = NR }
      END {
        if (!blob) { for (i = 1; i <= NR; i++) print lines[i]; exit }
        # ancestor levels: strictly decreasing indents before the blob line
        split("", keep);
        level = 1000000;
        for (i = blob - 1; i >= 1; i--) {
          line = lines[i]; rest = line; sub(/[^ ].*$/, "", rest); ind = length(rest);
          if (substr(line, ind + 1) ~ /^(SEQUENCE|SET) \(/ || substr(line, ind + 1) ~ /^\[0\] \(/ || substr(line, ind + 1) ~ /^\[4\] \(/ ) {
            if (ind < level) { keep[i] = 1; level = ind }
          }
        }
        for (i = 1; i <= NR; i++) {
          if (keep[i]) { sub(/ \(.*\)$/, " (<ec-len>)", lines[i]) }
          print lines[i]
        }
      }
    '
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

  "$OF_BIN" inspect -i "$af" | normalize >"$OUT/$name.autofirma.dump"

  # The contentHint description comes from AutoFirma's jmimemagic database,
  # which we do not ship, so it is read back from its own output instead of
  # being guessed. `inspect` dumps raw DER — attribute types appear as OIDs:
  # the ESS contentHint is …16.2.4. The comparison stays structural.
  # Only the hint attribute's own value block may produce the description:
  # OID line, then SET, SEQUENCE, and at that depth the UTF8String is the
  # contentDescription. Any other line (the contentType OID, a sibling
  # attribute) ends the search — mime-type and certificate-policies strings
  # sit at this same indentation in other attributes and are not it. The jar's
  # description reads "binary" today because this driver's classpath has no
  # jmimemagic database; a real AutoFirma would write the Spanish one, so the
  # dump stays the source of truth.
  local hint of=()
  hint="$(awk '
    /^ *OID 1\.2\.840\.113549\.1\.9\.16\.2\.4$/ { found = 1; next }
    !found { next }
    /^ *SET [0-9]/       { depth = 1; next }
    depth == 1 && /^ *SEQUENCE [0-9]/ { depth = 2; next }
    depth == 2 && /UTF8String / { sub(/^.*UTF8String "/, ""); sub(/".*$/, ""); print; exit }
    { exit }
  ' "$OUT/$name.autofirma.dump")"
  grep -qE '^ +INTEGER [0-9A-F]+$' "$OUT/$name.autofirma.dump" \
    || of+=(--no-issuer-serial)
  [ -n "$hint" ] && of+=(--content-hint "$hint")

  # --force: this script owns $ours (the corpus is regenerated per run, see
  # docs/validation.md), and the CLI refuses to replace an existing output of
  # another run without being told the overwrite is meant (review 06, A-3).
  "$OF_BIN" sign -i "$input" -o "$ours" --force \
    --cert "$CERTS/$base.crt" --key "$CERTS/$base.key" \
    --chain "$CERTS/intermediate.crt" --chain "$CERTS/ca.crt" \
    "${of[@]}" >/dev/null

  "$OF_BIN" inspect -i "$ours" | normalize >"$OUT/$name.openfirma.dump"

  if diff -u "$OUT/$name.autofirma.dump" "$OUT/$name.openfirma.dump" >"$OUT/$name.diff"; then
    rm -f "$OUT/$name.diff"
    echo "MATCH  $name"
  else
    echo "DIFF   $name  ($(grep -c '^[-+][^-+]' "$OUT/$name.diff") lines, see $OUT/$name.diff)"
  fi
}

# run_alg_case <name> <input> <cert base> <SHA1|SHA256|SHA384|SHA512>
# Like run_case, but the digest is pinned on both sides. The AutoFirma dump is
# read first and every knob it shows — encapsulation, whether signingTime is
# there, which signer-certificate attribute, its issuerAndSerialNumber, the
# contentHint description — is passed to openfirma explicitly. What stays under
# test is exactly what CAdESParameters.load derives from the digest: v1 for
# SHA-1, V2 for SHA-2, and no hashAlgorithm inside a SHA-256 ESSCertIDv2.
# The trailing arguments go to AutoFirma as extraParams, except --flag words:
# those belong to openfirma's side only (the jar takes key=value pairs and its
# driver refuses anything else), which is how the SHA-1 case keeps the M5
# opt-out on our side without polluting the reference invocation.
run_alg_case() {
  local name="$1" input="$2" base="$3" sha="$4"; shift 4
  local af_params=() of_extra=()
  local a
  for a in "$@"; do
    case "$a" in
      --*) of_extra+=("$a") ;;
      *) af_params+=("$a") ;;
    esac
  done
  local af="$OUT/$name.autofirma.csig" ours="$OUT/$name.openfirma.csig"
  local dump="$OUT/$name.autofirma.dump"
  # AutoFirma runs with these defaults plus any extraParams the caller passes
  # as trailing arguments; openfirma mirrors from the dump whatever shape came
  # out — encapsulation, signingTime, issuerAndSerialNumber, the contentHint
  # text — and appends of_extra, the --flags its side needs beyond them. The
  # finding under test stays unhidden either way: the v1 vs V2 choice
  # CAdESParameters.load derives from the digest is in the dump.

  java -Djava.awt.headless=true -cp "$JAR:$DRIVER" AutofirmaGolden \
    "$CERTS/$base.p12" "$PASS" "$input" "$af" "${sha}withRSA" \
    "${af_params[@]+"${af_params[@]}"}" >/dev/null 2>&1 \
    || { echo "SKIP   $name (AutoFirma refused to sign it)"; return 0; }

  "$OF_BIN" inspect -i "$af" | normalize >"$dump"

  local hint of=(--digest "$(echo "$sha" | tr 'A-Z' 'a-z')")
  hint="$(awk '
    /OID 1\.2\.840\.113549\.1\.9\.16\.2\.4$/ { found = 1; next }
    found && /UTF8String / { sub(/^ *UTF8String "/, ""); sub(/".*$/, ""); print; exit }
    found && /OID /        { exit }
  ' "$dump")"
  # encapsulated or detached: after the encapContentInfo contentType OID line,
  # `inspect` prints an `[0]` line one below it when eContent is present. The
  # top-level contentType (2-space indent) never has an [0] under it, so only
  # the nested occurrence (deeper indent) counts.
  awk '
    /OID 1\.2\.840\.113549\.1\.7\.2$/ {
      line = $0; sub(/OID.*$/, "", line)
      if (length(line) > 6) pending = 1
      next
    }
    pending { found = ($0 ~ /\[0\]/); pending = 0 }
    END { exit !found }
  ' "$dump" && of+=(--encapsulate)
  grep -qE '^ +OID 1\.2\.840\.113549\.1\.9\.5$' "$dump" || of+=(--no-signing-time)
  grep -qE 'OID 1\.2\.840\.113549\.1\.9\.16\.2\.(12|47)$' "$dump" \
    || { echo "SKIP   $name (the AutoFirma dump names no signer-certificate attribute)"; return 0; }
  # the issuerAndSerialNumber inside the signer-certificate attribute carries
  # the serial as its own INTEGER line, indented below the issuer Name
  grep -qE '^ +INTEGER [0-9A-F]+$' "$dump" || of+=(--no-issuer-serial)
  [ -n "$hint" ] && of+=(--content-hint "$hint")
  # openfirma-side flags beyond the dump-derived ones, set by the caller
  of+=("${of_extra[@]+"${of_extra[@]}"}")

  # --force: this script owns $ours (the corpus is regenerated per run, see
  # docs/validation.md), and the CLI refuses to replace an existing output of
  # another run without being told the overwrite is meant (review 06, A-3).
  "$OF_BIN" sign -i "$input" -o "$ours" --force \
    --cert "$CERTS/$base.crt" --key "$CERTS/$base.key" \
    --chain "$CERTS/intermediate.crt" --chain "$CERTS/ca.crt" \
    "${of[@]}" >/dev/null; echo "ALG-CASE $name flags: ${of[*]}" >&2

  "$OF_BIN" inspect -i "$ours" | normalize >"$OUT/$name.openfirma.dump"

  if diff -u "$dump" "$OUT/$name.openfirma.dump" >"$OUT/$name.diff"; then
    rm -f "$OUT/$name.diff"
    echo "MATCH  $name ($sha)"
  else
    echo "DIFF   $name  ($(grep -c '^[-+][^-+]' "$OUT/$name.diff") lines, see $OUT/$name.diff)"
  fi
}

run_case simple "$INPUTS/simple.txt" signer-rsa

# Finding M1, measured rather than argued: AutoFirma signs SHA-1 with the v1
# signingCertificate (its CAdESParameters.load picks v1 whenever the digest is
# not SHA-2), and openfirma must produce the identical shape.
# openfirma refuses weak output by default (finding M5), so the golden side
# that must reproduce AutoFirma's SHA-1 shape opts out explicitly. The env
# form matters: VAR=(…) cmd only exports a string, and the array would reach
# run_alg_case as its literal "(--allow-weak-algorithms)".
run_alg_case sha1 "$INPUTS/simple.txt" signer-rsa SHA1 --allow-weak-algorithms

# Finding B1: AutoFirma's ECDSA signatureAlgorithm carries an explicit NULL
# parameter (BouncyCastle's shape; RFC 5758 would leave it absent), and the
# digest algorithm is ecdsa-withSHA384/… as named by the digest. run_alg_case
# builds openfirma's flags from its own RSA key, so this one runs through a
# fixed pair of commands with the EC certificate on both sides; the contentHint
# description ("Texto plano") comes from the jar's jmimemagic database and is
# passed to openfirma explicitly, which is how every other case handles it.
if [ -f "$CERTS/signer-ec.p12" ]; then
  name=ecdsa
  af="$OUT/$name.autofirma.csig"; ours="$OUT/$name.openfirma.csig"
  # the test EC certificate is P-256, so the digest both sides use is SHA-256
  java -Djava.awt.headless=true -cp "$JAR:$DRIVER" AutofirmaGolden \
    "$CERTS/signer-ec.p12" "$PASS" "$INPUTS/simple.txt" "$af" SHA256withECDSA >/dev/null 2>&1
  "$OF_BIN" inspect -i "$af" | normalize >"$OUT/$name.autofirma.dump"
  hint="$(awk '
    /OID 1\.2\.840\.113549\.1\.9\.16\.2\.4$/ { found = 1; next }
    found && /UTF8String / { sub(/^ *UTF8String "/, ""); sub(/".*$/, ""); print; exit }
    found && /OID /        { exit }
  ' "$OUT/$name.autofirma.dump")"
  "$OF_BIN" sign --force -i "$INPUTS/simple.txt" -o "$ours" \
    --cert "$CERTS/signer-ec.crt" --key "$CERTS/signer-ec.key" \
    --chain "$CERTS/intermediate.crt" --chain "$CERTS/ca.crt" \
    --digest sha256 ${hint:+--content-hint "$hint"} >/dev/null
  "$OF_BIN" inspect -i "$ours" | normalize >"$OUT/$name.openfirma.dump"
  if diff -u "$OUT/$name.autofirma.dump" "$OUT/$name.openfirma.dump" >"$OUT/$name.diff"; then
    rm -f "$OUT/$name.diff"
    echo "MATCH  $name"
  else
    echo "DIFF   $name  ($(grep -c '^[-+][^-+]' "$OUT/$name.diff") lines, see $OUT/$name.diff)"
  fi
else
  echo "SKIP   ecdsa (run tools/gen-testcert.sh for signer-ec.p12)"
fi

# Findings M2 and M9, measured against the real thing:
#
#   `policies`      a certificate that declares certificatePolicies has them
#                   copied verbatim into the signer-certificate attribute —
#                   AutoFirma's getPolicyInformation, on by default (M2). No
#                   other knob on either side.
#   `policy_commit` signaturePolicyIdentifier and commitmentTypeIndication as
#                   a Spanish sede sends them. policyIdentifier alone crashes
#                   the jar's AdESPolicy (it parses the value as a URL), so
#                   hash and algorithm travel with it, exactly the shape an
#                   AGE invocation produces; the commitment attribute needs
#                   its count and index parameters, which is how
#                   CommitmentTypeIndicationsHelper reads it. The jar's hash
#                   (AQI= = bytes 01 02) is passed to openfirma too, so the
#                   case measures the DigestInfo shape itself, not the hash
#                   choice; openfirma also does AutoFirma's no-assertion
#                   fallback (placeholder byte 0x01).
# Without the policy certificate both cases skip.
if [ -f "$CERTS/signer-policy.p12" ]; then
  run_case policies "$INPUTS/simple.txt" signer-policy

  # the same cert with the two ETSI attributes; openfirma needs its CLI flags,
  # so this side runs through them with the values AutoFirma was given.
  name=policy_commit
  af="$OUT/$name.autofirma.csig"; ours="$OUT/$name.openfirma.csig"
  java -Djava.awt.headless=true -cp "$JAR:$DRIVER" AutofirmaGolden \
    "$CERTS/signer-policy.p12" "$PASS" "$INPUTS/simple.txt" "$af" SHA256withRSA \
    policyIdentifier=2.16.724.1.3.1.1.2.1.9 \
    policyIdentifierHash=AQI= policyIdentifierHashAlgorithm=SHA-256 \
    commitmentTypeIndications=1 commitmentTypeIndication0Identifier=5 >/dev/null 2>&1
  "$OF_BIN" inspect -i "$af" | normalize >"$OUT/$name.autofirma.dump"
  hint="$(awk '
    /OID 1\.2\.840\.113549\.1\.9\.16\.2\.4$/ { found = 1; next }
    found && /UTF8String / { sub(/^ *UTF8String "/, ""); sub(/".*$/, ""); print; exit }
    found && /OID /        { exit }
  ' "$OUT/$name.autofirma.dump")"
  "$OF_BIN" sign --force -i "$INPUTS/simple.txt" -o "$ours" \
    --cert "$CERTS/signer-policy.crt" --key "$CERTS/signer-policy.key" \
    --chain "$CERTS/intermediate.crt" --chain "$CERTS/ca.crt" \
    ${hint:+--content-hint "$hint"} \
    --signature-policy 2.16.724.1.3.1.1.2.1.9 \
    --signature-policy-hash 0102 \
    --commitment-type 1.2.840.113549.1.9.16.6.5 >/dev/null
  "$OF_BIN" inspect -i "$ours" | normalize >"$OUT/$name.openfirma.dump"
  if diff -u "$OUT/$name.autofirma.dump" "$OUT/$name.openfirma.dump" >"$OUT/$name.diff"; then
    rm -f "$OUT/$name.diff"
    echo "MATCH  $name"
  else
    echo "DIFF   $name  ($(grep -c '^[-+][^-+]' "$OUT/$name.diff") lines, see $OUT/$name.diff)"
  fi
else
  echo "SKIP   policies (run tools/gen-testcert.sh for signer-policy.p12)"
fi

# Finding M3: the mime-type attribute is a UTF8String under 0.4.0.1733.2.1,
# AutoFirma's shape (measured against the jar), not the IA5String openfirma
# used to emit. run_case mirrors from the dump whatever AutoFirma wrote except
# this one attribute, which is what the finding names: the mime-type value is
# already pinned identically on both sides by the parameters below, so it is
# passed to openfirma as a flag instead of being read back. Without them both
# sides sign detached with only contentType/signingTime/messageDigest/hint/
# ESSCertIDv2/messageHash, exactly like `simple`, plus this attribute.
name=mime
af="$OUT/$name.autofirma.csig"; ours="$OUT/$name.openfirma.csig"
java -Djava.awt.headless=true -cp "$JAR:$DRIVER" AutofirmaGolden \
  "$CERTS/signer-rsa.p12" "$PASS" "$INPUTS/simple.txt" "$af" SHA256withRSA \
  includeMimeTypeAttribute=true mimeType=text/plain >/dev/null 2>&1
"$OF_BIN" inspect -i "$af" | normalize >"$OUT/$name.autofirma.dump"
hint="$(awk '
  /OID 1\.2\.840\.113549\.1\.9\.16\.2\.4$/ { found = 1; next }
  found && /UTF8String / { sub(/^ *UTF8String "/, ""); sub(/".*$/, ""); print; exit }
  found && /OID /        { exit }
' "$OUT/$name.autofirma.dump")"
"$OF_BIN" sign --force -i "$INPUTS/simple.txt" -o "$ours" \
  --cert "$CERTS/signer-rsa.crt" --key "$CERTS/signer-rsa.key" \
  --chain "$CERTS/intermediate.crt" --chain "$CERTS/ca.crt" \
  ${hint:+--content-hint "$hint"} \
  --mime-type text/plain >/dev/null
"$OF_BIN" inspect -i "$ours" | normalize >"$OUT/$name.openfirma.dump"
if diff -u "$OUT/$name.autofirma.dump" "$OUT/$name.openfirma.dump" >"$OUT/$name.diff"; then
  rm -f "$OUT/$name.diff"
  echo "MATCH  $name"
else
  echo "DIFF   $name  ($(grep -c '^[-+][^-+]' "$OUT/$name.diff") lines, see $OUT/$name.diff)"
fi

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
#              Both sides reserve 27000 by default, but ours is a flag
#              (--contents-reserved), so the container is normalized away.
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

  "$OF_BIN" sign --force -i "$input" -o "$ours" --format pades-b-b \
    --cert "$CERTS/$base.crt" --key "$CERTS/$base.key" \
    --chain "$CERTS/intermediate.crt" --chain "$CERTS/ca.crt" >/dev/null

  python3 tools/golden/pdf-normalize.py "$af" --inspect "$OF_BIN" \
    | normalize_pades >"$OUT/$name.autofirma.pades.dump"
  python3 tools/golden/pdf-normalize.py "$ours" --inspect "$OF_BIN" \
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

# XAdES: enveloped XAdES-B-B over an XML document. The normalizer is Python
# on top of expat, lxml and xmlsec1 (tools/golden/xml-normalize.py), never
# our own XML code, and it recomputes every ds:Reference digest over the
# canonicalized bytes and has xmlsec1 verify the SignatureValue on both
# sides before the dumps are diffed, so a MATCH also means both files pass
# their own integrity claims. The measured reference is docs/xades.md.
run_xades_case() {
  local name="$1" input="$2" base="$3"
  local af="$OUT/$name.autofirma.xades.xml" ours="$OUT/$name.openfirma.xades.xml"

  command -v xmlsec1 >/dev/null \
    || { echo "SKIP   $name (no xmlsec1 to verify the SignatureValue with)"; return 0; }
  python3 -c 'import lxml.etree' 2>/dev/null \
    || { echo "SKIP   $name (no lxml for the canonicalization recomputation)"; return 0; }

  java -Djava.awt.headless=true -cp "$JAR:$DRIVER" AutofirmaGolden \
    "$CERTS/$base.p12" "$PASS" "$input" "$af" SHA256withRSA \
    format=XAdES\ Enveloped profile=baseline >/dev/null 2>&1 \
    || { echo "SKIP   $name (AutoFirma refused to sign it)"; return 0; }

  "$OF_BIN" sign --force -i "$input" -o "$ours" --format xades-b-b \
    --cert "$CERTS/$base.crt" --key "$CERTS/$base.key" \
    --chain "$CERTS/intermediate.crt" --chain "$CERTS/ca.crt" >/dev/null

  python3 tools/golden/xml-normalize.py "$af" --trusted "$CERTS/ca.crt" \
    | grep -v '^source:' >"$OUT/$name.autofirma.xades.dump"
  python3 tools/golden/xml-normalize.py "$ours" --trusted "$CERTS/ca.crt" \
    | grep -v '^source:' >"$OUT/$name.openfirma.xades.dump"

  # both sides must pass their own integrity check, or a MATCH is meaningless
  for side in autofirma openfirma; do
    local dump="$OUT/$name.$side.xades.dump"
    if grep -q '^  FAIL' "$dump"; then
      echo "FAIL   $name ($side: an integrity check failed)"
      grep '^  FAIL' "$dump" | head -4
      return 0
    fi
    if ! grep -q 'ok: xmlsec1 verified' "$dump"; then
      echo "FAIL   $name ($side: xmlsec1 did not verify the signature)"
      return 0
    fi
  done

  if diff -u "$OUT/$name.autofirma.xades.dump" "$OUT/$name.openfirma.xades.dump" \
       >"$OUT/$name.xades.diff"; then
    rm -f "$OUT/$name.xades.diff"
    echo "MATCH  $name (XAdES-B-B)"
  else
    echo "DIFF   $name  ($(grep -c '^[-+][^-+]' "$OUT/$name.xades.diff") lines, see $OUT/$name.xades.diff)"
  fi
}

run_xades_case simple "$INPUTS/simple.xml" signer-rsa

# A root that declares namespaces is the shape FacturaE and almost every
# administrative XML arrives in, and the shape review 03's C-1 broke: the
# canonical SignedInfo/SignedProperties must carry the inherited context. The
# golden normalizer recomputes every digest with lxml and has xmlsec1 verify
# both sides, so a regression here cannot hide on one side of the diff.
run_xades_case nsroot "$INPUTS/ns-root.xml" signer-rsa

# A document-level processing instruction is the shape this project had
# backwards: the data reference canonicalized the whole document, PI included,
# and no validator could reproduce the digest. AutoFirma writes no document-level
# PI at all, and neither do we now; both sides are recomputed with lxml and
# verified by xmlsec1 here, so a regression shows up as a DIFF and as a refusal.
run_xades_case doclevel-pis "$INPUTS/pi-doc-level.xml" signer-rsa

# A legal person is not a natural person with a different name: the subject
# carries a CIF in serialNumber and an organizationIdentifier, and there is no
# human in it at all. Both implementations must treat it as unremarkable.
run_case juridical "$INPUTS/simple.txt" signer-juridical
run_pades_case juridical "$INPUTS/simple.pdf" signer-juridical
run_xades_case juridical "$INPUTS/simple.xml" signer-juridical

echo
echo "dumps and signatures in $OUT"
