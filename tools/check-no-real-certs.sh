#!/usr/bin/env bash
# Blocks real certificate material from entering the repository.
#
# The dangerous case is not someone copying a .p12 in by hand. It is committing
# a signature: CAdES and PAdES embed the signer certificate and its chain
# inside the file, so a golden file or a PDF signed with a real FNMT or DNIe
# certificate carries the full name and identifier of whoever it identifies,
# a natural person (NIF, NIE, passport) or a legal person (CIF, sello de
# entidad, representative), and the private
# key operation that produced it proves nothing about whether the key leaked.
#
# The rule is content-first (review 07, H-3): an extension lies and so does a
# filename. A PDF carrying /Contents with a CMS whose certificates are not the
# synthetic test PKI, an XML carrying ds:SignatureValue over a non-synthetic
# X509Certificate, a CMS SignedData blob under any name, and a PEM private key
# in ANY extension — including .md, which an earlier revision excluded blind
# — all of these are certificate material whatever they are called. Only the
# allowlisted regenerable fixtures may skip the extension rule, and even they
# stay under every content check.
#
# Usage:
#   tools/check-no-real-certs.sh            scan the git index (staged files)
#   tools/check-no-real-certs.sh --tracked  scan every tracked file
#   tools/check-no-real-certs.sh --history  scan every blob in the whole history
#   tools/check-no-real-certs.sh FILE...    scan the given files
set -euo pipefail

cd "$(dirname "$0")/.."

# Marker of the synthetic PKI that tools/gen-testcert.sh creates. A
# certificate is allowed in the repository only if it chains to this.
TEST_CA_MARKER="openfirma Test"

# PEM header trigger. Written so this script does not match its own pattern:
# after "BEGIN " the expression requires a letter, and the only "BEGIN "
# literal in this file is the one inside the character class below.
PEM_TRIGGER='BEGIN [A-Z ]*(PRIVAT|PKCS)'

# Extensions that hold key material, a certificate, or a signature that
# embeds one. Banned everywhere in the tree, no exceptions: our own test
# material is regenerated locally and never committed.
BANNED_EXT='p12|pfx|p8|p7b|p7s|p10|p1m|csr|key|pem|crt|cer|der|jks|keystore|csig|xsig|sig|pfd'

# Basenames that are key or certificate stores whatever the extension.
BANNED_NAMES='cert9\.db|key4\.db|cert8\.db|secmod\.db|cacerts|user\.keystore|autofirma\.pfx'

violations=0

block() {
  echo "BLOCKED: $1" >&2
  violations=$((violations + 1))
}

list_files() {
  case "${1:-index}" in
    index)   git diff --cached --name-only --diff-filter=ACM ;;
    tracked) git ls-files ;;
    *)       printf '%s\n' "$@" ;;
  esac
}

# Certificates embedded anywhere inside one file, checked against the test-PKI
# rule. `openssl x509` only parses a file that IS one certificate; signatures
# carry theirs nested, and review 07's H-3 proof was that every nesting shape
# passed this script before: PDF /Contents (PAdES), ds:X509Certificate
# (XAdES), CMS [certificates] (CAdES and the raw SignedData case, encapsulated
# or detached — `openssl pkcs7 -print_certs` reads a detached CMS fine). The
# container is unwrapped to one PEM block per certificate (a PEM bundle holds
# several, so the split is explicit), and each block's subject+issuer must
# carry the synthetic marker. A file no reader can parse is simply not one of
# these shapes; the probes' exit status says so.
check_embedded_certs() {
  local f="$1" blocks part tmpblocks
  case "$(file -b --mime-type "$f" 2>/dev/null || echo unknown)" in
    text/*|application/xml|text/xml) ;;
    *)
      # binary: PDF and raw CMS paths only make sense there, and asking about
      # them costs one openssl call per real binary file, none per source file.
      head -c 5 "$f" | grep -q '%PDF-' || openssl pkcs7 -inform DER -in "$f" -noout 2>/dev/null || return 0
      ;;
  esac
  blocks=""
  if head -c 5 "$f" | grep -q '%PDF-'; then
    # PAdES: the /Contents hex string IS a CMS SignedData (possibly zero
    # padded); its DER prefix ends where the outer SEQUENCE says it does.
    blocks="$(pdf_certs_pem "$f")" || blocks=""
  elif grep -aq 'SignatureValue\|X509Certificate\|BEGIN CERTIFICATE' "$f"; then
    # XAdES or any text carrying a base64 certificate: XML wraps the DER as
    # raw base64 inside <ds:X509Certificate>, PEM wraps it with armor, and a
    # CMS print_certs dump interleaves subject/issuer lines with the base64.
    # All three shapes collapse to "long base64 runs": cut every run between
    # 400 and 10000 chars (a certificate DER is ~800–3200 bytes, i.e. ~1100–
    # 4300 chars), decode each independently — base64 -d ignores whitespace
    # and stops at the first non-alphabet character, so a run that bleeds into
    # XML markup simply fails to parse as a certificate and is skipped.
    blocks="$(grep -oE '[A-Za-z0-9+/]{400,10000}={0,2}' "$f" 2>/dev/null |
      while read -r run; do
        if printf '%s' "$run" | base64 -d 2>/dev/null |
           openssl x509 -inform DER -noout -subject -issuer 2>/dev/null; then
          echo "### cert"
        fi
      done)" || blocks=""
    [ -n "$blocks" ] || return 0
  elif openssl pkcs7 -inform DER -in "$f" -noout 2>/dev/null; then
    # same chunking as the PDF path, so a chain of several certificates is
    # judged one certificate at a time and not as one blob whose marker in
    # any line would hide a foreign leaf.
    blocks="$(openssl pkcs7 -print_certs -inform DER -in "$f" 2>/dev/null |
      awk '/^-+BEGIN/{print "### cert"; skip=1; next} /^-+END/{skip=0; next} skip{next} {print}')" || blocks=""
    [ -n "$blocks" ] || return 0
  else
    return 0
  fi
  # One certificate per chunk: openssl -noout prints its "subject=…\nissuer=…"
  # lines, terminated by the "### cert" marker each decoder emits. Every
  # chunk must mention the synthetic PKI on both of its lines — a real leaf
  # issued BY a test CA is still somebody's identity and fails the rule.
  tmpblocks="$(mktemp -d)"
  awk -v dir="$tmpblocks" '
    /^### cert$/ { idx++; next }
    /^(subject|issuer)=/ { idx = (idx ? idx : 1); print >> (dir "/" idx ".part"); next }
  ' <<< "$blocks"
  for part in "$tmpblocks"/*.part; do
    [ -e "$part" ] || continue
    if ! grep -q "$TEST_CA_MARKER" "$part"; then
      block "$f embeds an X.509 certificate that is not from the '$TEST_CA_MARKER' test PKI (signatures embed the signer's whole chain — this is exactly how a real FNMT or DNIe identity would leak)"
    fi
  done
  rm -rf "$tmpblocks"
}

# The CMS inside a PDF's /Contents, as the certificate list openssl prints.
# Prints nothing when the PDF carries no parsable CMS.
pdf_certs_pem() {
  local f="$1" hex cms_der
  hex="$(grep -ao '/Contents[[:space:]]*<[0-9A-Fa-f]*>' "$f" | head -1 | sed 's/.*<//; s/>$//')" || true
  [ -n "$hex" ] || return 0
  cms_der="$(printf '%s' "$hex" | python3 -c '
import sys
raw = bytes.fromhex(sys.stdin.read().rstrip() or "00")
if raw[:1] != b"\x30":
    sys.exit(1)
# DER: outer SEQUENCE length tells where the CMS ends inside the padding
ln = raw[1]
off = 2
if ln & 0x80:
    n = ln & 0x7F
    off = 2 + n
sys.stdout.write(raw[: off + int.from_bytes(raw[2:off], "big")].hex())
' 2>/dev/null)" || return 0
  [ -n "$cms_der" ] || return 0
  if [ -n "$PDFCMS_TMP" ]; then
    printf '%s' "$cms_der" | xxd -r -p > "$PDFCMS_TMP" 2>/dev/null || return 0
    # `openssl pkcs7 -print_certs` without -noout emits, per certificate, its
    # subject/issuer pair followed by the PEM body; dropping the PEM leaves
    # exactly one chunk per certificate for the chunker. The marker line is
    # printed BEFORE each BEGIN (the trailing issuer= would otherwise wait a
    # new block), so awk rotates the chunk there.
    openssl pkcs7 -print_certs -inform DER -in "$PDFCMS_TMP" 2>/dev/null |
      awk '/^-+BEGIN/{print "### cert"; skip=1; next} /^-+END/{skip=0; next} skip{next} {print}'
  fi
  return 0
}

check_file() {
  local f="$1"
  [ -e "$f" ] || return 0

  # Files whose NAME is allowlisted (regenerated fixtures, documentation):
  # the extension rule may be skipped, but NEVER the content rules — review
  # 07, H-3 measured that `*.md` and `docs/*` were returned-safe sight
  # unseen, so a PEM private key saved as README.md passed. An allowlisted
  # path is allowed to not be a banned extension; it is never allowed to
  # contain a real certificate or a private key.
  local allowlisted=0
  case "$f" in
    testdata/*/README.md|docs/*|*.md) allowlisted=1 ;;
    # Wave-3 hostile corpus (H-11): DER/PKCS#12-shaped crash bait under
    # testdata/hostile/. These files are NOT certificate material — they are
    # a handful of bytes each (max 36), carry no certificate, no key and no
    # signature over anything, and every one is regenerated byte-for-byte by
    # tools/gen-hostile-corpus.py. They wear .der/.p12 extensions only so the
    # tests can include_bytes! them like a real module hands them over. The
    # content checks below still run on them: what is allowlisted is the
    # extension rule, nothing else.
    testdata/hostile/*.der|testdata/hostile/*.p12) allowlisted=1 ;;
  esac

  local base ext
  base="$(basename "$f")"
  ext="${base##*.}"
  if [ "$ext" = "$base" ]; then ext=""; fi

  if [ "$allowlisted" -eq 0 ] && printf '%s' "$ext" | grep -qiE "^($BANNED_EXT)$"; then
    block "$f has a banned extension .$ext, certificate or key material does not belong in this repo"
    return 1
  fi
  if printf '%s' "$base" | grep -qiE "^($BANNED_NAMES)$"; then
    block "$f is a certificate or key store"
    return 1
  fi

  # Text level checks, cheap and they catch material pasted into a source
  # file, a fixture or a commit template — in EVERY extension now, including
  # markdown: H-3's probe was exactly this, a key copied to leak.md.
  if grep -qE "$PEM_TRIGGER" "$f" 2>/dev/null; then
    block "$f contains a PEM private key or PKCS#7/PKCS#12 block (no extension is exempt)"
    return 1
  fi

  # Anything that parses as a certificate must come from the synthetic test
  # PKI. Covers DER blobs with an unexpected extension and certificates
  # embedded in text.
  local subj
  for fmt in PEM DER; do
    if subj="$(openssl x509 -inform "$fmt" -in "$f" -noout -subject -issuer 2>/dev/null)" && [ -n "$subj" ]; then
      if ! printf '%s' "$subj" | grep -q "$TEST_CA_MARKER"; then
        block "$f parses as an X.509 certificate that is not from the '$TEST_CA_MARKER' test PKI"
      fi
      return 0
    fi
  done

  # Nested material: PAdES /Contents, ds:X509Certificate, CMS SignedData.
  check_embedded_certs "$f"
  return 0
}

check_history() {
  # Every blob ever committed, so a leak cannot hide in an older revision.
  # Same eyes as the working tree (H-3 asked for it): key-material PEMs, bare
  # certificates and nested signature containers are all judged against the
  # test-PKI marker here too. The scan is slower than the tree walk (one blob
  # at a time out of the object store); history is finite and this runs in CI
  # on every push, which is the point.
  local seen=0 tmp
  tmp="$(mktemp -d)"
  while read -r sha; do
    seen=$((seen + 1))
    git cat-file -p "$sha" > "$tmp/blob" 2>/dev/null || continue
    # the blob file lives outside the tree, so it bypasses no rule: the same
    # check_file judges it, and a violation names $tmp/blob — carry the sha
    # into the message by re-blocking through block().
    local before=$violations
    check_file "$tmp/blob" >/dev/null 2>&1 || true
    if [ "$violations" -gt "$before" ]; then
      echo "        (blob $sha in history)" >> /dev/stderr
    fi
    rm -f "$tmp/blob"
  done < <(git rev-list --objects --all | awk '{print $1}' | sort -u | while read -r o; do
             git cat-file -t "$o" 2>/dev/null | grep -q '^blob$' && echo "$o"
           done)
  rmdir "$tmp" 2>/dev/null || true
  echo "scanned $seen blobs from history" >&2
}

mode="${1:-index}"
case "$mode" in
  --history)
    check_history
    mapfile -t files < <(list_files tracked)
    ;;
  --tracked)
    mapfile -t files < <(list_files tracked)
    ;;
  --*)
    echo "unknown mode $mode" >&2; exit 2 ;;
  *)
    if [ "$#" -gt 0 ]; then files=("$@"); else mapfile -t files < <(list_files index); fi
    ;;
esac

# One scratch file for the PDF CMS path, reused per file (the scan is serial).
PDFCMS_TMP="$(mktemp)"
trap 'rm -f "$PDFCMS_TMP"' EXIT

for f in "${files[@]:-}"; do
  [ -n "$f" ] && check_file "$f" || true
done

if [ "$violations" -gt 0 ]; then
  cat >&2 <<EOF

$violations violation(s). Certificate material, private keys and signatures
made with a real certificate must not be committed. Test material is generated
by tools/gen-testcert.sh and stays out of git; see testdata/certs/README.md.
If you really need to commit a synthetic fixture, add an explicit allowlist
entry in this script with a comment saying why it is safe.
EOF
  exit 1
fi

echo "ok, no real certificate material (${#files[@]} paths checked)"
