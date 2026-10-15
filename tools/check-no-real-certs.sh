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

check_file() {
  local f="$1"
  [ -e "$f" ] || return 0

  # A path we deliberately allow, checked before the extension rules.
  case "$f" in
    testdata/*/README.md|docs/*|*.md) return 0 ;;
  esac

  local base ext
  base="$(basename "$f")"
  ext="${base##*.}"
  if [ "$ext" = "$base" ]; then ext=""; fi

  if printf '%s' "$ext" | grep -qiE "^($BANNED_EXT)$"; then
    block "$f has a banned extension .$ext, certificate or key material does not belong in this repo"
    return 1
  fi
  if printf '%s' "$base" | grep -qiE "^($BANNED_NAMES)$"; then
    block "$f is a certificate or key store"
    return 1
  fi

  # Text level checks, cheap and they catch material pasted into a source
  # file, a fixture or a commit template.
  if grep -qE "$PEM_TRIGGER" "$f" 2>/dev/null; then
    block "$f contains a PEM private key or PKCS#7/PKCS#12 block"
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
  return 0
}

check_history() {
  # Every blob ever committed, so a leak cannot hide in an older revision.
  local seen=0
  while read -r sha; do
    seen=$((seen + 1))
    if git cat-file -p "$sha" 2>/dev/null | grep -qE "$PEM_TRIGGER"; then
      block "blob $sha in the git history contains key material"
    fi
  done < <(git rev-list --objects --all | awk '{print $1}' | sort -u | while read -r o; do
             git cat-file -t "$o" 2>/dev/null | grep -q '^blob$' && echo "$o"
           done)
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
