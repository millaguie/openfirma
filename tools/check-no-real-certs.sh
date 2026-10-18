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
# The base64 certificate candidates of a text file, as "subject=/issuer=…
# ### cert" blocks. tr splits every non-base64 byte into a line break — no
# grep interval semantics (BSD caps {m,n}, GNU truncates matches at n, BSD
# read drops newline-less tails) survives between the file and this loop, and
# each run is small enough to feed openssl one printf at a time. Runs shorter
# than 300 chars cannot hold a real certificate's DER headers anyway; the DER
# reader, not the length guess, decides what is a certificate.
extract_base64_certs() {
  # $1 = file path. Candidates come from bash's OWN scanner over bash's own
  # read of the file (`|<prefix>` per line holding a ≥300-char run): tr/grep/
  # awk have each taken a turn being blind to probe files on CI (witness runs
  # 39088314047→39090607884), so no child gets the candidate decision and no
  # long payload crosses a pipe — BSD `read` splits records at 512 bytes, so
  # only ≤96-char prefixes travel. Each flagged line is identified by its
  # prefix (first-line-of-prefix match over bash's variable) and re-walked in
  # full from the SAME variable; every ≥300 run decodes through files, one
  # openssl at a time. Lines sharing a flag prefix that are NOT candidates
  # decode as nothing — cost: openssl attempts, never a missed candidate: a
  # line is only skipped if its exact 96-char head never appeared flagged,
  # and the scanner walks EVERY line, so no ≥300 run escapes.
  local f="$1" big td line rest tail w run prefix printed
  read_whole_file "$f" || { block "$f cannot be read whole; refusing to certify it clean"; return 1; }
  [ -n "$REPLY_DATA" ] || return 0
  if [ "$REPLY_TRUNC" = 1 ]; then
    # Past the cap: judge nothing from a cut-off variable; report material-
    # sized bytes honestly as unjudged and let callers keep their fail-closed
    # verdict (check_embedded_certs blocks truncation before calling this).
    return 0
  fi
  big="$(printf '%s\n' "$REPLY_DATA" | _scan_line_stream)" || big=""
  [ -n "$big" ] || return 0
  td="$(mktemp -d)" || return 0
  : > "$td/runs"
  while IFS= read -r line || [ -n "$line" ]; do
    prefix="${line:0:96}"
    [ -n "$prefix" ] || continue
    case "$big" in
      *"|$prefix"*) : ;;                   # scanner saw a run on this head
      *) continue ;;
    esac
    # Same geometry as _line_has_run300: the per-run walk is confined to the
    # tail after the FIRST window (prefix-glob finds it backward, in C; the
    # slice is O(1)), so lines that merely LOOK flagged (an ELF's .rodata)
    # cost one scan, not an O(runs × length) chew. A prefix may flag several
    # candidate-looking lines: confirming takes the tail from the FIRST
    # matching line only when it qualifies; otherwise the exact 96-char head
    # belongs to a non-candidate and skipping is provably safe (the walk
    # below sees ≥300 runs on this line exactly when _line_has_run300 says so).
    if ! _line_has_run300 "$line"; then continue; fi
    tail="${line%%*[A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/]*}"
    tail="${line:${#tail}}"
    rest="$tail"
    while [ -n "$rest" ]; do
      w="${rest%%[!A-Za-z0-9+/]*}"
      if [ "${#w}" -ge 300 ]; then printf '%s\n' "$w" >> "$td/runs"; fi
      rest="${rest#"$w"}"
      [ -n "$rest" ] || break
      rest="${rest#?}"
    done
  done <<EOF2
$REPLY_DATA
EOF2
  [ -s "$td/runs" ] || { rm -rf "$td"; return 0; }
  while IFS= read -r run || [ -n "$run" ]; do
    printf '%s' "$run" > "$td/run.b64"
    base64 -d < "$td/run.b64" > "$td/run.der" 2>/dev/null || rm -f "$td/run.der"
    if [ -s "$td/run.der" ] &&
       openssl x509 -inform DER -in "$td/run.der" -noout -subject -issuer 2>/dev/null; then
      echo "### cert"
    elif openssl x509 -inform PEM -in "$td/run.b64" -noout -subject -issuer 2>/dev/null; then
      echo "### cert"
    fi
    rm -f "$td/run.der"
  done < "$td/runs"
  rm -rf "$td"
}


# Scanner protocol (v3, the witness chain's end state): detection answers must
# be SHORT messages over a pipe (long payloads chop on BSD), so _scan_line_stream
# reports `|<line-prefix>` for every line containing a ≥24-char base64 window —
# prefixes up to 100 chars are safe across any pipe chunking — and extract uses
# that flag set only as a FILTER over lines it re-reads itself (never trusting
# a relayed long payload). A line flagged but containing no ≥300 run costs one
# extra walk and no openssl call; a line NOT flagged provably has no window, so
# no run. Detection never needs the full line: `|` + ≤100-char prefix is enough
# for the tripwire's opening check too (24 base64 chars = 18 decoded bytes).

# Whether any base64 run of $1 decodes as an X.509 certificate at all, with
# no synthetic PKI in sight — the raw-CMS branch asks this after openssl's
# pkcs7 parser took a bite. Run detection is byte arithmetic in awk (split on
# non-alphabet bytes, measure): zero child processes touching the file, so no
# tr/base64 dialect gets a vote. A single false from either probe once leaked
# a full XAdES through this branch on macOS (runs 39088995737/39089691658);
# it now answers from bytes and fails closed when the answer is no.
cms_hides_foreign_certs() {
  local f="$1" data runs
  read_whole_file "$f" || return 1
  if [ "$REPLY_HAS_NUL" = 1 ]; then
    # Binary: the text scan cannot claim completeness, but a file whose bytes
    # are DER had no business printing nothing — trust nothing, ask extract.
    runs="run binary"
  else
    data="$REPLY_DATA"
    runs="$(printf '%s\n' "$data" | _scan_line_stream)" || runs=""
  fi
  [ -n "$runs" ] || return 1
  ! extract_base64_certs "$f" | grep -q '### cert'
}

# Whole-file read with bash's OWN `read` builtin — no child is handed the
# path at all, because witness runs 39088314047→39089691658 each caught one
# child channel (BSD grep intervals, `tr`, `cat |`, even awk) answering that
# a probe file was EMPTY while other channels measured it whole. Text passes
# as-is; a binary file loses NUL bytes to bash's C-string variables and gets
# REPLY_HAS_NUL=1, which every shape/decoder judgement below respects. Files
# over the 4 MiB cap set REPLY_TRUNC — no scan past the cut may certify clean.
read_whole_file() {
  # $1 = path; result in REPLY_DATA (+REPLY_TRUNC / REPLY_HAS_NUL). Binary
  # files are PROBED (first bytes for a NUL) and then not walked at all: bash
  # strings stop at the first NUL no matter who fills them, so there is no
  # honest whole-variable read to be had — HAS_NUL says "lossy channel" and
  # every text-level decision declines for such files. The line loop only
  # ever sees byte sequences that contained no NUL in the probe window; a
  # NUL hidden deeper than the probe costs exactly one flagged-and-refused
  # line (loop below), never an O(length) chew like the lossy `read -d ''`
  # append loop paid over a 438 KiB ELF (rust_out, 11s/file).
  local cap=4194304 size nul line stripped
  REPLY_DATA=""; REPLY_TRUNC=0; REPLY_HAS_NUL=0
  [ -f "$1" ] || return 1
  size=$(wc -c < "$1" 2>/dev/null) || return 1
  size="${size//[^0-9]/}"
  [ -n "$size" ] || return 1
  if [ "$size" -gt "$cap" ]; then REPLY_TRUNC=1; return 0; fi
  # NUL count over the whole file, byte arithmetic: `tr -d '\0'` deletes only
  # bytes that ARE NUL and writes every other byte through (no dialect, no
  # line semantics), so deleted-bytes = size − survivors proves binary. The
  # equation is exact even when a pipe truncates both measurements the same
  # way; `wc` pads with spaces per BSD, hence the digit-strip. A file whose
  # NULs hide deeper than any head window still lands here (full-file tr),
  # and nothing may key on grep's "binary file matches" answer instead — it
  # fires for ANY pattern once a NUL is present.
  nul=$(tr -dc '\0' < "$1" 2>/dev/null | LC_ALL=C wc -c) || nul=""
  nul="${nul//[^0-9]/}"
  if [ -z "$nul" ] && [ "$size" -gt 0 ]; then
    REPLY_HAS_NUL=1                            # unreadable is never clean
    return 0
  fi
  if [ "${nul:-0}" != 0 ]; then
    REPLY_HAS_NUL=1                            # binary: the scan declines, honestly
    return 0
  fi
  # Byte accounting: bash ${#var} counts CHARACTERS, not bytes (a UTF-8 é is
  # one char, two bytes), so the size equation must count the same currency.
  # LC_ALL=C makes every byte one character — base64, DER and PEM payloads are
  # ASCII anyway, and any other locale would only disguise a NUL's worth of
  # loss as accented prose. Bytes-after-first-NUL remain invisible to `read`
  # (C strings); that is what the equation catches, marking the channel
  # lossy rather than certifying it clean.
  while IFS= read -r line || [ -n "$line" ]; do
    REPLY_DATA+="$line"$'\n'
    if [ "${#REPLY_DATA}" -gt "$cap" ]; then REPLY_TRUNC=1; break; fi
  done < "$1"
  stripped="$REPLY_DATA"
  # ${#var} counts CHARACTERS: measure the payload in BYTES with C-locale
  # wc (one byte = one character there), the same currency as `size`. A
  # payload shorter than stat by more than read()'s known final-newline loss
  # had bytes no bash string can hold (post-NUL, deeper than the probe), so
  # it reports lossy rather than certifying an unseen tail as clean.
  stripped=$(printf '%s' "$stripped" | LC_ALL=C wc -c)
  stripped="${stripped//[^0-9]/}"
  case "$stripped" in
    "$size"|"$(( size - 1 ))") return 0 ;;
  esac
  REPLY_HAS_NUL=1
  return 0
}

_line_has_run300() {
  # $1 = one line. True iff it holds a ≥300-char [A-Za-z0-9+/] run, with NO
  # per-run work at all: `${line%%*<32-window>*}` is one backward glob scan
  # that ends AT the window (C-speed), `${line:0:$len}` is O(1) pointer
  # arithmetic, and only the tail of the line — after the first window —
  # ever walks per run. The old forward walk (`${rest%%[!class]*}` + drop)
  # looked like whole-run steps but each drop copied the remainder: an
  # ELF's .rodata line (78 KiB, longest run 66 chars, 5k runs) cost it 11s.
  local tail cut
  case "$1" in
    *[A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/]*)
      : ;;
    *) return 1 ;;                               # provably no run ≥32
  esac
  tail="${1%%*[A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/]*}"
  tail="${1:${#tail}}"                           # from the FIRST window on: O(1) slice
  while [ -n "$tail" ]; do
    cut="${tail%%[!A-Za-z0-9+/]*}"
    if [ "${#cut}" -ge 300 ]; then return 0; fi
    tail="${tail#"$cut"}"
    [ -n "$tail" ] || return 1
    tail="${tail#?}"                             # step past ONE delimiter
  done
  return 1
}

# Reader-agnostic candidate scan over bash's own variable read (see below):
# lines split runs exactly how PEM/XAdES wrap material in practice, and any
# line holding a ≥300-char run reports its first 96 chars as `|<prefix>`.
# awk RS, grep intervals and `tr` have each taken a turn being blind or lossy
# here (runs 39088314047/39088995737: BSD grep said "no run" for a 1130-char
# certificate), so no child gets this decision.
_scan_line_stream() {
  # Emits `|<first 96 chars>` for every line that holds a ≥300-char base64
  # run, one line at a time from bash's own printf (the guard's variable-read
  # protocol: no child touches the probe path — witness runs). All judging
  # work lives in _line_has_run300 so scan, wire and extractor cannot
  # disagree on what a candidate is. Prefixes ≤96 chars cross pipes whole
  # (BSD `read` splits records at 512), so flagged lines stay identifiable by
  # head; candidates are re-walked from bash's own bytes — relayed prefixes
  # are filters, never the judged data.
  local line
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in '') continue ;; esac
    _line_has_run300 "$line" && printf '|%s\n' "${line:0:96}"
  done
}



# A 300+-character base64 run that OPENS like X.509 material (MII…/LS0t…) but
# decodes to no certificate anywhere, measured from the same variable channel
# the extractors use: either this machine's readers are lying or the material
# was fragmented to dodge them. Refuse to certify such a file clean — prose
# never carries MII… runs, so docs stay untouched. Same scanner as the
# candidate rule above (they must not disagree), and its prefix test is one
# builtin case per run.
x509_shaped_but_undecodable() {
  local data line tail cut out nul=0
  read_whole_file "$1" || return 1
  if [ "$REPLY_HAS_NUL" = 1 ]; then
    # The variable channel is lossy (binary), but the FILE still answers for
    # itself: a whole-file grep either finds an X.509-opening window at all
    # (nothing shaped) or proves one exists whose decode came up empty (the
    # contradiction). run 39089691658 is exactly this shape; declining here
    # was a fail-open in wire form.
    LC_ALL=C grep -qE 'MII[A-Za-z0-9+/]{300}|MIE[A-Za-z0-9+/]{300}|LS0t[A-Za-z0-9+/]{300}' "$1" 2>/dev/null || nul=1
    [ "$nul" = 1 ] && return 1
    return 0
  fi
  data="$REPLY_DATA"
  # Same scanner geometry as the candidate rule (they must not disagree): for
  # each line holding a ≥300-char run, test the first eight characters of any
  # such run. X.509 DER opens MII/MIE…, PEM banners open "-----" = LS0t in
  # base64; prose never carries those openings. The walk mirrors
  # _scan_line_stream exactly (one window prefilter, then prefix-glob runs
  # confined to the tail after the first window) so no line ever qualifies
  # for one rule and not the other.
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in '') continue ;; esac
    case "$line" in
      *[A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/]*)
        : ;;
      *) continue ;;                                # provably no run ≥32
    esac
    tail="${line%%*[A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/]*}"
    tail="${line:${#tail}}"                         # from the first window on
    out=""
    while [ -n "$tail" ]; do
      cut="${tail%%[!A-Za-z0-9+/]*}"
      if [ "${#cut}" -ge 300 ]; then out="${cut:0:8}"; break; fi
      tail="${tail#"$cut"}"
      [ -n "$tail" ] || break
      tail="${tail#?}"
    done
    case "$out" in MII*|MIE*|LS0t*) return 0 ;; esac
  done <<EOF2
$data
EOF2
  return 1
}

check_embedded_certs() {
  local f="$1" blocks="" part tmpblocks tail names_cert=0
  # Branch decisions come from file CONTENT and openssl only — magic bytes,
  # greps that match anywhere in the file, one DER parse. Nothing else gets a
  # veto: `file`'s guesses, grep's line handling, `-z`, brace-interval caps,
  # locale-dependent classes and awk dialects have each produced a fail-open
  # here on the CI's macOS within one review (H-3's fix was "content first" for
  # exactly this reason). The text candidate extractor is deliberately dumb:
  # `tr -c alphabet \n` turns every non-base64 byte into a line break, so runs
  # come out whole in any dialect, and each run gets one openssl attempt.
  if head -c 5 "$f" | grep -qa '%PDF-'; then
    # PAdES: the /Contents hex string IS a CMS SignedData (possibly zero
    # padded); its DER prefix ends where the outer SEQUENCE says it does.
    blocks="$(pdf_certs_pem "$f")" || blocks=""
    if [ -z "$blocks" ] && x509_shaped_but_undecodable "$f"; then
      block "$f is a PDF carrying base64 that opens exactly like X.509 material which no decoder on this machine can read — refusing to call it clean"
      return 1
    fi
  elif openssl pkcs7 -inform DER -in "$f" -noout 2>/dev/null; then
    # A raw CMS SignedData blob (CAdES detached/encapsulated): every one of
    # them embeds its certificates, so a parsable PKCS#7 always produces
    # blocks below — an empty parse result is the decoder failing on us, not
    # an absence of material.
    # same chunking as the PDF path, so a chain of several certificates is
    # judged one certificate at a time and not as one blob whose marker in
    # any line would hide a foreign leaf.
    blocks="$(openssl pkcs7 -print_certs -inform DER -in "$f" 2>/dev/null |
      awk '/^-+BEGIN/{print "### cert"; skip=1; next} /^-+END/{skip=0; next} skip{next} {print}')" || blocks=""
    if [ -z "$blocks" ] && cms_hides_foreign_certs "$f"; then
      # openssl parsed this as a PKCS#7 and printed no certificates, while
      # the file carries 300+ base64 runs that no reader resolves to the
      # synthetic PKI. Our XAdES is exactly this shape (the DER IS a parsable
      # ContentInfo under some Homebrew openssl builds), so "no certs" here
      # cannot be trusted as absence — refuse instead of passing (runs
      # 39088995737/39089691658 let one through).
      block "$f parses as a PKCS#7 whose certificates no reader on this machine can print while carrying unresolvable base64 material — refusing to certify it clean"
      return 1
    fi
  else
    # Candidate scan: does this file hold ANY long base64 run (300+ chars, so
    # big enough to be a certificate) or name a certificate at all? Written as
    # builtin prefix-glob walks over bash's own variable read (_scan_line_stream)
    # — on the CI's macOS, grep intervals AND `tr | awk` answered this very
    # question with silence for a 1130-char single-line certificate (witness
    # runs 39088314047/39088995737: first-run-len=0), and a false here is a
    # fail-open. Same scanner feeds the tripwire below, so scan and wire cannot
    # disagree; if the scan sees material and no decoder reads it, the wire
    # blocks. If nothing even looks like material and nothing names one, return
    # early — a prose "X509Certificate" mention still enters below through the
    # bash keyword test.
    local data runs
    read_whole_file "$f" || { block "$f cannot be read whole; refusing to certify it clean"; return 1; }
    if [ "$REPLY_TRUNC" = 1 ]; then
      # Past the cap no scan here can claim completeness ("nothing long enough"
      # may sit beyond the cut); a repo file of >4 MiB is not documentation and
      # not a fixture anyone has explained, so it stays blocked until someone
      # does. Nothing real this guard must bless comes close to that size.
      block "$f is larger than the guard reads (4 MiB) — too big to certify clean"
      return 1
    fi
    data="$REPLY_DATA"
    case "$data" in
      *SignatureValue*|*X509Certificate*|*'BEGIN CERTIFICATE'*) names_cert=1 ;;
    esac
    if [ "$REPLY_HAS_NUL" = 1 ]; then
      # Binary file, so the keyword case above never ran (data is empty). The
      # file answers for itself through grep -a instead: same three keywords,
      # byte semantics, no line-shape assumptions.
      if LC_ALL=C grep -qa -e SignatureValue -e X509Certificate -e 'BEGIN CERTIFICATE' "$f" 2>/dev/null; then
        names_cert=1
      fi
      # The text scan cannot claim completeness, so it enters the extractor
      # (which reads the FILE, not the variable) — and only cert keywords
      # make a no-decode outcome fatal below.
      runs="run binary"
    else
      runs="$(printf '%s\n' "$data" | _scan_line_stream)" || runs=""
    fi
    if [ "$names_cert" = 0 ] && [ -z "$runs" ]; then
      return 0
    fi
    blocks="$(extract_base64_certs "$f")" || blocks=""
    if [ -z "$blocks" ]; then
      # Long base64 is present (or a certificate is NAMED) and nothing in it
      # decoded. A docs page with no material produces nothing — clean, but
      # only when bash read the text WHOLE (REPLY_HAS_NUL: a binary file's
      # lossy variable must not feed a shape verdict; its bytes were already
      # judged by openssl over the file above) AND no run opens like X.509
      # material (MII…/LS0t…): that combination means this machine's readers
      # are lying, so refuse to certify the contradiction as clean. Runs with
      # NULs and a named certificate also block: the text pass cannot see the
      # file and no decoder printed a certificate either — nothing certifies
      # it clean (that is how run 39089691658 passed).
      tail="$(printf '%s\n' "$runs" | head -1)" || tail=""
      tail="${tail#|}"
      # A flagged line whose head starts with certificate material and no
      # decoder printed anything is the contradiction (the old scanner printed
      # run-heads directly; the v3 protocol flags by line prefix, so the head
      # test lives on the prefix — X.509 base64 always STARTS a line inside a
      # PEM/XAdES tag, which is exactly what the macOS XAdES showed).
      case "$tail" in
        MII*|MIE*|LS0t*)
          block "$f names a certificate and carries ${#tail}-char+ flagged base64 opening exactly like X.509 material, yet no decoder read it — refusing to call material I cannot fully inspect clean"
          return 1 ;;
      esac
      # HAS_NUL here means bytes bash could not hold at all (a NUL's tail),
      # never encoding noise — read_whole_file counts bytes in the C locale.
      if [ "$REPLY_HAS_NUL" = 1 ] && [ "$names_cert" = 1 ]; then
        block "$f is binary, names certificates, and no decoder printed one — refusing to certify it clean"
        return 1
      fi
      # Second opinion from the same bash scanner over a fresh read (the scan
      # above may have hit the cap or a lost-NUL text; this one re-reads and
      # re-measures, and a false "no runs" on a file that NAMED a certificate
      # is precisely how run 39089691658 passed).
      if x509_shaped_but_undecodable "$f"; then
        block "$f names a certificate and carries base64 opening exactly like X.509 material (bash's own scanner) which no decoder read — refusing to call it clean"
        return 1
      fi
      return 0
    fi
  fi
  # One certificate per chunk: openssl -noout prints its "subject=…\nissuer=…"
  # lines, terminated by the "### cert" marker each decoder emits. Every
  # chunk must mention the synthetic PKI on both of its lines — a real leaf
  # issued BY a test CA is still somebody's identity and fails the rule.
  # PipedReader input, never <<<: a here-string word before awk can be eaten
  # as an assignment in some shells, and awk must not expand a redirect path
  # out of DATA at all (a crafted "### cert" chunk would rewrite files).
  tmpblocks="$(mktemp -d)"
  printf '%s\n' "$blocks" | awk -v dir="$tmpblocks" '
    function out(i) { return dir "/" i ".part" }
    /^### cert$/ { idx++; next }
    /^(subject|issuer)=/ { if (!idx) idx = 1; print >> out(idx); next }
  '
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
  # `test -e` passing and every reader below then answering "no such file" is
  # not a contradiction on macOS: /var/folders (the default TMPDIR, where the
  # self-test's probes live) is periodically purged of files whose *mtime*
  # looks old — even while open. The probe generator now regenerates every run
  # for that reason (tools/test-check-no-real-certs.sh), and a file that vanishes
  # mid-scan is reported, not let through: fail closed, like everything else here.
  if [ ! -r "$f" ]; then
    block "$f cannot be read; the guard cannot certify what it cannot see"
    return 1
  fi

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
