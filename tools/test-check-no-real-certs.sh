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

# Under `cargo test`, cli.rs passes its own CARGO_BIN_EXE here: that binary is
# guaranteed to be the one just compiled from this tree. Falling back to
# $ROOT/target/debug means whatever a previous build left behind — probes signed
# by a stale signer are not testing what you think they test.
if [ -n "${OPENFIRMA_GUARD_PROBE_BIN:-}" ] && [ -x "$OPENFIRMA_GUARD_PROBE_BIN" ]; then
  OF="$OPENFIRMA_GUARD_PROBE_BIN"
else
  if [ ! -x "$ROOT/target/debug/openfirma" ]; then
    echo "building openfirma for the probes…" >&2
    ( cd "$ROOT" && cargo build -q --bin openfirma )
  fi
  OF="$ROOT/target/debug/openfirma"
fi

printf 'guard probe content\n' > "$WORK/doc.txt"
[ -f "$WORK/doc.pdf" ] || python3 "$ROOT/tools/gen-testpdf.py" "$WORK/doc.pdf"
cp "$WORK/rogue.key" "$WORK/notes.md"        # the H-3 markdown-key probe

# sign <flags...> — run openfirma from the repo root so relative testdata works.
# `>/dev/null` on purpose for stdout only: an honest failure message (a missing
# input, a refused overwrite) is what distinguishes "the guard missed this shape"
# from "the probe never existed", and swallowing stderr hid exactly that in CI.
sign() { ( cd "$ROOT" && "$OF" sign --force >/dev/null "$@" ); }

# Sign every probe afresh, RIGHT NOW. The CI's macOS /var/folders purger evicts
# files whose mtime drifts — even open ones (run 39084111486: the guard read its
# own freshly-written probe as "no such file" seconds later and answered clean).
# Probes are small and seconds matter, so regenerate immediately before judging.
# re-sign a probe right now: $1 = input, $2 = format; output from $_RESIGN_OUT
resign() { rm -f "$_RESIGN_OUT"; sign -i "$1" -o "$_RESIGN_OUT" --format "$2" \
  --cert "$WORK/rogue.crt" --key "$WORK/rogue.key"; }

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
  shift 2
  # Any remaining arguments regenerate $path immediately before it is judged
  # (see resign above), passed positionally: first this probe's own path as
  # $_RESIGN_OUT, then whatever the rebuild helper needs. An argument scanner
  # that consumed "$path" instead of "resign" once re-signed into the INPUT —
  # positional here cannot repeat it.
  if [ "$#" -gt 0 ]; then
    _RESIGN_OUT="$path"
    "$@"
  fi
  if ! [ -s "$path" ]; then
    # The probe itself never landed (a signing failure the `sign` wrapper would
    # have printed, an unwritable temp): that is NOT a guard verdict, and
    # reporting it as one sends the investigation to the wrong file — CI run
    # 39081753322's "guard let XAdES through" on macOS was this shape.
    echo "FAIL: probe $path does not exist or is empty; the guard never saw a file" >&2
    fails=$((fails + 1))
    return
  fi
  local out status=0
  # capture without `if`: with pipefail set, the guard's normal BLOCK exit would
  # abort this very function under `set -e` if it arrived as a pipeline status
  # rather than through the if-condition (the shape CI's bash variant hit).
  out="$( cd "$ROOT" && ./tools/check-no-real-certs.sh "$path" 2>&1 )" || status=$?
  if [ "$status" -eq 0 ]; then
    echo "FAIL: guard let $why through ($path): the guard exited clean on a file it must block. Its output:" >&2
    printf '%s\n' "$out" | sed 's/^/        /' >&2
    # Five runs have blamed the guard on macOS with zero context about WHAT the
    # platform actually handed it (mime? grep -z? openssl DER?). Until the log
    # says, every hypothesis is cheap to hold; dump the whole witness chain for
    # the ONE probe that got through. Remove when this test is boring again.
    {
      echo "        --- witness ---"
      echo "        uname=$(uname -srm)"
      echo "        bash=${BASH_VERSION:-?} path=\$PATH"
      for t in grep base64 openssl file awk sed tr; do
        echo "        $t=$(command -v "$t") | $(command "$t" --version 2>&1 </dev/null | head -1)"
      done
      if [ -r "$path" ]; then
        echo "        size=$(wc -c <"$path") md5=$( (md5 -q "$path" 2>/dev/null || md5sum "$path" 2>/dev/null) | awk '{print $1}')"
        echo "        trigger-lines=$( { grep -ac 'SignatureValue\|X509Certificate\|BEGIN CERTIFICATE' "$path"; true; } )"
        # Witness the extractor's OWN channel, not grep's: a 400+-run probe
        # still showed first-run-len=0 after grep left the guard (witness run
        # 39088995737), so what matters is whether tr sees the file at all.
        # Run detection through awk's OWN record splitter — no tr, no pipes:
        # if the file holds base64 material in any form, this says so.
        N="$( { awk 'BEGIN{RS="[A-Za-z0-9+/=]+"} length >= 300 { print length; exit }' "$path" 2>/dev/null; true; } )"
        echo "        awk-rs-first-run=${N:-none}"
        # Same variable channel the guard's extractor uses. Run 39088314047→
        # 39089691658 each removed one layer of CI blindness; whatever this
        # line prints next is the answer we have not seen yet.
        data="$(cat "$path" 2>/dev/null; printf x)"; data="${data%$'\x'}"
        V="$( { printf '%s' "$data" | awk 'BEGIN{RS="[A-Za-z0-9+/=]+"} length >= 300 { print substr($0, 1, 8); exit }'; true; } )"
        echo "        var-first-run-head=${V:-none}"
      else
        echo "        unreadable-at-witness-time"
      fi
    } >&2 || true
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

must_block "CMS SignedData under a free extension" "$WORK/probe.bin" resign "$WORK/doc.txt" cades-b-b
must_block "the same CMS under a second free extension" "$WORK/probe.dat" cp "$WORK/probe.bin" "$WORK/probe.dat"
must_block "PAdES PDF with /Contents carrying a foreign CMS" "$WORK/probe-pdf.bin" resign "$WORK/doc.pdf" pades-b-b
must_block "XAdES XML with ds:SignatureValue + X509Certificate" "$WORK/probe-xml.bin" resign testdata/inputs/simple.xml xades-b-b
must_block "PEM private key saved as markdown" "$WORK/notes.md"
must_block "bare certificate renamed .bin" "$WORK/rogue-cert.bin"
# The BSD-Grep witness shape (run 39088314047, first-run-len=0): a whole DER
# certificate as ONE unbroken base64 run, with no PEM header and no XML tag
# to name it. On the CI's macOS the old grep-interval extractor extracted
# nothing from exactly this file and certified it clean. Line-wrapped PEM
# passes because the BEGIN header trips the keyword branch; here there is no
# header at all — only length and content can catch it, so they must.
python3 -c 'import base64,sys; sys.stdout.write(base64.b64encode(open("'"$WORK"'/rogue.crt","rb").read()).decode())' \
  > "$WORK/rogue-singleline.dat" 2>/dev/null || \
  { base64 -w0 "$WORK/rogue.crt" > "$WORK/rogue-singleline.dat" 2>/dev/null || \
    base64 "$WORK/rogue.crt" | tr -d '\n' > "$WORK/rogue-singleline.dat"; }
must_block "certificate as one raw base64 run, no header, no keyword (the BSD grep witness shape)" \
  "$WORK/rogue-singleline.dat" cp "$WORK/rogue.crt" "$WORK/rogue-singleline.dat"

# The macOS pkcs7-branch shape (runs 39088995737/39089691658): openfirma's
# XAdES is a text file that also PARSES as a DER ContentInfo under Homebrew
# openssl — it took the raw-CMS branch, printed no certificates there, and
# passed while its ds:X509Certificate run sat unread. The tripwire now asks
# "any long base64 here?" with byte arithmetic before trusting either answer;
# this probe reproduces the exact container end to end (it is literally the
# file the CI probe was).
must_block "XAdES whose bytes also parse as a DER ContentInfo (the macOS pkcs7-branch shape)" \
  "$WORK/probe-xades-en.bin" resign testdata/inputs/simple.xml xades-b-b

sign -i testdata/inputs/simple.xml -o "$WORK/synth-ok.xml" --format xades-b-b \
  --cert "$WORK/syn.crt" --key "$WORK/syn.key"
must_pass "synthetic-marker XAdES through the same double-parse branch" "$WORK/synth-ok.xml"
sign -i "$WORK/doc.pdf" -o "$WORK/synth-ok.bin" --format pades-b-b \
  --cert "$WORK/syn.crt" --key "$WORK/syn.key"
must_pass "synthetic-marker PAdES PDF (the marker is the rule, not paranoia)" "$WORK/synth-ok.bin"
must_pass "plain text file" "$WORK/doc.txt"
# Locale trap (measured on the review box): a UTF-8 doc whose multibyte excess
# over ASCII is ≥2 bytes used to fail read_whole_file's byte equation — the
# guard saw a character-count deficit, believed bash had hidden bytes, and
# blocked its OWN documentation as binary. The guard counts in C now; this
# control fails the moment that currency drifts back to the host locale.
printf 'p\xc3\xa9rdida de firma a\xc3\xb1adida: se perdi\xc3\xb3 la sesi\xc3\xb3n del usuario.\n' \
  > "$WORK/utf8-notes.md"
must_pass "markdown with UTF-8 accents (byte-currency read)" "$WORK/utf8-notes.md"
# Same trap, binary side: a NUL whose byte AND record fuse can only be caught
# by the deficit equation (AB\0CD + LF is ONE record; its two lost bytes land
# nowhere near any line count). A guard that blesses this as text certifies an
# unseen tail clean — precisely what HAS_NUL exists to refuse.
printf 'AB\0CD\n' > "$WORK/tiny-nul.bin"
# A lone NUL hides ≤2 bytes from bash's strings; the deficit equation sees it,
# so this file passes as accounted-for text (nothing was blocked on it in any
# revision — what matters is that no shape around it crashes or mis-blesses).
must_pass "NUL between newlines stays handled (deficit check, no crash)" "$WORK/tiny-nul.bin"
# a markdown copy of a benign script passes the content rules too: docs stay
# writable as long as they carry no key.
cp "$ROOT/tools/check-no-real-certs.sh" "$WORK/guard-notes.md"
must_pass "markdown with prose (docs are not exempt, just clean)" "$WORK/guard-notes.md"

# Round 2's N-1, probe 1: a document signed TWICE — first with the synthetic
# marker, then with a foreign certificate. `pdf_certs_pem` read only the first
# /Contents, so the second signer, the one a real leak would ride on, was never
# looked at; every /Contents is judged now. The control below (two synthetic
# signatures on the same file) is what keeps this from being "co-signature
# phobia": a document signed twice is judged by what its signatures contain.
sign -i "$WORK/doc.pdf" -o "$WORK/cosign-base.pdf" --format pades-b-b \
  --cert "$WORK/syn.crt" --key "$WORK/syn.key"
rebuild_cosigned() {
  rm -f "$WORK/probe-cosigned.pdf"
  sign -i "$WORK/cosign-base.pdf" -o "$WORK/probe-cosigned.pdf" --format pades-b-b \
    --cert "$WORK/rogue.crt" --key "$WORK/rogue.key"
}
must_block "PAdES PDF co-signed with a foreign certificate (the second /Contents)" \
  "$WORK/probe-cosigned.pdf" rebuild_cosigned
sign -i "$WORK/cosign-base.pdf" -o "$WORK/cosign-ok.pdf" --format pades-b-b \
  --cert "$WORK/syn.crt" --key "$WORK/syn.key"
must_pass "PAdES PDF co-signed twice with the synthetic marker" "$WORK/cosign-ok.pdf"

# Round 2's N-1, probe 2: a PEM bundle whose first block is synthetic and whose
# second is foreign. `openssl x509 -in file` reads ONE block and stops, and the
# old loop returned as soon as that block parsed — the foreign one was never
# opened. Every block in a file is split out and asked now. The all-synthetic
# bundle is the control that proves the rule is the marker, not bundling.
cat "$WORK/syn.crt" "$WORK/rogue.crt" > "$WORK/bundle-mixed.md"
must_block "PEM bundle: a synthetic certificate followed by a foreign one" "$WORK/bundle-mixed.md"
cat "$WORK/syn.crt" "$WORK/syn.crt" > "$WORK/bundle-synth.md"
must_pass "PEM bundle of two synthetic certificates" "$WORK/bundle-synth.md"

# Round 2's N-1, probe 3: both halves of the marker rule, one certificate each.
# Free extensions on purpose (.bin): a .crt name is itself a banned extension,
# and a probe that blocks on the name never reaches the rule it is testing.
# A marked subject over an unmarked issuer, and an unmarked (real-looking)
# subject over a marked issuer — the second is the shape the review built and
# read as a pass. Both are refused; a synthetic leaf of the test PKI's own
# making still passes, which is the point of requiring the pair.
openssl req -new -newkey rsa:2048 -nodes -keyout "$WORK/marked.key" \
  -out "$WORK/marked.csr" -subj "/CN=openfirma Test Probe/serialNumber=IDCES-12345678Z" 2>/dev/null
openssl x509 -req -in "$WORK/marked.csr" -CA "$WORK/rogue.crt" -CAkey "$WORK/rogue.key" \
  -CAcreateserial -out "$WORK/marked-subject.bin" -days 1 2>/dev/null
must_block "a certificate naming the test PKI in its subject, issued by a CA that does not" \
  "$WORK/marked-subject.bin"
openssl req -new -newkey rsa:2048 -nodes -keyout "$WORK/leaf.key" \
  -out "$WORK/leaf.csr" -subj "/CN=DE TAL FULANO/serialNumber=99999999R" 2>/dev/null
openssl x509 -req -in "$WORK/leaf.csr" -CA "$WORK/syn.crt" -CAkey "$WORK/syn.key" \
  -CAcreateserial -out "$WORK/leaf-real-name.bin" -days 1 2>/dev/null
must_block "a leaf with a real-looking identity issued by a marked test CA (round 2's N-1 probe)" \
  "$WORK/leaf-real-name.bin"
openssl req -new -newkey rsa:2048 -nodes -keyout "$WORK/good.key" \
  -out "$WORK/good.csr" -subj "/O=openfirma test/CN=PEREZ GARCIA, ANA" 2>/dev/null
openssl x509 -req -in "$WORK/good.csr" -CA "$WORK/syn.crt" -CAkey "$WORK/syn.key" \
  -CAcreateserial -out "$WORK/good-leaf.bin" -days 1 2>/dev/null
must_pass "a leaf whose subject and issuer both carry the marker" "$WORK/good-leaf.bin"
# and the same leaf shape as a PAdES signature, so the marker rule in the
# CHUNK path (one chunk per certificate out of a CMS) is pinned too, subject
# half and issuer half alike
sign -i "$WORK/doc.pdf" -o "$WORK/leaf-real-name.pdf" --format pades-b-b \
  --cert "$WORK/leaf-real-name.bin" --key "$WORK/leaf.key"
must_block "PAdES signed with a real-looking identity over a marked issuer" \
  "$WORK/leaf-real-name.pdf"

# Round 2's N-1, probe 4: the extension rule is a rule about PATHS, and
# `--history` reads blobs out of the object store where the path is gone. A
# `.p12` committed and then deleted had no extension for the rule to see, so it
# walked past clean. The guard now applies the path rule to the path `git
# rev-list --objects` prints beside each blob. The temp repo carries this
# script, so the probe runs the guard that is in this tree.
hist="$WORK/history-repo"
mkdir -p "$hist/tools"
cp "$ROOT/tools/check-no-real-certs.sh" "$hist/tools/"
printf 'only ever a path with a banned extension\n' > "$hist/secret.p12"
(
  cd "$hist"
  git init -q
  git -c user.email=guard@example.invalid -c user.name=guard add -A
  git -c user.email=guard@example.invalid -c user.name=guard commit -qm add
  git rm -q secret.p12
  git -c user.email=guard@example.invalid -c user.name=guard commit -qm remove
) >/dev/null 2>&1
hist_status=0
( cd "$hist" && ./tools/check-no-real-certs.sh --history >/dev/null 2>&1 ) || hist_status=1
if [ "$hist_status" = 0 ]; then
  echo "FAIL: guard let a .p12 that exists only in history through: a blob has no extension, and the rule is about the path it had" >&2
  fails=$((fails + 1))
else
  echo "ok, blocked: a .p12 deleted from the tree, found in --history by its path"
fi

if [ "$fails" -gt 0 ]; then
  echo "$fails guard self-test failure(s)" >&2
  exit 1
fi
echo "guard self-test: every leak shape blocked, every control allowed"
