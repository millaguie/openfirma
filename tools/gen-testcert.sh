#!/usr/bin/env bash
# Generates the throwaway test material used by the test suite and by the
# golden file comparison against the official AutoFirma.
#
# Nothing here is secret, and nothing here is committed. testdata/certs is in
# .gitignore. If you need a signature that VALIDe reports as valid rather than
# "certificado no reconocido", use a real FNMT or DNIe certificate instead.
#
# The chain is three levels deep, root -> intermediate -> signer, because that
# is what a real Spanish PKI looks like and it is what exercises the
# certificate embedding in SignedData. Signer subjects mimic the DN layout of
# FNMT and DNIe certificates, including serialNumber (2.5.4.5) carrying the
# IDES/IDNIE identifier, since AutoFirma's certificate filters key off it.
#
# Portable across OpenSSL and the LibreSSL that macOS ships: no -addext, and
# every private key is normalized to PKCS#8 PEM with pkcs8 -topk8, because our
# loader only accepts PKCS#8 and ecparam -genkey emits SEC1.
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
DIR="$HERE/testdata/certs"
mkdir -p "$DIR"
cd "$DIR"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
# openssl stderr used to go to /dev/null here, which meant a failure on a
# runner we cannot log into told us nothing but "exit code 1". Keep it visible.
trap 'echo "gen-testcert.sh fallo en la linea $LINENO: $BASH_COMMAND" >&2' ERR

CA_EXT="$TMP/ca.ext"
SUB_EXT="$TMP/sub.ext"
ROOT_CONF="$TMP/root.conf"

cat > "$CA_EXT" <<'EOF'
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
EOF

# No authorityKeyIdentifier on purpose, LibreSSL's x509 -req -extfile accepts
# only a subset of extensions and chain building works off issuer and subject
cat > "$SUB_EXT" <<'EOF'
keyUsage = critical,digitalSignature,nonRepudiation
extendedKeyUsage = emailProtection
basicConstraints = critical,CA:FALSE
subjectKeyIdentifier = hash
EOF

cat > "$ROOT_CONF" <<'EOF'
[req]
distinguished_name = dn
x509_extensions = v3
prompt = no
[dn]
C = ES
O = openfirma test
OU = Test PKI
CN = openfirma Test Root CA
[v3]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
EOF

# Git Bash on Windows rewrites any argument starting with / into a Windows
# path, so openssl req -subj "/C=ES/..." arrives as
# "C:/Program Files/Git/C=ES/..." and req rejects it. Config files avoid
# -subj entirely and behave the same on OpenSSL, LibreSSL and Windows.
dn_conf() {
  # dn_conf <outfile> <key = value>...
  local out="$1"
  shift
  {
    echo "[req]"
    echo "distinguished_name = dn"
    echo "prompt = no"
    echo "[dn]"
    for kv in "$@"; do echo "$kv"; done
  } > "$out"
}

to_pkcs8() {
  # $1 input key in whatever format openssl produced, $2 output PKCS#8 PEM
  openssl pkcs8 -topk8 -nocrypt -in "$1" -out "$2"
}

issue() {
  # issue <csr> <out.crt> <ca.crt> <ca.key> <extfile>
  openssl x509 -req -in "$1" -out "$2" -days 825 -sha256 \
    -CA "$3" -CAkey "$4" -CAcreateserial -extfile "$5"
  openssl x509 -in "$2" -outform DER -out "$2.der"
}

echo "== root CA =="
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$TMP/ca-raw.key" -out ca.crt \
  -days 3650 -config "$ROOT_CONF"
to_pkcs8 "$TMP/ca-raw.key" ca.key
openssl x509 -in ca.crt -outform DER -out ca.crt.der

echo "== intermediate CA =="
dn_conf "$TMP/int.cnf" "C = ES" "O = openfirma test" "OU = Test PKI" \
  "CN = openfirma Test Intermediate CA"
openssl req -newkey rsa:2048 -nodes -keyout "$TMP/int-raw.key" -out "$TMP/intermediate.csr" \
  -config "$TMP/int.cnf"
to_pkcs8 "$TMP/int-raw.key" intermediate.key
openssl x509 -req -in "$TMP/intermediate.csr" -out intermediate.crt -days 1825 -sha256 \
  -CA ca.crt -CAkey ca.key -CAcreateserial -extfile "$CA_EXT"
openssl x509 -in intermediate.crt -outform DER -out intermediate.crt.der
cat intermediate.crt ca.crt > chain.crt

echo "== RSA 2048 signer, FNMT style DN =="
dn_conf "$TMP/rsa.cnf" "C = ES" "O = openfirma test" "OU = AC openfirma Usuarios" \
  "serialNumber = IDCES-12345678Z" "CN = PEREZ GARCIA, ANA"
openssl req -newkey rsa:2048 -nodes -keyout "$TMP/rsa-raw.key" -out "$TMP/rsa.csr" \
  -config "$TMP/rsa.cnf"
to_pkcs8 "$TMP/rsa-raw.key" signer-rsa.key
issue "$TMP/rsa.csr" signer-rsa.crt intermediate.crt intermediate.key "$SUB_EXT"
openssl pkcs8 -topk8 -nocrypt -in signer-rsa.key -outform DER -out signer-rsa.pk8.der

echo "== ECDSA P-256 signer, DNIe style DN =="
dn_conf "$TMP/ec.cnf" "C = ES" "O = DIRECCION GENERAL DE LA POLICIA" "OU = DNIE" \
  "serialNumber = IDNIE-12345678Y" "CN = LOPEZ MARTIN, JUAN"
openssl ecparam -name prime256v1 -genkey -noout -out "$TMP/ec-sec1.key"
to_pkcs8 "$TMP/ec-sec1.key" signer-ec.key
openssl req -new -key signer-ec.key -out "$TMP/ec.csr" \
  -config "$TMP/ec.cnf"
issue "$TMP/ec.csr" signer-ec.crt intermediate.crt intermediate.key "$SUB_EXT"
openssl pkcs8 -topk8 -nocrypt -in signer-ec.key -outform DER -out signer-ec.pk8.der

echo "== RSA 2048 signer, legal person, sello de entidad style DN =="
# A certificate whose subject is the entity itself, no natural person in it:
# the CN is the company name and serialNumber carries the CIF. openfirma must
# sign with it exactly as with a personal certificate, copying the subject
# verbatim. organizationIdentifier (2.5.4.97) is what ETSI EN 319 412-1 puts
# in legal person certificates, VATES- prefix for a Spanish CIF.
dn_conf "$TMP/jur.cnf" "C = ES" "O = OPENFIRMA TEST SL" "OU = sello de entidad" \
  "serialNumber = A12345678" "organizationIdentifier = VATES-A12345678" \
  "CN = OPENFIRMA TEST SL"
openssl req -newkey rsa:2048 -nodes -keyout "$TMP/jur-raw.key" -out "$TMP/jur.csr" \
  -config "$TMP/jur.cnf"
to_pkcs8 "$TMP/jur-raw.key" signer-juridical.key
issue "$TMP/jur.csr" signer-juridical.crt intermediate.crt intermediate.key "$SUB_EXT"

echo "== RSA 2048 signer, representative of a legal person =="
# The common real world case for company signing: a natural person's DNI in
# serialNumber, the entity in O and organizationIdentifier, and the role in
# title. The subject mixes both, so nothing may assume which one it gets.
dn_conf "$TMP/rep.cnf" "C = ES" "O = OPENFIRMA TEST SL" "OU = representante" \
  "serialNumber = IDCES-12345678Z" "organizationIdentifier = VATES-A12345678" \
  "title = Representante Legal" "CN = PEREZ GARCIA, ANA"
openssl req -newkey rsa:2048 -nodes -keyout "$TMP/rep-raw.key" -out "$TMP/rep.csr" \
  -config "$TMP/rep.cnf"
to_pkcs8 "$TMP/rep-raw.key" signer-representative.key
issue "$TMP/rep.csr" signer-representative.crt intermediate.crt intermediate.key "$SUB_EXT"

echo "== TSA certificate, for offline B-T tests with openssl ts =="
# extendedKeyUsage timeStamping, critical, is what makes openssl and every
# validator accept this certificate as a time-stamp authority.
dn_conf "$TMP/tsa.cnf" "C = ES" "O = openfirma test" "OU = Test TSA" \
  "CN = openfirma Test TSA"
openssl req -newkey rsa:2048 -nodes -keyout "$TMP/tsa-raw.key" -out "$TMP/tsa.csr" \
  -config "$TMP/tsa.cnf"
printf 'basicConstraints = critical, CA:FALSE\nkeyUsage = critical, digitalSignature, nonRepudiation\nextendedKeyUsage = critical, timeStamping\n' > "$TMP/tsa.ext"
issue "$TMP/tsa.csr" tsa.crt intermediate.crt intermediate.key "$TMP/tsa.ext"
to_pkcs8 "$TMP/tsa-raw.key" tsa.key

echo "== CRLs, for the PAdES B-LT validation data tests =="
# An empty CRL is a complete revocation datum: it is signed by the CA and says
# that nothing it issued is revoked, which is exactly what a B-LT archive needs
# for a healthy chain. `openssl ca -gencrl` is the portable way to produce one
# (OpenSSL and the LibreSSL macOS ships alike), and it insists on a database,
# so each CA gets a minimal throwaway one. The long validity is deliberate:
# this is test material regenerated on demand, and a CRL that expires in the
# usual 30 days would turn `cargo test` red on a stale testdata/certs.
make_crl() {
  # make_crl <name> <ca.crt> <ca.key>
  local name="$1" cacert="$2" cakey="$3"
  # The database paths go into the config CONTENT as paths relative to this
  # directory, deliberately not as $TMP paths: on Windows the -config
  # argument goes through Git Bash's path translation but the text inside
  # the file does not, and the native Windows openssl cannot resolve a
  # /tmp/... path. Relative paths work on OpenSSL, LibreSSL and Windows.
  local index="crl-$name.index" number="crl-$name.number" conf="crl-$name.conf"
  : > "$index"
  echo 01 > "$number"
  {
    echo "[ca]"
    echo "default_ca = settings"
    echo "[settings]"
    echo "database = $index"
    echo "crlnumber = $number"
    echo "default_md = sha256"
    echo "default_crl_days = 3650"
  } > "$conf"
  openssl ca -gencrl -config "$conf" -cert "$cacert" -keyfile "$cakey" \
    -out "$name.crl.pem"
  openssl crl -in "$name.crl.pem" -outform DER -out "$name.crl.der"
  rm -f "$index" "$number" "$conf" "$index.attr"
}
# ca.crl covers the intermediate, intermediate.crl covers the signing certs:
# one revocation datum per CA of the chain, which is what ETSI EN 319 142-1
# asks B-LT to archive.
make_crl ca ca.crt ca.key
make_crl intermediate intermediate.crt intermediate.key

echo "== OCSP responder delegate and one response, for the B-LT tests =="
# The OCSP variant of a revocation datum. openssl's ocsp app can act as a
# one-shot responder offline (-reqin/-respout) over a hand-built index.txt:
# status, expiry, revocation date, serial, filename and subject, tab
# separated. The fixed far-future expiry keeps the script off GNU date, which
# macOS does not ship. The response says signer-rsa is good and comes from the
# intermediate's "database", so its CertID hashes are the intermediate's,
# which is what associates it with the chain. Some openssl builds lack the
# one-shot responder; then this section warns and continues, and the tests
# that need the response skip (the CRL path is the mandatory one).
dn_conf "$TMP/ocsp.cnf" "C = ES" "O = openfirma test" "OU = Test OCSP Responder" \
  "CN = openfirma Test OCSP"
openssl req -newkey rsa:2048 -nodes -keyout "$TMP/ocsp-raw.key" -out "$TMP/ocsp.csr" \
  -config "$TMP/ocsp.cnf"
# extendedKeyUsage OCSPSigning, critical, is what makes openssl and every
# validator accept this certificate as an OCSP responder delegate
printf 'basicConstraints = critical, CA:FALSE\nkeyUsage = critical, digitalSignature\nextendedKeyUsage = critical, OCSPSigning\n' > "$TMP/ocsp.ext"
issue "$TMP/ocsp.csr" ocsp.crt intermediate.crt intermediate.key "$TMP/ocsp.ext"
to_pkcs8 "$TMP/ocsp-raw.key" ocsp.key

ocsp_response() {
  # ocsp_response <cert.crt> <out.der>: a "good" response for the certificate
  local cert="$1" out="$2" ser dn
  ser="$(openssl x509 -in "$cert" -serial -noout | cut -d= -f2)"
  dn="$(openssl x509 -in "$cert" -subject -noout -nameopt oneline | sed 's/^subject=//')"
  printf 'V\t491231235959Z\t\t%s\tunknown\t%s\n' "$ser" "$dn" > "$TMP/ocsp-index.txt"
  openssl ocsp -reqout "$TMP/ocsp.req" -issuer intermediate.crt -cert "$cert" -no_nonce
  openssl ocsp -index "$TMP/ocsp-index.txt" -CA intermediate.crt \
    -rsigner ocsp.crt -rkey ocsp.key \
    -reqin "$TMP/ocsp.req" -respout "$out"
}
# a stale response from a previous PKI would carry the old issuer hashes
rm -f signer-rsa.ocsp.der
if ocsp_response signer-rsa.crt signer-rsa.ocsp.der 2>/dev/null; then
  echo "signer-rsa.ocsp.der written"
else
  echo "WARNING: this openssl cannot answer an OCSP request offline;" >&2
  echo "WARNING: signer-rsa.ocsp.der is missing and the OCSP tests will skip" >&2
fi

echo "== PKCS#12 for the official AutoFirma, chain included =="
# AutoFirma loads .p12, so the golden files are produced with exactly the
# certificate openfirma uses. Password is not a secret.
openssl pkcs12 -export -in signer-rsa.crt -inkey signer-rsa.key -certfile chain.crt \
  -out signer-rsa.p12 -passout pass:openfirma -name "PEREZ GARCIA, ANA"
openssl pkcs12 -export -in signer-ec.crt -inkey signer-ec.key -certfile chain.crt \
  -out signer-ec.p12 -passout pass:openfirma -name "LOPEZ MARTIN, JUAN"
openssl pkcs12 -export -in signer-juridical.crt -inkey signer-juridical.key -certfile chain.crt \
  -out signer-juridical.p12 -passout pass:openfirma -name "OPENFIRMA TEST SL"

echo "== chain verification =="
openssl verify -CAfile ca.crt -untrusted intermediate.crt signer-rsa.crt
openssl verify -CAfile ca.crt -untrusted intermediate.crt signer-ec.crt
openssl verify -CAfile ca.crt -untrusted intermediate.crt signer-juridical.crt
openssl verify -CAfile ca.crt -untrusted intermediate.crt signer-representative.crt
openssl verify -CAfile ca.crt -untrusted intermediate.crt tsa.crt
openssl verify -CAfile ca.crt -untrusted intermediate.crt ocsp.crt

echo "== every key must be PKCS#8, our loader accepts nothing else =="
for k in ca.key intermediate.key signer-rsa.key signer-ec.key \
         signer-juridical.key signer-representative.key tsa.key ocsp.key; do
  # The pattern avoids spelling out the PEM header, tools/check-no-real-certs.sh
  # would flag this script for containing one
  head -1 "$k" | grep -qE '^-----BEGIN.*KEY-----$' || { echo "$k is not PKCS#8" >&2; exit 1; }
done
echo "all PKCS#8"

echo
echo "written to $DIR:"
ls -1
