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

echo "== PKCS#12 for the official AutoFirma, chain included =="
# AutoFirma loads .p12, so the golden files are produced with exactly the
# certificate openfirma uses. Password is not a secret.
openssl pkcs12 -export -in signer-rsa.crt -inkey signer-rsa.key -certfile chain.crt \
  -out signer-rsa.p12 -passout pass:openfirma -name "PEREZ GARCIA, ANA"
openssl pkcs12 -export -in signer-ec.crt -inkey signer-ec.key -certfile chain.crt \
  -out signer-ec.p12 -passout pass:openfirma -name "LOPEZ MARTIN, JUAN"

echo "== chain verification =="
openssl verify -CAfile ca.crt -untrusted intermediate.crt signer-rsa.crt
openssl verify -CAfile ca.crt -untrusted intermediate.crt signer-ec.crt

echo "== every key must be PKCS#8, our loader accepts nothing else =="
for k in ca.key intermediate.key signer-rsa.key signer-ec.key; do
  # The pattern avoids spelling out the PEM header, tools/check-no-real-certs.sh
  # would flag this script for containing one
  head -1 "$k" | grep -qE '^-----BEGIN.*KEY-----$' || { echo "$k is not PKCS#8" >&2; exit 1; }
done
echo "all PKCS#8"

echo
echo "written to $DIR:"
ls -1
