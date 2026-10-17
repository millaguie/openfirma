#!/usr/bin/env bash
# Build the DNIe-shaped key+certificate pair (finding A5) in $1:
#   auth.crt.der  keyUsage digitalSignature,            issuer AC DNIE…
#   sign.crt.der  keyUsage +nonRepudiation, same subject/issuer
#   marta.pk8     the PKCS#8 DER private key both ids pair to
# Everything generated fresh by the openssl CLI; nothing real.
set -euo pipefail
OUT="${1:?usage: gen-dnie-pair.sh <dir>}"
mkdir -p "$OUT"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$TMP/marta.key" 2>/dev/null
cat > "$TMP/ca.cnf" <<'CF'
[req]
distinguished_name = dn
prompt = no
[dn]
C = ES
O = DIRECCION GENERAL DE LA POLICIA
OU = DNIE
CN = AC DNIE 0000000000
CF
cat > "$TMP/leaf.cnf" <<'CF'
[dnie_ext]
keyUsage = critical, digitalSignature
[sign_ext]
keyUsage = critical, digitalSignature, nonRepudiation
CF
openssl req -new -x509 -key "$TMP/marta.key" -days 3650 -out "$TMP/ca.pem" -subj "/C=ES/O=DIRECCION GENERAL DE LA POLICIA/OU=DNIE/CN=AC DNIE 0000000000" 2>/dev/null
openssl req -new -key "$TMP/marta.key" -out "$TMP/marta.csr" -subj "/C=ES/CN=Marta Viajera Garcia - test" 2>/dev/null
openssl x509 -req -in "$TMP/marta.csr" -CA "$TMP/ca.pem" -CAkey "$TMP/marta.key" -days 3650 -extfile "$TMP/leaf.cnf" -extensions dnie_ext -set_serial 13 -out "$TMP/auth.pem" 2>/dev/null
openssl x509 -req -in "$TMP/marta.csr" -CA "$TMP/ca.pem" -CAkey "$TMP/marta.key" -days 3650 -extfile "$TMP/leaf.cnf" -extensions sign_ext -set_serial 14 -out "$TMP/sign.pem" 2>/dev/null
openssl x509 -in "$TMP/auth.pem" -outform DER -out "$OUT/auth.crt.der"
openssl x509 -in "$TMP/sign.pem" -outform DER -out "$OUT/sign.crt.der"
openssl pkcs8 -topk8 -nocrypt -in "$TMP/marta.key" -outform DER -out "$OUT/marta.pk8"
