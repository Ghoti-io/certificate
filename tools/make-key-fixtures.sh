#!/bin/bash
# Make the key fixtures: one key of each kind in each file format OpenSSL writes,
# a self-signed certificate for each, and OpenSSL's signature over a fixed message
# for every scheme the key can use.
#
# For each name in rsa, p256, p384, ed25519:
#   <name>.pk8.pem      PKCS#8 PrivateKeyInfo ("PRIVATE KEY")
#   <name>.legacy.pem   PKCS#1 or SEC1 ("RSA PRIVATE KEY", "EC PRIVATE KEY"); not for ed25519
#   <name>.cert.der     a self-signed certificate for the key
#   <name>.<scheme>.sig OpenSSL's signature of `message` with that scheme
# and rsa.enc.pem, the RSA key as an ENCRYPTED PRIVATE KEY under the password in
# `password`, and combined.pem, a certificate then a key in one file.
#
# Not deterministic: every run makes new keys. The tests only compare this
# library's answers with what is in the files, so a rerun does not break them.
#
# Usage: tools/make-key-fixtures.sh [outdir]   (default tests/data/keys)
set -eu

OUT="${1:-tests/data/keys}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
cd "$TMP"

printf 'the quick brown fox' > "$OUT/message"
printf 'hunter2' > "$OUT/password"
q() { "$@" >/dev/null 2>&1; }

# The certificate's own digest follows the curve (SHA-384 for P-384): this
# library verifies P-256 with SHA-256 and P-384 with SHA-384 and no other pairing.
mk() { # name digest genpkey-args...
  local name=$1 digest=$2
  shift 2
  q openssl genpkey "$@" -out "$name.key"
  q openssl pkcs8 -topk8 -nocrypt -in "$name.key" -out "$OUT/$name.pk8.pem"
  q openssl req -new -x509 "-$digest" -key "$name.key" -subj "/CN=$name" -days 36500 \
    -outform DER -out "$OUT/$name.cert.der"
}

mk rsa sha256 -algorithm RSA -pkeyopt rsa_keygen_bits:2048
mk p256 sha256 -algorithm EC -pkeyopt ec_paramgen_curve:P-256
mk p384 sha384 -algorithm EC -pkeyopt ec_paramgen_curve:P-384
mk ed25519 sha256 -algorithm ED25519

q openssl rsa -in rsa.key -traditional -out "$OUT/rsa.legacy.pem"
q openssl ec -in p256.key -out "$OUT/p256.legacy.pem"
q openssl ec -in p384.key -out "$OUT/p384.legacy.pem"
q openssl pkcs8 -topk8 -v2 aes-256-cbc -passout pass:hunter2 -in rsa.key -out "$OUT/rsa.enc.pem"

openssl x509 -inform DER -in "$OUT/rsa.cert.der" -out cert.pem
cat cert.pem "$OUT/rsa.pk8.pem" > "$OUT/combined.pem"

sig() { # name scheme digest [sigopts...]
  local name=$1 scheme=$2 digest=$3
  shift 3
  q openssl dgst "-$digest" -sign "$name.key" "$@" -out "$OUT/$name.$scheme.sig" "$OUT/message"
}
sig rsa pkcs1-sha256 sha256
sig rsa pkcs1-sha384 sha384
sig rsa pkcs1-sha512 sha512
for d in 256 384 512; do
  sig rsa pss-sha$d sha$d -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest \
    -sigopt rsa_mgf1_md:sha$d
done
sig p256 ecdsa-sha256 sha256
sig p384 ecdsa-sha384 sha384
q openssl pkeyutl -sign -inkey ed25519.key -rawin -in "$OUT/message" -out "$OUT/ed25519.ed25519.sig"

echo "wrote $(ls "$OUT" | wc -l) key fixtures to $OUT"
