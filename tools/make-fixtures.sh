#!/bin/bash
# Regenerate the certificate fixtures the policy tests need.
#
# The fixtures committed before 2026-09-28 have no generator: they were made
# by hand with OpenSSL and committed as bytes. These are the ones added for
# the policy rules gcert_x509_path applies - weak digests, small keys, an
# expired anchor, extendedKeyUsage, pathLenConstraint, keyUsage - and they do
# have one, because "what exactly is in this certificate" is a question a
# reader of the test will ask.
#
# Not deterministic: every run makes new keys and new serials, and the
# validity dates move. The tests do not depend on either. They read
# not_before and not_after from the certificate they parsed and pick the
# instant to test from those, so a fixture does not expire and a rerun of
# this script does not break them.
#
# Usage: tools/make-fixtures.sh [outdir]      (default tests/data/certs)
set -eu

OUT="${1:-tests/data/certs}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$OUT"

der() { openssl x509 -in "$1" -outform der -out "$2"; }

# A CA and a leaf, with the digest and key size named. $1 prefix, $2 digest,
# $3 key spec, $4 extra CA req args.
pair() {
  local prefix="$1" digest="$2" keyspec="$3" days="${4:-3650}"
  openssl req -x509 -newkey "$keyspec" -keyout "$TMP/$prefix-ca.key" \
      -out "$TMP/$prefix-ca.pem" -days "$days" -nodes "-$digest" \
      -subj "/CN=$prefix CA" \
      -addext "basicConstraints=critical,CA:TRUE" \
      -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1
  openssl req -newkey "$keyspec" -keyout "$TMP/$prefix-leaf.key" \
      -out "$TMP/$prefix-leaf.csr" -nodes -subj "/CN=leaf.example" \
      >/dev/null 2>&1
  openssl x509 -req -in "$TMP/$prefix-leaf.csr" -CA "$TMP/$prefix-ca.pem" \
      -CAkey "$TMP/$prefix-ca.key" -out "$TMP/$prefix-leaf.pem" -days 3650 \
      "-$digest" -copy_extensions copy >/dev/null 2>&1
  der "$TMP/$prefix-ca.pem" "$OUT/$prefix-ca.der"
  der "$TMP/$prefix-leaf.pem" "$OUT/$prefix-leaf.der"
}

# 1. Weak digests. gcert_x509_path must refuse both; gcert_x509_signed_by must
#    still verify them, which is how a caller identifies an old certificate.
pair sha1 sha1 rsa:2048
pair md5 md5 rsa:2048

# 2. A key below GCERT_X509_RSA_MIN_BITS, signed with SHA-256 so the digest is
#    not what the test is measuring.
pair weakkey sha256 rsa:1024

# 3. An anchor that expires before its own leaf does. The CA is good for two
#    days and the leaf for ten years, so there is an instant where the leaf is
#    in force and the anchor is not.
pair shortca sha256 rsa:2048 2

# 4. extendedKeyUsage. One certificate per case, all self-signed so the test
#    is about the extension and nothing else.
eku_cert() {
  local name="$1" eku="$2" crit="$3"
  local ext="extendedKeyUsage=$eku"
  if [ "$crit" = critical ]; then ext="extendedKeyUsage=critical,$eku"; fi
  openssl req -x509 -newkey rsa:2048 -keyout "$TMP/$name.key" \
      -out "$TMP/$name.pem" -days 3650 -nodes -sha256 \
      -subj "/CN=leaf.example" -addext "$ext" >/dev/null 2>&1
  der "$TMP/$name.pem" "$OUT/$name.der"
}
eku_cert eku-server serverAuth plain
eku_cert eku-code codeSigning critical
eku_cert eku-any anyExtendedKeyUsage plain
eku_cert eku-both "serverAuth,clientAuth" critical
# An OID with no bit of its own: 1.3.6.1.4.1.311.10.3.4 is Microsoft's EFS.
eku_cert eku-unknown 1.3.6.1.4.1.311.10.3.4 critical

# 5. pathLenConstraint. The root allows zero intermediates, so a chain with
#    one must be refused, and the same root signing a leaf directly is fine.
openssl req -x509 -newkey rsa:2048 -keyout "$TMP/plen-ca.key" \
    -out "$TMP/plen-ca.pem" -days 3650 -nodes -sha256 -subj "/CN=plen CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1
openssl req -newkey rsa:2048 -keyout "$TMP/plen-mid.key" \
    -out "$TMP/plen-mid.csr" -nodes -subj "/CN=plen mid" >/dev/null 2>&1
printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign\n' \
    > "$TMP/mid.ext"
openssl x509 -req -in "$TMP/plen-mid.csr" -CA "$TMP/plen-ca.pem" \
    -CAkey "$TMP/plen-ca.key" -out "$TMP/plen-mid.pem" -days 3650 -sha256 \
    -extfile "$TMP/mid.ext" >/dev/null 2>&1
openssl req -newkey rsa:2048 -keyout "$TMP/plen-leaf.key" \
    -out "$TMP/plen-leaf.csr" -nodes -subj "/CN=leaf.example" >/dev/null 2>&1
openssl x509 -req -in "$TMP/plen-leaf.csr" -CA "$TMP/plen-mid.pem" \
    -CAkey "$TMP/plen-mid.key" -out "$TMP/plen-leaf.pem" -days 3650 -sha256 \
    >/dev/null 2>&1
openssl x509 -req -in "$TMP/plen-leaf.csr" -CA "$TMP/plen-ca.pem" \
    -CAkey "$TMP/plen-ca.key" -out "$TMP/plen-direct.pem" -days 3650 -sha256 \
    >/dev/null 2>&1
der "$TMP/plen-ca.pem" "$OUT/plen-ca.der"
der "$TMP/plen-mid.pem" "$OUT/plen-mid.der"
der "$TMP/plen-leaf.pem" "$OUT/plen-leaf.der"
der "$TMP/plen-direct.pem" "$OUT/plen-direct.der"

# 6. An intermediate that is a CA but whose keyUsage omits keyCertSign.
printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature\n' \
    > "$TMP/nokcs.ext"
openssl x509 -req -in "$TMP/plen-mid.csr" -CA "$TMP/sha1-ca.pem" \
    -CAkey "$TMP/sha1-ca.key" -out "$TMP/nokcs-mid.pem" -days 3650 -sha256 \
    -extfile "$TMP/nokcs.ext" >/dev/null 2>&1
openssl x509 -req -in "$TMP/plen-leaf.csr" -CA "$TMP/nokcs-mid.pem" \
    -CAkey "$TMP/plen-mid.key" -out "$TMP/nokcs-leaf.pem" -days 3650 -sha256 \
    >/dev/null 2>&1
# Its own root is signed with SHA-256 rather than the sha1 pair's digest, so
# that the keyUsage rule is what the test measures.
openssl req -x509 -newkey rsa:2048 -keyout "$TMP/nokcs-ca.key" \
    -out "$TMP/nokcs-ca.pem" -days 3650 -nodes -sha256 -subj "/CN=nokcs CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1
openssl x509 -req -in "$TMP/plen-mid.csr" -CA "$TMP/nokcs-ca.pem" \
    -CAkey "$TMP/nokcs-ca.key" -out "$TMP/nokcs-mid.pem" -days 3650 -sha256 \
    -extfile "$TMP/nokcs.ext" >/dev/null 2>&1
openssl x509 -req -in "$TMP/plen-leaf.csr" -CA "$TMP/nokcs-mid.pem" \
    -CAkey "$TMP/plen-mid.key" -out "$TMP/nokcs-leaf.pem" -days 3650 -sha256 \
    >/dev/null 2>&1
der "$TMP/nokcs-ca.pem" "$OUT/nokcs-ca.der"
der "$TMP/nokcs-mid.pem" "$OUT/nokcs-mid.der"
der "$TMP/nokcs-leaf.pem" "$OUT/nokcs-leaf.der"

# 6b. Hostname patterns a matcher has to refuse. OpenSSL will put whatever
#     dNSName it is given into the SAN, which is what makes these possible: a
#     CA would not issue them, and the matcher must not rely on that.
san_cert() {
  openssl req -x509 -newkey rsa:2048 -keyout "$TMP/$1.key" -out "$TMP/$1.pem" \
      -days 3650 -nodes -sha256 -subj "/CN=$2" \
      -addext "subjectAltName=DNS:$2" >/dev/null 2>&1
  der "$TMP/$1.pem" "$OUT/$1.der"
}
san_cert san-wild-mid 'w*w.example.com'
san_cert san-wild-two '*.*.example.com'
san_cert san-wild-inner 'www.*.example.com'
san_cert san-bare-wild '*'
san_cert san-wild-tld '*.com'

# 7. A PFX with no MacData. Its contents are unauthenticated, which
#    gcert_pkcs12_open refuses.
openssl pkcs12 -export -inkey "$TMP/plen-leaf.key" -in "$TMP/plen-leaf.pem" \
    -out "$OUT/nomac.p12" -passout pass:secret -nomac >/dev/null 2>&1

# 8. A PBES2 key whose iteration count is above the cap. OpenSSL does the
#    derivation while writing it, so this line is the slow one.
openssl pkcs8 -topk8 -in "$TMP/plen-leaf.key" -out "$OUT/overiter.p8" \
    -outform DER -passout pass:secret -v2 aes-256-cbc \
    -iter 10000001 >/dev/null 2>&1

printf 'wrote to %s:\n' "$OUT"
ls -1 "$OUT" | grep -E '^(sha1|md5|weakkey|shortca|eku|plen|nokcs|nomac|overiter)' \
    | sed 's/^/  /'
