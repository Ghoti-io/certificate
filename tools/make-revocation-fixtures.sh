#!/bin/bash
# Make the revocation fixtures: one CA, three leaves, a CRL, and OCSP responses.
#
# The CA is `rev-ca`. `rev-good` and `rev-revoked` are leaves it issued, and
# `rev-revoked` is on the CRL and revoked in OCSP. The OCSP responses are made
# by the CA itself and, for the delegated case, by `rev-responder`, which the CA
# signed with id-kp-OCSPSigning. `rev-no-eku-responder` is signed by the CA and
# has no extendedKeyUsage, so it is not a responder. `rev-other-ca` is a second CA
# with the same subject name and a different key, for the wrong-key case.
#
# Not deterministic: every run makes new keys and serials. The tests read the
# dates from what they parse and choose the instant from those, so nothing
# here expires and a rerun does not break them. Lifetimes are a century.
#
# Usage: tools/make-revocation-fixtures.sh [outdir]   (default tests/data/certs)
set -eu

OUT="${1:-tests/data/certs}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
cd "$TMP"

der() { openssl x509 -in "$1" -outform der -out "$OUT/$2"; }
q() { "$@" >/dev/null 2>&1; }

mkdir demoCA
: > demoCA/index.txt
echo 1000 > demoCA/serial
echo 1000 > demoCA/crlnumber

cat > ca.cnf <<CNF
[ca]
default_ca = CA_default
[CA_default]
dir = $TMP/demoCA
database = \$dir/index.txt
new_certs_dir = \$dir
serial = \$dir/serial
crlnumber = \$dir/crlnumber
default_md = sha256
default_days = 36500
default_crl_days = 36500
policy = policy_any
copy_extensions = none
unique_subject = no
[policy_any]
commonName = supplied
[v3_leaf]
basicConstraints = CA:FALSE
[v3_responder]
basicConstraints = CA:FALSE
extendedKeyUsage = OCSPSigning
[req]
distinguished_name = dn
prompt = no
[dn]
CN = x
CNF

# The CA, and a second CA with the same name and another key.
q openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 36500 \
  -subj "/CN=rev-ca" -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"
q openssl req -x509 -newkey rsa:2048 -nodes -keyout other.key -out other.pem -days 36500 \
  -subj "/CN=rev-ca" -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

issue() { # name subject ext-section
  q openssl req -new -newkey rsa:2048 -nodes -keyout "$1.key" -out "$1.csr" -subj "/CN=$2"
  q openssl ca -batch -config ca.cnf -cert ca.pem -keyfile ca.key -in "$1.csr" -out "$1.pem" \
    -notext -extensions "$3"
}
issue_by() { # name subject ext-section cacert cakey
  q openssl req -new -newkey rsa:2048 -nodes -keyout "$1.key" -out "$1.csr" -subj "/CN=$2"
  q openssl x509 -req -in "$1.csr" -CA "$4" -CAkey "$5" -set_serial "$6" -days 36500 \
    -out "$1.pem" -extfile ca.cnf -extensions "$3"
}
issue good rev-good v3_leaf
issue revoked rev-revoked v3_leaf
issue responder rev-responder v3_responder
issue plain rev-plain-responder v3_leaf

issue_by foreign rev-foreign-responder v3_responder other.pem other.key 7001
issue_by unknown rev-unknown v3_leaf ca.pem ca.key 7002

q openssl ca -config ca.cnf -cert ca.pem -keyfile ca.key -revoke revoked.pem
q openssl ca -batch -config ca.cnf -cert ca.pem -keyfile ca.key -gencrl -out ca.crl.pem

req() { # name cert -> request for that certificate
  q openssl ocsp -sha256 -issuer ca.pem -cert "$2" -reqout "$1.req"
}
resp() { # name request signer-cert signer-key [extra args]
  local name=$1 reqf=$2 cert=$3 key=$4
  shift 4
  q openssl ocsp -index demoCA/index.txt -CA ca.pem -rsigner "$cert" -rkey "$key" \
    -reqin "$reqf" -respout "$name.resp" -ndays 36500 "$@"
}

req good good.pem
req unknown unknown.pem
req revoked revoked.pem
resp ocsp-good good.req ca.pem ca.key
resp ocsp-revoked revoked.req ca.pem ca.key
resp ocsp-delegated good.req responder.pem responder.key -resp_no_certs
resp ocsp-plain-delegate good.req plain.pem plain.key -resp_no_certs
resp ocsp-other-signed good.req other.pem other.key -resp_no_certs
resp ocsp-foreign good.req foreign.pem foreign.key -resp_no_certs
resp ocsp-unknown unknown.req ca.pem ca.key

# SHA-1 CertID, as a stapled response from an older responder has.
q openssl ocsp -sha1 -issuer ca.pem -cert good.pem -reqout good1.req
resp ocsp-good-sha1 good1.req ca.pem ca.key

der ca.pem rev-ca.der
der other.pem rev-other-ca.der
der good.pem rev-good.der
der revoked.pem rev-revoked.der
der responder.pem rev-responder.der
der plain.pem rev-plain-responder.der
der foreign.pem rev-foreign-responder.der
der unknown.pem rev-unknown.der
openssl crl -in ca.crl.pem -outform der -out "$OUT/rev-ca.crl"
for r in ocsp-good ocsp-revoked ocsp-delegated ocsp-plain-delegate ocsp-other-signed ocsp-good-sha1 ocsp-foreign ocsp-unknown; do
  cp "$r.resp" "$OUT/rev-$r.der"
done
echo "wrote $(ls "$OUT"/rev-* | wc -l) revocation fixtures to $OUT"
