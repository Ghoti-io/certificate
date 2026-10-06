# Oracles

The encodings this library implements are judged by something that is not
this library. `make check-oracle` first checks that the image still produces
the published SHA-256 of `abc`, which judges the oracle. It then has OpenSSL
write a certificate (for RSA, P-256, P-384 and Ed25519), its PEM, an
unencrypted PKCS#8 key, a PBES2 key, a PBES1 key, a PKCS#12 archive, a CRL,
and an OCSP response, and this library reads them. A difference fails the
target. A comparison the probe skips is a failure, and an encoding with an
outside judge that the probe never asks about is a failure.

Past the encodings, `make check-oracle` runs differentials on populations it
makes, and each has a short list of *declared* differences: a disagreement
that is not on the list fails, and a declared difference that no longer
happens fails too, because a list that describes nothing is how a rule gets
dropped without anyone deciding to.

| Comparison | Population | Declared differences |
| --- | --- | --- |
| Names (`-checkhost`, `-checkip`, `-checkemail`) | A DNS name, wildcard, common-name and address certificate against about forty references each | A partial wildcard (`f*.example`), which OpenSSL matches and RFC 9525 does not; an absolute name (trailing dot), which this library treats as the same name and OpenSSL refuses |
| IP literals (Python's `ipaddress`) | Fifty valid and invalid IPv4 and IPv6 texts, parsed bytes compared. OpenSSL's command line cannot judge this: it prints "does match" for text it cannot parse | A zone id (`fe80::1%eth0`), which Python reads and a certificate has no use for |
| Chains (`openssl verify`) | A root, two intermediates and a leaf, with reorderings, extras, a missing link, an unknown root, expired and not-yet-valid certificates, a re-issue, a pathLen violation, name constraints, extended key usage, a non-CA signer, an impostor, an expired anchor | 1024-bit RSA and SHA-1 links, which this library refuses and OpenSSL's default level does not; a cross-signed intermediate where the usable one comes after the unusable one, which this library finds and OpenSSL does not go back for |
| Signatures | Every scheme `key.h` has, on a fresh key of each kind: this library signs and OpenSSL verifies, OpenSSL signs and this library verifies, and a damaged signature is refused by both | None |
| Revocation (`openssl verify -crl_check`, `openssl ocsp`) | A CA with a good and a revoked leaf; a CRL and a CRL with a damaged signature; OCSP good, revoked, unknown, delegated, a responder with no OCSP signing, another CA of the same name, another CA's responder | None |

The primitives under these encodings are judged in `security`, against
OpenSSL and Wycheproof there. This library does not carry Wycheproof: none of
its data is a signature or a cipher test vector.

`make test` does not run a container. A checkout with no container runtime
still builds and tests. The differential is a separate target, and that
target fails closed.

## The image

`localhost/ghoti-certificate-oracle-openssl:3.5.7`, built from
`tools/oracle/containers/openssl/Containerfile`.

```
make oracle-build
make check-oracle
```

`oracle-build` uses `docker build`. The tag is local. `oracle_env.py` does
not pull an image whose name starts with `localhost/`; a missing image is
an error that names `make oracle-build`.

The finished image has no digest to pin. Two builds of one Containerfile
are not two copies of one image. What is pinned is everything the build
reads, and the run-time check runs whether the probe is inside the
container or on the host (`GHOTI_ORACLE_MODE=host`).

| What | Pin |
| --- | --- |
| Base | `docker.io/library/debian:13-slim` at `sha256:7792b1f7702a86946cd518db72b6a407302c3e9bc1635634368b878189e8221c` |
| Package | `openssl=3.5.7-1~deb13u2`, from the `trixie-security` suite the base image already lists. Main may still be on an older openssl, and an unpinned install would take it. |
| Reported version | `OpenSSL 3.5.7` followed by a space. `OpenSSL 3.5.70` does not match. |

This is the same OpenSSL as `security`'s image, on purpose: two libraries that
each judge a parser by it should be asking one reference. The apt pin stops
resolving when the archive drops that revision. That failure is the pin
working: the alternative is an oracle that moved and a diff that changed
meaning with it.

## What `check-oracle` runs

`GHOTI_ORACLE_REQUIRED=1`, so a missing runtime, a missing image, or a probe
that exits non-zero is a failure. The probe is `tools/oracle/openssl_kat.py`,
and the helpers are the `examples/` programs `make check-oracle` builds and
passes in `GCERT_*_BIN`.

## The committed corpus

`tests/data/vectors/` holds known-answer files the unit tests score, with no
container: `der`, `pem`, `pkcs8`, `x509`, `crl`, `ocsp` and `pkcs12`.
`tests/data/vectors/MANIFEST` is the SHA-256 of each file. `check-foundation`
recomputes those hashes. A vector file that is edited without updating the
manifest fails the build, which is the property a hand-edited expected digest
would not have.

`tests/data/certs/` holds the certificates, keys and archives the tests read.
The older fixtures have no generator and were made by hand with OpenSSL;
`tools/make-fixtures.sh` makes the policy fixtures, and
`tools/make-ocsp-ext.py` the OCSP one with a critical extension.
