# Ghoti.io Certificate

Certificates and keys in C: strict DER, PEM, PKCS#8, PKCS#12, X.509 with
path validation and issuance, a certificate revocation list, and a basic
OCSP response; and what a verifier builds on them: a trust store, path
building from whatever a peer sent, name verification as RFC 9525 has it,
the revocation checks a verifier applies, private keys that sign by scheme,
and what a certificate says about who holds it. The cryptography under them
is [security](https://github.com/Ghoti-io/security)'s. Fetching a list or a
response, and a handshake, are not here.

This library began as the certificate half of `security`: the code was moved
out of it on 2026-10-06 without a change in behaviour, tests and fixtures with
it. `security` is the primitives layer and this is what is built on it. What
this library has added since is in [Status](#status).

## What it reads and writes

This is what the library implements. A scheme that should not be used for
new work says so here and names the alternative. The headers say the same thing
next to the function.

| Format | |
| --- | --- |
| DER | One strict value. The reader does not allocate. An indefinite length, a non-minimal length or tag, and a truncated value are refused. |
| PEM | The first block in, and one block out. |
| PKCS#8 | An unencrypted key, or PBES2. PBES1 is opened so an old key can be read. A new encrypted key is PBES2 with AES. |
| PKCS#12 | A PFX, and it must carry a MacData: an archive with none is unauthenticated and is refused. A new encrypted bag is PBES2 with AES. The older schemes are opened so an old archive can be read. |
| X.509 | One certificate, a signature check, and a path the caller has already arranged, at a time the caller supplies. The path refuses MD5 and SHA-1, an RSA key below 2048 bits, and an expired anchor, and checks the leaf's extendedKeyUsage against a purpose the caller names. |
| Issuance | A certificate signed with P-256, P-384, Ed25519, or RSA, carrying a basicConstraints, a subjectAltName with a name, an address, a URI and a mailbox, and the key identifiers. |
| Trust store | A set of anchors, from DER, a PEM bundle, a file, or the operating system's list (a file on Unix, the ROOT store on Windows), found by subject with the key identifiers breaking ties. A bundle load counts what it could not read and carries on. |
| Path building | From a peer's chain in any order, with extras and gaps: the trust anchors first, then the pool, every candidate that reaches an anchor handed to the path check, whose verdict is the answer. The pool and the search are bounded. A refusal says why. |
| Names | RFC 9525: a DNS name, an IP address, a URI, a mailbox. A wildcard is the whole leftmost label and matches one, and needs two labels after the star. The common name is not read unless asked. |
| CRL | Parse, check the signature, look up a serial, and check it for a certificate: the right issuer, allowed to sign, fresh. |
| OCSP | A basic response, with `producedAt`, `thisUpdate` and `nextUpdate`. Checked for a certificate: the right issuer or a delegated responder that is authorised, fresh, and a status that is not unknown. |
| Revocation decision | Several pieces of evidence, or none, reduced to go on or refuse. Hard fail by default; soft fail is the caller's choice. |
| Keys | A private key from PKCS#8, or PEM (PKCS#8, encrypted, PKCS#1, SEC1), that signs with a named scheme and is wiped when freed; and the check of a signature against a certificate's key. |
| Identity | Every subjectAltName entry, and the attributes of a subject or issuer name. Reports; the policy is the caller's. |

A critical extension the parser does not understand is rejected. The
pointers in a parsed result address the caller's buffer.

## Before you call it

- Results are `GCERT_Result`. The primitives under this library return `GSEC_Result`, and nothing here hands one to the caller: a signature that does not verify is `GCERT_ERR_MISMATCH`, and `GCERT_OK` is the only success. The two enums have the same members, and `src/core/sec_result.h` is the one place one becomes the other.
- `gcert_x509_path` is where a trust policy lives: MD5 and SHA-1 links, RSA keys below `GCERT_X509_RSA_MIN_BITS`, and an anchor outside its own validity period are `GCERT_ERR_UNSUPPORTED` or `GCERT_ERR_MISMATCH` there, while `gcert_x509_signed_by` still verifies a weak signature so an old certificate can be identified before it is refused. Pass a `GCERT_X509_EKU_*` purpose, or check it yourself with `gcert_x509_purpose`: without one, a certificate issued for e-mail is a valid TLS certificate as far as the path is concerned.
- `gcert_x509_path` takes exactly one anchor and an ordered path, **anchor's side first**. A verifier has a store and a peer's chain in any order: that is `gcert_chain_build`, and its answer is `gcert_x509_path`'s.
- A path says the chain is good. It does not say the certificate is for the host you meant: `gcert_x509_verify_host` does, and a client needs both. It does not say the certificate is not revoked: `gcert_crl_check` and `gcert_ocsp_check` look at evidence the caller fetched, and `gcert_revocation_verdict` is where "no usable evidence" becomes a decision, **refuse** unless the policy says otherwise.
- Names compare ASCII, and a name that is not ASCII is `GCERT_ERR_INVALID`. Turning an internationalised name into its A-label is the caller's. `*.co.uk` is a wildcard that matches `a.co.uk`: there is no public-suffix list here.
- Loading the operating system's roots only enumerates them. A bundle is read leniently (the entries this library cannot parse are counted, three of the 150 in Debian's, all ECDSA with a digest of another size than the curve's), and what the platform keeps beside its list is not carried over.
- A zero in a `GCERT_Limits` field added since the first release means the default, so a struct filled field by field by older code stays valid.
- `NULL` for an allocator is cutil's default. `NULL` for limits is `gcert_limits_default`, which caps a password-based derivation at `GCERT_PBE_ITERATIONS_DEFAULT` iterations. That is the cap to lower when the files come from outside: the iteration count is in the file, and the default ceiling is about nine seconds of CPU.
- A successful `gcert_pkcs8_decrypt` is not an integrity check. PBES2 with a CBC cipher, and every PBES1 scheme, has no MAC.
- A zero length is success and does not read the pointers. A null pointer with a positive length is `GCERT_ERR_INVALID`.
- `gcert_result_string` returns one of a fixed set of static strings. There is no function that prints a key.
- `gcert_selftest` runs a known answer for DER, a PEM round trip, an IPv6 literal, and the revocation decision. The parsers with no writer have their known answers in the vector files.
- A `GCERT_Key` holds secret bytes in one allocation and wipes them when freed or when a load fails; the PEM loader wipes what it decoded. An RSA key is checked at load by signing and verifying, because a damaged PKCS#8 file can still parse.

## Examples

```c
#include <ghoti.io/certificate/certificate.h>
#include <stdio.h>

int main(void) {
  GCERT_Result result = gcert_selftest();

  if (result != GCERT_OK) {
    fprintf(stderr, "selftest: %s\n", gcert_result_string(result));
    return 1;
  }
  return 0;
}
```

It prints nothing. A zero exit status is the self-test succeeding. The
programs under `examples/` each read one format and print what they found;
`make check-oracle` runs them against OpenSSL.

What a client does with a server's certificate, in order. Nothing here
fetches, and nothing here decides what the time is. `examples/verify.c` is the
first half of this as a program (`verify chain.pem www.example.com`), and
builds with `make examples`:

```c
GCERT_TrustStore * store;
GCERT_Chain chain;

gcert_trust_new(NULL, NULL, &store);
gcert_trust_add_system(store, NULL, NULL);

/* leaf and pool are the DER the peer sent; now is the caller's clock. */
if (gcert_chain_build(store, leaf, leaf_len, pool, pool_lens, pool_count, now,
        GCERT_X509_EKU_SERVER_AUTH, NULL, &chain) != GCERT_OK) {
  /* chain.failure says why: unknown issuer, bad signature, expired, ... */
}
GCERT_X509 cert;
gcert_x509_parse(leaf, leaf_len, &cert);
if (gcert_x509_verify_host(&cert, "www.example.com", 15, NULL) != GCERT_OK) {
  /* the certificate is good and is for someone else */
}
/* Evidence the caller fetched, if any, and the decision: */
GCERT_Revocation evidence[2];
gcert_ocsp_check(&ocsp, &issuer, NULL, &cert, now, NULL, &evidence[0]);
if (gcert_revocation_verdict(evidence, 1, NULL) != GCERT_OK) {
  /* revoked, or no usable answer and the policy is hard fail (the default) */
}
```

## Compile and link

Once the library is installed, pkg-config carries the include path, the
library, and its dependencies:

```bash
cc -o show show.c $(pkg-config --cflags --libs ghoti.io-certificate-0)
```

The module name ends in the major version, `-0` for this release, so two
majors can be installed side by side. A build made with `make BRANCH=-dev`
installs `ghoti.io-certificate-dev` instead.

## Building the library

[cutil](https://github.com/Ghoti-io/cutil) and
[security](https://github.com/Ghoti-io/security) must already be installed
where pkg-config can see them. A dependency it cannot find is a hard error
naming the fix.

```bash
make
make test
sudo make install
```

From the parent of a suite checkout, which installs the dependencies first:

```bash
./suite/install.sh
export PKG_CONFIG_PATH="$PWD/.local/share/pkgconfig"
make -C libs/certificate test PREFIX="$PWD/.local"
```

`make test` is the suite: the unit tests, and the symbol, aliasing, stamp,
secret, hardening, depfile, static-analysis, foundation and fuzz-flag gates.
Each of those is written so that it fails when the thing it guards stops being
true - most of them by planting a violation and requiring it to be reported.
`make help` lists the rest.

| Target | What it does |
| --- | --- |
| `make test-asan` | Rebuild with ASan and UBSan and run the suite |
| `make test-valgrind` | Run the suite under Valgrind |
| `make analyze` | GCC's `-fanalyzer` over `src/`, slower than the gate |
| `make check-oracle` | Differentials against pinned OpenSSL, in a container |
| `make oracle-build` | Build that container |
| `make fuzz` | Build and run the libFuzzer harnesses |
| `make docs` | The Doxygen manual, into `./docs` |

`make test` does not run a container. `make check-oracle` fails if the
image is missing.

## The API

Everything is prefixed `gcert_` / `GCERT_`, under
`<ghoti.io/certificate/...>`. `<ghoti.io/certificate/certificate.h>` is the
umbrella.

- **`der.h`**, **`pem.h`** — the two encodings everything else sits on. `gcert_pem_next` walks a bundle.
- **`pkcs8.h`**, **`pkcs12.h`** — a private key, and an archive holding one.
- **`x509.h`**, **`crl.h`**, **`ocsp.h`** — a certificate, a revocation list, and a response.
- **`trust.h`**, **`chain.h`** — a set of anchors, and a path from a peer's certificates to one.
- **`names.h`**, **`identity.h`** — whether a certificate names what you were given, and who it names.
- **`revocation.h`** — the checks that make a CRL or an OCSP response count, and the decision.
- **`key.h`** — a private key that signs by scheme, and the matching check for a certificate.
- **`selftest.h`** — `gcert_selftest`.
- **`allocator.h`** — `GCERT_Allocator`, which is cutil's `GCU_Allocator`.
- **`core.h`** — the result codes and `GCERT_Limits`.

## Dependencies

Found through pkg-config, and the installed `.pc` file names them, so a
program that links `ghoti.io-certificate-0` links these too.

- [ghoti.io-security](https://github.com/Ghoti-io/security) — the hashes,
  HMAC, PBKDF2, the ciphers the old schemes name, and the signature
  algorithms a certificate is checked and issued with.
- [ghoti.io-cutil](https://github.com/Ghoti-io/cutil) — the allocator.

## Documentation

| Page | What it settles |
| --- | --- |
| [documentation/design.md](documentation/design.md) | What each call guarantees, what moved from `security` and what did not, and what is planned |
| [documentation/oracles.md](documentation/oracles.md) | The pinned OpenSSL image, and what `make check-oracle` asks of it |

`make docs` builds the manual from the headers.

## Status

On 2026-10-06 the code was `security`'s certificate code as it stood at
`security` commit `7c810c2`, moved without a change in behaviour. The same day
it gained the pieces a TLS verifier needs, in the order the workspace's
`planning/tls.md` lists them: a trust store, path building, names as RFC 9525
has them, identity extraction, the revocation checks and their decision, and
keys that sign by scheme. The record, with what each step measured and found, is
`notes/certificate/STATUS.md` in the workspace.

What is measured: `make test` is 162 tests in 19 binaries and nine gates;
`make test-asan` and `make test-valgrind` are clean; `make check-oracle`
agrees with OpenSSL 3.5.7 except where a difference is declared (see
[oracles.md](documentation/oracles.md)); twelve fuzz harnesses run from their
seeds without a trap; `make coverage` is 82.3% of 4,547 lines, the new files
86% to 97%; the library exports 56 functions.

What building the new pieces found in code that was already here, all fixed:
the documented order of `gcert_x509_path`'s intermediates was backwards (a
caller who followed it got a refusal); the signature algorithm and the ECDSA
unwrapping were parsed twice and now once; three of the 150 roots in Debian's
bundle (a P-384 key with an ECDSA-SHA-256 signature) were reported as corrupt
when they are well-formed and unsupported; a CERTIFICATE block with no body
ended a whole bundle load, found by the fuzzer in under a second; an RSA key
with a damaged private exponent parsed and then signed garbage; and
`host_ok` on the pattern and the `sig_key` check, the two items the
`security` audit left open, turned out to be unobservable by answer, and are
respectively removed with the reason in the code and tested by what they
read.

What differs from `security`: the result type is `GCERT_Result`, with its own
conversion from `GSEC_Result` and a test that the two enums stay in step, and
`security`'s constant-time gate is not carried over, because it drives
`gsec_equal` and the primitives and none of the code that moved. `pbes2.c`
has a `GCERT_CT_TEST` branch around its padding check that nothing drives under
memcheck, which was true in `security` too.

Not here, and recorded as open in
[documentation/design.md](documentation/design.md) section 7: ECDSA with a
digest of another size than the curve's (it needs a verify over a caller's
digest in `security`), building an OCSP request, the macOS keychain, and the
constant-time gate.

The Windows branches ran on 2026-10-06: the workspace's
`suite/tools/xwin/certificate.sh` cross-builds this library's DLL and archive with its
own Makefile and runs every test under wine, including the root-store
enumeration, and requires a planted defect to fail the same run. That is not a
Windows machine. It has not run `GCERT_API`'s dllimport arm, `make install`
into `/mingw64`, or real MSYS2; the Makefile's `TODO(windows)` marker says which.

## License

LGPL-3.0-only. See [COPYING.LESSER](COPYING.LESSER) for the license, and
[COPYING](COPYING) for the GPL text it is written as additional permissions
on top of.

To report a vulnerability, see [SECURITY.md](SECURITY.md), which also lists
the behaviour that is deliberate.

Contributions are not being accepted at this time; see
[CONTRIBUTING.md](CONTRIBUTING.md) for what is useful instead.
