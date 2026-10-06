# Ghoti.io Certificate

Certificates and keys in C: strict DER, PEM, PKCS#8, PKCS#12, X.509 with
path validation and issuance, a certificate revocation list, and a basic
OCSP response. The cryptography under them is
[security](https://github.com/Ghoti-io/security)'s. Fetching a list or a
response, and a handshake, are not here.

This library began as the certificate half of `security`: the code was moved
out of it on 2026-10-06 without a change in behaviour, tests and fixtures with
it. `security` is the primitives layer and this is what is built on it. What
this library adds to that code is in [Status](#status).

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
| X.509 | One certificate, a signature check, a path, and a name match. The caller supplies the chain and the time. The path refuses MD5 and SHA-1, an RSA key below 2048 bits, and an expired anchor, and checks the leaf's extendedKeyUsage against a purpose the caller names. It does not check revocation. |
| Issuance | A certificate signed with P-256, P-384, Ed25519, or RSA. |
| CRL | Parse, check the signature, and look up a serial. Fetching the list stays with the caller. |
| OCSP | A basic response, with `producedAt`, `thisUpdate` and `nextUpdate`, because a signed response with no visible age can be replayed. Fetching it, judging its freshness, and a delegated responder all stay with the caller. |

A critical extension the parser does not understand is rejected. The
pointers in a parsed result address the caller's buffer.

## Before you call it

- Results are `GCERT_Result`. The primitives under this library return `GSEC_Result`, and nothing here hands one to the caller: a signature that does not verify is `GCERT_ERR_MISMATCH`, and `GCERT_OK` is the only success. The two enums have the same members, and `src/core/sec_result.h` is the one place one becomes the other.
- `gcert_x509_path` is where a trust policy lives: MD5 and SHA-1 links, RSA keys below `GCERT_X509_RSA_MIN_BITS`, and an anchor outside its own validity period are `GCERT_ERR_UNSUPPORTED` or `GCERT_ERR_MISMATCH` there, while `gcert_x509_signed_by` still verifies a weak signature so an old certificate can be identified before it is refused. Pass a `GCERT_X509_EKU_*` purpose, or check it yourself with `gcert_x509_purpose`: without one, a certificate issued for e-mail is a valid TLS certificate as far as the path is concerned.
- `gcert_x509_path` takes exactly one anchor. A trust store that holds many is planned and is not here yet.
- `gcert_x509_hostname` compares ASCII, and a name that is not ASCII does not match. Turning an internationalised name into its A-label is the caller's.
- `NULL` for an allocator is cutil's default. `NULL` for limits is `gcert_limits_default`, which caps a password-based derivation at `GCERT_PBE_ITERATIONS_DEFAULT` iterations. That is the cap to lower when the files come from outside: the iteration count is in the file, and the default ceiling is about nine seconds of CPU.
- A successful `gcert_pkcs8_decrypt` is not an integrity check. PBES2 with a CBC cipher, and every PBES1 scheme, has no MAC.
- A zero length is success and does not read the pointers. A null pointer with a positive length is `GCERT_ERR_INVALID`.
- `gcert_result_string` returns one of a fixed set of static strings. There is no function that prints a key.
- `gcert_selftest` runs a known answer for DER and a PEM round trip. The parsers with no writer have their known answers in the vector files.

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

- **`der.h`**, **`pem.h`** — the two encodings everything else sits on.
- **`pkcs8.h`**, **`pkcs12.h`** — a private key, and an archive holding one.
- **`x509.h`**, **`crl.h`**, **`ocsp.h`** — a certificate, a revocation list, and a response.
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

The code is `security`'s certificate code as it stood at `security` commit
`7c810c2`, moved without a change in behaviour: the same sources with the
prefix changed, the same tests and fixtures, the same fuzz corpora, the same
vector files. `make test` is 72 tests and nine gates, `make test-asan` and
`make test-valgrind` are clean, `make check-oracle` agrees with OpenSSL 3.5.7,
and every fuzz harness runs from its seed without a trap.

What differs from `security`: the result type is `GCERT_Result`, with its own
conversion from `GSEC_Result` and a test that the two enums stay in step;
`GCERT_Limits` holds the one cap that moved (`max_pbe_iterations`); and
`security`'s constant-time gate is not carried over, because it drives
`gsec_equal` and the primitives and none of the code that moved is among them.
`pbes2.c` has a `GCERT_CT_TEST` branch around its padding check that nothing
drives under memcheck, which was true in `security` too and is recorded in
`notes/certificate/` in the workspace as work to do.

Planned, in the order it is planned, in the workspace's `planning/tls.md`: a
trust store that holds many anchors and reads the operating system's, chain
building, name verification as RFC 9525 has it (including a minimum label
count for a wildcard), peer identity extraction for mutual TLS, revocation
policy over the bytes this library parses, and key loading that returns a
signing object.

The Windows branches ran once, on 2026-10-06: the workspace's
`tools/xwin/certificate.sh` cross-builds this library's DLL and archive with its
own Makefile and runs all 72 tests under wine, and requires a planted defect to
fail the same run. That is not a Windows machine. It did find one defect that
Linux did not (a test comparing two enums, in a template from a system header,
which GCC does not report), and it has not run `GCERT_API`'s dllimport arm,
`make install` into `/mingw64`, or real MSYS2; the Makefile's `TODO(windows)`
marker says which.

## License

LGPL-3.0-only. See [COPYING.LESSER](COPYING.LESSER) for the license, and
[COPYING](COPYING) for the GPL text it is written as additional permissions
on top of.

To report a vulnerability, see [SECURITY.md](SECURITY.md), which also lists
the behaviour that is deliberate.

Contributions are not being accepted at this time; see
[CONTRIBUTING.md](CONTRIBUTING.md) for what is useful instead.
