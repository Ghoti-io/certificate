# Design

`certificate` is the suite's library for the encodings a certificate and its
key travel in. It was the certificate half of `security` until 2026-10-06,
when the code was moved here without a change in behaviour (`security`
commit `7c810c2` is the last state it was in there). The prefix is `GCERT_` /
`gcert_`. The package is `ghoti.io-certificate-0`, the include path
`<ghoti.io/certificate/...>`. It depends on `cutil` and on `security`.

Why a library of its own, why now, and what comes next are in the workspace's
`planning/tls.md`. In short: the code had no dependent outside `security`, so
the extraction was as cheap as it would ever be; `archive`, `color` and `audio`
depend on `security` for hashes and AES and should not inherit X.509; and the
TLS library is written against this API rather than against a primitives
library that happens to hold a parser.

---

## 1. What has to be true of a call

| Property | How it is enforced |
| --- | --- |
| A malformed encoding is refused, not guessed | The parsers reject an indefinite length, a non-minimal length or tag, a truncated value, and a critical extension they do not understand. `tests/unit/test_negative.cpp` mutates good inputs at every position and requires a refusal or a specific, explained acceptance. |
| A wrong signature is a failure | A signature check returns `GCERT_ERR_MISMATCH`, never a boolean. `src/core/sec_result.h` is where the primitives' `GSEC_ERR_MISMATCH` becomes this library's, and `test_core.cpp` plants a conversion that maps it to success and requires the tests to notice. |
| The two result enums do not drift | `GCERT_Result` and `GSEC_Result` have the same members in the same order, and C converts between enums silently. The conversion is a switch, and a test checks that the counts agree, that every member maps to the member of the same name and number, and that a value in neither enum is `GCERT_ERR_INTERNAL`. |
| A file cannot ask for unbounded work | `GCERT_Limits::max_pbe_iterations` caps the password-based derivation a PKCS#8 or PKCS#12 file names, default 10,000,000 (about nine seconds). The count is in the file, so it is an attacker's number when the file is. |
| Nothing in the library prints a secret | `gcert_result_string` returns one of a fixed table of static strings. There is no `_dump` for a key. |
| Secret bytes are not compared with `memcmp` | `tools/check-secret.py` scans `src/`, including comments, and rejects `memcmp`, `bcmp`, `timingsafe_bcmp`, cutil's Mersenne Twister, a userspace device node, `RAND_bytes`, and the `printf` family. The scanner is run against a plant of its own. |
| The exploit mitigations are on | `check-harden`, as in `security`. |
| A declaration has a judge | `check-foundation` reads the registry in `tools/oracle/primitives.txt` and the headers. An `implemented` row needs a declaration, a vector file hashed in `tests/data/vectors/MANIFEST`, and an entry in the oracle probe's coverage set; the planted `ssh_cert` row is `excluded` and a declaration for it must be rejected. |

A zero length is success and does not read the pointers. A null pointer with a
positive length is `GCERT_ERR_INVALID`, before any load.

## 2. What is implemented

| Function | Contract |
| --- | --- |
| `gcert_der_tlv` | One DER value, viewed inside the caller's buffer, with no allocation. An indefinite length, a non-minimal length or tag, and a truncated value are `GCERT_ERR_CORRUPT`. Bytes after the value are not an error; the caller advances by `total_len`. |
| `gcert_pem_decode`, `gcert_pem_encode` | The first PEM block in, and one block out at 64 characters to the line. Neither output is NUL-terminated, and the decoded bytes are not a string. |
| `gcert_pkcs8_parse`, `gcert_pkcs8_decrypt` | An unencrypted PrivateKeyInfo, and an EncryptedPrivateKeyInfo under PBES2 or PBES1. The result is the RSA factors or the elliptic scalar. An Ed25519 seed is the raw 32 bytes or one octet string around them, which is what OpenSSL and RFC 8410 write. The password bytes are used as given. |
| `gcert_pkcs12_open` | A PFX, RFC 7292, and MacData is required rather than optional: an archive with none is `GCERT_ERR_UNSUPPORTED`, because nothing about it is authenticated and any success would read as approval. The MAC turns the UTF-8 password into the BMP string with the trailing two zero bytes; a PBES2 or PBES1 bag uses the UTF-8 bytes themselves. A wrong password fails the MAC. The key and the certificates are views of the caller's scratch buffer, or of the input where a bag was not encrypted. |
| `gcert_x509_parse`, `gcert_x509_signed_by` | One certificate, viewed in the caller's buffer, and its signature checked with the primitives. A critical extension this parser does not understand is rejected. certificatePolicies is read and not enforced. |
| `gcert_x509_path`, `gcert_x509_purpose`, `gcert_x509_hostname` | A chain the caller arranged leaf, intermediates, anchor, at a Unix second, with both ends of each validity period inclusive. It refuses what RFC 5280 does not require a validator to refuse, because the caller of this function is making a trust decision: a link signed with MD5 or SHA-1, an RSA key below `GCERT_X509_RSA_MIN_BITS`, and an anchor outside its own dates - section 6.1 treats the anchor as trusted input, and an expired root is a thing that happens. `purpose`, when it is not 0, is one `GCERT_X509_EKU_*` bit the leaf's extendedKeyUsage must permit; `gcert_x509_purpose` is the same test for a caller that would rather apply it itself. A certificate with no extendedKeyUsage permits everything, one naming anyExtendedKeyUsage permits everything, and one naming only purposes this parser has no bit for permits nothing. An anchor with no basicConstraints is trusted as a CA, and one that says it is not a CA is rejected. Name constraints on dNSName and directoryName are applied and any other type is `GCERT_ERR_UNSUPPORTED`. The path does not check revocation. A wildcard is only the entire leftmost label. |
| `gcert_x509_issue` | A certificate built and signed with P-256, P-384, Ed25519, or RSA. The result parses with `gcert_x509_parse`. A failure wipes the output. |
| `gcert_crl_parse`, `gcert_crl_signed_by`, `gcert_crl_contains` | A revocation list, its signature, and a serial lookup where a hit is `GCERT_OK` and an absent serial is `GCERT_ERR_MISMATCH`. Fetching the list stays with the caller. |
| `gcert_ocsp_parse`, `gcert_ocsp_signed_by`, `gcert_ocsp_status` | A basic response, RFC 6960. The caller supplies the issuer-name and issuer-key hashes; a CertID that is not in the response is `GCERT_ERR_MISMATCH`. `GCERT_Ocsp::produced_at` and `GCERT_Ocsp_Single`'s `this_update` and `next_update` are what make the response's age visible. Fetching the response, comparing those times against a clock, and a responder the issuer delegated to all stay with the caller; a delegated response fails closed. |
| `gcert_selftest` | A DER header and a PEM round trip. The parsers with no writer are in `check_foundation.py`'s `SELFTEST_EXCLUDED`, with the reason: their known answers are fixtures and vector files. |
| `gcert_allocator_default`, `gcert_limits_default`, `gcert_result_string`, `gcert_version_string`, `gcert_version_number` | As in every library of the suite. |

The public umbrella is `certificate.h`.

## 3. The stack an embedder has to have

Everything works in automatic storage. Measured with `-fstack-usage` at `-O2`
in `security` before the move: `gcert_x509_path` 5,712 bytes in one frame. The
signature check under it is `security`'s, and the deepest chain through a
private-key operation is recorded in `security`'s design document; issuance
signs, so it is on that chain. A thread with a small stack that issues
certificates needs to read that number.

## 4. The corpus and the oracle

Known-answer files under `tests/data/vectors/` are scored by the unit tests
with no container, and `MANIFEST` is their SHA-256. The container is OpenSSL
3.5.7, built here and pinned by the base digest and the apt version.
`make check-oracle` requires the image; what it compares is
[oracles.md](oracles.md). A difference fails the target.

The fuzz targets under `tests/fuzz/` are libFuzzer with ASan and UBSan, one for
each parser. The corpora moved with them. `make fuzz-run-<name>` hands that
directory to libFuzzer as its corpus, so a campaign writes its own units there
too.

## 5. Departures from the suite conventions

Recorded in `CONVENTIONS.md` section 13.

- No `GCERT_Stream`. A caller already holds the buffer.
- No `_dump` of a secret.
- `GCERT_ERR_MISMATCH` is added to the result vocabulary, for the same reason `security` added it: a signature that does not match is the answer a verifier exists to give.
- No constant-time gate yet. See section 7.

## 6. What this library does not hold

A handshake, a socket, a fetch of a CRL or an OCSP response, and an algorithm.
The algorithms are `security`'s, and a new one needs a named caller in writing
there.

## 7. What is next

The work is listed in the workspace's `planning/tls.md` and is not done:

1. A trust store holding many anchors, read from caller bytes, from a PEM
   bundle, and from the operating system. `gcert_x509_path` takes exactly one
   anchor today.
2. Chain building from a pool of certificates, with a cap on the search.
3. Name verification as RFC 9525 has it: DNS names, IP addresses, URI and e-mail
   identities, and a minimum label count for a wildcard, which
   `notes/security/AUDIT.md` lists as open for the function that moved.
4. Peer identity extraction for mutual TLS.
5. Revocation policy over the bytes this library parses: freshness, the issuer
   of the response, and a stated treatment of an unavailable one.
6. Key loading that returns a signing object.
7. The two open audit items in the code that moved: the untestable issuer-key
   check (`sig_key`), and `host_ok` shadowing.
8. A constant-time gate for `pbes2.c`. The padding check there has a
   `GCERT_CT_TEST` branch that marks its result defined, and nothing drives it
   under memcheck: `security`'s `tools/ct/clean.c` calls `gsec_equal` and the
   primitives and none of the code that moved. A harness that decrypts a PBES2
   fixture with poisoned plaintext, and a planted leak that it must see, is the
   missing half.
