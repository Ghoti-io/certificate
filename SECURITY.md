# Reporting a vulnerability

Email **pennycuff.c@gmail.com** with `ghoti.io-certificate` in the subject. A
proof of concept, the commit you tested, and the platform are the three
things that make a report actionable fastest.

There is no bug bounty and no formal service level. What there is: an
acknowledgement, a fix or an explanation of why the behaviour is what it is,
and credit in the commit message unless you would rather not have it.

Please do report anything in the list below. A report is not wasted for being
one of these; they are listed because they are the ones most likely to be
mistaken for intended behaviour.

## Things that are deliberate

Not vulnerabilities, so a report about them will get an explanation rather
than a fix. All of them are in the headers as well; this list is here so that
the answer arrives before the effort does.

- **Old schemes are opened.** PKCS#12 and PBES1 name DES, RC2, RC4, MD5 and
  SHA-1, so a file that uses them can be read. The primitives are
  `security`'s, and that library says what each is. `gcert_x509_path` refuses
  MD5 and SHA-1 in a chain, which is the place where the choice is a trust
  decision rather than a caller's.
- **A successful `gcert_pkcs8_decrypt` is not an integrity check.** PBES2 with
  a CBC cipher, and every PBES1 scheme, has no MAC. See pkcs8.h.
- **Revocation needs evidence the caller fetched.** `gcert_x509_path` and
  `gcert_chain_build` check no CRL or OCSP response. `gcert_crl_check` and
  `gcert_ocsp_check` check what they are given, and `gcert_revocation_verdict`
  **refuses when there is none**, unless the policy says soft fail. An answer
  that is not about this issuer, is not signed by someone allowed to sign it,
  or is past `nextUpdate` is not evidence, and is reported as unusable and not
  as good. There is no OCSP nonce: a stapled response needs none, and a fetched
  one is the caller's to protect.
- **A chain is not a name.** A path that validates says the certificate is
  good, not that it is for the host you meant. `gcert_x509_verify_host` is the
  other half, and a client needs both.
- **There is no public-suffix list.** `*.co.uk` matches `a.co.uk`, as it does
  in OpenSSL. The label count rule stops `*.com`.
- **The common name is not a host name.** It is read only if the caller sets
  `common_name_fallback`, which RFC 9525 removed.
- **A trust bundle is read leniently.** What this library cannot parse is
  counted in `skipped` and the load goes on, because an operating system's
  bundle always has a few. Check the count if you need to be strict.
- **The operating system's list is enumerated, not trusted blindly.** What the
  platform keeps beside it (distrust dates, per-purpose restrictions) is not
  carried over, and the path validation is this library's own.
- **Names compare ASCII.** A name that is not is `GCERT_ERR_INVALID`; turning
  an internationalised name into its A-label is the caller's.
- **A key in memory is not hidden.** `GCERT_Key` wipes its bytes on free; it is
  not locked and not guarded against a process that can read memory.

## Things that are not deliberate

Worth a report, and the shapes most likely to matter here:

- Any read or write outside a buffer, including one only a sanitizer would
  see. `make test-asan`, `make test-valgrind` and `make fuzz` are the three
  that look for these; a case any of them misses is worth more than one they
  catch.
- A malformed certificate, CRL, OCSP response, PKCS#8 key or PKCS#12 archive
  that is *accepted*. `tests/unit/test_negative.cpp` is where a case like that
  belongs, and one that survives those sweeps is exactly the report wanted.
- A chain that `gcert_x509_path` validates and should not, or one that
  `gcert_chain_build` returns that `gcert_x509_path` would refuse (`fuzz_chain`
  checks exactly that).
- A name that `gcert_x509_verify_*` matches and should not, or a malformed
  `subjectAltName` that is accepted or silently shortened.
- A password-based derivation that runs longer than `GCERT_Limits` says it may.
- A secret left in a buffer the library owned after it returned, including a
  private key after `gcert_key_free` or a failed load.
