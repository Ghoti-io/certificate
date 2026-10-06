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
- **Revocation is the caller's.** `gcert_x509_path` does not fetch a CRL or an
  OCSP response, and does not check one it was not given.
- **Freshness is the caller's.** `gcert_ocsp_status` reports what the response
  says; comparing `this_update` and `next_update` against a clock is the
  caller's job, and a replayed response is a caller bug rather than a library
  one.
- **`gcert_x509_path` takes one anchor and compares ASCII names.** A set of
  anchors, and internationalised names, are the caller's until the library
  grows them.

## Things that are not deliberate

Worth a report, and the shapes most likely to matter here:

- Any read or write outside a buffer, including one only a sanitizer would
  see. `make test-asan`, `make test-valgrind` and `make fuzz` are the three
  that look for these; a case any of them misses is worth more than one they
  catch.
- A malformed certificate, CRL, OCSP response, PKCS#8 key or PKCS#12 archive
  that is *accepted*. `tests/unit/test_negative.cpp` is where a case like that
  belongs, and one that survives those sweeps is exactly the report wanted.
- A chain that `gcert_x509_path` validates and should not.
- A password-based derivation that runs longer than `GCERT_Limits` says it may.
- A secret left in a buffer the library owned after it returned.
