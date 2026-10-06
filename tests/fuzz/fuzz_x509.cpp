/**
 * @file
 *
 * libFuzzer harness for X.509 parse and hostname matching.
 *
 * Path validation is not run here. It signs nothing and it allocates
 * nothing beyond the result struct.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstddef>
#include <cstdint>

#include <ghoti.io/certificate/x509.h>


/* A view a parser returned has to point into the bytes it was given. NULL with
 * a zero length is how an absent field is spelled. */
static void inside(const uint8_t * data, size_t size, const void * view,
    size_t view_len) {
  const uint8_t * p = (const uint8_t *)view;

  if (p == nullptr) {
    if (view_len != 0) {
      __builtin_trap();
    }
    return;
  }
  if (p < data || p > data + size || view_len > (size_t)(data + size - p)) {
    __builtin_trap();
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
  GCERT_X509 cert;
  GCERT_Result result;

  if (size > GCERT_X509_DER_MAX) {
    size = GCERT_X509_DER_MAX;
  }
  result = gcert_x509_parse(data, size, &cert);
  if (result != GCERT_OK && result != GCERT_ERR_CORRUPT &&
      result != GCERT_ERR_UNSUPPORTED && result != GCERT_ERR_LIMIT &&
      result != GCERT_ERR_INVALID) {
    __builtin_trap();
  }
  if (result == GCERT_OK && size > 0) {
    GCERT_Result again = gcert_x509_hostname(&cert, (const char *)data,
        size > 64 ? 64 : size);
    if (again != GCERT_OK && again != GCERT_ERR_MISMATCH &&
        again != GCERT_ERR_INVALID) {
      __builtin_trap();
    }
  }
  /* Two invariants, because "it did not crash" is a weak thing to learn from
   * millions of inputs. The status is a function of the bytes, and every view
   * a successful parse returns lies inside the buffer it was given - which is
   * what the header promises and what a stale pointer would quietly break. */
  {
    GCERT_X509 twice;
    if (gcert_x509_parse(data, size, &twice) != result) {
      __builtin_trap();
    }
  }
  if (result == GCERT_OK) {
    inside(data, size, cert.tbs, cert.tbs_len);
    inside(data, size, cert.issuer, cert.issuer_len);
    inside(data, size, cert.subject, cert.subject_len);
    inside(data, size, cert.san, cert.san_len);
    inside(data, size, cert.name_constraints, cert.name_constraints_len);
    inside(data, size, cert.n, cert.n_len);
    inside(data, size, cert.e, cert.e_len);
    inside(data, size, cert.point, cert.point_len);
    /* sig is the exception the header names: an ECDSA signature is copied
     * into the result, so it points at cert, not at data. */
    if (cert.sig_key == GCERT_X509_RSA || cert.sig_key == GCERT_X509_ED25519) {
      inside(data, size, cert.sig, cert.sig_len);
    }
  }
  return 0;
}
