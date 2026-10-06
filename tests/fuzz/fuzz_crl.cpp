/**
 * @file
 *
 * libFuzzer harness for CRL parsing.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstddef>
#include <cstdint>

#include <ghoti.io/certificate/crl.h>


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
  GCERT_Crl crl;
  GCERT_Result result;
  GCERT_Result parsed;
  unsigned char serial[1] = {0x01};

  if (size > GCERT_X509_DER_MAX) {
    size = GCERT_X509_DER_MAX;
  }
  result = gcert_crl_parse(data, size, &crl);
  if (result != GCERT_OK && result != GCERT_ERR_CORRUPT &&
      result != GCERT_ERR_UNSUPPORTED && result != GCERT_ERR_LIMIT &&
      result != GCERT_ERR_INVALID) {
    __builtin_trap();
  }
  parsed = result;
  if (parsed == GCERT_OK) {
    result = gcert_crl_contains(&crl, serial, 1);
    if (result != GCERT_OK && result != GCERT_ERR_MISMATCH &&
        result != GCERT_ERR_CORRUPT && result != GCERT_ERR_INVALID) {
      __builtin_trap();
    }
  }
  {
    /* `parsed`, not `result`: the lookup above overwrites `result`, and
     * comparing the second parse against a lookup's answer is how this
     * invariant reported a non-deterministic parser that was nothing of the
     * kind. */
    GCERT_Crl twice;
    if (gcert_crl_parse(data, size, &twice) != parsed) {
      __builtin_trap();
    }
  }
  if (parsed == GCERT_OK) {
    inside(data, size, crl.tbs, crl.tbs_len);
    inside(data, size, crl.issuer, crl.issuer_len);
    inside(data, size, crl.revoked, crl.revoked_len);
  }
  return 0;
}
