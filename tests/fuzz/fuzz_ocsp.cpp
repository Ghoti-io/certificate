/**
 * @file
 *
 * libFuzzer harness for OCSP parsing.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstddef>
#include <cstdint>

#include <ghoti.io/certificate/ocsp.h>


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
  GCERT_Ocsp ocsp;
  GCERT_Result result;

  if (size > GCERT_X509_DER_MAX) {
    size = GCERT_X509_DER_MAX;
  }
  result = gcert_ocsp_parse(data, size, &ocsp);
  if (result != GCERT_OK && result != GCERT_ERR_CORRUPT &&
      result != GCERT_ERR_UNSUPPORTED && result != GCERT_ERR_LIMIT &&
      result != GCERT_ERR_INVALID) {
    __builtin_trap();
  }
  {
    GCERT_Ocsp twice;
    if (gcert_ocsp_parse(data, size, &twice) != result) {
      __builtin_trap();
    }
  }
  if (result == GCERT_OK) {
    inside(data, size, ocsp.tbs, ocsp.tbs_len);
    inside(data, size, ocsp.responses, ocsp.responses_len);
  }
  return 0;
}
