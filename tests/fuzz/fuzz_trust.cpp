/**
 * @file
 *
 * libFuzzer harness for the trust store.
 *
 * The input is loaded as a PEM bundle, and its first bytes also as a single
 * DER certificate, under small limits so the limit arms are reached. The
 * store's own counts must agree with what the calls reported, every anchor
 * must parse again from the bytes the store holds, and the issuer search must
 * report the same candidates when asked twice and in a short buffer.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstddef>
#include <cstdint>
#include <cstring>

#include <ghoti.io/certificate/trust.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
  GCERT_Limits limits;
  gcert_limits_default(&limits);
  limits.max_trust_anchors = 5;
  GCERT_TrustStore * s = nullptr;
  if (gcert_trust_new(nullptr, &limits, &s) != GCERT_OK) {
    return 0;
  }
  size_t added = 0;
  size_t skipped = 0;
  GCERT_Result r = gcert_trust_add_pem(s, data, size, &added, &skipped);
  if (r != GCERT_OK && r != GCERT_ERR_LIMIT) {
    __builtin_trap();
  }
  if (added != gcert_trust_count(s)) {
    __builtin_trap();
  }
  if (r == GCERT_ERR_LIMIT && gcert_trust_count(s) != 5) {
    __builtin_trap();
  }
  /* The same bytes as one DER certificate. */
  GCERT_Result d = gcert_trust_add_der(s, data, size);
  if (d != GCERT_OK && d != GCERT_ERR_CORRUPT && d != GCERT_ERR_UNSUPPORTED &&
      d != GCERT_ERR_LIMIT && d != GCERT_ERR_INVALID) {
    __builtin_trap();
  }
  if (gcert_trust_count(s) > 5) {
    __builtin_trap();
  }
  for (size_t i = 0; i < gcert_trust_count(s); i++) {
    const unsigned char * der;
    size_t n;
    GCERT_X509 x;
    if (gcert_trust_get(s, i, &der, &n) != GCERT_OK ||
        gcert_x509_parse(der, n, &x) != GCERT_OK) {
      __builtin_trap();
    }
    size_t idx[8];
    size_t count = 0;
    size_t one[1];
    size_t count2 = 0;
    if (gcert_trust_find_issuers(s, &x, idx, 8, &count) != GCERT_OK ||
        gcert_trust_find_issuers(s, &x, one, 1, &count2) != GCERT_OK || count != count2 ||
        (count != 0 && one[0] != idx[0])) {
      __builtin_trap();
    }
    for (size_t k = 0; k < count && k < 8; k++) {
      if (idx[k] >= gcert_trust_count(s)) {
        __builtin_trap();
      }
    }
  }
  gcert_trust_free(s);
  return 0;
}
