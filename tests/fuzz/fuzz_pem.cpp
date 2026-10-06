/**
 * @file
 *
 * libFuzzer harness for PEM.
 *
 * Decode accepts one block or rejects it. Encode of a short prefix must
 * round-trip when the label is fixed.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstddef>
#include <cstdint>

#include <ghoti.io/certificate/pem.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
  unsigned char der[256];
  char armour[512];
  char label[80];
  size_t n = 0;
  GCERT_Result result;

  result = gcert_pem_decode(data, size, der, sizeof der, &n, label, sizeof label);
  if (result != GCERT_OK && result != GCERT_ERR_CORRUPT &&
      result != GCERT_ERR_LIMIT && result != GCERT_ERR_INVALID) {
    __builtin_trap();
  }
  if (size > 48) {
    return 0;
  }
  result = gcert_pem_encode("TEST", data, size, armour, sizeof armour, &n);
  if (result != GCERT_OK) {
    __builtin_trap();
  }
  result = gcert_pem_decode(armour, n, der, sizeof der, &n, nullptr, 0);
  if (result != GCERT_OK || n != size) {
    __builtin_trap();
  }
  return 0;
}
