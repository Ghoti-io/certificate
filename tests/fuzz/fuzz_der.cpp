/**
 * @file
 *
 * libFuzzer harness for the strict DER reader.
 *
 * A buffer is corrupt or it is one value. Anything else is a bug.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstddef>
#include <cstdint>

#include <ghoti.io/certificate/der.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
  GCERT_Der view;
  GCERT_Result result = gcert_der_tlv(data, size, &view);
  if (result != GCERT_OK && result != GCERT_ERR_CORRUPT) {
    __builtin_trap();
  }
  if (result == GCERT_OK && view.total_len > size) {
    __builtin_trap();
  }
  return 0;
}
