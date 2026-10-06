/**
 * @file
 *
 * libFuzzer harness for unencrypted PKCS#8.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstddef>
#include <cstdint>

#include <ghoti.io/certificate/pkcs8.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
  GCERT_Pkcs8 key;
  GCERT_Result result = gcert_pkcs8_parse(data, size, &key);
  if (result != GCERT_OK && result != GCERT_ERR_CORRUPT &&
      result != GCERT_ERR_UNSUPPORTED && result != GCERT_ERR_INVALID) {
    __builtin_trap();
  }
  {
    GCERT_Pkcs8 twice;
    if (gcert_pkcs8_parse(data, size, &twice) != result) {
      __builtin_trap();
    }
  }
  return 0;
}
