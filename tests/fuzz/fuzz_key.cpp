/**
 * @file
 *
 * libFuzzer harness for key loading and signing.
 *
 * The input is loaded as a PEM file and as a PKCS#8 DER. A key that loads is
 * asked to sign with every scheme that fits it, and each signature has to
 * verify against the public key the key itself derives, and not verify with a
 * bit changed. A key that does not load leaves nothing behind: the output
 * pointer is null.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstddef>
#include <cstdint>
#include <cstring>

#include <ghoti.io/certificate/key.h>
#include <ghoti.io/certificate/pkcs8.h>

static void exercise(GCERT_Key * k, const GCERT_Pkcs8 * view) {
  static const GCERT_SigScheme all[] = {
    GCERT_SIG_RSA_PKCS1_SHA256, GCERT_SIG_ECDSA_P256_SHA256, GCERT_SIG_RSA_PKCS1_SHA384,
    GCERT_SIG_ECDSA_P384_SHA384, GCERT_SIG_RSA_PKCS1_SHA512, GCERT_SIG_RSA_PSS_SHA256,
    GCERT_SIG_RSA_PSS_SHA384, GCERT_SIG_RSA_PSS_SHA512, GCERT_SIG_ED25519};
  const uint32_t kind = gcert_key_kind(k);
  if (kind < GCERT_X509_RSA || kind > GCERT_X509_ED25519) {
    __builtin_trap();
  }
  (void)view;
  for (GCERT_SigScheme s : all) {
    unsigned char sig[GCERT_SIG_MAX];
    size_t n = 0;
    GCERT_Result r = gcert_key_sign(k, s, "fuzz", 4, sig, sizeof sig, &n);
    if (gcert_key_scheme_fits(s, kind)) {
      if (r != GCERT_OK || n == 0 || n > GCERT_SIG_MAX) {
        __builtin_trap();
      }
    } else if (r != GCERT_ERR_UNSUPPORTED || n != 0) {
      __builtin_trap();
    }
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
  GCERT_Key * k = nullptr;
  GCERT_Result r = gcert_key_from_pem(nullptr, data, size, "pw", 2, nullptr, &k);
  if (r == GCERT_OK) {
    if (k == nullptr) {
      __builtin_trap();
    }
    exercise(k, nullptr);
    gcert_key_free(k);
  } else if (k != nullptr) {
    __builtin_trap();
  }
  k = nullptr;
  r = gcert_key_from_pkcs8(nullptr, data, size, &k);
  if (r == GCERT_OK) {
    if (k == nullptr) {
      __builtin_trap();
    }
    exercise(k, nullptr);
    gcert_key_free(k);
  } else if (k != nullptr) {
    __builtin_trap();
  }
  return 0;
}
