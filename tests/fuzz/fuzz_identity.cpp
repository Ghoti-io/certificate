/**
 * @file
 *
 * libFuzzer harness for identity.h.
 *
 * The first byte picks what the rest is: a subjectAltName's content (wrapped
 * here), or a Name read for each attribute kind and index. Every value a call
 * returns has to lie inside the bytes it was given, the walk has to end, and
 * the entries it reports have to be the same on a second walk.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#include <ghoti.io/certificate/identity.h>

static void inside(const uint8_t * lo, size_t n, const unsigned char * p, size_t len) {
  if (len != 0 && (p < lo || p > lo + n || len > static_cast<size_t>(lo + n - p))) {
    __builtin_trap();
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
  if (size == 0) {
    return 0;
  }
  const bool san_mode = (data[0] & 1) != 0;
  const uint8_t * rest = data + 1;
  size_t n = size - 1;

  if (!san_mode) {
    for (int a = 1; a <= GCERT_ATTR_DOMAIN_COMPONENT; a++) {
      for (size_t i = 0; i < 3; i++) {
        const unsigned char * v = nullptr;
        size_t len = 0;
        GCERT_Result r = gcert_x509_name_attr(rest, n, static_cast<GCERT_NameAttr>(a), i, &v, &len);
        if (r != GCERT_OK && r != GCERT_ERR_FORMAT && r != GCERT_ERR_UNSUPPORTED &&
            r != GCERT_ERR_CORRUPT) {
          __builtin_trap();
        }
        if (r == GCERT_OK) {
          inside(rest, n, v, len);
        }
      }
    }
    return 0;
  }

  std::vector<unsigned char> san;
  san.push_back(0x30);
  if (n < 128) {
    san.push_back(static_cast<unsigned char>(n));
  } else {
    san.push_back(0x82);
    san.push_back(static_cast<unsigned char>(n >> 8));
    san.push_back(static_cast<unsigned char>(n));
  }
  san.insert(san.end(), rest, rest + n);
  GCERT_X509 cert;
  std::memset(&cert, 0, sizeof cert);
  cert.san = san.data();
  cert.san_len = san.size();

  std::vector<std::pair<unsigned, size_t>> first;
  GCERT_Result last = GCERT_OK;
  size_t cursor = 0;
  for (size_t steps = 0;; steps++) {
    unsigned choice = 99;
    const unsigned char * v = nullptr;
    size_t len = 0;
    if (steps > san.size()) {
      __builtin_trap();   /* an entry costs at least two bytes; the walk must end */
    }
    last = gcert_x509_san_next(&cert, &cursor, &choice, &v, &len);
    if (last != GCERT_OK) {
      break;
    }
    if (choice > GCERT_SAN_REGISTERED_ID) {
      __builtin_trap();
    }
    inside(san.data(), san.size(), v, len);
    first.push_back({choice, len});
  }
  if (last != GCERT_ERR_FORMAT && last != GCERT_ERR_CORRUPT) {
    __builtin_trap();
  }
  /* Again, from the start, and the same entries and the same ending. */
  cursor = 0;
  for (size_t i = 0;; i++) {
    unsigned choice = 99;
    const unsigned char * v = nullptr;
    size_t len = 0;
    GCERT_Result r = gcert_x509_san_next(&cert, &cursor, &choice, &v, &len);
    if (r != GCERT_OK) {
      if (r != last || i != first.size()) {
        __builtin_trap();
      }
      break;
    }
    if (i >= first.size() || first[i].first != choice || first[i].second != len) {
      __builtin_trap();
    }
  }
  return 0;
}
