/**
 * @file
 *
 * libFuzzer harness for path building.
 *
 * The input is a list of certificates, each preceded by a two-byte length. The
 * first is the trust anchor, the second the leaf, and the rest the pool. The
 * limits are small so that the budget is reached.
 *
 * What is checked is the property the design rests on, not only that nothing
 * crashes: whenever gcert_chain_build says a path was found, handing that
 * exact path to gcert_x509_path accepts it. The builder chooses what to ask;
 * it must never be able to accept what the verdict would not. A refusal says
 * why, and the reason has to be one of the defined ones.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstddef>
#include <cstdint>
#include <vector>

#include <ghoti.io/certificate/chain.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
  std::vector<std::pair<const uint8_t *, size_t>> certs;
  size_t pos = 0;
  while (pos + 2 <= size && certs.size() < 12) {
    size_t n = (static_cast<size_t>(data[pos]) << 8) | data[pos + 1];
    pos += 2;
    if (n > size - pos) {
      n = size - pos;
    }
    certs.push_back({data + pos, n});
    pos += n;
  }
  if (certs.size() < 2) {
    return 0;
  }
  GCERT_Limits limits;
  gcert_limits_default(&limits);
  limits.max_chain_pool = 8;
  limits.max_chain_attempts = 64;
  GCERT_TrustStore * s = nullptr;
  if (gcert_trust_new(nullptr, &limits, &s) != GCERT_OK) {
    return 0;
  }
  (void)gcert_trust_add_der(s, certs[0].first, certs[0].second);
  const void * pool[10];
  size_t lens[10];
  size_t pool_count = 0;
  for (size_t i = 2; i < certs.size() && pool_count < 10; i++) {
    pool[pool_count] = certs[i].first;
    lens[pool_count] = certs[i].second;
    pool_count++;
  }
  /* A time inside the window of the leaf when it parses, so the search is
   * reached rather than refused on dates every time. */
  int64_t t = 1700000000;
  GCERT_X509 leaf;
  if (certs[1].second != 0 && gcert_x509_parse(certs[1].first, certs[1].second, &leaf) == GCERT_OK) {
    t = leaf.not_before + (leaf.not_after - leaf.not_before) / 2;
  }
  GCERT_Chain c;
  GCERT_Result r = gcert_chain_build(s, certs[1].first, certs[1].second, pool, lens,
      pool_count, t, 0, &limits, &c);
  if (r != GCERT_OK && r != GCERT_ERR_MISMATCH && r != GCERT_ERR_LIMIT &&
      r != GCERT_ERR_CORRUPT && r != GCERT_ERR_UNSUPPORTED && r != GCERT_ERR_INVALID) {
    __builtin_trap();
  }
  if (c.failure > GCERT_CHAIN_REJECTED) {
    __builtin_trap();
  }
  if (r == GCERT_OK) {
    const void * mids[GCERT_X509_CHAIN_MAX];
    size_t mlens[GCERT_X509_CHAIN_MAX];
    if (c.failure != GCERT_CHAIN_NONE || c.mid_count > GCERT_X509_CHAIN_MAX ||
        c.anchor >= gcert_trust_count(s)) {
      __builtin_trap();
    }
    for (size_t i = 0; i < c.mid_count; i++) {
      if (c.mid[i] >= pool_count) {
        __builtin_trap();
      }
      mids[i] = pool[c.mid[i]];
      mlens[i] = lens[c.mid[i]];
    }
    const unsigned char * a;
    size_t an;
    if (gcert_trust_get(s, c.anchor, &a, &an) != GCERT_OK ||
        gcert_x509_path(certs[1].first, certs[1].second, mids, mlens, c.mid_count, a, an, t,
            0) != GCERT_OK) {
      __builtin_trap();
    }
  } else if (c.failure == GCERT_CHAIN_NONE && r == GCERT_ERR_MISMATCH) {
    __builtin_trap();  /* a refusal with no reason */
  }
  gcert_trust_free(s);
  return 0;
}
