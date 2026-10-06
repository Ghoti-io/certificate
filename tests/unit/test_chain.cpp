/**
 * @file
 *
 * Path building (chain.h): the pool in any order, extras, a missing link, a
 * re-issued intermediate that has expired, a cycle, and a pool built to make
 * the search cost more than it is allowed to.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "pki.h"

#include <cstdlib>
#include <string>
#include <vector>

namespace {

using pki::Bytes;
using pki::Key;

struct Pool {
  std::vector<Bytes> certs;
  std::vector<const void *> ptrs;
  std::vector<size_t> lens;
  void add(const Bytes & b) { certs.push_back(b); }
  void seal() {
    ptrs.clear();
    lens.clear();
    for (const Bytes & b : certs) {
      ptrs.push_back(b.data());
      lens.push_back(b.size());
    }
  }
};

struct Store {
  GCERT_TrustStore * s = nullptr;
  Store() { EXPECT_EQ(gcert_trust_new(nullptr, nullptr, &s), GCERT_OK); }
  ~Store() { gcert_trust_free(s); }
  void add(const Bytes & b) {
    ASSERT_EQ(gcert_trust_add_der(s, b.data(), b.size()), GCERT_OK);
  }
};

GCERT_Result build(const Store & st, const Bytes & leaf, Pool & pool, GCERT_Chain * out,
    int64_t t = pki::kNow, unsigned purpose = 0, const GCERT_Limits * limits = nullptr) {
  pool.seal();
  return gcert_chain_build(st.s, leaf.data(), leaf.size(),
      pool.certs.empty() ? nullptr : pool.ptrs.data(),
      pool.certs.empty() ? nullptr : pool.lens.data(), pool.certs.size(), t, purpose,
      limits, out);
}

/* What the builder returned must be what gcert_x509_path accepts: it is the
 * verdict, so this is checked on every success rather than in one test. */
void expect_path_agrees(const Store & st, const Bytes & leaf, const Pool & pool,
    const GCERT_Chain & c, int64_t t, unsigned purpose) {
  std::vector<const void *> mids;
  std::vector<size_t> lens;
  for (size_t i = 0; i < c.mid_count; i++) {
    mids.push_back(pool.ptrs[c.mid[i]]);
    lens.push_back(pool.lens[c.mid[i]]);
  }
  const unsigned char * a;
  size_t an;
  ASSERT_EQ(gcert_trust_get(st.s, c.anchor, &a, &an), GCERT_OK);
  EXPECT_EQ(gcert_x509_path(leaf.data(), leaf.size(), mids.data(), lens.data(),
      mids.size(), a, an, t, purpose), GCERT_OK);
}

/* root <- i1 <- i2 <- leaf */
struct Tree {
  Key kr = pki::key(20), k1 = pki::key(21), k2 = pki::key(22), kl = pki::key(1);
  Bytes root = pki::root("root", kr, 0x70);
  Bytes i1 = pki::signed_by("i1", k1, "root", kr, true, 0x71, 0x70);
  Bytes i2 = pki::signed_by("i2", k2, "i1", k1, true, 0x72, 0x71);
  Bytes leaf = pki::signed_by("leaf", kl, "i2", k2, false, 0, 0x72);
};

} /* namespace */

TEST(Chain, InOrderOutOfOrderAndWithExtras) {
  Tree t;
  Store st;
  st.add(t.root);
  Pool a;
  a.add(t.i2);
  a.add(t.i1);
  GCERT_Chain c;
  ASSERT_EQ(build(st, t.leaf, a, &c), GCERT_OK);
  EXPECT_EQ(c.mid_count, 2u);
  EXPECT_EQ(c.mid[0], 1u);  /* i1, which the root signed, first */
  EXPECT_EQ(c.mid[1], 0u);  /* i2, which signed the leaf, last */
  EXPECT_EQ(c.failure, GCERT_CHAIN_NONE);
  expect_path_agrees(st, t.leaf, a, c, pki::kNow, 0);

  Pool shuffled;
  Bytes stranger = pki::root("stranger", pki::key(30));
  Bytes stray = pki::signed_by("stray", pki::key(31), "stranger", pki::key(30), true);
  Bytes junk = {0x30, 0x03, 0x02, 0x01, 0x01};
  for (const Bytes * b : {&stranger, &t.i1, &junk, &t.root, &t.leaf, &stray, &t.i2, &t.i1}) {
    shuffled.add(*b);
  }
  Bytes empty;
  shuffled.add(empty);
  ASSERT_EQ(build(st, t.leaf, shuffled, &c), GCERT_OK);
  EXPECT_EQ(c.mid_count, 2u);
  EXPECT_EQ(shuffled.certs[c.mid[0]], t.i1);
  EXPECT_EQ(shuffled.certs[c.mid[1]], t.i2);
  expect_path_agrees(st, t.leaf, shuffled, c, pki::kNow, 0);
}

TEST(Chain, TheOrderGcertX509PathTakes) {
  /* Two intermediates, which no earlier test used: the order is the anchor's
   * side first, and the reverse is refused. */
  Tree t;
  const void * down[2] = {t.i1.data(), t.i2.data()};
  size_t down_lens[2] = {t.i1.size(), t.i2.size()};
  EXPECT_EQ(gcert_x509_path(t.leaf.data(), t.leaf.size(), down, down_lens, 2,
      t.root.data(), t.root.size(), pki::kNow, 0), GCERT_OK);
  const void * up[2] = {t.i2.data(), t.i1.data()};
  size_t up_lens[2] = {t.i2.size(), t.i1.size()};
  EXPECT_EQ(gcert_x509_path(t.leaf.data(), t.leaf.size(), up, up_lens, 2,
      t.root.data(), t.root.size(), pki::kNow, 0), GCERT_ERR_MISMATCH);
}

TEST(Chain, AnAnchorBelowTheRootEndsThePathThere) {
  Tree t;
  Store st;
  st.add(t.root);
  st.add(t.i1);  /* the store trusts an intermediate directly */
  Pool p;
  p.add(t.i2);
  p.add(t.i1);
  GCERT_Chain c;
  ASSERT_EQ(build(st, t.leaf, p, &c), GCERT_OK);
  EXPECT_EQ(c.mid_count, 1u);   /* i2 only: the shorter path */
  const unsigned char * der;
  size_t n;
  ASSERT_EQ(gcert_trust_get(st.s, c.anchor, &der, &n), GCERT_OK);
  EXPECT_EQ(Bytes(der, der + n), t.i1);
  expect_path_agrees(st, t.leaf, p, c, pki::kNow, 0);
}

TEST(Chain, MissingLinkAndUnknownRoot) {
  Tree t;
  Store st;
  st.add(t.root);
  GCERT_Chain c;
  Pool no_i1;
  no_i1.add(t.i2);
  EXPECT_EQ(build(st, t.leaf, no_i1, &c), GCERT_ERR_MISMATCH);
  EXPECT_EQ(c.failure, GCERT_CHAIN_UNKNOWN_ISSUER);
  EXPECT_EQ(c.mid_count, 0u);

  Pool none;
  EXPECT_EQ(build(st, t.leaf, none, &c), GCERT_ERR_MISMATCH);
  EXPECT_EQ(c.failure, GCERT_CHAIN_UNKNOWN_ISSUER);

  /* The full chain, to a root this store does not hold. The root the peer
   * sends is not trusted for being sent. */
  Store other;
  other.add(pki::root("other", pki::key(40)));
  Pool all;
  all.add(t.i2);
  all.add(t.i1);
  all.add(t.root);
  EXPECT_EQ(build(other, t.leaf, all, &c), GCERT_ERR_MISMATCH);
  EXPECT_EQ(c.failure, GCERT_CHAIN_UNKNOWN_ISSUER);
  /* ...and an empty store trusts nothing. */
  Store empty;
  EXPECT_EQ(build(empty, t.leaf, all, &c), GCERT_ERR_MISMATCH);
}

TEST(Chain, AnExpiredReissueIsSkippedForTheValidOne) {
  Tree t;
  Store st;
  st.add(t.root);
  pki::Spec old;
  old.subject = "i1";
  old.issuer = "root";
  old.subject_key = t.k1;
  old.signer = t.kr;
  old.ca = true;
  old.not_after = pki::kNow - pki::kDay;      /* the same key, expired yesterday */
  old.serial = 9;
  Bytes i1_old = pki::issue(old);
  pki::Spec future = old;
  future.not_before = pki::kNow + pki::kDay;
  future.not_after = pki::kNow + 90 * pki::kDay;
  future.serial = 10;
  Bytes i1_future = pki::issue(future);

  Pool both;
  both.add(t.i2);
  both.add(i1_old);
  both.add(i1_future);
  both.add(t.i1);
  GCERT_Chain c;
  ASSERT_EQ(build(st, t.leaf, both, &c), GCERT_OK);
  EXPECT_EQ(both.certs[c.mid[0]], t.i1);
  expect_path_agrees(st, t.leaf, both, c, pki::kNow, 0);

  Pool only_old;
  only_old.add(t.i2);
  only_old.add(i1_old);
  EXPECT_EQ(build(st, t.leaf, only_old, &c), GCERT_ERR_MISMATCH);
  EXPECT_EQ(c.failure, GCERT_CHAIN_EXPIRED);
  Pool only_future;
  only_future.add(t.i2);
  only_future.add(i1_future);
  EXPECT_EQ(build(st, t.leaf, only_future, &c), GCERT_ERR_MISMATCH);
  EXPECT_EQ(c.failure, GCERT_CHAIN_NOT_YET_VALID);

  /* The same pool, evaluated when the old reissue was in force. */
  ASSERT_EQ(build(st, t.leaf, only_old, &c, pki::kNow - 10 * pki::kDay), GCERT_OK);
}

TEST(Chain, ExpiredLeafAndExpiredAnchor) {
  Tree t;
  Store st;
  st.add(t.root);
  Pool p;
  p.add(t.i2);
  p.add(t.i1);
  GCERT_Chain c;
  EXPECT_EQ(build(st, t.leaf, p, &c, pki::kNow + 365 * pki::kDay), GCERT_ERR_MISMATCH);
  EXPECT_EQ(c.failure, GCERT_CHAIN_EXPIRED);
  EXPECT_EQ(build(st, t.leaf, p, &c, pki::kNow - 365 * pki::kDay), GCERT_ERR_MISMATCH);
  EXPECT_EQ(c.failure, GCERT_CHAIN_NOT_YET_VALID);

  pki::Spec r;
  r.subject = r.issuer = "root";
  r.subject_key = r.signer = t.kr;
  r.ca = true;
  r.not_after = pki::kNow - pki::kDay;
  Store expired;
  expired.add(pki::issue(r));
  EXPECT_EQ(build(expired, t.leaf, p, &c), GCERT_ERR_MISMATCH);
  EXPECT_EQ(c.failure, GCERT_CHAIN_EXPIRED);
}

TEST(Chain, WrongKeyIsABadSignatureNotAnUnknownIssuer) {
  Tree t;
  Store st;
  st.add(t.root);
  /* A certificate with i2's subject and a different key, so the name fits
   * and the signature does not. */
  Bytes impostor = pki::signed_by("i2", pki::key(50), "i1", t.k1, true);
  Pool only;
  only.add(impostor);
  only.add(t.i1);
  GCERT_Chain c;
  EXPECT_EQ(build(st, t.leaf, only, &c), GCERT_ERR_MISMATCH);
  EXPECT_EQ(c.failure, GCERT_CHAIN_BAD_SIGNATURE);
  Pool with_real;
  with_real.add(impostor);
  with_real.add(t.i1);
  with_real.add(t.i2);
  ASSERT_EQ(build(st, t.leaf, with_real, &c), GCERT_OK);
  EXPECT_EQ(with_real.certs[c.mid[1]], t.i2);
}

TEST(Chain, APolicyRefusalIsReportedAsOne) {
  /* i1 permits no further CA below it (pathLenConstraint 0), and the path
   * root <- i1 <- i2 <- leaf has one. The signatures are all good. */
  Key kr = pki::key(20), k1 = pki::key(21), k2 = pki::key(22);
  pki::Spec s1;
  s1.subject = "i1";
  s1.issuer = "root";
  s1.subject_key = k1;
  s1.signer = kr;
  s1.ca = true;
  s1.path_len = 0;
  Bytes i1 = pki::issue(s1);
  Bytes root = pki::root("root", kr);
  Bytes i2 = pki::signed_by("i2", k2, "i1", k1, true);
  Bytes leaf = pki::signed_by("leaf", pki::key(1), "i2", k2, false);
  Store st;
  st.add(root);
  Pool p;
  p.add(i2);
  p.add(i1);
  GCERT_Chain c;
  EXPECT_EQ(build(st, leaf, p, &c), GCERT_ERR_MISMATCH);
  EXPECT_EQ(c.failure, GCERT_CHAIN_REJECTED);
  /* More is known about a path that reached the anchor and was refused than
   * about a candidate whose key did not fit, so that is what is reported
   * when both happened. */
  Bytes impostor = pki::signed_by("i2", pki::key(50), "i1", k1, true);
  Pool mixed;
  mixed.add(impostor);
  mixed.add(i2);
  mixed.add(i1);
  EXPECT_EQ(build(st, leaf, mixed, &c), GCERT_ERR_MISMATCH);
  EXPECT_EQ(c.failure, GCERT_CHAIN_REJECTED);
  /* The refusal is gcert_x509_path's own, not a rule of the builder's. */
  const void * mids[2] = {p.ptrs[1], p.ptrs[0]};  /* i1 then i2 */
  size_t lens[2] = {p.lens[1], p.lens[0]};
  EXPECT_NE(gcert_x509_path(leaf.data(), leaf.size(), mids, lens, 2, root.data(),
      root.size(), pki::kNow, 0), GCERT_OK);
}

TEST(Chain, ALeafThatIsNotACaCannotBeAnIntermediate) {
  Key kr = pki::key(20), k1 = pki::key(21), kl = pki::key(1);
  Bytes root = pki::root("root", kr);
  Bytes not_ca = pki::signed_by("mid", k1, "root", kr, false);
  Bytes leaf = pki::signed_by("leaf", kl, "mid", k1, false);
  Store st;
  st.add(root);
  Pool p;
  p.add(not_ca);
  GCERT_Chain c;
  EXPECT_EQ(build(st, leaf, p, &c), GCERT_ERR_MISMATCH);
  EXPECT_EQ(c.failure, GCERT_CHAIN_REJECTED);
}

TEST(Chain, ACycleEnds) {
  Key ka = pki::key(61), kb = pki::key(62), kl = pki::key(1);
  Bytes a = pki::signed_by("a", ka, "b", kb, true);
  Bytes b = pki::signed_by("b", kb, "a", ka, true);
  Bytes leaf = pki::signed_by("leaf", kl, "a", ka, false);
  Store st;
  st.add(pki::root("elsewhere", pki::key(63)));
  Pool p;
  p.add(a);
  p.add(b);
  GCERT_Chain c;
  EXPECT_EQ(build(st, leaf, p, &c), GCERT_ERR_MISMATCH);
  EXPECT_EQ(c.failure, GCERT_CHAIN_UNKNOWN_ISSUER);
  /* It ends because a certificate is not offered twice on one path, not
   * because the depth runs out: with a budget too small for walking the
   * cycle sixteen times it still finishes. */
  GCERT_Limits tight;
  gcert_limits_default(&tight);
  tight.max_chain_attempts = 6;
  EXPECT_EQ(build(st, leaf, p, &c, pki::kNow, 0, &tight), GCERT_ERR_MISMATCH);
}

namespace {

/* `levels` ranks of `width` re-issues of one CA each (same name, same key,
 * different serial), every one signed correctly by the next rank up, and an
 * unknown issuer at the very top. Every combination passes every signature
 * check, so the search has width^levels paths to wear out. */
void make_mesh(int levels, int width, Pool * pool, Bytes * leaf) {
  std::vector<Key> keys;
  for (int i = 0; i <= levels; i++) {
    keys.push_back(pki::key(static_cast<unsigned char>(80 + i)));
  }
  for (int level = 0; level < levels; level++) {
    for (int w = 0; w < width; w++) {
      pki::Spec s;
      s.subject = "c" + std::to_string(level);
      s.issuer = "c" + std::to_string(level + 1);
      s.subject_key = keys[level];
      s.signer = keys[level + 1];
      s.ca = true;
      s.serial = static_cast<unsigned>(level * 100 + w + 1);
      pool->add(pki::issue(s));
    }
  }
  *leaf = pki::signed_by("leaf", pki::key(1), "c0", keys[0], false);
}

} /* namespace */

TEST(Chain, ASearchBuiltToBeExpensiveStopsAtTheBudget) {
  Pool pool;
  Bytes leaf;
  make_mesh(7, 3, &pool, &leaf);       /* 3^7 = 2187 paths, none reaches an anchor */
  Store st;
  st.add(pki::root("elsewhere", pki::key(99)));
  GCERT_Chain c;
  GCERT_Limits limits;
  gcert_limits_default(&limits);
  limits.max_chain_pool = 64;
  limits.max_chain_attempts = 100;
  EXPECT_EQ(build(st, leaf, pool, &c, pki::kNow, 0, &limits), GCERT_ERR_LIMIT);
  EXPECT_EQ(c.mid_count, 0u);
  /* Zero means the default, which is also too small for this pool. */
  limits.max_chain_attempts = 0;
  EXPECT_EQ(build(st, leaf, pool, &c, pki::kNow, 0, &limits), GCERT_ERR_LIMIT);

  /* With the budget to spare it finishes and says what it found. */
  limits.max_chain_attempts = 1000000;
  EXPECT_EQ(build(st, leaf, pool, &c, pki::kNow, 0, &limits), GCERT_ERR_MISMATCH);
  EXPECT_EQ(c.failure, GCERT_CHAIN_UNKNOWN_ISSUER);
}

TEST(Chain, ThePoolIsBounded) {
  Tree t;
  Store st;
  st.add(t.root);
  Pool p;
  p.add(t.i2);
  p.add(t.i1);
  p.add(t.i1);
  GCERT_Limits limits;
  gcert_limits_default(&limits);
  limits.max_chain_pool = 3;
  GCERT_Chain c;
  EXPECT_EQ(build(st, t.leaf, p, &c, pki::kNow, 0, &limits), GCERT_OK);
  limits.max_chain_pool = 2;
  EXPECT_EQ(build(st, t.leaf, p, &c, pki::kNow, 0, &limits), GCERT_ERR_LIMIT);
}

TEST(Chain, MoreIntermediatesThanTheDepthAllows) {
  const int n = static_cast<int>(GCERT_X509_CHAIN_MAX) + 1;
  std::vector<Key> keys;
  for (int i = 0; i <= n; i++) {
    keys.push_back(pki::key(static_cast<unsigned char>(100 + i)));
  }
  Store st;
  st.add(pki::root("m" + std::to_string(n), keys[n]));
  Pool p;
  for (int i = 1; i < n; i++) {
    p.add(pki::signed_by("m" + std::to_string(i), keys[i], "m" + std::to_string(i + 1),
        keys[i + 1], true));
  }
  Bytes leaf = pki::signed_by("leaf", pki::key(1), "m1", keys[1], false);
  GCERT_Chain c;
  /* n - 1 intermediates: exactly the maximum. */
  ASSERT_EQ(build(st, leaf, p, &c), GCERT_OK);
  EXPECT_EQ(c.mid_count, GCERT_X509_CHAIN_MAX);
  /* One more is refused. */
  Store st2;
  st2.add(pki::root("m" + std::to_string(n + 1), pki::key(120)));
  Pool p2 = p;
  p2.add(pki::signed_by("m" + std::to_string(n), keys[n], "m" + std::to_string(n + 1),
      pki::key(120), true));
  EXPECT_EQ(build(st2, leaf, p2, &c), GCERT_ERR_MISMATCH);
}

TEST(Chain, ArgumentsAndTheLeaf) {
  Tree t;
  Store st;
  st.add(t.root);
  Pool p;
  GCERT_Chain c;
  p.seal();
  EXPECT_EQ(gcert_chain_build(nullptr, t.leaf.data(), t.leaf.size(), nullptr, nullptr, 0,
      pki::kNow, 0, nullptr, &c), GCERT_ERR_INVALID);
  EXPECT_EQ(gcert_chain_build(st.s, nullptr, 3, nullptr, nullptr, 0, pki::kNow, 0,
      nullptr, &c), GCERT_ERR_INVALID);
  EXPECT_EQ(gcert_chain_build(st.s, t.leaf.data(), 0, nullptr, nullptr, 0, pki::kNow, 0,
      nullptr, &c), GCERT_ERR_INVALID);
  EXPECT_EQ(gcert_chain_build(st.s, t.leaf.data(), t.leaf.size(), nullptr, nullptr, 2,
      pki::kNow, 0, nullptr, &c), GCERT_ERR_INVALID);
  Bytes junk = {0x30, 0x03, 0x02, 0x01, 0x01};
  EXPECT_EQ(build(st, junk, p, &c), GCERT_ERR_CORRUPT);
  /* out may be null. */
  Pool full;
  full.add(t.i2);
  full.add(t.i1);
  full.seal();
  EXPECT_EQ(gcert_chain_build(st.s, t.leaf.data(), t.leaf.size(), full.ptrs.data(),
      full.lens.data(), 2, pki::kNow, 0, nullptr, nullptr), GCERT_OK);
}

TEST(Chain, ThePurposeIsPassedToThePathCheck) {
  Tree t;
  Store st;
  st.add(t.root);
  Pool p;
  p.add(t.i2);
  p.add(t.i1);
  GCERT_Chain c;
  /* The leaf has no extendedKeyUsage and so permits every purpose; the
   * builder only has to carry the argument. */
  EXPECT_EQ(build(st, t.leaf, p, &c, pki::kNow, GCERT_X509_EKU_SERVER_AUTH), GCERT_OK);
  EXPECT_EQ(build(st, t.leaf, p, &c, pki::kNow, GCERT_X509_EKU_CLIENT_AUTH), GCERT_OK);
}

TEST(Chain, EveryAllocationMayFail) {
  Tree t;
  struct Counter {
    size_t calls = 0, fail_at = 0, live = 0;
  } probe;
  auto m = [](void * ctx, size_t n) -> void * {
    auto * f = static_cast<Counter *>(ctx);
    if (++f->calls == f->fail_at) return nullptr;
    void * p = std::malloc(n == 0 ? 1 : n);
    if (p) f->live++;
    return p;
  };
  auto c = [](void * ctx, size_t a, size_t b) -> void * {
    auto * f = static_cast<Counter *>(ctx);
    if (++f->calls == f->fail_at) return nullptr;
    void * p = std::calloc(a, b == 0 ? 1 : b);
    if (p) f->live++;
    return p;
  };
  auto r = [](void * ctx, void * old, size_t n) -> void * {
    auto * f = static_cast<Counter *>(ctx);
    if (++f->calls == f->fail_at) return nullptr;
    void * p = std::realloc(old, n == 0 ? 1 : n);
    if (p && !old) f->live++;
    return p;
  };
  auto fr = [](void * ctx, void * p) {
    auto * f = static_cast<Counter *>(ctx);
    if (p) f->live--;
    std::free(p);
  };
  auto run = [&](Counter * ctr) -> GCERT_Result {
    GCERT_Allocator a = {ctr, m, c, r, fr};
    GCERT_TrustStore * s = nullptr;
    GCERT_Result res = gcert_trust_new(&a, nullptr, &s);
    if (res == GCERT_OK) {
      res = gcert_trust_add_der(s, t.root.data(), t.root.size());
    }
    if (res == GCERT_OK) {
      Pool p;
      p.add(t.i2);
      p.add(t.i1);
      p.seal();
      GCERT_Chain ch;
      res = gcert_chain_build(s, t.leaf.data(), t.leaf.size(), p.ptrs.data(),
          p.lens.data(), 2, pki::kNow, 0, nullptr, &ch);
    }
    gcert_trust_free(s);
    return res;
  };
  ASSERT_EQ(run(&probe), GCERT_OK);
  EXPECT_EQ(probe.live, 0u);
  for (size_t k = 1; k <= probe.calls; k++) {
    Counter f;
    f.fail_at = k;
    GCERT_Result res = run(&f);
    EXPECT_EQ(res, GCERT_ERR_OOM) << "failing allocation " << k;
    EXPECT_EQ(f.live, 0u) << "leak after failing allocation " << k;
  }
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
