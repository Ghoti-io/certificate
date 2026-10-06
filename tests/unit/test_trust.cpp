/**
 * @file
 *
 * The trust store: adding, bundles, limits, finding issuers, and the
 * allocator failing at each allocation.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "pki.h"

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

namespace {

using pki::Bytes;

std::string pem_of(const Bytes & der, const char * label = "CERTIFICATE") {
  std::vector<unsigned char> out(der.size() * 2 + 256);
  size_t n = 0;
  EXPECT_EQ(gcert_pem_encode(label, der.data(), der.size(), out.data(), out.size(), &n),
      GCERT_OK);
  return std::string(out.begin(), out.begin() + n);
}

struct Store {
  GCERT_TrustStore * s = nullptr;
  explicit Store(const GCERT_Limits * limits = nullptr,
      const GCERT_Allocator * a = nullptr) {
    EXPECT_EQ(gcert_trust_new(a, limits, &s), GCERT_OK);
  }
  ~Store() { gcert_trust_free(s); }
};

} /* namespace */

TEST(Trust, EmptyStore) {
  Store st;
  EXPECT_EQ(gcert_trust_count(st.s), 0u);
  GCERT_X509 c;
  Bytes leaf = pki::signed_by("leaf", pki::key(1), "ca", pki::key(2), false);
  ASSERT_EQ(gcert_x509_parse(leaf.data(), leaf.size(), &c), GCERT_OK);
  size_t idx[4];
  size_t count = 99;
  EXPECT_EQ(gcert_trust_find_issuers(st.s, &c, idx, 4, &count), GCERT_OK);
  EXPECT_EQ(count, 0u);
  const unsigned char * der;
  size_t n;
  EXPECT_EQ(gcert_trust_get(st.s, 0, &der, &n), GCERT_ERR_INVALID);
  gcert_trust_free(nullptr);  /* allowed */
}

TEST(Trust, AddDerCopiesAndDeduplicates) {
  Store st;
  Bytes ca = pki::root("ca", pki::key(2));
  ASSERT_EQ(gcert_trust_add_der(st.s, ca.data(), ca.size()), GCERT_OK);
  EXPECT_EQ(gcert_trust_count(st.s), 1u);
  Bytes copy = ca;
  EXPECT_EQ(gcert_trust_add_der(st.s, copy.data(), copy.size()), GCERT_OK);
  EXPECT_EQ(gcert_trust_count(st.s), 1u);
  /* The store holds its own bytes: wiping the caller's changes nothing. */
  std::memset(ca.data(), 0, ca.size());
  const unsigned char * der;
  size_t n;
  ASSERT_EQ(gcert_trust_get(st.s, 0, &der, &n), GCERT_OK);
  EXPECT_EQ(n, copy.size());
  EXPECT_EQ(std::memcmp(der, copy.data(), n), 0);
  GCERT_X509 parsed;
  EXPECT_EQ(gcert_x509_parse(der, n, &parsed), GCERT_OK);
}

TEST(Trust, AddDerRefusals) {
  Store st;
  Bytes ca = pki::root("ca", pki::key(2));
  EXPECT_EQ(gcert_trust_add_der(nullptr, ca.data(), ca.size()), GCERT_ERR_INVALID);
  EXPECT_EQ(gcert_trust_add_der(st.s, nullptr, 3), GCERT_ERR_INVALID);
  EXPECT_EQ(gcert_trust_add_der(st.s, ca.data(), 0), GCERT_ERR_INVALID);
  Bytes junk = {0x30, 0x03, 0x02, 0x01, 0x01};
  EXPECT_EQ(gcert_trust_add_der(st.s, junk.data(), junk.size()), GCERT_ERR_CORRUPT);
  Bytes truncated(ca.begin(), ca.end() - 1);
  EXPECT_EQ(gcert_trust_add_der(st.s, truncated.data(), truncated.size()),
      GCERT_ERR_CORRUPT);
  EXPECT_EQ(gcert_trust_count(st.s), 0u);
}

TEST(Trust, TheLimitIsEnforcedAtTheEdge) {
  GCERT_Limits limits;
  gcert_limits_default(&limits);
  limits.max_trust_anchors = 2;
  Store st(&limits);
  Bytes a = pki::root("a", pki::key(11));
  Bytes b = pki::root("b", pki::key(12));
  Bytes c = pki::root("c", pki::key(13));
  EXPECT_EQ(gcert_trust_add_der(st.s, a.data(), a.size()), GCERT_OK);
  EXPECT_EQ(gcert_trust_add_der(st.s, b.data(), b.size()), GCERT_OK);
  EXPECT_EQ(gcert_trust_add_der(st.s, c.data(), c.size()), GCERT_ERR_LIMIT);
  /* A duplicate at the limit is still not an error: nothing was added. */
  EXPECT_EQ(gcert_trust_add_der(st.s, a.data(), a.size()), GCERT_OK);
  EXPECT_EQ(gcert_trust_count(st.s), 2u);
}

TEST(Trust, ZeroLimitsMeanTheDefaults) {
  GCERT_Limits limits;
  std::memset(&limits, 0, sizeof limits);
  Store st(&limits);
  Bytes a = pki::root("a", pki::key(11));
  EXPECT_EQ(gcert_trust_add_der(st.s, a.data(), a.size()), GCERT_OK);
  EXPECT_EQ(gcert_trust_count(st.s), 1u);
}

TEST(Trust, BundleSkipsWhatIsNotACertificateAndCountsWhatIsBroken) {
  Bytes a = pki::root("a", pki::key(11));
  Bytes b = pki::root("b", pki::key(12));
  Bytes key_block = {0x30, 0x03, 0x02, 0x01, 0x01};
  std::string good_a = pem_of(a);
  std::string damaged = good_a;
  damaged[good_a.find('\n') + 5] = '!';  /* not base64 */
  Bytes not_x509 = {0x30, 0x03, 0x02, 0x01, 0x01};  /* decodes, is no certificate */

  std::string bundle =
      "# a comment line, as ca-certificates.crt has\n" + good_a + "\n"
      "Subject: some text between blocks\n" + pem_of(key_block, "PRIVATE KEY") +
      damaged + pem_of(not_x509) + pem_of(b) + pem_of(a);
  Store st;
  size_t added = 99;
  size_t skipped = 99;
  ASSERT_EQ(gcert_trust_add_pem(st.s, bundle.data(), bundle.size(), &added, &skipped),
      GCERT_OK);
  EXPECT_EQ(added, 2u);                  /* a and b; the second a is a duplicate */
  EXPECT_EQ(skipped, 2u);                /* the damaged block and the non-certificate */
  EXPECT_EQ(gcert_trust_count(st.s), 2u);

  /* Nothing in it, and null outputs. */
  EXPECT_EQ(gcert_trust_add_pem(st.s, "", 0, nullptr, nullptr), GCERT_OK);
  EXPECT_EQ(gcert_trust_add_pem(st.s, "no blocks here", 14, &added, &skipped), GCERT_OK);
  EXPECT_EQ(added, 0u);
  EXPECT_EQ(skipped, 0u);
  EXPECT_EQ(gcert_trust_add_pem(nullptr, "", 0, nullptr, nullptr), GCERT_ERR_INVALID);
  EXPECT_EQ(gcert_trust_add_pem(st.s, nullptr, 4, nullptr, nullptr), GCERT_ERR_INVALID);
}

TEST(Trust, AnEmptyBlockIsSkippedNotFatal) {
  /* Found by the fuzzer: a CERTIFICATE block with no body decodes to zero
   * bytes, which add_der calls INVALID, and that ended the whole load. */
  Bytes a = pki::root("a", pki::key(11));
  std::string bundle = "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n" + pem_of(a) +
      "-----BEGIN CERTIFICATE-----\n\n-----END CERTIFICATE-----\n";
  Store st;
  size_t added = 99;
  size_t skipped = 99;
  EXPECT_EQ(gcert_trust_add_pem(st.s, bundle.data(), bundle.size(), &added, &skipped), GCERT_OK);
  EXPECT_EQ(added, 1u);
  EXPECT_EQ(skipped, 2u);
}

TEST(Trust, BundleStopsWhenFull) {
  GCERT_Limits limits;
  gcert_limits_default(&limits);
  limits.max_trust_anchors = 1;
  Store st(&limits);
  std::string bundle = pem_of(pki::root("a", pki::key(11))) +
      pem_of(pki::root("b", pki::key(12)));
  size_t added = 0;
  size_t skipped = 0;
  EXPECT_EQ(gcert_trust_add_pem(st.s, bundle.data(), bundle.size(), &added, &skipped),
      GCERT_ERR_LIMIT);
  EXPECT_EQ(added, 1u);
}

namespace {

std::string write_file(const std::string & name, const void * data, size_t n) {
  const char * dir = std::getenv("TMPDIR");
  std::string path = std::string(dir != nullptr ? dir : "/tmp") + "/gcert-" + name +
      "-" + std::to_string(static_cast<long>(std::rand()));
  FILE * f = std::fopen(path.c_str(), "wb");
  EXPECT_NE(f, nullptr) << path;
  if (f != nullptr) {
    std::fwrite(data, 1, n, f);
    std::fclose(f);
  }
  return path;
}

} /* namespace */

TEST(Trust, FilesPemAndDer) {
  Bytes a = pki::root("a", pki::key(11));
  Bytes b = pki::root("b", pki::key(12));
  std::string pem = pem_of(a) + pem_of(b);
  std::string pem_path = write_file("bundle", pem.data(), pem.size());
  std::string der_path = write_file("single", a.data(), a.size());
  Store st;
  size_t added = 0;
  size_t skipped = 0;
  ASSERT_EQ(gcert_trust_add_file(st.s, pem_path.c_str(), &added, &skipped), GCERT_OK);
  EXPECT_EQ(added, 2u);
  Store st2;
  ASSERT_EQ(gcert_trust_add_file(st2.s, der_path.c_str(), &added, &skipped), GCERT_OK);
  EXPECT_EQ(added, 1u);
  EXPECT_EQ(skipped, 0u);
  EXPECT_EQ(gcert_trust_add_file(st2.s, "/nonexistent/gcert-no-such-file", nullptr,
      nullptr), GCERT_ERR_IO);
  EXPECT_EQ(gcert_trust_add_file(st2.s, nullptr, nullptr, nullptr), GCERT_ERR_INVALID);

  /* A file over the limit is refused, and exactly at it is not. */
  GCERT_Limits limits;
  gcert_limits_default(&limits);
  limits.max_trust_file_bytes = static_cast<uint32_t>(pem.size()) - 1u;
  Store small(&limits);
  EXPECT_EQ(gcert_trust_add_file(small.s, pem_path.c_str(), nullptr, nullptr),
      GCERT_ERR_LIMIT);
  limits.max_trust_file_bytes = static_cast<uint32_t>(pem.size());
  Store exact(&limits);
  EXPECT_EQ(gcert_trust_add_file(exact.s, pem_path.c_str(), &added, nullptr), GCERT_OK);
  EXPECT_EQ(added, 2u);
  std::remove(pem_path.c_str());
  std::remove(der_path.c_str());
}

TEST(Trust, FindIssuersOrdersByKeyIdentifier) {
  /* Three anchors share the subject "ca" (a re-keyed CA, and a cross-signed
   * twin). The child names the key it wants with its authorityKeyIdentifier. */
  Bytes want = pki::signed_by("ca", pki::key(21), "root", pki::key(20), true, 0x51);
  Bytes other = pki::signed_by("ca", pki::key(22), "root", pki::key(20), true, 0x52);
  Bytes unmarked = pki::signed_by("ca", pki::key(23), "root", pki::key(20), true);
  Bytes unrelated = pki::root("elsewhere", pki::key(24), 0x53);
  Bytes child = pki::signed_by("leaf", pki::key(1), "ca", pki::key(21), false, 0, 0x51);
  Store st;
  for (const Bytes * b : {&other, &unrelated, &unmarked, &want}) {
    ASSERT_EQ(gcert_trust_add_der(st.s, b->data(), b->size()), GCERT_OK);
  }
  GCERT_X509 c;
  ASSERT_EQ(gcert_x509_parse(child.data(), child.size(), &c), GCERT_OK);
  ASSERT_NE(c.aki, nullptr);
  size_t idx[8];
  size_t count = 0;
  ASSERT_EQ(gcert_trust_find_issuers(st.s, &c, idx, 8, &count), GCERT_OK);
  ASSERT_EQ(count, 3u);
  /* want (index 3) first, then the one with no identifier (2), then the one
   * whose identifier differs (0). The unrelated subject is not a candidate. */
  EXPECT_EQ(idx[0], 3u);
  EXPECT_EQ(idx[1], 2u);
  EXPECT_EQ(idx[2], 0u);

  /* A short buffer gets a prefix and the true count. */
  size_t one[1];
  ASSERT_EQ(gcert_trust_find_issuers(st.s, &c, one, 1, &count), GCERT_OK);
  EXPECT_EQ(count, 3u);
  EXPECT_EQ(one[0], 3u);
  EXPECT_EQ(gcert_trust_find_issuers(st.s, &c, nullptr, 0, &count), GCERT_OK);
  EXPECT_EQ(count, 3u);
  EXPECT_EQ(gcert_trust_find_issuers(st.s, &c, nullptr, 1, &count), GCERT_ERR_INVALID);
  EXPECT_EQ(gcert_trust_find_issuers(st.s, nullptr, idx, 8, &count), GCERT_ERR_INVALID);
}

#ifndef _WIN32
TEST(Trust, SystemLoaderHonoursTheEnvironmentFile) {
  Bytes a = pki::root("a", pki::key(11));
  std::string pem = pem_of(a);
  std::string path = write_file("env", pem.data(), pem.size());
  ASSERT_EQ(setenv("SSL_CERT_FILE", path.c_str(), 1), 0);
  Store st;
  size_t added = 0;
  size_t skipped = 0;
  EXPECT_EQ(gcert_trust_add_system(st.s, &added, &skipped), GCERT_OK);
  EXPECT_EQ(added, 1u);
  EXPECT_EQ(skipped, 0u);
  /* A file that is not there falls through to the well-known places; what
   * is on this machine is not ours to assert, only that it is not a crash
   * and not a half-loaded store. */
  ASSERT_EQ(setenv("SSL_CERT_FILE", "/nonexistent/gcert-no-such-file", 1), 0);
  Store st2;
  GCERT_Result r = gcert_trust_add_system(st2.s, &added, &skipped);
  EXPECT_TRUE(r == GCERT_OK || r == GCERT_ERR_IO) << gcert_result_string(r);
  EXPECT_EQ(gcert_trust_count(st2.s), added);
  unsetenv("SSL_CERT_FILE");
  std::remove(path.c_str());
}

TEST(Trust, SystemRootsOnThisMachine) {
  unsetenv("SSL_CERT_FILE");
  Store st;
  size_t added = 0;
  size_t skipped = 0;
  GCERT_Result r = gcert_trust_add_system(st.s, &added, &skipped);
  if (r == GCERT_ERR_IO) {
    GTEST_SKIP() << "no system bundle on this machine";
  }
  ASSERT_EQ(r, GCERT_OK);
  /* A real bundle has well over fifty roots, and this parser should read
   * nearly all of them: the entries it cannot are counted, not hidden. */
  EXPECT_GT(added, 50u);
  EXPECT_LT(skipped, added / 10u + 1u) << added << " read, " << skipped << " skipped";
  std::printf("system roots: %zu read, %zu skipped\n", added, skipped);
  /* Every anchor is one this library can parse again. */
  for (size_t i = 0; i < gcert_trust_count(st.s); i++) {
    const unsigned char * der;
    size_t n;
    GCERT_X509 x;
    ASSERT_EQ(gcert_trust_get(st.s, i, &der, &n), GCERT_OK);
    ASSERT_EQ(gcert_x509_parse(der, n, &x), GCERT_OK);
  }
}
#endif

#ifdef _WIN32
TEST(Trust, SystemRootsOnWindows) {
  /* The ROOT store, enumerated with CertEnumCertificatesInStore. Under wine it
   * holds what wine ships; on Windows, what the machine trusts. Either way
   * every entry the loader reported as added is one this library parses
   * again, and the counts agree with the store. */
  Store st;
  size_t added = 0;
  size_t skipped = 0;
  GCERT_Result r = gcert_trust_add_system(st.s, &added, &skipped);
  ASSERT_TRUE(r == GCERT_OK || r == GCERT_ERR_IO) << gcert_result_string(r);
  EXPECT_EQ(gcert_trust_count(st.s), added);
  std::printf("windows roots: %zu read, %zu skipped\n", added, skipped);
  for (size_t i = 0; i < gcert_trust_count(st.s); i++) {
    const unsigned char * der;
    size_t n;
    GCERT_X509 x;
    ASSERT_EQ(gcert_trust_get(st.s, i, &der, &n), GCERT_OK);
    ASSERT_EQ(gcert_x509_parse(der, n, &x), GCERT_OK);
  }
}
#endif

/* --- The allocator failing ------------------------------------------------- */

namespace {

struct Failing {
  size_t calls = 0;
  size_t fail_at = 0;     /* 1-based; 0 never fails */
  size_t live = 0;
};

void * f_malloc(void * ctx, size_t n) {
  Failing * f = static_cast<Failing *>(ctx);
  if (++f->calls == f->fail_at) {
    return nullptr;
  }
  void * p = std::malloc(n == 0 ? 1 : n);
  if (p != nullptr) {
    f->live++;
  }
  return p;
}

void * f_calloc(void * ctx, size_t a, size_t b) {
  Failing * f = static_cast<Failing *>(ctx);
  if (++f->calls == f->fail_at) {
    return nullptr;
  }
  void * p = std::calloc(a, b == 0 ? 1 : b);
  if (p != nullptr) {
    f->live++;
  }
  return p;
}

void * f_realloc(void * ctx, void * old, size_t n) {
  Failing * f = static_cast<Failing *>(ctx);
  if (++f->calls == f->fail_at) {
    return nullptr;
  }
  void * p = std::realloc(old, n == 0 ? 1 : n);
  if (p != nullptr && old == nullptr) {
    f->live++;
  }
  return p;
}

void f_free(void * ctx, void * p) {
  Failing * f = static_cast<Failing *>(ctx);
  if (p != nullptr) {
    f->live--;
  }
  std::free(p);
}

} /* namespace */

TEST(Trust, EveryAllocationMayFailAndNothingLeaks) {
  std::string bundle = pem_of(pki::root("a", pki::key(11))) +
      pem_of(pki::root("b", pki::key(12))) + pem_of(pki::root("c", pki::key(13)));
  /* First, count the allocations of a clean run. */
  Failing probe;
  GCERT_Allocator a = {&probe, f_malloc, f_calloc, f_realloc, f_free};
  {
    Store st(nullptr, &a);
    ASSERT_EQ(gcert_trust_add_pem(st.s, bundle.data(), bundle.size(), nullptr, nullptr),
        GCERT_OK);
    EXPECT_EQ(gcert_trust_count(st.s), 3u);
  }
  EXPECT_EQ(probe.live, 0u);
  const size_t total = probe.calls;
  ASSERT_GT(total, 6u);

  for (size_t k = 1; k <= total; k++) {
    Failing f;
    f.fail_at = k;
    GCERT_Allocator fa = {&f, f_malloc, f_calloc, f_realloc, f_free};
    GCERT_TrustStore * s = nullptr;
    GCERT_Result r = gcert_trust_new(&fa, nullptr, &s);
    if (r == GCERT_OK) {
      r = gcert_trust_add_pem(s, bundle.data(), bundle.size(), nullptr, nullptr);
    }
    EXPECT_TRUE(r == GCERT_OK || r == GCERT_ERR_OOM) << "failing allocation " << k
        << " gave " << gcert_result_string(r);
    EXPECT_EQ(r == GCERT_OK, k > total) << k;
    gcert_trust_free(s);
    EXPECT_EQ(f.live, 0u) << "leak after failing allocation " << k;
  }
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
