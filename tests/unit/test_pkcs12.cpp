/**
 * @file
 *
 * A PKCS#12 file OpenSSL wrote: a leaf key, the leaf, and its CA.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "test_helpers.h"

#include <cstdint>
#include <fstream>
#include <vector>

namespace {

std::vector<unsigned char> load(const char * name) {
  std::ifstream in(gsectest::data_dir() + "/certs/" + name, std::ios::binary);
  EXPECT_TRUE(in.good()) << name;
  return std::vector<unsigned char>(std::istreambuf_iterator<char>(in),
      std::istreambuf_iterator<char>());
}

} /* namespace */

TEST(Pkcs12, OpensKeyAndCerts) {
  auto p12 = load("leaf.p12");
  auto plain = load("leaf.plain.p8");
  unsigned char scratch[8192];
  GCERT_Pkcs12 bag;
  GCERT_Pkcs8 got;
  GCERT_Pkcs8 expect;
  GCERT_X509 cert;
  size_t i;
  int saw_leaf = 0;
  ASSERT_EQ(gcert_pkcs12_open(p12.data(), p12.size(), "secret", 6, scratch,
      sizeof scratch, &bag, nullptr), GCERT_OK);
  ASSERT_NE(bag.key, nullptr);
  ASSERT_EQ(gcert_pkcs8_parse(bag.key, bag.key_len, &got), GCERT_OK);
  ASSERT_EQ(gcert_pkcs8_parse(plain.data(), plain.size(), &expect), GCERT_OK);
  ASSERT_EQ(got.scalar_len, expect.scalar_len);
  EXPECT_EQ(gsec_equal(got.scalar, expect.scalar, got.scalar_len), GSEC_OK);
  EXPECT_GE(bag.cert_count, 2u);
  for (i = 0; i < bag.cert_count; i++) {
    ASSERT_EQ(gcert_x509_parse(bag.certs[i], bag.cert_lens[i], &cert), GCERT_OK);
    if (cert.dns_san) {
      saw_leaf = 1;
      EXPECT_EQ(gcert_x509_hostname(&cert, "leaf.example", 12), GCERT_OK);
    }
  }
  EXPECT_EQ(saw_leaf, 1);
}

TEST(Pkcs12, OpensATraditionalBag) {
  static const char * names[] = {
    "legacy-3des-rc2.p12",
    "legacy-rc4-rc2.p12",
  };
  auto plain = load("leaf.plain.p8");
  GCERT_Pkcs8 expect;
  size_t i;
  ASSERT_EQ(gcert_pkcs8_parse(plain.data(), plain.size(), &expect), GCERT_OK);
  for (i = 0; i < sizeof names / sizeof names[0]; i++) {
    auto p12 = load(names[i]);
    unsigned char scratch[8192];
    GCERT_Pkcs12 bag;
    GCERT_Pkcs8 got;
    SCOPED_TRACE(names[i]);
    ASSERT_EQ(gcert_pkcs12_open(p12.data(), p12.size(), "secret", 6, scratch,
        sizeof scratch, &bag, nullptr), GCERT_OK);
    ASSERT_NE(bag.key, nullptr);
    ASSERT_EQ(gcert_pkcs8_parse(bag.key, bag.key_len, &got), GCERT_OK);
    ASSERT_EQ(got.scalar_len, expect.scalar_len);
    EXPECT_EQ(gsec_equal(got.scalar, expect.scalar, got.scalar_len), GSEC_OK);
    EXPECT_GE(bag.cert_count, 1u);
  }
}

TEST(Pkcs12, WrongPasswordFailsTheMac) {
  auto p12 = load("leaf.p12");
  unsigned char scratch[64];
  GCERT_Pkcs12 bag;
  EXPECT_EQ(gcert_pkcs12_open(p12.data(), p12.size(), "nope", 4, scratch,
      sizeof scratch, &bag, nullptr), GCERT_ERR_MISMATCH);
}

TEST(Pkcs12, NoMacDataIsRefused) {
  /* RFC 7292 makes MacData optional. An archive without one is
   * unauthenticated: its unencrypted certificate bags can be replaced by
   * anyone who can write the file, and GCERT_OK would read as "this archive is
   * fine". Refused, rather than opened silently. */
  auto p12 = load("nomac.p12");
  unsigned char scratch[8192];
  GCERT_Pkcs12 bag;
  ASSERT_GT(p12.size(), 0u);
  EXPECT_EQ(gcert_pkcs12_open(p12.data(), p12.size(), "secret", 6, scratch,
      sizeof scratch, &bag, nullptr), GCERT_ERR_UNSUPPORTED);
}

TEST(Pkcs12, IterationCapIsTheCallers) {
  /* The iteration count is in the file, so it is an attacker's number when
   * the file is. The default ceiling refuses it before deriving anything, and
   * a caller that opens files it did not create can lower the ceiling. */
  auto p12 = load("leaf.p12");
  unsigned char scratch[8192];
  GCERT_Pkcs12 bag;
  GCERT_Limits limits;
  gcert_limits_default(&limits);
  EXPECT_EQ(limits.max_pbe_iterations, GCERT_PBE_ITERATIONS_DEFAULT);
  ASSERT_EQ(gcert_pkcs12_open(p12.data(), p12.size(), "secret", 6, scratch,
      sizeof scratch, &bag, &limits), GCERT_OK);
  /* One iteration is below what any real file asks for, so the same archive
   * that just opened must now be refused for its cost rather than opened
   * slowly. */
  limits.max_pbe_iterations = 1;
  EXPECT_EQ(gcert_pkcs12_open(p12.data(), p12.size(), "secret", 6, scratch,
      sizeof scratch, &bag, &limits), GCERT_ERR_LIMIT);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
