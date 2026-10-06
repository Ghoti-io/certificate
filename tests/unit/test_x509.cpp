/**
 * @file
 *
 * X.509 parse, path validation, and hostname matching against OpenSSL chains.
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

const int64_t kInside = 1600000000;

} /* namespace */

TEST(X509, P256LeafSignedByItsCa) {
  auto ca = load("p256-ca.der");
  auto leaf = load("p256-leaf.der");
  GCERT_X509 parsed;
  ASSERT_EQ(gcert_x509_parse(leaf.data(), leaf.size(), &parsed), GCERT_OK);
  EXPECT_EQ(parsed.key, GCERT_X509_P256);
  EXPECT_EQ(parsed.point_len, 64u);
  EXPECT_EQ(parsed.dns_san, 1);
  EXPECT_LT(parsed.not_before, kInside);
  EXPECT_GT(parsed.not_after, kInside);
  EXPECT_EQ(gcert_x509_path(leaf.data(), leaf.size(), nullptr, nullptr, 0,
      ca.data(), ca.size(), kInside, 0), GCERT_OK);
  EXPECT_EQ(gcert_x509_path(leaf.data(), leaf.size(), nullptr, nullptr, 0,
      ca.data(), ca.size(), parsed.not_before - 1, 0), GCERT_ERR_MISMATCH);
  EXPECT_EQ(gcert_x509_path(leaf.data(), leaf.size(), nullptr, nullptr, 0,
      ca.data(), ca.size(), parsed.not_after + 1, 0), GCERT_ERR_MISMATCH);
  EXPECT_EQ(gcert_x509_hostname(&parsed, "www.example.com", 15), GCERT_OK);
  EXPECT_EQ(gcert_x509_hostname(&parsed, "WWW.EXAMPLE.COM", 15), GCERT_OK);
  EXPECT_EQ(gcert_x509_hostname(&parsed, "other.example.com", 17),
      GCERT_ERR_MISMATCH);
}

TEST(X509, FlippedSignatureFails) {
  auto ca = load("p256-ca.der");
  auto leaf = load("p256-leaf.der");
  leaf.back() ^= 0x01;
  EXPECT_EQ(gcert_x509_path(leaf.data(), leaf.size(), nullptr, nullptr, 0,
      ca.data(), ca.size(), kInside, 0), GCERT_ERR_MISMATCH);
}

TEST(X509, IntermediateMustBeACa) {
  auto ca = load("p256-ca.der");
  auto mid = load("p256-mid.der");
  auto leaf = load("p256-mid-leaf.der");
  auto noca = load("p256-noca.der");
  auto nleaf = load("p256-noca-leaf.der");
  const void * mids[] = {mid.data()};
  size_t lens[] = {mid.size()};
  EXPECT_EQ(gcert_x509_path(leaf.data(), leaf.size(), mids, lens, 1,
      ca.data(), ca.size(), kInside, 0), GCERT_OK);
  mids[0] = noca.data();
  lens[0] = noca.size();
  EXPECT_EQ(gcert_x509_path(nleaf.data(), nleaf.size(), mids, lens, 1,
      ca.data(), ca.size(), kInside, 0), GCERT_ERR_MISMATCH);
}

TEST(X509, ExplicitCaFalseAnchorIsRejected) {
  auto bad = load("ca-false.der");
  EXPECT_EQ(gcert_x509_path(bad.data(), bad.size(), nullptr, nullptr, 0,
      bad.data(), bad.size(), kInside, 0), GCERT_ERR_MISMATCH);
}

TEST(X509, NameConstraintAndWildcard) {
  auto ca = load("nc-ca.der");
  auto ok = load("nc-ok.der");
  auto bad = load("nc-bad.der");
  auto wild_ca = load("p256-ca.der");
  auto wild = load("wild.der");
  GCERT_X509 parsed;
  EXPECT_EQ(gcert_x509_path(ok.data(), ok.size(), nullptr, nullptr, 0,
      ca.data(), ca.size(), kInside, 0), GCERT_OK);
  EXPECT_EQ(gcert_x509_path(bad.data(), bad.size(), nullptr, nullptr, 0,
      ca.data(), ca.size(), kInside, 0), GCERT_ERR_MISMATCH);
  ASSERT_EQ(gcert_x509_parse(wild.data(), wild.size(), &parsed), GCERT_OK);
  EXPECT_EQ(gcert_x509_hostname(&parsed, "www.example.com", 15), GCERT_OK);
  EXPECT_EQ(gcert_x509_hostname(&parsed, "example.com", 11), GCERT_ERR_MISMATCH);
  EXPECT_EQ(gcert_x509_hostname(&parsed, "a.b.example.com", 15),
      GCERT_ERR_MISMATCH);
  EXPECT_EQ(gcert_x509_path(wild.data(), wild.size(), nullptr, nullptr, 0,
      wild_ca.data(), wild_ca.size(), kInside, 0), GCERT_OK);
}

TEST(X509, RsaEd25519AndP384) {
  struct {
    const char * ca;
    const char * leaf;
    uint32_t key;
    size_t point;
  } rows[] = {
    {"rsa-ca.der", "rsa-leaf.der", GCERT_X509_RSA, 0},
    {"ed-ca.der", "ed-leaf.der", GCERT_X509_ED25519, 32},
    {"p384-ca.der", "p384-leaf.der", GCERT_X509_P384, 96},
  };
  for (const auto & row : rows) {
    auto ca = load(row.ca);
    auto leaf = load(row.leaf);
    GCERT_X509 parsed;
    ASSERT_EQ(gcert_x509_parse(leaf.data(), leaf.size(), &parsed), GCERT_OK)
        << row.leaf;
    EXPECT_EQ(parsed.key, row.key) << row.leaf;
    if (row.point != 0) {
      EXPECT_EQ(parsed.point_len, row.point) << row.leaf;
    }
    EXPECT_EQ(gcert_x509_path(leaf.data(), leaf.size(), nullptr, nullptr, 0,
        ca.data(), ca.size(), kInside, 0), GCERT_OK) << row.leaf;
  }
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
