/**
 * @file
 *
 * Unencrypted PKCS#8, and the rejection of a password-encrypted key.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "test_helpers.h"

#include <cstring>
#include <fstream>
#include <vector>

namespace {

std::vector<unsigned char> load(const char * name) {
  std::ifstream in(gsectest::data_dir() + "/certs/" + name, std::ios::binary);
  EXPECT_TRUE(in.good()) << name;
  return std::vector<unsigned char>(std::istreambuf_iterator<char>(in),
      std::istreambuf_iterator<char>());
}

std::string text(const char * name) {
  std::ifstream in(gsectest::data_dir() + "/certs/" + name);
  EXPECT_TRUE(in.good()) << name;
  return std::string(std::istreambuf_iterator<char>(in),
      std::istreambuf_iterator<char>());
}

} /* namespace */

TEST(Pkcs8, MatchesTheCertificate) {
  struct {
    const char * key;
    const char * cert;
    uint32_t kind;
    size_t scalar;
  } rows[] = {
    {"p256-leaf.pkcs8", "p256-leaf.der", GCERT_PKCS8_P256, 32},
    {"p384-leaf.pkcs8", "p384-leaf.der", GCERT_PKCS8_P384, 48},
    {"ed-leaf.pkcs8", "ed-leaf.der", GCERT_PKCS8_ED25519, 32},
    {"rsa-leaf.pkcs8", "rsa-leaf.der", GCERT_PKCS8_RSA, 0},
  };
  for (const auto & row : rows) {
    auto key = load(row.key);
    auto cert = load(row.cert);
    GCERT_Pkcs8 parsed;
    GCERT_X509 view;
    ASSERT_EQ(gcert_pkcs8_parse(key.data(), key.size(), &parsed), GCERT_OK)
        << row.key;
    EXPECT_EQ(parsed.kind, row.kind) << row.key;
    ASSERT_EQ(gcert_x509_parse(cert.data(), cert.size(), &view), GCERT_OK);
    if (row.kind == GCERT_PKCS8_RSA) {
      EXPECT_EQ(parsed.n_len, view.n_len);
      EXPECT_EQ(std::memcmp(parsed.n, view.n, parsed.n_len), 0);
      EXPECT_EQ(parsed.e_len, view.e_len);
      EXPECT_EQ(std::memcmp(parsed.e, view.e, parsed.e_len), 0);
      EXPECT_GT(parsed.d_len, 0u);
    } else {
      unsigned char pub[96];
      EXPECT_EQ(parsed.scalar_len, row.scalar) << row.key;
      if (row.kind == GCERT_PKCS8_P256) {
        ASSERT_EQ(gsec_ecdsa_p256_public(parsed.scalar, pub), GSEC_OK);
      } else if (row.kind == GCERT_PKCS8_P384) {
        ASSERT_EQ(gsec_ecdsa_p384_public(parsed.scalar, pub), GSEC_OK);
      } else {
        ASSERT_EQ(gsec_ed25519_public(parsed.scalar, pub), GSEC_OK);
      }
      EXPECT_EQ(std::memcmp(pub, view.point, view.point_len), 0) << row.key;
    }
  }
}

TEST(Pkcs8, EncryptedIsUnsupported) {
  std::string pem = text("enc.pem");
  unsigned char der[512];
  size_t n = 0;
  GCERT_Pkcs8 parsed;
  ASSERT_EQ(gcert_pem_decode(pem.data(), pem.size(), der, sizeof der, &n,
      nullptr, 0), GCERT_OK);
  EXPECT_EQ(gcert_pkcs8_parse(der, n, &parsed), GCERT_ERR_UNSUPPORTED);
}

TEST(Pem, CertificateRoundTrip) {
  auto der = load("p256-leaf.der");
  std::string pem = text("p256-leaf.pem");
  unsigned char back[1024];
  size_t n = 0;
  ASSERT_EQ(gcert_pem_decode(pem.data(), pem.size(), back, sizeof back, &n,
      nullptr, 0), GCERT_OK);
  ASSERT_EQ(n, der.size());
  EXPECT_EQ(std::memcmp(back, der.data(), n), 0);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
