/**
 * @file
 *
 * X.509 parse, path validation, and hostname matching against OpenSSL chains.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "test_helpers.h"

#include <cstdint>
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

TEST(X509, SerialSpkiAndKeyBitsAreExposed) {
  /* leaf.der's serial is the one leaf.crl lists (see test_crl.cpp). */
  static const unsigned char serial[] = {
    0x1d, 0xf0, 0x17, 0x04, 0x5e, 0xa3, 0x08, 0x80, 0x5b, 0x21,
    0x9a, 0x09, 0x22, 0xc6, 0xe6, 0xb4, 0x83, 0xc3, 0x15, 0x50
  };
  auto der = load("leaf.der");
  GCERT_X509 c;
  ASSERT_EQ(gcert_x509_parse(der.data(), der.size(), &c), GCERT_OK);
  ASSERT_EQ(c.serial_len, sizeof serial);
  EXPECT_EQ(std::memcmp(c.serial, serial, sizeof serial), 0);
  /* The SPKI is a SEQUENCE inside the certificate, and ends with the key bits. */
  ASSERT_NE(c.spki, nullptr);
  EXPECT_GE(c.spki, der.data());
  EXPECT_LE(c.spki + c.spki_len, der.data() + der.size());
  EXPECT_EQ(c.spki[0], 0x30);
  ASSERT_NE(c.key_bits, nullptr);
  EXPECT_EQ(c.key_bits + c.key_bits_len, c.spki + c.spki_len);
  /* RSAPublicKey is a SEQUENCE; a curve key's bits begin with 0x04. */
  EXPECT_EQ(c.key_bits[0], c.key == GCERT_X509_RSA ? 0x30 : 0x04);
  auto rsa = load("sha1-ca.der");
  GCERT_X509 r;
  ASSERT_EQ(gcert_x509_parse(rsa.data(), rsa.size(), &r), GCERT_OK);
  ASSERT_EQ(r.key, GCERT_X509_RSA);
  EXPECT_EQ(r.key_bits[0], 0x30);
  /* For a curve key the bits are the point, with its 0x04 prefix; for Ed25519, the key. */
  auto ed = load("ed-leaf.der");
  GCERT_X509 e;
  ASSERT_EQ(gcert_x509_parse(ed.data(), ed.size(), &e), GCERT_OK);
  ASSERT_EQ(e.key_bits_len, 32u);
  EXPECT_EQ(std::memcmp(e.key_bits, e.point, 32), 0);
  auto ec = load("p256-leaf.der");
  GCERT_X509 p;
  ASSERT_EQ(gcert_x509_parse(ec.data(), ec.size(), &p), GCERT_OK);
  ASSERT_EQ(p.key_bits_len, 65u);
  EXPECT_EQ(p.key_bits[0], 0x04);
  EXPECT_EQ(std::memcmp(p.key_bits + 1, p.point, 64), 0);
}

TEST(X509, AnEcdsaDigestFromAnotherCurveIsUnsupportedNotCorrupt) {
  /* The SSL.com ECC root, which is public: a P-384 key whose own signature is
   * ecdsa-with-SHA256 (SHA-256 fingerprint 3417bb06 cc6007da 1b961c92 0b8ab4ce
   * 3fad820e 4aa30b9a cbc4a74e bdcebc65). ECDSA does not tie the curve to the
   * digest, and this library verifies only the pairings P-256 with SHA-256
   * and P-384 with SHA-384, so it cannot check this signature. What it must
   * not do is call a well-formed certificate corrupt: a trust store loading
   * the system bundle counts these as unsupported, and a person reading the
   * result is told the true reason. 3 of the 150 roots in Debian's bundle
   * are like this. */
  auto der = load("ssl-com-ecc-root-p384-sha256.der");
  GCERT_X509 parsed;
  EXPECT_EQ(gcert_x509_parse(der.data(), der.size(), &parsed), GCERT_ERR_UNSUPPORTED);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
