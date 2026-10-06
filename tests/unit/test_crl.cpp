/**
 * @file
 *
 * A CRL OpenSSL issued, checked against the CA that signed it.
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

const unsigned char kSerial[] = {
  0x1d, 0xf0, 0x17, 0x04, 0x5e, 0xa3, 0x08, 0x80, 0x5b, 0x21,
  0x9a, 0x09, 0x22, 0xc6, 0xe6, 0xb4, 0x83, 0xc3, 0x15, 0x50
};

} /* namespace */

TEST(Crl, LeafIsRevokedByItsCa) {
  auto crl_der = load("leaf.crl");
  auto ca_der = load("ca.der");
  GCERT_Crl crl;
  GCERT_X509 ca;
  unsigned char other[1] = {0x02};
  ASSERT_EQ(gcert_crl_parse(crl_der.data(), crl_der.size(), &crl), GCERT_OK);
  ASSERT_EQ(gcert_x509_parse(ca_der.data(), ca_der.size(), &ca), GCERT_OK);
  EXPECT_EQ(gcert_crl_signed_by(&crl, &ca), GCERT_OK);
  EXPECT_EQ(gcert_crl_contains(&crl, kSerial, sizeof kSerial), GCERT_OK);
  EXPECT_EQ(gcert_crl_contains(&crl, other, 1), GCERT_ERR_MISMATCH);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
