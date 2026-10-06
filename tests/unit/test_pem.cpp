/**
 * @file
 *
 * PEM armour round trip.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "test_helpers.h"

#include <cstring>
#include <string>

TEST(Pem, RoundTrip) {
  static const unsigned char raw[] = {0x01, 0x02, 0x03, 0xff};
  char armour[128];
  unsigned char back[8];
  char label[32];
  size_t n = 0;
  size_t label_len = 0;

  ASSERT_EQ(gcert_pem_encode("CERTIFICATE", raw, sizeof raw, armour,
      sizeof armour, &n), GCERT_OK);
  ASSERT_EQ(gcert_pem_decode(armour, n, back, sizeof back, &n, label,
      sizeof label), GCERT_OK);
  EXPECT_EQ(n, sizeof raw);
  EXPECT_EQ(std::memcmp(back, raw, sizeof raw), 0);
  EXPECT_EQ(std::string(label, 11), "CERTIFICATE");
  (void)label_len;
}

TEST(Pem, RejectsABadBlock) {
  size_t n = 0;
  unsigned char out[4];
  EXPECT_EQ(gcert_pem_decode("no banner", 9, out, sizeof out, &n, nullptr, 0),
      GCERT_ERR_CORRUPT);
  EXPECT_EQ(gcert_pem_encode("", out, 0, out, sizeof out, &n), GCERT_ERR_INVALID);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
