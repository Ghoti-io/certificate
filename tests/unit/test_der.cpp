/**
 * @file
 *
 * Strict DER: one integer inside a sequence, and the lengths it must reject.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "test_helpers.h"

TEST(Der, SequenceOfOne) {
  static const unsigned char der[] = {0x30, 0x03, 0x02, 0x01, 0x01};
  GCERT_Der view;
  GCERT_Der inner;

  ASSERT_EQ(gcert_der_tlv(der, sizeof der, &view), GCERT_OK);
  EXPECT_EQ(view.number, 16u);
  EXPECT_EQ(view.constructed, 1u);
  EXPECT_EQ(view.total_len, sizeof der);
  ASSERT_EQ(gcert_der_tlv(view.value, view.value_len, &inner), GCERT_OK);
  EXPECT_EQ(inner.number, 2u);
  EXPECT_EQ(inner.value_len, 1u);
  EXPECT_EQ(inner.value[0], 0x01);
}

TEST(Der, RejectsIndefiniteAndNonMinimal) {
  static const unsigned char indefinite[] = {0x02, 0x80, 0x01, 0x00, 0x00};
  static const unsigned char padded[] = {0x02, 0x02, 0x00, 0x01};
  static const unsigned char unsorted[] = {
    0x31, 0x06, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01
  };
  static const unsigned char sorted[] = {
    0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02
  };
  GCERT_Der view;

  EXPECT_EQ(gcert_der_tlv(indefinite, sizeof indefinite, &view), GCERT_ERR_CORRUPT);
  EXPECT_EQ(gcert_der_tlv(padded, sizeof padded, &view), GCERT_ERR_CORRUPT);
  EXPECT_EQ(gcert_der_tlv(unsorted, sizeof unsorted, &view), GCERT_ERR_CORRUPT);
  EXPECT_EQ(gcert_der_tlv(sorted, sizeof sorted, &view), GCERT_OK);
}

TEST(Der, RejectsALongFormThatIsShort) {
  static const unsigned char der[] = {0x02, 0x81, 0x01, 0x01};
  GCERT_Der view;

  EXPECT_EQ(gcert_der_tlv(der, sizeof der, &view), GCERT_ERR_CORRUPT);
  EXPECT_EQ(gcert_der_tlv(nullptr, 0, &view), GCERT_ERR_CORRUPT);
  EXPECT_EQ(gcert_der_tlv(der, sizeof der, nullptr), GCERT_ERR_INVALID);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
