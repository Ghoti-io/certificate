/**
 * @file
 *
 * The result vocabulary, the limits, the version, and the allocator.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "test_helpers.h"

#include <ghoti.io/cutil/allocator.h>
#include <ghoti.io/certificate/libver.h>

#include "../../src/core/sec_result.h"

#include <set>
#include <string>

/* CONVENTIONS.md section 5: GCERT_RESULT_COUNT closes the enum so a test can
 * check the string table is complete. A new result without a string falls
 * through to "Unknown error" and is caught here. */
TEST(Result, EveryCodeHasItsOwnString) {
  std::set<std::string> seen;
  for (int i = 0; i < GCERT_RESULT_COUNT; i++) {
    const char * s = gcert_result_string(static_cast<GCERT_Result>(i));
    ASSERT_NE(s, nullptr);
    EXPECT_STRNE(s, "Unknown error") << "result " << i;
    EXPECT_TRUE(seen.insert(s).second) << "result " << i << " shares a string";
  }
}

TEST(Result, OutOfRangeIsUnknownNotUndefined) {
  EXPECT_STREQ(gcert_result_string(GCERT_RESULT_COUNT), "Unknown error");
  EXPECT_STREQ(gcert_result_string(static_cast<GCERT_Result>(-1)),
      "Unknown error");
}

TEST(Result, ZeroIsSuccess) {
  EXPECT_EQ(GCERT_OK, 0);
  EXPECT_STREQ(gcert_result_string(GCERT_OK), "No error");
}

TEST(Result, MismatchIsNotInvalid) {
  EXPECT_STRNE(gcert_result_string(GCERT_ERR_MISMATCH),
      gcert_result_string(GCERT_ERR_INVALID));
  EXPECT_STREQ(gcert_result_string(GCERT_ERR_MISMATCH), "Verification failed");
}

TEST(Limits, DefaultCapsPbeIterations) {
  GCERT_Limits limits;
  limits.max_pbe_iterations = 0;
  gcert_limits_default(&limits);
  EXPECT_EQ(limits.max_pbe_iterations, GCERT_PBE_ITERATIONS_DEFAULT);
}

TEST(Limits, NullDefaultIsIgnored) {
  gcert_limits_default(nullptr);
}

TEST(Version, StringMatchesTheGeneratedHeader) {
  EXPECT_STREQ(gcert_version_string(), GCERT_VERSION_STRING);
  EXPECT_EQ(gcert_version_number(), GCERT_VERSION_NUMBER);
  EXPECT_EQ(GCERT_VERSION_NUMBER,
      GCERT_MAKE_VERSION(GCERT_VERSION_MAJOR, GCERT_VERSION_MINOR,
          GCERT_VERSION_PATCH));
}

TEST(Allocator, DefaultIsCutils) {
  const GCERT_Allocator * allocator = gcert_allocator_default();
  ASSERT_NE(allocator, nullptr);
  EXPECT_EQ(allocator, gcu_allocator_default());
}

/* The two vocabularies are written twice, and the conversion between them is
 * a switch. Both of those are claims that a new member on one side breaks
 * silently, so each is checked here: the members line up by number and by
 * string, and a value that is in neither enum is an internal error rather
 * than a success. */
TEST(SecurityResult, SameCountAndSameStringsAsSecurity) {
  ASSERT_EQ(static_cast<int>(GCERT_RESULT_COUNT),
      static_cast<int>(GSEC_RESULT_COUNT));
  for (int i = 0; i < GSEC_RESULT_COUNT; i++) {
    const GCERT_Result mapped = gcert_from_gsec(static_cast<GSEC_Result>(i));
    EXPECT_EQ(static_cast<int>(mapped), i) << "result " << i;
    EXPECT_STREQ(gcert_result_string(mapped),
        gsec_result_string(static_cast<GSEC_Result>(i))) << "result " << i;
  }
}

TEST(SecurityResult, AValueInNeitherEnumIsNotSuccess) {
  EXPECT_EQ(gcert_from_gsec(GSEC_RESULT_COUNT), GCERT_ERR_INTERNAL);
  EXPECT_EQ(gcert_from_gsec(static_cast<GSEC_Result>(-1)), GCERT_ERR_INTERNAL);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
