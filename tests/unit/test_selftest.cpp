/**
 * @file
 *
 * The embedder-facing known-answer run.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include "test_helpers.h"

TEST(SelfTest, Passes) {
  EXPECT_EQ(gcert_selftest(), GCERT_OK);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
