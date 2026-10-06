/**
 * @file
 *
 * Shared helpers for the Ghoti.io Certificate unit tests.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#ifndef GHOTI_IO_GCERT_TEST_HELPERS_H
#define GHOTI_IO_GCERT_TEST_HELPERS_H

#include <gtest/gtest.h>

#include <ghoti.io/certificate/certificate.h>
#include <ghoti.io/security/security.h>

#include <cstdlib>
#include <string>

namespace gsectest {

/** Directory holding the checked-in vectors. The Makefile bakes in
 *  GCERT_TEST_DATA so the binaries can run from the build tree. */
inline std::string data_dir() {
  const char * env = std::getenv("GCERT_TEST_DATA");
  if (env != nullptr && env[0] != '\0') {
    return std::string(env);
  }
#ifdef GCERT_TEST_DATA
  return std::string(GCERT_TEST_DATA);
#else
  return std::string("tests/data");
#endif
}

} /* namespace gsectest */

#endif /* GHOTI_IO_GCERT_TEST_HELPERS_H */
