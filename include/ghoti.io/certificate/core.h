/*
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * Copyright (C) 2026 Corey Pennycuff
 *
 * This file is part of Ghoti.io Certificate.
 *
 * Ghoti.io Certificate is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * Ghoti.io Certificate is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/**
 * @file core.h
 *
 * Result codes, limits, and the version this build reports.
 *
 * No function here, and no function in this library, formats key material
 * into a string. ::gcert_result_string returns one of a fixed set of static
 * strings. There is no `_dump` for a key, a private scalar, or a derived
 * secret: that would be a disclosure primitive with a test suite guaranteeing
 * it works. See documentation/design.md.
 *
 * This is the result vocabulary of the certificate library. The primitives
 * under it return `GSEC_Result`, and nothing here converts one to the other
 * implicitly: a verification that fails is `GCERT_ERR_MISMATCH` whichever
 * library said so.
 */

#ifndef GHOTI_IO_GCERT_CORE_H
#define GHOTI_IO_GCERT_CORE_H

#include <ghoti.io/certificate/allocator.h>
#include <ghoti.io/certificate/macros.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Result of an operation.
 *
 * Zero is success. ::GCERT_RESULT_COUNT closes the enum so a test can check
 * the string table is complete.
 *
 * ::GCERT_ERR_MISMATCH is the one addition to the suite's fixed vocabulary.
 * A tag, a MAC, or a signature that does not match is the answer a
 * cryptographic check exists to give. Folding it into ::GCERT_ERR_INVALID
 * would make "the caller passed NULL" and "the tag is wrong" one result,
 * and a missing `!` on a boolean would make the wrong tag look like success.
 * Verification returns this status. It does not return a boolean.
 */
typedef enum {
  GCERT_OK = 0,          ///< The operation succeeded.
  GCERT_ERR_IO,          ///< A read, write, or the entropy source failed.
  GCERT_ERR_FORMAT,      ///< Well-formed bytes, but not a format handled here.
  GCERT_ERR_UNSUPPORTED, ///< The format is known and the feature is not
                        ///< implemented.
  GCERT_ERR_LIMIT,       ///< A ::GCERT_Limits field was exceeded.
  GCERT_ERR_CORRUPT,     ///< The bytes are not a valid encoding of this format.
  GCERT_ERR_OOM,         ///< The allocator returned NULL.
  GCERT_ERR_INVALID,     ///< A caller-supplied argument is wrong.
  GCERT_ERR_INTERNAL,    ///< The library's own invariant failed.
  GCERT_ERR_MISMATCH,    ///< A comparison, MAC, tag, or signature did not match.
  GCERT_RESULT_COUNT
} GCERT_Result;

/**
 * @brief Static description of a result code.
 *
 * The string is never NULL, never allocated, and never contains caller data.
 *
 * @param result The result code, including values outside the enum.
 * @return A static string.
 */
GCERT_API const char * gcert_result_string(GCERT_Result result);

/** Default ceiling on password-based derivation iterations. */
#define GCERT_PBE_ITERATIONS_DEFAULT 10000000u

/** Default for ::GCERT_Limits::max_trust_anchors. */
#define GCERT_TRUST_ANCHORS_DEFAULT 4096u

/**
 * @brief Caps on quantities a file can ask the library to spend.
 *
 * NULL at a call means these defaults.
 */
typedef struct GCERT_Limits {
  /**
   * Most password-based derivation iterations a file may ask for, for
   * ::gcert_pkcs8_decrypt and ::gcert_pkcs12_open. Default
   * ::GCERT_PBE_ITERATIONS_DEFAULT.
   *
   * The iteration count comes out of the file, so it is an attacker's
   * number when the file is. One PBKDF2-HMAC-SHA256 iteration is about
   * 0.9 microseconds here, so the default ceiling is around nine seconds
   * of CPU for one call. A caller that opens files it did not create -
   * a server, anything unattended - wants this much lower; a few hundred
   * thousand covers every file a tool in this decade writes.
   */
  uint32_t max_pbe_iterations;
  /**
   * Most anchors a ::GCERT_TrustStore holds. Default
   * ::GCERT_TRUST_ANCHORS_DEFAULT, which is several times the size of any
   * operating system's root list. A caller that loads a file it did not
   * write wants this no higher than it needs. 0 means the default.
   */
  uint32_t max_trust_anchors;
  /**
   * Largest file ::gcert_trust_add_file reads, in bytes. Default 16 MiB;
   * 0 means the default.
   */
  uint32_t max_trust_file_bytes;
  /**
   * Most certificates ::gcert_chain_build takes in its pool, the ones a peer
   * sent. More is ::GCERT_ERR_LIMIT, not a silent truncation. Default 32;
   * 0 means the default.
   */
  uint32_t max_chain_pool;
  /**
   * Most signature verifications and path validations one
   * ::gcert_chain_build may spend looking for a path. A pool of
   * cross-signed certificates has exponentially many candidate paths, and
   * each step costs a public-key operation; this is what bounds a hostile
   * peer. Default 256; 0 means the default. Exceeding it is
   * ::GCERT_ERR_LIMIT.
   */
  uint32_t max_chain_attempts;
} GCERT_Limits;

/**
 * @brief Fill in the default limits.
 *
 * @param limits Structure to populate. NULL is ignored.
 */
GCERT_API void gcert_limits_default(GCERT_Limits * limits);

/**
 * @brief This build's version, as the string the Makefile generated.
 *
 * @return A static string, never NULL. "0.0.0", or "0.0.0-dev" when BRANCH
 *   was overridden.
 */
GCERT_API const char * gcert_version_string(void);

/**
 * @brief This build's version, packed as ::GCERT_MAKE_VERSION packs it.
 *
 * @return `(major << 16) | (minor << 8) | patch`.
 */
GCERT_API unsigned gcert_version_number(void);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GCERT_CORE_H */
