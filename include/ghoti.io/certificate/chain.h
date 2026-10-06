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
 * @file chain.h
 *
 * Choose a path from a peer's certificates to a trust anchor.
 *
 * A peer sends a leaf and whatever else it thought useful, in any order,
 * possibly with extras and possibly missing an intermediate it assumed you
 * had. ::gcert_x509_path wants an ordered path. ::gcert_chain_build finds
 * one: starting at the leaf it looks, for each certificate, for an issuer
 * among the trust anchors and then among the rest of the pool, checks that
 * the issuer's key signed it, and when a candidate path reaches an anchor
 * hands it to ::gcert_x509_path. **The verdict is always that function's**;
 * the search only decides what to ask it, so it cannot accept a path that
 * function would refuse. A path built from the pool alone is never
 * accepted: it has to end at an anchor in the store.
 *
 * The pool is untrusted input and the search is bounded:
 * ::GCERT_Limits::max_chain_pool certificates are read and
 * ::GCERT_Limits::max_chain_attempts signature checks and path validations
 * are spent, then the answer is ::GCERT_ERR_LIMIT. A pool entry that does
 * not parse is ignored, which is what a client wants of a peer's stray
 * bytes; the leaf must parse.
 */

#ifndef GHOTI_IO_GCERT_CHAIN_H
#define GHOTI_IO_GCERT_CHAIN_H

#include <ghoti.io/certificate/core.h>
#include <ghoti.io/certificate/macros.h>
#include <ghoti.io/certificate/trust.h>
#include <ghoti.io/certificate/x509.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Why no path was accepted. The most informative reason found wins. */
typedef enum GCERT_ChainFailure {
  GCERT_CHAIN_NONE = 0,         ///< A path was accepted.
  GCERT_CHAIN_UNKNOWN_ISSUER,   ///< No certificate or anchor could have signed the end of the path.
  GCERT_CHAIN_BAD_SIGNATURE,    ///< Candidate issuers existed and none of their keys signed it.
  GCERT_CHAIN_EXPIRED,          ///< A certificate that would have fit was past its notAfter.
  GCERT_CHAIN_NOT_YET_VALID,    ///< A certificate that would have fit was before its notBefore.
  GCERT_CHAIN_REJECTED          ///< A path to an anchor was refused by ::gcert_x509_path's policy.
} GCERT_ChainFailure;

/**
 * @brief A path found by ::gcert_chain_build.
 *
 * @p mid holds indices into the pool in the order ::gcert_x509_path takes
 * intermediates: @p mid[0] is the certificate the anchor signed, and the
 * last is the one that signed the leaf.
 * @p anchor is an index into the trust store.
 */
typedef struct GCERT_Chain {
  size_t mid[GCERT_X509_CHAIN_MAX];  ///< Pool indices of the intermediates, the anchor's side first.
  size_t mid_count;                  ///< How many intermediates.
  size_t anchor;                     ///< Index of the anchor in the trust store.
  GCERT_ChainFailure failure;        ///< GCERT_CHAIN_NONE on success, otherwise why not.
} GCERT_Chain;

/**
 * @brief Find and validate a path from @p leaf to an anchor in @p store.
 *
 * @param store The anchors. Not NULL.
 * @param leaf The end-entity certificate, DER.
 * @param pool Other certificates the peer sent, DER; NULL only when
 *   @p pool_count is 0. Order does not matter, and the leaf may be among
 *   them.
 * @param pool_lens Length of each.
 * @param pool_count How many.
 * @param unix_time The instant to validate at, seconds since 1970-01-01 UTC.
 * @param purpose 0, or one ::GCERT_X509_EKU_* bit the leaf must permit, as
 *   for ::gcert_x509_path. A TLS client passes ::GCERT_X509_EKU_SERVER_AUTH.
 * @param out The path, and on a refusal the reason. Always written (zeroed
 *   with @p failure set) when @p out is not NULL.
 * @return ::GCERT_OK with @p out filled in; ::GCERT_ERR_MISMATCH when no path
 *   validates (see @p out->failure); ::GCERT_ERR_LIMIT when the pool is too
 *   large or the search budget ran out; ::GCERT_ERR_CORRUPT or
 *   ::GCERT_ERR_UNSUPPORTED when the leaf does not parse; ::GCERT_ERR_OOM;
 *   or ::GCERT_ERR_INVALID.
 */
GCERT_API GCERT_Result gcert_chain_build(const GCERT_TrustStore * store,
    const void * leaf, size_t leaf_len, const void * const * pool,
    const size_t * pool_lens, size_t pool_count, int64_t unix_time,
    unsigned purpose, const GCERT_Limits * limits, GCERT_Chain * out);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GCERT_CHAIN_H */
