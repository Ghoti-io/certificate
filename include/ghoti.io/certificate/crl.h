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
 * @file crl.h
 *
 * A certificate revocation list, as RFC 5280 specifies it.
 *
 * Parsing and the signature check live here. Fetching the list does not.
 * A critical extension this parser does not understand is rejected.
 * The pointers address the caller's buffer, except an ECDSA signature,
 * which is copied into the result.
 */

#ifndef GHOTI_IO_GCERT_CRL_H
#define GHOTI_IO_GCERT_CRL_H

#include <ghoti.io/certificate/core.h>
#include <ghoti.io/certificate/macros.h>
#include <ghoti.io/certificate/x509.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief A parsed CRL. The view is valid while the DER is.
 */
typedef struct GCERT_Crl {
  const unsigned char * tbs;      ///< The signed TBSCertList, header included.
  size_t tbs_len;                 ///< Length of @p tbs.
  const unsigned char * issuer;   ///< The issuer Name, whole SEQUENCE.
  size_t issuer_len;              ///< Length of @p issuer.
  int64_t this_update;            ///< thisUpdate, as seconds since 1970-01-01 UTC.
  int next_set;                   ///< 1 when the list carries nextUpdate.
  int64_t next_update;            ///< nextUpdate, in the same units; meaningful when @p next_set is 1.
  uint32_t sig_key;               ///< Signature key kind, a ::GCERT_X509_RSA or other key constant.
  uint32_t sig_hash;              ///< Signature digest, a ::GSEC_RSA_SHA256 or other id.
  const unsigned char * sig;      ///< The signature bits (for ECDSA, see @p ecdsa_raw).
  size_t sig_len;                 ///< Length of @p sig.
  unsigned char ecdsa_raw[96];    ///< An ECDSA signature as r then s, each zero-padded to the curve's width.
  const unsigned char * revoked;  ///< The revokedCertificates entries, or NULL when there are none.
  size_t revoked_len;             ///< Length of @p revoked.
} GCERT_Crl;

/**
 * @brief Parse one CertificateList.
 *
 * @param der DER encoding. NULL only when @p len is 0.
 * @param len Length of @p der. Above ::GCERT_X509_DER_MAX is
 *   ::GCERT_ERR_LIMIT.
 * @param out View. Not NULL.
 * @return ::GCERT_OK, ::GCERT_ERR_CORRUPT, ::GCERT_ERR_UNSUPPORTED,
 *   ::GCERT_ERR_LIMIT, or ::GCERT_ERR_INVALID.
 */
GCERT_API GCERT_Result gcert_crl_parse(const void * der, size_t len,
    GCERT_Crl * out);

/**
 * @brief Check that @p issuer's key signed @p crl.
 *
 * @return ::GCERT_OK, ::GCERT_ERR_MISMATCH, or ::GCERT_ERR_INVALID.
 */
GCERT_API GCERT_Result gcert_crl_signed_by(const GCERT_Crl * crl,
    const GCERT_X509 * issuer);

/**
 * @brief Report whether @p serial appears on the list.
 *
 * @p serial is the unsigned magnitude. A hit is ::GCERT_OK. An absent
 * serial is ::GCERT_ERR_MISMATCH.
 */
GCERT_API GCERT_Result gcert_crl_contains(const GCERT_Crl * crl, const void * serial,
    size_t serial_len);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GCERT_CRL_H */
