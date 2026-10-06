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
 * @file revocation.h
 *
 * What a verifier does with a CRL or an OCSP response once it has one.
 *
 * crl.h and ocsp.h read and authenticate the bytes. This file adds the
 * checks that make an answer count: that it is about this certificate's
 * issuer, that the issuer was allowed to sign it, that it is fresh, and
 * that the person who has no answer at all gets a decision the caller chose
 * rather than one the library did. **Fetching stays with the caller**,
 * because fetching is I/O; so does the clock, which is an argument.
 *
 * A check never returns an error for evidence it cannot use. It returns
 * ::GCERT_OK with a ::GCERT_Revocation whose status says GOOD, REVOKED or
 * UNUSABLE and, for the last, why. Only a malformed call is an error. That
 * is so that the decision is made in one place, ::gcert_revocation_verdict,
 * and cannot be made differently by every caller who forgot to look at an
 * error code.
 *
 * Not handled: delta CRLs, indirect CRLs and CRLs partitioned by an issuing
 * distribution point (each is a critical extension that crl.h refuses, so
 * the answer is a parse error from there, not a wrong answer from here); an
 * OCSP response signed by anyone but the issuer or a responder certificate
 * the issuer signed with id-kp-OCSPSigning; and the OCSP nonce. A stapled
 * response needs no nonce; a fetched one is the caller's to protect.
 */

#ifndef GHOTI_IO_GCERT_REVOCATION_H
#define GHOTI_IO_GCERT_REVOCATION_H

#include <ghoti.io/certificate/core.h>
#include <ghoti.io/certificate/crl.h>
#include <ghoti.io/certificate/macros.h>
#include <ghoti.io/certificate/ocsp.h>
#include <ghoti.io/certificate/x509.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Default for ::GCERT_RevocationPolicy::max_age: seven days, in seconds. */
#define GCERT_REVOCATION_MAX_AGE_DEFAULT (7 * 24 * 60 * 60)

/** Default for ::GCERT_RevocationPolicy::clock_skew: five minutes, in seconds. */
#define GCERT_REVOCATION_SKEW_DEFAULT 300

/**
 * @brief What is decided, and what is tolerated.
 *
 * A zeroed struct is the default policy: **hard fail**, five minutes of
 * clock skew, and a seven-day age limit for answers that carry no
 * nextUpdate. @p clock_skew and @p max_age of 0 mean those defaults; to
 * allow no skew at all set @p clock_skew to 1.
 */
typedef struct GCERT_RevocationPolicy {
  int soft_fail;       ///< 0 (the default): no usable evidence refuses. Nonzero: no usable evidence accepts.
  int64_t clock_skew;  ///< Seconds a thisUpdate may be ahead of, and a nextUpdate behind, the caller's clock; 0 is the default.
  int64_t max_age;     ///< Longest an answer without nextUpdate stays fresh, in seconds; 0 is the default.
} GCERT_RevocationPolicy;

/** @brief What a piece of evidence says about the certificate. */
typedef enum GCERT_RevocationStatus {
  GCERT_REVOCATION_UNUSABLE = 0,  ///< It says nothing that can be relied on; see the reason.
  GCERT_REVOCATION_GOOD,          ///< Authentic, fresh, and the certificate is not revoked.
  GCERT_REVOCATION_REVOKED        ///< Authentic, fresh, and the certificate is revoked.
} GCERT_RevocationStatus;

/** @brief Why evidence was unusable. */
typedef enum GCERT_RevocationReason {
  GCERT_REVOCATION_NONE = 0,         ///< The evidence was usable.
  GCERT_REVOCATION_WRONG_ISSUER,     ///< It is not from this certificate's issuer.
  GCERT_REVOCATION_CANNOT_SIGN,      ///< The issuer's keyUsage or basicConstraints forbids signing it.
  GCERT_REVOCATION_BAD_SIGNATURE,    ///< The signature does not verify.
  GCERT_REVOCATION_NOT_YET_VALID,    ///< Its thisUpdate is in the future beyond the skew.
  GCERT_REVOCATION_STALE,            ///< Past its nextUpdate, or older than the age limit.
  GCERT_REVOCATION_UNKNOWN_CERT,     ///< An OCSP response that does not cover this certificate, or says unknown.
  GCERT_REVOCATION_RESPONDER,        ///< The delegated responder is not authorised or not in force.
  GCERT_REVOCATION_MALFORMED         ///< It could not be read far enough to answer.
} GCERT_RevocationReason;

/** @brief The result of checking one piece of evidence. */
typedef struct GCERT_Revocation {
  GCERT_RevocationStatus status;  ///< Good, revoked, or unusable.
  GCERT_RevocationReason reason;  ///< Why unusable; ::GCERT_REVOCATION_NONE otherwise.
  int64_t revoked_at;             ///< For an OCSP revocation, when; 0 when unknown or for a CRL.
} GCERT_Revocation;

/** @brief Fill @p policy with the defaults. */
GCERT_API void gcert_revocation_policy_default(GCERT_RevocationPolicy * policy);

/**
 * @brief Check @p cert against a CRL from @p issuer.
 *
 * Tests, in this order: that @p cert was issued by @p issuer and the list
 * names @p issuer; that @p issuer may sign lists (cRLSign when keyUsage is
 * present, and a CA when basicConstraints is); that its key signed it; that
 * it is fresh at @p now; and then whether the serial is on it.
 *
 * @param policy NULL for the defaults.
 * @param out Always written. Not NULL.
 * @return ::GCERT_OK, or ::GCERT_ERR_INVALID.
 */
GCERT_API GCERT_Result gcert_crl_check(const GCERT_Crl * crl, const GCERT_X509 * issuer,
    const GCERT_X509 * cert, int64_t now, const GCERT_RevocationPolicy * policy,
    GCERT_Revocation * out);

/**
 * @brief Check @p cert against an OCSP response.
 *
 * The response must be signed by @p issuer or, when @p responder is not NULL,
 * by @p responder, which must itself be signed by @p issuer, in force at
 * @p now, and carry extendedKeyUsage id-kp-OCSPSigning (a certificate with no
 * extendedKeyUsage is not a responder, whatever ::gcert_x509_purpose says
 * about it). The CertID is looked up with SHA-256 and then SHA-1, since
 * responders echo the hash of the request they were sent. Freshness is
 * thisUpdate against the skew and nextUpdate, or the age limit when there is
 * no nextUpdate. A status of unknown is unusable, not good.
 *
 * @param responder NULL when @p issuer signed the response.
 * @param policy NULL for the defaults.
 * @param out Always written. Not NULL.
 * @return ::GCERT_OK, or ::GCERT_ERR_INVALID.
 */
GCERT_API GCERT_Result gcert_ocsp_check(const GCERT_Ocsp * ocsp,
    const GCERT_X509 * issuer, const GCERT_X509 * responder, const GCERT_X509 * cert,
    int64_t now, const GCERT_RevocationPolicy * policy, GCERT_Revocation * out);

/**
 * @brief Decide, from everything the caller found, whether to go on.
 *
 * Any revoked answer refuses. Otherwise any good answer accepts. Otherwise,
 * which is no evidence or none usable, the policy decides: refuse unless
 * ::GCERT_RevocationPolicy::soft_fail. An answer that is merely unusable
 * never outvotes a good one (a stale CRL beside a fresh OCSP response is
 * fine), and never outvotes a revoked one the other way either.
 *
 * @param evidence @p count results from the check functions; NULL only when
 *   @p count is 0, which is the caller having found nothing.
 * @param policy NULL for the defaults.
 * @return ::GCERT_OK to go on, ::GCERT_ERR_MISMATCH to refuse, or
 *   ::GCERT_ERR_INVALID.
 */
GCERT_API GCERT_Result gcert_revocation_verdict(const GCERT_Revocation * evidence,
    size_t count, const GCERT_RevocationPolicy * policy);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GCERT_REVOCATION_H */
