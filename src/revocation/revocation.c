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
 * @file
 *
 * The checks around a CRL or an OCSP response. The rules are in
 * revocation.h; the one place a decision is made is
 * gcert_revocation_verdict.
 */

#include <ghoti.io/certificate/macros.h>

#include <ghoti.io/certificate/revocation.h>
#include <ghoti.io/security/hmac.h>
#include <ghoti.io/security/sha1.h>
#include <ghoti.io/security/sha256.h>

#include "../der/der_int.h"
#include "../core/sec_result.h"

#include <string.h>

#define KU_CRL_SIGN 0x02u  /* bit 6 of keyUsage, in the layout GCERT_X509::key_usage uses */

void gcert_revocation_policy_default(GCERT_RevocationPolicy * policy) {
  if (policy == NULL) {
    return;
  }
  memset(policy, 0, sizeof *policy);
  policy->clock_skew = GCERT_REVOCATION_SKEW_DEFAULT;
  policy->max_age = GCERT_REVOCATION_MAX_AGE_DEFAULT;
}

static void resolve(const GCERT_RevocationPolicy * in, GCERT_RevocationPolicy * out) {
  gcert_revocation_policy_default(out);
  if (in == NULL) {
    return;
  }
  out->soft_fail = in->soft_fail;
  if (in->clock_skew > 0) {
    out->clock_skew = in->clock_skew;
  }
  if (in->max_age > 0) {
    out->max_age = in->max_age;
  }
}

static void unusable(GCERT_Revocation * out, GCERT_RevocationReason why) {
  memset(out, 0, sizeof *out);
  out->status = GCERT_REVOCATION_UNUSABLE;
  out->reason = why;
}

static int issued_by(const GCERT_X509 * cert, const GCERT_X509 * issuer) {
  return gcert_der_eq(cert->issuer, cert->issuer_len, issuer->subject, issuer->subject_len);
}

/* May @p issuer sign a list or a response: a CA when it says anything about
 * being one, with cRLSign when it restricts its key usage. @p need_crl_sign is
 * 0 for OCSP, where the issuer signing directly needs no cRLSign. */
static int may_sign(const GCERT_X509 * issuer, int need_crl_sign) {
  if (issuer->basic_constraints && !issuer->ca) {
    return 0;
  }
  if (need_crl_sign && issuer->key_usage_set && (issuer->key_usage & KU_CRL_SIGN) == 0) {
    return 0;
  }
  return 1;
}

/* GCERT_REVOCATION_NONE when an answer produced at @p this_update, good until
 * @p next_update, is fresh at @p now. */
static GCERT_RevocationReason fresh(int64_t this_update, int have_next, int64_t next_update,
    int64_t now, const GCERT_RevocationPolicy * p) {
  if (this_update > now && this_update - now > p->clock_skew) {
    return GCERT_REVOCATION_NOT_YET_VALID;
  }
  if (have_next) {
    if (now > next_update && now - next_update > p->clock_skew) {
      return GCERT_REVOCATION_STALE;
    }
  } else if (now > this_update && now - this_update > p->max_age) {
    return GCERT_REVOCATION_STALE;
  }
  return GCERT_REVOCATION_NONE;
}

GCERT_Result gcert_crl_check(const GCERT_Crl * crl, const GCERT_X509 * issuer,
    const GCERT_X509 * cert, int64_t now, const GCERT_RevocationPolicy * policy,
    GCERT_Revocation * out) {
  GCERT_RevocationPolicy p;
  GCERT_RevocationReason why;
  GCERT_Result result;

  if (out == NULL) {
    return GCERT_ERR_INVALID;
  }
  unusable(out, GCERT_REVOCATION_MALFORMED);
  if (crl == NULL || issuer == NULL || cert == NULL || cert->serial == NULL ||
      crl->issuer == NULL) {
    return GCERT_ERR_INVALID;
  }
  resolve(policy, &p);
  if (!issued_by(cert, issuer) ||
      !gcert_der_eq(crl->issuer, crl->issuer_len, issuer->subject, issuer->subject_len)) {
    unusable(out, GCERT_REVOCATION_WRONG_ISSUER);
    return GCERT_OK;
  }
  if (!may_sign(issuer, 1)) {
    unusable(out, GCERT_REVOCATION_CANNOT_SIGN);
    return GCERT_OK;
  }
  result = gcert_crl_signed_by(crl, issuer);
  if (result != GCERT_OK) {
    unusable(out, GCERT_REVOCATION_BAD_SIGNATURE);
    return GCERT_OK;
  }
  why = fresh(crl->this_update, crl->next_set, crl->next_update, now, &p);
  if (why != GCERT_REVOCATION_NONE) {
    unusable(out, why);
    return GCERT_OK;
  }
  result = gcert_crl_contains(crl, cert->serial, cert->serial_len);
  memset(out, 0, sizeof *out);
  if (result == GCERT_OK) {
    out->status = GCERT_REVOCATION_REVOKED;
    return GCERT_OK;
  }
  if (result == GCERT_ERR_MISMATCH) {
    out->status = GCERT_REVOCATION_GOOD;
    return GCERT_OK;
  }
  unusable(out, GCERT_REVOCATION_MALFORMED);
  return GCERT_OK;
}

/* H(issuer name) and H(issuer key bits) with the hash an OCSP CertID names. */
static int cert_id_hashes(uint32_t hash, const GCERT_X509 * issuer, unsigned char name[32],
    unsigned char key[32], size_t * n) {
  GSEC_Result a;
  GSEC_Result b;
  if (hash == GSEC_HMAC_SHA256) {
    a = gsec_sha256(issuer->subject, issuer->subject_len, name);
    b = gsec_sha256(issuer->key_bits, issuer->key_bits_len, key);
    *n = 32;
  } else {
    a = gsec_sha1(issuer->subject, issuer->subject_len, name);
    b = gsec_sha1(issuer->key_bits, issuer->key_bits_len, key);
    *n = 20;
  }
  return a == GSEC_OK && b == GSEC_OK;
}

GCERT_Result gcert_ocsp_check(const GCERT_Ocsp * ocsp, const GCERT_X509 * issuer,
    const GCERT_X509 * responder, const GCERT_X509 * cert, int64_t now,
    const GCERT_RevocationPolicy * policy, GCERT_Revocation * out) {
  GCERT_RevocationPolicy p;
  GCERT_RevocationReason why;
  const GCERT_X509 * signer = issuer;
  GCERT_Ocsp_Single single;
  static const uint32_t HASHES[2] = {GSEC_HMAC_SHA256, GSEC_HMAC_SHA1};
  int found = 0;
  size_t i;

  if (out == NULL) {
    return GCERT_ERR_INVALID;
  }
  unusable(out, GCERT_REVOCATION_MALFORMED);
  if (ocsp == NULL || issuer == NULL || cert == NULL || cert->serial == NULL ||
      issuer->key_bits == NULL) {
    return GCERT_ERR_INVALID;
  }
  memset(&single, 0, sizeof single);
  resolve(policy, &p);
  if (!issued_by(cert, issuer)) {
    unusable(out, GCERT_REVOCATION_WRONG_ISSUER);
    return GCERT_OK;
  }
  if (responder != NULL) {
    if (gcert_x509_signed_by(responder, issuer) != GCERT_OK ||
        responder->not_before > now || responder->not_after < now ||
        !responder->eku_set || (responder->eku & GCERT_X509_EKU_OCSP_SIGNING) == 0) {
      unusable(out, GCERT_REVOCATION_RESPONDER);
      return GCERT_OK;
    }
    signer = responder;
  } else if (!may_sign(issuer, 0)) {
    unusable(out, GCERT_REVOCATION_CANNOT_SIGN);
    return GCERT_OK;
  }
  if (gcert_ocsp_signed_by(ocsp, signer) != GCERT_OK) {
    unusable(out, GCERT_REVOCATION_BAD_SIGNATURE);
    return GCERT_OK;
  }
  for (i = 0; i < 2 && !found; i++) {
    unsigned char name[32];
    unsigned char key[32];
    size_t n = 0;
    GCERT_Result result;
    if (!cert_id_hashes(HASHES[i], issuer, name, key, &n)) {
      return GCERT_ERR_INTERNAL;
    }
    result = gcert_ocsp_status(ocsp, HASHES[i], name, n, key, n, cert->serial,
        cert->serial_len, &single);
    if (result == GCERT_OK) {
      found = 1;
    } else if (result != GCERT_ERR_MISMATCH) {
      unusable(out, GCERT_REVOCATION_MALFORMED);
      return GCERT_OK;
    }
  }
  if (!found) {
    unusable(out, GCERT_REVOCATION_UNKNOWN_CERT);
    return GCERT_OK;
  }
  why = fresh(single.this_update, single.have_next_update, single.next_update, now, &p);
  if (why != GCERT_REVOCATION_NONE) {
    unusable(out, why);
    return GCERT_OK;
  }
  memset(out, 0, sizeof *out);
  if (single.status == GCERT_OCSP_GOOD) {
    out->status = GCERT_REVOCATION_GOOD;
  } else if (single.status == GCERT_OCSP_REVOKED) {
    out->status = GCERT_REVOCATION_REVOKED;
    out->revoked_at = single.revoked_at;
  } else {
    unusable(out, GCERT_REVOCATION_UNKNOWN_CERT);
  }
  return GCERT_OK;
}

GCERT_Result gcert_revocation_verdict(const GCERT_Revocation * evidence, size_t count,
    const GCERT_RevocationPolicy * policy) {
  size_t i;
  int good = 0;

  if (evidence == NULL && count != 0) {
    return GCERT_ERR_INVALID;
  }
  for (i = 0; i < count; i++) {
    if (evidence[i].status == GCERT_REVOCATION_REVOKED) {
      return GCERT_ERR_MISMATCH;
    }
    if (evidence[i].status == GCERT_REVOCATION_GOOD) {
      good = 1;
    }
  }
  if (good) {
    return GCERT_OK;
  }
  return policy != NULL && policy->soft_fail ? GCERT_OK : GCERT_ERR_MISMATCH;
}
