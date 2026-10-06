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
 * The same signature rules a certificate uses, for a CRL and an OCSP
 * response.
 */

#include <ghoti.io/certificate/macros.h>
#include "../core/sec_result.h"

#include <ghoti.io/security/ecdsa_p256.h>
#include <ghoti.io/security/ecdsa_p384.h>
#include <ghoti.io/security/ed25519.h>
#include <ghoti.io/security/rsa.h>

#include "../der/der_int.h"
#include "signed.h"

static const unsigned char OID_RSA_MD5[] = {
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x04
};
static const unsigned char OID_RSA_SHA1[] = {
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05
};
static const unsigned char OID_RSA_SHA256[] = {
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b
};
static const unsigned char OID_RSA_SHA384[] = {
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c
};
static const unsigned char OID_RSA_SHA512[] = {
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d
};
static const unsigned char OID_ECDSA_SHA256[] = {
  0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02
};
static const unsigned char OID_ECDSA_SHA384[] = {
  0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03
};
static const unsigned char OID_ED25519[] = {0x2b, 0x65, 0x70};

static GCERT_Result null_param(const unsigned char ** p, size_t * left) {
  GCERT_Der param;
  GCERT_Result result;

  if (*left == 0) {
    return GCERT_ERR_CORRUPT;
  }
  result = gcert_der_next(p, left, &param);
  if (result != GCERT_OK || *left != 0) {
    return GCERT_ERR_CORRUPT;
  }
  if (!gcert_der_is(&param, GCERT_DER_UNIVERSAL, 0, 5) || param.value_len != 0) {
    return GCERT_ERR_CORRUPT;
  }
  return GCERT_OK;
}

GCERT_Result x509_sig_alg(const GCERT_Der * alg, uint32_t * key, uint32_t * hash) {
  const unsigned char * p;
  size_t left;
  GCERT_Der oid;
  GCERT_Result result;

  *key = 0;
  *hash = 0;
  if (!gcert_der_is(alg, GCERT_DER_UNIVERSAL, 1, 16)) {
    return GCERT_ERR_CORRUPT;
  }
  p = alg->value;
  left = alg->value_len;
  result = gcert_der_next(&p, &left, &oid);
  if (result != GCERT_OK || gcert_der_oid_ok(&oid) != GCERT_OK) {
    return GCERT_ERR_CORRUPT;
  }
  if (gcert_der_oid_is(&oid, OID_RSA_MD5, sizeof OID_RSA_MD5)) {
    *hash = GSEC_RSA_MD5;
    *key = GCERT_X509_RSA;
  } else if (gcert_der_oid_is(&oid, OID_RSA_SHA1, sizeof OID_RSA_SHA1)) {
    *hash = GSEC_RSA_SHA1;
    *key = GCERT_X509_RSA;
  } else if (gcert_der_oid_is(&oid, OID_RSA_SHA256, sizeof OID_RSA_SHA256)) {
    *hash = GSEC_RSA_SHA256;
    *key = GCERT_X509_RSA;
  } else if (gcert_der_oid_is(&oid, OID_RSA_SHA384, sizeof OID_RSA_SHA384)) {
    *hash = GSEC_RSA_SHA384;
    *key = GCERT_X509_RSA;
  } else if (gcert_der_oid_is(&oid, OID_RSA_SHA512, sizeof OID_RSA_SHA512)) {
    *hash = GSEC_RSA_SHA512;
    *key = GCERT_X509_RSA;
  } else if (gcert_der_oid_is(&oid, OID_ECDSA_SHA256, sizeof OID_ECDSA_SHA256)) {
    *key = GCERT_X509_P256;
  } else if (gcert_der_oid_is(&oid, OID_ECDSA_SHA384, sizeof OID_ECDSA_SHA384)) {
    *key = GCERT_X509_P384;
  } else if (gcert_der_oid_is(&oid, OID_ED25519, sizeof OID_ED25519)) {
    *key = GCERT_X509_ED25519;
    if (left != 0) {
      return GCERT_ERR_CORRUPT;
    }
    return GCERT_OK;
  } else {
    return GCERT_ERR_UNSUPPORTED;
  }
  if (*key == GCERT_X509_RSA) {
    return null_param(&p, &left);
  }
  if (left != 0) {
    return GCERT_ERR_CORRUPT;
  }
  return GCERT_OK;
}

static GCERT_Result ecdsa_raw(const unsigned char * bits, size_t bits_len,
    size_t width, unsigned char * raw) {
  GCERT_Der seq;
  GCERT_Der num;
  GCERT_Result result;
  const unsigned char * p;
  size_t left;
  const unsigned char * be;
  size_t be_len;
  size_t i;

  result = gcert_der_tlv(bits, bits_len, &seq);
  if (result != GCERT_OK || seq.total_len != bits_len ||
      !gcert_der_is(&seq, GCERT_DER_UNIVERSAL, 1, 16)) {
    return GCERT_ERR_CORRUPT;
  }
  p = seq.value;
  left = seq.value_len;
  for (i = 0; i < width * 2u; i++) {
    raw[i] = 0;
  }
  for (i = 0; i < 2; i++) {
    size_t j;
    unsigned char * dest;
    result = gcert_der_next(&p, &left, &num);
    if (result != GCERT_OK) {
      return result;
    }
    result = gcert_der_unsigned(&num, &be, &be_len);
    if (result != GCERT_OK || be_len == 0 || be_len > width) {
      return GCERT_ERR_CORRUPT;
    }
    dest = raw + i * width + (width - be_len);
    for (j = 0; j < be_len; j++) {
      dest[j] = be[j];
    }
  }
  if (left != 0) {
    return GCERT_ERR_CORRUPT;
  }
  return GCERT_OK;
}

GCERT_Result x509_sig_bits(uint32_t key, const unsigned char * bits,
    size_t bits_len, const unsigned char ** sig, size_t * sig_len,
    unsigned char raw[96]) {
  if (key == GCERT_X509_RSA || key == GCERT_X509_ED25519) {
    *sig = bits;
    *sig_len = bits_len;
    return GCERT_OK;
  }
  if (key == GCERT_X509_P256 || key == GCERT_X509_P384) {
    size_t width = key == GCERT_X509_P256 ? 32u : 48u;
    GCERT_Result result = ecdsa_raw(bits, bits_len, width, raw);
    if (result != GCERT_OK) {
      return result;
    }
    *sig = raw;
    *sig_len = width * 2u;
    return GCERT_OK;
  }
  return GCERT_ERR_UNSUPPORTED;
}

GCERT_Result x509_sig_verify(uint32_t key, uint32_t hash, const unsigned char * sig,
    size_t sig_len, const unsigned char * tbs, size_t tbs_len,
    const GCERT_X509 * issuer) {
  if (issuer == NULL || tbs == NULL || sig == NULL || issuer->key == 0) {
    return GCERT_ERR_INVALID;
  }
  if (key != issuer->key) {
    return GCERT_ERR_MISMATCH;
  }
  if (issuer->key == GCERT_X509_RSA) {
    return gcert_from_gsec(gsec_rsa_pkcs1_v15_verify(hash, issuer->n, issuer->n_len, issuer->e,
        issuer->e_len, tbs, tbs_len, sig, sig_len));
  }
  if (issuer->key == GCERT_X509_P256) {
    return gcert_from_gsec(gsec_ecdsa_p256_verify(issuer->point, tbs, tbs_len, sig));
  }
  if (issuer->key == GCERT_X509_P384) {
    return gcert_from_gsec(gsec_ecdsa_p384_verify(issuer->point, tbs, tbs_len, sig));
  }
  if (issuer->key == GCERT_X509_ED25519) {
    return gcert_from_gsec(gsec_ed25519_verify(issuer->point, tbs, tbs_len, sig));
  }
  return GCERT_ERR_UNSUPPORTED;
}
