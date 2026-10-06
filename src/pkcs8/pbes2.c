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
 * PBES2 with PBKDF2 and AES-CBC or three-key Triple DES. The padding
 * check walks the whole last block and only then branches.
 */

#include <ghoti.io/certificate/macros.h>
#include "../core/sec_result.h"

#include <ghoti.io/security/aes_cbc.h>
#include <ghoti.io/security/des.h>
#include <ghoti.io/security/pbkdf2.h>
#include <ghoti.io/security/secret.h>

#include "../der/der_int.h"
#include "pbes2.h"

#include <string.h>

#if defined(GCERT_CT_TEST)
#include <valgrind/memcheck.h>
#endif

static const unsigned char OID_PBES2[] = {
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0d
};
static const unsigned char OID_PBKDF2[] = {
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0c
};
static const unsigned char OID_HMAC_SHA1[] = {
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x07
};
static const unsigned char OID_HMAC_SHA256[] = {
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x09
};
static const unsigned char OID_HMAC_SHA384[] = {
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x0a
};
static const unsigned char OID_HMAC_SHA512[] = {
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x0b
};
static const unsigned char OID_AES128[] = {
  0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02
};
static const unsigned char OID_AES192[] = {
  0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x16
};
static const unsigned char OID_AES256[] = {
  0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a
};
static const unsigned char OID_DES_EDE3[] = {
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x03, 0x07
};

static uint32_t bit_of(uint32_t x) {
  x |= x >> 16;
  x |= x >> 8;
  x |= x >> 4;
  x |= x >> 2;
  x |= x >> 1;
  return x & 1u;
}

static uint32_t eq_byte(unsigned char a, uint32_t b) {
  return bit_of((uint32_t)a ^ b) ^ 1u;
}

static GCERT_Result u32_of(const GCERT_Der * v, uint32_t * out) {
  const unsigned char * be;
  size_t n;
  size_t i;
  uint32_t value;
  GCERT_Result result;

  result = gcert_der_unsigned(v, &be, &n);
  if (result != GCERT_OK) {
    return result;
  }
  if (n == 0 || n > 4) {
    return GCERT_ERR_LIMIT;
  }
  value = 0;
  for (i = 0; i < n; i++) {
    value = (value << 8) | be[i];
  }
  *out = value;
  return GCERT_OK;
}

static GCERT_Result prf_of(const GCERT_Der * alg, uint32_t * hash) {
  const unsigned char * p;
  size_t left;
  GCERT_Der oid;
  GCERT_Result result;

  if (alg == NULL) {
    *hash = GSEC_PBKDF2_SHA1;
    return GCERT_OK;
  }
  if (!gcert_der_is(alg, GCERT_DER_UNIVERSAL, 1, 16)) {
    return GCERT_ERR_CORRUPT;
  }
  p = alg->value;
  left = alg->value_len;
  result = gcert_der_next(&p, &left, &oid);
  if (result != GCERT_OK || gcert_der_oid_ok(&oid) != GCERT_OK) {
    return GCERT_ERR_CORRUPT;
  }
  if (gcert_der_oid_is(&oid, OID_HMAC_SHA1, sizeof OID_HMAC_SHA1)) {
    *hash = GSEC_PBKDF2_SHA1;
  } else if (gcert_der_oid_is(&oid, OID_HMAC_SHA256, sizeof OID_HMAC_SHA256)) {
    *hash = GSEC_PBKDF2_SHA256;
  } else if (gcert_der_oid_is(&oid, OID_HMAC_SHA384, sizeof OID_HMAC_SHA384)) {
    *hash = GSEC_PBKDF2_SHA384;
  } else if (gcert_der_oid_is(&oid, OID_HMAC_SHA512, sizeof OID_HMAC_SHA512)) {
    *hash = GSEC_PBKDF2_SHA512;
  } else {
    return GCERT_ERR_UNSUPPORTED;
  }
  if (left != 0) {
    GCERT_Der param;
    result = gcert_der_next(&p, &left, &param);
    if (result != GCERT_OK || left != 0) {
      return GCERT_ERR_CORRUPT;
    }
    if (!gcert_der_is(&param, GCERT_DER_UNIVERSAL, 0, 5) || param.value_len != 0) {
      return GCERT_ERR_UNSUPPORTED;
    }
  }
  return GCERT_OK;
}

GCERT_Result gcert_pkcs7_unpad(unsigned char * buf, size_t n, size_t block,
    size_t * out_len) {
  const volatile unsigned char * secret;
  uint32_t pad;
  uint32_t ok;
  size_t i;

  if (n == 0 || block == 0 || (n % block) != 0) {
    return GCERT_ERR_CORRUPT;
  }
  secret = buf;
  pad = secret[n - 1u];
  ok = ((pad - 1u) >> 31) ^ 1u;
  ok &= (((uint32_t)block - pad) >> 31) ^ 1u;
  for (i = 0; i < n; i++) {
    uint32_t from = (uint32_t)n - pad;
    uint32_t in_pad = (((uint32_t)i - from) >> 31) ^ 1u;
    uint32_t same = eq_byte(secret[i], pad);

    ok &= (in_pad ^ 1u) | same;
  }
#if defined(GCERT_CT_TEST)
  VALGRIND_MAKE_MEM_DEFINED(&ok, sizeof ok);
  VALGRIND_MAKE_MEM_DEFINED(&pad, sizeof pad);
  VALGRIND_MAKE_MEM_DEFINED(buf, n);
#endif
  if (ok == 0) {
    gsec_wipe(buf, n);
    return GCERT_ERR_MISMATCH;
  }
  *out_len = n - pad;
  gsec_wipe(buf + *out_len, pad);
  return GCERT_OK;
}

GCERT_Result gcert_pbes2_decrypt(uint32_t iter_max, const GCERT_Der * alg,
    const void * ct,
    size_t ct_len, const void * password, size_t password_len, void * out,
    size_t out_cap, size_t * out_len) {
  const unsigned char * p;
  size_t left;
  GCERT_Der oid;
  GCERT_Der params;
  GCERT_Der kdf;
  GCERT_Der enc;
  GCERT_Der field;
  GCERT_Result result;
  const unsigned char * salt = NULL;
  size_t salt_len = 0;
  const unsigned char * iv = NULL;
  size_t iv_len = 0;
  uint32_t iterations = 0;
  uint32_t hash = GSEC_PBKDF2_SHA1;
  uint32_t key_len = 0;
  int key_len_set = 0;
  size_t block = 0;
  unsigned char key[32];
  int triple = 0;

  if (alg == NULL || out_len == NULL || (ct == NULL && ct_len != 0) ||
      (password == NULL && password_len != 0) || out == NULL) {
    return GCERT_ERR_INVALID;
  }
  if (!gcert_der_is(alg, GCERT_DER_UNIVERSAL, 1, 16)) {
    return GCERT_ERR_CORRUPT;
  }
  p = alg->value;
  left = alg->value_len;
  result = gcert_der_next(&p, &left, &oid);
  if (result != GCERT_OK || gcert_der_oid_ok(&oid) != GCERT_OK) {
    return result != GCERT_OK ? result : GCERT_ERR_CORRUPT;
  }
  if (!gcert_der_oid_is(&oid, OID_PBES2, sizeof OID_PBES2)) {
    return GCERT_ERR_UNSUPPORTED;
  }
  result = gcert_der_next(&p, &left, &params);
  if (result != GCERT_OK || left != 0 ||
      !gcert_der_is(&params, GCERT_DER_UNIVERSAL, 1, 16)) {
    return GCERT_ERR_CORRUPT;
  }
  p = params.value;
  left = params.value_len;
  result = gcert_der_next(&p, &left, &kdf);
  if (result != GCERT_OK || !gcert_der_is(&kdf, GCERT_DER_UNIVERSAL, 1, 16)) {
    return GCERT_ERR_CORRUPT;
  }
  result = gcert_der_next(&p, &left, &enc);
  if (result != GCERT_OK || left != 0 ||
      !gcert_der_is(&enc, GCERT_DER_UNIVERSAL, 1, 16)) {
    return GCERT_ERR_CORRUPT;
  }
  p = kdf.value;
  left = kdf.value_len;
  result = gcert_der_next(&p, &left, &oid);
  if (result != GCERT_OK || !gcert_der_oid_is(&oid, OID_PBKDF2, sizeof OID_PBKDF2)) {
    return result != GCERT_OK ? result : GCERT_ERR_UNSUPPORTED;
  }
  result = gcert_der_next(&p, &left, &params);
  if (result != GCERT_OK || left != 0 ||
      !gcert_der_is(&params, GCERT_DER_UNIVERSAL, 1, 16)) {
    return GCERT_ERR_CORRUPT;
  }
  p = params.value;
  left = params.value_len;
  result = gcert_der_next(&p, &left, &field);
  if (result != GCERT_OK) {
    return result;
  }
  if (!gcert_der_is(&field, GCERT_DER_UNIVERSAL, 0, 4)) {
    return GCERT_ERR_UNSUPPORTED;
  }
  salt = field.value;
  salt_len = field.value_len;
  result = gcert_der_next(&p, &left, &field);
  if (result != GCERT_OK) {
    return result;
  }
  result = u32_of(&field, &iterations);
  if (result != GCERT_OK) {
    return result;
  }
  if (iterations == 0 || iterations > iter_max) {
    return iterations == 0 ? GCERT_ERR_INVALID : GCERT_ERR_LIMIT;
  }
  if (left != 0) {
    result = gcert_der_next(&p, &left, &field);
    if (result != GCERT_OK) {
      return result;
    }
    if (gcert_der_is(&field, GCERT_DER_UNIVERSAL, 0, 2)) {
      result = u32_of(&field, &key_len);
      if (result != GCERT_OK) {
        return result;
      }
      key_len_set = 1;
      if (left != 0) {
        result = gcert_der_next(&p, &left, &field);
        if (result != GCERT_OK || left != 0) {
          return GCERT_ERR_CORRUPT;
        }
        result = prf_of(&field, &hash);
      }
    } else {
      result = prf_of(&field, &hash);
    }
    if (result != GCERT_OK) {
      return result;
    }
  }
  p = enc.value;
  left = enc.value_len;
  result = gcert_der_next(&p, &left, &oid);
  if (result != GCERT_OK || gcert_der_oid_ok(&oid) != GCERT_OK) {
    return result != GCERT_OK ? result : GCERT_ERR_CORRUPT;
  }
  if (gcert_der_oid_is(&oid, OID_AES128, sizeof OID_AES128)) {
    key_len = key_len_set ? key_len : 16u;
    block = GSEC_AES_BLOCK_LEN;
  } else if (gcert_der_oid_is(&oid, OID_AES192, sizeof OID_AES192)) {
    key_len = key_len_set ? key_len : 24u;
    block = GSEC_AES_BLOCK_LEN;
  } else if (gcert_der_oid_is(&oid, OID_AES256, sizeof OID_AES256)) {
    key_len = key_len_set ? key_len : 32u;
    block = GSEC_AES_BLOCK_LEN;
  } else if (gcert_der_oid_is(&oid, OID_DES_EDE3, sizeof OID_DES_EDE3)) {
    key_len = key_len_set ? key_len : 24u;
    block = GSEC_DES_BLOCK_LEN;
    triple = 1;
  } else {
    return GCERT_ERR_UNSUPPORTED;
  }
  if ((triple && key_len != 24u) ||
      (!triple && key_len != 16u && key_len != 24u && key_len != 32u)) {
    return GCERT_ERR_UNSUPPORTED;
  }
  result = gcert_der_next(&p, &left, &field);
  if (result != GCERT_OK || left != 0 ||
      !gcert_der_is(&field, GCERT_DER_UNIVERSAL, 0, 4) ||
      field.value_len != block) {
    return GCERT_ERR_CORRUPT;
  }
  iv = field.value;
  iv_len = field.value_len;
  if (ct_len == 0 || (ct_len % block) != 0 || ct_len > out_cap ||
      ct_len > 65536u) {
    return ct_len > out_cap || ct_len > 65536u ? GCERT_ERR_LIMIT
        : GCERT_ERR_CORRUPT;
  }
  result = gcert_from_gsec(gsec_pbkdf2(hash, password, password_len, salt, salt_len, iterations,
      key, key_len));
  if (result != GCERT_OK) {
    gsec_wipe(key, sizeof key);
    return result;
  }
  if (triple) {
    result = gcert_from_gsec(gsec_des_ede3_cbc_decrypt(key, iv, ct, ct_len, out));
  } else {
    result = gcert_from_gsec(gsec_aes_cbc_decrypt(key, key_len, iv, ct, ct_len, out));
  }
  gsec_wipe(key, sizeof key);
  (void)iv_len;
  if (result != GCERT_OK) {
    gsec_wipe(out, ct_len);
    return result;
  }
  return gcert_pkcs7_unpad(out, ct_len, block, out_len);
}
