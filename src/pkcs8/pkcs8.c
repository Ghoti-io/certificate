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
 * PKCS#8 PrivateKeyInfo, version 0 or 1. Parsing reads an unencrypted
 * key. Decryption opens PBES2 and then parses. The private key bytes
 * stay in the caller's buffer.
 */

#include <ghoti.io/certificate/macros.h>

#include <ghoti.io/certificate/pkcs8.h>
#include <ghoti.io/security/secret.h>

#include "../der/der_int.h"
#include "pbes2.h"

static const unsigned char OID_RSA[] = {
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01
};
static const unsigned char OID_EC[] = {
  0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01
};
static const unsigned char OID_P256[] = {
  0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07
};
static const unsigned char OID_P384[] = {
  0x2b, 0x81, 0x04, 0x00, 0x22
};
static const unsigned char OID_ED25519[] = {
  0x2b, 0x65, 0x70
};

static void clear_out(GCERT_Pkcs8 * out) {
  out->kind = 0;
  out->n = NULL;
  out->n_len = 0;
  out->e = NULL;
  out->e_len = 0;
  out->d = NULL;
  out->d_len = 0;
  out->scalar = NULL;
  out->scalar_len = 0;
}

static GCERT_Result parse_rsa(const unsigned char * p, size_t n, GCERT_Pkcs8 * out) {
  GCERT_Der seq;
  GCERT_Der field;
  GCERT_Result result;
  const unsigned char * cursor;
  size_t left;
  const unsigned char * be;
  size_t be_len;

  result = gcert_der_tlv(p, n, &seq);
  if (result != GCERT_OK) {
    return result;
  }
  if (!gcert_der_is(&seq, GCERT_DER_UNIVERSAL, 1, 16) || seq.total_len != n) {
    return GCERT_ERR_CORRUPT;
  }
  cursor = seq.value;
  left = seq.value_len;
  result = gcert_der_next(&cursor, &left, &field);
  if (result != GCERT_OK) {
    return result;
  }
  result = gcert_der_unsigned(&field, &be, &be_len);
  if (result != GCERT_OK || be_len != 1 || be[0] != 0) {
    return GCERT_ERR_CORRUPT;
  }
  result = gcert_der_next(&cursor, &left, &field);
  if (result != GCERT_OK) {
    return result;
  }
  result = gcert_der_unsigned(&field, &out->n, &out->n_len);
  if (result != GCERT_OK || out->n_len == 0) {
    return GCERT_ERR_CORRUPT;
  }
  result = gcert_der_next(&cursor, &left, &field);
  if (result != GCERT_OK) {
    return result;
  }
  result = gcert_der_unsigned(&field, &out->e, &out->e_len);
  if (result != GCERT_OK || out->e_len == 0) {
    return GCERT_ERR_CORRUPT;
  }
  result = gcert_der_next(&cursor, &left, &field);
  if (result != GCERT_OK) {
    return result;
  }
  result = gcert_der_unsigned(&field, &out->d, &out->d_len);
  if (result != GCERT_OK || out->d_len == 0) {
    return GCERT_ERR_CORRUPT;
  }
  while (left != 0) {
    result = gcert_der_next(&cursor, &left, &field);
    if (result != GCERT_OK) {
      return result;
    }
  }
  out->kind = GCERT_PKCS8_RSA;
  return GCERT_OK;
}

static GCERT_Result parse_ec(const unsigned char * p, size_t n, size_t want,
    uint32_t kind, GCERT_Pkcs8 * out) {
  GCERT_Der seq;
  GCERT_Der field;
  GCERT_Result result;
  const unsigned char * cursor;
  size_t left;

  result = gcert_der_tlv(p, n, &seq);
  if (result != GCERT_OK) {
    return result;
  }
  if (!gcert_der_is(&seq, GCERT_DER_UNIVERSAL, 1, 16) || seq.total_len != n) {
    return GCERT_ERR_CORRUPT;
  }
  cursor = seq.value;
  left = seq.value_len;
  result = gcert_der_next(&cursor, &left, &field);
  if (result != GCERT_OK) {
    return result;
  }
  {
    const unsigned char * be;
    size_t be_len;
    result = gcert_der_unsigned(&field, &be, &be_len);
    if (result != GCERT_OK || be_len != 1 || be[0] != 1) {
      return GCERT_ERR_CORRUPT;
    }
  }
  result = gcert_der_next(&cursor, &left, &field);
  if (result != GCERT_OK || !gcert_der_is(&field, GCERT_DER_UNIVERSAL, 0, 4)) {
    return GCERT_ERR_CORRUPT;
  }
  if (field.value_len != want) {
    return GCERT_ERR_CORRUPT;
  }
  out->scalar = field.value;
  out->scalar_len = field.value_len;
  while (left != 0) {
    result = gcert_der_next(&cursor, &left, &field);
    if (result != GCERT_OK) {
      return result;
    }
  }
  out->kind = kind;
  return GCERT_OK;
}

GCERT_Result gcert_pkcs8_parse(const void * der, size_t len, GCERT_Pkcs8 * out) {
  GCERT_Der seq;
  GCERT_Der field;
  GCERT_Der oid;
  GCERT_Der param;
  GCERT_Result result;
  const unsigned char * cursor;
  size_t left;
  const unsigned char * be;
  size_t be_len;

  if (out == NULL || (der == NULL && len != 0)) {
    return GCERT_ERR_INVALID;
  }
  clear_out(out);
  if (len == 0) {
    return GCERT_ERR_CORRUPT;
  }
  result = gcert_der_tlv(der, len, &seq);
  if (result != GCERT_OK) {
    return result;
  }
  if (!gcert_der_is(&seq, GCERT_DER_UNIVERSAL, 1, 16) || seq.total_len != len) {
    return GCERT_ERR_CORRUPT;
  }
  cursor = seq.value;
  left = seq.value_len;
  result = gcert_der_next(&cursor, &left, &field);
  if (result != GCERT_OK) {
    return result;
  }
  if (!gcert_der_is(&field, GCERT_DER_UNIVERSAL, 0, 2)) {
    clear_out(out);
    return GCERT_ERR_UNSUPPORTED;
  }
  result = gcert_der_unsigned(&field, &be, &be_len);
  if (result != GCERT_OK || be_len != 1 || (be[0] != 0 && be[0] != 1)) {
    clear_out(out);
    return GCERT_ERR_CORRUPT;
  }
  result = gcert_der_next(&cursor, &left, &field);
  if (result != GCERT_OK || !gcert_der_is(&field, GCERT_DER_UNIVERSAL, 1, 16)) {
    clear_out(out);
    return GCERT_ERR_CORRUPT;
  }
  {
    const unsigned char * alg = field.value;
    size_t alg_left = field.value_len;
    result = gcert_der_next(&alg, &alg_left, &oid);
    if (result != GCERT_OK) {
      clear_out(out);
      return result;
    }
    result = gcert_der_oid_ok(&oid);
    if (result != GCERT_OK) {
      clear_out(out);
      return result;
    }
    if (gcert_der_oid_is(&oid, OID_RSA, sizeof OID_RSA)) {
      if (alg_left == 0) {
        clear_out(out);
        return GCERT_ERR_CORRUPT;
      }
      result = gcert_der_next(&alg, &alg_left, &param);
      if (result != GCERT_OK || alg_left != 0 ||
          !gcert_der_is(&param, GCERT_DER_UNIVERSAL, 0, 5) ||
          param.value_len != 0) {
        clear_out(out);
        return GCERT_ERR_CORRUPT;
      }
      result = gcert_der_next(&cursor, &left, &field);
      if (result != GCERT_OK || !gcert_der_is(&field, GCERT_DER_UNIVERSAL, 0, 4)) {
        clear_out(out);
        return GCERT_ERR_CORRUPT;
      }
      result = parse_rsa(field.value, field.value_len, out);
    } else if (gcert_der_oid_is(&oid, OID_EC, sizeof OID_EC)) {
      uint32_t kind;
      size_t want;
      if (alg_left == 0) {
        clear_out(out);
        return GCERT_ERR_CORRUPT;
      }
      result = gcert_der_next(&alg, &alg_left, &param);
      if (result != GCERT_OK || alg_left != 0) {
        clear_out(out);
        return GCERT_ERR_CORRUPT;
      }
      if (gcert_der_oid_is(&param, OID_P256, sizeof OID_P256)) {
        kind = GCERT_PKCS8_P256;
        want = 32;
      } else if (gcert_der_oid_is(&param, OID_P384, sizeof OID_P384)) {
        kind = GCERT_PKCS8_P384;
        want = 48;
      } else {
        clear_out(out);
        return GCERT_ERR_UNSUPPORTED;
      }
      result = gcert_der_next(&cursor, &left, &field);
      if (result != GCERT_OK || !gcert_der_is(&field, GCERT_DER_UNIVERSAL, 0, 4)) {
        clear_out(out);
        return GCERT_ERR_CORRUPT;
      }
      result = parse_ec(field.value, field.value_len, want, kind, out);
    } else if (gcert_der_oid_is(&oid, OID_ED25519, sizeof OID_ED25519)) {
      if (alg_left != 0) {
        clear_out(out);
        return GCERT_ERR_CORRUPT;
      }
      result = gcert_der_next(&cursor, &left, &field);
      if (result != GCERT_OK || !gcert_der_is(&field, GCERT_DER_UNIVERSAL, 0, 4)) {
        clear_out(out);
        return GCERT_ERR_CORRUPT;
      }
      if (field.value_len == 32) {
        out->scalar = field.value;
      } else {
        GCERT_Der inner;
        result = gcert_der_tlv(field.value, field.value_len, &inner);
        if (result != GCERT_OK || inner.total_len != field.value_len ||
            !gcert_der_is(&inner, GCERT_DER_UNIVERSAL, 0, 4) ||
            inner.value_len != 32) {
          clear_out(out);
          return GCERT_ERR_CORRUPT;
        }
        out->scalar = inner.value;
      }
      out->scalar_len = 32;
      out->kind = GCERT_PKCS8_ED25519;
      result = GCERT_OK;
    } else {
      clear_out(out);
      return GCERT_ERR_UNSUPPORTED;
    }
  }
  if (result != GCERT_OK) {
    clear_out(out);
    return result;
  }
  while (left != 0) {
    result = gcert_der_next(&cursor, &left, &field);
    if (result != GCERT_OK) {
      clear_out(out);
      return result;
    }
  }
  return GCERT_OK;
}

GCERT_Result gcert_pkcs8_decrypt(const void * der, size_t len,
    const void * password, size_t password_len, void * out, size_t out_cap,
    size_t * out_len, const GCERT_Limits * limits) {
  GCERT_Limits caps;
  GCERT_Der seq;
  GCERT_Der alg;
  GCERT_Der data;
  GCERT_Result result;
  const unsigned char * p;
  size_t left;
  GCERT_Pkcs8 key;

  if (out_len == NULL || (der == NULL && len != 0) ||
      (password == NULL && password_len != 0)) {
    return GCERT_ERR_INVALID;
  }
  if (len == 0) {
    return GCERT_ERR_CORRUPT;
  }
  if (limits == NULL) {
    gcert_limits_default(&caps);
  } else {
    caps = *limits;
  }
  result = gcert_der_tlv(der, len, &seq);
  if (result != GCERT_OK) {
    return result;
  }
  if (!gcert_der_is(&seq, GCERT_DER_UNIVERSAL, 1, 16) || seq.total_len != len) {
    return GCERT_ERR_CORRUPT;
  }
  p = seq.value;
  left = seq.value_len;
  result = gcert_der_next(&p, &left, &alg);
  if (result != GCERT_OK) {
    return result;
  }
  if (gcert_der_is(&alg, GCERT_DER_UNIVERSAL, 0, 2)) {
    return GCERT_ERR_UNSUPPORTED;
  }
  result = gcert_der_next(&p, &left, &data);
  if (result != GCERT_OK || left != 0 ||
      !gcert_der_is(&data, GCERT_DER_UNIVERSAL, 0, 4)) {
    return GCERT_ERR_CORRUPT;
  }
  result = gcert_pbe_decrypt(caps.max_pbe_iterations, &alg, data.value,
      data.value_len, password,
      password_len, out, out_cap, out_len);
  if (result != GCERT_OK) {
    if (result == GCERT_ERR_MISMATCH && out != NULL) {
      gsec_wipe(out, out_cap);
    }
    return result;
  }
  result = gcert_pkcs8_parse(out, *out_len, &key);
  if (result != GCERT_OK) {
    gsec_wipe(out, out_cap < data.value_len ? out_cap : data.value_len);
    return result == GCERT_ERR_INVALID ? result : GCERT_ERR_MISMATCH;
  }
  return GCERT_OK;
}
