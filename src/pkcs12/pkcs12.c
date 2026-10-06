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
 * PFX. The MAC is checked before any bag is decrypted. PBES2 is given
 * the UTF-8 password. The MAC is given that password as UTF-16BE with
 * two trailing zero bytes.
 */

#include <ghoti.io/certificate/macros.h>
#include "../core/sec_result.h"

#include <ghoti.io/security/hmac.h>
#include <ghoti.io/certificate/pkcs12.h>
#include <ghoti.io/certificate/x509.h>
#include <ghoti.io/security/secret.h>
#include <ghoti.io/security/sha1.h>
#include <ghoti.io/security/sha256.h>
#include <ghoti.io/security/sha384.h>
#include <ghoti.io/security/sha512.h>

#include "../der/der_int.h"
#include "../pkcs8/pbes2.h"

#include <string.h>

static const unsigned char OID_DATA[] = {
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01
};
static const unsigned char OID_ENCRYPTED[] = {
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x06
};
static const unsigned char OID_KEY_BAG[] = {
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x0a, 0x01, 0x01
};
static const unsigned char OID_SHROUDED[] = {
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x0a, 0x01, 0x02
};
static const unsigned char OID_CERT_BAG[] = {
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x0a, 0x01, 0x03
};
static const unsigned char OID_X509[] = {
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x16, 0x01
};
static const unsigned char OID_SHA1[] = {0x2b, 0x0e, 0x03, 0x02, 0x1a};
static const unsigned char OID_SHA256[] = {
  0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01
};
static const unsigned char OID_SHA384[] = {
  0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02
};
static const unsigned char OID_SHA512[] = {
  0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03
};

#define BMP_MAX 514u
#define I_MAX 2048u

GCERT_Result gcert_pkcs12_bmp(const unsigned char * in, size_t n,
    unsigned char * out, size_t * out_len) {
  size_t i = 0;
  size_t o = 0;

  if (n > 256u) {
    return GCERT_ERR_LIMIT;
  }
  while (i < n) {
    unsigned char c = in[i];
    uint32_t cp;
    size_t need;
    size_t k;
    if (c < 0x80u) {
      cp = c;
      need = 1;
    } else if ((c & 0xe0u) == 0xc0u) {
      cp = c & 0x1fu;
      need = 2;
    } else if ((c & 0xf0u) == 0xe0u) {
      cp = c & 0x0fu;
      need = 3;
    } else {
      return GCERT_ERR_UNSUPPORTED;
    }
    if (i + need > n) {
      return GCERT_ERR_INVALID;
    }
    for (k = 1; k < need; k++) {
      unsigned char cont = in[i + k];
      if ((cont & 0xc0u) != 0x80u) {
        return GCERT_ERR_INVALID;
      }
      cp = (cp << 6) | (cont & 0x3fu);
    }
    if ((need == 2 && cp < 0x80u) || (need == 3 && cp < 0x800u) ||
        (cp >= 0xd800u && cp <= 0xdfffu) || cp > 0xffffu) {
      return GCERT_ERR_INVALID;
    }
    out[o++] = (unsigned char)(cp >> 8);
    out[o++] = (unsigned char)cp;
    i += need;
  }
  out[o++] = 0;
  out[o++] = 0;
  *out_len = o;
  return GCERT_OK;
}

static GCERT_Result hash_id(const GCERT_Der * oid, uint32_t * id, size_t * u,
    size_t * v) {
  if (gcert_der_oid_is(oid, OID_SHA1, sizeof OID_SHA1)) {
    *id = GSEC_HMAC_SHA1;
    *u = 20;
    *v = 64;
  } else if (gcert_der_oid_is(oid, OID_SHA256, sizeof OID_SHA256)) {
    *id = GSEC_HMAC_SHA256;
    *u = 32;
    *v = 64;
  } else if (gcert_der_oid_is(oid, OID_SHA384, sizeof OID_SHA384)) {
    *id = GSEC_HMAC_SHA384;
    *u = 48;
    *v = 128;
  } else if (gcert_der_oid_is(oid, OID_SHA512, sizeof OID_SHA512)) {
    *id = GSEC_HMAC_SHA512;
    *u = 64;
    *v = 128;
  } else {
    return GCERT_ERR_UNSUPPORTED;
  }
  return GCERT_OK;
}

static GCERT_Result hash_bytes(uint32_t id, const unsigned char * p, size_t n,
    unsigned char * out) {
  if (id == GSEC_HMAC_SHA1) {
    return gcert_from_gsec(gsec_sha1(p, n, out));
  }
  if (id == GSEC_HMAC_SHA256) {
    return gcert_from_gsec(gsec_sha256(p, n, out));
  }
  if (id == GSEC_HMAC_SHA384) {
    return gcert_from_gsec(gsec_sha384(p, n, out));
  }
  return gcert_from_gsec(gsec_sha512(p, n, out));
}

GCERT_Result gcert_pkcs12_kdf(uint32_t iter_max, uint32_t id, size_t u,
    size_t v,
    const unsigned char * pass, size_t pass_len, const unsigned char * salt,
    size_t salt_len, uint32_t iterations, unsigned char purpose,
    unsigned char * dk, size_t dk_len) {
  unsigned char diversifier[128];
  unsigned char material[I_MAX];
  unsigned char block[64];
  size_t s_len;
  size_t p_len;
  size_t i_len;
  size_t produced = 0;
  size_t i;

  if (salt_len > 128u || iterations == 0 || iterations > iter_max) {
    return iterations > iter_max ? GCERT_ERR_LIMIT : GCERT_ERR_INVALID;
  }
  s_len = salt_len == 0 ? 0 : v * ((salt_len + v - 1u) / v);
  p_len = pass_len == 0 ? 0 : v * ((pass_len + v - 1u) / v);
  i_len = s_len + p_len;
  if (i_len > I_MAX || v > sizeof diversifier) {
    return GCERT_ERR_LIMIT;
  }
  for (i = 0; i < v; i++) {
    diversifier[i] = purpose;
  }
  for (i = 0; i < s_len; i++) {
    material[i] = salt[i % salt_len];
  }
  for (i = 0; i < p_len; i++) {
    material[s_len + i] = pass[i % pass_len];
  }
  while (produced < dk_len) {
    unsigned char joined[I_MAX + 128];
    size_t take;
    if (v + i_len > sizeof joined) {
      return GCERT_ERR_LIMIT;
    }
    memcpy(joined, diversifier, v);
    if (i_len != 0) {
      memcpy(joined + v, material, i_len);
    }
    if (hash_bytes(id, joined, v + i_len, block) != GCERT_OK) {
      return GCERT_ERR_INTERNAL;
    }
    for (i = 1; i < iterations; i++) {
      if (hash_bytes(id, block, u, block) != GCERT_OK) {
        return GCERT_ERR_INTERNAL;
      }
    }
    take = dk_len - produced;
    if (take > u) {
      take = u;
    }
    memcpy(dk + produced, block, take);
    produced += take;
    if (produced >= dk_len) {
      break;
    }
    {
      unsigned char B[128];
      size_t j;
      uint32_t carry;
      for (j = 0; j < v; j++) {
        B[j] = block[j % u];
      }
      for (j = 0; j < i_len; j += v) {
        size_t k;
        carry = 1;
        for (k = v; k > 0;) {
          k--;
          carry += (uint32_t)material[j + k] + B[k];
          material[j + k] = (unsigned char)carry;
          carry >>= 8;
        }
      }
    }
  }
  gsec_wipe(block, sizeof block);
  gsec_wipe(material, sizeof material);
  return GCERT_OK;
}

static GCERT_Result explicit_value(const GCERT_Der * field, GCERT_Der * inner) {
  GCERT_Result result;
  if (field->tag_class != GCERT_DER_CONTEXT || field->constructed != 1) {
    return GCERT_ERR_CORRUPT;
  }
  result = gcert_der_tlv(field->value, field->value_len, inner);
  if (result != GCERT_OK || inner->total_len != field->value_len) {
    return GCERT_ERR_CORRUPT;
  }
  return GCERT_OK;
}

static GCERT_Result add_cert(GCERT_Pkcs12 * out, const unsigned char * der, size_t n) {
  if (out->cert_count >= GCERT_PKCS12_CERT_MAX) {
    return GCERT_ERR_LIMIT;
  }
  out->certs[out->cert_count] = der;
  out->cert_lens[out->cert_count] = n;
  out->cert_count++;
  return GCERT_OK;
}

static GCERT_Result take_bags(uint32_t iter_max, const unsigned char * p,
    size_t n, const unsigned char * pass, size_t pass_len,
    unsigned char ** scratch, size_t * scratch_left, GCERT_Pkcs12 * out) {
  GCERT_Der seq;
  GCERT_Result result;
  const unsigned char * cursor;
  size_t left;

  result = gcert_der_tlv(p, n, &seq);
  if (result != GCERT_OK || seq.total_len != n ||
      !gcert_der_is(&seq, GCERT_DER_UNIVERSAL, 1, 16)) {
    return GCERT_ERR_CORRUPT;
  }
  cursor = seq.value;
  left = seq.value_len;
  while (left != 0) {
    GCERT_Der bag;
    GCERT_Der oid;
    GCERT_Der value;
    GCERT_Der inner;
    const unsigned char * bp;
    size_t bleft;
    result = gcert_der_next(&cursor, &left, &bag);
    if (result != GCERT_OK || !gcert_der_is(&bag, GCERT_DER_UNIVERSAL, 1, 16)) {
      return GCERT_ERR_CORRUPT;
    }
    bp = bag.value;
    bleft = bag.value_len;
    result = gcert_der_next(&bp, &bleft, &oid);
    if (result != GCERT_OK || gcert_der_oid_ok(&oid) != GCERT_OK) {
      return GCERT_ERR_CORRUPT;
    }
    result = gcert_der_next(&bp, &bleft, &value);
    if (result != GCERT_OK || value.tag_class != GCERT_DER_CONTEXT ||
        value.number != 0) {
      return GCERT_ERR_CORRUPT;
    }
    result = explicit_value(&value, &inner);
    if (result != GCERT_OK) {
      return result;
    }
    if (gcert_der_oid_is(&oid, OID_CERT_BAG, sizeof OID_CERT_BAG)) {
      GCERT_Der cert_oid;
      GCERT_Der cert_val;
      GCERT_Der cert_oct;
      const unsigned char * cp = inner.value;
      size_t cleft = inner.value_len;
      if (!gcert_der_is(&inner, GCERT_DER_UNIVERSAL, 1, 16)) {
        return GCERT_ERR_CORRUPT;
      }
      result = gcert_der_next(&cp, &cleft, &cert_oid);
      if (result != GCERT_OK || gcert_der_oid_ok(&cert_oid) != GCERT_OK) {
        return GCERT_ERR_CORRUPT;
      }
      result = gcert_der_next(&cp, &cleft, &cert_val);
      if (result != GCERT_OK || cleft != 0) {
        return GCERT_ERR_CORRUPT;
      }
      if (!gcert_der_oid_is(&cert_oid, OID_X509, sizeof OID_X509)) {
        continue;
      }
      result = explicit_value(&cert_val, &cert_oct);
      if (result != GCERT_OK || !gcert_der_is(&cert_oct, GCERT_DER_UNIVERSAL, 0, 4)) {
        return GCERT_ERR_CORRUPT;
      }
      result = add_cert(out, cert_oct.value, cert_oct.value_len);
      if (result != GCERT_OK) {
        return result;
      }
    } else     if (gcert_der_oid_is(&oid, OID_KEY_BAG, sizeof OID_KEY_BAG)) {
      if (out->key != NULL) {
        return GCERT_ERR_LIMIT;
      }
      out->key = inner.value - (inner.total_len - inner.value_len);
      out->key_len = inner.total_len;
    } else if (gcert_der_oid_is(&oid, OID_SHROUDED, sizeof OID_SHROUDED)) {
      GCERT_Der alg;
      GCERT_Der ct;
      const unsigned char * ep = inner.value;
      size_t eleft = inner.value_len;
      size_t plain_len = 0;
      if (out->key != NULL) {
        return GCERT_ERR_LIMIT;
      }
      if (!gcert_der_is(&inner, GCERT_DER_UNIVERSAL, 1, 16)) {
        return GCERT_ERR_CORRUPT;
      }
      result = gcert_der_next(&ep, &eleft, &alg);
      if (result != GCERT_OK) {
        return result;
      }
      result = gcert_der_next(&ep, &eleft, &ct);
      if (result != GCERT_OK || eleft != 0 ||
          !gcert_der_is(&ct, GCERT_DER_UNIVERSAL, 0, 4)) {
        return GCERT_ERR_CORRUPT;
      }
      if (ct.value_len > *scratch_left) {
        return GCERT_ERR_LIMIT;
      }
      result = gcert_pbe_decrypt(iter_max, &alg, ct.value, ct.value_len, pass,
          pass_len,
          *scratch, *scratch_left, &plain_len);
      if (result != GCERT_OK) {
        return result;
      }
      out->key = *scratch;
      out->key_len = plain_len;
      *scratch += plain_len;
      *scratch_left -= plain_len;
    }
    (void)bleft;
  }
  return GCERT_OK;
}

static GCERT_Result take_content(uint32_t iter_max, const GCERT_Der * info,
    const unsigned char * pass, size_t pass_len, unsigned char ** scratch,
    size_t * scratch_left, GCERT_Pkcs12 * out) {
  const unsigned char * p = info->value;
  size_t left = info->value_len;
  GCERT_Der oid;
  GCERT_Der body;
  GCERT_Der inner;
  GCERT_Result result;

  if (!gcert_der_is(info, GCERT_DER_UNIVERSAL, 1, 16)) {
    return GCERT_ERR_CORRUPT;
  }
  result = gcert_der_next(&p, &left, &oid);
  if (result != GCERT_OK || gcert_der_oid_ok(&oid) != GCERT_OK) {
    return GCERT_ERR_CORRUPT;
  }
  if (left == 0) {
    return GCERT_OK;
  }
  result = gcert_der_next(&p, &left, &body);
  if (result != GCERT_OK || left != 0 || body.number != 0) {
    return GCERT_ERR_CORRUPT;
  }
  result = explicit_value(&body, &inner);
  if (result != GCERT_OK) {
    return result;
  }
  if (gcert_der_oid_is(&oid, OID_DATA, sizeof OID_DATA)) {
    if (!gcert_der_is(&inner, GCERT_DER_UNIVERSAL, 0, 4)) {
      return GCERT_ERR_CORRUPT;
    }
    return take_bags(iter_max, inner.value, inner.value_len, pass, pass_len,
        scratch,
        scratch_left, out);
  }
  if (gcert_der_oid_is(&oid, OID_ENCRYPTED, sizeof OID_ENCRYPTED)) {
    GCERT_Der ver;
    GCERT_Der eci;
    GCERT_Der content_type;
    GCERT_Der alg;
    GCERT_Der ct;
    const unsigned char * ep;
    size_t eleft;
    size_t plain_len = 0;
    if (!gcert_der_is(&inner, GCERT_DER_UNIVERSAL, 1, 16)) {
      return GCERT_ERR_CORRUPT;
    }
    ep = inner.value;
    eleft = inner.value_len;
    result = gcert_der_next(&ep, &eleft, &ver);
    if (result != GCERT_OK || !gcert_der_is(&ver, GCERT_DER_UNIVERSAL, 0, 2)) {
      return GCERT_ERR_CORRUPT;
    }
    result = gcert_der_next(&ep, &eleft, &eci);
    if (result != GCERT_OK || eleft != 0 ||
        !gcert_der_is(&eci, GCERT_DER_UNIVERSAL, 1, 16)) {
      return GCERT_ERR_CORRUPT;
    }
    ep = eci.value;
    eleft = eci.value_len;
    result = gcert_der_next(&ep, &eleft, &content_type);
    if (result != GCERT_OK || gcert_der_oid_ok(&content_type) != GCERT_OK) {
      return GCERT_ERR_CORRUPT;
    }
    result = gcert_der_next(&ep, &eleft, &alg);
    if (result != GCERT_OK) {
      return result;
    }
    result = gcert_der_next(&ep, &eleft, &ct);
    if (result != GCERT_OK || eleft != 0 || ct.tag_class != GCERT_DER_CONTEXT ||
        ct.number != 0 || ct.constructed != 0) {
      return GCERT_ERR_CORRUPT;
    }
    if (ct.value_len > *scratch_left) {
      return GCERT_ERR_LIMIT;
    }
    result = gcert_pbe_decrypt(iter_max, &alg, ct.value, ct.value_len, pass,
          pass_len,
        *scratch, *scratch_left, &plain_len);
    if (result != GCERT_OK) {
      return result;
    }
    {
      unsigned char * nested = *scratch + plain_len;
      size_t nested_left = *scratch_left - plain_len;
      result = take_bags(iter_max, *scratch, plain_len, pass, pass_len, &nested,
          &nested_left, out);
      if (result != GCERT_OK) {
        return result;
      }
      *scratch = nested;
      *scratch_left = nested_left;
    }
    return GCERT_OK;
  }
  return GCERT_ERR_UNSUPPORTED;
}

GCERT_Result gcert_pkcs12_open(const void * der, size_t len, const void * password,
    size_t password_len, void * scratch, size_t scratch_cap, GCERT_Pkcs12 * out,
    const GCERT_Limits * limits) {
  GCERT_Limits caps;
  uint32_t iter_max;
  GCERT_Der seq;
  GCERT_Der ver;
  GCERT_Der auth;
  GCERT_Der mac;
  GCERT_Result result;
  const unsigned char * p;
  size_t left;
  const unsigned char * be;
  size_t be_len;
  unsigned char bmp[BMP_MAX];
  size_t bmp_len = 0;
  unsigned char * slot;
  size_t slot_left;
  int have_mac = 0;

  if (out == NULL || scratch == NULL || (der == NULL && len != 0) ||
      (password == NULL && password_len != 0)) {
    return GCERT_ERR_INVALID;
  }
  if (limits == NULL) {
    gcert_limits_default(&caps);
  } else {
    caps = *limits;
  }
  iter_max = caps.max_pbe_iterations;
  memset(out, 0, sizeof *out);
  if (len == 0 || len > GCERT_X509_DER_MAX) {
    return len == 0 ? GCERT_ERR_CORRUPT : GCERT_ERR_LIMIT;
  }
  result = gcert_pkcs12_bmp(password, password_len, bmp, &bmp_len);
  if (result != GCERT_OK) {
    return result;
  }
  result = gcert_der_tlv(der, len, &seq);
  if (result != GCERT_OK || seq.total_len != len ||
      !gcert_der_is(&seq, GCERT_DER_UNIVERSAL, 1, 16)) {
    gsec_wipe(bmp, sizeof bmp);
    return GCERT_ERR_CORRUPT;
  }
  p = seq.value;
  left = seq.value_len;
  result = gcert_der_next(&p, &left, &ver);
  if (result != GCERT_OK) {
    gsec_wipe(bmp, sizeof bmp);
    return result;
  }
  result = gcert_der_unsigned(&ver, &be, &be_len);
  if (result != GCERT_OK || be_len != 1 || be[0] != 3) {
    gsec_wipe(bmp, sizeof bmp);
    return GCERT_ERR_CORRUPT;
  }
  result = gcert_der_next(&p, &left, &auth);
  if (result != GCERT_OK) {
    gsec_wipe(bmp, sizeof bmp);
    return result;
  }
  if (left != 0) {
    result = gcert_der_next(&p, &left, &mac);
    if (result != GCERT_OK || left != 0 ||
        !gcert_der_is(&mac, GCERT_DER_UNIVERSAL, 1, 16)) {
      gsec_wipe(bmp, sizeof bmp);
      return GCERT_ERR_CORRUPT;
    }
    have_mac = 1;
  }
  /* RFC 7292 makes MacData optional. Refused: without it the archive is
   * unauthenticated, an unencrypted certificate bag can be replaced by
   * anyone who can write the file, and GCERT_OK would read as "this archive
   * is fine". */
  if (!have_mac) {
    gsec_wipe(bmp, sizeof bmp);
    return GCERT_ERR_UNSUPPORTED;
  }
  {
    GCERT_Der digest_info;
    GCERT_Der salt;
    GCERT_Der alg;
    GCERT_Der dig;
    GCERT_Der oid;
    GCERT_Der param;
    const unsigned char * mp = mac.value;
    size_t mleft = mac.value_len;
    uint32_t id;
    size_t u;
    size_t v;
    uint32_t iterations = 1;
    unsigned char key[64];
    const unsigned char * content;
    size_t content_len;
    GCERT_Der content_oid;
    GCERT_Der content_body;
    GCERT_Der content_oct;
    const unsigned char * ap;
    size_t aleft;
    result = gcert_der_next(&mp, &mleft, &digest_info);
    if (result != GCERT_OK || !gcert_der_is(&digest_info, GCERT_DER_UNIVERSAL, 1, 16)) {
      gsec_wipe(bmp, sizeof bmp);
      return GCERT_ERR_CORRUPT;
    }
    result = gcert_der_next(&mp, &mleft, &salt);
    if (result != GCERT_OK || !gcert_der_is(&salt, GCERT_DER_UNIVERSAL, 0, 4)) {
      gsec_wipe(bmp, sizeof bmp);
      return GCERT_ERR_CORRUPT;
    }
    if (mleft != 0) {
      GCERT_Der iter;
      result = gcert_der_next(&mp, &mleft, &iter);
      if (result != GCERT_OK || mleft != 0) {
        gsec_wipe(bmp, sizeof bmp);
        return GCERT_ERR_CORRUPT;
      }
      result = gcert_der_unsigned(&iter, &be, &be_len);
      if (result != GCERT_OK || be_len > 4) {
        gsec_wipe(bmp, sizeof bmp);
        return result != GCERT_OK ? result : GCERT_ERR_LIMIT;
      }
      iterations = 0;
      for (content_len = 0; content_len < be_len; content_len++) {
        iterations = (iterations << 8) | be[content_len];
      }
      if (iterations == 0) {
        gsec_wipe(bmp, sizeof bmp);
        return GCERT_ERR_INVALID;
      }
    }
    ap = digest_info.value;
    aleft = digest_info.value_len;
    result = gcert_der_next(&ap, &aleft, &alg);
    if (result != GCERT_OK) {
      gsec_wipe(bmp, sizeof bmp);
      return result;
    }
    result = gcert_der_next(&ap, &aleft, &dig);
    if (result != GCERT_OK || aleft != 0 ||
        !gcert_der_is(&dig, GCERT_DER_UNIVERSAL, 0, 4)) {
      gsec_wipe(bmp, sizeof bmp);
      return GCERT_ERR_CORRUPT;
    }
    ap = alg.value;
    aleft = alg.value_len;
    if (!gcert_der_is(&alg, GCERT_DER_UNIVERSAL, 1, 16)) {
      gsec_wipe(bmp, sizeof bmp);
      return GCERT_ERR_CORRUPT;
    }
    result = gcert_der_next(&ap, &aleft, &oid);
    if (result != GCERT_OK || gcert_der_oid_ok(&oid) != GCERT_OK) {
      gsec_wipe(bmp, sizeof bmp);
      return GCERT_ERR_CORRUPT;
    }
    if (aleft != 0) {
      result = gcert_der_next(&ap, &aleft, &param);
      if (result != GCERT_OK || aleft != 0 ||
          !gcert_der_is(&param, GCERT_DER_UNIVERSAL, 0, 5)) {
        gsec_wipe(bmp, sizeof bmp);
        return GCERT_ERR_CORRUPT;
      }
    }
    result = hash_id(&oid, &id, &u, &v);
    if (result != GCERT_OK) {
      gsec_wipe(bmp, sizeof bmp);
      return result;
    }
    if (dig.value_len != u) {
      gsec_wipe(bmp, sizeof bmp);
      return GCERT_ERR_CORRUPT;
    }
    ap = auth.value;
    aleft = auth.value_len;
    if (!gcert_der_is(&auth, GCERT_DER_UNIVERSAL, 1, 16)) {
      gsec_wipe(bmp, sizeof bmp);
      return GCERT_ERR_CORRUPT;
    }
    result = gcert_der_next(&ap, &aleft, &content_oid);
    if (result != GCERT_OK || !gcert_der_oid_is(&content_oid, OID_DATA, sizeof OID_DATA)) {
      gsec_wipe(bmp, sizeof bmp);
      return result != GCERT_OK ? result : GCERT_ERR_UNSUPPORTED;
    }
    result = gcert_der_next(&ap, &aleft, &content_body);
    if (result != GCERT_OK || aleft != 0) {
      gsec_wipe(bmp, sizeof bmp);
      return GCERT_ERR_CORRUPT;
    }
    result = explicit_value(&content_body, &content_oct);
    if (result != GCERT_OK || !gcert_der_is(&content_oct, GCERT_DER_UNIVERSAL, 0, 4)) {
      gsec_wipe(bmp, sizeof bmp);
      return GCERT_ERR_CORRUPT;
    }
    content = content_oct.value;
    content_len = content_oct.value_len;
    result = gcert_pkcs12_kdf(iter_max, id, u, v, bmp, bmp_len, salt.value,
        salt.value_len,
        iterations, 3, key, u);
    if (result != GCERT_OK) {
      gsec_wipe(bmp, sizeof bmp);
      gsec_wipe(key, sizeof key);
      return result;
    }
    result = gcert_from_gsec(gsec_hmac_verify(id, key, u, content, content_len, dig.value,
        dig.value_len));
    gsec_wipe(key, sizeof key);
    if (result != GCERT_OK) {
      gsec_wipe(bmp, sizeof bmp);
      gsec_wipe(scratch, scratch_cap);
      return result;
    }
  }
  {
    GCERT_Der content_oid;
    GCERT_Der content_body;
    GCERT_Der content_oct;
    GCERT_Der safe;
    const unsigned char * ap = auth.value;
    size_t aleft = auth.value_len;
    const unsigned char * sp;
    size_t sleft;
    if (!gcert_der_is(&auth, GCERT_DER_UNIVERSAL, 1, 16)) {
      gsec_wipe(bmp, sizeof bmp);
      return GCERT_ERR_CORRUPT;
    }
    result = gcert_der_next(&ap, &aleft, &content_oid);
    if (result != GCERT_OK || !gcert_der_oid_is(&content_oid, OID_DATA, sizeof OID_DATA)) {
      gsec_wipe(bmp, sizeof bmp);
      return result != GCERT_OK ? result : GCERT_ERR_UNSUPPORTED;
    }
    result = gcert_der_next(&ap, &aleft, &content_body);
    if (result != GCERT_OK || aleft != 0) {
      gsec_wipe(bmp, sizeof bmp);
      return GCERT_ERR_CORRUPT;
    }
    result = explicit_value(&content_body, &content_oct);
    if (result != GCERT_OK || !gcert_der_is(&content_oct, GCERT_DER_UNIVERSAL, 0, 4)) {
      gsec_wipe(bmp, sizeof bmp);
      return GCERT_ERR_CORRUPT;
    }
    result = gcert_der_tlv(content_oct.value, content_oct.value_len, &safe);
    if (result != GCERT_OK || safe.total_len != content_oct.value_len ||
        !gcert_der_is(&safe, GCERT_DER_UNIVERSAL, 1, 16)) {
      gsec_wipe(bmp, sizeof bmp);
      return GCERT_ERR_CORRUPT;
    }
    slot = scratch;
    slot_left = scratch_cap;
    sp = safe.value;
    sleft = safe.value_len;
    while (sleft != 0) {
      GCERT_Der info;
      result = gcert_der_next(&sp, &sleft, &info);
      if (result != GCERT_OK) {
        gsec_wipe(bmp, sizeof bmp);
        gsec_wipe(scratch, scratch_cap);
        return result;
      }
      result = take_content(iter_max, &info, password, password_len, &slot,
          &slot_left,
          out);
      if (result != GCERT_OK) {
        gsec_wipe(bmp, sizeof bmp);
        gsec_wipe(scratch, scratch_cap);
        memset(out, 0, sizeof *out);
        return result;
      }
    }
  }
  gsec_wipe(bmp, sizeof bmp);
  return GCERT_OK;
}
