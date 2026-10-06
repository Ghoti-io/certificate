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
 * X.509 parse and path validation. Certificate bytes are public. The
 * signature is checked with the primitives already in this library.
 */

#include <ghoti.io/certificate/macros.h>
#include "../core/sec_result.h"

#include <ghoti.io/security/ecdsa_p256.h>
#include <ghoti.io/security/ecdsa_p384.h>
#include <ghoti.io/security/ed25519.h>
#include <ghoti.io/security/rsa.h>
#include <ghoti.io/certificate/x509.h>

#include "../der/der_int.h"

#include <string.h>

static const unsigned char OID_RSA[] = {
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01
};
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
static const unsigned char OID_EC[] = {
  0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01
};
static const unsigned char OID_P256[] = {
  0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07
};
static const unsigned char OID_P384[] = {
  0x2b, 0x81, 0x04, 0x00, 0x22
};
static const unsigned char OID_ECDSA_SHA256[] = {
  0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02
};
static const unsigned char OID_ECDSA_SHA384[] = {
  0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03
};
static const unsigned char OID_ED25519[] = {0x2b, 0x65, 0x70};
static const unsigned char OID_BC[] = {0x55, 0x1d, 0x13};
static const unsigned char OID_KU[] = {0x55, 0x1d, 0x0f};
static const unsigned char OID_SAN[] = {0x55, 0x1d, 0x11};
static const unsigned char OID_NC[] = {0x55, 0x1d, 0x1e};
static const unsigned char OID_SKI[] = {0x55, 0x1d, 0x0e};
static const unsigned char OID_AKI[] = {0x55, 0x1d, 0x23};
static const unsigned char OID_EKU[] = {0x55, 0x1d, 0x25};
static const unsigned char OID_CP[] = {0x55, 0x1d, 0x20};
/* id-kp-* under 1.3.6.1.5.5.7.3, and anyExtendedKeyUsage at 2.5.29.37.0. */
static const unsigned char OID_KP_SERVER[] = {
  0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01
};
static const unsigned char OID_KP_CLIENT[] = {
  0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02
};
static const unsigned char OID_KP_CODE[] = {
  0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03
};
static const unsigned char OID_KP_EMAIL[] = {
  0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x04
};
static const unsigned char OID_KP_TIME[] = {
  0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08
};
static const unsigned char OID_KP_OCSP[] = {
  0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09
};
static const unsigned char OID_KP_ANY[] = {0x55, 0x1d, 0x25, 0x00};

enum {
  SEEN_BC = 1u,
  SEEN_KU = 2u,
  SEEN_SAN = 4u,
  SEEN_NC = 8u,
  SEEN_SKI = 16u,
  SEEN_AKI = 32u,
  SEEN_EKU = 64u,
  SEEN_CP = 128u
};

static void clear_cert(GCERT_X509 * out) {
  memset(out, 0, sizeof *out);
}

static GCERT_Result whole(const unsigned char * p, size_t n, GCERT_Der * out) {
  GCERT_Result result = gcert_der_tlv(p, n, out);
  if (result != GCERT_OK) {
    return result;
  }
  if (out->total_len != n) {
    return GCERT_ERR_CORRUPT;
  }
  return GCERT_OK;
}

static GCERT_Result null_param(const unsigned char ** p, size_t * left) {
  GCERT_Der param;
  GCERT_Result result;

  if (*left == 0) {
    return GCERT_ERR_CORRUPT;
  }
  result = gcert_der_next(p, left, &param);
  if (result != GCERT_OK || *left != 0 ||
      !gcert_der_is(&param, GCERT_DER_UNIVERSAL, 0, 5) || param.value_len != 0) {
    return GCERT_ERR_CORRUPT;
  }
  return GCERT_OK;
}

static GCERT_Result parse_spki(const GCERT_Der * spki, GCERT_X509 * out) {
  const unsigned char * p;
  size_t left;
  GCERT_Der field;
  GCERT_Der oid;
  GCERT_Result result;
  const unsigned char * bits;
  size_t bits_len;

  if (!gcert_der_is(spki, GCERT_DER_UNIVERSAL, 1, 16)) {
    return GCERT_ERR_CORRUPT;
  }
  p = spki->value;
  left = spki->value_len;
  result = gcert_der_next(&p, &left, &field);
  if (result != GCERT_OK || !gcert_der_is(&field, GCERT_DER_UNIVERSAL, 1, 16)) {
    return GCERT_ERR_CORRUPT;
  }
  {
    const unsigned char * alg = field.value;
    size_t alg_left = field.value_len;
    result = gcert_der_next(&alg, &alg_left, &oid);
    if (result != GCERT_OK || gcert_der_oid_ok(&oid) != GCERT_OK) {
      return GCERT_ERR_CORRUPT;
    }
    result = gcert_der_next(&p, &left, &field);
    if (result != GCERT_OK || left != 0) {
      return GCERT_ERR_CORRUPT;
    }
    result = gcert_der_bit_payload(&field, &bits, &bits_len);
    if (result != GCERT_OK) {
      return result;
    }
    if (gcert_der_oid_is(&oid, OID_RSA, sizeof OID_RSA)) {
      GCERT_Der key;
      GCERT_Der n;
      GCERT_Der e;
      const unsigned char * kp;
      size_t kleft;
      result = null_param(&alg, &alg_left);
      if (result != GCERT_OK) {
        return result;
      }
      result = whole(bits, bits_len, &key);
      if (result != GCERT_OK || !gcert_der_is(&key, GCERT_DER_UNIVERSAL, 1, 16)) {
        return GCERT_ERR_CORRUPT;
      }
      kp = key.value;
      kleft = key.value_len;
      result = gcert_der_next(&kp, &kleft, &n);
      if (result != GCERT_OK) {
        return result;
      }
      result = gcert_der_unsigned(&n, &out->n, &out->n_len);
      if (result != GCERT_OK || out->n_len == 0 || out->n_len > 512) {
        return GCERT_ERR_CORRUPT;
      }
      result = gcert_der_next(&kp, &kleft, &e);
      if (result != GCERT_OK || kleft != 0) {
        return GCERT_ERR_CORRUPT;
      }
      result = gcert_der_unsigned(&e, &out->e, &out->e_len);
      if (result != GCERT_OK || out->e_len == 0) {
        return GCERT_ERR_CORRUPT;
      }
      out->key = GCERT_X509_RSA;
      return GCERT_OK;
    }
    if (gcert_der_oid_is(&oid, OID_EC, sizeof OID_EC)) {
      GCERT_Der curve;
      size_t want;
      uint32_t kind;
      result = gcert_der_next(&alg, &alg_left, &curve);
      if (result != GCERT_OK || alg_left != 0) {
        return GCERT_ERR_CORRUPT;
      }
      if (gcert_der_oid_is(&curve, OID_P256, sizeof OID_P256)) {
        kind = GCERT_X509_P256;
        want = 32;
      } else if (gcert_der_oid_is(&curve, OID_P384, sizeof OID_P384)) {
        kind = GCERT_X509_P384;
        want = 48;
      } else {
        return GCERT_ERR_UNSUPPORTED;
      }
      if (bits_len != 1u + want * 2u || bits[0] != 0x04) {
        return bits_len > 0 && (bits[0] == 0x02 || bits[0] == 0x03)
            ? GCERT_ERR_UNSUPPORTED : GCERT_ERR_CORRUPT;
      }
      out->point = bits + 1;
      out->point_len = want * 2u;
      out->key = kind;
      return GCERT_OK;
    }
    if (gcert_der_oid_is(&oid, OID_ED25519, sizeof OID_ED25519)) {
      if (alg_left != 0 || bits_len != 32) {
        return GCERT_ERR_CORRUPT;
      }
      out->point = bits;
      out->point_len = 32;
      out->key = GCERT_X509_ED25519;
      return GCERT_OK;
    }
  }
  return GCERT_ERR_UNSUPPORTED;
}

static GCERT_Result parse_sig_alg(const GCERT_Der * alg, GCERT_X509 * out) {
  const unsigned char * p;
  size_t left;
  GCERT_Der oid;
  GCERT_Result result;

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
    out->sig_hash = GSEC_RSA_MD5;
    out->sig_key = GCERT_X509_RSA;
  } else if (gcert_der_oid_is(&oid, OID_RSA_SHA1, sizeof OID_RSA_SHA1)) {
    out->sig_hash = GSEC_RSA_SHA1;
    out->sig_key = GCERT_X509_RSA;
  } else if (gcert_der_oid_is(&oid, OID_RSA_SHA256, sizeof OID_RSA_SHA256)) {
    out->sig_hash = GSEC_RSA_SHA256;
    out->sig_key = GCERT_X509_RSA;
  } else if (gcert_der_oid_is(&oid, OID_RSA_SHA384, sizeof OID_RSA_SHA384)) {
    out->sig_hash = GSEC_RSA_SHA384;
    out->sig_key = GCERT_X509_RSA;
  } else if (gcert_der_oid_is(&oid, OID_RSA_SHA512, sizeof OID_RSA_SHA512)) {
    out->sig_hash = GSEC_RSA_SHA512;
    out->sig_key = GCERT_X509_RSA;
  } else if (gcert_der_oid_is(&oid, OID_ECDSA_SHA256, sizeof OID_ECDSA_SHA256)) {
    out->sig_key = GCERT_X509_P256;
  } else if (gcert_der_oid_is(&oid, OID_ECDSA_SHA384, sizeof OID_ECDSA_SHA384)) {
    out->sig_key = GCERT_X509_P384;
  } else if (gcert_der_oid_is(&oid, OID_ED25519, sizeof OID_ED25519)) {
    out->sig_key = GCERT_X509_ED25519;
    if (left != 0) {
      return GCERT_ERR_CORRUPT;
    }
    return GCERT_OK;
  } else {
    return GCERT_ERR_UNSUPPORTED;
  }
  if (out->sig_key == GCERT_X509_RSA) {
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

  result = whole(bits, bits_len, &seq);
  if (result != GCERT_OK || !gcert_der_is(&seq, GCERT_DER_UNIVERSAL, 1, 16)) {
    return GCERT_ERR_CORRUPT;
  }
  p = seq.value;
  left = seq.value_len;
  for (i = 0; i < width * 2u; i++) {
    raw[i] = 0;
  }
  for (i = 0; i < 2; i++) {
    result = gcert_der_next(&p, &left, &num);
    if (result != GCERT_OK) {
      return result;
    }
    result = gcert_der_unsigned(&num, &be, &be_len);
    if (result != GCERT_OK || be_len == 0 || be_len > width) {
      return GCERT_ERR_CORRUPT;
    }
    {
      size_t j;
      unsigned char * dest = raw + i * width + (width - be_len);
      for (j = 0; j < be_len; j++) {
        dest[j] = be[j];
      }
    }
  }
  if (left != 0) {
    return GCERT_ERR_CORRUPT;
  }
  return GCERT_OK;
}

/* The purposes, not just the syntax. An OID with no bit of its own sets
 * eku_unknown, so gcert_x509_purpose can refuse a certificate whose only
 * stated purposes are ones this parser cannot evaluate. */
static GCERT_Result parse_eku(const unsigned char * p, size_t n, int critical,
    GCERT_X509 * out) {
  GCERT_Der seq;
  GCERT_Result result;
  const unsigned char * cursor;
  size_t left;

  result = whole(p, n, &seq);
  if (result != GCERT_OK || !gcert_der_is(&seq, GCERT_DER_UNIVERSAL, 1, 16)) {
    return GCERT_ERR_CORRUPT;
  }
  cursor = seq.value;
  left = seq.value_len;
  if (left == 0) {
    return GCERT_ERR_CORRUPT;
  }
  out->eku_set = 1;
  out->eku_critical = critical;
  while (left != 0) {
    GCERT_Der oid;
    result = gcert_der_next(&cursor, &left, &oid);
    if (result != GCERT_OK || gcert_der_oid_ok(&oid) != GCERT_OK) {
      return GCERT_ERR_CORRUPT;
    }
    if (gcert_der_oid_is(&oid, OID_KP_ANY, sizeof OID_KP_ANY)) {
      out->eku |= GCERT_X509_EKU_ANY;
    } else if (gcert_der_oid_is(&oid, OID_KP_SERVER, sizeof OID_KP_SERVER)) {
      out->eku |= GCERT_X509_EKU_SERVER_AUTH;
    } else if (gcert_der_oid_is(&oid, OID_KP_CLIENT, sizeof OID_KP_CLIENT)) {
      out->eku |= GCERT_X509_EKU_CLIENT_AUTH;
    } else if (gcert_der_oid_is(&oid, OID_KP_CODE, sizeof OID_KP_CODE)) {
      out->eku |= GCERT_X509_EKU_CODE_SIGNING;
    } else if (gcert_der_oid_is(&oid, OID_KP_EMAIL, sizeof OID_KP_EMAIL)) {
      out->eku |= GCERT_X509_EKU_EMAIL_PROTECTION;
    } else if (gcert_der_oid_is(&oid, OID_KP_TIME, sizeof OID_KP_TIME)) {
      out->eku |= GCERT_X509_EKU_TIME_STAMPING;
    } else if (gcert_der_oid_is(&oid, OID_KP_OCSP, sizeof OID_KP_OCSP)) {
      out->eku |= GCERT_X509_EKU_OCSP_SIGNING;
    } else {
      out->eku_unknown = 1;
    }
  }
  return GCERT_OK;
}

static GCERT_Result walk_ok(const unsigned char * p, size_t n) {
  while (n != 0) {
    GCERT_Der field;
    GCERT_Result result = gcert_der_next(&p, &n, &field);
    if (result != GCERT_OK) {
      return result;
    }
  }
  return GCERT_OK;
}

static GCERT_Result parse_bc(const unsigned char * p, size_t n, GCERT_X509 * out) {
  GCERT_Der seq;
  GCERT_Der field;
  GCERT_Result result;
  const unsigned char * cursor;
  size_t left;

  result = whole(p, n, &seq);
  if (result != GCERT_OK || !gcert_der_is(&seq, GCERT_DER_UNIVERSAL, 1, 16)) {
    return GCERT_ERR_CORRUPT;
  }
  cursor = seq.value;
  left = seq.value_len;
  out->ca = 0;
  out->basic_constraints = 1;
  out->path_len_set = 0;
  if (left == 0) {
    return GCERT_OK;
  }
  result = gcert_der_next(&cursor, &left, &field);
  if (result != GCERT_OK) {
    return result;
  }
  if (gcert_der_is(&field, GCERT_DER_UNIVERSAL, 0, 1)) {
    if (field.value_len != 1 || (field.value[0] != 0 && field.value[0] != 0xff)) {
      return GCERT_ERR_CORRUPT;
    }
    out->ca = field.value[0] == 0xff;
    if (left == 0) {
      return GCERT_OK;
    }
    result = gcert_der_next(&cursor, &left, &field);
    if (result != GCERT_OK) {
      return result;
    }
  }
  if (!out->ca) {
    return GCERT_ERR_CORRUPT;
  }
  {
    const unsigned char * be;
    size_t be_len;
    size_t i;
    uint32_t value;
    result = gcert_der_unsigned(&field, &be, &be_len);
    if (result != GCERT_OK || be_len == 0 || be_len > 4 || left != 0) {
      return GCERT_ERR_CORRUPT;
    }
    value = 0;
    for (i = 0; i < be_len; i++) {
      value = (value << 8) | be[i];
    }
    out->path_len = value;
    out->path_len_set = 1;
  }
  return GCERT_OK;
}

static GCERT_Result parse_ku(const unsigned char * p, size_t n, GCERT_X509 * out) {
  GCERT_Der bits;
  const unsigned char * payload;
  size_t payload_len;
  GCERT_Result result;

  result = whole(p, n, &bits);
  if (result != GCERT_OK) {
    return result;
  }
  result = gcert_der_bit_payload(&bits, &payload, &payload_len);
  if (result != GCERT_OK || payload_len == 0 || payload_len > 2) {
    return GCERT_ERR_CORRUPT;
  }
  /* Bit 0 is the high bit of the first payload byte. keyCertSign is 0x04. */
  out->key_usage = payload[0];
  if (payload_len > 1) {
    out->key_usage |= (unsigned)payload[1] << 8;
  }
  out->key_usage_set = 1;
  return GCERT_OK;
}

static int dns_eq(const unsigned char * a, size_t an, const unsigned char * b,
    size_t bn) {
  size_t i;
  if (an != bn) {
    return 0;
  }
  for (i = 0; i < an; i++) {
    unsigned char ca = a[i];
    unsigned char cb = b[i];
    if (ca >= 'A' && ca <= 'Z') {
      ca = (unsigned char)(ca - 'A' + 'a');
    }
    if (cb >= 'A' && cb <= 'Z') {
      cb = (unsigned char)(cb - 'A' + 'a');
    }
    if (ca != cb) {
      return 0;
    }
  }
  return 1;
}

static int dns_in(const unsigned char * name, size_t nn, const unsigned char * base,
    size_t bn) {
  if (bn == 0 || nn == 0) {
    return 0;
  }
  if (dns_eq(name, nn, base, bn)) {
    return 1;
  }
  if (nn > bn + 1u && name[nn - bn - 1u] == '.' &&
      dns_eq(name + (nn - bn), bn, base, bn)) {
    return 1;
  }
  return 0;
}

static GCERT_Result dn_suffix(const unsigned char * name, size_t name_len,
    const unsigned char * base, size_t base_len) {
  GCERT_Der name_seq;
  GCERT_Der base_seq;
  const unsigned char * nr[16];
  size_t nl[16];
  const unsigned char * br[16];
  size_t bl[16];
  size_t nn;
  size_t bn;
  size_t i;
  GCERT_Result result;
  const unsigned char * p;
  size_t left;

  result = whole(name, name_len, &name_seq);
  if (result != GCERT_OK || !gcert_der_is(&name_seq, GCERT_DER_UNIVERSAL, 1, 16)) {
    return GCERT_ERR_CORRUPT;
  }
  result = whole(base, base_len, &base_seq);
  if (result != GCERT_OK || !gcert_der_is(&base_seq, GCERT_DER_UNIVERSAL, 1, 16)) {
    return GCERT_ERR_CORRUPT;
  }
  nn = 0;
  p = name_seq.value;
  left = name_seq.value_len;
  while (left != 0) {
    GCERT_Der rdn;
    if (nn == 16) {
      return GCERT_ERR_LIMIT;
    }
    result = gcert_der_next(&p, &left, &rdn);
    if (result != GCERT_OK) {
      return result;
    }
    nr[nn] = p - rdn.total_len;
    nl[nn] = rdn.total_len;
    nn++;
  }
  bn = 0;
  p = base_seq.value;
  left = base_seq.value_len;
  while (left != 0) {
    GCERT_Der rdn;
    if (bn == 16) {
      return GCERT_ERR_LIMIT;
    }
    result = gcert_der_next(&p, &left, &rdn);
    if (result != GCERT_OK) {
      return result;
    }
    br[bn] = p - rdn.total_len;
    bl[bn] = rdn.total_len;
    bn++;
  }
  if (bn == 0 || bn > nn) {
    return GCERT_ERR_MISMATCH;
  }
  for (i = 0; i < bn; i++) {
    if (!gcert_der_eq(nr[nn - bn + i], nl[nn - bn + i], br[i], bl[i])) {
      return GCERT_ERR_MISMATCH;
    }
  }
  return GCERT_OK;
}

/* [0] and [1] are IMPLICIT. Their contents are the GeneralSubtree values.
 * An EXPLICIT encoding wraps those values in one more SEQUENCE. */
static GCERT_Result general_subtrees(const GCERT_Der * choice,
    const unsigned char ** p, size_t * left) {
  GCERT_Der outer;
  GCERT_Der first;
  GCERT_Result result;

  *p = choice->value;
  *left = choice->value_len;
  if (*left == 0) {
    return GCERT_ERR_CORRUPT;
  }
  result = gcert_der_tlv(*p, *left, &outer);
  if (result != GCERT_OK) {
    return result;
  }
  if (!gcert_der_is(&outer, GCERT_DER_UNIVERSAL, 1, 16) ||
      outer.total_len != *left || outer.value_len == 0) {
    return GCERT_OK;
  }
  result = gcert_der_tlv(outer.value, outer.value_len, &first);
  if (result != GCERT_OK) {
    return result;
  }
  if (gcert_der_is(&first, GCERT_DER_UNIVERSAL, 1, 16)) {
    *p = outer.value;
    *left = outer.value_len;
  }
  return GCERT_OK;
}

static GCERT_Result apply_one_nc(const GCERT_X509 * cert, const unsigned char * nc,
    size_t nc_len) {
  GCERT_Der seq;
  GCERT_Result result;
  const unsigned char * p;
  size_t left;
  int saw_permit_dns;
  int dns_permitted;
  int san_dns;

  result = whole(nc, nc_len, &seq);
  if (result != GCERT_OK || !gcert_der_is(&seq, GCERT_DER_UNIVERSAL, 1, 16)) {
    return GCERT_ERR_CORRUPT;
  }
  saw_permit_dns = 0;
  dns_permitted = 0;
  san_dns = 0;
  p = seq.value;
  left = seq.value_len;
  while (left != 0) {
    GCERT_Der choice;
    const unsigned char * sp;
    size_t sleft;
    int excluded;
    result = gcert_der_next(&p, &left, &choice);
    if (result != GCERT_OK || choice.tag_class != GCERT_DER_CONTEXT ||
        choice.constructed == 0 || choice.number > 1) {
      return GCERT_ERR_CORRUPT;
    }
    excluded = choice.number == 1;
    result = general_subtrees(&choice, &sp, &sleft);
    if (result != GCERT_OK) {
      return result;
    }
    if (sleft == 0) {
      return GCERT_ERR_CORRUPT;
    }
    while (sleft != 0) {
      GCERT_Der tree;
      GCERT_Der base;
      const unsigned char * tp;
      size_t tleft;
      result = gcert_der_next(&sp, &sleft, &tree);
      if (result != GCERT_OK || !gcert_der_is(&tree, GCERT_DER_UNIVERSAL, 1, 16)) {
        return GCERT_ERR_CORRUPT;
      }
      tp = tree.value;
      tleft = tree.value_len;
      result = gcert_der_next(&tp, &tleft, &base);
      if (result != GCERT_OK) {
        return result;
      }
      if (tleft != 0) {
        GCERT_Der extra;
        result = gcert_der_next(&tp, &tleft, &extra);
        if (result != GCERT_OK) {
          return result;
        }
        if (!(extra.tag_class == GCERT_DER_CONTEXT && extra.number == 0 &&
            extra.value_len == 3 && extra.value[0] == 0x02 &&
            extra.value[1] == 0x01 && extra.value[2] == 0x00) || tleft != 0) {
          return GCERT_ERR_UNSUPPORTED;
        }
      }
      if (base.tag_class == GCERT_DER_CONTEXT && base.constructed == 0 &&
          base.number == 2) {
        int inside = dns_in(NULL, 0, base.value, base.value_len);
        (void)inside;
        if (excluded) {
          if (cert->san != NULL && cert->san_len != 0) {
            GCERT_Der names;
            const unsigned char * np;
            size_t nleft;
            result = whole(cert->san, cert->san_len, &names);
            if (result != GCERT_OK) {
              return result;
            }
            np = names.value;
            nleft = names.value_len;
            while (nleft != 0) {
              GCERT_Der gn;
              result = gcert_der_next(&np, &nleft, &gn);
              if (result != GCERT_OK) {
                return result;
              }
              if (gn.tag_class == GCERT_DER_CONTEXT && gn.constructed == 0 &&
                  gn.number == 2 &&
                  dns_in(gn.value, gn.value_len, base.value, base.value_len)) {
                return GCERT_ERR_MISMATCH;
              }
            }
          }
        } else {
          saw_permit_dns = 1;
        }
      } else if (base.tag_class == GCERT_DER_CONTEXT && base.constructed == 1 &&
          base.number == 4) {
        result = dn_suffix(cert->subject, cert->subject_len, base.value,
            base.value_len);
        if (excluded) {
          if (result == GCERT_OK) {
            return GCERT_ERR_MISMATCH;
          }
          if (result != GCERT_ERR_MISMATCH) {
            return result;
          }
        } else if (result != GCERT_OK) {
          return result;
        }
      } else {
        return GCERT_ERR_UNSUPPORTED;
      }
    }
  }
  if (saw_permit_dns) {
    if (cert->san == NULL) {
      return GCERT_OK;
    }
    {
      GCERT_Der names;
      const unsigned char * np;
      size_t nleft;
      result = whole(cert->san, cert->san_len, &names);
      if (result != GCERT_OK || !gcert_der_is(&names, GCERT_DER_UNIVERSAL, 1, 16)) {
        return GCERT_ERR_CORRUPT;
      }
      np = names.value;
      nleft = names.value_len;
      while (nleft != 0) {
        GCERT_Der gn;
        int matched;
        result = gcert_der_next(&np, &nleft, &gn);
        if (result != GCERT_OK) {
          return result;
        }
        if (!(gn.tag_class == GCERT_DER_CONTEXT && gn.constructed == 0 &&
            gn.number == 2)) {
          continue;
        }
        san_dns = 1;
        matched = 0;
        {
          const unsigned char * cp = seq.value;
          size_t cleft = seq.value_len;
          while (cleft != 0) {
            GCERT_Der choice;
            result = gcert_der_next(&cp, &cleft, &choice);
            if (result != GCERT_OK) {
              return result;
            }
            if (choice.number != 0) {
              continue;
            }
            {
              const unsigned char * tp;
              size_t tleft;
              result = general_subtrees(&choice, &tp, &tleft);
              if (result != GCERT_OK) {
                return result;
              }
              while (tleft != 0) {
                GCERT_Der tree;
                GCERT_Der base;
                const unsigned char * ip;
                size_t ileft;
                result = gcert_der_next(&tp, &tleft, &tree);
                if (result != GCERT_OK) {
                  return result;
                }
                ip = tree.value;
                ileft = tree.value_len;
                result = gcert_der_next(&ip, &ileft, &base);
                if (result != GCERT_OK) {
                  return result;
                }
                if (base.number == 2 && base.tag_class == GCERT_DER_CONTEXT &&
                    dns_in(gn.value, gn.value_len, base.value, base.value_len)) {
                  matched = 1;
                }
              }
            }
          }
        }
        if (!matched) {
          return GCERT_ERR_MISMATCH;
        }
        dns_permitted = 1;
      }
    }
    (void)dns_permitted;
    (void)san_dns;
  }
  return GCERT_OK;
}

/* certificatePolicies: read for shape, not enforced. The one caller left
 * after extendedKeyUsage got a parser of its own. */
static GCERT_Result policy_seq(const unsigned char * p, size_t n) {
  GCERT_Der seq;
  GCERT_Result result;
  const unsigned char * cursor;
  size_t left;

  result = whole(p, n, &seq);
  if (result != GCERT_OK || !gcert_der_is(&seq, GCERT_DER_UNIVERSAL, 1, 16)) {
    return GCERT_ERR_CORRUPT;
  }
  cursor = seq.value;
  left = seq.value_len;
  if (left == 0) {
    return GCERT_ERR_CORRUPT;
  }
  while (left != 0) {
    GCERT_Der field;
    const unsigned char * ip;
    size_t ileft;
    GCERT_Der oid;
    result = gcert_der_next(&cursor, &left, &field);
    if (result != GCERT_OK) {
      return result;
    }
    if (!gcert_der_is(&field, GCERT_DER_UNIVERSAL, 1, 16)) {
      return GCERT_ERR_CORRUPT;
    }
    ip = field.value;
    ileft = field.value_len;
    result = gcert_der_next(&ip, &ileft, &oid);
    if (result != GCERT_OK || gcert_der_oid_ok(&oid) != GCERT_OK) {
      return GCERT_ERR_CORRUPT;
    }
    result = walk_ok(ip, ileft);
    if (result != GCERT_OK) {
      return result;
    }
  }
  return GCERT_OK;
}

/* AuthorityKeyIdentifier ::= SEQUENCE { keyIdentifier [0] OCTET STRING OPTIONAL,
 * authorityCertIssuer [1] ..., authorityCertSerialNumber [2] ... }. Only the
 * key identifier is kept, which is what a chain builder matches on. The
 * sequence has already been walked for shape. */
static GCERT_Result parse_aki(const unsigned char * p, size_t n, GCERT_X509 * out) {
  GCERT_Der seq;
  GCERT_Result result;
  const unsigned char * cursor;
  size_t left;

  result = whole(p, n, &seq);
  if (result != GCERT_OK || !gcert_der_is(&seq, GCERT_DER_UNIVERSAL, 1, 16)) {
    return GCERT_ERR_CORRUPT;
  }
  cursor = seq.value;
  left = seq.value_len;
  while (left != 0) {
    GCERT_Der field;
    result = gcert_der_next(&cursor, &left, &field);
    if (result != GCERT_OK) {
      return result;
    }
    if (field.tag_class == GCERT_DER_CONTEXT && field.number == 0 &&
        field.constructed == 0 && field.value_len != 0) {
      out->aki = field.value;
      out->aki_len = field.value_len;
    }
  }
  return GCERT_OK;
}

static GCERT_Result parse_extensions(const unsigned char * p, size_t n,
    GCERT_X509 * out) {
  GCERT_Der seq;
  GCERT_Result result;
  const unsigned char * cursor;
  size_t left;
  unsigned seen;

  result = whole(p, n, &seq);
  if (result != GCERT_OK || !gcert_der_is(&seq, GCERT_DER_UNIVERSAL, 1, 16)) {
    return GCERT_ERR_CORRUPT;
  }
  cursor = seq.value;
  left = seq.value_len;
  seen = 0;
  if (left == 0) {
    return GCERT_ERR_CORRUPT;
  }
  while (left != 0) {
    GCERT_Der ext;
    GCERT_Der oid;
    GCERT_Der value;
    const unsigned char * ep;
    size_t eleft;
    int critical;
    unsigned flag;
    result = gcert_der_next(&cursor, &left, &ext);
    if (result != GCERT_OK || !gcert_der_is(&ext, GCERT_DER_UNIVERSAL, 1, 16)) {
      return GCERT_ERR_CORRUPT;
    }
    ep = ext.value;
    eleft = ext.value_len;
    result = gcert_der_next(&ep, &eleft, &oid);
    if (result != GCERT_OK || gcert_der_oid_ok(&oid) != GCERT_OK) {
      return GCERT_ERR_CORRUPT;
    }
    critical = 0;
    if (eleft != 0) {
      GCERT_Der maybe;
      const unsigned char * save = ep;
      size_t save_left = eleft;
      result = gcert_der_next(&ep, &eleft, &maybe);
      if (result != GCERT_OK) {
        return result;
      }
      if (gcert_der_is(&maybe, GCERT_DER_UNIVERSAL, 0, 1)) {
        if (maybe.value_len != 1 || (maybe.value[0] != 0 && maybe.value[0] != 0xff)) {
          return GCERT_ERR_CORRUPT;
        }
        critical = maybe.value[0] == 0xff;
      } else {
        ep = save;
        eleft = save_left;
      }
    }
    result = gcert_der_next(&ep, &eleft, &value);
    if (result != GCERT_OK || eleft != 0 ||
        !gcert_der_is(&value, GCERT_DER_UNIVERSAL, 0, 4)) {
      return GCERT_ERR_CORRUPT;
    }
    flag = 0;
    if (gcert_der_oid_is(&oid, OID_BC, sizeof OID_BC)) {
      flag = SEEN_BC;
      result = parse_bc(value.value, value.value_len, out);
    } else if (gcert_der_oid_is(&oid, OID_KU, sizeof OID_KU)) {
      flag = SEEN_KU;
      result = parse_ku(value.value, value.value_len, out);
    } else if (gcert_der_oid_is(&oid, OID_SAN, sizeof OID_SAN)) {
      flag = SEEN_SAN;
      out->san = value.value;
      out->san_len = value.value_len;
      result = whole(value.value, value.value_len, &ext);
      if (result == GCERT_OK && !gcert_der_is(&ext, GCERT_DER_UNIVERSAL, 1, 16)) {
        result = GCERT_ERR_CORRUPT;
      }
      if (result == GCERT_OK) {
        GCERT_Der names;
        const unsigned char * np;
        size_t nleft;
        result = whole(value.value, value.value_len, &names);
        if (result != GCERT_OK) {
          return result;
        }
        np = names.value;
        nleft = names.value_len;
        while (nleft != 0) {
          GCERT_Der gn;
          result = gcert_der_next(&np, &nleft, &gn);
          if (result != GCERT_OK) {
            return result;
          }
          if (gn.tag_class == GCERT_DER_CONTEXT && gn.number == 2 &&
              gn.constructed == 0) {
            out->dns_san = 1;
          }
        }
        result = GCERT_OK;
      }
    } else if (gcert_der_oid_is(&oid, OID_NC, sizeof OID_NC)) {
      flag = SEEN_NC;
      out->name_constraints = value.value;
      out->name_constraints_len = value.value_len;
      result = GCERT_OK;
    } else if (gcert_der_oid_is(&oid, OID_SKI, sizeof OID_SKI)) {
      flag = SEEN_SKI;
      result = whole(value.value, value.value_len, &ext);
      if (result == GCERT_OK && !gcert_der_is(&ext, GCERT_DER_UNIVERSAL, 0, 4)) {
        result = GCERT_ERR_CORRUPT;
      }
      if (result == GCERT_OK && ext.value_len != 0) {
        out->ski = ext.value;
        out->ski_len = ext.value_len;
      }
    } else if (gcert_der_oid_is(&oid, OID_AKI, sizeof OID_AKI)) {
      flag = SEEN_AKI;
      result = walk_ok(value.value, value.value_len);
      if (result == GCERT_OK) {
        result = parse_aki(value.value, value.value_len, out);
      }
    } else if (gcert_der_oid_is(&oid, OID_EKU, sizeof OID_EKU)) {
      flag = SEEN_EKU;
      result = parse_eku(value.value, value.value_len, critical, out);
    } else if (gcert_der_oid_is(&oid, OID_CP, sizeof OID_CP)) {
      flag = SEEN_CP;
      result = policy_seq(value.value, value.value_len);
    } else if (critical) {
      return GCERT_ERR_UNSUPPORTED;
    } else {
      result = walk_ok(value.value, value.value_len);
    }
    if (result != GCERT_OK) {
      return result;
    }
    if (flag != 0) {
      if ((seen & flag) != 0) {
        return GCERT_ERR_CORRUPT;
      }
      seen |= flag;
    }
  }
  return GCERT_OK;
}

static GCERT_Result parse_tbs(const GCERT_Der * tbs, const unsigned char * tbs_bytes,
    size_t tbs_len, GCERT_X509 * out) {
  const unsigned char * p;
  size_t left;
  GCERT_Der field;
  GCERT_Result result;
  unsigned version;
  const unsigned char * alg_bytes;
  size_t alg_len;

  p = tbs->value;
  left = tbs->value_len;
  version = 0;
  result = gcert_der_next(&p, &left, &field);
  if (result != GCERT_OK) {
    return result;
  }
  if (field.tag_class == GCERT_DER_CONTEXT && field.constructed == 1 &&
      field.number == 0) {
    GCERT_Der ver;
    const unsigned char * be;
    size_t be_len;
    result = whole(field.value, field.value_len, &ver);
    if (result != GCERT_OK) {
      return result;
    }
    result = gcert_der_unsigned(&ver, &be, &be_len);
    if (result != GCERT_OK || be_len != 1 || be[0] > 2) {
      return GCERT_ERR_CORRUPT;
    }
    version = be[0];
    result = gcert_der_next(&p, &left, &field);
    if (result != GCERT_OK) {
      return result;
    }
  }
  {
    const unsigned char * be;
    size_t be_len;
    result = gcert_der_unsigned(&field, &be, &be_len);
    if (result != GCERT_OK || be_len == 0 || be_len > 20) {
      return GCERT_ERR_CORRUPT;
    }
  }
  result = gcert_der_next(&p, &left, &field);
  if (result != GCERT_OK) {
    return result;
  }
  alg_bytes = p - field.total_len;
  alg_len = field.total_len;
  result = parse_sig_alg(&field, out);
  if (result != GCERT_OK) {
    return result;
  }
  result = gcert_der_next(&p, &left, &field);
  if (result != GCERT_OK || !gcert_der_is(&field, GCERT_DER_UNIVERSAL, 1, 16)) {
    return GCERT_ERR_CORRUPT;
  }
  out->issuer = p - field.total_len;
  out->issuer_len = field.total_len;
  {
    const unsigned char * np = field.value;
    size_t nleft = field.value_len;
    while (nleft != 0) {
      GCERT_Der rdn;
      result = gcert_der_next(&np, &nleft, &rdn);
      if (result != GCERT_OK) {
        return result;
      }
      result = gcert_der_set_sorted(&rdn);
      if (result != GCERT_OK || rdn.value_len == 0) {
        return result != GCERT_OK ? result : GCERT_ERR_CORRUPT;
      }
    }
  }
  result = gcert_der_next(&p, &left, &field);
  if (result != GCERT_OK || !gcert_der_is(&field, GCERT_DER_UNIVERSAL, 1, 16)) {
    return GCERT_ERR_CORRUPT;
  }
  {
    const unsigned char * vp = field.value;
    size_t vleft = field.value_len;
    GCERT_Der t0;
    GCERT_Der t1;
    result = gcert_der_next(&vp, &vleft, &t0);
    if (result != GCERT_OK) {
      return result;
    }
    result = gcert_der_time(&t0, &out->not_before);
    if (result != GCERT_OK) {
      return result;
    }
    result = gcert_der_next(&vp, &vleft, &t1);
    if (result != GCERT_OK || vleft != 0) {
      return GCERT_ERR_CORRUPT;
    }
    result = gcert_der_time(&t1, &out->not_after);
    if (result != GCERT_OK) {
      return result;
    }
  }
  result = gcert_der_next(&p, &left, &field);
  if (result != GCERT_OK || !gcert_der_is(&field, GCERT_DER_UNIVERSAL, 1, 16)) {
    return GCERT_ERR_CORRUPT;
  }
  out->subject = p - field.total_len;
  out->subject_len = field.total_len;
  {
    const unsigned char * np = field.value;
    size_t nleft = field.value_len;
    while (nleft != 0) {
      GCERT_Der rdn;
      result = gcert_der_next(&np, &nleft, &rdn);
      if (result != GCERT_OK) {
        return result;
      }
      result = gcert_der_set_sorted(&rdn);
      if (result != GCERT_OK || rdn.value_len == 0) {
        return result != GCERT_OK ? result : GCERT_ERR_CORRUPT;
      }
    }
  }
  result = gcert_der_next(&p, &left, &field);
  if (result != GCERT_OK) {
    return result;
  }
  result = parse_spki(&field, out);
  if (result != GCERT_OK) {
    return result;
  }
  while (left != 0) {
    result = gcert_der_next(&p, &left, &field);
    if (result != GCERT_OK) {
      return result;
    }
    if (field.tag_class == GCERT_DER_CONTEXT && field.number == 1) {
      if (version < 1) {
        return GCERT_ERR_CORRUPT;
      }
      continue;
    }
    if (field.tag_class == GCERT_DER_CONTEXT && field.number == 2) {
      if (version < 1) {
        return GCERT_ERR_CORRUPT;
      }
      continue;
    }
    if (field.tag_class == GCERT_DER_CONTEXT && field.constructed == 1 &&
        field.number == 3) {
      GCERT_Der ext;
      if (version != 2) {
        return GCERT_ERR_CORRUPT;
      }
      result = whole(field.value, field.value_len, &ext);
      if (result != GCERT_OK || !gcert_der_is(&ext, GCERT_DER_UNIVERSAL, 1, 16)) {
        return result != GCERT_OK ? result : GCERT_ERR_CORRUPT;
      }
      result = parse_extensions(field.value, field.value_len, out);
      if (result != GCERT_OK) {
        return result;
      }
      continue;
    }
    return GCERT_ERR_CORRUPT;
  }
  (void)alg_bytes;
  (void)alg_len;
  (void)tbs_bytes;
  (void)tbs_len;
  out->tbs = tbs_bytes;
  out->tbs_len = tbs_len;
  return GCERT_OK;
}

GCERT_Result gcert_x509_parse(const void * der, size_t len, GCERT_X509 * out) {
  GCERT_Der seq;
  GCERT_Der tbs;
  GCERT_Der alg;
  GCERT_Der sig;
  GCERT_Result result;
  const unsigned char * p;
  size_t left;
  const unsigned char * tbs_bytes;
  const unsigned char * bits;
  size_t bits_len;
  uint32_t inner_key;
  uint32_t inner_hash;

  if (out == NULL || (der == NULL && len != 0)) {
    return GCERT_ERR_INVALID;
  }
  clear_cert(out);
  if (len == 0 || len > GCERT_X509_DER_MAX) {
    return len == 0 ? GCERT_ERR_CORRUPT : GCERT_ERR_LIMIT;
  }
  result = whole((const unsigned char *)der, len, &seq);
  if (result != GCERT_OK || !gcert_der_is(&seq, GCERT_DER_UNIVERSAL, 1, 16)) {
    return GCERT_ERR_CORRUPT;
  }
  p = seq.value;
  left = seq.value_len;
  result = gcert_der_next(&p, &left, &tbs);
  if (result != GCERT_OK || !gcert_der_is(&tbs, GCERT_DER_UNIVERSAL, 1, 16)) {
    return GCERT_ERR_CORRUPT;
  }
  tbs_bytes = p - tbs.total_len;
  result = gcert_der_next(&p, &left, &alg);
  if (result != GCERT_OK) {
    return result;
  }
  result = gcert_der_next(&p, &left, &sig);
  if (result != GCERT_OK || left != 0) {
    return GCERT_ERR_CORRUPT;
  }
  result = gcert_der_bit_payload(&sig, &bits, &bits_len);
  if (result != GCERT_OK) {
    return result;
  }
  result = parse_tbs(&tbs, tbs_bytes, tbs.total_len, out);
  if (result != GCERT_OK) {
    clear_cert(out);
    return result;
  }
  inner_key = out->sig_key;
  inner_hash = out->sig_hash;
  /* Only the algorithm fields, and only so that parse_sig_alg's answer for
   * the outer AlgorithmIdentifier can be compared with the inner one. The
   * rest of the certificate has already been parsed; clear_cert is where
   * fields start at zero. */
  out->sig_key = 0;
  out->sig_hash = 0;
  result = parse_sig_alg(&alg, out);
  if (result != GCERT_OK || out->sig_key != inner_key ||
      out->sig_hash != inner_hash) {
    clear_cert(out);
    return result != GCERT_OK ? result : GCERT_ERR_CORRUPT;
  }
  if (out->sig_key == GCERT_X509_RSA || out->sig_key == GCERT_X509_ED25519) {
    out->sig = bits;
    out->sig_len = bits_len;
  } else {
    size_t width = out->sig_key == GCERT_X509_P256 ? 32u : 48u;
    result = ecdsa_raw(bits, bits_len, width, out->ecdsa_raw);
    if (result != GCERT_OK) {
      clear_cert(out);
      return result;
    }
    out->sig = out->ecdsa_raw;
    out->sig_len = width * 2u;
  }
  return GCERT_OK;
}

GCERT_Result gcert_x509_signed_by(const GCERT_X509 * cert, const GCERT_X509 * issuer) {
  if (cert == NULL || issuer == NULL || cert->tbs == NULL || issuer->key == 0) {
    return GCERT_ERR_INVALID;
  }
  /* Every mismatch this catches would also fail the verification it skips,
   * because a signature for one key kind is never a valid signature for
   * another, so no answer tells the check from its absence. What differs is
   * the read: the other kind's verifier is handed signature bytes it was not
   * sized for. test_x509_policy.cpp pairs a 3-byte "RSA signature" with an EC
   * issuer, which `make test-asan` reports as an overflow without this.
   * Dispatching on the issuer's key while ignoring what the certificate says
   * it was signed with is the shape that algorithm-confusion bugs are made
   * of. parse_tbs separately requires the inner and outer
   * AlgorithmIdentifiers to agree. */
  if (cert->sig_key != issuer->key) {
    return GCERT_ERR_MISMATCH;
  }
  if (issuer->key == GCERT_X509_RSA) {
    return gcert_from_gsec(gsec_rsa_pkcs1_v15_verify(cert->sig_hash, issuer->n, issuer->n_len,
        issuer->e, issuer->e_len, cert->tbs, cert->tbs_len, cert->sig,
        cert->sig_len));
  }
  if (issuer->key == GCERT_X509_P256) {
    return gcert_from_gsec(gsec_ecdsa_p256_verify(issuer->point, cert->tbs, cert->tbs_len,
        cert->sig));
  }
  if (issuer->key == GCERT_X509_P384) {
    return gcert_from_gsec(gsec_ecdsa_p384_verify(issuer->point, cert->tbs, cert->tbs_len,
        cert->sig));
  }
  if (issuer->key == GCERT_X509_ED25519) {
    return gcert_from_gsec(gsec_ed25519_verify(issuer->point, cert->tbs, cert->tbs_len,
        cert->sig));
  }
  return GCERT_ERR_UNSUPPORTED;
}

static int names_eq(const GCERT_X509 * a_subject, const GCERT_X509 * b_issuer) {
  return gcert_der_eq(a_subject->subject, a_subject->subject_len,
      b_issuer->issuer, b_issuer->issuer_len);
}

static int in_force(const GCERT_X509 * cert, int64_t unix_time) {
  return cert->not_before <= unix_time && unix_time <= cert->not_after;
}

static int self_issued(const GCERT_X509 * cert) {
  return gcert_der_eq(cert->subject, cert->subject_len, cert->issuer,
      cert->issuer_len);
}

/* MD5 and SHA-1 are refused for a link in a chain. Both have practical
 * chosen-prefix collisions - Flame in 2012, SHA-1 in 2020 - so a signature
 * over a digest either of them produced is not evidence of anything.
 * gcert_x509_signed_by still verifies them on purpose: identifying an old
 * certificate is how a caller comes to refuse it. */
static GCERT_Result strong_enough(const GCERT_X509 * cert) {
  if (cert->sig_hash == GSEC_RSA_MD5 || cert->sig_hash == GSEC_RSA_SHA1) {
    return GCERT_ERR_UNSUPPORTED;
  }
  return GCERT_OK;
}

/* A 1024-bit RSA key in a certificate is not a key. The primitives allow
 * smaller, because a self-test signs with a 512-bit key deliberately; a
 * trust decision does not get that latitude. */
static GCERT_Result key_big_enough(const GCERT_X509 * cert) {
  if (cert->key == GCERT_X509_RSA &&
      cert->n_len * 8u < GCERT_X509_RSA_MIN_BITS) {
    return GCERT_ERR_UNSUPPORTED;
  }
  return GCERT_OK;
}

static GCERT_Result check_link(const GCERT_X509 * cert, const GCERT_X509 * parent,
    int64_t unix_time, const GCERT_X509 * const * prior, size_t prior_n,
    int require_ca) {
  GCERT_Result result;
  size_t i;

  if (!names_eq(parent, cert)) {
    return GCERT_ERR_MISMATCH;
  }
  result = strong_enough(cert);
  if (result != GCERT_OK) {
    return result;
  }
  result = key_big_enough(cert);
  if (result != GCERT_OK) {
    return result;
  }
  result = gcert_x509_signed_by(cert, parent);
  if (result != GCERT_OK) {
    return result;
  }
  if (!in_force(cert, unix_time)) {
    return GCERT_ERR_MISMATCH;
  }
  for (i = 0; i < prior_n; i++) {
    if (prior[i]->name_constraints_len == 0) {
      continue;
    }
    result = apply_one_nc(cert, prior[i]->name_constraints,
        prior[i]->name_constraints_len);
    if (result != GCERT_OK) {
      return result;
    }
  }
  if (require_ca) {
    if (!cert->ca) {
      return GCERT_ERR_MISMATCH;
    }
    if (cert->key_usage_set && (cert->key_usage & 0x04u) == 0) {
      return GCERT_ERR_MISMATCH;
    }
  }
  return GCERT_OK;
}

GCERT_Result gcert_x509_path(const void * leaf, size_t leaf_len,
    const void * const * mids, const size_t * mid_lens, size_t mid_count,
    const void * anchor, size_t anchor_len, int64_t unix_time,
    unsigned purpose) {
  GCERT_X509 trust;
  GCERT_X509 chain[GCERT_X509_CHAIN_MAX];
  GCERT_X509 end;
  GCERT_Result result;
  const GCERT_X509 * prior[GCERT_X509_CHAIN_MAX + 1u];
  size_t prior_n;
  size_t i;
  int room;

  if (leaf == NULL || anchor == NULL || (mids == NULL && mid_count != 0) ||
      (mid_lens == NULL && mid_count != 0)) {
    return GCERT_ERR_INVALID;
  }
  if (mid_count > GCERT_X509_CHAIN_MAX) {
    return GCERT_ERR_LIMIT;
  }
  result = gcert_x509_parse(anchor, anchor_len, &trust);
  if (result != GCERT_OK) {
    return result;
  }
  if (trust.basic_constraints && !trust.ca) {
    return GCERT_ERR_MISMATCH;
  }
  if (trust.key_usage_set && (trust.key_usage & 0x04u) == 0) {
    return GCERT_ERR_MISMATCH;
  }
  result = key_big_enough(&trust);
  if (result != GCERT_OK) {
    return result;
  }
  /* RFC 5280 section 6.1 does not examine the anchor's dates: it is trusted
   * input. Checked anyway. An expired root is a thing that happens, and a
   * caller that is told the chain is good has no way to notice. */
  if (!in_force(&trust, unix_time)) {
    return GCERT_ERR_MISMATCH;
  }
  prior[0] = &trust;
  prior_n = 1;
  room = trust.path_len_set ? (int)trust.path_len : -1;
  for (i = 0; i < mid_count; i++) {
    if (room == 0) {
      return GCERT_ERR_MISMATCH;
    }
    result = gcert_x509_parse(mids[i], mid_lens[i], &chain[i]);
    if (result != GCERT_OK) {
      return result;
    }
    result = check_link(&chain[i], prior[prior_n - 1u], unix_time, prior,
        prior_n, 1);
    if (result != GCERT_OK) {
      return result;
    }
    if (!self_issued(&chain[i]) && room > 0) {
      room--;
    }
    if (chain[i].path_len_set && (room < 0 || (int)chain[i].path_len < room)) {
      room = (int)chain[i].path_len;
    }
    prior[prior_n++] = &chain[i];
  }
  result = gcert_x509_parse(leaf, leaf_len, &end);
  if (result != GCERT_OK) {
    return result;
  }
  result = check_link(&end, prior[prior_n - 1u], unix_time, prior, prior_n, 0);
  if (result != GCERT_OK) {
    return result;
  }
  if (purpose != 0) {
    return gcert_x509_purpose(&end, purpose);
  }
  return GCERT_OK;
}

GCERT_Result gcert_x509_purpose(const GCERT_X509 * cert, unsigned purpose) {
  if (cert == NULL || purpose == 0) {
    return GCERT_ERR_INVALID;
  }
  if (!cert->eku_set) {
    return GCERT_OK;
  }
  if ((cert->eku & GCERT_X509_EKU_ANY) != 0) {
    return GCERT_OK;
  }
  if ((cert->eku & purpose) != 0) {
    return GCERT_OK;
  }
  return GCERT_ERR_MISMATCH;
}
