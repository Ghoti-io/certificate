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
 * A certificate, built and signed. The time encoding is the inverse of
 * the reader: UTCTime through 2049, GeneralizedTime after that.
 */

#include <ghoti.io/certificate/macros.h>
#include "../core/sec_result.h"

#include <ghoti.io/security/ecdsa_p256.h>
#include <ghoti.io/security/ecdsa_p384.h>
#include <ghoti.io/security/ed25519.h>
#include <ghoti.io/security/rsa.h>
#include <ghoti.io/security/secret.h>
#include <ghoti.io/certificate/x509.h>

#include <string.h>

#define ISSUE_MAX 8192u

typedef struct {
  unsigned char b[ISSUE_MAX];
  size_t n;
  int bad;
} Buf;

static void add(Buf * o, const void * p, size_t n) {
  if (o->bad || o->n + n > ISSUE_MAX) {
    o->bad = 1;
    return;
  }
  if (n != 0) {
    memcpy(o->b + o->n, p, n);
  }
  o->n += n;
}

static void add_len(Buf * o, size_t n) {
  unsigned char h[3];

  if (n < 128u) {
    h[0] = (unsigned char)n;
    add(o, h, 1);
  } else if (n < 256u) {
    h[0] = 0x81;
    h[1] = (unsigned char)n;
    add(o, h, 2);
  } else {
    h[0] = 0x82;
    h[1] = (unsigned char)(n >> 8);
    h[2] = (unsigned char)n;
    add(o, h, 3);
  }
}

static void add_tlv(Buf * o, unsigned char tag, const void * p, size_t n) {
  unsigned char t = tag;
  add(o, &t, 1);
  add_len(o, n);
  add(o, p, n);
}

static void add_uint(Buf * o, const unsigned char * be, size_t n) {
  size_t i = 0;
  unsigned char zero = 0;
  unsigned char tag = 0x02;

  while (i < n && be[i] == 0) {
    i++;
  }
  if (i == n) {
    add_tlv(o, 0x02, &zero, 1);
    return;
  }
  if ((be[i] & 0x80u) != 0) {
    add(o, &tag, 1);
    add_len(o, n - i + 1u);
    add(o, &zero, 1);
    add(o, be + i, n - i);
    return;
  }
  add_tlv(o, 0x02, be + i, n - i);
}

static void add_seq(Buf * o, const Buf * inner) {
  if (inner->bad) {
    o->bad = 1;
    return;
  }
  add_tlv(o, 0x30, inner->b, inner->n);
}

static void two_digits(unsigned char * p, int v) {
  p[0] = (unsigned char)('0' + v / 10);
  p[1] = (unsigned char)('0' + v % 10);
}

static void civil_from_days(int64_t z, int * year, int * month, int * day) {
  int64_t era;
  unsigned doe;
  unsigned yoe;
  unsigned doy;
  unsigned mp;
  int64_t y;

  z += 719468;
  era = (z >= 0 ? z : z - 146096) / 146097;
  doe = (unsigned)(z - era * 146097);
  yoe = (doe - doe / 1460u + doe / 36524u - doe / 146096u) / 365u;
  y = (int64_t)yoe + era * 400;
  doy = doe - (365u * yoe + yoe / 4u - yoe / 100u);
  mp = (5u * doy + 2u) / 153u;
  *day = (int)(doy - (153u * mp + 2u) / 5u + 1u);
  *month = (int)(mp < 10u ? mp + 3u : mp - 9u);
  y += (*month <= 2);
  *year = (int)y;
}

static void add_time(Buf * o, int64_t unix_time) {
  int64_t days;
  int64_t rem;
  int year;
  int month;
  int day;
  int hour;
  int minute;
  int second;
  unsigned char text[16];
  size_t n;
  unsigned char tag;

  days = unix_time / 86400;
  rem = unix_time % 86400;
  if (rem < 0) {
    rem += 86400;
    days -= 1;
  }
  civil_from_days(days, &year, &month, &day);
  hour = (int)(rem / 3600);
  minute = (int)((rem % 3600) / 60);
  second = (int)(rem % 60);
  if (year < 1950 || year > 9999) {
    o->bad = 1;
    return;
  }
  if (year <= 2049) {
    tag = 0x17;
    two_digits(text, year % 100);
    n = 2;
  } else {
    tag = 0x18;
    two_digits(text, year / 100);
    two_digits(text + 2, year % 100);
    n = 4;
  }
  two_digits(text + n, month);
  two_digits(text + n + 2, day);
  two_digits(text + n + 4, hour);
  two_digits(text + n + 6, minute);
  two_digits(text + n + 8, second);
  text[n + 10] = 'Z';
  add_tlv(o, tag, text, n + 11u);
}

static void add_oid(Buf * o, const unsigned char * oid, size_t n) {
  add_tlv(o, 0x06, oid, n);
}

static void add_alg(Buf * o, const unsigned char * alg, size_t n) {
  add(o, alg, n);
}

static const unsigned char ALG_ECDSA_SHA256[] = {
  0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02
};
static const unsigned char ALG_ECDSA_SHA384[] = {
  0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03
};
static const unsigned char ALG_ED25519[] = {
  0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70
};
static const unsigned char ALG_RSA_SHA256[] = {
  0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
  0x0b, 0x05, 0x00
};
static const unsigned char ALG_RSA_SHA384[] = {
  0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
  0x0c, 0x05, 0x00
};
static const unsigned char ALG_RSA_SHA512[] = {
  0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
  0x0d, 0x05, 0x00
};
static const unsigned char ALG_RSA_SHA1[] = {
  0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
  0x05, 0x05, 0x00
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
static const unsigned char OID_RSA[] = {
  0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01
};
static const unsigned char OID_ED25519[] = {0x2b, 0x65, 0x70};
static const unsigned char OID_BC[] = {0x55, 0x1d, 0x13};
static const unsigned char OID_SAN[] = {0x55, 0x1d, 0x11};
static const unsigned char OID_SKI[] = {0x55, 0x1d, 0x0e};
static const unsigned char OID_AKI[] = {0x55, 0x1d, 0x23};
static const unsigned char NULL_TLV[] = {0x05, 0x00};

static int alg_for(const GCERT_X509_Signer * signer, const unsigned char ** alg,
    size_t * alg_len) {
  if (signer->key == GCERT_X509_P256) {
    *alg = ALG_ECDSA_SHA256;
    *alg_len = sizeof ALG_ECDSA_SHA256;
    return 1;
  }
  if (signer->key == GCERT_X509_P384) {
    *alg = ALG_ECDSA_SHA384;
    *alg_len = sizeof ALG_ECDSA_SHA384;
    return 1;
  }
  if (signer->key == GCERT_X509_ED25519) {
    *alg = ALG_ED25519;
    *alg_len = sizeof ALG_ED25519;
    return 1;
  }
  if (signer->key != GCERT_X509_RSA) {
    return 0;
  }
  if (signer->hash == GSEC_RSA_SHA256) {
    *alg = ALG_RSA_SHA256;
    *alg_len = sizeof ALG_RSA_SHA256;
  } else if (signer->hash == GSEC_RSA_SHA384) {
    *alg = ALG_RSA_SHA384;
    *alg_len = sizeof ALG_RSA_SHA384;
  } else if (signer->hash == GSEC_RSA_SHA512) {
    *alg = ALG_RSA_SHA512;
    *alg_len = sizeof ALG_RSA_SHA512;
  } else if (signer->hash == GSEC_RSA_SHA1) {
    *alg = ALG_RSA_SHA1;
    *alg_len = sizeof ALG_RSA_SHA1;
  } else {
    return 0;
  }
  return 1;
}

static void add_spki(Buf * o, const GCERT_X509_Tbs * tbs) {
  Buf alg;
  Buf seq;
  unsigned char bits[1u + 96u + 1u];

  memset(&alg, 0, sizeof alg);
  memset(&seq, 0, sizeof seq);
  if (tbs->subject_key == GCERT_X509_P256 || tbs->subject_key == GCERT_X509_P384) {
    size_t want = tbs->subject_key == GCERT_X509_P256 ? 32u : 48u;
    const unsigned char * curve = want == 32u ? OID_P256 : OID_P384;
    size_t curve_len = want == 32u ? sizeof OID_P256 : sizeof OID_P384;
    if (tbs->point == NULL || tbs->point_len != want * 2u) {
      o->bad = 1;
      return;
    }
    add_oid(&alg, OID_EC, sizeof OID_EC);
    add_oid(&alg, curve, curve_len);
    add_seq(&seq, &alg);
    bits[0] = 0x00;
    bits[1] = 0x04;
    memcpy(bits + 2, tbs->point, tbs->point_len);
    add_tlv(&seq, 0x03, bits, 2u + tbs->point_len);
  } else if (tbs->subject_key == GCERT_X509_ED25519) {
    if (tbs->point == NULL || tbs->point_len != 32u) {
      o->bad = 1;
      return;
    }
    add_oid(&alg, OID_ED25519, sizeof OID_ED25519);
    add_seq(&seq, &alg);
    bits[0] = 0x00;
    memcpy(bits + 1, tbs->point, 32);
    add_tlv(&seq, 0x03, bits, 33);
  } else if (tbs->subject_key == GCERT_X509_RSA) {
    if (tbs->n == NULL || tbs->e == NULL || tbs->n_len == 0 || tbs->e_len == 0 ||
        tbs->n_len > 512u) {
      o->bad = 1;
      return;
    }
  } else {
    o->bad = 1;
    return;
  }
  if (tbs->subject_key == GCERT_X509_RSA) {
    Buf alg_only;
    Buf key;
    Buf spki;
    Buf bitsb;
    memset(&alg_only, 0, sizeof alg_only);
    memset(&key, 0, sizeof key);
    memset(&spki, 0, sizeof spki);
    memset(&bitsb, 0, sizeof bitsb);
    add_oid(&alg_only, OID_RSA, sizeof OID_RSA);
    add(&alg_only, NULL_TLV, sizeof NULL_TLV);
    add_seq(&spki, &alg_only);
    add_uint(&key, tbs->n, tbs->n_len);
    add_uint(&key, tbs->e, tbs->e_len);
    bits[0] = 0x00;
    add(&bitsb, bits, 1);
    add_seq(&bitsb, &key);
    add_tlv(&spki, 0x03, bitsb.b, bitsb.n);
    if (bitsb.bad) {
      spki.bad = 1;
    }
    add_seq(o, &spki);
    return;
  }
  add_seq(o, &seq);
}

static void add_extension(Buf * o, const unsigned char * oid, size_t oid_len,
    int critical, const Buf * value) {
  Buf ext;
  Buf oct;
  unsigned char yes = 0xff;

  memset(&ext, 0, sizeof ext);
  memset(&oct, 0, sizeof oct);
  add_oid(&ext, oid, oid_len);
  if (critical) {
    add_tlv(&ext, 0x01, &yes, 1);
  }
  add_tlv(&oct, 0x04, value->b, value->n);
  if (value->bad) {
    oct.bad = 1;
  }
  add(&ext, oct.b, oct.n);
  if (oct.bad) {
    ext.bad = 1;
  }
  add_seq(o, &ext);
}

static void add_extensions(Buf * o, const GCERT_X509_Tbs * tbs) {
  Buf list;
  Buf body;
  Buf one;
  int any = 0;

  memset(&list, 0, sizeof list);
  if (tbs->ca) {
    unsigned char yes = 0xff;
    memset(&body, 0, sizeof body);
    add_tlv(&body, 0x01, &yes, 1);
    if (tbs->path_len_set) {
      unsigned char path_byte;
      if (tbs->path_len > 255u) {
        o->bad = 1;
        return;
      }
      path_byte = (unsigned char)tbs->path_len;
      add_uint(&body, &path_byte, 1);
    }
    memset(&one, 0, sizeof one);
    add_seq(&one, &body);
    add_extension(&list, OID_BC, sizeof OID_BC, 1, &one);
    any = 1;
  }
  if (tbs->dns_len != 0 || tbs->ip_len != 0 || tbs->uri_len != 0 || tbs->email_len != 0) {
    Buf name;
    size_t i;
    const unsigned char * dns = tbs->dns;
    const unsigned char * uri = tbs->uri;
    const unsigned char * email = tbs->email;
    if ((tbs->dns_len != 0 && tbs->dns == NULL) || (tbs->uri_len != 0 && uri == NULL) ||
        (tbs->email_len != 0 && email == NULL) ||
        (tbs->ip_len != 0 && (tbs->ip == NULL || (tbs->ip_len != 4 && tbs->ip_len != 16)))) {
      o->bad = 1;
      return;
    }
    for (i = 0; i < tbs->dns_len; i++) {
      if (dns[i] >= 0x80u) {
        o->bad = 1;
        return;
      }
    }
    for (i = 0; i < tbs->uri_len; i++) {
      if (uri[i] >= 0x80u) {
        o->bad = 1;
        return;
      }
    }
    for (i = 0; i < tbs->email_len; i++) {
      if (email[i] >= 0x80u) {
        o->bad = 1;
        return;
      }
    }
    memset(&name, 0, sizeof name);
    if (tbs->email_len != 0) {
      add_tlv(&name, 0x81, email, tbs->email_len);
    }
    if (tbs->dns_len != 0) {
      add_tlv(&name, 0x82, dns, tbs->dns_len);
    }
    if (tbs->uri_len != 0) {
      add_tlv(&name, 0x86, uri, tbs->uri_len);
    }
    if (tbs->ip_len != 0) {
      add_tlv(&name, 0x87, tbs->ip, tbs->ip_len);
    }
    memset(&one, 0, sizeof one);
    add_seq(&one, &name);
    add_extension(&list, OID_SAN, sizeof OID_SAN, 0, &one);
    any = 1;
  }
  if (tbs->ski_len != 0) {
    if (tbs->ski == NULL) {
      o->bad = 1;
      return;
    }
    memset(&one, 0, sizeof one);
    add_tlv(&one, 0x04, tbs->ski, tbs->ski_len);
    add_extension(&list, OID_SKI, sizeof OID_SKI, 0, &one);
    any = 1;
  }
  if (tbs->aki_len != 0) {
    Buf kid;
    if (tbs->aki == NULL) {
      o->bad = 1;
      return;
    }
    memset(&kid, 0, sizeof kid);
    add_tlv(&kid, 0x80, tbs->aki, tbs->aki_len);
    memset(&one, 0, sizeof one);
    add_seq(&one, &kid);
    add_extension(&list, OID_AKI, sizeof OID_AKI, 0, &one);
    any = 1;
  }
  if (!any) {
    return;
  }
  memset(&body, 0, sizeof body);
  add_seq(&body, &list);
  add_tlv(o, 0xa3, body.b, body.n);
  if (body.bad || list.bad) {
    o->bad = 1;
  }
}

static GCERT_Result issue_fail(void * out, size_t out_cap, GCERT_Result result) {
  gsec_wipe(out, out_cap);
  return result;
}

GCERT_Result gcert_x509_issue(const GCERT_X509_Tbs * tbs,
    const GCERT_X509_Signer * signer, void * out, size_t out_cap,
    size_t * out_len) {
  Buf tbs_buf;
  Buf cert;
  Buf validity;
  const unsigned char * alg = NULL;
  size_t alg_len = 0;
  unsigned char version[3] = {0x02, 0x01, 0x02};
  unsigned char sig[512];
  unsigned char der_sig[520];
  size_t der_len = 0;
  GCERT_Result result = GCERT_OK;

  if (out == NULL) {
    return GCERT_ERR_INVALID;
  }
  if (tbs == NULL || signer == NULL || out_len == NULL ||
      tbs->issuer == NULL || tbs->subject == NULL || tbs->serial == NULL ||
      tbs->issuer_len == 0 || tbs->subject_len == 0 || tbs->serial_len == 0 ||
      tbs->serial_len > 20u || signer->d == NULL || signer->d_len == 0) {
    return issue_fail(out, out_cap, GCERT_ERR_INVALID);
  }
  if (!alg_for(signer, &alg, &alg_len)) {
    return issue_fail(out, out_cap, GCERT_ERR_INVALID);
  }
  memset(&tbs_buf, 0, sizeof tbs_buf);
  add_tlv(&tbs_buf, 0xa0, version, sizeof version);
  add_uint(&tbs_buf, tbs->serial, tbs->serial_len);
  add_alg(&tbs_buf, alg, alg_len);
  add(&tbs_buf, tbs->issuer, tbs->issuer_len);
  memset(&validity, 0, sizeof validity);
  add_time(&validity, tbs->not_before);
  add_time(&validity, tbs->not_after);
  add_seq(&tbs_buf, &validity);
  add(&tbs_buf, tbs->subject, tbs->subject_len);
  add_spki(&tbs_buf, tbs);
  add_extensions(&tbs_buf, tbs);
  if (tbs_buf.bad || validity.bad) {
    return issue_fail(out, out_cap, GCERT_ERR_LIMIT);
  }
  {
    Buf wrapped;
    memset(&wrapped, 0, sizeof wrapped);
    add_seq(&wrapped, &tbs_buf);
    if (wrapped.bad) {
      return issue_fail(out, out_cap, GCERT_ERR_LIMIT);
    }
    memcpy(tbs_buf.b, wrapped.b, wrapped.n);
    tbs_buf.n = wrapped.n;
  }
  if (signer->key == GCERT_X509_P256) {
    if (signer->d_len != GSEC_ECDSA_P256_LEN) {
      return issue_fail(out, out_cap, GCERT_ERR_INVALID);
    }
    result = gcert_from_gsec(gsec_ecdsa_p256_sign(signer->d, tbs_buf.b, tbs_buf.n, sig));
    der_len = 64;
  } else if (signer->key == GCERT_X509_P384) {
    if (signer->d_len != GSEC_ECDSA_P384_LEN) {
      return issue_fail(out, out_cap, GCERT_ERR_INVALID);
    }
    result = gcert_from_gsec(gsec_ecdsa_p384_sign(signer->d, tbs_buf.b, tbs_buf.n, sig));
    der_len = 96;
  } else if (signer->key == GCERT_X509_ED25519) {
    if (signer->d_len != 32u) {
      return issue_fail(out, out_cap, GCERT_ERR_INVALID);
    }
    result = gcert_from_gsec(gsec_ed25519_sign(signer->d, tbs_buf.b, tbs_buf.n, sig));
    der_len = 64;
  } else {
    size_t k = signer->n_len;
    const unsigned char * n = signer->n;
    if (signer->n == NULL || signer->e == NULL || k == 0) {
      return issue_fail(out, out_cap, GCERT_ERR_INVALID);
    }
    while (k > 0 && n[0] == 0x00) {
      n++;
      k--;
    }
    if (k == 0 || k > sizeof sig) {
      return issue_fail(out, out_cap, GCERT_ERR_INVALID);
    }
    result = gcert_from_gsec(gsec_rsa_private_pkcs1_v15_sign(signer->hash, signer->n,
        signer->n_len, signer->e, signer->e_len, signer->d, signer->d_len,
        tbs_buf.b, tbs_buf.n, sig, k));
    der_len = k;
  }
  if (result != GCERT_OK) {
    gsec_wipe(sig, sizeof sig);
    return issue_fail(out, out_cap, result);
  }
  if (signer->key == GCERT_X509_P256 || signer->key == GCERT_X509_P384) {
    Buf nums;
    Buf seq;
    size_t half = der_len / 2u;
    memset(&nums, 0, sizeof nums);
    memset(&seq, 0, sizeof seq);
    add_uint(&nums, sig, half);
    add_uint(&nums, sig + half, half);
    add_seq(&seq, &nums);
    if (seq.bad || seq.n > sizeof der_sig) {
      gsec_wipe(sig, sizeof sig);
      return issue_fail(out, out_cap, GCERT_ERR_LIMIT);
    }
    memcpy(der_sig, seq.b, seq.n);
    der_len = seq.n;
  } else {
    if (der_len > sizeof der_sig) {
      gsec_wipe(sig, sizeof sig);
      return issue_fail(out, out_cap, GCERT_ERR_LIMIT);
    }
    memcpy(der_sig, sig, der_len);
  }
  gsec_wipe(sig, sizeof sig);
  memset(&cert, 0, sizeof cert);
  add(&cert, tbs_buf.b, tbs_buf.n);
  add_alg(&cert, alg, alg_len);
  {
    Buf bits;
    unsigned char zero = 0;
    memset(&bits, 0, sizeof bits);
    add(&bits, &zero, 1);
    add(&bits, der_sig, der_len);
    add_tlv(&cert, 0x03, bits.b, bits.n);
    if (bits.bad) {
      cert.bad = 1;
    }
  }
  {
    Buf wrapped;
    memset(&wrapped, 0, sizeof wrapped);
    add_seq(&wrapped, &cert);
    if (wrapped.bad || wrapped.n > out_cap) {
      gsec_wipe(der_sig, sizeof der_sig);
      return issue_fail(out, out_cap, GCERT_ERR_LIMIT);
    }
    memcpy(out, wrapped.b, wrapped.n);
    *out_len = wrapped.n;
  }
  gsec_wipe(der_sig, sizeof der_sig);
  return GCERT_OK;
}
