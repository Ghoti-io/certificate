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
 * Private keys, and signing and verifying by scheme. See key.h.
 */

#include <ghoti.io/certificate/macros.h>

#include <ghoti.io/certificate/key.h>
#include <ghoti.io/certificate/pem.h>
#include <ghoti.io/certificate/pkcs8.h>
#include <ghoti.io/security/ecdsa_p256.h>
#include <ghoti.io/security/ecdsa_p384.h>
#include <ghoti.io/security/ed25519.h>
#include <ghoti.io/security/random.h>
#include <ghoti.io/security/rsa.h>
#include <ghoti.io/security/secret.h>

#include "../core/sec_result.h"
#include "../der/der_int.h"
#include "../x509/signed.h"

#include <string.h>

#define RSA_MAX 512u
#define RSA_E_MAX 8u

struct GCERT_Key {
  const GCERT_Allocator * alloc;
  uint32_t kind;
  unsigned char n[RSA_MAX];
  size_t n_len;
  unsigned char e[RSA_E_MAX];
  size_t e_len;
  unsigned char d[RSA_MAX];
  size_t d_len;
  unsigned char scalar[48];   /* EC scalar, or the Ed25519 seed */
  size_t scalar_len;
  unsigned char pub[96];      /* x then y, or the Ed25519 public key */
  size_t pub_len;
};

static const unsigned char * strip(const unsigned char * p, size_t * n) {
  while (*n > 1u && p[0] == 0) {
    p++;
    (*n)--;
  }
  return p;
}

/* ---- schemes ---------------------------------------------------------- */

typedef struct SchemeInfo {
  GCERT_SigScheme scheme;
  uint32_t kind;
  uint32_t hash;   /* a GSEC_RSA_* id, for RSA */
  int pss;
  size_t digest;   /* digest length, for the PSS salt */
} SchemeInfo;

static const SchemeInfo SCHEMES[] = {
  {GCERT_SIG_RSA_PKCS1_SHA256, GCERT_X509_RSA, GSEC_RSA_SHA256, 0, 32},
  {GCERT_SIG_RSA_PKCS1_SHA384, GCERT_X509_RSA, GSEC_RSA_SHA384, 0, 48},
  {GCERT_SIG_RSA_PKCS1_SHA512, GCERT_X509_RSA, GSEC_RSA_SHA512, 0, 64},
  {GCERT_SIG_RSA_PSS_SHA256, GCERT_X509_RSA, GSEC_RSA_SHA256, 1, 32},
  {GCERT_SIG_RSA_PSS_SHA384, GCERT_X509_RSA, GSEC_RSA_SHA384, 1, 48},
  {GCERT_SIG_RSA_PSS_SHA512, GCERT_X509_RSA, GSEC_RSA_SHA512, 1, 64},
  {GCERT_SIG_ECDSA_P256_SHA256, GCERT_X509_P256, 0, 0, 0},
  {GCERT_SIG_ECDSA_P384_SHA384, GCERT_X509_P384, 0, 0, 0},
  {GCERT_SIG_ED25519, GCERT_X509_ED25519, 0, 0, 0},
};

static const SchemeInfo * scheme_info(GCERT_SigScheme scheme) {
  size_t i;
  for (i = 0; i < sizeof SCHEMES / sizeof SCHEMES[0]; i++) {
    if (SCHEMES[i].scheme == scheme) {
      return &SCHEMES[i];
    }
  }
  return NULL;
}

int gcert_key_scheme_fits(GCERT_SigScheme scheme, uint32_t kind) {
  const SchemeInfo * s = scheme_info(scheme);
  return s != NULL && s->kind == kind;
}

/* ---- loading ---------------------------------------------------------- */

static void wipe_key(GCERT_Key * k) {
  (void)gsec_wipe(k, sizeof *k);
}

GCERT_Result gcert_key_from_pkcs8_view(const GCERT_Allocator * allocator,
    const GCERT_Pkcs8 * view, GCERT_Key ** out);

static GCERT_Result rsa_roundtrip(const GCERT_Key * k) {
  static const unsigned char msg[] = "gcert key check";
  unsigned char sig[RSA_MAX];
  size_t n_len = k->n_len;
  size_t n_off = 0;
  GCERT_Result result;

  while (n_len > 1u && k->n[n_off] == 0) {
    n_off++;
    n_len--;
  }
  result = gcert_from_gsec(gsec_rsa_private_pkcs1_v15_sign(GSEC_RSA_SHA256, k->n, k->n_len,
      k->e, k->e_len, k->d, k->d_len, msg, sizeof msg - 1u, sig, n_len));
  if (result != GCERT_OK) {
    /* A private exponent that does not invert the public one makes the blinding
     * self-check fail, which the primitive reports as an internal error; here
     * that is the key being wrong, not the library. */
    return result == GCERT_ERR_INVALID || result == GCERT_ERR_INTERNAL
        ? GCERT_ERR_MISMATCH : result;
  }
  result = gcert_from_gsec(gsec_rsa_pkcs1_v15_verify(GSEC_RSA_SHA256, k->n, k->n_len, k->e,
      k->e_len, msg, sizeof msg - 1u, sig, n_len));
  (void)gsec_wipe(sig, sizeof sig);
  return result;
}

GCERT_Result gcert_key_from_pkcs8_view(const GCERT_Allocator * allocator,
    const GCERT_Pkcs8 * v, GCERT_Key ** out) {
  const GCERT_Allocator * a = allocator != NULL ? allocator : gcert_allocator_default();
  GCERT_Key * k;
  GCERT_Result result = GCERT_OK;

  *out = NULL;
  k = a->calloc_fn(a->ctx, 1, sizeof *k);
  if (k == NULL) {
    return GCERT_ERR_OOM;
  }
  k->alloc = a;
  switch (v->kind) {
    case GCERT_PKCS8_RSA: {
      size_t nl = v->n_len;
      size_t el = v->e_len;
      size_t dl = v->d_len;
      const unsigned char * n = strip(v->n, &nl);
      const unsigned char * e = strip(v->e, &el);
      const unsigned char * d = strip(v->d, &dl);
      if (nl > RSA_MAX || dl > RSA_MAX || el > RSA_E_MAX || nl == 0 || el == 0 || dl == 0) {
        result = GCERT_ERR_UNSUPPORTED;
        break;
      }
      k->kind = GCERT_X509_RSA;
      memcpy(k->n, n, nl);
      k->n_len = nl;
      memcpy(k->e, e, el);
      k->e_len = el;
      memcpy(k->d, d, dl);
      k->d_len = dl;
      result = rsa_roundtrip(k);
      break;
    }
    case GCERT_PKCS8_P256:
      if (v->scalar_len != 32) {
        result = GCERT_ERR_CORRUPT;
        break;
      }
      k->kind = GCERT_X509_P256;
      memcpy(k->scalar, v->scalar, 32);
      k->scalar_len = 32;
      k->pub_len = 64;
      result = gcert_from_gsec(gsec_ecdsa_p256_public(k->scalar, k->pub));
      break;
    case GCERT_PKCS8_P384:
      if (v->scalar_len != 48) {
        result = GCERT_ERR_CORRUPT;
        break;
      }
      k->kind = GCERT_X509_P384;
      memcpy(k->scalar, v->scalar, 48);
      k->scalar_len = 48;
      k->pub_len = 96;
      result = gcert_from_gsec(gsec_ecdsa_p384_public(k->scalar, k->pub));
      break;
    case GCERT_PKCS8_ED25519:
      if (v->scalar_len != 32) {
        result = GCERT_ERR_CORRUPT;
        break;
      }
      k->kind = GCERT_X509_ED25519;
      memcpy(k->scalar, v->scalar, 32);
      k->scalar_len = 32;
      k->pub_len = 32;
      result = gcert_from_gsec(gsec_ed25519_public(k->scalar, k->pub));
      break;
    default:
      result = GCERT_ERR_UNSUPPORTED;
      break;
  }
  if (result == GCERT_ERR_INVALID) {
    result = GCERT_ERR_CORRUPT;  /* a scalar out of range is a bad file, not a bad call */
  }
  if (result != GCERT_OK) {
    wipe_key(k);
    a->free_fn(a->ctx, k);
    return result;
  }
  *out = k;
  return GCERT_OK;
}

GCERT_Result gcert_key_from_pkcs8(const GCERT_Allocator * allocator, const void * der,
    size_t len, GCERT_Key ** out) {
  GCERT_Pkcs8 view;
  GCERT_Result result;

  if (out == NULL) {
    return GCERT_ERR_INVALID;
  }
  *out = NULL;
  if (der == NULL || len == 0) {
    return GCERT_ERR_INVALID;
  }
  result = gcert_pkcs8_parse(der, len, &view);
  if (result != GCERT_OK) {
    return result;
  }
  return gcert_key_from_pkcs8_view(allocator, &view, out);
}

/* PKCS#1 RSAPrivateKey: SEQUENCE { version, n, e, d, p, q, dP, dQ, qInv }. */
static GCERT_Result from_pkcs1(const GCERT_Allocator * allocator, const unsigned char * der,
    size_t len, GCERT_Key ** out) {
  GCERT_Der seq;
  GCERT_Der f[4];
  GCERT_Pkcs8 v;
  const unsigned char * p;
  size_t left;
  size_t i;
  GCERT_Result result = gcert_der_tlv(der, len, &seq);

  if (result != GCERT_OK || seq.total_len != len ||
      !gcert_der_is(&seq, GCERT_DER_UNIVERSAL, 1, 16)) {
    return GCERT_ERR_CORRUPT;
  }
  p = seq.value;
  left = seq.value_len;
  for (i = 0; i < 4; i++) {
    result = gcert_der_next(&p, &left, &f[i]);
    if (result != GCERT_OK || !gcert_der_is(&f[i], GCERT_DER_UNIVERSAL, 0, 2)) {
      return GCERT_ERR_CORRUPT;
    }
  }
  memset(&v, 0, sizeof v);
  v.kind = GCERT_PKCS8_RSA;
  if (gcert_der_unsigned(&f[1], &v.n, &v.n_len) != GCERT_OK ||
      gcert_der_unsigned(&f[2], &v.e, &v.e_len) != GCERT_OK ||
      gcert_der_unsigned(&f[3], &v.d, &v.d_len) != GCERT_OK) {
    return GCERT_ERR_CORRUPT;
  }
  /* f[0] is the version, 0 for two primes. */
  {
    const unsigned char * ver;
    size_t ver_len;
    if (gcert_der_unsigned(&f[0], &ver, &ver_len) != GCERT_OK || ver_len != 1 || ver[0] != 0) {
      return GCERT_ERR_UNSUPPORTED;
    }
  }
  return gcert_key_from_pkcs8_view(allocator, &v, out);
}

/* SEC1 ECPrivateKey: SEQUENCE { 1, OCTET STRING scalar, [0] curve OID, [1] public }. */
static const unsigned char OID_P256[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};
static const unsigned char OID_P384[] = {0x2b, 0x81, 0x04, 0x00, 0x22};

static GCERT_Result from_sec1(const GCERT_Allocator * allocator, const unsigned char * der,
    size_t len, GCERT_Key ** out) {
  GCERT_Der seq;
  GCERT_Der f;
  GCERT_Pkcs8 v;
  const unsigned char * p;
  size_t left;
  const unsigned char * ver;
  size_t ver_len;
  GCERT_Result result = gcert_der_tlv(der, len, &seq);

  if (result != GCERT_OK || seq.total_len != len ||
      !gcert_der_is(&seq, GCERT_DER_UNIVERSAL, 1, 16)) {
    return GCERT_ERR_CORRUPT;
  }
  p = seq.value;
  left = seq.value_len;
  result = gcert_der_next(&p, &left, &f);
  if (result != GCERT_OK || gcert_der_unsigned(&f, &ver, &ver_len) != GCERT_OK ||
      ver_len != 1 || ver[0] != 1) {
    return GCERT_ERR_CORRUPT;
  }
  result = gcert_der_next(&p, &left, &f);
  if (result != GCERT_OK || !gcert_der_is(&f, GCERT_DER_UNIVERSAL, 0, 4)) {
    return GCERT_ERR_CORRUPT;
  }
  memset(&v, 0, sizeof v);
  v.scalar = f.value;
  v.scalar_len = f.value_len;
  v.kind = f.value_len == 32 ? GCERT_PKCS8_P256 : (f.value_len == 48 ? GCERT_PKCS8_P384 : 0u);
  while (left != 0) {
    GCERT_Der opt;
    result = gcert_der_next(&p, &left, &opt);
    if (result != GCERT_OK) {
      return GCERT_ERR_CORRUPT;
    }
    if (opt.tag_class == GCERT_DER_CONTEXT && opt.number == 0 && opt.constructed == 1) {
      GCERT_Der oid;
      result = gcert_der_tlv(opt.value, opt.value_len, &oid);
      if (result != GCERT_OK || oid.total_len != opt.value_len) {
        return GCERT_ERR_CORRUPT;
      }
      if (gcert_der_oid_is(&oid, OID_P256, sizeof OID_P256)) {
        if (v.kind != GCERT_PKCS8_P256) {
          return GCERT_ERR_CORRUPT;
        }
      } else if (gcert_der_oid_is(&oid, OID_P384, sizeof OID_P384)) {
        if (v.kind != GCERT_PKCS8_P384) {
          return GCERT_ERR_CORRUPT;
        }
      } else {
        return GCERT_ERR_UNSUPPORTED;
      }
    }
  }
  if (v.kind == 0) {
    return GCERT_ERR_UNSUPPORTED;
  }
  return gcert_key_from_pkcs8_view(allocator, &v, out);
}

static int label_is(const char * label, const char * want) {
  size_t n = strlen(want);
  return strlen(label) == n && gcert_der_eq((const unsigned char *)label,
      n, (const unsigned char *)want, n);
}

GCERT_Result gcert_key_from_pem(const GCERT_Allocator * allocator, const void * pem,
    size_t len, const void * password, size_t password_len, const GCERT_Limits * limits,
    GCERT_Key ** out) {
  const GCERT_Allocator * a = allocator != NULL ? allocator : gcert_allocator_default();
  unsigned char * buf;
  unsigned char * plain = NULL;
  size_t pos = 0;
  GCERT_Result result = GCERT_ERR_FORMAT;

  if (out == NULL) {
    return GCERT_ERR_INVALID;
  }
  *out = NULL;
  if ((pem == NULL && len != 0) || (password == NULL && password_len != 0)) {
    return GCERT_ERR_INVALID;
  }
  buf = a->malloc_fn(a->ctx, len + 1u);
  if (buf == NULL) {
    return GCERT_ERR_OOM;
  }
  for (;;) {
    char label[65];
    size_t n = 0;

    memset(label, 0, sizeof label);
    result = gcert_pem_next(pem, len, &pos, buf, len + 1u, &n, label, sizeof label - 1u);
    if (result == GCERT_ERR_FORMAT) {
      break;  /* no private key in the file */
    }
    if (result != GCERT_OK) {
      continue;  /* a block that does not decode is not this key; try the next */
    }
    if (label_is(label, "PRIVATE KEY")) {
      result = gcert_key_from_pkcs8(a, buf, n, out);
    } else if (label_is(label, "RSA PRIVATE KEY")) {
      result = from_pkcs1(a, buf, n, out);
    } else if (label_is(label, "EC PRIVATE KEY")) {
      result = from_sec1(a, buf, n, out);
    } else if (label_is(label, "ENCRYPTED PRIVATE KEY")) {
      size_t plain_len = 0;
      if (password == NULL && password_len == 0) {
        result = GCERT_ERR_INVALID;
        break;
      }
      plain = a->malloc_fn(a->ctx, n + 1u);
      if (plain == NULL) {
        result = GCERT_ERR_OOM;
        break;
      }
      result = gcert_pkcs8_decrypt(buf, n, password, password_len, plain, n + 1u,
          &plain_len, limits);
      if (result == GCERT_OK) {
        result = gcert_key_from_pkcs8(a, plain, plain_len, out);
      }
      (void)gsec_wipe(plain, n + 1u);
      a->free_fn(a->ctx, plain);
    } else {
      continue;  /* a certificate, or something else in a combined file */
    }
    break;
  }
  (void)gsec_wipe(buf, len + 1u);
  a->free_fn(a->ctx, buf);
  return result;
}

void gcert_key_free(GCERT_Key * k) {
  const GCERT_Allocator * a;
  if (k == NULL) {
    return;
  }
  a = k->alloc;
  wipe_key(k);
  a->free_fn(a->ctx, k);
}

uint32_t gcert_key_kind(const GCERT_Key * k) {
  return k == NULL ? 0u : k->kind;
}

GCERT_Result gcert_key_matches(const GCERT_Key * k, const GCERT_X509 * cert) {
  if (k == NULL || cert == NULL) {
    return GCERT_ERR_INVALID;
  }
  if (k->kind != cert->key) {
    return GCERT_ERR_MISMATCH;
  }
  if (k->kind == GCERT_X509_RSA) {
    size_t cn = cert->n_len;
    size_t ce = cert->e_len;
    const unsigned char * n = strip(cert->n, &cn);
    const unsigned char * e = strip(cert->e, &ce);
    return gcert_der_eq(n, cn, k->n, k->n_len) && gcert_der_eq(e, ce, k->e, k->e_len)
        ? GCERT_OK : GCERT_ERR_MISMATCH;
  }
  return gcert_der_eq(cert->point, cert->point_len, k->pub, k->pub_len)
      ? GCERT_OK : GCERT_ERR_MISMATCH;
}

/* ---- ECDSA-Sig-Value --------------------------------------------------- */

/* One INTEGER from a big-endian magnitude of @p n bytes. */
static size_t put_integer(unsigned char * out, const unsigned char * v, size_t n) {
  size_t i = 0;
  size_t o = 0;
  while (i + 1u < n && v[i] == 0) {
    i++;
  }
  out[o++] = 0x02;
  out[o++] = (unsigned char)(n - i + ((v[i] & 0x80u) != 0 ? 1u : 0u));
  if ((v[i] & 0x80u) != 0) {
    out[o++] = 0;
  }
  memcpy(out + o, v + i, n - i);
  return o + (n - i);
}

static size_t der_ecdsa(unsigned char * out, const unsigned char raw[96], size_t width) {
  unsigned char body[110];
  size_t n = put_integer(body, raw, width);
  n += put_integer(body + n, raw + width, width);
  out[0] = 0x30;
  out[1] = (unsigned char)n;
  memcpy(out + 2, body, n);
  return n + 2u;
}

/* ---- signing ----------------------------------------------------------- */

GCERT_Result gcert_key_sign(const GCERT_Key * k, GCERT_SigScheme scheme, const void * msg,
    size_t msg_len, void * out, size_t cap, size_t * out_len) {
  const SchemeInfo * s = scheme_info(scheme);
  unsigned char raw[96];
  GCERT_Result result;
  size_t n;

  if (out_len == NULL) {
    return GCERT_ERR_INVALID;
  }
  *out_len = 0;
  if (k == NULL || (msg == NULL && msg_len != 0) || (out == NULL && cap != 0)) {
    return GCERT_ERR_INVALID;
  }
  if (s == NULL || s->kind != k->kind) {
    return GCERT_ERR_UNSUPPORTED;
  }
  switch (k->kind) {
    case GCERT_X509_ED25519:
      if (cap < 64u) {
        return GCERT_ERR_LIMIT;
      }
      result = gcert_from_gsec(gsec_ed25519_sign(k->scalar, msg, msg_len, out));
      if (result == GCERT_OK) {
        *out_len = 64;
      }
      break;
    case GCERT_X509_P256:
    case GCERT_X509_P384: {
      size_t width = k->kind == GCERT_X509_P256 ? 32u : 48u;
      unsigned char der[110];
      result = k->kind == GCERT_X509_P256
          ? gcert_from_gsec(gsec_ecdsa_p256_sign(k->scalar, msg, msg_len, raw))
          : gcert_from_gsec(gsec_ecdsa_p384_sign(k->scalar, msg, msg_len, raw));
      if (result != GCERT_OK) {
        break;
      }
      n = der_ecdsa(der, raw, width);
      if (n > cap) {
        result = GCERT_ERR_LIMIT;
        break;
      }
      memcpy(out, der, n);
      *out_len = n;
      break;
    }
    case GCERT_X509_RSA: {
      size_t sl = k->n_len;
      unsigned char salt[64];
      if (sl > cap) {
        return GCERT_ERR_LIMIT;
      }
      if (s->pss) {
        result = gcert_from_gsec(gsec_random_bytes(salt, s->digest, NULL));
        if (result == GCERT_OK) {
          result = gcert_from_gsec(gsec_rsa_private_pss_sign(s->hash, s->hash, k->n, k->n_len,
              k->e, k->e_len, k->d, k->d_len, msg, msg_len, out, sl, salt, s->digest));
        }
        (void)gsec_wipe(salt, sizeof salt);
      } else {
        result = gcert_from_gsec(gsec_rsa_private_pkcs1_v15_sign(s->hash, k->n, k->n_len, k->e,
            k->e_len, k->d, k->d_len, msg, msg_len, out, sl));
      }
      if (result == GCERT_OK) {
        *out_len = sl;
      }
      break;
    }
    default:
      result = GCERT_ERR_INTERNAL;
      break;
  }
  (void)gsec_wipe(raw, sizeof raw);
  if (result != GCERT_OK && out != NULL) {
    (void)gsec_wipe(out, cap);
  }
  return result;
}

/* ---- verifying --------------------------------------------------------- */

GCERT_Result gcert_x509_verify_signature(const GCERT_X509 * cert, GCERT_SigScheme scheme,
    const void * msg, size_t msg_len, const void * sig, size_t sig_len) {
  const SchemeInfo * s = scheme_info(scheme);

  if (cert == NULL || (msg == NULL && msg_len != 0) || sig == NULL || sig_len == 0) {
    return GCERT_ERR_INVALID;
  }
  if (s == NULL || s->kind != cert->key) {
    return GCERT_ERR_UNSUPPORTED;
  }
  switch (cert->key) {
    case GCERT_X509_ED25519:
      if (sig_len != 64u) {
        return GCERT_ERR_MISMATCH;
      }
      return gcert_from_gsec(gsec_ed25519_verify(cert->point, msg, msg_len, sig));
    case GCERT_X509_P256:
    case GCERT_X509_P384: {
      const unsigned char * raw;
      size_t raw_len;
      unsigned char buf[96];
      GCERT_Result result = x509_sig_bits(cert->key, sig, sig_len, &raw, &raw_len, buf);
      if (result != GCERT_OK) {
        /* A signature that is not a well-formed ECDSA-Sig-Value is a signature
         * that does not verify, whatever the reason for the malformation. */
        return GCERT_ERR_MISMATCH;
      }
      return cert->key == GCERT_X509_P256
          ? gcert_from_gsec(gsec_ecdsa_p256_verify(cert->point, msg, msg_len, raw))
          : gcert_from_gsec(gsec_ecdsa_p384_verify(cert->point, msg, msg_len, raw));
    }
    case GCERT_X509_RSA:
      if (s->pss) {
        return gcert_from_gsec(gsec_rsa_pss_verify(s->hash, s->hash, cert->n, cert->n_len,
            cert->e, cert->e_len, msg, msg_len, sig, sig_len, s->digest));
      }
      return gcert_from_gsec(gsec_rsa_pkcs1_v15_verify(s->hash, cert->n, cert->n_len, cert->e,
          cert->e_len, msg, msg_len, sig, sig_len));
    default:
      return GCERT_ERR_UNSUPPORTED;
  }
}
