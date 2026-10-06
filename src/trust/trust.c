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
 * The trust store: copies of anchor certificates, found by subject.
 */

#include <ghoti.io/certificate/macros.h>

#include <ghoti.io/certificate/pem.h>
#include <ghoti.io/certificate/trust.h>

#include "../der/der_int.h"
#include "trust_int.h"

#include <stdio.h>
#include <string.h>

#define MAX_ANCHORS(s) ((s)->limits.max_trust_anchors != 0 ? \
    (s)->limits.max_trust_anchors : GCERT_TRUST_ANCHORS_DEFAULT)

static void * xalloc(const GCERT_TrustStore * s, size_t n) {
  return s->alloc->malloc_fn(s->alloc->ctx, n);
}

static void xfree(const GCERT_TrustStore * s, void * p) {
  s->alloc->free_fn(s->alloc->ctx, p);
}

GCERT_Result gcert_trust_new(const GCERT_Allocator * allocator,
    const GCERT_Limits * limits, GCERT_TrustStore ** out) {
  GCERT_TrustStore * s;
  const GCERT_Allocator * a = allocator != NULL ? allocator : gcert_allocator_default();

  if (out == NULL) {
    return GCERT_ERR_INVALID;
  }
  *out = NULL;
  s = a->calloc_fn(a->ctx, 1, sizeof *s);
  if (s == NULL) {
    return GCERT_ERR_OOM;
  }
  s->alloc = a;
  if (limits != NULL) {
    s->limits = *limits;
  } else {
    gcert_limits_default(&s->limits);
  }
  *out = s;
  return GCERT_OK;
}

void gcert_trust_free(GCERT_TrustStore * s) {
  size_t i;
  if (s == NULL) {
    return;
  }
  for (i = 0; i < s->n; i++) {
    xfree(s, s->v[i]->der);
    xfree(s, s->v[i]);
  }
  xfree(s, s->v);
  xfree(s, s);
}

size_t gcert_trust_count(const GCERT_TrustStore * s) {
  return s == NULL ? 0u : s->n;
}

static GCERT_Result push(GCERT_TrustStore * s, Anchor * a) {
  if (s->n == s->cap) {
    size_t cap = s->cap == 0 ? 16u : s->cap * 2u;
    Anchor ** v;
    if (cap > SIZE_MAX / sizeof *v) {
      return GCERT_ERR_OOM;
    }
    v = s->alloc->realloc_fn(s->alloc->ctx, s->v, cap * sizeof *v);
    if (v == NULL) {
      return GCERT_ERR_OOM;
    }
    s->v = v;
    s->cap = cap;
  }
  s->v[s->n++] = a;
  return GCERT_OK;
}

GCERT_Result gcert_trust_add_der(GCERT_TrustStore * s, const void * der, size_t len) {
  GCERT_X509 probe;
  GCERT_Result result;
  Anchor * a;
  size_t i;

  if (s == NULL || der == NULL || len == 0) {
    return GCERT_ERR_INVALID;
  }
  result = gcert_x509_parse(der, len, &probe);
  if (result != GCERT_OK) {
    return result;
  }
  for (i = 0; i < s->n; i++) {
    if (gcert_der_eq(s->v[i]->der, s->v[i]->len, der, len)) {
      return GCERT_OK;
    }
  }
  if (s->n >= MAX_ANCHORS(s)) {
    return GCERT_ERR_LIMIT;
  }
  a = s->alloc->calloc_fn(s->alloc->ctx, 1, sizeof *a);
  if (a == NULL) {
    return GCERT_ERR_OOM;
  }
  a->der = xalloc(s, len);
  if (a->der == NULL) {
    xfree(s, a);
    return GCERT_ERR_OOM;
  }
  memcpy(a->der, der, len);
  a->len = len;
  result = gcert_x509_parse(a->der, a->len, &a->x);
  if (result == GCERT_OK) {
    result = push(s, a);
  }
  if (result != GCERT_OK) {
    xfree(s, a->der);
    xfree(s, a);
  }
  return result;
}

static int is_certificate_label(const char * label, size_t n) {
  const unsigned char * l = (const unsigned char *)label;
  return gcert_der_eq(l, n, (const unsigned char *)"CERTIFICATE", 11u) ||
      gcert_der_eq(l, n, (const unsigned char *)"X509 CERTIFICATE", 16u);
}

/* Store one decoded certificate for a bundle load: the counts, not the
 * error, say what was unusable, but running out of room or memory stops. */
static GCERT_Result add_counted(GCERT_TrustStore * s, const void * der, size_t len,
    size_t * added, size_t * skipped) {
  size_t before = s->n;
  GCERT_Result result = gcert_trust_add_der(s, der, len);
  if (result == GCERT_ERR_CORRUPT || result == GCERT_ERR_UNSUPPORTED ||
      (result == GCERT_ERR_LIMIT && len > GCERT_X509_DER_MAX)) {
    (*skipped)++;
    return GCERT_OK;
  }
  if (result == GCERT_OK && s->n > before) {
    (*added)++;
  }
  return result;
}

GCERT_Result gcert_trust_add_pem(GCERT_TrustStore * s, const void * pem, size_t len,
    size_t * added, size_t * skipped) {
  unsigned char * scratch;
  size_t pos = 0;
  size_t n_added = 0;
  size_t n_skipped = 0;
  GCERT_Result result = GCERT_OK;

  if (added != NULL) {
    *added = 0;
  }
  if (skipped != NULL) {
    *skipped = 0;
  }
  if (s == NULL || (pem == NULL && len != 0)) {
    return GCERT_ERR_INVALID;
  }
  scratch = xalloc(s, GCERT_X509_DER_MAX);
  if (scratch == NULL) {
    return GCERT_ERR_OOM;
  }
  for (;;) {
    char label[65];
    size_t label_len;
    size_t der_len = 0;

    memset(label, 0, sizeof label);
    result = gcert_pem_next(pem, len, &pos, scratch, GCERT_X509_DER_MAX, &der_len,
        label, sizeof label - 1u);
    if (result == GCERT_ERR_FORMAT) {
      result = GCERT_OK;
      break;
    }
    if (result != GCERT_OK) {
      /* A block that does not decode, or is too big to be a certificate. Its
       * label is not known, and a damaged block might have been one. */
      n_skipped++;
      result = GCERT_OK;
      continue;
    }
    label_len = strlen(label);  /* the label has no NUL in it, and the buffer was zeroed */
    if (!is_certificate_label(label, label_len)) {
      continue;
    }
    result = add_counted(s, scratch, der_len, &n_added, &n_skipped);
    if (result != GCERT_OK) {
      break;
    }
  }
  xfree(s, scratch);
  if (added != NULL) {
    *added = n_added;
  }
  if (skipped != NULL) {
    *skipped = n_skipped;
  }
  return result;
}

GCERT_Result gcert_trust_add_file(GCERT_TrustStore * s, const char * path,
    size_t * added, size_t * skipped) {
  FILE * in;
  unsigned char * buf = NULL;
  size_t len = 0;
  size_t cap = 0;
  size_t max;
  GCERT_Result result = GCERT_OK;

  if (added != NULL) {
    *added = 0;
  }
  if (skipped != NULL) {
    *skipped = 0;
  }
  if (s == NULL || path == NULL) {
    return GCERT_ERR_INVALID;
  }
  max = s->limits.max_trust_file_bytes != 0 ? s->limits.max_trust_file_bytes
      : 16u * 1024u * 1024u;
  in = fopen(path, "rb");
  if (in == NULL) {
    return GCERT_ERR_IO;
  }
  for (;;) {
    size_t got;
    if (len == cap) {
      size_t ncap = cap == 0 ? 65536u : cap * 2u;
      unsigned char * nb;
      if (ncap > max + 1u) {
        ncap = max + 1u;
      }
      if (ncap == cap) {
        result = GCERT_ERR_LIMIT;  /* the buffer is full at max + 1 bytes: more than max */
        break;
      }
      nb = s->alloc->realloc_fn(s->alloc->ctx, buf, ncap);
      if (nb == NULL) {
        result = GCERT_ERR_OOM;
        break;
      }
      buf = nb;
      cap = ncap;
    }
    got = fread(buf + len, 1, cap - len, in);
    len += got;
    if (got == 0) {
      if (ferror(in)) {
        result = GCERT_ERR_IO;
      }
      break;
    }
  }
  fclose(in);
  if (result == GCERT_OK) {
    if (len != 0 && buf[0] == 0x30) {
      size_t n_added = 0;
      size_t n_skipped = 0;
      result = add_counted(s, buf, len, &n_added, &n_skipped);
      if (added != NULL) {
        *added = n_added;
      }
      if (skipped != NULL) {
        *skipped = n_skipped;
      }
    } else {
      result = gcert_trust_add_pem(s, buf, len, added, skipped);
    }
  }
  xfree(s, buf);
  return result;
}

GCERT_Result gcert_trust_get(const GCERT_TrustStore * s, size_t index,
    const unsigned char ** der, size_t * len) {
  if (s == NULL || der == NULL || len == NULL || index >= s->n) {
    return GCERT_ERR_INVALID;
  }
  *der = s->v[index]->der;
  *len = s->v[index]->len;
  return GCERT_OK;
}

/* 0: key identifiers agree; 1: one side has none; 2: both have one and they
 * differ. */
static int rank_of(const GCERT_X509 * child, const GCERT_X509 * issuer) {
  if (child->aki == NULL || issuer->ski == NULL) {
    return 1;
  }
  return gcert_der_eq(child->aki, child->aki_len, issuer->ski, issuer->ski_len) ? 0 : 2;
}

GCERT_Result gcert_trust_find_issuers(const GCERT_TrustStore * s,
    const GCERT_X509 * cert, size_t * out, size_t cap, size_t * count) {
  size_t i;
  size_t total = 0;
  int rank;

  if (count != NULL) {
    *count = 0;
  }
  if (s == NULL || cert == NULL || count == NULL || (out == NULL && cap != 0) ||
      cert->issuer == NULL) {
    return GCERT_ERR_INVALID;
  }
  for (rank = 0; rank < 3; rank++) {
    for (i = 0; i < s->n; i++) {
      const GCERT_X509 * x = &s->v[i]->x;
      if (!gcert_der_eq(x->subject, x->subject_len, cert->issuer, cert->issuer_len) ||
          rank_of(cert, x) != rank) {
        continue;
      }
      if (total < cap) {
        out[total] = i;
      }
      total++;
    }
  }
  *count = total;
  return GCERT_OK;
}
