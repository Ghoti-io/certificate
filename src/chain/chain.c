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
 * Path building. The search is in this file; the verdict is
 * gcert_x509_path's, which is called on every candidate that reaches an
 * anchor.
 */

#include <ghoti.io/certificate/macros.h>

#include <ghoti.io/certificate/chain.h>

#include "../der/der_int.h"
#include "../trust/trust_int.h"

#include <string.h>

typedef struct Node {
  GCERT_X509 x;  /* points into the caller's bytes, and into itself (ECDSA) */
  const unsigned char * der;
  size_t len;
  int ok;        /* parsed */
} Node;

typedef struct Search {
  const GCERT_TrustStore * store;
  Node * pool;
  size_t n;
  const GCERT_X509 * leaf;
  const unsigned char * leaf_der;
  size_t leaf_len;
  int64_t t;
  unsigned purpose;
  uint32_t budget;
  uint32_t used;
  size_t path[GCERT_X509_CHAIN_MAX];
  GCERT_ChainFailure best;
  GCERT_Result hard;   /* GCERT_OK, or the error that stopped the search */
  GCERT_Chain * out;
} Search;

/* Priorities: a path that reached an anchor and was refused says the most. */
static int weight(GCERT_ChainFailure f) {
  switch (f) {
    case GCERT_CHAIN_UNKNOWN_ISSUER:
      return 1;
    case GCERT_CHAIN_BAD_SIGNATURE:
      return 2;
    case GCERT_CHAIN_EXPIRED:
    case GCERT_CHAIN_NOT_YET_VALID:
      return 3;
    case GCERT_CHAIN_REJECTED:
      return 4;
    case GCERT_CHAIN_NONE:
      break;
  }
  return 0;
}

static void note(Search * s, GCERT_ChainFailure f) {
  if (weight(f) > weight(s->best)) {
    s->best = f;
  }
}

/* GCERT_CHAIN_NONE when @p x is in force at @p t. */
static GCERT_ChainFailure window(const GCERT_X509 * x, int64_t t) {
  if (t < x->not_before) {
    return GCERT_CHAIN_NOT_YET_VALID;
  }
  if (t > x->not_after) {
    return GCERT_CHAIN_EXPIRED;
  }
  return GCERT_CHAIN_NONE;
}

static int spend(Search * s) {
  if (s->used >= s->budget) {
    s->hard = GCERT_ERR_LIMIT;
    return 0;
  }
  s->used++;
  return 1;
}

static int rank_of(const GCERT_X509 * child, const GCERT_X509 * issuer) {
  if (child->aki == NULL || issuer->ski == NULL) {
    return 1;
  }
  return gcert_der_eq(child->aki, child->aki_len, issuer->ski, issuer->ski_len) ? 0 : 2;
}

static int in_path(const Search * s, size_t depth, size_t index) {
  size_t i;
  for (i = 0; i < depth; i++) {
    if (s->path[i] == index) {
      return 1;
    }
  }
  return 0;
}

/* The path is complete up to an anchor: ask gcert_x509_path, and on a
 * refusal say why as well as the times let us. */
static int try_anchor(Search * s, size_t depth, size_t anchor_index) {
  const Anchor * a = s->store->v[anchor_index];
  const void * mids[GCERT_X509_CHAIN_MAX];
  size_t lens[GCERT_X509_CHAIN_MAX];
  size_t i;
  GCERT_Result result;

  /* path[] was filled from the leaf upward; gcert_x509_path wants the
   * anchor's side first. */
  for (i = 0; i < depth; i++) {
    mids[i] = s->pool[s->path[depth - 1u - i]].der;
    lens[i] = s->pool[s->path[depth - 1u - i]].len;
  }
  if (!spend(s)) {
    return 0;
  }
  result = gcert_x509_path(s->leaf_der, s->leaf_len, mids, lens, depth, a->der, a->len,
      s->t, s->purpose);
  if (result == GCERT_OK) {
    if (s->out != NULL) {
      memset(s->out, 0, sizeof *s->out);
      for (i = 0; i < depth; i++) {
        s->out->mid[i] = s->path[depth - 1u - i];
      }
      s->out->mid_count = depth;
      s->out->anchor = anchor_index;
      s->out->failure = GCERT_CHAIN_NONE;
    }
    return 1;
  }
  if (result == GCERT_ERR_OOM || result == GCERT_ERR_INTERNAL ||
      result == GCERT_ERR_INVALID) {
    s->hard = result;
    return 0;
  }
  {
    GCERT_ChainFailure f = GCERT_CHAIN_REJECTED;
    GCERT_ChainFailure w = window(&a->x, s->t);
    if (w == GCERT_CHAIN_NONE) {
      w = window(s->leaf, s->t);
    }
    for (i = 0; w == GCERT_CHAIN_NONE && i < depth; i++) {
      w = window(&s->pool[s->path[i]].x, s->t);
    }
    if (w != GCERT_CHAIN_NONE) {
      f = w;
    }
    note(s, f);
  }
  return 0;
}

static int search(Search * s, const GCERT_X509 * cur, size_t depth) {
  size_t cand[64];
  size_t count = 0;
  size_t i;
  int rank;
  int considered = 0;

  /* Anchors first: a path that ends sooner has fewer links to be wrong. */
  if (gcert_trust_find_issuers(s->store, cur, cand, sizeof cand / sizeof cand[0],
      &count) != GCERT_OK) {
    s->hard = GCERT_ERR_INTERNAL;
    return 0;
  }
  if (count > sizeof cand / sizeof cand[0]) {
    count = sizeof cand / sizeof cand[0];
  }
  for (i = 0; i < count; i++) {
    const GCERT_X509 * a = &s->store->v[cand[i]]->x;
    GCERT_ChainFailure w = window(a, s->t);
    considered = 1;
    if (w != GCERT_CHAIN_NONE) {
      note(s, w);
      continue;
    }
    if (!spend(s)) {
      return 0;
    }
    if (gcert_x509_signed_by(cur, a) != GCERT_OK) {
      note(s, GCERT_CHAIN_BAD_SIGNATURE);
      continue;
    }
    if (try_anchor(s, depth, cand[i])) {
      return 1;
    }
    if (s->hard != GCERT_OK) {
      return 0;
    }
  }
  if (depth >= GCERT_X509_CHAIN_MAX) {
    return 0;
  }
  for (rank = 0; rank < 3; rank++) {
    for (i = 0; i < s->n; i++) {
      Node * c = &s->pool[i];
      GCERT_ChainFailure w;
      if (!c->ok || in_path(s, depth, i) || &c->x == cur ||
          !gcert_der_eq(c->x.subject, c->x.subject_len, cur->issuer, cur->issuer_len) ||
          rank_of(cur, &c->x) != rank) {
        continue;
      }
      considered = 1;
      w = window(&c->x, s->t);
      if (w != GCERT_CHAIN_NONE) {
        note(s, w);
        continue;
      }
      if (!spend(s)) {
        return 0;
      }
      if (gcert_x509_signed_by(cur, &c->x) != GCERT_OK) {
        note(s, GCERT_CHAIN_BAD_SIGNATURE);
        continue;
      }
      s->path[depth] = i;
      if (search(s, &c->x, depth + 1u)) {
        return 1;
      }
      if (s->hard != GCERT_OK) {
        return 0;
      }
    }
  }
  if (!considered) {
    note(s, GCERT_CHAIN_UNKNOWN_ISSUER);
  }
  return 0;
}

GCERT_Result gcert_chain_build(const GCERT_TrustStore * store, const void * leaf,
    size_t leaf_len, const void * const * pool, const size_t * pool_lens,
    size_t pool_count, int64_t unix_time, unsigned purpose,
    const GCERT_Limits * limits, GCERT_Chain * out) {
  Search s;
  GCERT_X509 leaf_x;
  GCERT_Limits lim;
  size_t i;
  GCERT_Result result;
  int found;

  if (out != NULL) {
    memset(out, 0, sizeof *out);
    out->failure = GCERT_CHAIN_UNKNOWN_ISSUER;
  }
  if (store == NULL || leaf == NULL || leaf_len == 0 ||
      (pool_count != 0 && (pool == NULL || pool_lens == NULL))) {
    return GCERT_ERR_INVALID;
  }
  if (limits != NULL) {
    lim = *limits;
  } else {
    gcert_limits_default(&lim);
  }
  if (lim.max_chain_pool == 0 || lim.max_chain_attempts == 0) {
    GCERT_Limits def;
    gcert_limits_default(&def);
    if (lim.max_chain_pool == 0) {
      lim.max_chain_pool = def.max_chain_pool;
    }
    if (lim.max_chain_attempts == 0) {
      lim.max_chain_attempts = def.max_chain_attempts;
    }
  }
  if (pool_count > lim.max_chain_pool) {
    return GCERT_ERR_LIMIT;
  }
  result = gcert_x509_parse(leaf, leaf_len, &leaf_x);
  if (result != GCERT_OK) {
    return result;
  }
  memset(&s, 0, sizeof s);
  s.store = store;
  s.leaf = &leaf_x;
  s.leaf_der = leaf;
  s.leaf_len = leaf_len;
  s.t = unix_time;
  s.purpose = purpose;
  s.budget = lim.max_chain_attempts;
  s.out = out;
  s.best = GCERT_CHAIN_NONE;
  {
    GCERT_ChainFailure w = window(&leaf_x, unix_time);
    if (w != GCERT_CHAIN_NONE) {
      if (out != NULL) {
        out->failure = w;
      }
      return GCERT_ERR_MISMATCH;
    }
  }
  if (pool_count != 0) {
    s.pool = store->alloc->calloc_fn(store->alloc->ctx, pool_count, sizeof *s.pool);
    if (s.pool == NULL) {
      return GCERT_ERR_OOM;
    }
    s.n = pool_count;
    for (i = 0; i < pool_count; i++) {
      s.pool[i].der = pool[i];
      s.pool[i].len = pool_lens[i];
      s.pool[i].ok = pool[i] != NULL && pool_lens[i] != 0 &&
          gcert_x509_parse(pool[i], pool_lens[i], &s.pool[i].x) == GCERT_OK;
    }
  }
  found = search(&s, &leaf_x, 0);
  if (s.pool != NULL) {
    store->alloc->free_fn(store->alloc->ctx, s.pool);
  }
  if (found) {
    return GCERT_OK;
  }
  if (s.hard != GCERT_OK) {
    if (out != NULL) {
      memset(out, 0, sizeof *out);
      out->failure = s.best != GCERT_CHAIN_NONE ? s.best : GCERT_CHAIN_UNKNOWN_ISSUER;
    }
    return s.hard;
  }
  if (out != NULL) {
    out->failure = s.best != GCERT_CHAIN_NONE ? s.best : GCERT_CHAIN_UNKNOWN_ISSUER;
  }
  return GCERT_ERR_MISMATCH;
}
