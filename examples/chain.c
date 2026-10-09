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
 * Build and validate a path.
 *
 * `chain <unix-time> <purpose> <anchors.pem> <leaf.der> [pool.der ...]`
 * where purpose is 0, server or client. Prints `ok <anchor-index>
 * <intermediates>` and exits 0, or `fail <reason>` and exits 1. `make
 * check-oracle` compares it with `openssl verify`.
 */

#include <ghoti.io/certificate/macros.h>

#include <ghoti.io/certificate/certificate.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned char leaf[GCERT_X509_DER_MAX];
static unsigned char pool_buf[8][GCERT_X509_DER_MAX];

static int read_file(const char * path, unsigned char * buf, size_t cap, size_t * n) {
  FILE * in = fopen(path, "rb");
  if (in == NULL) {
    return 0;
  }
  *n = fread(buf, 1, cap, in);
  if (!feof(in)) {
    fclose(in);
    return 0;
  }
  fclose(in);
  return 1;
}

static const char * reason(GCERT_ChainFailure f) {
  switch (f) {
    case GCERT_CHAIN_NONE:
      return "none";
    case GCERT_CHAIN_UNKNOWN_ISSUER:
      return "unknown-issuer";
    case GCERT_CHAIN_BAD_SIGNATURE:
      return "bad-signature";
    case GCERT_CHAIN_EXPIRED:
      return "expired";
    case GCERT_CHAIN_NOT_YET_VALID:
      return "not-yet-valid";
    case GCERT_CHAIN_REJECTED:
      return "rejected";
  }
  return "?";
}

int main(int argc, char ** argv) {
  GCERT_TrustStore * store = NULL;
  const void * pool[8];
  size_t lens[8];
  size_t leaf_len = 0;
  size_t pool_count = 0;
  GCERT_Chain chain;
  GCERT_Result r;
  unsigned purpose = 0;
  int i;

  if (argc < 5 || argc - 5 > 8) {
    /* check-secret: allow printf -- what the example found in a public input (a name, a count, a verdict), never a private key */
    fprintf(stderr, "usage: chain <unix-time> <0|server|client> <anchors.pem> <leaf.der> [pool.der ...]\n");
    return 2;
  }
  /* check-secret: allow strcmp -- command-line words, never a secret */
  if (strcmp(argv[2], "server") == 0) {
    purpose = GCERT_X509_EKU_SERVER_AUTH;
  /* check-secret: allow strcmp -- command-line words, never a secret */
  } else if (strcmp(argv[2], "client") == 0) {
    purpose = GCERT_X509_EKU_CLIENT_AUTH;
  }
  if (gcert_trust_new(NULL, NULL, &store) != GCERT_OK ||
      gcert_trust_add_file(store, argv[3], NULL, NULL) != GCERT_OK ||
      !read_file(argv[4], leaf, sizeof leaf, &leaf_len)) {
    /* check-secret: allow printf -- what the example found in a public input (a name, a count, a verdict), never a private key */
    fprintf(stderr, "chain: cannot read the inputs\n");
    return 2;
  }
  for (i = 5; i < argc; i++) {
    if (!read_file(argv[i], pool_buf[pool_count], sizeof pool_buf[0], &lens[pool_count])) {
      /* check-secret: allow printf -- what the example found in a public input (a name, a count, a verdict), never a private key */
      fprintf(stderr, "chain: cannot read %s\n", argv[i]);
      return 2;
    }
    pool[pool_count] = pool_buf[pool_count];
    pool_count++;
  }
  r = gcert_chain_build(store, leaf, leaf_len, pool, lens, pool_count, atoll(argv[1]),
      purpose, NULL, &chain);
  gcert_trust_free(store);
  if (r == GCERT_OK) {
    /* check-secret: allow printf -- what the example found in a public input (a name, a count, a verdict), never a private key */
    printf("ok %zu %zu\n", chain.anchor, chain.mid_count);
    return 0;
  }
  /* check-secret: allow printf -- what the example found in a public input (a name, a count, a verdict), never a private key */
  printf("fail %s\n", r == GCERT_ERR_MISMATCH ? reason(chain.failure) : gcert_result_string(r));
  return 1;
}
