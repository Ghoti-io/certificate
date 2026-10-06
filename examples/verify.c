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
 * Check a server's certificate chain the way a client would.
 *
 * `verify <chain.pem> <host> [anchors.pem] [unix-time]`. The first
 * certificate in `chain.pem` is the server's, the rest are what it sent. The
 * anchors are the operating system's roots unless a file is named. Prints
 * `ok` and exits 0 when the chain leads to an anchor and the certificate is
 * for `host`, and otherwise says which of the two failed and exits 1. Revocation is not
 * checked: that needs evidence somebody fetched, and this program does not.
 */

#include <ghoti.io/certificate/macros.h>

#include <ghoti.io/certificate/certificate.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_CERTS 16

static unsigned char file[1 << 20];
static unsigned char der[MAX_CERTS][GCERT_X509_DER_MAX];

int main(int argc, char ** argv) {
  GCERT_TrustStore * store = NULL;
  const void * pool[MAX_CERTS];
  size_t lens[MAX_CERTS];
  size_t count = 0;
  size_t n = 0;
  size_t pos = 0;
  FILE * in;
  GCERT_Chain chain;
  GCERT_X509 leaf;
  GCERT_Result r;
  int64_t now;

  if (argc < 3 || argc > 5) {
    fprintf(stderr, "usage: verify <chain.pem> <host> [anchors.pem] [unix-time]\n");
    return 2;
  }
  in = fopen(argv[1], "rb");
  if (in == NULL) {
    fprintf(stderr, "verify: cannot open %s\n", argv[1]);
    return 2;
  }
  n = fread(file, 1, sizeof file, in);
  fclose(in);
  for (;;) {
    char label[65] = {0};
    size_t len = 0;
    r = gcert_pem_next(file, n, &pos, der[count], GCERT_X509_DER_MAX, &len, label,
        sizeof label - 1);
    if (r == GCERT_ERR_FORMAT) {
      break;
    }
    if (r == GCERT_OK && strcmp(label, "CERTIFICATE") == 0 && count < MAX_CERTS) {
      pool[count] = der[count];
      lens[count] = len;
      count++;
    }
  }
  if (count == 0) {
    fprintf(stderr, "verify: no certificate in %s\n", argv[1]);
    return 2;
  }
  now = argc == 5 ? atoll(argv[4]) : (int64_t)time(NULL);
  if (gcert_trust_new(NULL, NULL, &store) != GCERT_OK) {
    return 2;
  }
  if (argc >= 4) {
    r = gcert_trust_add_file(store, argv[3], NULL, NULL);
  } else {
    r = gcert_trust_add_system(store, NULL, NULL);
  }
  if (r != GCERT_OK) {
    fprintf(stderr, "verify: no trust anchors: %s\n", gcert_result_string(r));
    gcert_trust_free(store);
    return 2;
  }
  r = gcert_chain_build(store, pool[0], lens[0], pool + 1, lens + 1, count - 1u, now,
      GCERT_X509_EKU_SERVER_AUTH, NULL, &chain);
  gcert_trust_free(store);
  if (r != GCERT_OK) {
    printf("chain: %s\n", r == GCERT_ERR_MISMATCH ? "no path to a trust anchor" :
        gcert_result_string(r));
    return 1;
  }
  if (gcert_x509_parse(pool[0], lens[0], &leaf) != GCERT_OK ||
      gcert_x509_verify_host(&leaf, argv[2], strlen(argv[2]), NULL) != GCERT_OK) {
    printf("name: the certificate is not for %s\n", argv[2]);
    return 1;
  }
  printf("ok\n");
  return 0;
}
