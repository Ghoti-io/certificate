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
 * Read a certificate revocation list.
 *
 * `crl <list.der> <issuer.der> <hexserial>` prints `signed` and the
 * thisUpdate instant when the issuer's key signed the list and the
 * serial is on it. Anything else exits 1.
 */

#include <ghoti.io/certificate/macros.h>

#include <ghoti.io/certificate/crl.h>
#include <ghoti.io/certificate/x509.h>

#include <stdio.h>
#include <string.h>

static int nibble(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  return -1;
}

static int read_file(const char * path, unsigned char * buf, size_t cap,
    size_t * n) {
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

static int parse_hex(const char * text, unsigned char * out, size_t cap,
    size_t * n) {
  size_t len = strlen(text);
  size_t i;

  if ((len % 2u) != 0 || len / 2u == 0 || len / 2u > cap) {
    return 0;
  }
  *n = len / 2u;
  for (i = 0; i < *n; i++) {
    int hi = nibble(text[i * 2u]);
    int lo = nibble(text[i * 2u + 1u]);
    if (hi < 0 || lo < 0) {
      return 0;
    }
    out[i] = (unsigned char)((hi << 4) | lo);
  }
  return 1;
}

int main(int argc, char ** argv) {
  unsigned char list[GCERT_X509_DER_MAX];
  unsigned char issuer[GCERT_X509_DER_MAX];
  unsigned char serial[32];
  size_t list_len = 0;
  size_t issuer_len = 0;
  size_t serial_len = 0;
  GCERT_Crl crl;
  GCERT_X509 ca;

  if (argc != 4) {
    /* check-secret: allow printf -- what the example found in a public input (a name, a count, a verdict), never a private key */
    fprintf(stderr, "usage: crl <list.der> <issuer.der> <hexserial>\n");
    return 2;
  }
  if (!read_file(argv[1], list, sizeof list, &list_len) ||
      !read_file(argv[2], issuer, sizeof issuer, &issuer_len) ||
      !parse_hex(argv[3], serial, sizeof serial, &serial_len)) {
    return 2;
  }
  if (gcert_crl_parse(list, list_len, &crl) != GCERT_OK ||
      gcert_x509_parse(issuer, issuer_len, &ca) != GCERT_OK ||
      gcert_crl_signed_by(&crl, &ca) != GCERT_OK ||
      gcert_crl_contains(&crl, serial, serial_len) != GCERT_OK) {
    return 1;
  }
  /* check-secret: allow printf -- what the example found in a public input (a name, a count, a verdict), never a private key */
  printf("signed %lld\n", (long long)crl.this_update);
  return 0;
}
