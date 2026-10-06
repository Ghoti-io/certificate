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
 * Read a basic OCSP response.
 *
 * `ocsp <response.der> <issuer.der> <hexserial>` prints `good`,
 * `revoked` and the revocation instant, or `unknown`, when the issuer
 * signed the response. The issuer name and key hashes are SHA-1, which
 * is what a response from that era carries. The issuer key has to be
 * P-256 or P-384. Anything else exits 1.
 */

#include <ghoti.io/certificate/macros.h>

#include <ghoti.io/security/hmac.h>
#include <ghoti.io/certificate/ocsp.h>
#include <ghoti.io/security/sha1.h>
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
  unsigned char response[GCERT_X509_DER_MAX];
  unsigned char issuer[GCERT_X509_DER_MAX];
  unsigned char serial[32];
  unsigned char point[1u + 96u];
  unsigned char name_hash[GSEC_SHA1_DIGEST_LEN];
  unsigned char key_hash[GSEC_SHA1_DIGEST_LEN];
  size_t response_len = 0;
  size_t issuer_len = 0;
  size_t serial_len = 0;
  GCERT_Ocsp_Single single;
  uint32_t status = 99;
  int64_t when = 0;
  GCERT_Ocsp ocsp;
  GCERT_X509 ca;

  if (argc != 4) {
    fprintf(stderr, "usage: ocsp <response.der> <issuer.der> <hexserial>\n");
    return 2;
  }
  if (!read_file(argv[1], response, sizeof response, &response_len) ||
      !read_file(argv[2], issuer, sizeof issuer, &issuer_len) ||
      !parse_hex(argv[3], serial, sizeof serial, &serial_len)) {
    return 2;
  }
  if (gcert_ocsp_parse(response, response_len, &ocsp) != GCERT_OK ||
      gcert_x509_parse(issuer, issuer_len, &ca) != GCERT_OK ||
      gcert_ocsp_signed_by(&ocsp, &ca) != GCERT_OK) {
    return 1;
  }
  if ((ca.key != GCERT_X509_P256 && ca.key != GCERT_X509_P384) ||
      ca.point_len > 96u) {
    return 1;
  }
  point[0] = 0x04;
  memcpy(point + 1, ca.point, ca.point_len);
  if (gsec_sha1(ca.subject, ca.subject_len, name_hash) != GSEC_OK ||
      gsec_sha1(point, 1u + ca.point_len, key_hash) != GSEC_OK ||
      gcert_ocsp_status(&ocsp, GSEC_HMAC_SHA1, name_hash, sizeof name_hash,
          key_hash, sizeof key_hash, serial, serial_len, &single)
          != GCERT_OK) {
    return 1;
  }
  status = single.status;
  when = single.revoked_at;
  /* What a caller does with these is compare them against its own clock: a
   * response whose age is invisible is one that can be replayed. On stderr
   * rather than stdout, because make check-oracle reads this program's stdout
   * and compares it with OpenSSL's answer. */
  fprintf(stderr, "produced %lld this %lld", (long long)ocsp.produced_at,
      (long long)single.this_update);
  if (single.have_next_update) {
    fprintf(stderr, " next %lld", (long long)single.next_update);
  }
  fprintf(stderr, "\n");
  if (status == GCERT_OCSP_GOOD) {
    printf("good\n");
  } else if (status == GCERT_OCSP_REVOKED) {
    printf("revoked %lld\n", (long long)when);
  } else if (status == GCERT_OCSP_UNKNOWN) {
    printf("unknown\n");
  } else {
    return 1;
  }
  return 0;
}
