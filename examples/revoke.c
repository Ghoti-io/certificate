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
 * Check a certificate against a CRL or an OCSP response.
 *
 * `revoke crl <list.der> <issuer.der> <cert.der> <now>` or `revoke ocsp
 * <response.der> <issuer.der> <cert.der> <now> [responder.der]`. Prints
 * `good`, `revoked` or `unusable <reason>` and exits 0, 1 or 2. `make
 * check-oracle` compares it with `openssl ocsp` and `openssl verify
 * -crl_check`.
 */

#include <ghoti.io/certificate/macros.h>

#include <ghoti.io/certificate/certificate.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned char buf[4][GCERT_X509_DER_MAX];

static int read_file(const char * path, unsigned char * b, size_t * n) {
  FILE * in = fopen(path, "rb");
  if (in == NULL) {
    return 0;
  }
  *n = fread(b, 1, GCERT_X509_DER_MAX, in);
  if (!feof(in)) {
    fclose(in);
    return 0;
  }
  fclose(in);
  return 1;
}

static const char * why(GCERT_RevocationReason r) {
  switch (r) {
    case GCERT_REVOCATION_NONE:
      return "none";
    case GCERT_REVOCATION_WRONG_ISSUER:
      return "wrong-issuer";
    case GCERT_REVOCATION_CANNOT_SIGN:
      return "cannot-sign";
    case GCERT_REVOCATION_BAD_SIGNATURE:
      return "bad-signature";
    case GCERT_REVOCATION_NOT_YET_VALID:
      return "not-yet-valid";
    case GCERT_REVOCATION_STALE:
      return "stale";
    case GCERT_REVOCATION_UNKNOWN_CERT:
      return "unknown-cert";
    case GCERT_REVOCATION_RESPONDER:
      return "responder";
    case GCERT_REVOCATION_MALFORMED:
      return "malformed";
  }
  return "?";
}

int main(int argc, char ** argv) {
  size_t n[4] = {0, 0, 0, 0};
  GCERT_X509 issuer;
  GCERT_X509 cert;
  GCERT_X509 responder;
  GCERT_Revocation out;
  GCERT_Result r;
  int64_t now;
  int is_crl;

  /* check-secret: allow strcmp -- command-line words, never a secret */
  if (argc < 6 || argc > 7 || (strcmp(argv[1], "crl") != 0 && strcmp(argv[1], "ocsp") != 0)) {
    /* check-secret: allow printf -- what the example found in a public input (a name, a count, a verdict), never a private key */
    fprintf(stderr, "usage: revoke crl|ocsp <evidence.der> <issuer.der> <cert.der> <now> [responder.der]\n");
    return 3;
  }
  /* check-secret: allow strcmp -- command-line words, never a secret */
  is_crl = strcmp(argv[1], "crl") == 0;
  now = atoll(argv[5]);
  if (!read_file(argv[2], buf[0], &n[0]) || !read_file(argv[3], buf[1], &n[1]) ||
      !read_file(argv[4], buf[2], &n[2]) ||
      gcert_x509_parse(buf[1], n[1], &issuer) != GCERT_OK ||
      gcert_x509_parse(buf[2], n[2], &cert) != GCERT_OK) {
    /* check-secret: allow printf -- what the example found in a public input (a name, a count, a verdict), never a private key */
    fprintf(stderr, "revoke: cannot read the inputs\n");
    return 3;
  }
  if (is_crl) {
    GCERT_Crl crl;
    if (gcert_crl_parse(buf[0], n[0], &crl) != GCERT_OK) {
      /* check-secret: allow printf -- what the example found in a public input (a name, a count, a verdict), never a private key */
      printf("unusable malformed\n");
      return 2;
    }
    r = gcert_crl_check(&crl, &issuer, &cert, now, NULL, &out);
  } else {
    GCERT_Ocsp ocsp;
    int have_responder = argc == 7;
    if (have_responder && (!read_file(argv[6], buf[3], &n[3]) ||
        gcert_x509_parse(buf[3], n[3], &responder) != GCERT_OK)) {
      /* check-secret: allow printf -- what the example found in a public input (a name, a count, a verdict), never a private key */
      fprintf(stderr, "revoke: cannot read the responder\n");
      return 3;
    }
    if (gcert_ocsp_parse(buf[0], n[0], &ocsp) != GCERT_OK) {
      /* check-secret: allow printf -- what the example found in a public input (a name, a count, a verdict), never a private key */
      printf("unusable malformed\n");
      return 2;
    }
    r = gcert_ocsp_check(&ocsp, &issuer, have_responder ? &responder : NULL, &cert, now, NULL,
        &out);
  }
  if (r != GCERT_OK) {
    /* check-secret: allow printf -- what the example found in a public input (a name, a count, a verdict), never a private key */
    fprintf(stderr, "revoke: %s\n", gcert_result_string(r));
    return 3;
  }
  if (out.status == GCERT_REVOCATION_GOOD) {
    /* check-secret: allow printf -- what the example found in a public input (a name, a count, a verdict), never a private key */
    printf("good\n");
    return 0;
  }
  if (out.status == GCERT_REVOCATION_REVOKED) {
    /* check-secret: allow printf -- what the example found in a public input (a name, a count, a verdict), never a private key */
    printf("revoked\n");
    return 1;
  }
  /* check-secret: allow printf -- what the example found in a public input (a name, a count, a verdict), never a private key */
  printf("unusable %s\n", why(out.reason));
  return 2;
}
