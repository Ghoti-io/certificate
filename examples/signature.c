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
 * Sign with a private key, or check a signature against a certificate.
 *
 * `signature sign <key.pem> <scheme> <message> <out>` writes the signature.
 * `signature verify <cert.der> <scheme> <message> <signature>` prints `valid`
 * and exits 0, or `invalid` and exits 1. The scheme is one of rsa-pkcs1-sha256,
 * rsa-pkcs1-sha384, rsa-pkcs1-sha512, rsa-pss-sha256, rsa-pss-sha384,
 * rsa-pss-sha512, ecdsa-p256-sha256, ecdsa-p384-sha384 or ed25519. `make
 * check-oracle` has OpenSSL verify what this signs and sign what this checks.
 */

#include <ghoti.io/certificate/macros.h>

#include <ghoti.io/certificate/certificate.h>

#include <stdio.h>
#include <string.h>

static const struct {
  const char * name;
  GCERT_SigScheme scheme;
} SCHEMES[] = {
  {"rsa-pkcs1-sha256", GCERT_SIG_RSA_PKCS1_SHA256},
  {"rsa-pkcs1-sha384", GCERT_SIG_RSA_PKCS1_SHA384},
  {"rsa-pkcs1-sha512", GCERT_SIG_RSA_PKCS1_SHA512},
  {"rsa-pss-sha256", GCERT_SIG_RSA_PSS_SHA256},
  {"rsa-pss-sha384", GCERT_SIG_RSA_PSS_SHA384},
  {"rsa-pss-sha512", GCERT_SIG_RSA_PSS_SHA512},
  {"ecdsa-p256-sha256", GCERT_SIG_ECDSA_P256_SHA256},
  {"ecdsa-p384-sha384", GCERT_SIG_ECDSA_P384_SHA384},
  {"ed25519", GCERT_SIG_ED25519},
};

static unsigned char file_a[GCERT_X509_DER_MAX];
static unsigned char file_m[1 << 16];
static unsigned char file_s[GCERT_SIG_MAX + 16];

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

int main(int argc, char ** argv) {
  size_t a_len = 0;
  size_t m_len = 0;
  size_t s_len = 0;
  GCERT_SigScheme scheme = 0;
  size_t i;
  int found = 0;

  if (argc != 6) {
    /* check-secret: allow printf -- what the example found in a public input (a name, a count, a verdict), never a private key */
    fprintf(stderr, "usage: signature sign|verify <key.pem|cert.der> <scheme> <message> <out|signature>\n");
    return 2;
  }
  for (i = 0; i < sizeof SCHEMES / sizeof SCHEMES[0]; i++) {
    /* check-secret: allow strcmp -- command-line words, never a secret */
    if (strcmp(SCHEMES[i].name, argv[3]) == 0) {
      scheme = SCHEMES[i].scheme;
      found = 1;
    }
  }
  if (!found || !read_file(argv[2], file_a, sizeof file_a, &a_len) ||
      !read_file(argv[4], file_m, sizeof file_m, &m_len)) {
    /* check-secret: allow printf -- what the example found in a public input (a name, a count, a verdict), never a private key */
    fprintf(stderr, "signature: bad arguments or unreadable files\n");
    return 2;
  }
  /* check-secret: allow strcmp -- command-line words, never a secret */
  if (strcmp(argv[1], "sign") == 0) {
    GCERT_Key * key = NULL;
    GCERT_Result r = gcert_key_from_pem(NULL, file_a, a_len, NULL, 0, NULL, &key);
    FILE * out;
    if (r != GCERT_OK) {
      /* check-secret: allow printf -- what the example found in a public input (a name, a count, a verdict), never a private key */
      fprintf(stderr, "signature: %s\n", gcert_result_string(r));
      return 2;
    }
    r = gcert_key_sign(key, scheme, file_m, m_len, file_s, GCERT_SIG_MAX, &s_len);
    gcert_key_free(key);
    if (r != GCERT_OK) {
      /* check-secret: allow printf -- what the example found in a public input (a name, a count, a verdict), never a private key */
      fprintf(stderr, "signature: %s\n", gcert_result_string(r));
      return 2;
    }
    out = fopen(argv[5], "wb");
    /* check-secret: allow write -- writes the converted public certificate or signature, the example's output */
    if (out == NULL || fwrite(file_s, 1, s_len, out) != s_len) {
      return 2;
    }
    fclose(out);
    return 0;
  }
  /* check-secret: allow strcmp -- command-line words, never a secret */
  if (strcmp(argv[1], "verify") == 0) {
    GCERT_X509 cert;
    GCERT_Result r;
    if (!read_file(argv[5], file_s, sizeof file_s, &s_len) ||
        gcert_x509_parse(file_a, a_len, &cert) != GCERT_OK) {
      /* check-secret: allow printf -- what the example found in a public input (a name, a count, a verdict), never a private key */
      fprintf(stderr, "signature: cannot read the certificate or signature\n");
      return 2;
    }
    r = gcert_x509_verify_signature(&cert, scheme, file_m, m_len, file_s, s_len);
    if (r == GCERT_OK) {
      /* check-secret: allow printf -- what the example found in a public input (a name, a count, a verdict), never a private key */
      printf("valid\n");
      return 0;
    }
    /* check-secret: allow printf -- what the example found in a public input (a name, a count, a verdict), never a private key */
    printf("invalid\n");
    return 1;
  }
  return 2;
}
