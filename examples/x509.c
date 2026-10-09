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
 * Read one certificate and print its key kind and validity.
 *
 * `x509 <file.der>` prints the kind and the inclusive Unix seconds of
 * notBefore and notAfter. A certificate this parser rejects exits 1.
 */

#include <ghoti.io/certificate/macros.h>

#include <ghoti.io/certificate/x509.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char ** argv) {
  FILE * in;
  unsigned char buf[GCERT_X509_DER_MAX];
  size_t n;
  GCERT_X509 cert;
  const char * name;

  if (argc != 2) {
    /* check-secret: allow printf -- what the example found in a public input (a name, a count, a verdict), never a private key */
    fprintf(stderr, "usage: x509 <file.der>\n");
    return 2;
  }
  in = fopen(argv[1], "rb");
  if (in == NULL) {
    return 2;
  }
  n = fread(buf, 1, sizeof buf, in);
  if (!feof(in)) {
    fclose(in);
    return 1;
  }
  fclose(in);
  if (gcert_x509_parse(buf, n, &cert) != GCERT_OK) {
    return 1;
  }
  if (cert.key == GCERT_X509_RSA) {
    name = "rsa";
  } else if (cert.key == GCERT_X509_P256) {
    name = "p256";
  } else if (cert.key == GCERT_X509_P384) {
    name = "p384";
  } else if (cert.key == GCERT_X509_ED25519) {
    name = "ed25519";
  } else {
    return 1;
  }
  /* check-secret: allow printf -- what the example found in a public input (a name, a count, a verdict), never a private key */
  printf("%s %lld %lld\n", name, (long long)cert.not_before,
      (long long)cert.not_after);
  return 0;
}
