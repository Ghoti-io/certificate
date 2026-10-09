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
 * Open a PKCS#12 archive and print the key kind and the certificates.
 *
 * `pkcs12 <password> <file>` prints the kind, the certificate count, and
 * then one lowercase-hex certificate per line. The private key is not
 * printed. A wrong password exits 1.
 */

#include <ghoti.io/certificate/macros.h>

#include <ghoti.io/certificate/pkcs12.h>
#include <ghoti.io/certificate/pkcs8.h>
#include <ghoti.io/security/secret.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FILE_MAX 65536u
#define SCRATCH_MAX 65536u

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

static void write_hex(const unsigned char * p, size_t n) {
  static const char hex[] = "0123456789abcdef";
  size_t i;

  for (i = 0; i < n; i++) {
    putchar(hex[p[i] >> 4]);
    putchar(hex[p[i] & 0x0fu]);
  }
  putchar('\n');
}

int main(int argc, char ** argv) {
  unsigned char file[FILE_MAX];
  unsigned char scratch[SCRATCH_MAX];
  size_t n = 0;
  size_t i;
  GCERT_Pkcs12 bag;
  GCERT_Pkcs8 key;
  const char * name;

  if (argc != 3) {
    /* check-secret: allow printf -- what the example found in a public input (a name, a count, a verdict), never a private key */
    fprintf(stderr, "usage: pkcs12 <password> <file>\n");
    return 2;
  }
  if (!read_file(argv[2], file, sizeof file, &n)) {
    return 2;
  }
  if (gcert_pkcs12_open(file, n, argv[1], strlen(argv[1]), scratch,
      sizeof scratch, &bag, NULL) != GCERT_OK) {
    gsec_wipe(file, sizeof file);
    gsec_wipe(scratch, sizeof scratch);
    return 1;
  }
  if (bag.key == NULL || gcert_pkcs8_parse(bag.key, bag.key_len, &key) != GCERT_OK) {
    gsec_wipe(file, sizeof file);
    gsec_wipe(scratch, sizeof scratch);
    return 1;
  }
  if (key.kind == GCERT_PKCS8_RSA) {
    name = "rsa";
  } else if (key.kind == GCERT_PKCS8_P256) {
    name = "p256";
  } else if (key.kind == GCERT_PKCS8_P384) {
    name = "p384";
  } else if (key.kind == GCERT_PKCS8_ED25519) {
    name = "ed25519";
  } else {
    gsec_wipe(file, sizeof file);
    gsec_wipe(scratch, sizeof scratch);
    return 1;
  }
  /* check-secret: allow printf -- what the example found in a public input (a name, a count, a verdict), never a private key */
  printf("%s %zu\n", name, bag.cert_count);
  for (i = 0; i < bag.cert_count; i++) {
    write_hex(bag.certs[i], bag.cert_lens[i]);
  }
  gsec_wipe(file, sizeof file);
  gsec_wipe(scratch, sizeof scratch);
  return 0;
}
