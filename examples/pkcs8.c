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
 * Read a PKCS#8 file and print the key kind.
 *
 * `pkcs8 <file>` reads an unencrypted key. `pkcs8 decrypt <password>
 * <file>` opens a PBES2 or PBES1 EncryptedPrivateKeyInfo first. The key
 * bytes are not printed. A password-encrypted file given to the first
 * form exits 1.
 */

#include <ghoti.io/certificate/macros.h>

#include <ghoti.io/certificate/pkcs8.h>
#include <ghoti.io/security/secret.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define KEY_MAX 8192u

int main(int argc, char ** argv) {
  FILE * in;
  unsigned char buf[KEY_MAX];
  size_t n;
  GCERT_Pkcs8 key;
  const char * name;

  if (argc == 4 && strcmp(argv[1], "decrypt") == 0) {
    unsigned char plain[KEY_MAX];
    size_t plain_len = 0;
    GCERT_Result opened;

    in = fopen(argv[3], "rb");
    if (in == NULL) {
      return 2;
    }
    n = fread(buf, 1, sizeof buf, in);
    if (!feof(in)) {
      fclose(in);
      gsec_wipe(buf, sizeof buf);
      return 1;
    }
    fclose(in);
    opened = gcert_pkcs8_decrypt(buf, n, argv[2], strlen(argv[2]), plain,
        sizeof plain, &plain_len, NULL);
    gsec_wipe(buf, sizeof buf);
    if (opened != GCERT_OK || gcert_pkcs8_parse(plain, plain_len, &key) != GCERT_OK) {
      gsec_wipe(plain, sizeof plain);
      return 1;
    }
    gsec_wipe(plain, sizeof plain);
  } else if (argc == 2) {
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
    if (gcert_pkcs8_parse(buf, n, &key) != GCERT_OK) {
      gsec_wipe(buf, sizeof buf);
      return 1;
    }
    gsec_wipe(buf, sizeof buf);
  } else {
    fprintf(stderr, "usage: pkcs8 <file> | pkcs8 decrypt <password> <file>\n");
    return 2;
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
    return 1;
  }
  printf("%s\n", name);
  return 0;
}
