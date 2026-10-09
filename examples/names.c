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
 * Match a certificate against a name, an address, a mailbox or a URI.
 *
 * `names <cert.der> <kind> <value> [min_labels] [cn]` where kind is one of
 * dns, ip, email, uri or host, or `ipparse`, which prints the address
 * `gcert_ip_parse` reads from the value as hex (the certificate is not read).
 * `min_labels` is the wildcard rule's count (0 for the default, 2) and `cn`
 * as the last argument turns the common-name fallback on, for dns. Prints `match`, `mismatch` or `invalid` and exits
 * 0, 1 or 2; any other failure exits 3. `make check-oracle` compares it with
 * OpenSSL's `-checkhost`, `-checkip` and `-checkemail`.
 */

/* check-secret: allow printf -- what the example found in a public input (a name, a count, a verdict), never a private key */
/* check-secret: allow strcmp -- command-line words, never a secret */

#include <ghoti.io/certificate/macros.h>

#include <ghoti.io/certificate/certificate.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
  static unsigned char der[GCERT_X509_DER_MAX];
  size_t der_len = 0;
  GCERT_X509 cert;
  GCERT_NameOptions options;
  GCERT_Result r;
  const char * kind;
  const char * value;

  if (argc < 4 || argc > 6) {
    fprintf(stderr, "usage: names <cert.der> <dns|ip|email|uri|host> <value> [min_labels] [cn]\n");
    return 3;
  }
  if (strcmp(argv[2], "ipparse") == 0) {
    unsigned char addr[16];
    size_t addr_len = 0;
    size_t i;
    if (gcert_ip_parse(argv[3], strlen(argv[3]), addr, &addr_len) != GCERT_OK) {
      printf("invalid\n");
      return 2;
    }
    for (i = 0; i < addr_len; i++) {
      printf("%02x", addr[i]);
    }
    printf("\n");
    return 0;
  }
  gcert_name_options_default(&options);
  if (argc >= 5) {
    options.wildcard_min_labels = (unsigned)strtoul(argv[4], NULL, 10);
  }
  if (argc == 6 && strcmp(argv[5], "cn") == 0) {
    options.common_name_fallback = 1;
  }
  if (!read_file(argv[1], der, sizeof der, &der_len) ||
      gcert_x509_parse(der, der_len, &cert) != GCERT_OK) {
    fprintf(stderr, "names: cannot read the certificate\n");
    return 3;
  }
  kind = argv[2];
  value = argv[3];
  if (strcmp(kind, "dns") == 0) {
    r = gcert_x509_verify_dns(&cert, value, strlen(value), &options);
  } else if (strcmp(kind, "host") == 0) {
    r = gcert_x509_verify_host(&cert, value, strlen(value), &options);
  } else if (strcmp(kind, "email") == 0) {
    r = gcert_x509_verify_email(&cert, value, strlen(value));
  } else if (strcmp(kind, "uri") == 0) {
    r = gcert_x509_verify_uri(&cert, value, strlen(value));
  } else if (strcmp(kind, "ip") == 0) {
    unsigned char addr[16];
    size_t addr_len = 0;
    r = gcert_ip_parse(value, strlen(value), addr, &addr_len);
    if (r == GCERT_OK) {
      r = gcert_x509_verify_ip(&cert, addr, addr_len);
    }
  } else {
    fprintf(stderr, "names: unknown kind %s\n", kind);
    return 3;
  }
  if (r == GCERT_OK) {
    printf("match\n");
    return 0;
  }
  if (r == GCERT_ERR_MISMATCH) {
    printf("mismatch\n");
    return 1;
  }
  if (r == GCERT_ERR_INVALID) {
    printf("invalid\n");
    return 2;
  }
  fprintf(stderr, "names: %s\n", gcert_result_string(r));
  return 3;
}
