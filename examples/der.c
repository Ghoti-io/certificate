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
 * Read one DER value from hex on the command line and print its tag.
 *
 * `der <hex>` prints the class, the constructed bit, and the number.
 * Trailing bytes after the first value are ignored. Bad hex exits 2.
 * A value that is not strict DER exits 1.
 */

#include <ghoti.io/certificate/macros.h>

#include <ghoti.io/certificate/der.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DER_MAX 4096u

static int nibble(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

int main(int argc, char ** argv) {
  unsigned char buf[DER_MAX];
  size_t n;
  size_t i;
  GCERT_Der view;
  const char * hex;

  if (argc != 2) {
    fprintf(stderr, "usage: der <hex>\n");
    return 2;
  }
  hex = argv[1];
  n = strlen(hex);
  if (n == 0 || (n % 2u) != 0 || n / 2u > DER_MAX) {
    return 2;
  }
  for (i = 0; i < n; i += 2) {
    int hi = nibble(hex[i]);
    int lo = nibble(hex[i + 1]);
    if (hi < 0 || lo < 0) {
      return 2;
    }
    buf[i / 2u] = (unsigned char)((hi << 4) | lo);
  }
  if (gcert_der_tlv(buf, n / 2u, &view) != GCERT_OK) {
    return 1;
  }
  printf("%u %u %u\n", view.tag_class, view.constructed, view.number);
  return 0;
}
