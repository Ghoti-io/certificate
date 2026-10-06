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
 * Strict DER. Lengths and tags are the shortest form that holds them.
 * An indefinite length is rejected. Nothing here is a secret.
 */

#include <ghoti.io/certificate/macros.h>

#include <ghoti.io/certificate/der.h>

#include "der_int.h"

#include <stddef.h>
#include <stdint.h>

int gcert_der_is(const GCERT_Der * v, unsigned tag_class, unsigned constructed,
    unsigned number) {
  return v->tag_class == tag_class && v->constructed == constructed &&
      v->number == number;
}

int gcert_der_eq(const unsigned char * a, size_t a_len, const unsigned char * b,
    size_t b_len) {
  size_t i;
  unsigned diff;

  if (a_len != b_len) {
    return 0;
  }
  diff = 0;
  for (i = 0; i < a_len; i++) {
    diff |= (unsigned)a[i] ^ (unsigned)b[i];
  }
  return diff == 0;
}

static GCERT_Result read_tag(const unsigned char * p, size_t n, unsigned * used,
    unsigned * tag_class, unsigned * constructed, unsigned * number) {
  unsigned b;
  unsigned i;
  unsigned value;
  unsigned consumed;

  if (n == 0) {
    return GCERT_ERR_CORRUPT;
  }
  b = p[0];
  *tag_class = b >> 6;
  *constructed = (b >> 5) & 1u;
  value = b & 0x1fu;
  if (value != 0x1fu) {
    *number = value;
    *used = 1;
    return GCERT_OK;
  }
  if (n < 2 || (p[1] & 0x80u) == 0) {
    return GCERT_ERR_CORRUPT;
  }
  /* A leading 0x80 is a base-128 zero, which the short form already covers. */
  if (p[1] == 0x80u) {
    return GCERT_ERR_CORRUPT;
  }
  value = 0;
  consumed = 1;
  for (i = 1; i < n && i < 6; i++) {
    unsigned c = p[i];
    if (value > (0xffffffffu >> 7)) {
      return GCERT_ERR_CORRUPT;
    }
    value = (value << 7) | (c & 0x7fu);
    consumed = i + 1u;
    if ((c & 0x80u) == 0) {
      if (value < 31u) {
        return GCERT_ERR_CORRUPT;
      }
      *number = value;
      *used = consumed;
      return GCERT_OK;
    }
  }
  return GCERT_ERR_CORRUPT;
}

static GCERT_Result read_length(const unsigned char * p, size_t n,
    unsigned * used, size_t * length) {
  unsigned b;
  unsigned nbytes;
  unsigned i;
  size_t value;

  if (n == 0) {
    return GCERT_ERR_CORRUPT;
  }
  b = p[0];
  if ((b & 0x80u) == 0) {
    *length = b;
    *used = 1;
    return GCERT_OK;
  }
  nbytes = b & 0x7fu;
  if (nbytes == 0 || nbytes > sizeof(size_t) || n < 1u + nbytes) {
    return GCERT_ERR_CORRUPT;
  }
  if (p[1] == 0) {
    return GCERT_ERR_CORRUPT;
  }
  value = 0;
  for (i = 0; i < nbytes; i++) {
    value = (value << 8) | p[1u + i];
  }
  if (value < 128u) {
    return GCERT_ERR_CORRUPT;
  }
  *length = value;
  *used = 1u + nbytes;
  return GCERT_OK;
}

static int integer_minimal(const unsigned char * p, size_t n) {
  if (n == 0) {
    return 0;
  }
  if (n >= 2 && p[0] == 0x00 && (p[1] & 0x80u) == 0) {
    return 0;
  }
  if (n >= 2 && p[0] == 0xff && (p[1] & 0x80u) != 0) {
    return 0;
  }
  return 1;
}

GCERT_Result gcert_der_set_sorted(const GCERT_Der * set);

GCERT_Result gcert_der_tlv(const void * buf, size_t len, GCERT_Der * out) {
  const unsigned char * p;
  unsigned tag_used;
  unsigned len_used;
  size_t value_len;
  GCERT_Result result;

  if (out == NULL || (buf == NULL && len != 0)) {
    return GCERT_ERR_INVALID;
  }
  if (len == 0) {
    return GCERT_ERR_CORRUPT;
  }
  p = (const unsigned char *)buf;
  result = read_tag(p, len, &tag_used, &out->tag_class, &out->constructed,
      &out->number);
  if (result != GCERT_OK) {
    return result;
  }
  result = read_length(p + tag_used, len - tag_used, &len_used, &value_len);
  if (result != GCERT_OK) {
    return result;
  }
  if (len - tag_used - len_used < value_len) {
    return GCERT_ERR_CORRUPT;
  }
  out->value = p + tag_used + len_used;
  out->value_len = value_len;
  out->total_len = (size_t)tag_used + (size_t)len_used + value_len;
  if (out->tag_class == GCERT_DER_UNIVERSAL && out->constructed == 0) {
    if (out->number == 2 && !integer_minimal(out->value, out->value_len)) {
      return GCERT_ERR_CORRUPT;
    }
    if (out->number == 1 &&
        (out->value_len != 1 || (out->value[0] != 0x00 && out->value[0] != 0xff))) {
      return GCERT_ERR_CORRUPT;
    }
    if (out->number == 5 && out->value_len != 0) {
      return GCERT_ERR_CORRUPT;
    }
  }
  if (out->tag_class == GCERT_DER_UNIVERSAL && out->constructed == 1 &&
      out->number == 17) {
    return gcert_der_set_sorted(out);
  }
  return GCERT_OK;
}

GCERT_Result gcert_der_next(const unsigned char ** p, size_t * left,
    GCERT_Der * out) {
  GCERT_Result result;

  result = gcert_der_tlv(*p, *left, out);
  if (result != GCERT_OK) {
    return result;
  }
  *p += out->total_len;
  *left -= out->total_len;
  return GCERT_OK;
}

GCERT_Result gcert_der_unsigned(const GCERT_Der * v, const unsigned char ** be,
    size_t * be_len) {
  const unsigned char * p;
  size_t n;

  if (!gcert_der_is(v, GCERT_DER_UNIVERSAL, 0, 2)) {
    return GCERT_ERR_CORRUPT;
  }
  p = v->value;
  n = v->value_len;
  if (n == 0) {
    return GCERT_ERR_CORRUPT;
  }
  if (n >= 2) {
    if (p[0] == 0x00 && (p[1] & 0x80u) == 0) {
      return GCERT_ERR_CORRUPT;
    }
    if (p[0] == 0xff && (p[1] & 0x80u) != 0) {
      return GCERT_ERR_CORRUPT;
    }
  }
  if ((p[0] & 0x80u) != 0) {
    return GCERT_ERR_CORRUPT;
  }
  if (n > 1 && p[0] == 0x00) {
    p++;
    n--;
  }
  *be = p;
  *be_len = n;
  return GCERT_OK;
}

GCERT_Result gcert_der_bit_payload(const GCERT_Der * v, const unsigned char ** bits,
    size_t * bits_len) {
  unsigned unused;
  unsigned mask;

  if (!gcert_der_is(v, GCERT_DER_UNIVERSAL, 0, 3) || v->value_len < 1) {
    return GCERT_ERR_CORRUPT;
  }
  unused = v->value[0];
  if (unused > 7) {
    return GCERT_ERR_CORRUPT;
  }
  if (v->value_len == 1) {
    if (unused != 0) {
      return GCERT_ERR_CORRUPT;
    }
    *bits = v->value + 1;
    *bits_len = 0;
    return GCERT_OK;
  }
  if (unused != 0) {
    mask = (1u << unused) - 1u;
    if ((v->value[v->value_len - 1u] & mask) != 0) {
      return GCERT_ERR_CORRUPT;
    }
  }
  *bits = v->value + 1;
  *bits_len = v->value_len - 1u;
  return GCERT_OK;
}

GCERT_Result gcert_der_oid_ok(const GCERT_Der * v) {
  size_t i;

  if (!gcert_der_is(v, GCERT_DER_UNIVERSAL, 0, 6) || v->value_len == 0) {
    return GCERT_ERR_CORRUPT;
  }
  i = 0;
  while (i < v->value_len) {
    if (v->value[i] == 0x80u) {
      return GCERT_ERR_CORRUPT;
    }
    while ((v->value[i] & 0x80u) != 0) {
      i++;
      if (i >= v->value_len) {
        return GCERT_ERR_CORRUPT;
      }
    }
    i++;
  }
  return GCERT_OK;
}

int gcert_der_oid_is(const GCERT_Der * v, const unsigned char * oid,
    size_t oid_len) {
  if (gcert_der_oid_ok(v) != GCERT_OK) {
    return 0;
  }
  return gcert_der_eq(v->value, v->value_len, oid, oid_len);
}

GCERT_Result gcert_der_set_sorted(const GCERT_Der * set) {
  const unsigned char * cursor;
  size_t remain;
  const unsigned char * earlier;
  size_t earlier_len;

  if (!gcert_der_is(set, GCERT_DER_UNIVERSAL, 1, 17)) {
    return GCERT_ERR_CORRUPT;
  }
  if (set->value_len == 0) {
    return GCERT_OK;
  }
  cursor = set->value;
  remain = set->value_len;
  earlier = NULL;
  earlier_len = 0;
  while (remain != 0) {
    unsigned tag_used;
    unsigned len_used;
    unsigned tag_class;
    unsigned constructed;
    unsigned number;
    size_t value_len;
    GCERT_Result result;
    const unsigned char * encoding;
    size_t total;
    size_t i;
    int decided;
    size_t n;

    /* Headers only. A nested SET is checked when that value is read. */
    result = read_tag(cursor, remain, &tag_used, &tag_class, &constructed,
        &number);
    if (result != GCERT_OK) {
      return result;
    }
    result = read_length(cursor + tag_used, remain - tag_used, &len_used,
        &value_len);
    if (result != GCERT_OK || remain - tag_used - len_used < value_len) {
      return GCERT_ERR_CORRUPT;
    }
    encoding = cursor;
    total = (size_t)tag_used + (size_t)len_used + value_len;
    cursor += total;
    remain -= total;
    (void)tag_class;
    (void)constructed;
    (void)number;
    if (earlier != NULL) {
      n = earlier_len < total ? earlier_len : total;
      decided = 0;
      for (i = 0; i < n; i++) {
        if (earlier[i] < encoding[i]) {
          decided = 1;
          break;
        }
        if (earlier[i] > encoding[i]) {
          return GCERT_ERR_CORRUPT;
        }
      }
      if (!decided && earlier_len >= total) {
        return GCERT_ERR_CORRUPT;
      }
    }
    earlier = encoding;
    earlier_len = total;
  }
  return GCERT_OK;
}

static int leap(int year) {
  if (year % 400 == 0) {
    return 1;
  }
  if (year % 100 == 0) {
    return 0;
  }
  return year % 4 == 0;
}

static int month_days(int year, int month) {
  static const int days[12] = {
    31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
  };
  if (month == 2 && leap(year)) {
    return 29;
  }
  return days[month - 1];
}

static int64_t days_from_civil(int year, int month, int day) {
  int era;
  unsigned yoe;
  unsigned doy;
  unsigned doe;
  int y;

  y = year;
  if (month <= 2) {
    y -= 1;
  }
  era = (y >= 0 ? y : y - 399) / 400;
  yoe = (unsigned)(y - era * 400);
  doy = (153u * (unsigned)(month + (month > 2 ? -3 : 9)) + 2u) / 5u +
      (unsigned)day - 1u;
  doe = yoe * 365u + yoe / 4u - yoe / 100u + doy;
  return (int64_t)era * 146097 + (int64_t)doe - 719468;
}

static int two(const unsigned char * p) {
  if (p[0] < '0' || p[0] > '9' || p[1] < '0' || p[1] > '9') {
    return -1;
  }
  return (p[0] - '0') * 10 + (p[1] - '0');
}

static int four(const unsigned char * p) {
  int hi = two(p);
  int lo = two(p + 2);
  if (hi < 0 || lo < 0) {
    return -1;
  }
  return hi * 100 + lo;
}

GCERT_Result gcert_der_time(const GCERT_Der * v, int64_t * unix_time) {
  int year;
  int month;
  int day;
  int hour;
  int minute;
  int second;
  size_t n;
  const unsigned char * p;
  int64_t days;

  if (v->constructed != 0 || v->tag_class != GCERT_DER_UNIVERSAL) {
    return GCERT_ERR_CORRUPT;
  }
  p = v->value;
  n = v->value_len;
  if (v->number == 23) {
    if (n != 13 || p[12] != 'Z') {
      return GCERT_ERR_CORRUPT;
    }
    year = two(p);
    if (year < 0) {
      return GCERT_ERR_CORRUPT;
    }
    year += year >= 50 ? 1900 : 2000;
    p += 2;
  } else if (v->number == 24) {
    if (n != 15 || p[14] != 'Z') {
      return GCERT_ERR_CORRUPT;
    }
    year = four(p);
    if (year < 1900 || year > 9999) {
      return GCERT_ERR_CORRUPT;
    }
    p += 4;
  } else {
    return GCERT_ERR_CORRUPT;
  }
  month = two(p);
  day = two(p + 2);
  hour = two(p + 4);
  minute = two(p + 6);
  second = two(p + 8);
  if (month < 1 || month > 12 || day < 1 || hour < 0 || hour > 23 ||
      minute < 0 || minute > 59 || second < 0 || second > 59 ||
      day > month_days(year, month)) {
    return GCERT_ERR_CORRUPT;
  }
  days = days_from_civil(year, month, day);
  *unix_time = days * 86400 + (int64_t)hour * 3600 + (int64_t)minute * 60 +
      second;
  return GCERT_OK;
}
