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
 * PEM armour. Base64 is the standard alphabet. Whitespace between the
 * banners is ignored.
 */

#include <ghoti.io/certificate/macros.h>

#include <ghoti.io/certificate/pem.h>

#include <stddef.h>

static int b64_digit(unsigned char c) {
  if (c >= 'A' && c <= 'Z') {
    return c - 'A';
  }
  if (c >= 'a' && c <= 'z') {
    return c - 'a' + 26;
  }
  if (c >= '0' && c <= '9') {
    return c - '0' + 52;
  }
  if (c == '+') {
    return 62;
  }
  if (c == '/') {
    return 63;
  }
  return -1;
}

static int is_space(unsigned char c) {
  return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

static int label_eq(const unsigned char * a, size_t a_len,
    const unsigned char * b, size_t b_len) {
  size_t i;

  if (a_len != b_len) {
    return 0;
  }
  for (i = 0; i < a_len; i++) {
    if (a[i] != b[i]) {
      return 0;
    }
  }
  return 1;
}

static int label_char(unsigned char c) {
  if (c >= 'A' && c <= 'Z') {
    return 1;
  }
  if (c >= 'a' && c <= 'z') {
    return 1;
  }
  if (c >= '0' && c <= '9') {
    return 1;
  }
  return c == ' ' || c == '-';
}

static GCERT_Result b64_decode(const unsigned char * text, size_t n,
    unsigned char * out, size_t cap, size_t * out_len) {
  int group[4];
  int k;
  int pads;
  size_t i;
  size_t o;
  int finished;

  k = 0;
  pads = 0;
  o = 0;
  finished = 0;
  for (i = 0; i < n; i++) {
    unsigned char c = text[i];
    int digit;

    if (is_space(c)) {
      continue;
    }
    if (finished) {
      return GCERT_ERR_CORRUPT;
    }
    if (c == '=') {
      if (k < 2) {
        return GCERT_ERR_CORRUPT;
      }
      group[k++] = 0;
      pads++;
    } else {
      if (pads != 0) {
        return GCERT_ERR_CORRUPT;
      }
      digit = b64_digit(c);
      if (digit < 0) {
        return GCERT_ERR_CORRUPT;
      }
      group[k++] = digit;
    }
    if (k != 4) {
      continue;
    }
    if (o >= cap || (pads < 2 && o + 1 >= cap) || (pads == 0 && o + 2 >= cap)) {
      return GCERT_ERR_LIMIT;
    }
    out[o++] = (unsigned char)((group[0] << 2) | (group[1] >> 4));
    if (pads < 2) {
      out[o++] = (unsigned char)(((group[1] & 0x0f) << 4) | (group[2] >> 2));
    }
    if (pads == 0) {
      out[o++] = (unsigned char)(((group[2] & 0x03) << 6) | group[3]);
    }
    if (pads != 0) {
      finished = 1;
    }
    k = 0;
    pads = 0;
  }
  if (k != 0) {
    return GCERT_ERR_CORRUPT;
  }
  *out_len = o;
  return GCERT_OK;
}

static const char B64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

GCERT_Result gcert_pem_decode(const void * text, size_t text_len, void * out,
    size_t cap, size_t * out_len, char * label, size_t label_cap) {
  const unsigned char * p;
  const unsigned char * begin;
  const unsigned char * end_banner;
  size_t i;
  size_t label_len;
  size_t body;
  static const char begin_mark[] = "-----BEGIN ";
  static const char end_mark[] = "-----END ";

  if (out_len == NULL || (text == NULL && text_len != 0) ||
      (out == NULL && cap != 0) || (label == NULL && label_cap != 0)) {
    return GCERT_ERR_INVALID;
  }
  p = (const unsigned char *)text;
  begin = NULL;
  for (i = 0; i + sizeof begin_mark - 1u <= text_len; i++) {
    size_t k;
    int match = 1;
    for (k = 0; k < sizeof begin_mark - 1u; k++) {
      if (p[i + k] != (unsigned char)begin_mark[k]) {
        match = 0;
        break;
      }
    }
    if (match) {
      begin = p + i + sizeof begin_mark - 1u;
      break;
    }
  }
  if (begin == NULL) {
    return GCERT_ERR_CORRUPT;
  }
  label_len = 0;
  while ((size_t)(begin + label_len - p) + 5u <= text_len &&
      !(begin[label_len] == '-' && begin[label_len + 1u] == '-' )) {
    if (!label_char(begin[label_len]) || label_len >= 64u) {
      return GCERT_ERR_CORRUPT;
    }
    label_len++;
  }
  if (label_len == 0 || (size_t)(begin + label_len - p) + 5u > text_len) {
    return GCERT_ERR_CORRUPT;
  }
  if (begin[label_len] != '-' || begin[label_len + 1u] != '-' ||
      begin[label_len + 2u] != '-' || begin[label_len + 3u] != '-' ||
      begin[label_len + 4u] != '-') {
    return GCERT_ERR_CORRUPT;
  }
  body = (size_t)(begin + label_len + 5u - p);
  if (body < text_len && p[body] == '\r') {
    body++;
  }
  if (body >= text_len || p[body] != '\n') {
    return GCERT_ERR_CORRUPT;
  }
  body++;
  end_banner = NULL;
  for (i = body; i + sizeof end_mark - 1u + label_len + 5u <= text_len; i++) {
    size_t k;
    int match = 1;
    for (k = 0; k < sizeof end_mark - 1u; k++) {
      if (p[i + k] != (unsigned char)end_mark[k]) {
        match = 0;
        break;
      }
    }
    if (!match) {
      continue;
    }
    if (!label_eq(begin, label_len, p + i + sizeof end_mark - 1u, label_len)) {
      return GCERT_ERR_CORRUPT;
    }
    k = i + sizeof end_mark - 1u + label_len;
    if (k + 5u > text_len || p[k] != '-' || p[k + 1u] != '-' ||
        p[k + 2u] != '-' || p[k + 3u] != '-' || p[k + 4u] != '-') {
      return GCERT_ERR_CORRUPT;
    }
    end_banner = p + i;
    break;
  }
  if (end_banner == NULL) {
    return GCERT_ERR_CORRUPT;
  }
  if (label_cap != 0) {
    if (label_len > label_cap) {
      return GCERT_ERR_LIMIT;
    }
    for (i = 0; i < label_len; i++) {
      label[i] = (char)begin[i];
    }
  }
  return b64_decode(p + body, (size_t)(end_banner - (p + body)),
      (unsigned char *)out, cap, out_len);
}

static GCERT_Result emit(unsigned char * out, size_t cap, size_t * used,
    const char * bytes, size_t n) {
  size_t i;

  if (*used > cap || n > cap - *used) {
    return GCERT_ERR_LIMIT;
  }
  for (i = 0; i < n; i++) {
    out[*used + i] = (unsigned char)bytes[i];
  }
  *used += n;
  return GCERT_OK;
}

GCERT_Result gcert_pem_encode(const char * label, const void * der, size_t der_len,
    void * out, size_t cap, size_t * out_len) {
  const unsigned char * raw;
  unsigned char * dest;
  size_t label_len;
  size_t i;
  size_t used;
  size_t col;
  unsigned pending;
  int pending_n;
  GCERT_Result result;

  if (label == NULL || out_len == NULL || (der == NULL && der_len != 0) ||
      (out == NULL && cap != 0)) {
    return GCERT_ERR_INVALID;
  }
  label_len = 0;
  while (label[label_len] != '\0') {
    if (!label_char((unsigned char)label[label_len]) || label_len >= 64u) {
      return GCERT_ERR_INVALID;
    }
    label_len++;
  }
  if (label_len == 0) {
    return GCERT_ERR_INVALID;
  }
  dest = (unsigned char *)out;
  used = 0;
  result = emit(dest, cap, &used, "-----BEGIN ", 11);
  if (result != GCERT_OK) {
    return result;
  }
  result = emit(dest, cap, &used, label, label_len);
  if (result != GCERT_OK) {
    return result;
  }
  result = emit(dest, cap, &used, "-----\n", 6);
  if (result != GCERT_OK) {
    return result;
  }
  raw = (const unsigned char *)der;
  pending = 0;
  pending_n = 0;
  col = 0;
  for (i = 0; i < der_len; i++) {
    pending = (pending << 8) | raw[i];
    pending_n++;
    if (pending_n != 3) {
      continue;
    }
    {
      char chunk[5];
      chunk[0] = B64[(pending >> 18) & 63u];
      chunk[1] = B64[(pending >> 12) & 63u];
      chunk[2] = B64[(pending >> 6) & 63u];
      chunk[3] = B64[pending & 63u];
      chunk[4] = '\0';
      result = emit(dest, cap, &used, chunk, 4);
      if (result != GCERT_OK) {
        return result;
      }
    }
    pending = 0;
    pending_n = 0;
    col += 4;
    if (col == 64) {
      result = emit(dest, cap, &used, "\n", 1);
      if (result != GCERT_OK) {
        return result;
      }
      col = 0;
    }
  }
  if (pending_n == 1) {
    char chunk[5];
    pending <<= 16;
    chunk[0] = B64[(pending >> 18) & 63u];
    chunk[1] = B64[(pending >> 12) & 63u];
    chunk[2] = '=';
    chunk[3] = '=';
    result = emit(dest, cap, &used, chunk, 4);
    if (result != GCERT_OK) {
      return result;
    }
    col += 4;
  } else if (pending_n == 2) {
    char chunk[5];
    pending <<= 8;
    chunk[0] = B64[(pending >> 18) & 63u];
    chunk[1] = B64[(pending >> 12) & 63u];
    chunk[2] = B64[(pending >> 6) & 63u];
    chunk[3] = '=';
    result = emit(dest, cap, &used, chunk, 4);
    if (result != GCERT_OK) {
      return result;
    }
    col += 4;
  }
  if (col != 0) {
    result = emit(dest, cap, &used, "\n", 1);
    if (result != GCERT_OK) {
      return result;
    }
  }
  result = emit(dest, cap, &used, "-----END ", 9);
  if (result != GCERT_OK) {
    return result;
  }
  result = emit(dest, cap, &used, label, label_len);
  if (result != GCERT_OK) {
    return result;
  }
  result = emit(dest, cap, &used, "-----\n", 6);
  if (result != GCERT_OK) {
    return result;
  }
  *out_len = used;
  return GCERT_OK;
}
