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
 * Reference-identity matching, RFC 9525. The rules are in names.h.
 */

#include <ghoti.io/certificate/macros.h>

#include <ghoti.io/certificate/names.h>

#include "../der/der_int.h"

#include <string.h>

static const unsigned char OID_CN[] = {0x55, 0x04, 0x03};

enum {
  GN_RFC822 = 1,
  GN_DNS = 2,
  GN_URI = 6,
  GN_IP = 7
};

/* ---- DNS names -------------------------------------------------------- */

static unsigned char fold(unsigned char c) {
  return (c >= 'A' && c <= 'Z') ? (unsigned char)(c - 'A' + 'a') : c;
}

static int ascii_eq(const unsigned char * a, size_t an, const unsigned char * b,
    size_t bn) {
  size_t i;
  if (an != bn) {
    return 0;
  }
  for (i = 0; i < an; i++) {
    if (fold(a[i]) != fold(b[i])) {
      return 0;
    }
  }
  return 1;
}

/* A well-formed host name: letters, digits, hyphen, underscore and the
 * wildcard character, no empty label, a label of at
 * most 63 bytes, at most 253 in all. Both the caller's name and a pattern
 * from a certificate are held to it. */
static int host_ok(const unsigned char * name, size_t n) {
  size_t i;
  size_t label = 0;
  if (n == 0 || n > 253u) {
    return 0;
  }
  for (i = 0; i < n; i++) {
    unsigned char c = name[i];
    if (c == '.') {
      if (label == 0) {
        return 0;
      }
      label = 0;
      continue;
    }
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
        (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '*')) {
      return 0;
    }
    label++;
    if (label > 63u) {
      return 0;
    }
  }
  return label != 0;
}

static size_t count_labels(const unsigned char * s, size_t n) {
  size_t i;
  size_t labels = n != 0 ? 1u : 0u;
  for (i = 0; i < n; i++) {
    if (s[i] == '.') {
      labels++;
    }
  }
  return labels;
}

/* Does the certificate's pattern name the host. `*` is special only as the
 * whole of the first label, followed by a dot, with at least min_labels
 * labels after it.
 *
 * The pattern is not checked for being a well-formed name, and that is a
 * decision, not an omission: the host has been, and a pattern matches only by
 * being equal to the host from the first label on, so a malformed pattern
 * cannot match. A check on the pattern could never change an answer, which
 * is how the audit found its predecessor (notes/security/AUDIT.md, L8). */
static int dns_match(const unsigned char * host, size_t hn, const unsigned char * pat,
    size_t pn, unsigned min_labels) {
  size_t i;
  if (pn >= 2 && pat[0] == '*' && pat[1] == '.') {
    const unsigned char * rest = pat + 2;
    size_t rn = pn - 2u;
    if (count_labels(rest, rn) < min_labels) {
      return 0;
    }
    for (i = 0; i < hn; i++) {
      if (host[i] == '.') {
        break;
      }
    }
    if (i == hn) { /* one label: also keeps the arithmetic below inside host */
      return 0;
    }
    return ascii_eq(host + i + 1u, hn - i - 1u, rest, rn);
  }
  /* A `*` anywhere else is an ordinary byte that no host can contain, so
   * the comparison refuses it without being told to. */
  return ascii_eq(host, hn, pat, pn);
}

/* ---- walking the subjectAltName -------------------------------------- */

typedef int (*san_fn)(const GCERT_Der * gn, void * ctx);

/* Calls fn for each context-tagged primitive entry of the given type. Stops
 * and returns 1 at the first entry for which fn returns nonzero. */
static GCERT_Result san_find(const GCERT_X509 * cert, unsigned type, san_fn fn,
    void * ctx, int * found) {
  GCERT_Der names;
  const unsigned char * p;
  size_t left;
  GCERT_Result result;

  *found = 0;
  if (cert->san == NULL) {
    return GCERT_OK;
  }
  result = gcert_der_tlv(cert->san, cert->san_len, &names);
  if (result != GCERT_OK) {
    return result;
  }
  if (names.total_len != cert->san_len) {
    return GCERT_ERR_CORRUPT;
  }
  p = names.value;
  left = names.value_len;
  while (left != 0) {
    GCERT_Der gn;
    result = gcert_der_next(&p, &left, &gn);
    if (result != GCERT_OK) {
      return result;
    }
    if (gn.tag_class == GCERT_DER_CONTEXT && gn.constructed == 0 &&
        gn.number == type && fn(&gn, ctx)) {
      *found = 1;
      /* Keep walking: a malformed later entry is still a malformed
       * certificate, and answering before reading it would make the
       * answer depend on entry order. */
    }
  }
  return GCERT_OK;
}

struct dns_ctx {
  const unsigned char * host;
  size_t host_len;
  unsigned min_labels;
};

static int dns_entry(const GCERT_Der * gn, void * ctx) {
  const struct dns_ctx * c = ctx;
  return dns_match(c->host, c->host_len, gn->value, gn->value_len, c->min_labels);
}

static GCERT_Result match_cn(const GCERT_X509 * cert, struct dns_ctx * c) {
  GCERT_Der name;
  GCERT_Result result;
  const unsigned char * p;
  size_t left;

  result = gcert_der_tlv(cert->subject, cert->subject_len, &name);
  if (result != GCERT_OK) {
    return result;
  }
  if (name.total_len != cert->subject_len) {
    return GCERT_ERR_CORRUPT;
  }
  p = name.value;
  left = name.value_len;
  while (left != 0) {
    GCERT_Der rdn;
    const unsigned char * rp;
    size_t rleft;
    result = gcert_der_next(&p, &left, &rdn);
    if (result != GCERT_OK) {
      return result;
    }
    rp = rdn.value;
    rleft = rdn.value_len;
    while (rleft != 0) {
      GCERT_Der atv;
      GCERT_Der oid;
      GCERT_Der val;
      const unsigned char * ap;
      size_t aleft;
      result = gcert_der_next(&rp, &rleft, &atv);
      if (result != GCERT_OK || !gcert_der_is(&atv, GCERT_DER_UNIVERSAL, 1, 16)) {
        return GCERT_ERR_CORRUPT;
      }
      ap = atv.value;
      aleft = atv.value_len;
      result = gcert_der_next(&ap, &aleft, &oid);
      if (result != GCERT_OK) {
        return result;
      }
      result = gcert_der_next(&ap, &aleft, &val);
      if (result != GCERT_OK || aleft != 0) {
        return GCERT_ERR_CORRUPT;
      }
      if (gcert_der_oid_is(&oid, OID_CN, sizeof OID_CN) && val.constructed == 0 &&
          dns_match(c->host, c->host_len, val.value, val.value_len, c->min_labels)) {
        return GCERT_OK;
      }
    }
  }
  return GCERT_ERR_MISMATCH;
}

void gcert_name_options_default(GCERT_NameOptions * options) {
  if (options == NULL) {
    return;
  }
  memset(options, 0, sizeof *options);
  options->wildcard_min_labels = GCERT_NAME_WILDCARD_MIN_LABELS;
}

GCERT_Result gcert_x509_verify_dns(const GCERT_X509 * cert, const char * name,
    size_t name_len, const GCERT_NameOptions * options) {
  struct dns_ctx c;
  int found;
  GCERT_Result result;

  if (cert == NULL || (name == NULL && name_len != 0)) {
    return GCERT_ERR_INVALID;
  }
  c.host = (const unsigned char *)name;
  if (name_len > 0 && c.host[name_len - 1u] == '.') {
    name_len--;
  }
  c.host_len = name_len;
  if (!host_ok(c.host, c.host_len) || memchr(c.host, '*', c.host_len) != NULL) {
    return GCERT_ERR_INVALID;
  }
  c.min_labels = GCERT_NAME_WILDCARD_MIN_LABELS;
  if (options != NULL && options->wildcard_min_labels != 0) {
    c.min_labels = options->wildcard_min_labels;
  }
  if (cert->dns_san) {
    result = san_find(cert, GN_DNS, dns_entry, &c, &found);
    if (result != GCERT_OK) {
      return result;
    }
    return found ? GCERT_OK : GCERT_ERR_MISMATCH;
  }
  if (options != NULL && options->common_name_fallback) {
    return match_cn(cert, &c);
  }
  return GCERT_ERR_MISMATCH;
}

GCERT_Result gcert_x509_hostname(const GCERT_X509 * cert, const char * name,
    size_t name_len) {
  GCERT_NameOptions options;
  gcert_name_options_default(&options);
  options.common_name_fallback = 1;
  return gcert_x509_verify_dns(cert, name, name_len, &options);
}

/* ---- IP addresses ------------------------------------------------------ */

static int parse_v4(const unsigned char * s, size_t n, unsigned char out[4]) {
  size_t i = 0;
  int field;
  for (field = 0; field < 4; field++) {
    unsigned value = 0;
    size_t digits = 0;
    while (i < n && s[i] >= '0' && s[i] <= '9') {
      if (digits == 1 && value == 0) {
        return 0; /* leading zero */
      }
      value = value * 10u + (unsigned)(s[i] - '0');
      digits++;
      i++;
      if (digits > 3 || value > 255u) {
        return 0;
      }
    }
    if (digits == 0) {
      return 0;
    }
    out[field] = (unsigned char)value;
    if (field < 3) {
      if (i >= n || s[i] != '.') {
        return 0;
      }
      i++;
    }
  }
  return i == n;
}

static int hex_digit(unsigned char c) {
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

static int parse_v6(const unsigned char * s, size_t n, unsigned char out[16]) {
  unsigned short head[8] = {0};
  unsigned short tail[8] = {0};
  size_t nhead = 0;
  size_t ntail = 0;
  int seen_gap = 0;
  size_t i = 0;
  size_t groups;
  size_t k;

  if (n < 2) {
    return 0;
  }
  if (s[0] == ':') {
    if (s[1] != ':') {
      return 0;
    }
    seen_gap = 1;
    i = 2;
  }
  while (i < n) {
    unsigned value = 0;
    size_t digits = 0;
    size_t start = i;
    unsigned short * dst = seen_gap ? tail : head;
    size_t * count = seen_gap ? &ntail : &nhead;

    while (i < n && hex_digit(s[i]) >= 0) {
      value = value * 16u + (unsigned)hex_digit(s[i]);
      digits++;
      i++;
      if (digits > 4) {
        return 0;
      }
    }
    if (i < n && s[i] == '.') {
      /* A trailing dotted quad is the last two groups. */
      unsigned char quad[4];
      if (!parse_v4(s + start, n - start, quad) || nhead + ntail > 6) {
        return 0;
      }
      dst[(*count)++] = (unsigned short)((quad[0] << 8) | quad[1]);
      dst[(*count)++] = (unsigned short)((quad[2] << 8) | quad[3]);
      i = n;
      break;
    }
    if (digits == 0) {
      return 0;
    }
    if (nhead + ntail >= 8) {
      return 0;
    }
    dst[(*count)++] = (unsigned short)value;
    if (i == n) {
      break;
    }
    if (s[i] != ':') {
      return 0;
    }
    i++;
    if (i < n && s[i] == ':') {
      if (seen_gap) {
        return 0;
      }
      seen_gap = 1;
      i++;
      if (i == n) {
        break;
      }
    } else if (i == n) {
      return 0; /* a single trailing colon */
    }
  }
  groups = nhead + ntail;
  if (seen_gap ? groups > 7 : groups != 8) {
    return 0;
  }
  memset(out, 0, 16);
  for (k = 0; k < nhead; k++) {
    out[2 * k] = (unsigned char)(head[k] >> 8);
    out[2 * k + 1] = (unsigned char)head[k];
  }
  for (k = 0; k < ntail; k++) {
    size_t pos = 8 - ntail + k;
    out[2 * pos] = (unsigned char)(tail[k] >> 8);
    out[2 * pos + 1] = (unsigned char)tail[k];
  }
  return 1;
}

GCERT_Result gcert_ip_parse(const char * text, size_t len, unsigned char out[16],
    size_t * out_len) {
  const unsigned char * s = (const unsigned char *)text;
  size_t i;
  int colon = 0;

  if (out == NULL || out_len == NULL || (text == NULL && len != 0) || len == 0 ||
      len > 45u) {
    return GCERT_ERR_INVALID;
  }
  for (i = 0; i < len; i++) {
    if (s[i] == ':') {
      colon = 1;
    }
  }
  if (colon) {
    if (!parse_v6(s, len, out)) {
      return GCERT_ERR_INVALID;
    }
    *out_len = 16;
    return GCERT_OK;
  }
  if (!parse_v4(s, len, out)) {
    return GCERT_ERR_INVALID;
  }
  *out_len = 4;
  return GCERT_OK;
}

struct bytes_ctx {
  const unsigned char * b;
  size_t n;
};

static int bytes_entry(const GCERT_Der * gn, void * ctx) {
  const struct bytes_ctx * c = ctx;
  return gcert_der_eq(gn->value, gn->value_len, c->b, c->n);
}

GCERT_Result gcert_x509_verify_ip(const GCERT_X509 * cert, const void * addr,
    size_t addr_len) {
  struct bytes_ctx c;
  int found;
  GCERT_Result result;

  if (cert == NULL || addr == NULL || (addr_len != 4 && addr_len != 16)) {
    return GCERT_ERR_INVALID;
  }
  c.b = addr;
  c.n = addr_len;
  result = san_find(cert, GN_IP, bytes_entry, &c, &found);
  if (result != GCERT_OK) {
    return result;
  }
  return found ? GCERT_OK : GCERT_ERR_MISMATCH;
}

/* ---- URIs and mailboxes ------------------------------------------------ */

static int text_ok(const unsigned char * s, size_t n) {
  size_t i;
  if (n == 0 || n > 2048u) {
    return 0;
  }
  for (i = 0; i < n; i++) {
    if (s[i] < 0x21 || s[i] >= 0x7f) {
      return 0;
    }
  }
  return 1;
}

GCERT_Result gcert_x509_verify_uri(const GCERT_X509 * cert, const char * uri,
    size_t uri_len) {
  struct bytes_ctx c;
  int found;
  GCERT_Result result;

  if (cert == NULL || (uri == NULL && uri_len != 0) ||
      !text_ok((const unsigned char *)uri, uri_len)) {
    return GCERT_ERR_INVALID;
  }
  c.b = (const unsigned char *)uri;
  c.n = uri_len;
  result = san_find(cert, GN_URI, bytes_entry, &c, &found);
  if (result != GCERT_OK) {
    return result;
  }
  return found ? GCERT_OK : GCERT_ERR_MISMATCH;
}

static int mailbox_split(const unsigned char * s, size_t n, size_t * at) {
  size_t i;
  if (!text_ok(s, n)) {
    return 0;
  }
  for (i = n; i > 0; i--) {
    if (s[i - 1u] == '@') {
      *at = i - 1u;
      return *at != 0 && *at + 1u < n;
    }
  }
  return 0;
}

static int mailbox_entry(const GCERT_Der * gn, void * ctx) {
  const struct bytes_ctx * c = ctx;
  size_t want_at;
  size_t have_at;
  if (!mailbox_split(c->b, c->n, &want_at) ||
      !mailbox_split(gn->value, gn->value_len, &have_at)) {
    return 0;
  }
  return gcert_der_eq(c->b, want_at, gn->value, have_at) &&
      ascii_eq(c->b + want_at + 1u, c->n - want_at - 1u, gn->value + have_at + 1u,
          gn->value_len - have_at - 1u);
}

GCERT_Result gcert_x509_verify_email(const GCERT_X509 * cert, const char * mailbox,
    size_t mailbox_len) {
  struct bytes_ctx c;
  size_t at;
  int found;
  GCERT_Result result;

  if (cert == NULL || (mailbox == NULL && mailbox_len != 0) ||
      !mailbox_split((const unsigned char *)mailbox, mailbox_len, &at)) {
    return GCERT_ERR_INVALID;
  }
  c.b = (const unsigned char *)mailbox;
  c.n = mailbox_len;
  result = san_find(cert, GN_RFC822, mailbox_entry, &c, &found);
  if (result != GCERT_OK) {
    return result;
  }
  return found ? GCERT_OK : GCERT_ERR_MISMATCH;
}

/* ---- either ------------------------------------------------------------ */

GCERT_Result gcert_x509_verify_host(const GCERT_X509 * cert, const char * host,
    size_t host_len, const GCERT_NameOptions * options) {
  unsigned char addr[16];
  size_t addr_len;

  if (cert == NULL || (host == NULL && host_len != 0)) {
    return GCERT_ERR_INVALID;
  }
  if (gcert_ip_parse(host, host_len, addr, &addr_len) == GCERT_OK) {
    return gcert_x509_verify_ip(cert, addr, addr_len);
  }
  return gcert_x509_verify_dns(cert, host, host_len, options);
}
