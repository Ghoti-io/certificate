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
 * Reporting what a certificate names. See identity.h.
 */

#include <ghoti.io/certificate/macros.h>

#include <ghoti.io/certificate/identity.h>

#include "../der/der_int.h"

GCERT_Result gcert_x509_san_next(const GCERT_X509 * cert, size_t * cursor, unsigned * choice,
    const unsigned char ** value, size_t * len) {
  GCERT_Der names;
  const unsigned char * p;
  size_t left;
  size_t seen = 0;
  GCERT_Result result;

  if (cert == NULL || cursor == NULL || choice == NULL || value == NULL || len == NULL) {
    return GCERT_ERR_INVALID;
  }
  if (cert->san == NULL) {
    return GCERT_ERR_FORMAT;
  }
  result = gcert_der_tlv(cert->san, cert->san_len, &names);
  if (result != GCERT_OK || names.total_len != cert->san_len ||
      !gcert_der_is(&names, GCERT_DER_UNIVERSAL, 1, 16)) {
    return GCERT_ERR_CORRUPT;
  }
  p = names.value;
  left = names.value_len;
  while (left != 0) {
    GCERT_Der gn;
    result = gcert_der_next(&p, &left, &gn);
    if (result != GCERT_OK) {
      return GCERT_ERR_CORRUPT;
    }
    if (gn.tag_class != GCERT_DER_CONTEXT || gn.number > GCERT_SAN_REGISTERED_ID) {
      return GCERT_ERR_CORRUPT;  /* every GeneralName is a context-tagged choice 0 to 8 */
    }
    if (seen++ == *cursor) {
      *choice = (unsigned)gn.number;
      *value = gn.value;
      *len = gn.value_len;
      (*cursor)++;
      return GCERT_OK;
    }
  }
  return GCERT_ERR_FORMAT;
}

static const unsigned char OID_CN[] = {0x55, 0x04, 0x03};
static const unsigned char OID_SERIAL[] = {0x55, 0x04, 0x05};
static const unsigned char OID_C[] = {0x55, 0x04, 0x06};
static const unsigned char OID_L[] = {0x55, 0x04, 0x07};
static const unsigned char OID_ST[] = {0x55, 0x04, 0x08};
static const unsigned char OID_O[] = {0x55, 0x04, 0x0a};
static const unsigned char OID_OU[] = {0x55, 0x04, 0x0b};
static const unsigned char OID_EMAIL[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01};
static const unsigned char OID_DC[] = {0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19};

static int attr_oid(GCERT_NameAttr attr, const unsigned char ** oid, size_t * n) {
  switch (attr) {
    case GCERT_ATTR_COMMON_NAME:
      *oid = OID_CN;
      *n = sizeof OID_CN;
      return 1;
    case GCERT_ATTR_COUNTRY:
      *oid = OID_C;
      *n = sizeof OID_C;
      return 1;
    case GCERT_ATTR_LOCALITY:
      *oid = OID_L;
      *n = sizeof OID_L;
      return 1;
    case GCERT_ATTR_STATE:
      *oid = OID_ST;
      *n = sizeof OID_ST;
      return 1;
    case GCERT_ATTR_ORGANIZATION:
      *oid = OID_O;
      *n = sizeof OID_O;
      return 1;
    case GCERT_ATTR_ORG_UNIT:
      *oid = OID_OU;
      *n = sizeof OID_OU;
      return 1;
    case GCERT_ATTR_SERIAL_NUMBER:
      *oid = OID_SERIAL;
      *n = sizeof OID_SERIAL;
      return 1;
    case GCERT_ATTR_EMAIL:
      *oid = OID_EMAIL;
      *n = sizeof OID_EMAIL;
      return 1;
    case GCERT_ATTR_DOMAIN_COMPONENT:
      *oid = OID_DC;
      *n = sizeof OID_DC;
      return 1;
  }
  return 0;
}

GCERT_Result gcert_x509_name_attr(const unsigned char * name, size_t name_len,
    GCERT_NameAttr attr, size_t index, const unsigned char ** value, size_t * len) {
  GCERT_Der seq;
  const unsigned char * p;
  size_t left;
  const unsigned char * oid_bytes = NULL;
  size_t oid_len = 0;
  size_t seen = 0;
  GCERT_Result result;

  if (name == NULL || value == NULL || len == NULL || !attr_oid(attr, &oid_bytes, &oid_len)) {
    return GCERT_ERR_INVALID;
  }
  result = gcert_der_tlv(name, name_len, &seq);
  if (result != GCERT_OK || seq.total_len != name_len ||
      !gcert_der_is(&seq, GCERT_DER_UNIVERSAL, 1, 16)) {
    return GCERT_ERR_CORRUPT;
  }
  p = seq.value;
  left = seq.value_len;
  while (left != 0) {
    GCERT_Der rdn;
    const unsigned char * rp;
    size_t rleft;
    result = gcert_der_next(&p, &left, &rdn);
    if (result != GCERT_OK || !gcert_der_is(&rdn, GCERT_DER_UNIVERSAL, 1, 17)) {
      return GCERT_ERR_CORRUPT;
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
        return GCERT_ERR_CORRUPT;
      }
      result = gcert_der_next(&ap, &aleft, &val);
      if (result != GCERT_OK || aleft != 0) {
        return GCERT_ERR_CORRUPT;
      }
      if (!gcert_der_oid_is(&oid, oid_bytes, oid_len)) {
        continue;
      }
      if (seen++ != index) {
        continue;
      }
      if (val.tag_class != GCERT_DER_UNIVERSAL || val.constructed != 0 ||
          (val.number != 12 && val.number != 19 && val.number != 22)) {
        return GCERT_ERR_UNSUPPORTED;
      }
      *value = val.value;
      *len = val.value_len;
      return GCERT_OK;
    }
  }
  return GCERT_ERR_FORMAT;
}
