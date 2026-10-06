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
 * Known answers an embedder can run without the test suite.
 *
 * The bytes below are not secret. They are fixed inputs, and nothing here
 * writes them anywhere except into stack buffers.
 */

#include <ghoti.io/certificate/macros.h>

#include <ghoti.io/certificate/der.h>
#include <ghoti.io/certificate/names.h>
#include <ghoti.io/certificate/pem.h>
#include <ghoti.io/certificate/revocation.h>
#include <ghoti.io/certificate/selftest.h>
#include <ghoti.io/security/secret.h>

#include <string.h>

#include "sec_result.h"

GCERT_Result gcert_selftest(void) {
  GCERT_Result result;

  {
    static const unsigned char der[] = {0x30, 0x03, 0x02, 0x01, 0x01};
    GCERT_Der view;
    result = gcert_der_tlv(der, sizeof der, &view);
    if (result != GCERT_OK || view.number != 16 || view.value_len != 3) {
      return result == GCERT_OK ? GCERT_ERR_INTERNAL : result;
    }
  }
  /* PEM, which has a writer, so its self test is a round trip. */
  {
    static const unsigned char der[] = {0x30, 0x03, 0x02, 0x01, 0x01};
    unsigned char armour[128];
    unsigned char back[16];
    char label[16];
    size_t armour_len = 0;
    size_t back_len = 0;

    result = gcert_pem_encode("TEST", der, sizeof der, armour, sizeof armour,
        &armour_len);
    if (result == GCERT_OK) {
      result = gcert_pem_decode(armour, armour_len, back, sizeof back,
          &back_len, label, sizeof label);
    }
    if (result == GCERT_OK && (back_len != sizeof der ||
        gcert_from_gsec(gsec_equal(back, der, sizeof der)) != GCERT_OK)) {
      result = GCERT_ERR_INTERNAL;
    }
    if (result != GCERT_OK) {
      return result;
    }
  }
  /* An IPv6 literal with a `::` and a trailing IPv4, RFC 4291 section 2.2. */
  {
    static const unsigned char want[16] = {
      0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 1
    };
    unsigned char got[16];
    size_t got_len = 0;

    result = gcert_ip_parse("2001:db8::ffff:192.0.2.1", 24, got, &got_len);
    if (result != GCERT_OK || got_len != 16 ||
        gcert_from_gsec(gsec_equal(got, want, 16)) != GCERT_OK) {
      return result == GCERT_OK ? GCERT_ERR_INTERNAL : result;
    }
  }
  /* A wildcard names exactly one label: a SubjectAltName of *.example.com. */
  {
    static const unsigned char san[] = {
      0x30, 0x0f, 0x82, 0x0d, '*', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'
    };
    GCERT_X509 cert;

    memset(&cert, 0, sizeof cert);
    cert.san = san;
    cert.san_len = sizeof san;
    cert.dns_san = 1;
    if (gcert_x509_verify_dns(&cert, "www.example.com", 15, NULL) != GCERT_OK ||
        gcert_x509_verify_dns(&cert, "example.com", 11, NULL) != GCERT_ERR_MISMATCH ||
        gcert_x509_verify_dns(&cert, "a.b.example.com", 15, NULL) != GCERT_ERR_MISMATCH) {
      return GCERT_ERR_INTERNAL;
    }
  }
  /* The revocation decision: revoked refuses, good accepts, nothing refuses
   * unless the policy says otherwise. */
  {
    GCERT_Revocation good = {GCERT_REVOCATION_GOOD, GCERT_REVOCATION_NONE, 0};
    GCERT_Revocation bad = {GCERT_REVOCATION_REVOKED, GCERT_REVOCATION_NONE, 0};
    GCERT_Revocation both[2];
    GCERT_RevocationPolicy soft;

    gcert_revocation_policy_default(&soft);
    soft.soft_fail = 1;
    both[0] = good;
    both[1] = bad;
    if (gcert_revocation_verdict(&good, 1, NULL) != GCERT_OK ||
        gcert_revocation_verdict(both, 2, &soft) != GCERT_ERR_MISMATCH ||
        gcert_revocation_verdict(NULL, 0, NULL) != GCERT_ERR_MISMATCH ||
        gcert_revocation_verdict(NULL, 0, &soft) != GCERT_OK) {
      return GCERT_ERR_INTERNAL;
    }
  }
  return GCERT_OK;
}
