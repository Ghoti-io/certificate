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
 * The operating system's root certificates. Enumeration only: what is read
 * here becomes anchors in a ::GCERT_TrustStore, and gcert_x509_path decides
 * everything else.
 */

#include <ghoti.io/certificate/macros.h>

#include <ghoti.io/certificate/trust.h>

#include <stdlib.h>

#if defined(_WIN32)

#include <windows.h>
#include <wincrypt.h>

GCERT_Result gcert_trust_add_system(GCERT_TrustStore * store, size_t * added,
    size_t * skipped) {
  HCERTSTORE h;
  PCCERT_CONTEXT c = NULL;
  size_t n_added = 0;
  size_t n_skipped = 0;
  GCERT_Result result = GCERT_OK;

  if (added != NULL) {
    *added = 0;
  }
  if (skipped != NULL) {
    *skipped = 0;
  }
  if (store == NULL) {
    return GCERT_ERR_INVALID;
  }
  h = CertOpenSystemStoreA(0, "ROOT");
  if (h == NULL) {
    return GCERT_ERR_IO;
  }
  while ((c = CertEnumCertificatesInStore(h, c)) != NULL) {
    size_t before = gcert_trust_count(store);
    result = gcert_trust_add_der(store, c->pbCertEncoded, c->cbCertEncoded);
    if (result == GCERT_ERR_CORRUPT || result == GCERT_ERR_UNSUPPORTED) {
      n_skipped++;
      result = GCERT_OK;
      continue;
    }
    if (result != GCERT_OK) {
      CertFreeCertificateContext(c);
      break;
    }
    if (gcert_trust_count(store) > before) {
      n_added++;
    }
  }
  CertCloseStore(h, 0);
  if (added != NULL) {
    *added = n_added;
  }
  if (skipped != NULL) {
    *skipped = n_skipped;
  }
  return result;
}

#else

#include <unistd.h>

static const char * const BUNDLES[] = {
  "/etc/ssl/certs/ca-certificates.crt",
  "/etc/pki/tls/certs/ca-bundle.crt",
  "/etc/ssl/ca-bundle.pem",
  "/etc/ssl/cert.pem",
};

GCERT_Result gcert_trust_add_system(GCERT_TrustStore * store, size_t * added,
    size_t * skipped) {
  const char * env;
  size_t i;
  GCERT_Result result = GCERT_ERR_IO;

  if (store == NULL) {
    return GCERT_ERR_INVALID;
  }
  /* A setuid program must not let its caller choose what it trusts. */
  env = getuid() == geteuid() && getgid() == getegid() ? getenv("SSL_CERT_FILE") : NULL;
  if (env != NULL && env[0] != '\0') {
    result = gcert_trust_add_file(store, env, added, skipped);
    if (result != GCERT_ERR_IO) {
      return result;
    }
  }
  for (i = 0; i < sizeof BUNDLES / sizeof BUNDLES[0]; i++) {
    result = gcert_trust_add_file(store, BUNDLES[i], added, skipped);
    if (result != GCERT_ERR_IO) {
      return result;
    }
  }
  return result;
}

#endif
