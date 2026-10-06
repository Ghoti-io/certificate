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
 * @file trust.h
 *
 * A set of trust anchors.
 *
 * ::gcert_x509_path takes one anchor. A verifier has a list, and has to find
 * which entry could have signed a certificate it was handed. A store holds
 * copies of the certificates, so the caller's buffers can go, and answers
 * "which anchors could be the issuer of this certificate".
 *
 * An anchor here is a certificate that **is a CA**: ::gcert_x509_path
 * refuses an anchor whose basicConstraints says it is not, so a pinned
 * end-entity certificate is not a use this supports, and says so when the
 * path is built rather than when it is added. Adding does not judge: an
 * expired anchor is stored, and refused when a path is validated at a time
 * it is not in force.
 *
 * Everything that reads the operating system's list only enumerates it.
 * What the list means (distrust dates, per-purpose restrictions the
 * platform keeps beside it) is not carried over, and path validation is this
 * library's, never the platform's.
 *
 * A store is not thread-safe while it is being added to. Once nothing adds
 * to it, any number of threads may read it.
 */

#ifndef GHOTI_IO_GCERT_TRUST_H
#define GHOTI_IO_GCERT_TRUST_H

#include <ghoti.io/certificate/allocator.h>
#include <ghoti.io/certificate/core.h>
#include <ghoti.io/certificate/macros.h>
#include <ghoti.io/certificate/x509.h>

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** An opaque set of anchors. */
typedef struct GCERT_TrustStore GCERT_TrustStore;

/**
 * @brief Make an empty store.
 *
 * @param allocator NULL for cutil's default. The store keeps the pointer, so
 *   it must outlive the store.
 * @param limits NULL for the defaults. Copied.
 * @param out Receives the store. Not NULL.
 * @return ::GCERT_OK, ::GCERT_ERR_OOM, or ::GCERT_ERR_INVALID.
 */
GCERT_API GCERT_Result gcert_trust_new(const GCERT_Allocator * allocator,
    const GCERT_Limits * limits, GCERT_TrustStore ** out);

/** @brief Free a store and every anchor in it. NULL is allowed. */
GCERT_API void gcert_trust_free(GCERT_TrustStore * store);

/** @brief The number of anchors held. */
GCERT_API size_t gcert_trust_count(const GCERT_TrustStore * store);

/**
 * @brief Add one DER certificate.
 *
 * Copies it. A certificate already present, byte for byte, is not added
 * twice and is not an error.
 *
 * @return ::GCERT_OK, ::GCERT_ERR_CORRUPT, ::GCERT_ERR_UNSUPPORTED,
 *   ::GCERT_ERR_LIMIT (the store is at ::GCERT_Limits::max_trust_anchors, or the
 *   certificate is over ::GCERT_X509_DER_MAX), ::GCERT_ERR_OOM, or
 *   ::GCERT_ERR_INVALID.
 */
GCERT_API GCERT_Result gcert_trust_add_der(GCERT_TrustStore * store,
    const void * der, size_t len);

/**
 * @brief Add every CERTIFICATE block of a PEM bundle.
 *
 * Blocks with another label (a bundle may carry keys or CRLs) and the text
 * between blocks are skipped without being counted. A CERTIFICATE block that
 * does not decode, or whose certificate this library cannot read (a key or
 * signature algorithm it does not have, an extension it must reject), is
 * counted in @p skipped and **not** an error, because the operating system's
 * own bundles carry a few such entries and one of them must not make the
 * rest unavailable. A caller that wants strictness checks @p skipped is 0.
 * Running out of room is an error and stops the load.
 *
 * @param added Receives how many new anchors were stored. NULL to ignore.
 * @param skipped Receives how many CERTIFICATE blocks were not usable.
 *   NULL to ignore.
 * @return ::GCERT_OK, ::GCERT_ERR_LIMIT, ::GCERT_ERR_OOM, or
 *   ::GCERT_ERR_INVALID.
 */
GCERT_API GCERT_Result gcert_trust_add_pem(GCERT_TrustStore * store,
    const void * pem, size_t len, size_t * added, size_t * skipped);

/**
 * @brief Add the certificates in a file: a PEM bundle, or one DER certificate.
 *
 * The file is read whole, up to ::GCERT_Limits::max_trust_file_bytes. A file
 * that begins with a DER SEQUENCE is one certificate; anything else is read as
 * a bundle. Counts are as for ::gcert_trust_add_pem.
 *
 * @return ::GCERT_OK, ::GCERT_ERR_IO (cannot open or read it),
 *   ::GCERT_ERR_LIMIT (too large), ::GCERT_ERR_OOM, or ::GCERT_ERR_INVALID.
 */
GCERT_API GCERT_Result gcert_trust_add_file(GCERT_TrustStore * store,
    const char * path, size_t * added, size_t * skipped);

/**
 * @brief Add the operating system's roots.
 *
 * On Linux and the other Unix systems this reads the first of these that
 * exists: the file named by SSL_CERT_FILE, then
 * `/etc/ssl/certs/ca-certificates.crt` (Debian, Ubuntu, Alpine),
 * `/etc/pki/tls/certs/ca-bundle.crt` (Fedora, RHEL),
 * `/etc/ssl/ca-bundle.pem` (openSUSE), and `/etc/ssl/cert.pem` (the BSDs,
 * and macOS, which carries its system roots there). The environment variable
 * is honoured only when the caller's process is not setuid, which is
 * tested with `getuid() == geteuid()`. On Windows it enumerates the ROOT
 * system store with `CertEnumCertificatesInStore`.
 *
 * @param added Receives how many new anchors were stored. NULL to ignore.
 * @param skipped Receives how many entries were not usable. NULL to ignore.
 * @return ::GCERT_OK, or ::GCERT_ERR_IO when no source could be read, with
 *   the other results of ::gcert_trust_add_file.
 */
GCERT_API GCERT_Result gcert_trust_add_system(GCERT_TrustStore * store,
    size_t * added, size_t * skipped);

/**
 * @brief The DER of the anchor at @p index.
 *
 * The pointer is valid until the store is freed. Anchors are numbered in
 * the order they were first added, from 0.
 *
 * @return ::GCERT_OK, or ::GCERT_ERR_INVALID if @p index is out of range.
 */
GCERT_API GCERT_Result gcert_trust_get(const GCERT_TrustStore * store, size_t index,
    const unsigned char ** der, size_t * len);

/**
 * @brief Which anchors could have signed @p cert.
 *
 * An anchor is a candidate when its subject is @p cert's issuer, byte for
 * byte. Candidates whose subjectKeyIdentifier equals @p cert's
 * authorityKeyIdentifier come first, then those where either is absent,
 * then those where both are present and differ, because a mismatch is the
 * strongest sign the key is wrong but not proof the certificate is. Only
 * the first @p cap indices are written; @p count says how many candidates
 * there are in all.
 *
 * Nothing is verified here: the caller checks the signature and the rest
 * with ::gcert_x509_signed_by and ::gcert_x509_path, or lets
 * ::gcert_chain_build do it.
 *
 * @param out Indices into the store. NULL only when @p cap is 0.
 * @param count Receives the number of candidates. Not NULL.
 * @return ::GCERT_OK, or ::GCERT_ERR_INVALID.
 */
GCERT_API GCERT_Result gcert_trust_find_issuers(const GCERT_TrustStore * store,
    const GCERT_X509 * cert, size_t * out, size_t cap, size_t * count);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GCERT_TRUST_H */
