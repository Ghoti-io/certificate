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
 * @file names.h
 *
 * Whether a certificate names the thing a caller meant to reach: RFC 9525.
 *
 * A reference identity is what the caller asked for (a host name, an IP
 * address, a URI, a mailbox), and the answer is whether one of the
 * certificate's subjectAltName entries of that **type** matches it. A DNS
 * name never matches an iPAddress entry or the reverse, which is the rule
 * that stops `192.0.2.1` from matching a certificate for a host that merely
 * spells like it.
 *
 * Matching rules, all of them stricter than a text compare:
 *
 * - A DNS name is compared ASCII case-insensitively, without a trailing
 *   dot. A name that is not ASCII, or is longer than 253 bytes, or has a
 *   label longer than 63, or an empty label, is ::GCERT_ERR_INVALID. An
 *   internationalized name is the caller's to turn into A-labels first.
 * - A wildcard is only the whole leftmost label, `*.example.com`. It
 *   matches exactly one label, never zero and never two, and never a
 *   partial label. The labels **after** the `*` must number at least
 *   ::GCERT_NameOptions::wildcard_min_labels (default 2), so `*.com` names
 *   nothing. A list of public suffixes would catch `*.co.uk` as well; this
 *   library has none, so that case is the caller's.
 * - The common name is not consulted unless the caller sets
 *   ::GCERT_NameOptions::common_name_fallback. RFC 9525 removed it.
 * - A URI is compared byte for byte. A mailbox compares its local part byte
 *   for byte and its domain case-insensitively.
 *
 * A caller that matches a name and then makes a trust decision should also
 * pass the leaf through ::gcert_x509_path, which checks the chain; a match
 * here says only that the certificate was issued for the name.
 */

#ifndef GHOTI_IO_GCERT_NAMES_H
#define GHOTI_IO_GCERT_NAMES_H

#include <ghoti.io/certificate/core.h>
#include <ghoti.io/certificate/macros.h>
#include <ghoti.io/certificate/x509.h>

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Default for ::GCERT_NameOptions::wildcard_min_labels. */
#define GCERT_NAME_WILDCARD_MIN_LABELS 2u

/**
 * @brief Knobs for matching a DNS name.
 *
 * @p wildcard_min_labels is how many labels must follow the `*`. 0 means
 * ::GCERT_NAME_WILDCARD_MIN_LABELS, so a zeroed struct is the default.
 * @p common_name_fallback is 1 to compare the subject's commonName when the
 * certificate has no dNSName entries, which RFC 9525 forbids and some old
 * deployments need.
 */
typedef struct GCERT_NameOptions {
  unsigned wildcard_min_labels;  ///< Labels required after the `*`; 0 is the default.
  int common_name_fallback;      ///< Nonzero: use the common name when no dNSName exists.
} GCERT_NameOptions;

/** @brief Fill @p options with the defaults (all of RFC 9525's rules). */
GCERT_API void gcert_name_options_default(GCERT_NameOptions * options);

/**
 * @brief Parse an IPv4 or IPv6 literal.
 *
 * IPv4 is four decimal fields without leading zeros. IPv6 is the textual
 * form of RFC 4291 section 2.2, including one `::` and a trailing IPv4 in
 * the last 32 bits. No brackets, no zone (`%`), no prefix length.
 *
 * @param text The literal.
 * @param len Length of @p text.
 * @param out Receives 4 or 16 bytes, in network order. Not NULL; 16 bytes.
 * @param out_len Receives 4 or 16.
 * @return ::GCERT_OK, or ::GCERT_ERR_INVALID if @p text is not a literal.
 */
GCERT_API GCERT_Result gcert_ip_parse(const char * text, size_t len,
    unsigned char out[16], size_t * out_len);

/**
 * @brief Does a dNSName entry match @p name.
 *
 * @param options NULL for the defaults.
 * @return ::GCERT_OK, ::GCERT_ERR_MISMATCH, or ::GCERT_ERR_INVALID.
 */
GCERT_API GCERT_Result gcert_x509_verify_dns(const GCERT_X509 * cert,
    const char * name, size_t name_len, const GCERT_NameOptions * options);

/**
 * @brief Does an iPAddress entry equal @p addr.
 *
 * @param addr 4 or 16 bytes in network order.
 * @return ::GCERT_OK, ::GCERT_ERR_MISMATCH, or ::GCERT_ERR_INVALID.
 */
GCERT_API GCERT_Result gcert_x509_verify_ip(const GCERT_X509 * cert,
    const void * addr, size_t addr_len);

/**
 * @brief Does a uniformResourceIdentifier entry equal @p uri, byte for byte.
 *
 * @return ::GCERT_OK, ::GCERT_ERR_MISMATCH, or ::GCERT_ERR_INVALID.
 */
GCERT_API GCERT_Result gcert_x509_verify_uri(const GCERT_X509 * cert,
    const char * uri, size_t uri_len);

/**
 * @brief Does an rfc822Name entry name the mailbox @p mailbox.
 *
 * @return ::GCERT_OK, ::GCERT_ERR_MISMATCH, or ::GCERT_ERR_INVALID.
 */
GCERT_API GCERT_Result gcert_x509_verify_email(const GCERT_X509 * cert,
    const char * mailbox, size_t mailbox_len);

/**
 * @brief Match what a caller was given to connect to.
 *
 * An IP literal (see ::gcert_ip_parse) is matched against iPAddress entries
 * only; anything else is a DNS name. A literal in brackets is not one: the
 * caller removes them. This is what a TLS client calls with the host it
 * dialed.
 *
 * @param options For a DNS name; NULL for the defaults.
 * @return ::GCERT_OK, ::GCERT_ERR_MISMATCH, or ::GCERT_ERR_INVALID.
 */
GCERT_API GCERT_Result gcert_x509_verify_host(const GCERT_X509 * cert,
    const char * host, size_t host_len, const GCERT_NameOptions * options);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GCERT_NAMES_H */
