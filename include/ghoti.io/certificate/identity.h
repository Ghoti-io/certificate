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
 * @file identity.h
 *
 * What a certificate says about who holds it: the entries of its
 * subjectAltName, and the attributes of its subject or issuer name.
 *
 * This reports and does not decide. Whether `CN=alice` or a URI of
 * `spiffe://example.org/web` is someone the caller wants to talk to is the
 * caller's policy, and so is which attribute to look at. What this adds to
 * reading the bytes yourself is that the walk is strict (a malformed entry
 * is an error, not a skipped one), and that the strings it hands back are
 * ones it will vouch for the encoding of.
 *
 * Matching a certificate against a name you were *given* is names.h. This is
 * for the other direction, where the certificate is what you were given: a
 * client certificate in mutual TLS.
 *
 * The pointers address the certificate's DER, which the caller keeps alive.
 */

#ifndef GHOTI_IO_GCERT_IDENTITY_H
#define GHOTI_IO_GCERT_IDENTITY_H

#include <ghoti.io/certificate/core.h>
#include <ghoti.io/certificate/macros.h>
#include <ghoti.io/certificate/x509.h>

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** GeneralName choice: otherName. The value is its content, undecoded. */
#define GCERT_SAN_OTHER 0u
/** GeneralName choice: rfc822Name, an ASCII mailbox. */
#define GCERT_SAN_EMAIL 1u
/** GeneralName choice: dNSName, ASCII. */
#define GCERT_SAN_DNS 2u
/** GeneralName choice: x400Address. The value is its content, undecoded. */
#define GCERT_SAN_X400 3u
/** GeneralName choice: directoryName. The value is the Name's content, undecoded. */
#define GCERT_SAN_DIRECTORY 4u
/** GeneralName choice: ediPartyName. The value is its content, undecoded. */
#define GCERT_SAN_EDI 5u
/** GeneralName choice: uniformResourceIdentifier, ASCII. */
#define GCERT_SAN_URI 6u
/** GeneralName choice: iPAddress, 4 or 16 bytes (or 8 or 32 in a constraint). */
#define GCERT_SAN_IP 7u
/** GeneralName choice: registeredID. The value is the OID's content. */
#define GCERT_SAN_REGISTERED_ID 8u

/** @brief An attribute of a distinguished name. */
typedef enum GCERT_NameAttr {
  GCERT_ATTR_COMMON_NAME = 1,   ///< 2.5.4.3
  GCERT_ATTR_COUNTRY,           ///< 2.5.4.6
  GCERT_ATTR_LOCALITY,          ///< 2.5.4.7
  GCERT_ATTR_STATE,             ///< 2.5.4.8
  GCERT_ATTR_ORGANIZATION,      ///< 2.5.4.10
  GCERT_ATTR_ORG_UNIT,          ///< 2.5.4.11
  GCERT_ATTR_SERIAL_NUMBER,     ///< 2.5.4.5, the subject's own, not the certificate's
  GCERT_ATTR_EMAIL,             ///< 1.2.840.113549.1.9.1
  GCERT_ATTR_DOMAIN_COMPONENT   ///< 0.9.2342.19200300.100.1.25
} GCERT_NameAttr;

/**
 * @brief Step through the subjectAltName.
 *
 * Start with @p *cursor of 0 and call again with the same variable until the
 * result is ::GCERT_ERR_FORMAT, which here means there are no more entries.
 * Every entry is reported, including the kinds this library does not
 * interpret (the value is then the entry's content, whole). A certificate
 * with no subjectAltName has no entries.
 *
 * @param choice Receives the entry's `GCERT_SAN_*` choice number.
 * @param value Receives the entry's value; for the ASCII kinds, the string
 *   (not NUL-terminated; embedded NULs and non-ASCII bytes are the caller's
 *   to refuse, and names.h does).
 * @param len Receives its length.
 * @return ::GCERT_OK; ::GCERT_ERR_FORMAT at the end; ::GCERT_ERR_CORRUPT when
 *   the extension is malformed; or ::GCERT_ERR_INVALID.
 */
GCERT_API GCERT_Result gcert_x509_san_next(const GCERT_X509 * cert, size_t * cursor,
    unsigned * choice, const unsigned char ** value, size_t * len);

/**
 * @brief Find an attribute in a Name.
 *
 * @p name is a certificate's @p subject or @p issuer, the whole SEQUENCE.
 * Attributes are visited in the order they are encoded, which is from the
 * most general (country) to the most specific, across a multi-valued RDN as
 * well; @p index picks the nth match, from 0.
 *
 * The string comes back only if its encoding is one this can promise: UTF8String,
 * PrintableString or IA5String, which are UTF-8 or ASCII as they sit. The older
 * encodings (TeletexString, BMPString, UniversalString) are
 * ::GCERT_ERR_UNSUPPORTED rather than returned as bytes that mean something
 * else.
 *
 * @param value Receives the string, not NUL-terminated.
 * @param len Receives its length.
 * @return ::GCERT_OK; ::GCERT_ERR_FORMAT when there is no such attribute;
 *   ::GCERT_ERR_UNSUPPORTED for an encoding it will not return;
 *   ::GCERT_ERR_CORRUPT; or ::GCERT_ERR_INVALID.
 */
GCERT_API GCERT_Result gcert_x509_name_attr(const unsigned char * name, size_t name_len,
    GCERT_NameAttr attr, size_t index, const unsigned char ** value, size_t * len);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GCERT_IDENTITY_H */
