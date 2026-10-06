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
 * @file pkcs12.h
 *
 * A PKCS#12 PFX, as RFC 7292 specifies it.
 *
 * The password is UTF-8. The MAC turns it into the BMP string RFC 7292
 * requires, including the trailing two zero bytes, then uses the PKCS#12
 * key derivation of Appendix B with id 3 and HMAC. A PBES2 bag and a
 * PBES1 bag use the UTF-8 bytes themselves. A PKCS#12 PBE bag turns the
 * password into the BMP string before deriving the key. A character
 * outside the Basic Multilingual Plane is rejected. A wrong password
 * fails the MAC.
 *
 * Shrouded keys and encrypted cert bags use PBES2, PBES1, or a PKCS#12
 * PBE, including RC2 and RC4. PBES1, RC2, and RC4 are here so an old
 * archive can be opened. A new encrypted bag is PBES2 with AES.
 * **A PFX with no MacData is refused**, ::GCERT_ERR_UNSUPPORTED. RFC 7292
 * makes MacData optional, and an archive without one is unauthenticated:
 * its unencrypted certificate bags can be substituted by anyone who can
 * write the file, and there is no answer this function could return that
 * would not read as "this archive is fine". A caller that has some other
 * reason to trust the bytes can parse them with the PKCS#7 and PKCS#8
 * entry points directly.
 *
 * The key and the certificates are views of @p scratch, or of the input
 * when a bag was not encrypted. At most ::GCERT_PKCS12_CERT_MAX
 * certificates are returned.
 */

#ifndef GHOTI_IO_GCERT_PKCS12_H
#define GHOTI_IO_GCERT_PKCS12_H

#include <ghoti.io/certificate/core.h>
#include <ghoti.io/certificate/macros.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Certificates one call will return. */
#define GCERT_PKCS12_CERT_MAX 8u

/**
 * @brief A private key and the certificates that travelled with it.
 *
 * @p key is a PrivateKeyInfo. Each certificate is a full Certificate.
 */
typedef struct GCERT_Pkcs12 {
  const unsigned char * key;       ///< The PrivateKeyInfo.
  size_t key_len;                  ///< Length of @p key.
  const unsigned char * certs[GCERT_PKCS12_CERT_MAX]; ///< The certificates, each a full Certificate.
  size_t cert_lens[GCERT_PKCS12_CERT_MAX]; ///< Length of each entry of @p certs.
  size_t cert_count;               ///< How many entries of @p certs are filled.
} GCERT_Pkcs12;

/**
 * @brief Open a PFX.
 *
 * @param der PFX bytes. NULL only when @p len is 0.
 * @param len Length of @p der.
 * @param password UTF-8 password. NULL only when @p password_len is 0.
 * @param password_len Length of @p password.
 * @param scratch Space for decrypted bags. Not NULL.
 * @param scratch_cap Capacity of @p scratch. A ciphertext that does not
 *   fit is ::GCERT_ERR_LIMIT. Wiped when the MAC or the padding fails.
 * @param out Views. Not NULL.
 * @param limits NULL for ::gcert_limits_default. An iteration count above
 *   @p limits->max_pbe_iterations is ::GCERT_ERR_LIMIT before any
 *   derivation runs.
 * @return ::GCERT_OK, ::GCERT_ERR_MISMATCH, ::GCERT_ERR_UNSUPPORTED,
 *   ::GCERT_ERR_CORRUPT, ::GCERT_ERR_LIMIT, or ::GCERT_ERR_INVALID.
 */
GCERT_API GCERT_Result gcert_pkcs12_open(const void * der, size_t len,
    const void * password, size_t password_len, void * scratch,
    size_t scratch_cap, GCERT_Pkcs12 * out, const GCERT_Limits * limits);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GCERT_PKCS12_H */
