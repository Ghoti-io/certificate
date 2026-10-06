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
 * @file pkcs8.h
 *
 * An unencrypted PKCS#8 private key.
 *
 * This lives here until a certificates library takes it. The pointers in
 * the result address the caller's buffer. They are the key, so the caller
 * wipes that buffer. A password-encrypted key is opened with
 * ::gcert_pkcs8_decrypt. PKCS#12 is a different encoding.
 *
 * RSA yields the modulus, the public exponent, and the private exponent.
 * P-256 and P-384 yield the scalar. Ed25519 yields the 32-byte seed.
 */

#ifndef GHOTI_IO_GCERT_PKCS8_H
#define GHOTI_IO_GCERT_PKCS8_H

#include <ghoti.io/certificate/core.h>
#include <ghoti.io/certificate/macros.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** RSA modulus, public exponent, and private exponent. */
#define GCERT_PKCS8_RSA 1u

/** P-256 scalar, 32 bytes. */
#define GCERT_PKCS8_P256 2u

/** P-384 scalar, 48 bytes. */
#define GCERT_PKCS8_P384 3u

/** Ed25519 seed, 32 bytes. */
#define GCERT_PKCS8_ED25519 4u

/**
 * @brief Key material viewed inside the PKCS#8 buffer.
 *
 * Unused pointers are NULL and the matching length is 0. The view is
 * valid while the buffer passed to ::gcert_pkcs8_parse is.
 */
typedef struct GCERT_Pkcs8 {
  uint32_t kind;                  ///< ::GCERT_PKCS8_RSA and the others.
  const unsigned char * n;        ///< RSA modulus.
  size_t n_len;                   ///< Length of @p n.
  const unsigned char * e;        ///< RSA public exponent.
  size_t e_len;                   ///< Length of @p e.
  const unsigned char * d;        ///< RSA private exponent.
  size_t d_len;                   ///< Length of @p d.
  const unsigned char * scalar;   ///< Elliptic-curve scalar or Ed25519 seed.
  size_t scalar_len;              ///< Length of @p scalar.
} GCERT_Pkcs8;

/**
 * @brief Parse an unencrypted PrivateKeyInfo.
 *
 * @param der DER bytes. NULL only when @p len is 0.
 * @param len Length of @p der.
 * @param out View. Not NULL. Wiped of its own pointers on failure, which
 *   does not wipe the caller's key buffer.
 * @return ::GCERT_OK, ::GCERT_ERR_CORRUPT, ::GCERT_ERR_UNSUPPORTED, or
 *   ::GCERT_ERR_INVALID.
 */
GCERT_API GCERT_Result gcert_pkcs8_parse(const void * der, size_t len,
    GCERT_Pkcs8 * out);

/**
 * @brief Decrypt an EncryptedPrivateKeyInfo.
 *
 * PBES2 and PBES1 use @p password as given. A PKCS#12 PBE object
 * identifier turns it into UTF-16BE with two trailing zero bytes first.
 * PBES1 and a PKCS#12 PBE are here so an old key can be opened. A new
 * encrypted key is PBES2 with AES.
 * On success @p out holds a PrivateKeyInfo, which ::gcert_pkcs8_parse can
 * read. A wrong password is ::GCERT_ERR_MISMATCH and @p out is wiped. An
 * algorithm this library does not implement is ::GCERT_ERR_UNSUPPORTED.
 *
 * @param der EncryptedPrivateKeyInfo. NULL only when @p len is 0.
 * @param len Length of @p der.
 * @param password Password. NULL only when @p password_len is 0.
 * @param password_len Length of @p password.
 * @param out Buffer for the PrivateKeyInfo. Wiped on failure.
 * @param out_cap Capacity of @p out. It must hold the ciphertext.
 * @param out_len Receives the PrivateKeyInfo length. Not written on failure.
 * **A successful decrypt is not an integrity check.** PBES2 with a CBC
 * cipher, and every PBES1 scheme, carries no MAC. A flipped bit in the
 * ciphertext garbles one block of the plaintext, and when that garbling
 * lands inside a big integer rather than in a tag, a length or the
 * padding, the result still parses and this function returns
 * ::GCERT_OK on a key that is not the key. What ::GCERT_OK means here is
 * that the password was right and the bytes decoded - not that nobody
 * altered the file. A caller that needs the stronger statement wants
 * PKCS#12, whose MAC covers the archive.
 *
 * @param limits NULL for ::gcert_limits_default. An iteration count above
 *   @p limits->max_pbe_iterations is ::GCERT_ERR_LIMIT before any
 *   derivation runs: the count is in the file, so it is an attacker's
 *   number whenever the file is, and the work it asks for is unbounded
 *   otherwise.
 * @return ::GCERT_OK, ::GCERT_ERR_MISMATCH, ::GCERT_ERR_UNSUPPORTED,
 *   ::GCERT_ERR_CORRUPT, ::GCERT_ERR_LIMIT, or ::GCERT_ERR_INVALID.
 */
GCERT_API GCERT_Result gcert_pkcs8_decrypt(const void * der, size_t len,
    const void * password, size_t password_len, void * out, size_t out_cap,
    size_t * out_len, const GCERT_Limits * limits);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GCERT_PKCS8_H */
