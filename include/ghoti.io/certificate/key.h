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
 * @file key.h
 *
 * A private key you can sign with, and the matching check on a certificate.
 *
 * The one place the handshake and this library share a type. A caller loads
 * a key from a file once; the handshake asks it to sign a transcript with a
 * named scheme and never learns whether the key is RSA, ECDSA or Ed25519.
 * The other direction is ::gcert_x509_verify_signature: a peer's
 * CertificateVerify is checked against the certificate's key by scheme, with
 * the key kind dispatched here.
 *
 * Schemes are named by the SignatureScheme code points TLS 1.3 gives them
 * (RFC 8446 section 4.2.3) because those are the names everything else
 * already uses; the numbers mean nothing to this library beyond being
 * distinct. RSA-PSS here is the rsaE variant: an RSA key with the
 * rsaEncryption identifier signing with PSS, which is what certificates
 * carry. A key with the RSASSA-PSS identifier is not read at all.
 *
 * A loaded key holds secret bytes. ::gcert_key_free wipes them. The key
 * object is not thread-safe to free while another thread signs; signing
 * with one key from several threads is.
 */

#ifndef GHOTI_IO_GCERT_KEY_H
#define GHOTI_IO_GCERT_KEY_H

#include <ghoti.io/certificate/allocator.h>
#include <ghoti.io/certificate/core.h>
#include <ghoti.io/certificate/macros.h>
#include <ghoti.io/certificate/x509.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief A signature algorithm, by its TLS 1.3 SignatureScheme code point. */
typedef enum GCERT_SigScheme {
  GCERT_SIG_RSA_PKCS1_SHA256 = 0x0401,   ///< RSASSA-PKCS1-v1_5 with SHA-256; an RSA key.
  GCERT_SIG_ECDSA_P256_SHA256 = 0x0403,  ///< ECDSA with SHA-256; a P-256 key.
  GCERT_SIG_RSA_PKCS1_SHA384 = 0x0501,   ///< RSASSA-PKCS1-v1_5 with SHA-384; an RSA key.
  GCERT_SIG_ECDSA_P384_SHA384 = 0x0503,  ///< ECDSA with SHA-384; a P-384 key.
  GCERT_SIG_RSA_PKCS1_SHA512 = 0x0601,   ///< RSASSA-PKCS1-v1_5 with SHA-512; an RSA key.
  GCERT_SIG_RSA_PSS_SHA256 = 0x0804,     ///< RSASSA-PSS (salt = digest length) with SHA-256; an RSA key.
  GCERT_SIG_RSA_PSS_SHA384 = 0x0805,     ///< RSASSA-PSS with SHA-384; an RSA key.
  GCERT_SIG_RSA_PSS_SHA512 = 0x0806,     ///< RSASSA-PSS with SHA-512; an RSA key.
  GCERT_SIG_ED25519 = 0x0807             ///< Ed25519; an Ed25519 key.
} GCERT_SigScheme;

/** Largest signature ::gcert_key_sign produces, in bytes: a 4096-bit RSA modulus. */
#define GCERT_SIG_MAX 512u

/** @brief An opaque private key. Holds secret bytes; free it with ::gcert_key_free. */
typedef struct GCERT_Key GCERT_Key;

/**
 * @brief Make a key from an unencrypted PKCS#8 PrivateKeyInfo.
 *
 * Copies what it needs, so @p der can be wiped afterwards, and the caller
 * should. An RSA key is checked by signing a fixed message and verifying it,
 * because a PKCS#8 file that was altered can still parse (see
 * ::gcert_pkcs8_decrypt); the ECDSA and Ed25519 keys cannot be checked on
 * their own and are checked against their certificate by
 * ::gcert_key_matches. RSA moduli above 4096 bits and public exponents above
 * 8 bytes are ::GCERT_ERR_UNSUPPORTED.
 *
 * @param allocator NULL for cutil's default. Kept; it must outlive the key.
 * @param out Receives the key. Not NULL.
 * @return ::GCERT_OK, ::GCERT_ERR_CORRUPT, ::GCERT_ERR_UNSUPPORTED,
 *   ::GCERT_ERR_MISMATCH (an RSA key that does not sign what it should),
 *   ::GCERT_ERR_OOM, or ::GCERT_ERR_INVALID.
 */
GCERT_API GCERT_Result gcert_key_from_pkcs8(const GCERT_Allocator * allocator,
    const void * der, size_t len, GCERT_Key ** out);

/**
 * @brief Make a key from the first private key in a PEM file.
 *
 * Blocks that are not private keys (the certificate in a combined file) are
 * skipped. The labels read are PRIVATE KEY, ENCRYPTED PRIVATE KEY (opened
 * with @p password), RSA PRIVATE KEY (PKCS#1) and EC PRIVATE KEY (SEC1,
 * P-256 and P-384). The decoded bytes are wiped before returning.
 *
 * @param password For an encrypted key; NULL only when @p password_len is 0.
 *   An encrypted key with no password is ::GCERT_ERR_INVALID.
 * @param limits NULL for the defaults; caps the work a password-based
 *   encryption may ask for.
 * @return As ::gcert_key_from_pkcs8, and ::GCERT_ERR_FORMAT when the file
 *   holds no private key, ::GCERT_ERR_MISMATCH for a wrong password.
 */
GCERT_API GCERT_Result gcert_key_from_pem(const GCERT_Allocator * allocator,
    const void * pem, size_t len, const void * password, size_t password_len,
    const GCERT_Limits * limits, GCERT_Key ** out);

/** @brief Wipe and free a key. NULL is allowed. */
GCERT_API void gcert_key_free(GCERT_Key * key);

/** @brief The key kind, a ::GCERT_X509_RSA or other key constant; 0 for NULL. */
GCERT_API uint32_t gcert_key_kind(const GCERT_Key * key);

/**
 * @brief Does @p key belong to @p cert.
 *
 * The public key is derived from the private one and compared with the
 * certificate's: modulus and exponent for RSA, the point for the others.
 *
 * @return ::GCERT_OK, ::GCERT_ERR_MISMATCH, or ::GCERT_ERR_INVALID.
 */
GCERT_API GCERT_Result gcert_key_matches(const GCERT_Key * key, const GCERT_X509 * cert);

/**
 * @brief Does @p scheme sign with a key of kind @p kind.
 *
 * @return 1 if so, 0 if not.
 */
GCERT_API int gcert_key_scheme_fits(GCERT_SigScheme scheme, uint32_t kind);

/**
 * @brief Sign @p msg with @p scheme.
 *
 * ECDSA signatures are the DER ECDSA-Sig-Value TLS puts on the wire. RSA-PSS
 * draws its salt from the kernel generator.
 *
 * @param out Signature. At most ::GCERT_SIG_MAX bytes; NULL only when
 *   @p cap is 0. Wiped on failure.
 * @param out_len Receives the length. Not NULL.
 * @return ::GCERT_OK; ::GCERT_ERR_UNSUPPORTED when @p scheme does not fit
 *   the key; ::GCERT_ERR_LIMIT when @p cap is too small; ::GCERT_ERR_IO when
 *   the generator failed; ::GCERT_ERR_INTERNAL; or ::GCERT_ERR_INVALID.
 */
GCERT_API GCERT_Result gcert_key_sign(const GCERT_Key * key, GCERT_SigScheme scheme,
    const void * msg, size_t msg_len, void * out, size_t cap, size_t * out_len);

/**
 * @brief Check a signature over @p msg against @p cert's public key.
 *
 * This is the check on a peer's CertificateVerify, once the certificate has
 * been validated. ECDSA signatures are the DER form; one with a trailing
 * byte, a wrong-width integer or a negative integer is
 * ::GCERT_ERR_MISMATCH, not accepted as the nearest valid one.
 *
 * @return ::GCERT_OK; ::GCERT_ERR_MISMATCH when it does not verify;
 *   ::GCERT_ERR_UNSUPPORTED when @p scheme does not fit the certificate's
 *   key; or ::GCERT_ERR_INVALID.
 */
GCERT_API GCERT_Result gcert_x509_verify_signature(const GCERT_X509 * cert,
    GCERT_SigScheme scheme, const void * msg, size_t msg_len, const void * sig,
    size_t sig_len);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GCERT_KEY_H */
