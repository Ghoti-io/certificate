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
 * @file x509.h
 *
 * An X.509 certificate and a path check, as RFC 5280 specifies them.
 *
 * This lives here until a certificates library takes it. It does not
 * depend on anything but the primitives in this library. The time is a
 * Unix second the caller already decided, not a chron instant. A DNS
 * name is compared as stored: internationalized names are the caller's
 * to turn into A-labels. Revocation is not checked. A critical extension
 * this parser does not understand is rejected. certificatePolicies is
 * read and not enforced. PKCS#12 is not a certificate and is not read
 * here.
 *
 * The pointers in the result address the certificate the caller passed
 * in, except an ECDSA signature, which is copied into the result so the
 * raw r and s have a fixed width. Do not relocate the result without
 * the certificate bytes.
 */

#ifndef GHOTI_IO_GCERT_X509_H
#define GHOTI_IO_GCERT_X509_H

#include <ghoti.io/certificate/core.h>
#include <ghoti.io/certificate/macros.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Largest certificate this parser will read. */
#define GCERT_X509_DER_MAX 65536u

/** Intermediates ::gcert_x509_path will walk, not counting the leaf or the anchor. */
#define GCERT_X509_CHAIN_MAX 16u

/** RSA public key. */
#define GCERT_X509_RSA 1u

/** P-256 public key, x then y. */
#define GCERT_X509_P256 2u

/** P-384 public key, x then y. */
#define GCERT_X509_P384 3u

/** Ed25519 public key. */
#define GCERT_X509_ED25519 4u

/** extendedKeyUsage: anyExtendedKeyUsage. */
#define GCERT_X509_EKU_ANY 0x01u

/** extendedKeyUsage: id-kp-serverAuth. */
#define GCERT_X509_EKU_SERVER_AUTH 0x02u

/** extendedKeyUsage: id-kp-clientAuth. */
#define GCERT_X509_EKU_CLIENT_AUTH 0x04u

/** extendedKeyUsage: id-kp-codeSigning. */
#define GCERT_X509_EKU_CODE_SIGNING 0x08u

/** extendedKeyUsage: id-kp-emailProtection. */
#define GCERT_X509_EKU_EMAIL_PROTECTION 0x10u

/** extendedKeyUsage: id-kp-timeStamping. */
#define GCERT_X509_EKU_TIME_STAMPING 0x20u

/** extendedKeyUsage: id-kp-OCSPSigning. */
#define GCERT_X509_EKU_OCSP_SIGNING 0x40u

/**
 * Smallest RSA modulus ::gcert_x509_path will accept in a chain, in bits.
 * The primitives in rsa.h have a lower floor, because a self-test and a
 * fuzz harness sign with a small key on purpose; a certificate is a trust
 * decision and does not get that latitude.
 */
#define GCERT_X509_RSA_MIN_BITS 2048u

/**
 * @brief A parsed certificate. The view is valid while the DER is.
 *
 * @p key_usage bit 0 is digitalSignature. Bit 5 is keyCertSign.
 *
 * @p eku holds the `GCERT_X509_EKU_*` bits of the purposes named by
 * extendedKeyUsage, @p eku_unknown is 1 when it named a purpose this
 * parser does not have a bit for, and @p eku_critical is 1 when the
 * extension was marked critical. All three are 0 when @p eku_set is 0.
 * ::gcert_x509_purpose is what reads them; the extension used to be
 * syntax-checked and discarded, which meant a critical
 * extendedKeyUsage was accepted and then ignored.
 */
typedef struct GCERT_X509 {
  const unsigned char * tbs;      ///< The signed TBSCertificate, header included.
  size_t tbs_len;                 ///< Length of @p tbs.
  const unsigned char * issuer;   ///< The issuer Name, whole SEQUENCE.
  size_t issuer_len;              ///< Length of @p issuer.
  const unsigned char * subject;  ///< The subject Name, whole SEQUENCE.
  size_t subject_len;             ///< Length of @p subject.
  int64_t not_before;             ///< notBefore, as seconds since 1970-01-01 UTC.
  int64_t not_after;              ///< notAfter, in the same units.
  uint32_t key;                   ///< Subject key kind: ::GCERT_X509_RSA, ::GCERT_X509_P256, ::GCERT_X509_P384 or ::GCERT_X509_ED25519.
  const unsigned char * n;        ///< RSA modulus, when @p key is RSA.
  size_t n_len;                   ///< Length of @p n.
  const unsigned char * e;        ///< RSA public exponent, when @p key is RSA.
  size_t e_len;                   ///< Length of @p e.
  const unsigned char * point;    ///< x then y for a curve key, or the 32-byte Ed25519 public key.
  size_t point_len;               ///< Length of @p point.
  uint32_t sig_key;               ///< Signature key kind, a ::GCERT_X509_RSA or other key constant.
  uint32_t sig_hash;              ///< Signature digest, a ::GSEC_RSA_SHA256 or other id.
  const unsigned char * sig;      ///< The signature bits (for ECDSA, see @p ecdsa_raw).
  size_t sig_len;                 ///< Length of @p sig.
  unsigned char ecdsa_raw[96];    ///< An ECDSA signature as r then s, each zero-padded to the curve's width.
  int ca;                         ///< 1 when basicConstraints sets cA.
  int basic_constraints;          ///< 1 when the certificate has a basicConstraints extension.
  int path_len_set;               ///< 1 when basicConstraints carries pathLenConstraint.
  uint32_t path_len;              ///< pathLenConstraint; meaningful when @p path_len_set is 1.
  int key_usage_set;              ///< 1 when the certificate has a keyUsage extension.
  unsigned key_usage;             ///< keyUsage bits (see above); meaningful when @p key_usage_set is 1.
  const unsigned char * san;      ///< The subjectAltName extension value, or NULL.
  size_t san_len;                 ///< Length of @p san.
  int dns_san;                    ///< 1 when subjectAltName names at least one dNSName.
  const unsigned char * name_constraints; ///< The nameConstraints extension value, or NULL.
  size_t name_constraints_len;    ///< Length of @p name_constraints.
  int eku_set;                    ///< 1 when the certificate has an extendedKeyUsage extension.
  int eku_critical;               ///< 1 when that extension was marked critical.
  int eku_unknown;                ///< 1 when it named a purpose with no bit here.
  unsigned eku;                   ///< The `GCERT_X509_EKU_*` bits it names.
} GCERT_X509;

/**
 * @brief Parse one certificate.
 *
 * @param der DER encoding. NULL only when @p len is 0.
 * @param len Length of @p der. Above ::GCERT_X509_DER_MAX is
 *   ::GCERT_ERR_LIMIT.
 * @param out View. Not NULL.
 * @return ::GCERT_OK, ::GCERT_ERR_CORRUPT, ::GCERT_ERR_UNSUPPORTED,
 *   ::GCERT_ERR_LIMIT, or ::GCERT_ERR_INVALID.
 */
GCERT_API GCERT_Result gcert_x509_parse(const void * der, size_t len,
    GCERT_X509 * out);

/**
 * @brief Check that @p issuer's key signed @p cert.
 *
 * Names and times are not considered, and neither is the strength of the
 * digest: this will verify an MD5 or SHA-1 signature, which is what makes
 * it possible to identify an old certificate and then refuse it for its
 * algorithm. @p cert->sig_hash is the digest that was used.
 * ::gcert_x509_path is the function that applies a policy.
 *
 * @return ::GCERT_OK, ::GCERT_ERR_MISMATCH, or ::GCERT_ERR_INVALID.
 */
GCERT_API GCERT_Result gcert_x509_signed_by(const GCERT_X509 * cert,
    const GCERT_X509 * issuer);

/**
 * @brief Validate a chain from the leaf up to a trust anchor.
 *
 * @p mids are the intermediates, leaf's issuer first and the anchor's
 * subject last. @p mid_count of 0 means the anchor signed the leaf.
 * The anchor is trusted as a CA even when it has no basicConstraints.
 * An anchor that says it is not a CA is rejected. An intermediate must
 * be a CA and, when keyUsage is present, must have keyCertSign. Both
 * ends of the validity period are inclusive. Name constraints on dNSName
 * and directoryName are applied. Any other name-constraint type is
 * ::GCERT_ERR_UNSUPPORTED.
 *
 * What it refuses that RFC 5280's algorithm does not require, each
 * because a caller of this function is making a trust decision and the
 * alternative is that it makes it wrongly:
 *
 * - **A link signed with MD5 or SHA-1** is ::GCERT_ERR_UNSUPPORTED.
 *   Chosen-prefix collisions are practical for both. ::gcert_x509_signed_by
 *   still verifies them, which is how an old certificate is identified
 *   before being refused.
 * - **An RSA key below ::GCERT_X509_RSA_MIN_BITS** anywhere in the chain is
 *   ::GCERT_ERR_UNSUPPORTED.
 * - **The anchor's own validity period** is checked, though RFC 5280 §6.1
 *   treats the anchor as trusted input whose dates are not examined. An
 *   expired root is a thing that happens, and accepting one silently is
 *   worse than the interoperability it buys.
 *
 * @param unix_time The instant to test, as seconds since 1970-01-01 UTC.
 * @param purpose 0, or one ::GCERT_X509_EKU_* bit that the leaf's
 *   extendedKeyUsage must permit. 0 does not check it, which is the right
 *   answer only when the caller checks it with ::gcert_x509_purpose
 *   instead: a certificate issued for e-mail is otherwise a valid TLS
 *   server certificate as far as this function is concerned.
 * @return ::GCERT_OK, ::GCERT_ERR_MISMATCH, ::GCERT_ERR_CORRUPT,
 *   ::GCERT_ERR_UNSUPPORTED, ::GCERT_ERR_LIMIT, or ::GCERT_ERR_INVALID.
 */
GCERT_API GCERT_Result gcert_x509_path(const void * leaf, size_t leaf_len,
    const void * const * mids, const size_t * mid_lens, size_t mid_count,
    const void * anchor, size_t anchor_len, int64_t unix_time,
    unsigned purpose);

/**
 * @brief Report whether @p cert's extendedKeyUsage permits @p purpose.
 *
 * A certificate with no extendedKeyUsage permits every purpose, which is
 * what RFC 5280 says. So does one that names anyExtendedKeyUsage. A
 * certificate that names purposes none of which is @p purpose is
 * ::GCERT_ERR_MISMATCH, and that includes the case where the only purposes
 * it names are ones this parser has no bit for.
 *
 * @param purpose One ::GCERT_X509_EKU_* bit.
 * @return ::GCERT_OK, ::GCERT_ERR_MISMATCH, or ::GCERT_ERR_INVALID.
 */
GCERT_API GCERT_Result gcert_x509_purpose(const GCERT_X509 * cert,
    unsigned purpose);

/**
 * @brief Match a DNS name against the certificate.
 *
 * subjectAltName dNSName entries are tried when any are present.
 * Otherwise the common name is tried. A wildcard is only the entire
 * leftmost label. The comparison is ASCII case-insensitive. A name that
 * is not ASCII does not match.
 *
 * @return ::GCERT_OK, ::GCERT_ERR_MISMATCH, or ::GCERT_ERR_INVALID.
 */
GCERT_API GCERT_Result gcert_x509_hostname(const GCERT_X509 * cert,
    const char * name, size_t name_len);

/**
 * @brief What to put in a certificate, apart from the issuer's key.
 *
 * @p issuer and @p subject are Name values, the whole SEQUENCE. @p serial
 * is the unsigned magnitude, 1 to 20 bytes. @p point is x then y for a
 * curve, or the 32-byte Ed25519 public key. @p dns, when @p dns_len is
 * not 0, is one dNSName. @p ca emits a critical basicConstraints.
 */
typedef struct GCERT_X509_Tbs {
  const void * issuer;     ///< The issuer Name, whole SEQUENCE.
  size_t issuer_len;       ///< Length of @p issuer.
  const void * subject;    ///< The subject Name, whole SEQUENCE.
  size_t subject_len;      ///< Length of @p subject.
  int64_t not_before;      ///< notBefore, as seconds since 1970-01-01 UTC.
  int64_t not_after;       ///< notAfter, in the same units.
  const void * serial;     ///< The serial number, unsigned magnitude.
  size_t serial_len;       ///< Length of @p serial, 1 to 20 bytes.
  uint32_t subject_key;    ///< Subject key kind, a ::GCERT_X509_RSA or other key constant.
  const void * n;          ///< RSA modulus, when the subject key is RSA.
  size_t n_len;            ///< Length of @p n.
  const void * e;          ///< RSA public exponent, when the subject key is RSA.
  size_t e_len;            ///< Length of @p e.
  const void * point;      ///< x then y for a curve key, or the 32-byte Ed25519 public key.
  size_t point_len;        ///< Length of @p point.
  int ca;                  ///< Nonzero to emit a critical basicConstraints with cA set.
  int path_len_set;        ///< Nonzero to include @p path_len in it.
  uint32_t path_len;       ///< pathLenConstraint.
  const void * dns;        ///< One dNSName, when @p dns_len is not 0.
  size_t dns_len;          ///< Length of @p dns.
} GCERT_X509_Tbs;

/**
 * @brief The issuer's private key.
 *
 * @p hash selects the RSA digest. P-256 signs with SHA-256 and P-384 with
 * SHA-384. Ed25519 ignores @p hash. @p d is the private exponent, the
 * scalar, or the Ed25519 seed.
 */
typedef struct GCERT_X509_Signer {
  uint32_t key;        ///< Issuer key kind, a ::GCERT_X509_RSA or other key constant.
  uint32_t hash;       ///< RSA digest id; ignored for the curve and Ed25519 keys.
  const void * n;      ///< RSA modulus, when @p key is RSA.
  size_t n_len;        ///< Length of @p n.
  const void * e;      ///< RSA public exponent, when @p key is RSA.
  size_t e_len;        ///< Length of @p e.
  const void * d;      ///< The private exponent, the scalar, or the Ed25519 seed.
  size_t d_len;        ///< Length of @p d.
} GCERT_X509_Signer;

/**
 * @brief Build a certificate and sign it.
 *
 * The result parses with ::gcert_x509_parse. Extensions are a critical
 * basicConstraints when @p tbs->ca is set, and one dNSName when
 * @p tbs->dns_len is not 0.
 *
 * @param out The certificate. Wiped on failure.
 * @param out_len Receives the certificate length.
 * @return ::GCERT_OK, ::GCERT_ERR_INVALID, ::GCERT_ERR_LIMIT, ::GCERT_ERR_IO,
 *   or ::GCERT_ERR_INTERNAL.
 */
GCERT_API GCERT_Result gcert_x509_issue(const GCERT_X509_Tbs * tbs,
    const GCERT_X509_Signer * signer, void * out, size_t out_cap,
    size_t * out_len);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GCERT_X509_H */
