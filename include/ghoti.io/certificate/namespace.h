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
 * @file namespace.h
 *
 * Maps every public name of this library into its version namespace.
 *
 * Kept in one file rather than beside each declaration: a type rename has to
 * be in effect before any struct tag that uses the name, and an internal
 * header may define such a tag without including the public header that
 * declares the typedef.
 *
 * `make check-symbols` fails if an exported symbol is missing from this list.
 *
 * See CONVENTIONS.md section 4.
 */

#ifndef GHOTI_IO_GCERT_NAMESPACE_H
#define GHOTI_IO_GCERT_NAMESPACE_H

#include <ghoti.io/certificate/libver.h>

/// @cond HIDDEN_SYMBOLS

/* Public types and functions. */
#define GCERT_Allocator GHOTIIO_CERTIFICATE(GCERT_Allocator)
#define GCERT_Chain GHOTIIO_CERTIFICATE(GCERT_Chain)
#define GCERT_ChainFailure GHOTIIO_CERTIFICATE(GCERT_ChainFailure)
#define GCERT_Crl GHOTIIO_CERTIFICATE(GCERT_Crl)
#define GCERT_Der GHOTIIO_CERTIFICATE(GCERT_Der)
#define GCERT_Limits GHOTIIO_CERTIFICATE(GCERT_Limits)
#define GCERT_NameOptions GHOTIIO_CERTIFICATE(GCERT_NameOptions)
#define GCERT_Ocsp GHOTIIO_CERTIFICATE(GCERT_Ocsp)
#define GCERT_Pkcs12 GHOTIIO_CERTIFICATE(GCERT_Pkcs12)
#define GCERT_Pkcs8 GHOTIIO_CERTIFICATE(GCERT_Pkcs8)
#define GCERT_Result GHOTIIO_CERTIFICATE(GCERT_Result)
#define GCERT_Revocation GHOTIIO_CERTIFICATE(GCERT_Revocation)
#define GCERT_RevocationPolicy GHOTIIO_CERTIFICATE(GCERT_RevocationPolicy)
#define GCERT_RevocationReason GHOTIIO_CERTIFICATE(GCERT_RevocationReason)
#define GCERT_RevocationStatus GHOTIIO_CERTIFICATE(GCERT_RevocationStatus)
#define GCERT_TrustStore GHOTIIO_CERTIFICATE(GCERT_TrustStore)
#define GCERT_X509 GHOTIIO_CERTIFICATE(GCERT_X509)
#define GCERT_X509_Signer GHOTIIO_CERTIFICATE(GCERT_X509_Signer)
#define GCERT_X509_Tbs GHOTIIO_CERTIFICATE(GCERT_X509_Tbs)

#define gcert_allocator_default GHOTIIO_CERTIFICATE(gcert_allocator_default)
#define gcert_chain_build GHOTIIO_CERTIFICATE(gcert_chain_build)
#define gcert_crl_check GHOTIIO_CERTIFICATE(gcert_crl_check)
#define gcert_crl_contains GHOTIIO_CERTIFICATE(gcert_crl_contains)
#define gcert_crl_parse GHOTIIO_CERTIFICATE(gcert_crl_parse)
#define gcert_crl_signed_by GHOTIIO_CERTIFICATE(gcert_crl_signed_by)
#define gcert_der_tlv GHOTIIO_CERTIFICATE(gcert_der_tlv)
#define gcert_ip_parse GHOTIIO_CERTIFICATE(gcert_ip_parse)
#define gcert_limits_default GHOTIIO_CERTIFICATE(gcert_limits_default)
#define gcert_name_options_default GHOTIIO_CERTIFICATE(gcert_name_options_default)
#define gcert_ocsp_check GHOTIIO_CERTIFICATE(gcert_ocsp_check)
#define gcert_ocsp_parse GHOTIIO_CERTIFICATE(gcert_ocsp_parse)
#define gcert_ocsp_signed_by GHOTIIO_CERTIFICATE(gcert_ocsp_signed_by)
#define gcert_ocsp_status GHOTIIO_CERTIFICATE(gcert_ocsp_status)
#define gcert_pem_decode GHOTIIO_CERTIFICATE(gcert_pem_decode)
#define gcert_pem_encode GHOTIIO_CERTIFICATE(gcert_pem_encode)
#define gcert_pem_next GHOTIIO_CERTIFICATE(gcert_pem_next)
#define gcert_pkcs12_open GHOTIIO_CERTIFICATE(gcert_pkcs12_open)
#define gcert_pkcs8_decrypt GHOTIIO_CERTIFICATE(gcert_pkcs8_decrypt)
#define gcert_pkcs8_parse GHOTIIO_CERTIFICATE(gcert_pkcs8_parse)
#define gcert_random_bytes GHOTIIO_CERTIFICATE(gcert_random_bytes)
#define gcert_result_string GHOTIIO_CERTIFICATE(gcert_result_string)
#define gcert_revocation_policy_default GHOTIIO_CERTIFICATE(gcert_revocation_policy_default)
#define gcert_revocation_verdict GHOTIIO_CERTIFICATE(gcert_revocation_verdict)
#define gcert_selftest GHOTIIO_CERTIFICATE(gcert_selftest)
#define gcert_trust_add_der GHOTIIO_CERTIFICATE(gcert_trust_add_der)
#define gcert_trust_add_file GHOTIIO_CERTIFICATE(gcert_trust_add_file)
#define gcert_trust_add_pem GHOTIIO_CERTIFICATE(gcert_trust_add_pem)
#define gcert_trust_add_system GHOTIIO_CERTIFICATE(gcert_trust_add_system)
#define gcert_trust_count GHOTIIO_CERTIFICATE(gcert_trust_count)
#define gcert_trust_find_issuers GHOTIIO_CERTIFICATE(gcert_trust_find_issuers)
#define gcert_trust_free GHOTIIO_CERTIFICATE(gcert_trust_free)
#define gcert_trust_get GHOTIIO_CERTIFICATE(gcert_trust_get)
#define gcert_trust_new GHOTIIO_CERTIFICATE(gcert_trust_new)
#define gcert_version_number GHOTIIO_CERTIFICATE(gcert_version_number)
#define gcert_version_string GHOTIIO_CERTIFICATE(gcert_version_string)
#define gcert_x509_hostname GHOTIIO_CERTIFICATE(gcert_x509_hostname)
#define gcert_x509_issue GHOTIIO_CERTIFICATE(gcert_x509_issue)
#define gcert_x509_parse GHOTIIO_CERTIFICATE(gcert_x509_parse)
#define gcert_x509_path GHOTIIO_CERTIFICATE(gcert_x509_path)
#define gcert_x509_purpose GHOTIIO_CERTIFICATE(gcert_x509_purpose)
#define gcert_x509_signed_by GHOTIIO_CERTIFICATE(gcert_x509_signed_by)
#define gcert_x509_verify_dns GHOTIIO_CERTIFICATE(gcert_x509_verify_dns)
#define gcert_x509_verify_email GHOTIIO_CERTIFICATE(gcert_x509_verify_email)
#define gcert_x509_verify_host GHOTIIO_CERTIFICATE(gcert_x509_verify_host)
#define gcert_x509_verify_ip GHOTIIO_CERTIFICATE(gcert_x509_verify_ip)
#define gcert_x509_verify_uri GHOTIIO_CERTIFICATE(gcert_x509_verify_uri)

/// @endcond

#endif /* GHOTI_IO_GCERT_NAMESPACE_H */
