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
 * @file certificate.h
 *
 * Umbrella header for the Ghoti.io Certificate library.
 *
 * The encodings a certificate and its key travel in: strict DER, PEM, PKCS#8
 * including PBES2, PBES1 and the PKCS#12 PBE, PKCS#12, X.509 including path
 * validation and issuance, CRLs, and basic OCSP. The cryptography under them
 * is `security`'s. The handshake is not here. See documentation/design.md.
 */

#ifndef GHOTI_IO_GCERT_CERTIFICATE_H
#define GHOTI_IO_GCERT_CERTIFICATE_H

#include <ghoti.io/certificate/allocator.h>
#include <ghoti.io/certificate/chain.h>
#include <ghoti.io/certificate/core.h>
#include <ghoti.io/certificate/crl.h>
#include <ghoti.io/certificate/der.h>
#include <ghoti.io/certificate/identity.h>
#include <ghoti.io/certificate/key.h>
#include <ghoti.io/certificate/macros.h>
#include <ghoti.io/certificate/names.h>
#include <ghoti.io/certificate/ocsp.h>
#include <ghoti.io/certificate/pem.h>
#include <ghoti.io/certificate/pkcs12.h>
#include <ghoti.io/certificate/pkcs8.h>
#include <ghoti.io/certificate/revocation.h>
#include <ghoti.io/certificate/trust.h>
#include <ghoti.io/certificate/selftest.h>
#include <ghoti.io/certificate/x509.h>

#endif /* GHOTI_IO_GCERT_CERTIFICATE_H */
