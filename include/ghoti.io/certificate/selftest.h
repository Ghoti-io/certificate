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
 * @file selftest.h
 *
 * A known answer for the parts of this library that have a writer.
 *
 * Optional for the caller. It does not print, and it does not return the
 * bytes it used. A failure is a status from the call that failed. The
 * parsers with no writer (PKCS#8, PKCS#12, X.509, CRL, OCSP) have their
 * known answers in the vector files and fixtures, because a fixture compiled
 * into the library would be most of the library's data. This does not run
 * `gsec_selftest`; a caller that wants the primitives checked calls it.
 */

#ifndef GHOTI_IO_GCERT_SELFTEST_H
#define GHOTI_IO_GCERT_SELFTEST_H

#include <ghoti.io/certificate/core.h>
#include <ghoti.io/certificate/macros.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Run the built-in known answers.
 *
 * Covers one DER header and a PEM encode and decode round trip.
 *
 * @return ::GCERT_OK, or the status of the first check that failed.
 */
GCERT_API GCERT_Result gcert_selftest(void);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GCERT_SELFTEST_H */
