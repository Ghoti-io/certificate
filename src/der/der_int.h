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
 * @file
 *
 * DER helpers shared by PKCS#8 and X.509. Not a public header.
 */

#ifndef GHOTI_IO_GCERT_DER_INT_H
#define GHOTI_IO_GCERT_DER_INT_H

#include <ghoti.io/certificate/macros.h>

#include <ghoti.io/certificate/der.h>

#include <stddef.h>
#include <stdint.h>

int gcert_der_is(const GCERT_Der * v, unsigned tag_class, unsigned constructed,
    unsigned number);

int gcert_der_eq(const unsigned char * a, size_t a_len, const unsigned char * b,
    size_t b_len);

GCERT_Result gcert_der_next(const unsigned char ** p, size_t * left, GCERT_Der * out);

GCERT_Result gcert_der_unsigned(const GCERT_Der * v, const unsigned char ** be,
    size_t * be_len);

GCERT_Result gcert_der_bit_payload(const GCERT_Der * v, const unsigned char ** bits,
    size_t * bits_len);

GCERT_Result gcert_der_oid_ok(const GCERT_Der * v);

int gcert_der_oid_is(const GCERT_Der * v, const unsigned char * oid, size_t oid_len);

GCERT_Result gcert_der_set_sorted(const GCERT_Der * v);

GCERT_Result gcert_der_time(const GCERT_Der * v, int64_t * unix_time);

#endif /* GHOTI_IO_GCERT_DER_INT_H */
