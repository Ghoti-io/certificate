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
 * Password-based decryption shared by encrypted PKCS#8 and PKCS#12.
 * ::gcert_pbe_decrypt accepts PBES2, PBES1, and the PKCS#12 PBE schemes.
 * PBES2 uses the password bytes as given. PBES1 does too. A PKCS#12 PBE
 * object identifier turns the password into UTF-16BE with two trailing
 * zero bytes before the key derivation. The MAC uses that same string.
 */

#ifndef GHOTI_IO_GCERT_PBES2_H
#define GHOTI_IO_GCERT_PBES2_H

#include <ghoti.io/certificate/macros.h>

#include <ghoti.io/certificate/der.h>

#include <stddef.h>

/* A million iterations is a hostile file, not a password. */
#define GCERT_PBES2_ITER_MAX 10000000u

GCERT_Result gcert_pbes2_decrypt(uint32_t iter_max, const GCERT_Der * alg,
    const void * ct,
    size_t ct_len, const void * password, size_t password_len, void * out,
    size_t out_cap, size_t * out_len);

GCERT_Result gcert_pbe_decrypt(uint32_t iter_max, const GCERT_Der * alg,
    const void * ct,
    size_t ct_len, const void * password, size_t password_len, void * out,
    size_t out_cap, size_t * out_len);

GCERT_Result gcert_pkcs7_unpad(unsigned char * buf, size_t n, size_t block,
    size_t * out_len);

GCERT_Result gcert_pkcs12_bmp(const unsigned char * in, size_t n,
    unsigned char * out, size_t * out_len);

GCERT_Result gcert_pkcs12_kdf(uint32_t iter_max, uint32_t id, size_t u,
    size_t v,
    const unsigned char * pass, size_t pass_len, const unsigned char * salt,
    size_t salt_len, uint32_t iterations, unsigned char purpose,
    unsigned char * dk, size_t dk_len);

#endif /* GHOTI_IO_GCERT_PBES2_H */
