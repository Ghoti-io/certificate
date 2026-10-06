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
 * @file pem.h
 *
 * One PEM block, as RFC 7468 writes it.
 *
 * This lives here until a certificates library takes it. The textual
 * headers are not encrypted. A file that holds several blocks yields the
 * first one. Password-encrypted blocks are still PEM; the bytes inside
 * are whatever the armour carried, and PKCS#8 decides whether it can
 * read them.
 */

#ifndef GHOTI_IO_GCERT_PEM_H
#define GHOTI_IO_GCERT_PEM_H

#include <ghoti.io/certificate/core.h>
#include <ghoti.io/certificate/macros.h>

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Decode the first PEM block.
 *
 * @p label receives the label between BEGIN and END, without a trailing
 * NUL. @p label_cap of 0 skips that copy. The decoded bytes are not a
 * string.
 *
 * @param text The armour, not necessarily NUL-terminated.
 * @param text_len Length of @p text.
 * @param out Decoded bytes. NULL only when @p cap is 0.
 * @param cap Capacity of @p out.
 * @param out_len Receives the decoded length. Not NULL.
 * @param label Label bytes. NULL only when @p label_cap is 0.
 * @param label_cap Capacity of @p label.
 * @return ::GCERT_OK, ::GCERT_ERR_CORRUPT, ::GCERT_ERR_LIMIT, or
 *   ::GCERT_ERR_INVALID.
 */
GCERT_API GCERT_Result gcert_pem_decode(const void * text, size_t text_len,
    void * out, size_t cap, size_t * out_len, char * label, size_t label_cap);

/**
 * @brief Encode one PEM block.
 *
 * The label is the words between BEGIN and END, such as @c CERTIFICATE.
 * The output is not NUL-terminated. Lines are 64 characters, ending in
 * a newline.
 *
 * @param label Label. Not NULL. Empty is rejected.
 * @param der Bytes to armour. NULL only when @p der_len is 0.
 * @param der_len Length of @p der.
 * @param out Armour. NULL only when @p cap is 0.
 * @param cap Capacity of @p out.
 * @param out_len Receives the armour length. Not NULL.
 * @return ::GCERT_OK, ::GCERT_ERR_LIMIT, or ::GCERT_ERR_INVALID.
 */
GCERT_API GCERT_Result gcert_pem_encode(const char * label, const void * der,
    size_t der_len, void * out, size_t cap, size_t * out_len);

#ifdef __cplusplus
}
#endif

#endif /* GHOTI_IO_GCERT_PEM_H */
