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
 * The layout of a trust store, shared with the chain builder, which walks
 * the anchors without the copy a public accessor would make.
 */

#ifndef GHOTI_IO_GCERT_TRUST_INT_H
#define GHOTI_IO_GCERT_TRUST_INT_H

#include <ghoti.io/certificate/macros.h>

#include <ghoti.io/certificate/trust.h>

typedef struct Anchor {
  unsigned char * der;
  size_t len;
  GCERT_X509 x;  /* points into der, and points into itself for an ECDSA
                  * signature: the Anchor is allocated once and never moved */
} Anchor;

struct GCERT_TrustStore {
  const GCERT_Allocator * alloc;
  GCERT_Limits limits;
  Anchor ** v;
  size_t n;
  size_t cap;
};

#endif /* GHOTI_IO_GCERT_TRUST_INT_H */
