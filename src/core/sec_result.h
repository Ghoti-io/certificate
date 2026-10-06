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
 * The one place a `GSEC_Result` becomes a `GCERT_Result`.
 *
 * The two enums have the same members in the same order, and C converts
 * between enums silently. That is exactly why the conversion is a switch: a
 * member added to one and not the other would otherwise pass through as
 * whatever integer it happened to be. A value outside both is an internal
 * error, not a success.
 */

#ifndef GHOTI_IO_GCERT_SEC_RESULT_H
#define GHOTI_IO_GCERT_SEC_RESULT_H

#include <ghoti.io/certificate/core.h>
#include <ghoti.io/certificate/macros.h>
#include <ghoti.io/security/core.h>

static inline GCERT_Result gcert_from_gsec(GSEC_Result result) {
  switch (result) {
    case GSEC_OK:
      return GCERT_OK;
    case GSEC_ERR_IO:
      return GCERT_ERR_IO;
    case GSEC_ERR_FORMAT:
      return GCERT_ERR_FORMAT;
    case GSEC_ERR_UNSUPPORTED:
      return GCERT_ERR_UNSUPPORTED;
    case GSEC_ERR_LIMIT:
      return GCERT_ERR_LIMIT;
    case GSEC_ERR_CORRUPT:
      return GCERT_ERR_CORRUPT;
    case GSEC_ERR_OOM:
      return GCERT_ERR_OOM;
    case GSEC_ERR_INVALID:
      return GCERT_ERR_INVALID;
    case GSEC_ERR_INTERNAL:
      return GCERT_ERR_INTERNAL;
    case GSEC_ERR_MISMATCH:
      return GCERT_ERR_MISMATCH;
    case GSEC_RESULT_COUNT:
      break;
  }
  return GCERT_ERR_INTERNAL;
}

#endif /* GHOTI_IO_GCERT_SEC_RESULT_H */
