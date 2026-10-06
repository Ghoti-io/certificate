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
 * Result strings and the default limits.
 *
 * The string table is indexed by the enum. A new result that is not added
 * here falls through to "Unknown error", and the unit test that walks
 * GCERT_RESULT_COUNT rejects that.
 */

#include <ghoti.io/certificate/macros.h>

#include <ghoti.io/certificate/core.h>

#include <string.h>

const char * gcert_result_string(GCERT_Result result) {
  switch (result) {
    case GCERT_OK:
      return "No error";
    case GCERT_ERR_IO:
      return "Input/output error";
    case GCERT_ERR_FORMAT:
      return "Format not recognised";
    case GCERT_ERR_UNSUPPORTED:
      return "Unsupported feature";
    case GCERT_ERR_LIMIT:
      return "Limit exceeded";
    case GCERT_ERR_CORRUPT:
      return "Corrupt input";
    case GCERT_ERR_OOM:
      return "Out of memory";
    case GCERT_ERR_INVALID:
      return "Invalid argument";
    case GCERT_ERR_INTERNAL:
      return "Internal error";
    case GCERT_ERR_MISMATCH:
      return "Verification failed";
    case GCERT_RESULT_COUNT:
      break;
  }
  return "Unknown error";
}

void gcert_limits_default(GCERT_Limits * limits) {
  if (!limits) {
    return;
  }
  memset(limits, 0, sizeof *limits);
  limits->max_pbe_iterations = GCERT_PBE_ITERATIONS_DEFAULT;
  limits->max_trust_anchors = GCERT_TRUST_ANCHORS_DEFAULT;
  limits->max_trust_file_bytes = 16u * 1024u * 1024u;
  limits->max_chain_pool = 32u;
  limits->max_chain_attempts = 256u;
}
