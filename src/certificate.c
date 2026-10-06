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
 * Library-wide entry points: the version this build reports.
 */

#include <ghoti.io/certificate/macros.h>

#include <ghoti.io/certificate/core.h>
#include <ghoti.io/certificate/libver.h>

const char * gcert_version_string(void) {
  return GCERT_VERSION_STRING;
}

unsigned gcert_version_number(void) {
  return GCERT_VERSION_NUMBER;
}
