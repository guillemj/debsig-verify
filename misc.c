/*
 * debsig-verify - Debian package signature verification tool
 *
 * Copyright (c) 2000 by Ben Collins <bcollins@debian.org>
 *
 * This Program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.
 *
 * This Program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this Program; see the file COPYING.  If not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 */

/* $Id$
 * miscellaneous functions
 */

#include <stdio.h>
#include <stdarg.h>

#include "debsig.h"

int debug_level = 1;

void ds_printf(int level, const char *fmt, ...) {
    va_list ap;
    char buf[8096];

    if (level >= debug_level) {
	va_start(ap, fmt);
	snprintf(buf, sizeof(buf) - 1, "debsig: %s\n", fmt);
	(void) vfprintf (stderr, buf, ap);
	va_end(ap);
    }

    return;
}
