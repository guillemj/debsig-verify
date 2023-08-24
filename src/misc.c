/*
 * debsig-verify - Debian package signature verification tool
 *
 * Copyright © 2000 Ben Collins <bcollins@debian.org>
 * Copyright © 2014, 2016, 2019, 2021 Guillem Jover <guillem@debian.org>
 *
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/*
 * miscellaneous functions
 */

#include <config.h>

#include <stdarg.h>
#include <stdio.h>

#include "debsig.h"

int ds_debug_level = 1;

void
ds_printf(int level, const char *fmt, ...)
{
    va_list ap;

    if (level >= ds_debug_level) {
	printf("debsig: ");
	va_start(ap, fmt);
	(void) vprintf(fmt, ap);
	va_end(ap);
	printf("\n");
    }
}
