/*
 * debsig-verify - Debian package signature verification tool
 *
 * Copyright © 2000 Ben Collins <bcollins@debian.org>
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

#include <stdio.h>
#include <stdarg.h>

#include "debsig.h"

int ds_debug_level = 1;

void ds_printf(int level, const char *fmt, ...) {
    va_list ap;
    char buf[8096];

    if (level >= ds_debug_level) {
	va_start(ap, fmt);
	snprintf(buf, sizeof(buf) - 1, "debsig: %s\n", fmt);
	(void) vprintf (buf, ap);
	va_end(ap);
    }

    return;
}

off_t
checkSigExist(const char *name)
{
    char buf[16];

    if (name == NULL) {
	ds_printf(DS_LEV_DEBUG, "checkSigExist: NULL values passed");
	return 0;
    }

    snprintf(buf, sizeof(buf) - 1, "_gpg%s", name);

    return findMember(buf);
}
