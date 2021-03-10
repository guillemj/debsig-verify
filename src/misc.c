/*
 * debsig-verify - Debian package signature verification tool
 *
 * Copyright © 2000 Ben Collins <bcollins@debian.org>
 * Copyright © 2014, 2016 Guillem Jover <guillem@debian.org>
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

#include <sys/stat.h>

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <dpkg/ehandle.h>
#include <dpkg/varbuf.h>

#include "debsig.h"

int ds_debug_level = 1;

void
ds_printf(int level, const char *fmt, ...)
{
    va_list ap;
    char buf[8096];

    if (level >= ds_debug_level) {
	va_start(ap, fmt);
	snprintf(buf, sizeof(buf) - 1, "debsig: %s\n", fmt);
	(void) vprintf(buf, ap);
	va_end(ap);
    }
}

bool
find_command(const char *prog)
{
    struct varbuf filename = VARBUF_INIT;
    struct stat stab;
    const char *path_list;
    const char *path, *path_end;
    size_t path_len;

    path_list = getenv("PATH");
    if (!path_list)
      ohshit("PATH is not set");

    for (path = path_list; path; path = *path_end ? path_end + 1 : NULL) {
        path_end = strchrnul(path, ':');
        path_len = (size_t)(path_end - path);

        varbuf_reset(&filename);
        varbuf_add_buf(&filename, path, path_len);
        if (path_len)
            varbuf_add_char(&filename, '/');
        varbuf_add_str(&filename, prog);
        varbuf_end_str(&filename);

        if (stat(filename.buf, &stab) == 0 && (stab.st_mode & 0111)) {
            varbuf_destroy(&filename);
            return true;
        }
    }

    varbuf_destroy(&filename);
    return false;
}
