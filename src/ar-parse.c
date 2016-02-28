/*
 * debsig-verify - Debian package signature verification tool
 *
 * Copyright © 2000 Ben Collins <bcollins@debian.org>
 * Copyright © 2014 Guillem Jover <guillem@debian.org>
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
 * processes ar style archives (the format of a .deb package)
 */

#include <config.h>

#include <sys/types.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <ar.h>

#include <dpkg/dpkg.h>
#include <dpkg/ar.h>
#include <dpkg/error.h>
#include <dpkg/buffer.h>
#include <dpkg/fdio.h>

#include "debsig.h"

/* This function takes a member name as an argument. It then goes through
 * the archive trying to find it. If it does, it returns the size of the
 * member's data, and leaves the deb_fd file pointer at the start of that
 * data. Yes, we may have a zero length member in here somewhere, but
 * nothing important is going to be zero length anyway, so we treat it as
 * "non-existant".  */
off_t
findMember(struct deb_archive *deb, const char *name)
{
    struct dpkg_error err;
    char magic[SARMAG+1];
    struct ar_hdr arh;
    off_t mem_len;
    ssize_t r;
    size_t len = strlen(name);

    if (len > sizeof(arh.ar_name)) {
	ds_printf(DS_LEV_DEBUG, "findMember: '%s' is too long to be an archive member name",
		  name);
	return 0;
    }

    /* This shouldn't happen, but... */
    if (deb->fd < 0)
	ohshit("findMember: called while deb_fd < 0");

    if (lseek(deb->fd, 0, SEEK_SET) < 0)
	ohshit("findMember: cannot rewind package");

    r = fd_read(deb->fd, magic, SARMAG);
    if (r < 0)
	ohshite("findMember: failure to read package");
    if (r != SARMAG)
	ohshit("findMember: unexpected end of package");

    magic[SARMAG] = '\0';

    /* We will fail in main() with this one */
    if (strcmp(magic, ARMAG) != 0) {
	ds_printf(DS_LEV_DEBUG, "findMember: archive has bad magic");
	return 0;
    }

    for (;;) {
	r = fd_read(deb->fd, &arh, sizeof(arh));
	if (r == 0)
	    return 0;
	if (r < 0)
	    ohshite("findMember: error while parsing archive header");
	if (r != sizeof(arh))
	    ohshit("findMember: unexpected end of package");

	if (dpkg_ar_member_is_illegal(&arh))
	    ohshit("findMember: archive appears to be corrupt, fmag incorrect");

	dpkg_ar_normalize_name(&arh);
	mem_len = dpkg_ar_member_get_size(deb->name, &arh);

	/*
	 * If all looks well, then we return the length of the member, and
	 * leave the file pointer where it is (at the start of the data).
	 * The logic here is based on the ar spec. The ar_name field is
	 * padded with spaces to get the full length. The actual name may
	 * also be suffixed with '/' (dpkg-deb creates .deb's without the
	 * trailing '/' in the member names, but binutils ar does, so we
	 * try to be compatible, like dpkg does). We don't support the
	 * "extended naming" scheme that binutils does.
	 */
	if (strncmp(arh.ar_name, name, len) == 0 &&
	    strnlen(arh.ar_name, sizeof(arh.ar_name)) == len)
	    return mem_len;

	/* Skip to the start of the next member, and try again. */
	if (fd_skip(deb->fd, mem_len + (mem_len & 1), &err) < 0)
	    ohshit("findMember: error while skipping member data: %s", err.str);
    }

    /* well, nothing found, so let's pass on the bad news */
    return 0;
}
