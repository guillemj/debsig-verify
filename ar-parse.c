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
 * processes ar style archives (the format of a .deb package)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <ar.h>

#include "debsig.h"

/* borrowed from dpkg */
static unsigned long parseLength(const char *inh, size_t len) {
    char buf[16];
    unsigned long r;
    char *endp;

    if (memchr(inh, 0, len))
	ds_printf(DS_LEV_ERR, "parseLength: member lenght contains NULL's");

    assert(sizeof(buf) > len);
    memcpy(buf, inh, len);
    buf[len]= ' ';
    *strchr(buf,' ') = 0;
    r = strtoul(buf,&endp,10);

    if (*endp) {
	ds_printf(DS_LEV_ERR,"parseLength: archive is corrupt - bad digit `%c' member length",
		  *endp);
	return -1;
    }

    return r;
}

/* This function takes a member name as an argument. It then goes throught
 * the archive trying to find it. If it does, it returns the size of the
 * member's data, and leaves the deb_fs file pointer at the start of that
 * data. Yes, we may have a zero length member in here somewhere, but
 * nothing important is going to be zero length anyway.
 */
size_t findMember(const char *name) {
    char magic[SARMAG+1];
    struct ar_hdr arh;
    long mem_len;
    int len = strlen(name);
/*
    ds_printf(DS_LEV_VER, "findMember: checking for archive member `%s'", name);
 */
    if (len > sizeof(arh.ar_name)) {
	ds_printf(DS_LEV_ERR, "findMember: `%s' is too long to be an archive member name",
		  name);
	return 0;
    }
    
    /* This shouldn't happen, but... */
    if (deb_fs == NULL) {
	ds_printf(DS_LEV_ERR, "findMember: called while deb_fs == NULL");
	exit(1);
    }

    rewind(deb_fs);
    
    if (!fgets(magic,sizeof(magic),deb_fs)) {
	ds_printf(DS_LEV_ERR, "findMember: failure to read package (%s)",
		  strerror(errno));
	exit(1);
    }

    if (strcmp(magic,ARMAG)) {
	ds_printf(DS_LEV_VER, "findMember: archive has bad magic");
	exit(1);
    }

    while(!feof(deb_fs)) {
	if (fread(&arh, 1, sizeof(arh),deb_fs) != sizeof(arh)) {
	    if (ferror(deb_fs)) {
		ds_printf(DS_LEV_ERR, "findMember: error while parsing archive header (%s)",
			  strerror(errno));
		exit(1);
	    }
	    return 0;
	}

	if (memcmp(arh.ar_fmag, ARFMAG, sizeof(arh.ar_fmag))) {
	    ds_printf(DS_LEV_ERR, "findMember: archive appears to be corrupt, fmag incorrect");
	    exit(1);
	}

	if ((mem_len = parseLength(arh.ar_size, sizeof(arh.ar_size))) < 0) {
	    ds_printf(DS_LEV_ERR, "findMember: archive appears to be corrupt, negative member length");
	    return 0;
	}

	/*
	 * If all looks well, then we return the length of the member, and
	 * leave the file pointer where it is (at the start of the data).
	 * The logic here is based on the ar spec. The ar_name field is
	 * padded with spaces to get the full lenght. The actual name may
	 * also be suffixed with '/' (dpkg-deb creates .deb's without the
	 * trailing '/' in the member names, but binutils ar does, so we
	 * try to be compatible, like dpkg does).
	 */
	if (!strncmp(arh.ar_name, name, len) && (len == sizeof(arh.ar_name) ||
		    arh.ar_name[len] == '/' || arh.ar_name[len] == ' '))
	    return (size_t)mem_len;

	/* fseek to the start of the next member, and try again */
	if (fseek(deb_fs, mem_len + (mem_len & 1), SEEK_CUR) == -1 && ferror(deb_fs)) {
	    ds_printf(DS_LEV_ERR, "findMember: error during file seek (%s)", strerror(errno));
	    return 0;
	}
    }

    /* well, nothing found, so let's pass on the bad news */
    return 0;
}
