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
 * routines to parse gpg output
 */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdlib.h>

#include "debsig.h"

static int gpg_inited = 0;

/* Crazy damn hack to make sure gpg has created ~/.gnupg, else it will
 * fail first time called */
static void gpg_init(void) {
    if (gpg_inited) return;
    system(GPG_PROG" --options /dev/null < /dev/null > /dev/null 2>&1");
    gpg_inited = 1;
}

char *getKeyID (const struct match *mtc) {
    static char buf[2048];
    FILE *ds;
    char *c, *d, *ret = mtc->id;

    if (ret == NULL)
	return NULL;

    gpg_init();

    snprintf(buf, sizeof(buf) - 1, GPG_PROG" "GPG_ARGS_FMT" --list-packets -q "DEBSIG_KEYRINGS_FMT,
	     GPG_ARGS, originID, mtc->file);

    if ((ds = popen(buf, "r")) == NULL) {
	perror("gpg");
	return NULL;
    }

    c = fgets(buf, sizeof(buf), ds);
    while (c != NULL) {
	if (!strncmp(buf, USER_MAGIC, strlen(USER_MAGIC))) {
	    if ((c = strchr(buf, '"')) == NULL) continue;
	    d = c + 1;
	    if ((c = strchr(d, '"')) == NULL) continue;
	    *c = '\0';
	    if (!strcmp(d, mtc->id)) {
		c = fgets(buf, sizeof(buf), ds);
		if (c == NULL) continue;
		if (!strncmp(buf, SIG_MAGIC, strlen(SIG_MAGIC))) {
		    if ((c = strchr(buf, '\n')) != NULL)
			*c = '\0';
		    d = strstr(buf, "keyid");
		    if (d) {
			ret = d + 6;
			break;
		    }
		}
	    }
	}
	c = fgets(buf, sizeof(buf), ds);
    }

    pclose(ds);

    if (ret == NULL)
	ds_printf(DS_LEV_DEBUG, "        getKeyID: failed for %s", mtc->id);
    else
	ds_printf(DS_LEV_DEBUG, "        getKeyID: mapped %s -> %s", mtc->id, ret);

    return ret;
}

char *getSigKeyID (const char *deb, const char *type) {
    static char buf[2048];
    int pread[2], pwrite[2], t;
    off_t len = checkSigExist(type);
    pid_t pid;
    FILE *ds_read, *ds_write;
    char *c, *ret = NULL;

    if (!len)
	return NULL;

    gpg_init();

    /* Fork for gpg, keeping a nice pipe to read/write from.  */
    pipe(pread);pipe(pwrite);
    /* I like file streams, so sue me :P */
    if ((ds_read = fdopen(pread[0], "r")) == NULL ||
	 (ds_write = fdopen(pwrite[1], "w")) == NULL)
	ds_fail_printf(DS_FAIL_INTERNAL, "error opening file stream for gpg");

    if (!(pid = fork())) {
	/* Here we go */
	dup2(pread[1],1); close(pread[0]); close(pread[1]);
	dup2(pwrite[0],0); close(pwrite[0]); close(pwrite[1]);
	execl(GPG_PROG, "gpg", GPG_ARGS, "--list-packets", "-q", "-", NULL);
	exit(1);
    }
    close(pread[1]); close(pwrite[0]);

    /* First, let's feed gpg our signature. Don't forget, our call to
     * checkSigExist() above positioned the deb_fs file pointer already.  */
    t = fread(buf, 1, sizeof(buf), deb_fs);
    while(len > 0) {
	if (t > len)
	    fwrite(buf, 1, len, ds_write);
	else
	    fwrite(buf, 1, t, ds_write);
	len -= t;
	t = fread(buf, 1, sizeof(buf), deb_fs);
    }
    if (ferror(ds_write))
	ds_fail_printf(DS_FAIL_INTERNAL, "error writing to gpg");
    fclose(ds_write);

    /* Now, let's see what gpg has to say about all this */
    c = fgets(buf, sizeof(buf), ds_read);
    while (c != NULL) {
	if (!strncmp(buf, SIG_MAGIC, strlen(SIG_MAGIC))) {
	    if ((c = strchr(buf, '\n')) != NULL)
		*c = '\0';
	    /* This is the only line we care about */
	    ret = strstr(buf, "keyid");
	    if (ret) {
		ret += 6;
		break;
	    }
	}
	c = fgets(buf, sizeof(buf), ds_read);
    }
    if (ferror(ds_read))
	ds_fail_printf(DS_FAIL_INTERNAL, "error reading from gpg");
    fclose(ds_read);

    waitpid(pid, NULL, 0);
    if (ret == NULL)
	ds_printf(DS_LEV_DEBUG, "        getSigKeyID: failed for %s", type);
    else
	ds_printf(DS_LEV_DEBUG, "        getSigKeyID: got %s for %s key", ret, type);

    return ret;
}

int gpgVerify(const char *data, struct match *mtc, const char *sig) {
    char keyring[8192];
    int status;
    pid_t pid;
    struct stat st;

    gpg_init();

    snprintf(keyring, sizeof(keyring) - 1, DEBSIG_KEYRINGS_FMT, originID, mtc->file);
    if (stat(keyring, &st)) {
	ds_printf(DS_LEV_DEBUG, "gpgVerify: could not stat %s", keyring);
	return 0;
    }

    if (!(pid = fork())) {
	if (DS_LEV_DEBUG < ds_debug_level) {
	    close(0); close(1); close(2);
	}
	execl(GPG_PROG, "gpg", GPG_ARGS, "--keyring",
		keyring, "--verify", sig, data, NULL);
	exit(1);
    }

    waitpid(pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status)) {
	ds_printf(DS_LEV_DEBUG, "gpgVerify: gpg exited abnormally or with non-zero exit status");
	return 0;
    }

    return 1;
}
