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
 * main routines
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "debsig.h"

static char originID[2048];

char *deb = NULL;
FILE *deb_fs = NULL;

int checkSigExist(const char *name) {
    char buf[16];

    if (name == NULL) {
	ds_printf(DS_LEV_VER, "checkSigExist: NULL values passed");
	return 0;
    }

    snprintf(buf, sizeof(buf) - 1, "_gpg%s", name);

    return findMember(buf);
}

static char *getKeyID (const struct match *mtc) {
    static char buf[2048];
    FILE *ds;
    char *c, *d, *ret = mtc->id;

    if (ret == NULL)
	return NULL;

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
    return ret;
}

static char *getSigKeyID (const char *deb, const char *type) {
    static char buf[2048];
    int pread[2], pwrite[2], len = checkSigExist(type), t;
    pid_t pid;
    FILE *ds_read, *ds_write;
    char *c, *ret = NULL;

    if (!len)
	return NULL;

    /* Fork for gpg, keeping a nice pipe to read/write from.  */
    pipe(pread);pipe(pwrite);
    if (!(pid = fork())) {
	/* Here we go */
	dup2(pread[1],1); close(pread[0]); close(pread[1]);
	dup2(pwrite[0],0); close(pwrite[0]); close(pwrite[1]);
	execl(GPG_PROG, "gpg", GPG_ARGS, "--list-packets", "-q", "-", NULL);
	ds_printf(DS_LEV_ERR, "failed to exec %s", GPG_PROG);
	exit(1);
    }

    /* I like file streams, so sue me :P */
    if ((ds_read = fdopen(pread[0], "r")) == NULL ||
	    (ds_write = fdopen(pwrite[1], "w")) == NULL) {
	ds_printf(DS_LEV_ERR, "error opening file stream for gpg");
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
    if (ferror(ds_write)) {
	ds_printf(DS_LEV_ERR, "error writing to gpg");
	exit(1);
    }
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
    if (ferror(ds_read)) {
	ds_printf(DS_LEV_ERR, "error reading from gpg");
	exit(1);
    }
    fclose(ds_read);
    
    waitpid(pid, NULL, 0);
    if (ret == NULL)
	ds_printf(DS_LEV_VER, "getSigKeyID: failed for %s", type);
    else
	ds_printf(DS_LEV_VER, "getSigKeyID: returning %s", ret);

    return ret;
}

static int gpgVerify(const char *deb, struct match *mtc, const char *tmp_file) {
    char buf[8192], keyring[8192];
    struct stat st;

    /* If we have an ID for this match, check to make sure it exists, and
     * matches the signature we are about to check.  */
    if (mtc->id) {
	char *m_id = getKeyID(mtc);
	char *d_id = getSigKeyID(deb, mtc->name);
	if (m_id == NULL || d_id == NULL || strcmp(m_id, d_id))
	    return 0;
    }

    snprintf(keyring, sizeof(keyring) - 1, DEBSIG_KEYRINGS_FMT, originID, mtc->file);
    if (stat(keyring, &st))
	return 0;

    /* XXX: remove ar usage */
    snprintf(buf, sizeof(buf) - 1, "ar p %s control.tar.gz data.tar.gz | "
	     GPG_PROG" "GPG_ARGS_FMT" --always-trust -q --keyring %s --verify %s - >/dev/null 2>&1",
	     deb, GPG_ARGS, keyring, tmp_file);
    if (system(buf))
	return 0;
    return 1;
}

static int checkGroupRules(struct group *grp, const char *deb) {
    FILE *fg;
    char buf[2048], tmp_file[32];
    int opt_count = 0, t, fd;
    struct match *mtc;

    /* If we don't have any matches, we fail. We don't wont blank,
     * take-all rules. This actually gets checked while we parse the
     * policy file, but we check again for good measure.  */
    if (grp->matches == NULL)
	return 0;

    for (mtc = grp->matches; mtc; mtc = mtc->next) {
	/* This will also position deb_fs to the start of the member */
	int len = checkSigExist(mtc->name);
	/* If the member exists and we reject it, die now. Also, if it
	 * doesn't exist, and we require it, die aswell. */
	if ((!len && mtc->type == REQUIRED_MATCH) ||
		(len && mtc->type == REJECT_MATCH)) {
	    return 0;
	}

	if (!len) continue;

	/* Write it to a temp file */
	strncpy(tmp_file, "/tmp/debsig.XXXXXX", sizeof(tmp_file));
	if ((fd = mkstemp(tmp_file)) == -1 || (fg = fdopen(fd, "w+")) == NULL) {
	    fprintf(stderr, "error creating tmpfile: %s\n", strerror(errno));
	    if (fd != -1) close(fd);
	    return 0;
	}

	t = fread(buf, 1, sizeof(buf), deb_fs);
	while(len > 0) {
	    if (t > len)
		fwrite(buf, 1, len, fg);
	    else
		fwrite(buf, 1, t, fg);
	    len -= t;
	    t = fread(buf, 1, sizeof(buf), deb_fs);
	}

	fclose(fg);

	/* Now, let's check with gpg on this one */
	t = gpgVerify(deb, mtc, tmp_file);
	unlink(tmp_file);

	/* We fail no matter what now. Even if this is an optional match
	 * rule, by now, we know that the sig exists, so we must fail */
	if (!t) {
	    ds_printf(DS_LEV_VER, "checkGroupRules: failed for %s", mtc->name);
	    return 0;
	}

	/* Kick up the count once for checking later */
	if (mtc->type == OPTIONAL_MATCH)
	    opt_count++;
    }

    if (opt_count < grp->min_opt) {
	ds_printf(DS_LEV_VER, "checkGroupRules: opt passed - %d, opt required %d",
		  opt_count, grp->min_opt);
	return 0;
    }
    
    return 1;
}

int main(int argc, char *argv[]) {
    struct policy *pol = NULL;
    char buf[8192], pol_file[8192], *tmpID;
    DIR *pd = NULL;
    struct dirent *pd_ent;
    struct group *grp;

    if (argc != 2) {
	ds_printf(DS_LEV_ERR, "Usage: %s <deb>", argv[0]);
	exit (1);
    }

    deb = argv[1];
    if ((deb_fs = fopen(deb, "r")) == NULL) {
	ds_printf(DS_LEV_ERR, "could not open %s (%s)", deb, strerror(errno));
	exit(1);
    }

    if (!findMember("debian-binary") || !findMember("control.tar.gz") ||
	    !findMember("data.tar.gz")) {
	ds_printf(DS_LEV_ERR, "%s does not appear to be a deb format package", deb);
	exit (1);
    }

    if ((tmpID = getSigKeyID(deb, "origin")) == NULL) {
	fprintf(stderr, "Sig check for %s failed, could not get Origin ID\n", deb);
	exit (1);
    }
    strncpy(originID, tmpID, sizeof(originID));

    /* Now we have an ID, let's check the policy to use */

    snprintf(buf, sizeof(buf) - 1, DEBSIG_POLICIES_DIR_FMT, originID);
    if ((pd = opendir(buf)) == NULL) {
	fprintf(stderr, "Could not open Origin dir %s: %s\n", buf, strerror(errno));
	exit (1);
    }

    while ((pd_ent = readdir(pd)) != NULL && pol == NULL) {
	/* Make sure we have the right name format */
	if (strstr(pd_ent->d_name, ".pol") == NULL)
	    continue;

	/* Now try to parse the file */
	snprintf(pol_file, sizeof(pol_file) - 1, "%s/%s", buf, pd_ent->d_name);
	pol = parsePolicyFile(pol_file);

	if (pol == NULL) continue;

	/* Now let's see if this policy's selection is useful for this .deb  */
	for (grp = pol->sels; grp != NULL; grp = grp->next) {
	    if (!checkGroupRules(grp, deb)) {
		pol = NULL;
		break;
	    }
	}
    }
    closedir(pd);

    if (pol == NULL) {
	/* Damn, can't verify this one */
	fprintf(stderr, "No applicable policies found. Verify failed.\n");
	exit (1);
    }

    /* Now the final test */
    for (grp = pol->vers; grp; grp = grp->next) {
	if (!checkGroupRules(grp, deb)) {
	    fprintf(stderr, "Failed validation.\n");
	    exit(1);
	}
    }

    fprintf(stderr, "Verified using the `%s' (%s) policy in %s.\n", pol->description,
	    pol->name, pol_file);

    /* If we get here, then things passed just fine */
    exit(0);
}
