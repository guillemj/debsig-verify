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
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>

#include "debsig.h"

char originID[2048];

char *deb = NULL;
FILE *deb_fs = NULL;

char *ver_members[] = { "control.tar.gz", "data.tar.gz", 0 };

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
	int len;

	/* If we have an ID for this match, check to make sure it exists, and
	 * matches the signature we are about to check.  */
	if (mtc->id) {
	    char *m_id = getKeyID(mtc);
	    char *d_id = getSigKeyID(deb, mtc->name);
	    if (m_id == NULL || d_id == NULL || strcmp(m_id, d_id))
		return 0;
	}

	/* This will also position deb_fs to the start of the member */
	len = checkSigExist(mtc->name);

	/* If the member exists and we reject it, die now. Also, if it
	 * doesn't exist, and we require it, die aswell. */
	if ((!len && mtc->type == REQUIRED_MATCH) ||
		(len && mtc->type == REJECT_MATCH)) {
	    return 0;
	}

	/* This would mean this is Optional, so we ignore it for now */
	if (!len) continue;

	/* Write it to a temp file */
	strncpy(tmp_file, "/tmp/debsig.XXXXXX", sizeof(tmp_file));
	if ((fd = mkstemp(tmp_file)) == -1 || (fg = fdopen(fd, "w+")) == NULL) {
	    ds_printf(DS_LEV_ERR, "error creating tmpfile: %s\n", strerror(errno));
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

static void outputVersion(void) {
    fprintf(stderr, "Debsig Program Version - "VERSION"\n");
    fprintf(stderr, "  Signature Version - "SIG_VERSION"\n");
    fprintf(stderr, "  Signature Namespace - "DEBSIG_NS"\n");
    fprintf(stderr, "  Policies Directory - "DEBSIG_POLICIES_DIR"\n");
    fprintf(stderr, "  Keyrings Directory - "DEBSIG_KEYRINGS_DIR"\n");
    return;
}

int main(int argc, char *argv[]) {
    struct policy *pol = NULL;
    char buf[8192], pol_file[8192], *tmpID, *force_file = NULL;
    DIR *pd = NULL;
    struct dirent *pd_ent;
    struct group *grp;
    int i, list_only = 0;

    if (argc < 2)
	goto usage;

    for (i = 1; i < argc && argv[i][0] == '-'; i++) {
	if (!strcmp(argv[i], "-q"))
	    ds_debug_level = DS_LEV_ERR;
	else if (!strcmp(argv[i], "-v"))
	    ds_debug_level = DS_LEV_VER;
	else if (!strcmp(argv[i], "--version")) {
	    outputVersion();
	    /* Make sure we exit non-zero if there are any more args. This
	     * makes sure someone doesn't so something stupid like pass
	     * --version and a .deb, and expect it to return a validation
	     * exit status.  */
	    if (argc > 2)
		exit(1);
	    else
		exit(0);
	} else if (!strcmp(argv[i], "--list-policies")) {
	    /* Just create a list of policies we can use */
	    list_only = 1;
	    ds_printf(DS_LEV_ALWAYS, "Listing usable policies");
	} else if (!strcmp(argv[i], "--use-policy")) {
	    /* We take one arg */
	    force_file = argv[++i];
	    if (i == argc || force_file[0] == '-') {
		ds_printf(DS_LEV_ERR, "--use-policy requires an argument");
		goto usage;
	    }
	} else
	    goto usage;
    }

    if (i + 1 != argc) { /* There should only be one arg left */
usage:
	fprintf(stderr, "Usage: %s [ options ] <deb>\n\n", argv[0]);
	fprintf(stderr, "   -q                  Quiet, only output fatal errors\n");
	fprintf(stderr, "   -v                  Verbose output (mainly debug)\n");
	fprintf(stderr, "   --version           Output version info, and exit\n");
	fprintf(stderr, "   --list-policies     Only list policies that can be used to\n");
	fprintf(stderr, "                       validate this sig. This runs through\n");
	fprintf(stderr, "                       `Selection' block of the policies only.\n");
	fprintf(stderr, "   --use-policy <name> Used in conjunction with the above\n");
	fprintf(stderr, "                       option. This allows you to specify the\n");
	fprintf(stderr, "                       short name of the policy you wish to try.\n");
	exit(1);
    }

    deb = argv[i];
    
    if ((deb_fs = fopen(deb, "r")) == NULL)
	ds_fail_printf("could not open %s (%s)", deb, strerror(errno));

    if (!list_only)
	ds_printf(DS_LEV_INFO, "Starting verification for: %s", deb);

    if (!findMember("debian-binary"))
	goto not_deb;

    for (i = 0; ver_members[i]; i++) {
	if (!findMember(ver_members[i]))
not_deb:
	    ds_fail_printf("%s does not appear to be a deb format package", deb);
    }

    if ((tmpID = getSigKeyID(deb, "origin")) == NULL)
	ds_fail_printf("Origin Signature check failed. This deb might not be signed.\n");

    strncpy(originID, tmpID, sizeof(originID));

    /* Now we have an ID, let's check the policy to use */

    snprintf(buf, sizeof(buf) - 1, DEBSIG_POLICIES_DIR_FMT, originID);
    if ((pd = opendir(buf)) == NULL)
	ds_fail_printf("Could not open Origin dir %s: %s\n", buf, strerror(errno));

    if (list_only)
	ds_printf(DS_LEV_ALWAYS, "  Policies in: %s", buf);

    while ((pd_ent = readdir(pd)) != NULL && (pol == NULL || list_only)) {
	/* Make sure we have the right name format */
	if (strstr(pd_ent->d_name, ".pol") == NULL)
	    continue;

	if (force_file != NULL && strcmp(pd_ent->d_name, force_file))
		continue;

	/* Now try to parse the file */
	snprintf(pol_file, sizeof(pol_file) - 1, "%s/%s", buf, pd_ent->d_name);
	pol = parsePolicyFile(pol_file);

	if (pol == NULL) continue;

	/* Now let's see if this policy's selection is useful for this .deb  */
	for (grp = pol->sels; grp != NULL; grp = grp->next) {
	    if (!checkGroupRules(grp, deb)) {
		clear_policy();
		pol = NULL;
		break;
	    }
	}
	if (pol && list_only) {
	    ds_printf(DS_LEV_ALWAYS, "    Usable: %s", pd_ent->d_name);
	    list_only++;
	}
    }
    closedir(pd);

    if (pol == NULL && list_only <= 1)
	/* Damn, can't verify this one */
	ds_fail_printf("No applicable policies found. Verify failed.\n");

    if (list_only)
	exit(0); /* our job is done */

    /* Now the final test */
    for (grp = pol->vers; grp; grp = grp->next) {
	if (!checkGroupRules(grp, deb))
	    ds_fail_printf("Failed validation for %s.", deb);
    }

    ds_printf(DS_LEV_INFO, "Verified using `%s' (%s)", pol->description,
	    pol->name);
    ds_printf(DS_LEV_INFO, "Used Policy file: %s", pol_file);

    /* If we get here, then things passed just fine */
    exit(0);
}
