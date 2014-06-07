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

char *ver_members[] = { "debian-binary", "control.tar.gz", "data.tar.gz", 0 };

static char *prog_name = NULL;

static int checkSelRules(struct group *grp, const char *deb) {
    int opt_count = 0;
    struct match *mtc;
    int len;

    for (mtc = grp->matches; mtc; mtc = mtc->next) {

        ds_printf(DS_LEV_VER, "      Processing '%s' key...", mtc->name);

        /* If we have an ID for this match, check to make sure it exists, and
         * matches the signature we are about to check.  */
        if (mtc->id) {
            char *m_id = getKeyID(mtc);
            char *d_id = getSigKeyID(deb, mtc->name);
            if (m_id == NULL || d_id == NULL || strcmp(m_id, d_id))
                return 0;
        }

	/* XXX: If the match doesn't specify an ID, we need to check to
	 * make sure the ID of the signature exists in the keyring
	 * specified, don't we?
	 */

        len = checkSigExist(mtc->name);

        /* If the member exists and we reject it, fail now. Also, if it
         * doesn't exist, and we require it, fail aswell. */
        if ((!len && mtc->type == REQUIRED_MATCH) ||
                (len && mtc->type == REJECT_MATCH)) {
            return 0;
        }
        /* This would mean this is Optional, so we ignore it for now */
        if (!len) continue;

        /* Kick up the count once for checking later */
        if (mtc->type == OPTIONAL_MATCH)
            opt_count++;
    }

    if (opt_count < grp->min_opt) {
        ds_printf(DS_LEV_DEBUG, "checkSelRules: opt passed - %d, opt required %d",
                  opt_count, grp->min_opt);
        return 0;
    }

    return 1;
}


static int verifyGroupRules(struct group *grp, const char *deb) {
    FILE *fp;
    char buf[2048], tmp_sig[32] = {'\0'}, tmp_data[32] = {'\0'};
    int opt_count = 0, t, i, fd;
    struct match *mtc;
    int len;

    /* If we don't have any matches, we fail. We don't want blank,
     * take-all rules. This actually gets checked while we parse the
     * policy file, but we check again for good measure.  */
    if (grp->matches == NULL)
	return 0;

    /* Go ahead and write out our data to a temp file */
    strncpy(tmp_data, "/tmp/debsig-data.XXXXXX", sizeof(tmp_data));
    if ((fd = mkstemp(tmp_data)) == -1 || (fp = fdopen(fd, "w+")) == NULL) {
	ds_printf(DS_LEV_ERR, "error creating temp file %s: %s\n",
		  tmp_data, strerror(errno));
	if (fd != -1) {
	    close(fd);
	    unlink(tmp_data);
	}
	return 0;
    }

    /* Now, let's find all the members we need to check and cat them into a
     * single temp file. This is what we pass to gpg.  */
    for (i = 0; ver_members[i]; i++) {
	if (!(len = findMember(ver_members[i])))
	    goto fail_and_close;
	while(len > 0) {
	    t = fread(buf, 1, sizeof(buf), deb_fs);
	    fwrite(buf, 1, (t > len) ? len : t, fp);
	    len -= t;
	}
    }
    fclose(fp);
    fd = -1;

    for (mtc = grp->matches; mtc; mtc = mtc->next) {

	ds_printf(DS_LEV_VER, "      Processing '%s' key...", mtc->name);

	/* If we have an ID for this match, check to make sure it exists, and
	 * matches the signature we are about to check.  */
	if (mtc->id) {
	    char *m_id = getKeyID(mtc);
	    char *d_id = getSigKeyID(deb, mtc->name);
	    if (m_id == NULL || d_id == NULL || strcmp(m_id, d_id))
		goto fail_and_close;
	}

	/* This will also position deb_fs to the start of the member */
	len = checkSigExist(mtc->name);

	/* If the member exists and we reject it, die now. Also, if it
	 * doesn't exist, and we require it, die aswell. */
	if ((!len && mtc->type == REQUIRED_MATCH) ||
		(len && mtc->type == REJECT_MATCH)) {
	    goto fail_and_close;
	}

	/* This would mean this is Optional, so we ignore it for now */
	if (!len) continue;

	/* let's get our temp file */
	strncpy(tmp_sig, "/tmp/debsig-sig.XXXXXX", sizeof(tmp_sig));
	if ((fd = mkstemp(tmp_sig)) == -1 || (fp = fdopen(fd, "w+")) == NULL) {
	    ds_printf(DS_LEV_ERR, "error creating temp file %s: %s\n",
		      tmp_sig, strerror(errno));
	    goto fail_and_close;
	}

	while(len > 0) {
	    t = fread(buf, 1, sizeof(buf), deb_fs);
	    fwrite(buf, 1, (t > len) ? len : t, fp);
	    len -= t;
	}
	fclose(fp);

	/* Now, let's check with gpg on this one */
	t = gpgVerify(tmp_data, mtc, tmp_sig);

	fd = -1;
	unlink(tmp_sig);

	/* We fail no matter what now. Even if this is an optional match
	 * rule, by now, we know that the sig exists, so we must fail */
	if (!t) {
	    ds_printf(DS_LEV_DEBUG, "verifyGroupRules: failed for %s", mtc->name);
	    goto fail_and_close;
	}

	/* Kick up the count once for checking later */
	if (mtc->type == OPTIONAL_MATCH)
	    opt_count++;
    }

    if (opt_count < grp->min_opt) {
	ds_printf(DS_LEV_DEBUG, "verifyGroupRules: opt passed - %d, opt required %d",
		  opt_count, grp->min_opt);
	goto fail_and_close;
    }

    unlink(tmp_data);
    return 1;

fail_and_close:
    unlink(tmp_data);
    if (fd != -1) {
	close(fd);
	unlink(tmp_sig);
    }
    return 0;
}

static int checkIsDeb(void) {
    int i;
    if (!findMember("debian-binary"))
        return 0;

    for (i = 0; ver_members[i]; i++)
        if (!findMember(ver_members[i]))
	    return 0;

    return 1;
}

static void outputVersion(void) {
    fprintf(stderr, "\
Debsig Program Version - "VERSION"\n\
  Signature Version - "SIG_VERSION"\n\
  Signature Namespace - "DEBSIG_NS"\n\
  Policies Directory - "DEBSIG_POLICIES_DIR"\n\
  Keyrings Directory - "DEBSIG_KEYRINGS_DIR"\n");
    return;
}

static void outputUsage(void) {
        fprintf(stderr, "\
Usage: %s [ options ] <deb>\n\n\
   -q                  Quiet, only output fatal errors\n\
   -v                  Verbose output (mainly debug)\n\
   -d                  Debug output aswell\n\
   --version           Output version info, and exit\n\
   --list-policies     Only list policies that can be used to\n\
                       validate this sig. This runs through\n\
                       'Selection' block of the policies only.\n\
   --use-policy <name> Used in conjunction with the above\n\
                       option. This allows you to specify the\n\
                       short name of the policy you wish to try.\n",
	prog_name);
        exit(1);
}

int main(int argc, char *argv[]) {
    struct policy *pol = NULL;
    char buf[8192], pol_file[8192], *tmpID, *force_file = NULL;
    DIR *pd = NULL;
    struct dirent *pd_ent;
    struct group *grp;
    int i, list_only = 0;

    if ((prog_name = strrchr(argv[0], '/')) == NULL)
	prog_name = strdup(argv[0]);
    else
	prog_name = strdup(prog_name + 1);

    if (argc < 2)
	outputUsage();

    for (i = 1; i < argc && argv[i][0] == '-'; i++) {
	if (!strcmp(argv[i], "-q"))
	    ds_debug_level = DS_LEV_ERR;
	else if (!strcmp(argv[i], "-v"))
	    ds_debug_level = DS_LEV_VER;
	else if (!strcmp(argv[i], "-d"))
	    ds_debug_level = DS_LEV_DEBUG;
	else if (!strcmp(argv[i], "--version")) {
	    outputVersion();
	    /* Make sure we exit non-zero if there are any more args. This
	     * makes sure someone doesn't do something stupid like pass
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
		outputUsage();
	    }
	} else
	    outputUsage();
    }

    if (i + 1 != argc) /* There should only be one arg left */
	outputUsage();

    deb = argv[i];

    if ((deb_fs = fopen(deb, "r")) == NULL)
	ds_fail_printf(DS_FAIL_INTERNAL, "could not open %s (%s)", deb, strerror(errno));

    if (!list_only)
	ds_printf(DS_LEV_VER, "Starting verification for: %s", deb);

    if (!checkIsDeb())
	ds_fail_printf(DS_FAIL_INTERNAL, "%s does not appear to be a deb format package", deb);

    if ((tmpID = getSigKeyID(deb, "origin")) == NULL)
	ds_fail_printf(DS_FAIL_NOSIGS, "Origin Signature check failed. This deb might not be signed.\n");

    strncpy(originID, tmpID, sizeof(originID));

    /* Now we have an ID, let's check the policy to use */

    snprintf(buf, sizeof(buf) - 1, DEBSIG_POLICIES_DIR_FMT, originID);
    if ((pd = opendir(buf)) == NULL)
	ds_fail_printf(DS_FAIL_UNKNOWN_ORIGIN,
		       "Could not open Origin dir %s: %s\n", buf, strerror(errno));

    ds_printf(DS_LEV_VER, "Using policy directory: %s", buf);

    if (list_only)
	ds_printf(DS_LEV_ALWAYS, "  Policies in: %s", buf);

    while ((pd_ent = readdir(pd)) != NULL && (pol == NULL || list_only)) {
	char *ext = strstr(pd_ent->d_name, ".pol");
	/* Make sure we have the right name format */
	if (ext == NULL || (ext - pd_ent->d_name) + 4 != strlen(pd_ent->d_name))
	    continue;

	if (force_file != NULL && strcmp(pd_ent->d_name, force_file))
	    continue;

	/* Now try to parse the file */
	snprintf(pol_file, sizeof(pol_file) - 1, "%s/%s", buf, pd_ent->d_name);
	ds_printf(DS_LEV_VER, "  Parsing policy file: %s", pol_file);
	pol = parsePolicyFile(pol_file);

	if (pol == NULL) continue;

	/* Now let's see if this policy's selection is useful for this .deb  */
	ds_printf(DS_LEV_VER, "    Checking Selection group(s).");
	for (grp = pol->sels; grp != NULL; grp = grp->next) {
	    if (!checkSelRules(grp, deb)) {
		clear_policy();
		ds_printf(DS_LEV_VER, "    Selection group failed checks.");
		pol = NULL;
		break;
	    }
	}

	if (pol && list_only) {
	    ds_printf(DS_LEV_ALWAYS, "    Usable: %s", pd_ent->d_name);
	    list_only++;
	} else if (pol)
	    ds_printf(DS_LEV_VER, "    Selection group(s) passed, policy is usable.");
    }
    closedir(pd);

    if ((pol == NULL && !list_only) || list_only == 1) /* Damn, can't verify this one */
	ds_fail_printf(DS_FAIL_NOPOLICIES, "No applicable policy found.");

    if (list_only)
	exit(0); /* our job is done */

    ds_printf(DS_LEV_VER, "Using policy file: %s", pol_file);

    /* This should actually be caught in the xml-parsing. */
    if (pol->vers == NULL)
	ds_fail_printf(DS_FAIL_NOPOLICIES, "Failed, no Verification groups in policy.");

    /* Now the final test */
    ds_printf(DS_LEV_VER, "    Checking Verification group(s).");

    for (grp = pol->vers; grp; grp = grp->next) {
	if (!verifyGroupRules(grp, deb)) {
	    ds_printf(DS_LEV_VER, "    Verification group failed checks.");
	    ds_fail_printf(DS_FAIL_BADSIG, "Failed verification for %s.", deb);
	}
    }

    ds_printf(DS_LEV_VER, "    Verification group(s) passed, deb is validated.");

    ds_printf(DS_LEV_INFO, "Verified package from '%s' (%s)",
	      pol->description, pol->name);

    /* If we get here, then things passed just fine */
    exit(DS_SUCCESS);
}
