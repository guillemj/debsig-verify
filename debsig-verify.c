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


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>


#include <xmlmemory.h>
#include <parser.h>

#define DEBSIG_POLICIES_DIR_FMT DEBSIG_POLICIES_DIR"/%s"
#define DEBSIG_KEYRINGS_FMT DEBSIG_KEYRINGS_DIR"/%s/%s"

#define GPG_PROG "/usr/bin/gpg --no-options --no-default-keyring"

#define SIG_MAGIC ":signature packet:"
#define USER_MAGIC ":user ID packet:"

#define OPTIONAL_MATCH 1
#define REQUIRED_MATCH 2
#define REJECT_MATCH 3

char originID[2048];

struct match {
	struct match *next;
	int type;
	char *name;
	char *file;
	char *id;
	int day_expiry;
};

struct group {
	struct group *next;
	struct match *matches;
	int min_opt;
};

struct policy {
	char *name;
	char *id;
	char *description;
	struct group *sels;
	struct group *vers;
};

struct match *parseMatch (xmlDocPtr doc, xmlNodePtr cur) {
    struct match *ma = NULL, *ret = NULL;
    char *exp;

    cur = cur->xmlChildrenNode;
    while (cur != NULL) {
	if (ma == NULL) {
	    ma = (struct match *) malloc(sizeof(struct match));
	    ret = ma;
	} else {
	    ma->next = (struct match *) malloc(sizeof(struct match));
	    ma = ma->next;
	}
	if (ma == NULL) {
	    fprintf(stderr,"out of memory\n");
	    return(NULL);
	}
	memset(ma, 0, sizeof(struct match));
	
	if (!strcmp(cur->name, "Required"))
	    ma->type = REQUIRED_MATCH;
	else if (!strcmp(cur->name, "Optional"))
	    ma->type = OPTIONAL_MATCH;
	else if (!strcmp(cur->name, "Reject"))
	    ma->type = REJECT_MATCH;
	else {
	    fprintf(stderr,"Unknown match type, %s.\n", cur->name);
	    return NULL;
	}

	if ((ma->name = xmlGetProp(cur, "Type")) == NULL)
	    fprintf(stderr, "Match does not contain a Type.\n");
	if ((ma->file = xmlGetProp(cur, "File")) == NULL &&
		ma->type != REJECT_MATCH)
	    fprintf(stderr,"Opt/Req match does not contain a File.\n");
	if ((exp = xmlGetProp(cur, "Expiry")) != NULL)
	    ma->day_expiry = atoi(exp);
	/* This field is not required */
	ma->id = xmlGetProp(cur, "ID");

	cur = cur->next;
    }

    return ret;
}

struct group *parseGroup(xmlDocPtr doc, xmlNodePtr cur) {
    struct group *ret = NULL;
    char *minm;

    ret = (struct group *) malloc(sizeof(struct group));
    if (ret == NULL) {
        fprintf(stderr,"out of memory\n");
        return(NULL);
    }
    memset(ret, 0, sizeof(struct group));

    if ((minm = xmlGetProp(cur, "MinOptional")) != NULL)
        ret->min_opt = atoi(minm);

    if ((ret->matches = parseMatch(doc, cur)) == NULL)
        return NULL;

    return(ret);
}

struct policy *parsePolicyFile(char *filename) {
    xmlDocPtr doc;
    struct group *ver = NULL, *sel = NULL;
    struct policy *ret;
    xmlNodePtr cur;

    doc = xmlParseFile(filename);
    if (doc == NULL) return(NULL);

    cur = xmlDocGetRootElement(doc);
    if (cur == NULL) {
        fprintf(stderr,"empty document?\n");
	xmlFreeDoc(doc);
	return NULL;
    }
    if (strcmp(cur->name, "Policy")) {
        fprintf(stderr,"of the wrong type, root node != Policy");
	xmlFreeDoc(doc);
	return NULL;
    }

    ret = (struct policy *) malloc(sizeof(struct policy));
    if (ret == NULL) {
        fprintf(stderr,"out of memory\n");
	xmlFreeDoc(doc);
	return NULL;
    }
    memset(ret, 0, sizeof(struct policy));

    cur = cur->xmlChildrenNode;
    while (cur && xmlIsBlankNode(cur))
	cur = cur->next;

    if (cur == NULL) {
	return NULL;
    } else if (strcmp(cur->name, "Origin")) {
	fprintf(stderr, "incorrect format, Origin is not first node\n");
	goto free_fail;
    }

    if ((ret->name = xmlGetProp(cur, "Name")) == NULL) {
	fprintf(stderr, "no Name attribute for Origin node\n");
	goto free_fail;
    } else if ((ret->id = xmlGetProp(cur, "ID")) == NULL) {
	fprintf(stderr, "no ID attribute for Origin node\n");
	goto free_fail;
    }
    ret->description = xmlGetProp(cur, "Description");

    cur = cur->next;
    while (cur != NULL) {
	if (!strcmp(cur->name, "Selection")) {
	    if (ret->sels == NULL)
		ret->sels = sel = parseGroup(doc, cur);
	    else {
		sel->next = parseGroup(doc, cur);
		sel = sel->next;
	    }
	    if (sel == NULL) {
		fprintf(stderr, "failed to parse Selection group\n");
		goto free_fail;
	    }
	} else if (!strcmp(cur->name, "Verification")) {
	    if (ret->vers == NULL)
		ret->vers = ver = parseGroup(doc, cur);
	    else {
		ver->next = parseGroup(doc, cur);
		ver = ver->next;
	    }
	    if (ver == NULL) {
		fprintf(stderr, "failed to parse Verification group\n");
		goto free_fail;
	    }
	}
	cur = cur->next;
    }

    return(ret);

free_fail:
    xmlFreeDoc(doc);
    free(ret);
    return(NULL);

}

char *getKeyID (const struct match *mtc) {
    static char buf[2048];
    FILE *ds;
    char *c, *d, *ret = mtc->id;

    if (ret == NULL)
	return NULL;

    snprintf(buf, sizeof(buf) - 1, GPG_PROG" --list-packets -q "DEBSIG_KEYRINGS_FMT,
	     originID, mtc->file);

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

char *getSigKeyID (const char *deb, const char *type) {
    static char buf[2048];
    FILE *ds;
    char *c, *ret = NULL;

    snprintf(buf, sizeof(buf) - 1, "ar p %s _gpg%s | "GPG_PROG" --list-packets -q -",
	     deb, type);

    if ((ds = popen(buf, "r")) == NULL) {
	perror("ar | gpg");
	return NULL;
    }

    /* :signature packet: algo 17, keyid 7CD73F641E04EC2D */
    c = fgets(buf, sizeof(buf), ds);
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
	c = fgets(buf, sizeof(buf), ds);
    }

    if (pclose(ds)) ret = NULL;
    return ret;
}

int checkNameExist(const char *name, const char *deb, int sig) {
    char buf[2048], file[32];
    FILE *ds;
    char *c;
    int ret = 0;

    snprintf(buf, sizeof(buf) - 1, "ar t %s", deb);
    if ((ds = popen(buf, "r")) == NULL) {
	perror("ar");
	return 0;
    }
   
    if (sig)
	snprintf(file, sizeof(file) - 1, "_gpg%s", name);
    else
	strncpy(file, name, sizeof(file));
    
    c = fgets(buf, sizeof(buf), ds);
    while (c != NULL) {
	if ((c = strchr(buf, '\n')) != NULL)
	    *c = '\0';

	if (!strcmp(buf, file)) {
	    ret = 1;
	    break;
	} else

	c = fgets(buf, sizeof(buf), ds);
    }
    pclose(ds);
    return ret;
}

int gpgVerify(const char *deb, struct match *mtc, const char *tmp_file) {
    char buf[8192], keyring[8192];
    struct stat st;

    if (mtc->id && strcmp(getSigKeyID(deb, mtc->name), getKeyID(mtc)))
	return 0;

    snprintf(keyring, sizeof(keyring) - 1, DEBSIG_KEYRINGS_FMT, originID, mtc->file);
    if (stat(keyring, &st))
	return 0;

    snprintf(buf, sizeof(buf) - 1, "ar p %s control.tar.gz data.tar.gz | "
	     GPG_PROG " --always-trust -q --keyring %s --verify %s - >/dev/null 2>&1",
	     deb, keyring, tmp_file);
    if (system(buf))
	return 0;
    return 1;
}

int checkGroupRules(struct group *grp, const char *deb) {
    FILE *fs, *fg;
    char buf[2048], tmp_file[32];
    int opt_count = 0, t, fd;
    struct match *mtc;

    /* If we don't have any matches, we fail. We don't wont blank,
     * take-all rules */
    if (grp->matches == NULL)
	return 0;

    for (mtc = grp->matches; mtc; mtc = mtc->next) {
	t = checkNameExist(mtc->name, deb, 1);
	/* If the member exists and we reject it, die now. Also, if it
	 * doesn't exist, and we require it, die aswell. */
	if ((!t && mtc->type == REQUIRED_MATCH) ||
		(t && mtc->type == REJECT_MATCH)) {
	    return 0;
	}

	if (!t) continue;

	/* Open a pipe to the sig data */
	snprintf(buf, sizeof(buf) - 1, "ar p %s _gpg%s", deb, mtc->name);
	if ((fs = popen(buf, "r")) == NULL) {
	    fprintf(stderr, "error executing `ar': %s\n", strerror(errno));
	    return 0;
	}

	/* Write it to a temp file */
	strncpy(tmp_file, "/tmp/debsig.XXXXXX", sizeof(tmp_file));
	if ((fd = mkstemp(tmp_file)) == -1 || (fg = fdopen(fd, "w+")) == NULL) {
	    fprintf(stderr, "error creating tmpfile: %s\n", strerror(errno));
	    if (fd != -1) close(fd);
	    return 0;
	}

	t = fread(buf, 1, sizeof(buf), fs);
	while(t) {
	    fwrite(buf, 1, t, fg);
	    t = fread(buf, 1, sizeof(buf), fs);
	}
	if (pclose(fs) == -1) {
	    fprintf(stderr, "error with pipe to `ar'\n");
	    return 0;
	}

	fclose(fg);

	/* Now, let's check with gpg on this one */
	t = gpgVerify(deb, mtc, tmp_file);
	unlink(tmp_file);

	if (!t && mtc->type == REQUIRED_MATCH)
	    return 0;
	if (t && mtc->type == OPTIONAL_MATCH)
	    opt_count++;
    }

    if (opt_count < grp->min_opt)
	return 0;
    
    return 1;
}

#define DEB_MAGIC "!<arch>"
int checkDeb(const char *deb) {
    char buf[32];
    FILE *fs;

    if ((fs = fopen(deb, "r")) == NULL)
	return 0;

    if (fread(buf, 1, strlen(DEB_MAGIC), fs) < strlen(DEB_MAGIC))
	return 0;

    if (memcmp(buf, DEB_MAGIC, strlen(DEB_MAGIC)))
	return 0;
    
    fclose(fs);
    
    if (!checkNameExist("control.tar.gz", deb, 0) ||
	    !checkNameExist("data.tar.gz", deb, 0))
	return 0;

    return 1;
}

int main(int argc, char *argv[]) {
    struct policy *pol = NULL;
    char *deb, buf[8192], pol_file[8192], *tmpID;
    DIR *pd = NULL;
    struct dirent *pd_ent;
    struct group *grp;

    LIBXML_TEST_VERSION
    xmlKeepBlanksDefault(0);

    if (argc != 2) {
	fprintf(stderr, "Usage: %s <deb>\n", argv[0]);
	exit (1);
    }

    deb = argv[1];

    if (!checkDeb(deb)) {
	fprintf(stderr, "%s is not a Debian archive or does not exist\n", deb);
	exit (1);
    }

    if (!checkNameExist("origin", deb, 1)) {
	fprintf(stderr, "%s does not contain an `origin' sig\n", deb);
	exit (1);
    }
    
    if ((tmpID = getSigKeyID(deb, "origin")) == NULL) {
	fprintf(stderr, "Sig check for %s failed, could not get Origin ID\n", deb);
	exit (1);
    }
    strncpy(originID, tmpID, sizeof(originID));

    /* Now we have an ID, let's check check the policy to use */

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
