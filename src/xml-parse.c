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
 * provides the XML parsing code for policy files, via expat (xmltok)
 */

#include <config.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <sys/stat.h>
#include <obstack.h>

#include <dpkg/dpkg.h>
#include <xmltok/xmlparse.h>

#include "debsig.h"

#define obstack_chunk_alloc m_malloc
#define obstack_chunk_free free

static int parse_err_cnt;
static struct policy ret;
static struct group *cur_grp = NULL;
static XML_Parser parser;
static struct obstack deb_obs;
static int deb_obs_init = 0;

#define parse_error(fmt, args...) \
{ \
    parse_err_cnt++; \
    ds_printf(DS_LEV_DEBUG , "%d: " fmt , XML_GetCurrentLineNumber(parser) , ## args); \
}

static void
startElement(void *userData, const char *name, const char **atts)
{
    int i, depth;
    int *depthPtr = userData;

    /* save the current and increment the userdata */
    depth = *depthPtr;
    *depthPtr = depth + 1;

    if (strcmp(name, "Policy") == 0) {
	if (depth != 0)
	    parse_error("policy parse error: 'Policy' found at wrong level");

	for (i = 0; atts[i]; i += 2) {
	    if (strcmp(atts[i], "xmlns") == 0) {
		if (strcmp(atts[i + 1], DEBSIG_NAMESPACE) != 0)
		    parse_error("policy name space != " DEBSIG_NAMESPACE);
	    } else
		parse_error("Policy element contains unknown attribute '%s'",
			     atts[i]);
	}
    } else if (strcmp(name, "Origin") == 0) {
	if (depth != 1)
	    parse_error("policy parse error: 'Origin' found at wrong level");
	
	for (i = 0; atts[i]; i += 2) {
	    if (strcmp(atts[i], "id") == 0)
		ret.id = obstack_copy0(&deb_obs, atts[i + 1], strlen(atts[i + 1]));
	    else if (strcmp(atts[i], "Name") == 0)
		ret.name = obstack_copy0(&deb_obs, atts[i + 1], strlen(atts[i + 1]));
	    else if (strcmp(atts[i], "Description") == 0)
		ret.description = obstack_copy0(&deb_obs, atts[i + 1], strlen(atts[i + 1]));
	    else
		parse_error("Origin element contains unknown attribute '%s'",
			     atts[i]);
	}

	if (ret.id == NULL || ret.name == NULL)
	    parse_error("Origin element missing Name or ID attribute");
    } else if (strcmp(name, "Selection") == 0 ||
	       strcmp(name, "Verification") == 0) {
	struct group *g = NULL;

	if (depth != 1)
	    parse_error("policy parse error: 'Selection/Verification' found at wrong level");

	/* create a new entry, make it the current */
	cur_grp = (struct group *)obstack_alloc(&deb_obs, sizeof(struct group));
	if (cur_grp == NULL)
	    ohshit("out of memory");
	memset(cur_grp, 0, sizeof(struct group));

	if (strcmp(name, "Selection") == 0) {
	    if (ret.sels == NULL)
		ret.sels = cur_grp;
	    else
		g = ret.sels;
	} else {
	    if (ret.vers == NULL)
		ret.vers = cur_grp;
	    else
		g = ret.vers;
	}
	if (g) {
	    for ( ; g->next; g = g->next)
		; /* find the end of the chain */
	    g->next = cur_grp;
	}

	for (i = 0; atts[i]; i += 2) {
	    if (strcmp(atts[i], "MinOptional") == 0) {
		int t;
		const char *c = atts[i + 1];

		for (t = 0; c[t]; t++) {
		    if (!isdigit(c[t]))
			parse_error("MinOptional requires a numerical value");
		}
		cur_grp->min_opt = atoi(c);
	    } else {
		parse_error("Selection/Verification element contains unknown attribute '%s'",
			     atts[i]);
	    }
	}
    } else if (strcmp(name, "Required") == 0 ||
	       strcmp(name, "Reject") == 0||
	       strcmp(name, "Optional") == 0) {
	struct match *m = NULL, *cur_m = NULL;

	if (depth != 2)
	    parse_error("policy parse error: Match element found at wrong level");

	/* This should never happen with the other checks in place */
	if (cur_grp == NULL) {
	    parse_error("policy parse error: No current group for match element");
	    return;
	}

        /* create a new entry, make it the current */
        cur_m = (struct match *)obstack_alloc(&deb_obs, sizeof(struct match));
        if (cur_m == NULL)
            ohshit("out of memory");
        memset(cur_m, 0, sizeof(struct match));

	if (cur_grp->matches == NULL)
	    cur_grp->matches = cur_m;
	else {
	    for (m = cur_grp->matches; m->next; m = m->next)
		; /* find the end of the chain */
	    m->next = cur_m;
	}

	/* Set the attributes first, so we can sanity check the type after */
        for (i = 0; atts[i]; i += 2) {
            if (strcmp(atts[i], "Type") == 0) {
                cur_m->name = obstack_copy0(&deb_obs, atts[i + 1], strlen(atts[i + 1]));
	    } else if (strcmp(atts[i], "File") == 0) {
		cur_m->file = obstack_copy0(&deb_obs, atts[i + 1], strlen(atts[i + 1]));;
	    } else if (strcmp(atts[i], "id") == 0) {
		cur_m->id = obstack_copy0(&deb_obs, atts[i + 1], strlen(atts[i + 1]));;
	    } else if (strcmp(atts[i], "Expiry") == 0) {
		int t;
		const char *c = atts[i + 1];

		for (t = 0; c[t]; t++) {
		    if (!isdigit(c[t]))
			parse_error("Expiry requires a numerical value");
		}
                cur_m->day_expiry = atoi(c);
            } else {
                parse_error("Match element contains unknown attribute '%s'",
                             atts[i]);
            }
        }


        if (strcmp(name, "Required") == 0) {
	    cur_m->type = REQUIRED_MATCH;
	    if (cur_m->name == NULL || cur_m->file == NULL)
		parse_error("Required must have a Type and File attribute");
	} else if (strcmp(name, "Optional") == 0) {
	    cur_m->type = OPTIONAL_MATCH;
	    if (cur_m->name == NULL || cur_m->file == NULL)
		parse_error("Optional must have a Type and File attribute");
	} else { /* Reject */
	    cur_m->type = REJECT_MATCH;
	    if (cur_m->name == NULL)
		parse_error("Reject must have a Type attribute");
	}
    }
}

static void
endElement(void *userData, const char *name)
{
    int *depthPtr = userData;
    *depthPtr -= 1;

    if (strcmp(name, "Selection") == 0 || strcmp(name, "Verification") == 0) {
	struct match *m;
	int i = 0;

	/* sanity check this block */
	for (m = cur_grp->matches; m; m = m->next) {
	    if (m->type == OPTIONAL_MATCH ||
		m->type == REQUIRED_MATCH)
		i++;
	}
	if (!i) {
	    parse_error("Selection/Verification block does not contain any "
			 "Required or Optional matches.");
	}
	cur_grp = NULL; /* just to make sure */
    }
}

void
clear_policy(void)
{
    if (deb_obs_init) {
	obstack_free(&deb_obs, 0);
	deb_obs_init = 0;
    }
    memset(&ret, '\0', sizeof(struct policy));
}

struct policy *
parsePolicyFile(const char *filename)
{
    char buf[BUFSIZ];
    int done, depth = 0;
    FILE *pol_fs;
    struct stat st;

    /* clear and initialize */
    parser = XML_ParserCreate(NULL);
    //clear_policy();
    obstack_init(&deb_obs);
    deb_obs_init = 1;

    ds_printf(DS_LEV_DEBUG, "    parsePolicyFile: parsing '%s'", filename);

    pol_fs = fopen(filename, "r");
    if (pol_fs == NULL) {
	ds_printf(DS_LEV_ERR, "parsePolicyFile: could not open '%s' (%s)",
		  filename, strerror(errno));
	return NULL;
    }
    if (fstat(fileno(pol_fs), &st)) {
	ds_printf(DS_LEV_ERR, "parsePolicyFile: could not stat %s", filename);
	fclose(pol_fs);
	return NULL;
    }
    if (!S_ISREG(st.st_mode)) {
	ds_printf(DS_LEV_ERR, "parsePolicyFile: %s is not a regular file", filename);
	fclose(pol_fs);
	return NULL;
    }

    XML_SetUserData(parser, &depth);
    XML_SetElementHandler(parser, startElement, endElement);

    parse_err_cnt = 0;

    do {
	size_t len = fread(buf, 1, sizeof(buf), pol_fs);

	done = len < sizeof(buf);
	if (!XML_Parse(parser, buf, len, done)) {
	    ds_printf(DS_LEV_DEBUG,
		"%s at line %d",
		XML_ErrorString(XML_GetErrorCode(parser)),
		XML_GetCurrentLineNumber(parser));
	    parse_err_cnt++;
	    break;
	}
    } while (!done);

    XML_ParserFree(parser);
    fclose(pol_fs);

    ds_printf(DS_LEV_DEBUG, "    parsePolicyFile: completed");

    if (parse_err_cnt) {
	ds_printf(DS_LEV_DEBUG, "    parsePolicyFile: %d errors during parsing, failed",
		  parse_err_cnt);
	clear_policy();
	return NULL;
    }

    return &ret;
}
