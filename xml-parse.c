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
 * provides the XML parsing code for policy files, via expat (xmltok)
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>

#include <xmltok/xmlparse.h>

#include "debsig.h"

static int parse_error;
static struct policy ret;
static struct group *cur_grp = NULL;

#define PARSE_ERROR(x) do { parse_error++; ds_printf x; } while(0)

static void startElement(void *userData, const char *name, const char **atts) {
    int i;
    int *depthPtr = userData;

    if (!strcmp(name,"Policy")) {
	if (*depthPtr != 0)
	    PARSE_ERROR((DS_LEV_ERR, "policy parse error: `Policy' found at wrong level"));

	for (i = 0; atts[i]; i += 2) {
	    if (!strcmp(atts[i], "xmlns")) {
		if (strcmp(atts[i+1], DEBSIG_NS))
		    PARSE_ERROR((DS_LEV_ERR, "policy name space != " DEBSIG_NS));
	    } else
		PARSE_ERROR((DS_LEV_ERR, "Policy element contains unknown attribute `%s'",
			     atts[i]));
	}
    } else if (!strcmp(name,"Origin")) {
	if (*depthPtr != 1)
	    PARSE_ERROR((DS_LEV_ERR, "policy parse error: `Origin' found at wrong level"));
	
	for (i = 0; atts[i]; i += 2) {
	    if (!strcmp(atts[i], "id"))
		ret.id = strdup(atts[i+1]);
	    else if (!strcmp(atts[i], "Name"))
		ret.name = strdup(atts[i+1]);
	    else if (!strcmp(atts[i], "Description"))
		ret.description = strdup(atts[i+1]);
	    else
		PARSE_ERROR((DS_LEV_ERR, "Origin element contains unknown attribute `%s'",
			     atts[i]));
	}

	if (ret.id == NULL || ret.name == NULL)
	    PARSE_ERROR((DS_LEV_ERR, "Origin element missing Name or ID attribute"));
    } else if (!strcmp(name,"Selection") || !strcmp(name,"Verification")) {
	struct group *g = NULL;
	if (*depthPtr != 1)
	    PARSE_ERROR((DS_LEV_ERR,
			 "policy parse error: `Selection/Verification' found at wrong level"));

	/* create a new entry, make it the current */
	cur_grp = (struct group *)malloc(sizeof(struct group));
	if (cur_grp == NULL) {
	    ds_printf(DS_LEV_ERR, "out of memory");
	    exit(1);
	}
	memset(cur_grp, 0, sizeof(struct group));

	if (!strcmp(name,"Selection")) {
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
	    if (!strcmp(atts[i], "MinOptional")) {
		int t; const char *c = atts[i+1];
		for (t = 0; c[t]; t++) {
		    if (!isdigit(c[t]))
			PARSE_ERROR((DS_LEV_ERR, "MinOptional requires a numerical value"));
		}
		cur_grp->min_opt = atoi(c);
	    } else {
		PARSE_ERROR((DS_LEV_ERR,
			     "Selection/Verification element contains unknown attribute `%s'",
			     atts[i]));
	    }
	}
    } else if (!strcmp(name,"Required") || !strcmp(name,"Reject") ||
	       !strcmp(name,"Optional")) {
	struct match *m = NULL, *cur_m = NULL;
	if (*depthPtr != 2)
	    PARSE_ERROR((DS_LEV_ERR,
			 "policy parse error: Match element found at wrong level"));

	/* This should never happen with the other checks in place */
	if (cur_grp == NULL) {
	    PARSE_ERROR((DS_LEV_ERR,
			 "policy parse error: No current group for match element"));
	    goto get_out;
	}

        /* create a new entry, make it the current */
        cur_m = (struct match *)malloc(sizeof(struct match));
        if (cur_m == NULL) {
            ds_printf(DS_LEV_ERR, "out of memory");
            exit(1);
        }
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
            if (!strcmp(atts[i], "Type")) {
                cur_m->name = strdup(atts[i+1]);
	    } else if (!strcmp(atts[i], "File")) {
		cur_m->file = strdup(atts[i+1]);
	    } else if (!strcmp(atts[i], "id")) {
		cur_m->id = strdup(atts[i+1]);
	    } else if (!strcmp(atts[i], "Expiry")) {
		int t; const char *c = atts[i+1];
		for (t = 0; c[t]; t++) {
		    if (!isdigit(c[t]))
			PARSE_ERROR((DS_LEV_ERR, "Expiry requires a numerical value"));
		}
                cur_m->day_expiry = atoi(c);
            } else {
                PARSE_ERROR((DS_LEV_ERR,
                             "Match element contains unknown attribute `%s'",
                             atts[i]));
            }
        }


        if (!strcmp(name,"Required")) {
	    cur_m->type = REQUIRED_MATCH;
	    if (cur_m->name == NULL || cur_m->file == NULL)
		PARSE_ERROR((DS_LEV_ERR,
			     "Required must have a Type and File attribute"));
	} else if (!strcmp(name,"Optional")) {
	    cur_m->type = OPTIONAL_MATCH;
	    if (cur_m->name == NULL || cur_m->file == NULL)
		PARSE_ERROR((DS_LEV_ERR,
			     "Optional must have a Type and File attribute"));
	} else { /* Reject */
	    cur_m->type = REJECT_MATCH;
	    if (cur_m->name == NULL)
		PARSE_ERROR((DS_LEV_ERR,
			     "Reject must have a Type attribute"));
	}
    }

get_out:
    *depthPtr += 1;
}

static void endElement(void *userData, const char *name) {
    int *depthPtr = userData;
    *depthPtr -= 1;

    if (!strcmp(name,"Selection") || !strcmp(name,"Verification")) {
	struct match *m; int i = 0;
	/* sanity check this block */
	for (m = cur_grp->matches; m; m = m->next) {
	    if (m->type == OPTIONAL_MATCH ||
		m->type == REQUIRED_MATCH)
		i++;
	}
	if (!i) {
	    PARSE_ERROR((DS_LEV_ERR, "Selection/Verification block does not contain any "
			 "Required or Optional matches."));
	}
	cur_grp = NULL; /* just to make sure */
    }
}

static void free_matches(struct match *mch) {
    if (mch == NULL) return;
    if (mch->name) free(mch->name);
    if (mch->id) free(mch->id);
    if (mch->file) free(mch->file);
}

static void free_group(struct group *grp) {
    if (grp == NULL) return;
    for ( ; grp; grp = grp->next)
	free_matches(grp->matches);
    return;
}

void clear_policy(void) {

    if (ret.name) free(ret.name);
    if (ret.id) free(ret.id);
    if (ret.description) free(ret.description);

    free_group(ret.sels);
    free_group(ret.vers);

    memset(&ret, 0, sizeof(struct policy));
    return;
}

struct policy *parsePolicyFile(char *filename) {
    char buf[BUFSIZ];
    XML_Parser parser = XML_ParserCreate(NULL);
    int done, depth = 0;
    FILE *pol_fs;

    ds_printf(DS_LEV_VER, "parsePolicyFile: parsing `%s'", filename);

    if ((pol_fs = fopen(filename, "r")) == NULL) {
	ds_printf(DS_LEV_ERR, "parsePolicyFile: could not open `%s' (%s)",
		  filename, strerror(errno));
	return NULL;
    }
    
    XML_SetUserData(parser, &depth);
    XML_SetElementHandler(parser, startElement, endElement);

    parse_error = 0;
    clear_policy();

    do {
	size_t len = fread(buf, 1, sizeof(buf), pol_fs);
	done = len < sizeof(buf);
	if (!XML_Parse(parser, buf, len, done)) {
	    ds_printf(DS_LEV_ERR,
		"%s at line %d",
		XML_ErrorString(XML_GetErrorCode(parser)),
		XML_GetCurrentLineNumber(parser));
	    parse_error++;
	    break;
	}
    } while (!done);

    XML_ParserFree(parser);
    fclose(pol_fs);

    ds_printf(DS_LEV_VER, "parsePolicyFile: completed");

    if (parse_error) {
	ds_printf(DS_LEV_ERR, "parsePolicyFile: %d errors during parsing, failed",
		  parse_error);
	clear_policy();
	return NULL;
    }

    return &ret;
}
