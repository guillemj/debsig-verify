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

/* $Id$ */

#define DEBSIG_POLICIES_DIR_FMT DEBSIG_POLICIES_DIR"/%s"
#define DEBSIG_KEYRINGS_FMT DEBSIG_KEYRINGS_DIR"/%s/%s"

#define GPG_PROG "/usr/bin/gpg"

/* This is so ugly, but easy */
#define GPG_ARGS_FMT "%s %s"
#define GPG_ARGS "--no-options", "--no-default-keyring"

#define SIG_MAGIC ":signature packet:"
#define USER_MAGIC ":user ID packet:"

#define OPTIONAL_MATCH 1
#define REQUIRED_MATCH 2
#define REJECT_MATCH 3

#define VERSION "0.1"
#define SIG_VERSION "1.0"
#define DEBSIG_NS "http://www.debian.org/debsig/"SIG_VERSION"/"

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

struct policy *parsePolicyFile(char *filename);
size_t findMember(const char *name);
int checkSigExist(const char *name);
char *getKeyID (const struct match *mtc);
char *getSigKeyID (const char *deb, const char *type);
int gpgVerify(const char *deb, struct match *mtc, const char *tmp_file);

#define DS_LEV_ERR 2
#define DS_LEV_INFO 1
#define DS_LEV_VER 0
void ds_printf(int level, const char *fmt, ...);

extern int ds_debug_level;
extern FILE *deb_fs;
extern char *deb;
extern char originID[];
