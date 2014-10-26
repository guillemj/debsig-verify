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

#define GPG_PROG "/usr/bin/gpg"

/* This is so ugly, but easy */
#define GPG_ARGS_FMT "%s %s %s"
#define GPG_ARGS "--no-options", "--no-default-keyring", "--batch"

#define SIG_MAGIC ":signature packet:"
#define USER_MAGIC ":user ID packet:"

#define OPTIONAL_MATCH 1
#define REQUIRED_MATCH 2
#define REJECT_MATCH 3

#define SIG_VERSION "1.0"
#define DEBSIG_NAMESPACE "http://www.debian.org/debsig/"SIG_VERSION"/"

struct deb_archive {
	const char *name;
	int fd;
};

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

struct policy *parsePolicyFile(const char *filename);
off_t
findMember(struct deb_archive *deb, const char *name);
off_t
checkSigExist(struct deb_archive *deb, const char *name);
char *
getKeyID(const char *originID, const struct match *mtc);
char *
getSigKeyID(struct deb_archive *deb, const char *type);
int
gpgVerify(const char *originID, struct match *mtc,
          const char *data, const char *sig);
void clear_policy(void);

/* Debugging and failures */
#define DS_LEV_ALWAYS 3
#define DS_LEV_ERR 2
#define DS_LEV_INFO 1
#define DS_LEV_VER 0
#define DS_LEV_DEBUG -1

#define DS_SUCCESS		0
#define DS_FAIL_NOSIGS		10
#define DS_FAIL_UNKNOWN_ORIGIN	11
#define DS_FAIL_NOPOLICIES	12
#define DS_FAIL_BADSIG		13
#define DS_FAIL_INTERNAL	14
extern void ds_printf(int level, const char *fmt, ...)
	__attribute__ ((__format__ (__printf__, 2, 3)));
#define ds_fail_printf(myexit, fmt, args...)	\
do {						\
	ds_printf(DS_LEV_ERR, fmt, ##args);	\
	exit(myexit);				\
} while(0)

extern int ds_debug_level;
extern char *rootdir;
extern const char *policies_dir;
extern const char *keyrings_dir;
