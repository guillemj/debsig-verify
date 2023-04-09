/*
 * debsig-verify - Debian package signature verification tool
 * openpgp-gpg.c - OpenPGP backend (GnuPG)
 *
 * Copyright © 2000 Ben Collins <bcollins@debian.org>
 * Copyright © 2014-2017, 2019-2021 Guillem Jover <guillem@debian.org>
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

#include <config.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <ctype.h>
#include <fcntl.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include <dpkg/dpkg.h>
#include <dpkg/subproc.h>
#include <dpkg/command.h>
#include <dpkg/buffer.h>
#include <dpkg/path.h>

#include "debsig.h"

static int gpg_inited = 0;
static char *gpg_tmpdir;
static const char *gpg_prog = "gpg";

static void
cleanup_gpg_tmpdir(void)
{
    pid_t pid;

    pid = subproc_fork();
    if (pid == 0) {
      execlp("rm", "rm", "-rf", gpg_tmpdir, NULL);
      ohshite("unable to execute %s (%s)", "rm", "rm -rf");
    }
    subproc_reap(pid, "remove GnuPG temporary home directory", SUBPROC_NOCHECK);

    free(gpg_tmpdir);
    gpg_tmpdir = NULL;
    gpg_inited = 0;
}

/* Ensure that gpg has a writable HOME to put its keyrings */
static void
gpg_init(void)
{
    const char *prog;
    char *gpg_tmpdir_template;
    int rc;

    if (gpg_inited)
        return;

    prog = getenv("DEBSIG_GNUPG_PROGRAM");
    if (prog)
      gpg_prog = prog;

    gpg_tmpdir_template = path_make_temp_template("debsig-verify");
    gpg_tmpdir = mkdtemp(gpg_tmpdir_template);
    if (gpg_tmpdir == NULL)
        ohshite("cannot create temporary directory '%s'", gpg_tmpdir_template);

    /* Do not let external interference. */
    unsetenv("GPG_TTY");

    rc = setenv("GNUPGHOME", gpg_tmpdir, 1);
    if (rc < 0)
        ohshite("cannot set environment variable %s to '%s'", "GNUPGHOME",
                gpg_tmpdir);

    rc = atexit(cleanup_gpg_tmpdir);
    if (rc != 0)
       ohshit("cannot set atexit cleanup handler");

    gpg_inited = 1;
}

static void
command_gpg_init(struct command *cmd)
{
    command_init(cmd, gpg_prog, "gpg");
    command_add_arg(cmd, gpg_prog);
    command_add_args(cmd, "--no-options", "--no-default-keyring", "--batch",
                          "--no-secmem-warning", "--no-permission-warning",
                          "--no-mdc-warning", "--no-auto-check-trustdb", NULL);
    command_add_args(cmd, "--weak-digest", "RIPEMD160", NULL);
    command_add_args(cmd, "--weak-digest", "SHA1", NULL);
}

enum keyid_state {
    KEYID_UNKNOWN,
    KEYID_PUB,
    KEYID_FPR,
    KEYID_UID,
    KEYID_SIG,
};

enum colon_fields {
    COLON_FIELD_FPR_ID = 10,
    COLON_FIELD_UID_ID = 10,
};

enum errsig_fields {
    ERRSIG_FIELD_SELF = 2,
    ERRSIG_FIELD_KEY_ID = 3,
    ERRSIG_FIELD_FPR_ID = 9,
};

static bool
match_prefix(const char *str, const char *prefix)
{
    size_t prefix_len = strlen(prefix);

    return strncmp(str, prefix, prefix_len) == 0;
}

static char *
get_field(const char *str, int field_sep, int field_num)
{
    const char *end;

    for (int field = 1; field < field_num && str[0]; field++) {
        str = strchrnul(str, field_sep);
        if (str[0] != field_sep && str[0] != '\0')
            return NULL;
        if (str[0])
            str++;
    }

    end = strchrnul(str, field_sep);
    if (end[0] != field_sep && end[0] != '\0')
        return NULL;

    return strndup(str, end - str);
}

static char *
get_space_field(const char *str, int field_num)
{
    return get_field(str, ' ', field_num);
}

static char *
get_colon_field(const char *str, int field_num)
{
    return get_field(str, ':', field_num);
}

static char *
gpg_getKeyID(const char *keyring, const char *match_id)
{
    char *buf = NULL;
    size_t buflen = 0;
    ssize_t nread;
    pid_t pid;
    int pipefd[2];
    FILE *ds;
    char *ret = NULL;
    char *fpr = NULL;
    enum keyid_state state = KEYID_UNKNOWN;

    if (match_id == NULL)
	return NULL;

    gpg_init();

    m_pipe(pipefd);
    pid = subproc_fork();
    if (pid == 0) {
        struct command cmd;

        m_dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[0]);
        close(pipefd[1]);

        command_gpg_init(&cmd);
        command_add_args(&cmd, "--quiet", "--with-colons", "--show-keys",
                               keyring, NULL);
        command_exec(&cmd);
    }
    close(pipefd[1]);

    ds = fdopen(pipefd[0], "r");
    if (ds == NULL) {
	perror("gpg");
	return NULL;
    }

    while ((nread = getline(&buf, &buflen, ds)) >= 0) {
        if (buf[nread - 1] != '\n') {
          ds_printf(DS_LEV_DEBUG, "        getKeyID: found truncated input from GnuPG, aborting");
          break;
        }
        buf[nread - 1] = '\0';

	if (state == KEYID_UNKNOWN) {
            if (!match_prefix(buf, "pub:"))
		continue;

            /* Certificate found. */
            state = KEYID_PUB;
        } else if (state == KEYID_PUB) {
            if (!match_prefix(buf, "fpr:"))
		continue;
            fpr = get_colon_field(buf, COLON_FIELD_FPR_ID);
            if (eqKeyID(fpr, match_id)) {
                ret = fpr;
                break;
            }
            state = KEYID_FPR;
        } else if (state == KEYID_FPR) {
            char *uid;

            if (!match_prefix(buf, "uid:"))
		continue;

            uid = get_colon_field(buf, COLON_FIELD_UID_ID);
            if (uid == NULL)
		continue;
            if (strcmp(uid, match_id) != 0) {
                free(uid);
		continue;
	    }
            free(uid);

            /* Fingerprint match found. */
            ret = fpr;
            break;
        }
    }
    fclose(ds);
    free(buf);

    subproc_reap(pid, "getKeyID", SUBPROC_NORMAL);

    if (ret == NULL) {
	ds_printf(DS_LEV_DEBUG, "        getKeyID: failed for %s", match_id);
        /* If we did not find any match release any parsed fingerprint. */
        free(fpr);
    } else {
	ds_printf(DS_LEV_DEBUG, "        getKeyID: mapped %s -> %s", match_id, ret);
    }

    return ret;
}

static char *
gpg_getSigKeyID(struct dpkg_ar *deb, const char *name)
{
    char *buf = NULL;
    size_t buflen = 0;
    ssize_t nread;
    struct dpkg_error err;
    int pread[2], pwrite[2];
    off_t len = checkSigExist(deb, name);
    pid_t pid;
    FILE *ds_read;
    char *ret = NULL;

    if (!len)
	return NULL;

    gpg_init();

    /* Fork for gpg, keeping a nice pipe to read/write from.  */
    if (pipe(pread) < 0)
        ohshite("error creating a pipe");
    if (pipe(pwrite) < 0)
        ohshite("error creating a pipe");
    /* I like file streams, so sue me :P */
    if ((ds_read = fdopen(pread[0], "r")) == NULL)
	ohshite("error opening file stream for gpg");

    pid = subproc_fork();
    if (pid == 0) {
        struct command cmd;
        int null_fd;

	/* Here we go */
	m_dup2(pread[1], 1);
	close(pread[0]);
	close(pread[1]);
	m_dup2(pwrite[0], 0);
	close(pwrite[0]);
	close(pwrite[1]);

	null_fd = open("/dev/null", O_WRONLY);
	m_dup2(null_fd, STDERR_FILENO);

	command_gpg_init(&cmd);
	command_add_args(&cmd, "--keyring", "/dev/null", NULL);
	command_add_args(&cmd, "--status-fd", "1", NULL);
	command_add_args(&cmd, "--verify", "-", "/dev/null", NULL);
	command_exec(&cmd);
    }
    close(pread[1]); close(pwrite[0]);

    /* First, let's feed gpg our signature. Don't forget, our call to
     * checkSigExist() above positioned the deb->fd file pointer already.  */
    if (fd_fd_copy(deb->fd, pwrite[1], len, &err) < 0)
	ohshit("getSigKeyID: error reading signature (%s)", err.str);

    if (close(pwrite[1]) < 0)
	ohshite("getSigKeyID: error closing gpg write pipe");

    /* Now, let's see what gpg has to say about all this */
    while ((nread = getline(&buf, &buflen, ds_read)) >= 0) {
        if (buf[nread - 1] != '\n') {
          ds_printf(DS_LEV_DEBUG, "        getKeyID: found truncated input from GnuPG, aborting");
          break;
        }
        buf[nread - 1] = '\0';

        /* Skip comments. */
        if (buf[0] == '#')
            continue;

        if (strncmp(buf, "[GNUPG:]", 8) != 0)
            continue;

        ret = get_space_field(buf, ERRSIG_FIELD_SELF);
        if (strcmp(ret, "ERRSIG") != 0) {
            free(ret);
            ret = NULL;
            continue;
        }

        free(ret);
        ret = get_space_field(buf, ERRSIG_FIELD_FPR_ID);
        if (strcmp(ret, "-") != 0)
            break;

        free(ret);
        ret = get_space_field(buf, ERRSIG_FIELD_KEY_ID);
        break;
    }
    if (ferror(ds_read))
	ohshit("error reading from gpg");
    fclose(ds_read);
    free(buf);

    subproc_reap(pid, "getSigKeyID", SUBPROC_NOCHECK);

    if (ret == NULL)
	ds_printf(DS_LEV_DEBUG, "        getSigKeyID: failed for %s", name);
    else
	ds_printf(DS_LEV_DEBUG, "        getSigKeyID: got %s for %s key", ret, name);

    return ret;
}

static int
gpg_sigVerify(const char *keyring, const char *data, const char *sig)
{
    pid_t pid;
    int rc;

    gpg_init();

    pid = subproc_fork();
    if (pid == 0) {
        struct command cmd;

	if (DS_LEV_DEBUG < ds_debug_level) {
	    close(0); close(1); close(2);
	}

        command_gpg_init(&cmd);
        command_add_args(&cmd, "--keyring", keyring, "--verify", sig, data, NULL);
        command_exec(&cmd);
    }

    rc = subproc_reap(pid, "sigVerify", SUBPROC_RETERROR | SUBPROC_RETSIGNO);
    if (rc != 0) {
	ds_printf(DS_LEV_DEBUG, "sigVerify: gpg exited abnormally or with non-zero exit status");
	return 0;
    }

    return 1;
}

const struct openpgp openpgp_gpg = {
	.cmd = "gpg",
	.getKeyID = gpg_getKeyID,
	.getSigKeyID = gpg_getSigKeyID,
	.sigVerify = gpg_sigVerify,
};
