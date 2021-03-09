/*
 * debsig-verify - Debian package signature verification tool
 *
 * Copyright © 2000 Ben Collins <bcollins@debian.org>
 * Copyright © 2014-2017 Guillem Jover <guillem@debian.org>
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

#include <config.h>

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdlib.h>

#include <dpkg/dpkg.h>
#include <dpkg/subproc.h>
#include <dpkg/command.h>
#include <dpkg/buffer.h>
#include <dpkg/path.h>

#include "debsig.h"

#define SIG_MAGIC ":signature packet:"
#define USER_MAGIC ":user ID packet:"

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
    subproc_reap(pid, "getSigKeyID", SUBPROC_NOCHECK);

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
    command_add_args(cmd, "--no-options", "--no-default-keyring", "--batch",
                          "--no-secmem-warning", "--no-permission-warning",
                          "--no-mdc-warning", "--no-auto-check-trustdb", NULL);
}

enum keyid_state {
    KEYID_UNKNOWN,
    KEYID_USER,
    KEYID_SIG,
};

char *
getKeyID(const char *originID, const struct match *mtc)
{
    static char buf[2048];
    char *keyring;
    pid_t pid;
    int pipefd[2];
    FILE *ds;
    char *c, *d, *ret = NULL;
    enum keyid_state state = KEYID_UNKNOWN;

    if (mtc->id == NULL)
	return NULL;

    gpg_init();

    m_asprintf(&keyring, "%s%s/%s/%s", rootdir, keyrings_dir, originID,
               mtc->file);

    m_pipe(pipefd);
    pid = subproc_fork();
    if (pid == 0) {
        struct command cmd;

        m_dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[0]);
        close(pipefd[1]);

        command_gpg_init(&cmd);
        command_add_args(&cmd, "--list-packets", "-q", keyring, NULL);
        command_exec(&cmd);
    }
    close(pipefd[1]);

    free(keyring);

    ds = fdopen(pipefd[0], "r");
    if (ds == NULL) {
	perror("gpg");
	return NULL;
    }

    while (fgets(buf, sizeof(buf), ds) != NULL) {
	/* Skip comments. */
	if (buf[0] == '#')
	    continue;

	if (state == KEYID_UNKNOWN) {
	    if (strncmp(buf, USER_MAGIC, strlen(USER_MAGIC)) != 0)
		continue;
	    c = strchr(buf, '"');
	    if (c == NULL)
		continue;
	    d = c + 1;
	    c = strchr(d, '"');
	    if (c == NULL)
		continue;
	    *c = '\0';
	    if (strcmp(d, mtc->id) != 0)
		continue;
	    /* User match found. */
	    state = KEYID_USER;
	} else if (state == KEYID_USER) {
	    if (strncmp(buf, SIG_MAGIC, strlen(SIG_MAGIC)) != 0)
		continue;
	    if ((c = strchr(buf, '\n')) != NULL)
		*c = '\0';
	    d = strstr(buf, "keyid");
	    if (d) {
		ret = d + 6;
		/* Keyid match found. */
		break;
	    }
	    /* Reset state. */
	    state = KEYID_UNKNOWN;
	}
    }
    fclose(ds);

    subproc_reap(pid, "getKeyID", SUBPROC_NORMAL);

    if (ret == NULL) {
	ds_printf(DS_LEV_DEBUG, "        getKeyID: no match, falling back to %s", mtc->id);
	ret = mtc->id;
    } else {
	ds_printf(DS_LEV_DEBUG, "        getKeyID: mapped %s -> %s", mtc->id, ret);
    }

    return ret;
}

char *
getSigKeyID(struct dpkg_ar *deb, const char *type)
{
    static char buf[2048];
    struct dpkg_error err;
    int pread[2], pwrite[2];
    off_t len = checkSigExist(deb, type);
    pid_t pid;
    FILE *ds_read;
    char *c, *ret = NULL;

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

	/* Here we go */
	m_dup2(pread[1], 1);
	close(pread[0]);
	close(pread[1]);
	m_dup2(pwrite[0], 0);
	close(pwrite[0]);
	close(pwrite[1]);

	command_gpg_init(&cmd);
	command_add_args(&cmd, "--list-packets", "-q", "-", NULL);
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
    while (fgets(buf, sizeof(buf), ds_read) != NULL) {
	if (strncmp(buf, SIG_MAGIC, strlen(SIG_MAGIC)) == 0) {
	    if ((c = strchr(buf, '\n')) != NULL)
		*c = '\0';
	    /* This is the only line we care about */
	    ret = strstr(buf, "keyid");
	    if (ret) {
		ret += 6;
		break;
	    }
	}
    }
    if (ferror(ds_read))
	ohshit("error reading from gpg");
    fclose(ds_read);

    subproc_reap(pid, "getSigKeyID", SUBPROC_NOCHECK);

    if (ret == NULL)
	ds_printf(DS_LEV_DEBUG, "        getSigKeyID: failed for %s", type);
    else
	ds_printf(DS_LEV_DEBUG, "        getSigKeyID: got %s for %s key", ret, type);

    return ret;
}

int
gpgVerify(const char *originID, struct match *mtc,
          const char *data, const char *sig)
{
    char keyring[8192];
    pid_t pid;
    int rc;
    struct stat st;

    gpg_init();

    snprintf(keyring, sizeof(keyring) - 1, "%s%s/%s/%s",
             rootdir, keyrings_dir, originID, mtc->file);
    if (stat(keyring, &st)) {
	ds_printf(DS_LEV_DEBUG, "gpgVerify: could not stat %s", keyring);
	return 0;
    }

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

    rc = subproc_reap(pid, "gpgVerify", SUBPROC_RETERROR | SUBPROC_RETSIGNO);
    if (rc != 0) {
	ds_printf(DS_LEV_DEBUG, "gpgVerify: gpg exited abnormally or with non-zero exit status");
	return 0;
    }

    return 1;
}
