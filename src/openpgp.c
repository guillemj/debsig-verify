/*
 * debsig-verify - Debian package signature verification tool
 * openpgp.c - OpenPGP frontend
 *
 * Copyright © 2021 Guillem Jover <guillem@debian.org>
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

#include <dpkg/dpkg.h>
#include <dpkg/path.h>

#include "debsig.h"

extern const struct openpgp openpgp_gpg;

static const struct openpgp *openpgp_impl[] = {
	&openpgp_gpg,
	NULL,
};

static const struct openpgp *
getOpenPGP(void)
{
	const struct openpgp *openpgp;

	for (openpgp = *openpgp_impl; openpgp; openpgp++)
		if (find_command(openpgp->cmd))
			break;

	if (openpgp == NULL)
		ohshit("cannot find an OpenPGP implementation");

	return openpgp;
}

char *
getKeyID(const char *originID, const struct match *mtc)
{
	const struct openpgp *openpgp = getOpenPGP();

	return openpgp->getKeyID(originID, mtc);
}

char *
getSigKeyID(struct dpkg_ar *deb, const char *type)
{
	const struct openpgp *openpgp = getOpenPGP();

	return openpgp->getSigKeyID(deb, type);
}

off_t
checkSigExist(struct dpkg_ar *deb, const char *name)
{
	char buf[16];

	if (name == NULL) {
		ds_printf(DS_LEV_DEBUG, "checkSigExist: NULL values passed");
		return 0;
	}

	snprintf(buf, sizeof(buf) - 1, "_gpg%s", name);

	return findMember(deb, buf);
}

int
sigVerify(const char *originID, struct match *mtc,
          const char *data, const char *sig)
{
	const struct openpgp *openpgp = getOpenPGP();

	return openpgp->sigVerify(originID, mtc, data, sig);
}
