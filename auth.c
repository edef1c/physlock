/* physlock: auth.c
 * Copyright (c) 2013 Bert Muennich <be.muennich at gmail.com>
 * Copyright (c) 2013 edef <edef at edef.eu>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#define _POSIX_C_SOURCE 200112L
#define _XOPEN_SOURCE   500 /* for crypt() and strdup() */

#include <string.h>
#include <shadow.h>
#include <pwd.h>
#include <unistd.h>
#include <errno.h>

#include "auth.h"
#include "util.h"

#include <security/pam_appl.h>
#include <security/pam_misc.h>
static const struct pam_conv conv = {
  misc_conv,
  NULL
};

char* get_uname(uid_t uid) {
	struct passwd *pw;

	pw = getpwuid(uid);
	if (pw == NULL)
		die("could not get user info for uid %u\n", uid);
	
	char* uname = strdup(pw->pw_name);
	if (uname == NULL)
		die("could not allocate memory");
	return strdup(pw->pw_name);
}


int authenticate(const char *uname) {
  pam_handle_t *pamh;
  int pamret;
  pamret = pam_start("login", uname, &conv, &pamh);
  if (pamret != PAM_SUCCESS)
    return 0;
  pamret = pam_authenticate(pamh, 0);
  if (pamret != PAM_SUCCESS)
    return 0;
	return 1;
}
