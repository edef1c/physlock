/* physlock: main.c
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>

#include "auth.h"
#include "config.h"
#include "options.h"
#include "util.h"
#include "vt.h"

enum { BUFLEN = 1024 };

static char buf[BUFLEN];
static int oldvt;
static vt_t vt;
static int oldsysrq;

void cleanup() {
	static int in = 0;

	if (!in++) {
		if (oldsysrq > 0)
			set_sysrq_state(SYSRQ_PATH, oldsysrq);
		if (vt.fd >= 0)
			reset_vt(&vt);
		unlock_vt_switch();
		release_vt(&vt, oldvt);
		vt_destroy();
	}
}

void sa_handler_exit(int signum) {
	cleanup();
	exit(0);
}

int setup_signal(int signum, void (*handler)(int)) {
	struct sigaction sigact;

	sigact.sa_flags = 0;
	sigact.sa_handler = handler;
	sigemptyset(&sigact.sa_mask);
	
	if (sigaction(signum, &sigact, NULL) < 0) {
		warn("could not set handler for signal %d: %s", signum, strerror(errno));
		return -1;
	} else {
		return 0;
	}
}

int main(int argc, char **argv) {
	int auth = 0, chpid;
	char* user;

	oldvt = oldsysrq = vt.nr = vt.fd = -1;
	vt.ios = NULL;

	parse_options(argc, argv);

	if (geteuid() != 0) {
		fprintf(stderr, "physlock: must be root!\n");
		return 1;
	}

	setup_signal(SIGTERM, sa_handler_exit);
	setup_signal(SIGQUIT, sa_handler_exit);
	setup_signal(SIGHUP, SIG_IGN);
	setup_signal(SIGINT, SIG_IGN);
	setup_signal(SIGUSR1, SIG_IGN);
	setup_signal(SIGUSR2, SIG_IGN);

	vt_init();
	get_current_vt(&oldvt);

	if (options->only_lock) {
		lock_vt_switch();
		vt_destroy();
		return 0;
	} else if (options->only_unlock) {
		unlock_vt_switch();
		vt_destroy();
		return 0;
	}

	if (options->disable_sysrq) {
		oldsysrq = get_sysrq_state(SYSRQ_PATH);
		if (oldsysrq > 0)
			set_sysrq_state(SYSRQ_PATH, 0);
	}

	user = get_uname(getuid());

	acquire_new_vt(&vt);
	lock_vt_switch();
	secure_vt(&vt);

	if (options->detach) {
		chpid = fork();
		if (chpid < 0)
			die("could not spawn background process: %s", strerror(errno));
		else if (chpid > 0)
			return 0;
		else
			setsid();
	}

	while (!auth) {
		flush_vt(&vt);

		auth = authenticate(user);
		if (!auth) {
			printf("\nAuthentication failed\n");
			sleep(AUTH_FAIL_TIMEOUT);
		}
	}

	cleanup();

	return 0;
}
