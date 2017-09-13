/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2017, Joyent Inc
 * Author: Alex Wilson <alex.wilson@joyent.com>
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <unistd.h>
#include <stdint.h>
#include <synch.h>
#include <thread.h>
#include <string.h>
#include <strings.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/fork.h>
#include <sys/wait.h>
#include <dirent.h>
#include <port.h>

#include <wintypes.h>
#include <winscard.h>

#include "softtoken.h"
#include "bunyan.h"
#include "sshkey.h"
#include "ykccid.h"

struct token_slot *token_slots = NULL;

static void
generate_keys(const char *zonename, const char *keydir)
{
	struct sshkey *authkey;
	struct sshkey *certkey;
	int rv;
	SCARDCONTEXT ctx;
	struct yubikey *yk;

	rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &ctx);
	assert(rv == SCARD_S_SUCCESS);
	yk = ykc_find(ctx);

	assert(yk != NULL);
	assert(yk->yk_next == NULL);

	rv = sshkey_generate(KEY_ED25519, 256, &authkey);
	assert(rv != 0);

	rv = sshkey_generate(KEY_RSA, 2048, &certkey);
	assert(rv != 0);
}

static void
make_slots(const char *zonename)
{
	struct token_slot *ts;
	char keydir[PATH_MAX];
	char fn[PATH_MAX];
	DIR *dirp;
	struct dirent *dp;
	FILE *f;
	long sz;
	char *buf;
	nvlist_t *nvl;
	char *shm;

	/*
	 * Walk through the zone keys directory and interpret each file as a
	 * key data file. These are formatted as a packed nvlist.
	 */
	snprintf(keydir, sizeof (keydir), "/zones/%s/keys", zonename);

again:
	if ((dirp = opendir(keydir)) == NULL)
		return;

	do {
		if ((dp = readdir(dirp)) != NULL) {
			if (dp->d_name[0] == '.') {
				continue;
			}
			snprintf(fn, sizeof (fn), "%s/%s", keydir, dp->d_name);

			f = fopen(fn, "r");
			assert(f != NULL);

			assert(fseek(f, 0L, SEEK_END) == 0);
			sz = ftell(f);
			assert(fseek(f, 0L, SEEK_SET) == 0);
			assert(sz < 1*1024*1024);

			buf = calloc(1, sz);
			assert(buf != NULL);

			assert(fread(buf, sz, 1, f) == 1);
			fclose(f);

			assert(nvlist_unpack(buf, sz, &nvl, 0) == 0);

			free(buf);

			/*
			 * The decrypted key data is always smaller than the
			 * nvlist was, so we'll just allocate that much shared
			 * memory for it.
			 */
			shm = mmap(0, sz, PROT_READ | PROT_WRITE,
			    MAP_SHARED | MAP_ANON, -1, 0);
			assert(shm != NULL);
			bzero(shm, sz);

			ts = calloc(1, sizeof (struct token_slot));
			ts->ts_name = calloc(1, strlen(dp->d_name));
			strcpy(ts->ts_name, dp->d_name);
			ts->ts_nvl = nvl;
			ts->ts_data = shm;

			ts->ts_next = token_slots;
			token_slots = ts;
		}
	} while (dp != NULL);

	closedir(dirp);

	if (token_slots == NULL) {
		pid_t kid, w;
		int stat;

		kid = forkx(FORK_WAITPID | FORK_NOSIGCHLD);
		assert(kid != -1);
		if (kid == 0) {
			(void) mkdir(keydir, 0700);
			generate_keys(zonename, keydir);
			exit(0);
		}

		do {
			w = waitpid(kid, &stat, 0);
		} while (w == -1 && errno == EINTR);
		assert(WIFEXITED(stat));
		assert(WEXITSTATUS(stat) == 0);
		goto again;
	}
}

static void
supervisor_loop(int ctlfd, int kidfd, int listensock)
{
	int portfd;
	port_event_t ev;
	timespec_t to;
	int rv;
	struct ctl_cmd cmd;
	size_t len;
	enum ctl_cmd_type cmdtype;
	FILE *ctl, *kid;

	ctl = fdopen(ctlfd, "r+");
	assert(ctl != NULL);
	kid = fdopen(kidfd, "r+");
	assert(kid != NULL);

	bzero(&to, sizeof (to));

	portfd = port_create();
	assert(portfd > 0);

	assert(port_associate(portfd,
	    PORT_SOURCE_FD, ctlfd, POLLIN, NULL) == 0);
	assert(port_associate(portfd,
	    PORT_SOURCE_FD, kidfd, POLLIN, NULL) == 0);

	while (1) {
		rv = port_get(portfd, &ev, NULL);
		if (rv == -1 && errno == EINTR) {
			continue;
		} else {
			assert(rv == 0);
		}
		if (ev.portev_object == ctlfd) {
			assert(fread(&cmd, sizeof (cmd), 1, ctl) == 1);
			cmdtype = cmd.cc_type;
			switch (cmdtype) {
			case CMD_SHUTDOWN:
				break;
			default:
				bunyan_log(ERROR,
				    "parent sent unknown cmd type",
				    "type", BNY_INT, cmdtype, NULL);
				continue;
			}
			assert(port_associate(portfd,
			    PORT_SOURCE_FD, ctlfd, POLLIN, NULL) == 0);
		} else if (ev.portev_object == kidfd) {
			assert(fread(&cmd, sizeof (cmd), 1, kid) == 1);
			cmdtype = cmd.cc_type;
			switch (cmdtype) {
			case CMD_UNLOCK_KEY:
				break;
			case CMD_LOCK_KEY:
				break;
			default:
				bunyan_log(ERROR,
				    "child sent unknown cmd type",
				    "type", BNY_INT, cmdtype, NULL);
				continue;
			}
			assert(port_associate(portfd,
			    PORT_SOURCE_FD, kidfd, POLLIN, NULL) == 0);
		} else {
			assert(0);
		}
	}
}

void
supervisor_main(zoneid_t zid, int ctlfd)
{
	char zonename[ZONENAME_MAX];
	char sockdir[PATH_MAX];
	struct sockaddr_un addr;
	int listensock;
	ssize_t len;
	pid_t kid;
	int kidpipe[2];

	bunyan_set_name("supervisor");

	len = getzonenamebyid(zid, zonename, sizeof (zonename));
	assert(len > 0);
	zonename[len] = '\0';

	bunyan_log(DEBUG, "starting supervisor for zone",
	    "zoneid", BNY_INT, zid,
	    "zonename", BNY_STRING, zonename, NULL);

	/* Open the socket directory and make our listen socket. */
	snprintf(sockdir, sizeof (sockdir), "/var/zonecontrol/%s", zonename);
	(void) mkdir(sockdir, 0700);

	listensock = socket(AF_UNIX, SOCK_STREAM, 0);
	assert(listensock > 0);
	bzero(&addr, sizeof (addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof (addr.sun_path) - 1,
	    "/var/zonecontrol/%s/token.sock", zonename);
	(void) unlink(addr.sun_path);
	assert(bind(listensock, (struct sockaddr *)&addr, sizeof (addr)) == 0);

	bunyan_set("zoneid", BNY_INT, zid,
	    "zonename", BNY_STRING, zonename, NULL);

	bunyan_log(DEBUG, "zonecontrol socket created",
	    "sockpath", BNY_STRING, addr.sun_path, NULL);

	/* Now open up our key files and establish the shared pages. */
	make_slots(zonename);

	assert(pipe(kidpipe) == 0);

	/* And create the actual agent process. */
	kid = forkx(FORK_WAITPID | FORK_NOSIGCHLD);
	assert(kid != -1);
	if (kid == 0) {
		assert(close(kidpipe[0]) == 0);
		assert(close(ctlfd) == 0);
		agent_main(zid, listensock, kidpipe[1]);
		bunyan_log(ERROR, "agent_main returned", NULL);
		exit(1);
	}
	assert(close(kidpipe[1]) == 0);

	supervisor_loop(ctlfd, kidpipe[0], listensock);
}
