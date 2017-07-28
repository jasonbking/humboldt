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

#include <sys/types.h>
#include <sys/socket.h>
#include <dirent.h>

#include "softtoken.h"
#include "bunyan.h"

struct token_slot *token_slots = NULL;

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

	snprintf(keydir, sizeof (keydir), "/zones/%s/keys", zonename);
	if ((dirp = opendir(keydir)) == NULL)
		return;

	do {
		if ((dp = readdir(dirp)) != NULL) {
			if (dp->d_name[0] == '.' && (
			    dp->d_name[1] == '\0' || dp->d_name[1] == '.')) {
				continue;
			}
			snprintf(fn, sizeof (fn), "%s/%s", keydir, dp->d_name);

			f = fopen(fn, "r");
			assert(f != NULL);

			assert(fseek(f, 0L, SEEK_END) == 0);
			sz = ftell(f);
			assert(fseek(f, 0L, SEEK_SET) == 0);
			assert(sz < 1*1024*1024);

			buf = calloc(sz, 1);
			assert(buf != NULL);

			assert(fread(buf, sz, 1, f) == 1);
			fclose(f);

			assert(nvlist_unpack(buf, sz, &nvl, 0) == 0);

			free(buf);

			ts = calloc(sizeof (struct token_slot), 1);
			ts->ts_name = calloc(strlen(dp->d_name), 1);
			strcpy(ts->ts_name, dp->d_name);
			ts->ts_nvl = nvl;
			ts->ts_next = token_slots;
			token_slots = ts;
		}
	} while (dp != NULL);

	closedir(dirp);
}

void
supervisor_main(zoneid_t zid)
{
	char zonename[ZONENAME_MAX];
	char sockdir[PATH_MAX];
	struct sockaddr_un addr;
	int listensock;
	ssize_t len;

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
	memset(&addr, 0, sizeof (addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof (addr.sun_path) - 1,
	    "/var/zonecontrol/%s/token.sock", zonename);
	(void) unlink(addr.sun_path);
	assert(bind(listensock, (struct sockaddr *)&addr, sizeof (addr)) == 0);

	bunyan_log(DEBUG, "zonecontrol socket created",
	    "sockpath", BNY_STRING, addr.sun_path,
	    "zoneid", BNY_INT, zid,
	    "zonename", BNY_STRING, zonename, NULL);

	/* Now establish the shared pages. */
	make_slots(zonename);

	for (;;)
		pause();
}
