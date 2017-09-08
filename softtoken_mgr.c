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

#include <zone.h>
#include <libsysevent.h>
#include <libnvpair.h>

#include <sys/types.h>
#include <sys/wait.h>

#include "bunyan.h"
#include "softtoken.h"

struct zone_state {
	zoneid_t zs_id;
	struct zone_state *zs_next;
	pid_t zs_child;
	int zs_pipe[2];
};
static struct zone_state *zonest = NULL;
static mutex_t zonest_mutex;

static evchan_t *evchan;

static int
fdwalk_assert_fd(void *p, int fd)
{
	struct zone_state *zs = (struct zone_state *)p;
	assert(fd <= 2 || fd == zs->zs_pipe[1]);
	return (0);
}

static void
start_supervisor(struct zone_state *forzone)
{
	struct zone_state *zs;
	assert(sysevent_evc_unbind(evchan) == 0);
	(void) signal(SIGCHLD, SIG_DFL);

	for (zs = zonest; zs != NULL; zs = zs->zs_next) {
		assert(close(zs->zs_pipe[0]) == 0);
	}
	assert(fdwalk(fdwalk_assert_fd, forzone) == 0);

	supervisor_main(forzone->zs_id, forzone->zs_pipe[1]);
	bunyan_log(ERROR, "supervisor_main returned!", NULL);
	exit(1);
}

static void
add_zone_unlocked(zoneid_t id)
{
	struct zone_state *zs = calloc(1, sizeof (struct zone_state));
	assert(zs != NULL);
	zs->zs_id = id;
	assert(pipe(zs->zs_pipe) == 0);

	pid_t kid = fork();
	assert(kid != -1);
	if (kid == 0) {
		assert(close(zs->zs_pipe[0]) == 0);
		start_supervisor(zs);
		return;
	}
	zs->zs_child = kid;
	assert(close(zs->zs_pipe[1]) == 0);

	zs->zs_next = zonest;
	zonest = zs;
}

static void
check_add_zone(zoneid_t id)
{
	struct zone_state *zs;

	if (id == GLOBAL_ZONEID)
		return;

	mutex_enter(&zonest_mutex);
	for (zs = zonest; zs != NULL; zs = zs->zs_next) {
		if (zs->zs_id == id) {
			mutex_exit(&zonest_mutex);
			return;
		}
	}

	bunyan_log(DEBUG, "adding zone to index",
	    "zoneid", BNY_INT, id, NULL);
	add_zone_unlocked(id);
	mutex_exit(&zonest_mutex);
}

static void
add_all_zones(void)
{
	zoneid_t *ids = calloc(MAX_ZONEID, sizeof (zoneid_t));
	assert(ids != NULL);
	uint_t count = MAX_ZONEID;
	int i;
	assert(zone_list(ids, &count) == 0);
	bunyan_log(INFO, "found zones",
	    "count", BNY_INT, count, NULL);
	for (i = 0; i < count; ++i) {
		check_add_zone(ids[i]);
	}
}

static int
sysevc_handler(sysevent_t *ev, void *cookie)
{
	nvlist_t *nvl;
	int zid;

	assert(sysevent_get_attr_list(ev, &nvl) == 0);
	if (nvlist_lookup_int32(nvl, "zoneid", &zid) != 0)
		return (0);

	check_add_zone(zid);
	return (0);
}

static void
sigchld_handler(int signo)
{
	pid_t kid;
	int kid_status;
	struct zone_state *zsp = NULL, *zs;

	while ((kid = waitpid((pid_t)0, &kid_status, WNOHANG)) > 0) {
		mutex_enter(&zonest_mutex);
		for (zs = zonest; zs != NULL; zsp = zs, zs = zs->zs_next) {
			if (zs->zs_child == kid) {
				zsp->zs_next = zs->zs_next;
				break;
			}
		}
		mutex_exit(&zonest_mutex);
	}
}

int
main(int argc, char *argv[])
{
	const char *channel = "com.sun:zones:status";
	char subid[128];

	bunyan_init();
	bunyan_set_name("softtoken_mgr");
	bunyan_log(INFO, "starting up", NULL);

	assert(mutex_init(&zonest_mutex,
	    USYNC_THREAD | LOCK_ERRORCHECK, NULL) == 0);

	(void) signal(SIGCHLD, sigchld_handler);

	assert(sysevent_evc_bind(channel, &evchan, 0) == 0);
	snprintf(subid, sizeof (subid), "softtokend-%ld", getpid());
	assert(sysevent_evc_subscribe(evchan, subid, EC_ALL, sysevc_handler,
	    (void *)channel, 0) == 0);

	add_all_zones();

	for (;;) {
		pause();
	}
}
