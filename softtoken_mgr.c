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
#include <strings.h>
#include <signal.h>

#include <zone.h>
#include <libsysevent.h>
#include <libnvpair.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/debug.h>

#include "bunyan.h"
#include "softtoken.h"

struct zone_state {
	zoneid_t zs_id;
	struct zone_state *zs_next;
	pid_t zs_child;
	int zs_pipe[2];
	uint8_t zs_cookie;
	boolean_t zs_unwanted;
};
static struct zone_state *zonest = NULL;
static mutex_t zonest_mutex;

static evchan_t *evchan;

static int
fdwalk_assert_fd(void *p, int fd)
{
	struct zone_state *zs = (struct zone_state *)p;
	if (fd != zs->zs_pipe[1])
		VERIFY3S(fd, <=, 2);
	return (0);
}

static void
start_supervisor(struct zone_state *forzone)
{
	struct zone_state *zs;
	VERIFY0(sysevent_evc_unbind(evchan));
	(void) signal(SIGCHLD, SIG_DFL);

	for (zs = zonest; zs != NULL; zs = zs->zs_next) {
		VERIFY0(close(zs->zs_pipe[0]));
	}
	VERIFY0(fdwalk(fdwalk_assert_fd, forzone));

	supervisor_main(forzone->zs_id, forzone->zs_pipe[1]);
	bunyan_log(ERROR, "supervisor_main returned!", NULL);
	exit(1);
}

static void
add_zone_unlocked(zoneid_t id)
{
	struct zone_state *zs = calloc(1, sizeof (struct zone_state));
	VERIFY3P(zs, !=, NULL);
	zs->zs_id = id;
	zs->zs_unwanted = B_FALSE;
	VERIFY0(pipe(zs->zs_pipe));

	pid_t kid = fork();
	VERIFY3S(kid, !=, -1);
	if (kid == 0) {
		VERIFY0(close(zs->zs_pipe[0]));
		start_supervisor(zs);
		return;
	}
	zs->zs_child = kid;
	VERIFY0(close(zs->zs_pipe[1]));

	zs->zs_next = zonest;
	zonest = zs;
}

static void
check_add_zone(zoneid_t id)
{
	struct zone_state *zs;

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

int
read_cmd(int fd, struct ctl_cmd *cmd)
{
	size_t off = 0, rem = sizeof (*cmd);
	int rv;
	bzero(cmd, sizeof (*cmd));
	do {
		rv = read(fd, ((char *)cmd) + off, rem);
		if (rv > 0) {
			VERIFY3U(rv, <=, rem);
			off += rv;
			rem -= rv;
		}
	} while (!(rv == 0 ||
	    (rv == -1 && !(errno == EINTR || errno == EAGAIN)) ||
	    rem <= 0));
	if (rv == -1)
		return (errno);
	if (rv == 0)
		return (ENOENT);
	bunyan_log(TRACE, "received cmd",
	    "cookie", BNY_INT, cmd->cc_cookie,
	    "type", BNY_INT, cmd->cc_type,
	    "p1", BNY_INT, cmd->cc_p1,
	    NULL);
	return (0);
}

int
write_cmd(int fd, const struct ctl_cmd *cmd)
{
	size_t off = 0, rem = sizeof (*cmd);
	int rv;
	bunyan_log(TRACE, "sending cmd",
	    "cookie", BNY_INT, cmd->cc_cookie,
	    "type", BNY_INT, cmd->cc_type,
	    "p1", BNY_INT, cmd->cc_p1,
	    NULL);
	do {
		rv = write(fd, ((const char *)cmd) + off, rem);
		if (rv > 0) {
			VERIFY3U(rv, <=, rem);
			off += rv;
			rem -= rv;
		}
	} while ((rv != -1 || errno == EINTR || errno == EAGAIN) && rem > 0);
	if (rv == -1)
		return (errno);
	return (0);
}

static void
stop_zone(zoneid_t id)
{
	struct zone_state *zs;
	struct ctl_cmd cmd;

	mutex_enter(&zonest_mutex);
	for (zs = zonest; zs != NULL; zs = zs->zs_next) {
		if (zs->zs_id == id) {
			break;
		}
	}

	if (zs != NULL) {
		zs->zs_unwanted = B_TRUE;

		bunyan_log(DEBUG, "sending shutdown command to zone",
		    "zoneid", BNY_INT, (int)id, NULL);

		bzero(&cmd, sizeof (cmd));
		cmd.cc_cookie = (++zs->zs_cookie);
		cmd.cc_type = CMD_SHUTDOWN;
		VERIFY0(write_cmd(zs->zs_pipe[0], &cmd));
	}
	mutex_exit(&zonest_mutex);
}

static void
add_all_zones(void)
{
	zoneid_t *ids = calloc(MAX_ZONEID, sizeof (zoneid_t));
	VERIFY3P(ids, !=, NULL);
	uint_t count = MAX_ZONEID;
	int i;
	VERIFY0(zone_list(ids, &count));
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
	char *nstate;

	VERIFY0(sysevent_get_attr_list(ev, &nvl));
	if (nvlist_lookup_int32(nvl, "zoneid", &zid) != 0)
		return (0);
	if (nvlist_lookup_string(nvl, "newstate", &nstate) != 0)
		return (0);

	if (strcmp(nstate, "initialized") == 0 ||
	    strcmp(nstate, "ready") == 0) {
		check_add_zone(zid);

	} else if (strcmp(nstate, "shutting_down") == 0 ||
	    strcmp(nstate, "uninitialized") == 0) {
		stop_zone(zid);
	}
	return (0);
}

static void
sigchld_handler(int signo)
{
	pid_t kid;
	int kid_status;
	struct zone_state *zsp = NULL, *zs;
	zoneid_t zid;

	while ((kid = waitpid((pid_t)0, &kid_status, WNOHANG)) > 0) {
		mutex_enter(&zonest_mutex);
		for (zs = zonest; zs != NULL; zsp = zs, zs = zs->zs_next) {
			if (zs->zs_child == kid) {
				break;
			}
		}
		if (zs != NULL) {
			zid = zs->zs_id;
			bunyan_log(TRACE,
			    "zone supervisor stopped",
			    "zoneid", BNY_INT, (int)zid,
			    "pid", BNY_INT, (int)kid,
			    "exit_status", BNY_INT,
			    (int)WEXITSTATUS(kid_status),
			    NULL);
			if (zsp != NULL) {
				zsp->zs_next = zs->zs_next;
			} else {
				VERIFY3P(zonest, ==, zs);
				zonest = zs->zs_next;
			}
			VERIFY0(close(zs->zs_pipe[0]));
			if (!zs->zs_unwanted) {
				bunyan_log(WARN,
				    "restarting zone supervisor",
				    "zoneid", BNY_INT, (int)zid,
				    "pid", BNY_INT, (int)kid,
				    NULL);
				add_zone_unlocked(zid);
			}
			free(zs);
		}
		mutex_exit(&zonest_mutex);
	}
}

const char *
_umem_debug_init()
{
	return ("guards");
}

int
main(int argc, char *argv[])
{
	const char *channel = "com.sun:zones:status";
	char subid[128];
	const char *lvl;

	bunyan_init();
	bunyan_set_name("softtoken_mgr");
	bunyan_log(INFO, "starting up", NULL);

	bunyan_set_level(DEBUG);

	lvl = getenv("LOG_LEVEL");
	if (lvl != NULL) {
		if (strcasecmp(lvl, "trace") == 0)
			bunyan_set_level(TRACE);
		if (strcasecmp(lvl, "info") == 0)
			bunyan_set_level(INFO);
		if (strcasecmp(lvl, "warn") == 0)
			bunyan_set_level(WARN);
		if (strcasecmp(lvl, "error") == 0)
			bunyan_set_level(ERROR);
	}

	VERIFY0(mutex_init(&zonest_mutex,
	    USYNC_THREAD | LOCK_ERRORCHECK, NULL));

	(void) signal(SIGCHLD, sigchld_handler);

	VERIFY0(sysevent_evc_bind(channel, &evchan, 0));
	snprintf(subid, sizeof (subid), "softtoken%u", getpid());
	VERIFY0(sysevent_evc_subscribe(evchan, subid, EC_ALL, sysevc_handler,
	    (void *)channel, 0));

	add_all_zones();

	for (;;) {
		pause();
	}
}
