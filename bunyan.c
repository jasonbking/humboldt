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
#include <stdarg.h>
#include <time.h>
#include <netdb.h>

#include <sys/mman.h>
#include <libnvpair.h>

#include "bunyan.h"

static const char *bunyan_name = NULL;
static char *bunyan_hostname = NULL;
static mutex_t *bunyan_mutex = NULL;
static void *bunyan_shmem = NULL;

void
bunyan_init(void)
{
	bunyan_shmem = mmap(0, sizeof (mutex_t), PROT_READ | PROT_WRITE,
	    MAP_SHARED | MAP_ANON, -1, 0);
	assert(bunyan_shmem != NULL);
	bunyan_mutex = (mutex_t *)bunyan_shmem;
	assert(mutex_init(bunyan_mutex, USYNC_PROCESS, NULL) == 0);
}

void
bunyan_set_name(const char *name)
{
	bunyan_name = name;
}

static void
bunyan_get_hostname(void)
{
	char *buf = calloc(MAXHOSTNAMELEN, 1);
	assert(buf != NULL);
	assert(gethostname(buf, MAXHOSTNAMELEN) == 0);
	if (bunyan_hostname != NULL)
		free(bunyan_hostname);
	bunyan_hostname = buf;
}

static void
bunyan_timestamp(char *buffer, size_t len)
{
	struct timespec ts;
	struct tm *info;

	assert(clock_gettime(CLOCK_REALTIME, &ts) == 0);
	info = gmtime(&ts.tv_sec);
	assert(info != NULL);

	snprintf(buffer, len, "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
	    info->tm_year + 1900, info->tm_mon + 1, info->tm_mday,
	    info->tm_hour, info->tm_min, info->tm_sec, ts.tv_nsec / 1000000);
}

void
bunyan_log(enum bunyan_log_level level, const char *msg, ...)
{
	nvlist_t *nvl;
	char time[128];
	va_list ap;
	const char *propname;
	enum bunyan_arg_type typ;

	assert(nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0) == 0);
	assert(nvlist_add_int32(nvl, "v", 1) == 0);
	assert(nvlist_add_int32(nvl, "level", level) == 0);
	assert(nvlist_add_string(nvl, "name", bunyan_name) == 0);
	if (bunyan_hostname == NULL)
		bunyan_get_hostname();
	assert(nvlist_add_string(nvl, "hostname", bunyan_hostname) == 0);
	assert(nvlist_add_int32(nvl, "pid", getpid()) == 0);

	bunyan_timestamp(time, sizeof (time));
	assert(nvlist_add_string(nvl, "time", time) == 0);

	assert(nvlist_add_string(nvl, "msg", msg) == 0);

	va_start(ap, msg);
	while (1) {
		const char *strval;
		int intval;
		nvlist_t *nvlval;

		propname = va_arg(ap, const char *);
		if (propname == NULL)
			break;

		typ = va_arg(ap, enum bunyan_arg_type);

		switch (typ) {
		case BNY_STRING:
			strval = va_arg(ap, const char *);
			assert(nvlist_add_string(nvl, propname, strval) == 0);
			break;
		case BNY_INT:
			intval = va_arg(ap, int);
			assert(nvlist_add_int32(nvl, propname, intval) == 0);
			break;
		case BNY_NVLIST:
			nvlval = va_arg(ap, nvlist_t *);
			assert(nvlist_add_nvlist(nvl, propname, nvlval) == 0);
			break;
		}
	}
	va_end(ap);

	assert(mutex_lock(bunyan_mutex) == 0);
	nvlist_print_json(stderr, nvl);
	fprintf(stderr, "\n");
	assert(mutex_unlock(bunyan_mutex) == 0);
	nvlist_free(nvl);
}
