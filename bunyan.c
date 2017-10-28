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
#include <strings.h>

#include <sys/mman.h>
#include <sys/debug.h>
#include <sys/sdt.h>
#include <libnvpair.h>

#include "bunyan.h"

static const char *bunyan_name = NULL;
static char *bunyan_hostname = NULL;
static mutex_t bunyan_bmutex;
mutex_t *bunyan_wrmutex = NULL;
static void *bunyan_shmem = NULL;
static nvlist_t *bunyan_base = NULL;
static enum bunyan_log_level bunyan_min_level = INFO;

struct bunyan_timers {
	struct timer_block *bt_first;
	struct timer_block *bt_last;
	struct timespec bt_current;
};

#define	TBLOCK_N	16
struct timer_block {
	struct timespec tb_timers[TBLOCK_N];
	const char *tb_names[TBLOCK_N];
	size_t tb_pos;
	struct timer_block *tb_next;
};

#define	NS_PER_S	1000000000ULL

static inline char
nybble_to_hex(uint8_t nybble)
{
	if (nybble >= 0xA)
		return ('A' + (nybble - 0xA));
	else
		return ('0' + nybble);
}

char *
buf_to_hex(const uint8_t *buf, size_t len, boolean_t spaces)
{
	size_t i, j = 0;
	char *out = calloc(1, len * 3 + 1);
	uint8_t nybble;
	for (i = 0; i < len; ++i) {
		nybble = (buf[i] & 0xF0) >> 4;
		out[j++] = nybble_to_hex(nybble);
		nybble = (buf[i] & 0x0F);
		out[j++] = nybble_to_hex(nybble);
		if (spaces && i + 1 < len)
			out[j++] = ' ';
	}
	out[j] = 0;
	return (out);
}

void
tspec_subtract(struct timespec *result, const struct timespec *x,
    const struct timespec *y)
{
	struct timespec xcarry;
	bcopy(x, &xcarry, sizeof (xcarry));
	if (xcarry.tv_nsec < y->tv_nsec) {
		xcarry.tv_sec -= 1;
		xcarry.tv_nsec += NS_PER_S;
	}
	result->tv_sec = xcarry.tv_sec - y->tv_sec;
	result->tv_nsec = xcarry.tv_nsec - y->tv_nsec;
}

static int
bny_timers_to_nvl(struct bunyan_timers *tms, nvlist_t *nvl)
{
	struct timer_block *b;
	size_t idx;
	uint64_t usec;
	int rv;

	for (b = tms->bt_first; b != NULL; b = b->tb_next) {
		for (idx = 0; idx < b->tb_pos; ++idx) {
			usec = b->tb_timers[idx].tv_nsec / 1000;
			usec += b->tb_timers[idx].tv_sec * 1000000;
			if ((rv = nvlist_add_uint64(nvl,
			    b->tb_names[idx], usec))) {
				return (rv);
			}
		}
	}
	return (0);
}

void
bunyan_set_level(enum bunyan_log_level level)
{
	mutex_enter(&bunyan_bmutex);
	bunyan_min_level = level;
	mutex_exit(&bunyan_bmutex);
}

struct bunyan_timers *
bny_timers_new(void)
{
	struct bunyan_timers *tms;
	tms = calloc(1, sizeof (struct bunyan_timers));
	if (tms == NULL)
		return (NULL);
	tms->bt_first = calloc(1, sizeof (struct timer_block));
	if (tms->bt_first == NULL) {
		free(tms);
		return (NULL);
	}
	tms->bt_last = tms->bt_first;
	return (tms);
}

int
bny_timer_begin(struct bunyan_timers *tms)
{
	if (clock_gettime(CLOCK_MONOTONIC, &tms->bt_current))
		return (errno);
	return (0);
}

int
bny_timer_next(struct bunyan_timers *tms, const char *name)
{
	struct timespec now;
	size_t idx;
	struct timer_block *b;

	if (clock_gettime(CLOCK_MONOTONIC, &now))
		return (errno);
	b = tms->bt_last;
	b->tb_names[b->tb_pos] = name;
	tspec_subtract(&b->tb_timers[b->tb_pos], &now, &tms->bt_current);
	if (++b->tb_pos >= TBLOCK_N) {
		b = calloc(1, sizeof (struct timer_block));
		if (b == NULL) {
			tms->bt_last->tb_pos--;
			return (ENOMEM);
		}
		tms->bt_last->tb_next = b;
		tms->bt_last = b;
		if (clock_gettime(CLOCK_MONOTONIC, &tms->bt_current))
			return (errno);
	} else {
		bcopy(&now, &tms->bt_current, sizeof (struct timespec));
	}
	return (0);
}

void
bny_timers_free(struct bunyan_timers *tms)
{
	struct timer_block *b, *nb;
	for (b = tms->bt_first; b != NULL; b = nb) {
		nb = b->tb_next;
		free(b);
	}
	free(tms);
}

void
bunyan_unshare(void)
{
	assert(bunyan_shmem != NULL);
	VERIFY0(munmap(bunyan_shmem, sizeof (mutex_t)));
	bunyan_shmem = NULL;
	bunyan_shmem = mmap(0, sizeof (mutex_t), PROT_READ | PROT_WRITE,
	    MAP_SHARED | MAP_ANON, -1, 0);
	assert(bunyan_shmem != NULL);
	bzero(bunyan_shmem, sizeof (mutex_t));
	bunyan_wrmutex = (mutex_t *)bunyan_shmem;
	VERIFY0(mutex_init(bunyan_wrmutex, USYNC_PROCESS | LOCK_ERRORCHECK,
	    NULL));
}

void
bunyan_init(void)
{
	assert(bunyan_shmem == NULL);
	bunyan_shmem = mmap(0, sizeof (mutex_t), PROT_READ | PROT_WRITE,
	    MAP_SHARED | MAP_ANON, -1, 0);
	assert(bunyan_shmem != NULL);
	bzero(bunyan_shmem, sizeof (mutex_t));
	bunyan_wrmutex = (mutex_t *)bunyan_shmem;
	VERIFY0(mutex_init(bunyan_wrmutex, USYNC_PROCESS | LOCK_ERRORCHECK,
	    NULL));
	VERIFY0(mutex_init(&bunyan_bmutex, USYNC_THREAD | LOCK_ERRORCHECK,
	    NULL));
	VERIFY0(nvlist_alloc(&bunyan_base, NV_UNIQUE_NAME, 0));
	VERIFY0(nvlist_add_int32(bunyan_base, "v", 1));
}

void
bunyan_set_name(const char *name)
{
	mutex_enter(&bunyan_bmutex);
	bunyan_name = name;
	mutex_exit(&bunyan_bmutex);
}

static void
bunyan_get_hostname(void)
{
	char *buf = calloc(1, MAXHOSTNAMELEN);
	assert(buf != NULL);
	VERIFY0(gethostname(buf, MAXHOSTNAMELEN));
	if (bunyan_hostname != NULL)
		free(bunyan_hostname);
	bunyan_hostname = buf;
}

static void
bunyan_timestamp(char *buffer, size_t len)
{
	struct timespec ts;
	struct tm *info;

	VERIFY0(clock_gettime(CLOCK_REALTIME, &ts));
	info = gmtime(&ts.tv_sec);
	assert(info != NULL);

	snprintf(buffer, len, "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
	    info->tm_year + 1900, info->tm_mon + 1, info->tm_mday,
	    info->tm_hour, info->tm_min, info->tm_sec, ts.tv_nsec / 1000000);
}

void
bunyan_set(const char *name1, enum bunyan_arg_type typ1, ...)
{
	const char *propname = name1;
	enum bunyan_arg_type typ = typ1;
	nvlist_t * const nvl = bunyan_base;
	va_list ap;

	va_start(ap, typ1);
	while (1) {
		const char *strval;
		int intval;
		nvlist_t *nvlval;

		switch (typ) {
		case BNY_STRING:
			strval = va_arg(ap, const char *);
			mutex_enter(&bunyan_bmutex);
			VERIFY0(nvlist_add_string(nvl, propname, strval));
			mutex_exit(&bunyan_bmutex);
			break;
		case BNY_INT:
			intval = va_arg(ap, int);
			mutex_enter(&bunyan_bmutex);
			VERIFY0(nvlist_add_int32(nvl, propname, intval));
			mutex_exit(&bunyan_bmutex);
			break;
		case BNY_NVLIST:
			nvlval = va_arg(ap, nvlist_t *);
			mutex_enter(&bunyan_bmutex);
			VERIFY0(nvlist_add_nvlist(nvl, propname, nvlval));
			mutex_exit(&bunyan_bmutex);
			break;
		}

		propname = va_arg(ap, const char *);
		if (propname == NULL)
			break;

		typ = va_arg(ap, enum bunyan_arg_type);
	}
	va_end(ap);
}

void
bunyan_log(enum bunyan_log_level level, const char *msg, ...)
{
	nvlist_t *nvl, *nnvl;
	char time[128];
	va_list ap;
	const char *propname;
	enum bunyan_arg_type typ;

	mutex_enter(&bunyan_bmutex);
	VERIFY0(nvlist_dup(bunyan_base, &nvl, 0));
	VERIFY0(nvlist_add_int32(nvl, "level", level));
	VERIFY0(nvlist_add_string(nvl, "name", bunyan_name));
	if (bunyan_hostname == NULL)
		bunyan_get_hostname();
	VERIFY0(nvlist_add_string(nvl, "hostname", bunyan_hostname));
	mutex_exit(&bunyan_bmutex);

	VERIFY0(nvlist_add_int32(nvl, "pid", getpid()));

	bunyan_timestamp(time, sizeof (time));
	VERIFY0(nvlist_add_string(nvl, "time", time));

	VERIFY0(nvlist_add_string(nvl, "msg", msg));

	va_start(ap, msg);
	while (1) {
		const char *strval;
		char *wstrval;
		const uint8_t *binval;
		int intval;
		uint uintval;
		uint64_t uint64val;
		size_t szval;
		nvlist_t *nvlval;
		struct bunyan_timers *tsval;

		propname = va_arg(ap, const char *);
		if (propname == NULL)
			break;

		typ = va_arg(ap, enum bunyan_arg_type);

		switch (typ) {
		case BNY_STRING:
			strval = va_arg(ap, const char *);
			VERIFY0(nvlist_add_string(nvl, propname, strval));
			break;
		case BNY_INT:
			intval = va_arg(ap, int);
			VERIFY0(nvlist_add_int32(nvl, propname, intval));
			break;
		case BNY_UINT:
			uintval = va_arg(ap, uint);
			VERIFY0(nvlist_add_uint32(nvl, propname, uintval));
			break;
		case BNY_UINT64:
			uint64val = va_arg(ap, uint64_t);
			VERIFY0(nvlist_add_uint64(nvl, propname, uint64val));
			break;
		case BNY_SIZE_T:
			szval = va_arg(ap, size_t);
			VERIFY0(nvlist_add_uint64(nvl, propname, szval));
			break;
		case BNY_NVLIST:
			nvlval = va_arg(ap, nvlist_t *);
			VERIFY0(nvlist_add_nvlist(nvl, propname, nvlval));
			break;
		case BNY_TIMERS:
			tsval = va_arg(ap, struct bunyan_timers *);
			VERIFY0(nvlist_alloc(&nnvl, NV_UNIQUE_NAME, 0));
			VERIFY0(bny_timers_to_nvl(tsval, nnvl));
			VERIFY0(nvlist_add_nvlist(nvl, propname, nnvl));
			break;
		case BNY_BIN_HEX:
			binval = va_arg(ap, const uint8_t *);
			szval = va_arg(ap, size_t);
			wstrval = buf_to_hex(binval, szval, B_TRUE);
			VERIFY0(nvlist_add_string(nvl, propname, wstrval));
			free(wstrval);
			break;
		default:
			assert(0);
		}
	}
	va_end(ap);

	mutex_enter(&bunyan_bmutex);
	if (level < bunyan_min_level) {
		mutex_exit(&bunyan_bmutex);
		return;
	}
	mutex_exit(&bunyan_bmutex);

	mutex_enter(bunyan_wrmutex);
	nvlist_print_json(stderr, nvl);
	fprintf(stderr, "\n");
	mutex_exit(bunyan_wrmutex);
	nvlist_free(nvl);
}
