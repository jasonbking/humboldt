/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2017, Joyent Inc
 * Author: Alex Wilson <alex.wilson@joyent.com>
 */

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
#include <signal.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/debug.h>
#include <sys/mman.h>
#include <sys/fork.h>
#include <sys/wait.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <dirent.h>
#include <port.h>

#include <wintypes.h>
#include <winscard.h>

#include <librename.h>
#include <libnvpair.h>

#include "libssh/sshkey.h"
#include "libssh/sshbuf.h"
#include "libssh/digest.h"
#include "libssh/cipher.h"

#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "trustchain.h"
#include "bunyan.h"
#include "piv.h"
#include "json.h"

static const char *datadir = "/var/db/trustchain";
#define	PEER_DB_FNAME		"peers.dat"
#define	CHAIN_DB_FNAME		"chain-%s.dat"

static struct peer *peers = NULL;
static size_t peer_count = 0;
static mutex_t peer_mutex;

static pid_t protokid_pid;

struct peer {
	struct peer *p_next;
	struct peer *p_prev;

	struct timespec *p_lastseen;

	int p_fd;
	struct sshbuf *p_in;
	struct sshbuf *p_out;
	struct sshbuf *p_req;
	int p_events;

	int p_proto;
	socklen_t p_addrlen;
	struct sockaddr *p_addr;
};

const char *
_umem_debug_init()
{
	return ("guards");
}

int
main(int argc, char *argv[])
{
	const char *lvl;

	bunyan_init();
	bunyan_set_name("gossip_sup");
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

	protokid_pid = forkx(FORK_WAITPID | FORK_NOSIGCHLD);
	VERIFY(protokid_pid != -1);
	if (protokid_pid == 0) {
	}
}
