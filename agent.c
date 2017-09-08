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
#include <dirent.h>
#include <port.h>

#include "softtoken.h"
#include "bunyan.h"

struct client_state {
	int cs_fd;
	struct sockaddr_un cs_peer;
	struct sshbuf *cs_in;
	struct sshbuf *cs_out;
	struct sshbuf *cs_req;
	int cs_events;
	struct client_state *cs_next;
	struct client_state *cs_prev;
};

static mutex_t clients_mtx;
static struct client_state *clients;
static int clport;

const static int N_THREADS = 8;
static pthread_t reactor_threads[N_THREADS];

static void
close_client(struct client_state *cl)
{
	assert(close(cl->cs_fd) == 0);
	cl->cs_events = 0;
	sshbuf_free(cl->cs_in);
	sshbuf_free(cl->cs_out);
}

static void *
client_reactor(void *)
{
	port_event_t ev;
	timespec_t to;
	struct client_state *cl;
	size_t len;
	char *buf = calloc(1, 4096);
	int buflen = 4096;

	while (1) {
		rv = port_get(portfd, &ev, NULL);
		if (rv == -1 && errno == EINTR) {
			continue;
		} else {
			assert(rv == 0);
		}
		cl = (struct client_state *)ev.portev_user;
		assert(cl != NULL);
		assert(cl->cs_fd == ev.portev_object);

		len = read(cl->cs_fd, buf, buflen);
		if (len == -1 && (errno == EAGAIN ||
		    errno == EWOULDBLOCK || errno == EINTR)) {
			goto rearm;
		} else if (len <= 0) {
			close_client(cl);
		}
rearm:
		assert(port_associate(clport,
		    PORT_SOURCE_FD, cl->cs_fd, cs->cs_events, cl) == 0);
	}
}

void
agent_main(int listensock, int ctlfd)
{
	int portfd;
	struct ctl_cmd cmd;
	enum ctl_cmd_type cmdtype;
	FILE *ctl;
	port_event_t ev;
	timespec_t to;
	int sockfd;
	struct sockaddr_un raddr;
	size_t raddrlen;
	struct client_state *cl;
	int i, rv;

	assert(listen(listensock, 10) == 0);

	portfd = port_create();
	assert(portfd > 0);

	clport = port_create();
	assert(clport > 0);

	assert(mutex_init(&clients_mtx, USYNC_THREAD, NULL) == 0);

	for (i = 0; i < N_THREADS; ++i) {
		rv = pthread_create(&reactor_threads[i], NULL,
		    client_reactor, NULL);
	}

	assert(port_associate(portfd,
	    PORT_SOURCE_FD, listensock, POLLIN, NULL) == 0);
	assert(port_associate(portfd,
	    PORT_SOURCE_FD, ctlfd, POLLIN, NULL) == 0);

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
			case CMD_STATUS:
				break;
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

		} else if (ev.portev_object == listensock) {
			raddrlen = sizeof (raddr);
			bzero(&raddr, sizeof (raddr));
			sockfd = accept(listensock, &raddr, &raddrlen);
			assert(sockfd > 0);

			cl = calloc(1, sizeof (struct client_state));
			bcopy(&raddr, cl->cs_peer, raddrlen);
			cl->cs_fd = sockfd;
			cl->cs_in = sshbuf_new();
			cl->cs_out = sshbuf_new();
			cl->cs_events = POLLIN;

			assert(mutex_lock(&clients_mtx) == 0);
			if (clients != NULL)
				clients->cs_prev = cl;
			cl->cs_next = clients;
			clients = cl;
			assert(mutex_unlock(&clients_mtx) == 0);

			assert(port_associate(clport,
			    PORT_SOURCE_FD, cl->cs_fd, cs->cs_events, cl) == 0);
			assert(port_associate(portfd,
			    PORT_SOURCE_FD, listensock, POLLIN, NULL) == 0);

		} else {
			assert(0);
		}
	}
}
