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
#include <ucred.h>
#include <priv.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <dirent.h>
#include <port.h>

#include "softtoken.h"
#include "bunyan.h"
#include "sshbuf.h"

/* Messages for the authentication agent connection. */
#define SSH_AGENTC_REQUEST_RSA_IDENTITIES	1
#define SSH_AGENT_RSA_IDENTITIES_ANSWER		2
#define SSH_AGENTC_RSA_CHALLENGE		3
#define SSH_AGENT_RSA_RESPONSE			4
#define SSH_AGENT_FAILURE			5
#define SSH_AGENT_SUCCESS			6
#define SSH_AGENTC_ADD_RSA_IDENTITY		7
#define SSH_AGENTC_REMOVE_RSA_IDENTITY		8
#define SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES	9

/* private OpenSSH extensions for SSH2 */
#define SSH2_AGENTC_REQUEST_IDENTITIES		11
#define SSH2_AGENT_IDENTITIES_ANSWER		12
#define SSH2_AGENTC_SIGN_REQUEST		13
#define SSH2_AGENT_SIGN_RESPONSE		14
#define SSH2_AGENTC_ADD_IDENTITY		17
#define SSH2_AGENTC_REMOVE_IDENTITY		18
#define SSH2_AGENTC_REMOVE_ALL_IDENTITIES	19

/* smartcard */
#define SSH_AGENTC_ADD_SMARTCARD_KEY		20
#define SSH_AGENTC_REMOVE_SMARTCARD_KEY		21

/* lock/unlock the agent */
#define SSH_AGENTC_LOCK				22
#define SSH_AGENTC_UNLOCK			23

/* add key with constraints */
#define SSH_AGENTC_ADD_RSA_ID_CONSTRAINED	24
#define SSH2_AGENTC_ADD_ID_CONSTRAINED		25
#define SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED 26

#define	SSH_AGENT_CONSTRAIN_LIFETIME		1
#define	SSH_AGENT_CONSTRAIN_CONFIRM		2

/* extended failure messages */
#define SSH2_AGENT_FAILURE			30

/* additional error code for ssh.com's ssh-agent2 */
#define SSH_COM_AGENT2_FAILURE			102

#define	SSH_AGENT_OLD_SIGNATURE			0x01
#define	SSH_AGENT_RSA_SHA2_256			0x02
#define	SSH_AGENT_RSA_SHA2_512			0x04

struct client_state {
	int cs_fd;
	struct sockaddr_un cs_peer;
	ucred_t *cs_ucred;
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

#define	N_THREADS	8
static thread_t reactor_threads[N_THREADS];

static void
close_client(struct client_state *cl)
{
	mutex_enter(&clients_mtx);
	if (cl->cs_prev != NULL)
		cl->cs_prev->cs_next = cl->cs_next;
	if (cl->cs_next != NULL)
		cl->cs_next->cs_prev = cl->cs_prev;
	if (clients == cl)
		clients = cl->cs_next;
	mutex_exit(&clients_mtx);

	assert(close(cl->cs_fd) == 0);
	cl->cs_events = 0;
	sshbuf_free(cl->cs_in);
	sshbuf_free(cl->cs_out);
	ucred_free(cl->cs_ucred);
	if (cl->cs_req != NULL)
		sshbuf_free(cl->cs_req);
	free(cl);
}

enum msg_err {
	ERR_NOERROR = 0,
	ERR_INCOMPLETE,
	ERR_BADMSG
};

static void
send_status(struct client_state *cl, boolean_t success)
{
	assert(sshbuf_put_u32(cl->cs_out, 1) == 0);
	assert(sshbuf_put_u8(cl->cs_out, success ?
	    SSH_AGENT_SUCCESS : SSH_AGENT_FAILURE) == 0);
}

static int
try_process_message(struct client_state *cl)
{
	const uint8_t *cp;
	size_t len;
	int rv;
	uint8_t type;
	pid_t clientpid;

	if (sshbuf_len(cl->cs_in) < 5)
		return (ERR_INCOMPLETE);

	cp = sshbuf_ptr(cl->cs_in);
	len = cp[0] << 24 | cp[1] << 16 | cp[2] << 8 | cp[3];
	if (len > 256 * 1024) {
		close_client(cl);
		return (ERR_BADMSG);
	}

	if (sshbuf_len(cl->cs_in) < len + 4)
		return (ERR_INCOMPLETE);

	sshbuf_reset(cl->cs_req);
	rv = sshbuf_get_stringb(cl->cs_in, cl->cs_req);
	assert(rv == 0);
	rv = sshbuf_get_u8(cl->cs_req, &type);
	assert(rv == 0);

	bunyan_set(
	    "client_pid", BNY_INT, (int)ucred_getpid(cl->cs_ucred),
	    "client_euid", BNY_INT, (int)ucred_geteuid(cl->cs_ucred),
	    "type", BNY_INT, (int)type,
	    NULL);

	bunyan_log(TRACE, "processing message from client", NULL);

	switch (type) {
	case SSH2_AGENTC_SIGN_REQUEST:
		//process_sign_request2(e);
		break;
	case SSH2_AGENTC_REQUEST_IDENTITIES:
		//process_request_identities(e, 2);
		break;
	case SSH_AGENTC_LOCK:
	case SSH_AGENTC_UNLOCK:
		sshbuf_reset(cl->cs_req);
		send_status(cl, B_FALSE);
		break;
	case SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES:
		sshbuf_reset(cl->cs_req);
		send_status(cl, B_FALSE);
		break;
	case SSH2_AGENTC_ADD_IDENTITY:
	case SSH2_AGENTC_ADD_ID_CONSTRAINED:
	case SSH2_AGENTC_REMOVE_IDENTITY:
	case SSH2_AGENTC_REMOVE_ALL_IDENTITIES:
		bunyan_log(DEBUG, "unsupported operation", NULL);
		sshbuf_reset(cl->cs_req);
		send_status(cl, B_FALSE);
		break;
	default:
		bunyan_log(ERROR, "client sent unknown message type", NULL);
		sshbuf_reset(cl->cs_req);
		send_status(cl, B_FALSE);
	}
	return (0);
}

static void *
client_reactor(void *arg)
{
	port_event_t ev;
	timespec_t to;
	struct client_state *cl;
	size_t len;
	char *buf = calloc(1, 4096);
	int buflen = 4096;
	int rv;

	while (1) {
		rv = port_get(clport, &ev, NULL);
		if (rv == -1 && errno == EINTR) {
			continue;
		} else {
			assert(rv == 0);
		}
		cl = (struct client_state *)ev.portev_user;
		assert(cl != NULL);
		assert(cl->cs_fd == ev.portev_object);
		cl->cs_events = POLLIN;

		if ((ev.portev_events & POLLOUT) != 0 &&
		    sshbuf_len(cl->cs_out) > 0) {
			len = write(cl->cs_fd,
			    sshbuf_ptr(cl->cs_out),
			    sshbuf_len(cl->cs_out));
			if (len == -1 && (errno == EAGAIN ||
			    errno == EWOULDBLOCK || errno == EINTR)) {
			    	cl->cs_events |= POLLOUT;
				goto rearm;
			}
			if (len <= 0) {
				close_client(cl);
				continue;
			}
			rv = sshbuf_consume(cl->cs_out, len);
			assert(rv == 0);
			if (sshbuf_len(cl->cs_out) > 0)
				cl->cs_events |= POLLOUT;
		}

		if ((ev.portev_events & POLLIN) != 0) {
			len = read(cl->cs_fd, buf, buflen);
			if (len == -1 && (errno == EAGAIN ||
			    errno == EWOULDBLOCK || errno == EINTR)) {
				goto rearm;
			}
			if (len <= 0) {
				close_client(cl);
				continue;
			}
			rv = sshbuf_put(cl->cs_in, buf, len);
			assert(rv == 0);
			explicit_bzero(buf, len);
			rv = try_process_message(cl);
			if (rv == ERR_BADMSG)
				continue;
			if (sshbuf_len(cl->cs_out) > 0)
				cl->cs_events |= POLLOUT;
		}

rearm:
		assert(port_associate(clport,
		    PORT_SOURCE_FD, cl->cs_fd, cl->cs_events, cl) == 0);
	}
}

void
agent_main(zoneid_t zid, int listensock, int ctlfd)
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
	zoneid_t theirzid;

	bunyan_set_name("agent");

	assert(listen(listensock, 10) == 0);

	portfd = port_create();
	assert(portfd > 0);

	clport = port_create();
	assert(clport > 0);

	assert(mutex_init(&clients_mtx, USYNC_THREAD | LOCK_ERRORCHECK,
	    NULL) == 0);

	for (i = 0; i < N_THREADS; ++i) {
		rv = thr_create(NULL, 0, client_reactor, NULL, 0,
		    &reactor_threads[i]);
		assert(rv == 0);
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
				break;
			}
			assert(port_associate(portfd,
			    PORT_SOURCE_FD, ctlfd, POLLIN, NULL) == 0);

		} else if (ev.portev_object == listensock) {
			raddrlen = sizeof (raddr);
			bzero(&raddr, sizeof (raddr));
			sockfd = accept(listensock, (struct sockaddr *)&raddr,
			    &raddrlen);
			assert(sockfd > 0);

			cl = calloc(1, sizeof (struct client_state));
			assert(cl != NULL);
			bcopy(&raddr, &cl->cs_peer, raddrlen);
			if (getpeerucred(sockfd, &cl->cs_ucred) != 0) {
				bunyan_log(ERROR,
				    "failed to get peer ucred",
				    "errno", BNY_INT, errno, NULL);
				free(cl);
				assert(close(sockfd) == 0);
				goto rearmlisten;
			}
			theirzid = ucred_getzoneid(cl->cs_ucred);
			if (theirzid != zid) {
				bunyan_log(ERROR,
				    "zoneid of client doesn't match server",
				    "client_zoneid", BNY_INT, theirzid, NULL);
				free(cl);
				assert(close(sockfd) == 0);
				goto rearmlisten;
			}
			cl->cs_fd = sockfd;
			cl->cs_in = sshbuf_new();
			assert(cl->cs_in != NULL);
			cl->cs_out = sshbuf_new();
			assert(cl->cs_in != NULL);
			cl->cs_req = sshbuf_new();
			assert(cl->cs_in != NULL);
			cl->cs_events = POLLIN;

			mutex_enter(&clients_mtx);
			if (clients != NULL)
				clients->cs_prev = cl;
			cl->cs_next = clients;
			clients = cl;
			mutex_exit(&clients_mtx);

			assert(port_associate(clport,
			    PORT_SOURCE_FD, cl->cs_fd, cl->cs_events, cl) == 0);
rearmlisten:
			assert(port_associate(portfd,
			    PORT_SOURCE_FD, listensock, POLLIN, NULL) == 0);

		} else {
			assert(0);
		}
	}
}
