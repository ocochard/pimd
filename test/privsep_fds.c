/*
 * privsep_fds - what the privsep socket does with descriptors it was not asked for
 *
 * Copyright (c) 2026  Olivier Cochard-Labbe <olivier@cochard.me>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *
 * The parent of a separated pimd reads every request with msg_recv() and
 * wants no descriptor out of one, and a child replies through the same
 * function wanting one at most.  The kernel installs every SCM_RIGHTS
 * descriptor a message carries before recvmsg() returns, so the ones not
 * wanted have to be closed, or a child attaching two to every request
 * fills the root parent's descriptor table a pair at a time.
 * msg_take_fd() (src/privsep.c) closes them; this asserts it, over the
 * same SOCK_SEQPACKET socketpair pimd uses, by counting this process's
 * open descriptors around each message.
 *
 * The counts are 0 to 3 and 10.  pimd's control buffer is CMSG_SPACE() of
 * one int, which the alignment rounds up to room for two on LP64, so the
 * larger counts are the kernel's truncation path rather than msg_take_fd()'s
 * -- and whether the descriptors that did not fit are closed for us or left
 * installed is the operating system's to answer; this asks it.  FreeBSD
 * drops every descriptor of a truncated message, so a reply that carried
 * more than fit hands over none, which is asserted only as "nothing left
 * open": no pimd reply carries more than one.  Zero and one are the
 * controls: a request carrying nothing, and a reply carrying the one
 * descriptor it is meant to.
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "defs.h"
#include "privsep.h"

#define MAX_FDS	10

/* What msg_recv()'s control buffer holds */
#define FITS	((int)((CMSG_SPACE(sizeof(int)) - CMSG_LEN(0)) / sizeof(int)))

static int open_fds(void)
{
	int fd, n = 0, max = getdtablesize();

	for (fd = 0; fd < max; fd++) {
		if (fcntl(fd, F_GETFD) != -1 || errno != EBADF)
			n++;
	}

	return n;
}

/* One message of @len bytes carrying @nfds fresh descriptors, which the
 * sender's side closes again once they are on the way */
static int send_fds(int sd, void *buf, size_t len, int nfds)
{
	union {
		struct cmsghdr align;
		char buf[CMSG_SPACE(MAX_FDS * sizeof(int))];
	} cmsg;
	int fds[MAX_FDS], i, rc;
	struct msghdr msg;
	struct iovec iov;

	memset(&msg, 0, sizeof(msg));
	iov.iov_base   = buf;
	iov.iov_len    = len;
	msg.msg_iov    = &iov;
	msg.msg_iovlen = 1;

	for (i = 0; i < nfds; i++) {
		fds[i] = open("/dev/null", O_RDONLY);
		if (fds[i] < 0)
			return -1;
	}

	if (nfds) {
		struct cmsghdr *cm;

		memset(&cmsg, 0, sizeof(cmsg));
		msg.msg_control    = cmsg.buf;
		msg.msg_controllen = CMSG_SPACE(nfds * sizeof(int));

		cm = CMSG_FIRSTHDR(&msg);
		cm->cmsg_len   = CMSG_LEN(nfds * sizeof(int));
		cm->cmsg_level = SOL_SOCKET;
		cm->cmsg_type  = SCM_RIGHTS;
		memcpy(CMSG_DATA(cm), fds, nfds * sizeof(int));
	}

	rc = sendmsg(sd, &msg, 0) == (ssize_t)len ? 0 : -1;
	for (i = 0; i < nfds; i++)
		close(fds[i]);

	return rc;
}

/*
 * One message with @nfds descriptors, read the way the parent reads a
 * request (@want 0, no descriptor out of it) or the way the child reads a
 * reply (@want 1, the first one kept).  Fails unless the process holds
 * exactly as many descriptors afterwards as before, plus the one kept.
 */
static int check(int sv[2], int nfds, int want)
{
	char out[64], in[64];
	int before, after, got = -1, kept;

	memset(out, 'x', sizeof(out));
	before = open_fds();
	if (send_fds(sv[0], out, sizeof(out), nfds)) {
		printf("FAIL  %d descriptors, %s: send failed: %s\n", nfds,
		       want ? "reply" : "request", strerror(errno));
		return 1;
	}

	if (priv_msg_recv(sv[1], in, sizeof(in), want ? &got : NULL) ||
	    memcmp(in, out, sizeof(in))) {
		printf("FAIL  %d descriptors, %s: the message itself did not arrive\n",
		       nfds, want ? "reply" : "request");
		return 1;
	}

	kept = (want && nfds && got >= 0) ? 1 : 0;
	after = open_fds();
	if (got >= 0)
		close(got);

	if (want && nfds && nfds <= FITS && got < 0) {
		printf("FAIL  %d descriptors, reply: the one wanted was not handed over\n", nfds);
		return 1;
	}
	if (after != before + kept) {
		printf("FAIL  %d descriptors, %s: %d open before, %d after, %d kept\n",
		       nfds, want ? "reply" : "request", before, after, kept);
		return 1;
	}

	printf("ok    %d descriptors, %s: %d open before and after%s\n", nfds,
	       want ? "reply" : "request", before, kept ? ", the wanted one aside" : "");
	return 0;
}

int main(void)
{
	static const int counts[] = { 0, 1, 2, 3, MAX_FDS };
	int sv[2], rc = 0;
	size_t i;

	if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) < 0) {
		perror("socketpair");
		return 1;
	}

	for (i = 0; i < sizeof(counts) / sizeof(counts[0]); i++) {
		rc |= check(sv, counts[i], 0);
		rc |= check(sv, counts[i], 1);
	}

	close(sv[0]);
	close(sv[1]);

	return rc;
}
