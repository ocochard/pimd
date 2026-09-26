/*
 * Copyright (c) 2026 Olivier Cochard-Labbe <olivier@cochard.me>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "defs.h"
#include "autorp.h"
#include <sys/stat.h>		/* umask() */
#include <pwd.h>
#include <time.h>		/* tzset() */
#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif
#ifdef HAVE_SYS_PROCCTL_H
#include <sys/procctl.h>
#endif
#if defined(HAVE_LINUX_SECCOMP_H) && defined(HAVE_LINUX_FILTER_H) && \
    defined(HAVE_LINUX_AUDIT_H) && defined(HAVE_SYS_PRCTL_H)
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sys/syscall.h>

/*
 * The filter has to refuse any architecture but the one it was built for,
 * or a 32-bit entry into a 64-bit kernel would reach a syscall table where
 * the numbers below mean something else entirely.  An architecture with no
 * constant here gets no filter rather than a wrong one.
 */
# if defined(__x86_64__)
#  define PIMD_AUDIT_ARCH	AUDIT_ARCH_X86_64
# elif defined(__i386__)
#  define PIMD_AUDIT_ARCH	AUDIT_ARCH_I386
# elif defined(__aarch64__)
#  define PIMD_AUDIT_ARCH	AUDIT_ARCH_AARCH64
# elif defined(__arm__)
#  define PIMD_AUDIT_ARCH	AUDIT_ARCH_ARM
# elif defined(__powerpc64__)
#  define PIMD_AUDIT_ARCH	AUDIT_ARCH_PPC64LE
# elif defined(__riscv) && __riscv_xlen == 64
#  define PIMD_AUDIT_ARCH	AUDIT_ARCH_RISCV64
# endif
#endif
#include <grp.h>
#include <sys/wait.h>

/*
 * The wire.  Both messages are fixed size and neither side ever parses a
 * length the other side chose: every transfer is the size of the struct,
 * so a message that arrives at all arrives whole.  That costs a couple of
 * kilobytes per call on a socketpair and buys the absence of the entire
 * class of bug this daemon is being separated to contain.  The size is the
 * agreement; a transfer that stops short of it is resumed rather than read
 * as the peer going away, see msg_send() and msg_recv().
 */
struct priv_req {
    uint32_t	op;
    union {
	uint32_t	  sock;		/* enum priv_sock		*/
	struct vifctl	  vc;
	struct {
	    uint32_t	  vifi;
	    struct vifctl vc;		/* Linux wants the whole thing	*/
	} delvif;
	struct mfcctl	  mc;
	struct sioc_vif_req vreq;
	struct sioc_sg_req  sgreq;
	char		  ifname[IFNAMSIZ];
	struct {
	    int32_t	  severity;
	    int32_t	  syserr;
	    char	  msg[PRIV_LOG_MAX];
	} log;
    } u;
};

struct priv_rep {
    uint32_t	op;
    int32_t	rc;
    int32_t	err;
    uint32_t	count;			/* records below, or an ifindex	*/
    union {
	struct sioc_vif_req vreq;
	struct sioc_sg_req  sgreq;
	struct priv_ifrec   ifrec[PRIV_IFREC_MAX];
    } u;
};

enum priv_op {
    PRIV_SOCKET = 1,
    PRIV_SOCKET_RELEASE,
    PRIV_MRT_INIT,
    PRIV_MRT_DONE,
    PRIV_ADD_VIF,
    PRIV_DEL_VIF,
    PRIV_CHG_MFC,
    PRIV_DEL_MFC,
    PRIV_VIF_CNT,
    PRIV_SG_CNT,
    PRIV_IFSCAN,
    PRIV_IFINDEX,
    PRIV_CONF_OPEN,
    PRIV_TEMPFILE,
    PRIV_PIDFILE,
    PRIV_IPC_SOCKET,
    PRIV_IPC_CLOSE,
    PRIV_LOG,
};

/*
 * Child state.  priv_sock is the one descriptor the child keeps to the
 * parent, and the only thing that tells the two halves apart at runtime.
 */
static int   priv_sock = -1;
static char  priv_username[64];
static char  priv_sandbox_name[32] = "none";
/* Holds PRIVSEP_CHROOT, a compile-time constant, or "none": sized from the
 * constant itself so that what is reported is never a truncation of what
 * was done. */
static char  priv_chroot_path[sizeof(PRIVSEP_CHROOT) > 8
			      ? sizeof(PRIVSEP_CHROOT) : 8] = "none";

/* Parent state.  The paths are fixed here before the fork and are never
 * sent, so that nothing the child says can name a file. */
static char *parent_conf;
static char *parent_pid;
static char *parent_sock;
static int   parent_fd[PRIV_SOCK_AUTORP + 1];
static pid_t parent_child = -1;

static void parent_cleanup(void);
static int parent_loop(int sd) __attribute__((noreturn));

/*
 * Send and receive, with an optional descriptor riding along.  EINTR is
 * expected: the child runs on a SIGALRM tick, and sigaction() is called
 * with no SA_RESTART on purpose (src/main.c), so every signal this daemon
 * takes lands in the middle of whatever syscall was running.
 *
 * Both loop until the whole struct has crossed, and that is not belt and
 * braces.  A unix SOCK_SEQPACKET socket on FreeBSD carries neither
 * PR_ATOMIC nor a record boundary (sys/kern/uipc_usrreq.c): it runs
 * through sosend_generic() like a stream, so a blocking sendmsg() that has
 * already copied part of a record and is waiting for room returns *what it
 * copied* when a signal arrives, not EINTR.  Measured, on a socketpair
 * with the buffer filled and a 1ms timer: "SHORT 436 of 700".  Treating
 * that as the peer going away is what it was, and it cost a daemon on the
 * FreeBSD CI runner: the fragment stayed in the buffer, the far side read
 * the next message across it, and both halves gave up without a word --
 * the child because the log it tried to send is the thing that broke, the
 * parent because a message it cannot read means the child is gone.
 *
 * So a short transfer is resumed from where it stopped.  The descriptor
 * rides on the first fragment; a signal cannot split a control message
 * away from the byte it accompanies, since SCM_RIGHTS is passed with the
 * first byte of the record either way.
 */
static int msg_send(int sd, void *buf, size_t len, int fd)
{
    struct msghdr msg;
    struct iovec iov;
    union {
	struct cmsghdr align;
	char buf[CMSG_SPACE(sizeof(int))];
    } cmsg;
    size_t off = 0;
    ssize_t n;

    while (off < len) {
	iov.iov_base = (char *)buf + off;
	iov.iov_len  = len - off;

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov    = &iov;
	msg.msg_iovlen = 1;

	if (fd >= 0 && off == 0) {
	    struct cmsghdr *cm;

	    memset(&cmsg, 0, sizeof(cmsg));
	    msg.msg_control    = cmsg.buf;
	    msg.msg_controllen = sizeof(cmsg.buf);

	    cm = CMSG_FIRSTHDR(&msg);
	    cm->cmsg_len   = CMSG_LEN(sizeof(int));
	    cm->cmsg_level = SOL_SOCKET;
	    cm->cmsg_type  = SCM_RIGHTS;
	    memcpy(CMSG_DATA(cm), &fd, sizeof(fd));
	}

	n = sendmsg(sd, &msg, 0);
	if (n < 0) {
	    if (errno == EINTR)
		continue;	/* Nothing copied, the whole of it is left */
	    return -1;
	}
	if (n == 0)
	    return -1;		/* Cannot happen on a socket, and not a loop */

	off += (size_t)n;
    }

    return 0;
}

/*
 * Every descriptor in here is already open in this process: the kernel
 * installed them before recvmsg() returned, so one that is not wanted has
 * to be closed rather than skipped.  Counting them out of cmsg_len rather
 * than demanding one exactly is the difference: this side is the
 * privileged one when the parent reads a request, and a child that
 * attached two descriptors to every message it sent would otherwise fill
 * the parent's descriptor table a pair at a time.
 */
static int msg_take_fd(struct msghdr *msg, int *fd)
{
    struct cmsghdr *cm;

    for (cm = CMSG_FIRSTHDR(msg); cm; cm = CMSG_NXTHDR(msg, cm)) {
	size_t i, nfds;

	if (cm->cmsg_level != SOL_SOCKET || cm->cmsg_type != SCM_RIGHTS)
	    continue;
	if (cm->cmsg_len < CMSG_LEN(0))
	    continue;	       /* Not a length to subtract from */

	nfds = (cm->cmsg_len - CMSG_LEN(0)) / sizeof(int);

	for (i = 0; i < nfds; i++) {
	    int rfd;

	    memcpy(&rfd, CMSG_DATA(cm) + i * sizeof(int), sizeof(rfd));
	    if (fd && *fd < 0)
		*fd = rfd;     /* One is all any reply is meant to carry */
	    else
		close(rfd);
	}
    }

    return 0;
}

static int msg_recv(int sd, void *buf, size_t len, int *fd)
{
    struct msghdr msg;
    struct iovec iov;
    union {
	struct cmsghdr align;
	char buf[CMSG_SPACE(sizeof(int))];
    } cmsg;
    size_t off = 0;
    ssize_t n;

    if (fd)
	*fd = -1;

    while (off < len) {
	iov.iov_base = (char *)buf + off;
	iov.iov_len  = len - off;

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov        = &iov;
	msg.msg_iovlen     = 1;
	msg.msg_control    = cmsg.buf;
	msg.msg_controllen = sizeof(cmsg.buf);

	n = recvmsg(sd, &msg, 0);
	if (n < 0) {
	    if (errno == EINTR)
		continue;
	    return -1;
	}
	if (n == 0)
	    return -1;		/* The peer really is gone */

	off += (size_t)n;

	/* The descriptors of this fragment, before the next read
	 * overwrites the control buffer they were counted out of. */
	if (msg_take_fd(&msg, fd))
	    return -1;

	/* Waiting here for the rest of a message gives the peer nothing it
	 * did not already have: each half talks to one other process and to
	 * no one else, so a peer that stops mid-message can equally stop
	 * before sending one, and a parent with no child to serve has
	 * nothing left to do anyway. */
    }

    return 0;
}


/*
 * One request, one reply.  Anything that goes wrong on the socket means
 * the parent is gone, and a child that cannot reach it cannot keep
 * forwarding: say so once and exit rather than run on blind.
 */
static int priv_call(struct priv_req *req, struct priv_rep *rep, int *fd)
{
    if (msg_send(priv_sock, req, sizeof(*req), -1) ||
	msg_recv(priv_sock, rep, sizeof(*rep), fd)) {
	if (priv_sock >= 0) {
	    priv_sock = -1;    /* Stop priv_log() from recursing into this */
	    logit(LOG_ERR, errno, "Lost the privileged helper, exiting");
	}

	exit(1);
    }

    /* A reply for another request means the two sides have lost step,
     * which cannot be recovered from and must not be read as an answer:
     * the descriptor or the struct in it would belong to something else. */
    if (rep->op != req->op) {
	priv_sock = -1;
	logit(LOG_ERR, 0, "Privsep protocol desync, asked %u and was answered %u",
	      req->op, rep->op);
	exit(1);
    }

    if (rep->rc)
	errno = rep->err;

    return rep->rc;
}

static void req_init(struct priv_req *req, enum priv_op op)
{
    memset(req, 0, sizeof(*req));
    req->op = op;
}

int priv_enabled(void)
{
    return priv_sock >= 0;
}

const char *priv_user(void)
{
    return priv_username;
}

const char *priv_sandbox(void)
{
    return priv_sandbox_name;
}

const char *priv_chroot_dir(void)
{
    return priv_chroot_path;
}

/*
 * Shut the filesystem away from the child, before it stops being root and
 * can no longer do it.  There is nothing left for it to want: the
 * configuration arrives as a descriptor the parent opened, the PID file
 * and the pimctl socket are the parent's, and so is every log line: both
 * syslog(3) and the timestamp on a foreground one are written by
 * log_emit() (src/debug.c) on that side, which is what leaves this side
 * with no /etc/localtime to want either.  So this costs the daemon nothing
 * and takes open(2) by path away from whatever gets into the parser --
 * which on the BSDs, where there is no sandbox to be had, is the only
 * thing that does.
 *
 * Best effort on purpose, like the fallback to nobody: pimd separates by
 * default, and a router that refuses to start because a directory is
 * missing is worse than one that says so and runs.  What it will not do is
 * chroot somewhere unsafe -- a directory anyone but root can write to is a
 * chroot the child could be handed a file in.
 *
 * One thing is lost with it: a core dump, which the kernel writes relative
 * to the process's root and which this directory may not be written to.
 * --without-privsep-chroot, or --no-privsep, is how to get one.
 */
static void priv_do_chroot(void)
{
    const char *dir = PRIVSEP_CHROOT;
    struct stat st;

    if (!dir[0])
	return;		       /* Configured off */

    if (stat(dir, &st) < 0) {
	if (errno != ENOENT || mkdir(dir, 0555) < 0 || stat(dir, &st) < 0) {
	    logit(LOG_NOTICE, errno, "No %s to confine the unprivileged half to", dir);
	    return;
	}
    }

    if (!S_ISDIR(st.st_mode) || st.st_uid != 0 || (st.st_mode & (S_IWGRP | S_IWOTH))) {
	logit(LOG_WARNING, 0, "%s is not a directory owned by root and writable by nobody else,"
	      " leaving the unprivileged half unconfined", dir);
	return;
    }

    /* chdir() first and chroot(".") after it, so that the working
     * directory is inside the new root rather than a way back out of it. */
    if (chdir(dir) < 0 || chroot(".") < 0 || chdir("/") < 0) {
	logit(LOG_WARNING, errno, "Failed confining the unprivileged half to %s", dir);
	return;
    }

    strlcpy(priv_chroot_path, dir, sizeof(priv_chroot_path));
}

/*
 * The child half.  Each of these does the plain thing in-process when
 * separation is off, so no call site needs to know which it is.
 */
int priv_socket(enum priv_sock kind)
{
    struct priv_req req;
    struct priv_rep rep;
    int fd = -1;

    if (!priv_enabled())
	return -1;	       /* The caller opens its own */

    req_init(&req, PRIV_SOCKET);
    req.u.sock = kind;

    if (priv_call(&req, &rep, &fd) < 0)
	return -1;

    return fd;
}

void priv_socket_release(void)
{
    struct priv_req req;
    struct priv_rep rep;

    if (!priv_enabled())
	return;

    req_init(&req, PRIV_SOCKET_RELEASE);
    priv_call(&req, &rep, NULL);
}

int priv_mrt_init(void)
{
    struct priv_req req;
    struct priv_rep rep;

    req_init(&req, PRIV_MRT_INIT);

    return priv_call(&req, &rep, NULL);
}

int priv_mrt_done(void)
{
    struct priv_req req;
    struct priv_rep rep;

    req_init(&req, PRIV_MRT_DONE);

    return priv_call(&req, &rep, NULL);
}

int priv_add_vif(struct vifctl *vc)
{
    struct priv_req req;
    struct priv_rep rep;

    req_init(&req, PRIV_ADD_VIF);
    req.u.vc = *vc;

    return priv_call(&req, &rep, NULL);
}

int priv_del_vif(vifi_t vifi, struct vifctl *vc)
{
    struct priv_req req;
    struct priv_rep rep;

    req_init(&req, PRIV_DEL_VIF);
    req.u.delvif.vifi = vifi;
    req.u.delvif.vc   = *vc;

    return priv_call(&req, &rep, NULL);
}

int priv_chg_mfc(struct mfcctl *mc)
{
    struct priv_req req;
    struct priv_rep rep;

    req_init(&req, PRIV_CHG_MFC);
    req.u.mc = *mc;

    return priv_call(&req, &rep, NULL);
}

int priv_del_mfc(struct mfcctl *mc)
{
    struct priv_req req;
    struct priv_rep rep;

    req_init(&req, PRIV_DEL_MFC);
    req.u.mc = *mc;

    return priv_call(&req, &rep, NULL);
}

int priv_vif_cnt(struct sioc_vif_req *vreq)
{
    struct priv_req req;
    struct priv_rep rep;

    req_init(&req, PRIV_VIF_CNT);
    req.u.vreq = *vreq;

    if (priv_call(&req, &rep, NULL) < 0)
	return -1;

    *vreq = rep.u.vreq;

    return 0;
}

int priv_sg_cnt(struct sioc_sg_req *sgreq)
{
    struct priv_req req;
    struct priv_rep rep;

    req_init(&req, PRIV_SG_CNT);
    req.u.sgreq = *sgreq;

    if (priv_call(&req, &rep, NULL) < 0)
	return -1;

    *sgreq = rep.u.sgreq;

    return 0;
}

unsigned int priv_ifindex(const char *ifname)
{
    struct priv_req req;
    struct priv_rep rep;

    if (!priv_enabled())
	return if_nametoindex(ifname);

    req_init(&req, PRIV_IFINDEX);
    strlcpy(req.u.ifname, ifname, sizeof(req.u.ifname));

    if (priv_call(&req, &rep, NULL) < 0)
	return 0;

    return rep.count;
}

/*
 * The interface scan, rebuilt on this side into the struct ifaddrs list
 * the callers already walk.  One allocation holds the array of entries and
 * the three addresses of each, so priv_freeifaddrs() is a single free().
 */
struct priv_ifaddrs {
    struct ifaddrs	ifa;
    struct sockaddr_in	addr;
    struct sockaddr_in	netmask;
    struct sockaddr_in	dstaddr;
    char		name[IFNAMSIZ];
};

static void ifrec_to_sockaddr(struct sockaddr_in *sin, uint32_t addr)
{
    memset(sin, 0, sizeof(*sin));
#ifdef HAVE_SA_LEN
    sin->sin_len = sizeof(*sin);
#endif
    sin->sin_family      = AF_INET;
    sin->sin_addr.s_addr = addr;
}

int priv_getifaddrs(struct ifaddrs **ifap)
{
    struct priv_ifaddrs *list = NULL;
    struct priv_req req;
    struct priv_rep rep;
    size_t total = 0, used = 0, i;

    if (!priv_enabled())
	return getifaddrs(ifap);

    req_init(&req, PRIV_IFSCAN);

    /*
     * The parent answers with as many messages as the scan needs and a
     * zero count to end it, so that neither side has to know how many
     * interfaces the machine has before the walk starts.
     */
    if (msg_send(priv_sock, &req, sizeof(req), -1)) {
	errno = EIO;
	return -1;
    }

    for (;;) {
	if (msg_recv(priv_sock, &rep, sizeof(rep), NULL)) {
	    free(list);
	    errno = EIO;
	    return -1;
	}

	if (rep.rc < 0) {
	    free(list);
	    errno = rep.err;
	    return -1;
	}

	if (rep.count == 0)
	    break;

	if (rep.count > PRIV_IFREC_MAX || used + rep.count > PRIV_IFREC_LIMIT) {
	    free(list);
	    errno = EPROTO;
	    return -1;
	}

	if (used + rep.count > total) {
	    struct priv_ifaddrs *grown;

	    total = used + rep.count + PRIV_IFREC_MAX;
	    grown = realloc(list, total * sizeof(*list));
	    if (!grown) {
		free(list);
		errno = ENOMEM;
		return -1;
	    }
	    list = grown;
	}

	for (i = 0; i < rep.count; i++) {
	    struct priv_ifrec *rec = &rep.u.ifrec[i];
	    struct priv_ifaddrs *e = &list[used++];

	    memset(e, 0, sizeof(*e));
	    memcpy(e->name, rec->name, sizeof(e->name));
	    e->name[sizeof(e->name) - 1] = 0;

	    e->ifa.ifa_name  = e->name;
	    e->ifa.ifa_flags = rec->flags;

	    if (rec->have & PRIV_IFREC_ADDR) {
		ifrec_to_sockaddr(&e->addr, rec->addr);
		e->addr.sin_family = rec->family;
		e->ifa.ifa_addr = (struct sockaddr *)&e->addr;
	    }
	    if (rec->have & PRIV_IFREC_NETMASK) {
		ifrec_to_sockaddr(&e->netmask, rec->netmask);
		e->ifa.ifa_netmask = (struct sockaddr *)&e->netmask;
	    }
	    if (rec->have & PRIV_IFREC_DSTADDR) {
		ifrec_to_sockaddr(&e->dstaddr, rec->dstaddr);
		e->ifa.ifa_dstaddr = (struct sockaddr *)&e->dstaddr;
	    }
	}
    }

    /* Only now that realloc() can no longer move them do the entries get
     * linked to each other. */
    for (i = 0; i + 1 < used; i++)
	list[i].ifa.ifa_next = &list[i + 1].ifa;

    *ifap = used ? &list[0].ifa : NULL;
    if (!used)
	free(list);

    return 0;
}

void priv_freeifaddrs(struct ifaddrs *ifa)
{
    if (!priv_enabled()) {
	freeifaddrs(ifa);
	return;
    }

    free(ifa);		       /* The list is one allocation, ifa its head */
}

FILE *priv_fopen_conf(void)
{
    struct priv_req req;
    struct priv_rep rep;
    int fd = -1;
    FILE *fp;

    if (!priv_enabled())
	return fopen(config_file, "r");

    req_init(&req, PRIV_CONF_OPEN);

    if (priv_call(&req, &rep, &fd) < 0 || fd < 0)
	return NULL;

    fp = fdopen(fd, "r");
    if (!fp)
	close(fd);

    return fp;
}

/*
 * A scratch file for the pimctl handlers, which write a table, rewind and
 * read it back.  It is unlinked before it gets here, so what crosses is a
 * descriptor to a file with no name -- the child could not have opened one
 * itself, /tmp being a path and capability mode having none.
 */
FILE *priv_tempfile(void)
{
    struct priv_req req;
    struct priv_rep rep;
    int fd = -1;
    FILE *fp;

    if (!priv_enabled())
	return tempfile();

    req_init(&req, PRIV_TEMPFILE);

    if (priv_call(&req, &rep, &fd) < 0 || fd < 0)
	return NULL;

    fp = fdopen(fd, "w+");
    if (!fp)
	close(fd);

    return fp;
}

int priv_pidfile(const char *path)
{
    struct priv_req req;
    struct priv_rep rep;

    if (!priv_enabled())
	return pidfile(path);

    req_init(&req, PRIV_PIDFILE);

    return priv_call(&req, &rep, NULL);
}

int priv_ipc_socket(void)
{
    struct priv_req req;
    struct priv_rep rep;
    int fd = -1;

    if (!priv_enabled())
	return -1;	       /* ipc.c binds its own */

    req_init(&req, PRIV_IPC_SOCKET);

    if (priv_call(&req, &rep, &fd) < 0)
	return -1;

    return fd;
}

void priv_ipc_close(void)
{
    struct priv_req req;
    struct priv_rep rep;

    if (!priv_enabled())
	return;

    req_init(&req, PRIV_IPC_CLOSE);
    priv_call(&req, &rep, NULL);
}

/*
 * Logging.  The message arrives rendered and is logged with "%s", so a
 * format string never crosses the boundary.  No reply: a log line the
 * parent drops is better than a daemon that blocks on one.
 */
void priv_log(int severity, int syserr, const char *msg)
{
    struct priv_req req;

    if (!priv_enabled())
	return;

    req_init(&req, PRIV_LOG);
    req.u.log.severity = severity;
    req.u.log.syserr   = syserr;
    strlcpy(req.u.log.msg, msg, sizeof(req.u.log.msg));

    /*
     * Blocking, like every other message, and that is not a choice: a
     * unix SOCK_SEQPACKET socket on FreeBSD carries PR_CONNREQUIRED |
     * PR_CAPATTACH | PR_SOCKBUF and *not* PR_ATOMIC
     * (sys/kern/uipc_usrreq.c), so it runs through sosend_generic() like a
     * stream and a non-blocking send may write part of a record.  The next
     * message then lands on the fragment, the far side reads one buffer
     * across two, and everything after that is out of step.  MSG_DONTWAIT
     * here did exactly that under the flood of test/lab.sh's keepalive
     * scenario: "Privsep protocol desync, asked 14 and was answered 0".
     *
     * So a log line can throttle the daemon if the other half is slow to
     * write it.  That is what an unseparated pimd does at the same point,
     * writing the line itself, so it is not a change.
     */
    (void)msg_send(priv_sock, &req, sizeof(req), -1);
}

/*
 * Enter the sandbox.  Called once, with everything the child will ever
 * need already open: from here it can read and write the descriptors it
 * holds and talk to the parent, and that is all.  A restart does not leave
 * it -- the new descriptors come from the parent, which is the whole
 * reason the parent is there.
 *
 * seccomp-bpf on Linux.  Nothing on the BSDs, and on FreeBSD that is a
 * decision rather than an omission: **Capsicum cannot host this daemon**,
 * and the next person to reach for it should read this before spending the
 * day it costs to find out.  kern_sendit() (sys/kern/uipc_syscalls.c)
 * returns ECAPMODE for a sendto() or sendmsg() carrying any destination
 * address at all, unconditionally -- it is not a right that cap_rights_limit()
 * could grant -- and kern_connectat() does the same for connect() with
 * AT_FDCWD, so a socket cannot be pointed at a destination from inside
 * either.  Only a socket connected *before* cap_enter() can send, and pimd
 * sends to a set of addresses that is not known before it starts and does
 * not stop changing: every neighbour, every RP, and a destination per group
 * for IGMP.  Under cap_enter() the daemon comes up, answers pimctl, builds
 * its VIFs, and silently sends nothing -- "sendto from 10.0.1.1 to
 * 224.0.0.13: Not permitted in capability mode", once per Hello, forever.
 *
 * The way in would be to compose every packet in the child and have the
 * parent send it, which is written up in aidd_docs/plans/privilege-separation.md
 * along with why the security it buys is narrower than it looks: a child
 * that can ask the parent to send anything anywhere can still forge any
 * packet it likes.
 *
 * So on the BSDs the uid drop stands on its own, and says so in the log and
 * in "pimctl show status" -- a sandbox nobody can see is one nobody notices
 * the absence of.
 */
#ifdef PIMD_AUDIT_ARCH
/*
 * One entry per syscall the event loop actually makes.  Everything else
 * kills the process: an unprivileged half that has started making calls
 * nobody wrote down is the event this is here to stop, and a filter that
 * returned an errno instead would let it keep trying.
 *
 * The list is what is left after the moves of priv_*(): no openat, no
 * socket, no execve, no connect, no unlink, no sysctl.  bind and
 * getsockname stay because netlink.c binds the descriptors the parent
 * hands it, and ioctl because SIOCGIFFLAGS and friends are reads on a
 * socket the child already holds.
 */
#define SC_ALLOW(name)								\
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_##name, 0, 1),			\
	BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)

static int sandbox_seccomp(void)
{
    struct sock_filter filter[] = {
	BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PIMD_AUDIT_ARCH, 1, 0),
	BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

	BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),

	/* The wire, both to the kernel and to the parent */
	SC_ALLOW(read),
	SC_ALLOW(write),
	SC_ALLOW(readv),
	SC_ALLOW(writev),
	SC_ALLOW(recvmsg),
	SC_ALLOW(sendmsg),
	SC_ALLOW(recvfrom),
	SC_ALLOW(sendto),
	SC_ALLOW(setsockopt),
	SC_ALLOW(getsockopt),
	SC_ALLOW(getsockname),
	SC_ALLOW(bind),
	SC_ALLOW(ioctl),
#ifdef __NR_accept
	SC_ALLOW(accept),
#endif
	SC_ALLOW(accept4),
	SC_ALLOW(shutdown),

	/* The event loop */
#ifdef __NR_select
	SC_ALLOW(select),
#endif
#ifdef __NR__newselect
	SC_ALLOW(_newselect),
#endif
	SC_ALLOW(pselect6),
#ifdef __NR_pselect6_time64
	SC_ALLOW(pselect6_time64),
#endif
#ifdef __NR_clock_gettime
	SC_ALLOW(clock_gettime),
#endif
#ifdef __NR_clock_gettime64
	SC_ALLOW(clock_gettime64),
#endif
#ifdef __NR_gettimeofday
	SC_ALLOW(gettimeofday),
#endif

	/* stdio over the descriptors it already has, and malloc */
	SC_ALLOW(close),
	SC_ALLOW(fcntl),
	SC_ALLOW(lseek),
#ifdef __NR_fstat
	SC_ALLOW(fstat),
#endif
#ifdef __NR_newfstatat
	SC_ALLOW(newfstatat),
#endif
	SC_ALLOW(brk),
	SC_ALLOW(mmap),
	SC_ALLOW(munmap),
	SC_ALLOW(mremap),
	SC_ALLOW(futex),

	/* What libc reaches for underneath.  getrandom(2) is not optional:
	 * glibc's arc4random() is built on it, and queue.h and the GenID of
	 * RFC 7761 sec. 4.3.1 both want numbers a neighbour cannot predict --
	 * which is why the first full run of test/lab.sh on Linux killed
	 * eleven scenarios' daemons with SIGSYS on syscall 318.  The rest are
	 * allocator and timing calls that cost the sandbox nothing: none of
	 * them names a file, creates a socket or starts a process. */
	SC_ALLOW(getrandom),
	SC_ALLOW(madvise),
	SC_ALLOW(mprotect),
#ifdef __NR_nanosleep
	SC_ALLOW(nanosleep),
#endif
	SC_ALLOW(clock_nanosleep),
	SC_ALLOW(restart_syscall),
	SC_ALLOW(sched_yield),
#ifdef __NR_poll
	SC_ALLOW(poll),
#endif
	SC_ALLOW(ppoll),
	SC_ALLOW(getuid),
	SC_ALLOW(geteuid),
	SC_ALLOW(getgid),
	SC_ALLOW(getegid),
	SC_ALLOW(uname),

	/* Signals, and going away.  gettid and tgkill are abort()'s, so that
	 * a child that does die dies with a core and not on a filter. */
	SC_ALLOW(gettid),
	SC_ALLOW(tgkill),
	SC_ALLOW(rt_sigreturn),
	SC_ALLOW(rt_sigaction),
	SC_ALLOW(rt_sigprocmask),
	SC_ALLOW(getpid),
	SC_ALLOW(exit),
	SC_ALLOW(exit_group),

	BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
    };
    struct sock_fprog prog = {
	.len    = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
	.filter = filter,
    };

    /* Without this the kernel refuses the filter to anyone who is not
     * already privileged, and it is what stops a setuid binary from
     * getting back out of the sandbox by exec. */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
	return -1;

    return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0);
}
#endif /* PIMD_AUDIT_ARCH */

void priv_sandbox_enter(void)
{
    if (!priv_enabled())
	return;

#ifdef PIMD_AUDIT_ARCH
    if (sandbox_seccomp() == 0) {
	strlcpy(priv_sandbox_name, "seccomp", sizeof(priv_sandbox_name));
	logit(LOG_INFO, 0, "Running as %s under a seccomp filter", priv_username);
	return;
    }

    logit(LOG_WARNING, errno, "Failed installing the seccomp filter");
#elif defined(HAVE_SYS_PRCTL_H) && defined(PR_SET_NO_NEW_PRIVS)
    /* A Linux this filter has no syscall table for: no sandbox, but this
     * much holds everywhere and is worth saying so in show status. */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0) {
	strlcpy(priv_sandbox_name, "no-new-privs", sizeof(priv_sandbox_name));
	logit(LOG_NOTICE, 0, "No seccomp filter for this architecture, running as %s "
	      "with no-new-privs only", priv_username);
	return;
    }
#endif

    logit(LOG_NOTICE, 0, "No sandbox available, the unprivileged half runs as %s only",
	  priv_username);
}

/*
 * The parent half.  Nothing here calls logit() at LOG_ERR: an error is a
 * reply with an errno in it, and the child decides what that means.
 */
static int parent_socket(uint32_t kind)
{
    int sd = -1;

    if (kind < PRIV_SOCK_IGMP || kind > PRIV_SOCK_AUTORP) {
	errno = EINVAL;
	return -1;
    }

    switch (kind) {
    case PRIV_SOCK_IGMP:
	sd = socket(AF_INET, SOCK_RAW, IPPROTO_IGMP);
	break;

    case PRIV_SOCK_PIM:
	sd = socket(AF_INET, SOCK_RAW, IPPROTO_PIM);
	break;

    case PRIV_SOCK_UDP:
	sd = socket(AF_INET, SOCK_DGRAM, 0);
	break;

    case PRIV_SOCK_AUTORP:
	/* The one socket that arrives bound.  Auto-RP is UDP to port 496,
	 * which is privileged, so the child could not bind it even where
	 * it is allowed to create a socket at all -- and under the Linux
	 * filter it is not.
	 */
	sd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sd >= 0) {
	    struct sockaddr_in sin;
	    int on = 1;

	    (void)setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	    memset(&sin, 0, sizeof(sin));
	    sin.sin_family      = AF_INET;
	    sin.sin_addr.s_addr = INADDR_ANY;
	    sin.sin_port        = htons(AUTORP_PORT);

	    if (bind(sd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		int err = errno;

		close(sd);
		errno = err;
		sd = -1;
	    }
	}
	break;

    case PRIV_SOCK_ROUTE:
    case PRIV_SOCK_IFEVENT:
	/* Neither of these needs privilege -- a routing socket is readable
	 * by anyone, and rts_attach() has no priv_check() -- but they are
	 * created here all the same, so that the child needs socket(2) for
	 * nothing and the Linux filter can refuse the call outright.
	 *
	 * Which socket it is belongs to whichever of routesock.c and
	 * netlink.c was linked in, not to a header probe: this host has the
	 * netlink headers and is built on the routing socket. */
	sd = kern_routesock(kind == PRIV_SOCK_IFEVENT);
	break;
    }

    if (sd < 0)
	return -1;

    /* The parent keeps a copy of every descriptor it hands out: the MRT_*
     * calls below are made on this side, and a restart has to be able to
     * let the old ones go. */
    if (parent_fd[kind] >= 0)
	close(parent_fd[kind]);
    parent_fd[kind] = sd;

    return sd;
}

/*
 * Which descriptor the counter ioctls go to.  Where the kernel takes them
 * on a raw socket -- Linux, IOCTL_OK_ON_RAW_SOCKET -- vif.c sets
 * udp_socket to igmp_socket and never asks for a UDP socket at all, so the
 * slot for one stays empty on this side and an ioctl on it would be an
 * EBADF with nothing to say why.  Asking what was actually handed out
 * rather than repeating that #ifdef here keeps the two from drifting.
 */
static int parent_ioctl_fd(void)
{
    if (parent_fd[PRIV_SOCK_UDP] >= 0)
	return parent_fd[PRIV_SOCK_UDP];

    return parent_fd[PRIV_SOCK_IGMP];
}

static void parent_release(void)
{
    int i;

    for (i = PRIV_SOCK_IGMP; i <= PRIV_SOCK_AUTORP; i++) {
	if (parent_fd[i] >= 0) {
	    close(parent_fd[i]);
	    parent_fd[i] = -1;
	}
    }
}

static int parent_ifscan(int sd)
{
    struct ifaddrs *ifap, *ifa;
    struct priv_rep rep;
    uint32_t n = 0;

    if (getifaddrs(&ifap) < 0) {
	memset(&rep, 0, sizeof(rep));
	rep.op  = PRIV_IFSCAN;
	rep.rc  = -1;
	rep.err = errno;

	return msg_send(sd, &rep, sizeof(rep), -1);
    }

    memset(&rep, 0, sizeof(rep));
    rep.op = PRIV_IFSCAN;

    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
	struct priv_ifrec *rec = &rep.u.ifrec[n];

	memset(rec, 0, sizeof(*rec));
	if (ifa->ifa_name)
	    strlcpy(rec->name, ifa->ifa_name, sizeof(rec->name));
	rec->flags   = ifa->ifa_flags;
	rec->ifindex = ifa->ifa_name ? if_nametoindex(ifa->ifa_name) : 0;

	if (ifa->ifa_addr) {
	    rec->family = ifa->ifa_addr->sa_family;
	    rec->have  |= PRIV_IFREC_ADDR;
	    if (ifa->ifa_addr->sa_family == AF_INET)
		rec->addr = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr;
	}
	if (ifa->ifa_netmask && ifa->ifa_netmask->sa_family == AF_INET) {
	    rec->have |= PRIV_IFREC_NETMASK;
	    rec->netmask = ((struct sockaddr_in *)ifa->ifa_netmask)->sin_addr.s_addr;
	}
	if (ifa->ifa_dstaddr && ifa->ifa_dstaddr->sa_family == AF_INET) {
	    rec->have |= PRIV_IFREC_DSTADDR;
	    rec->dstaddr = ((struct sockaddr_in *)ifa->ifa_dstaddr)->sin_addr.s_addr;
	}

	if (++n == PRIV_IFREC_MAX) {
	    rep.count = n;
	    if (msg_send(sd, &rep, sizeof(rep), -1)) {
		freeifaddrs(ifap);
		return -1;
	    }
	    n = 0;
	}
    }

    freeifaddrs(ifap);

    if (n) {
	rep.count = n;
	if (msg_send(sd, &rep, sizeof(rep), -1))
	    return -1;
    }

    rep.count = 0;		/* End of the scan */

    return msg_send(sd, &rep, sizeof(rep), -1);
}

static int parent_ipc_socket(void)
{
    struct sockaddr_un sun;
    mode_t mask;
    int sd;

    sd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sd < 0)
	return -1;

    memset(&sun, 0, sizeof(sun));
    sun.sun_family = AF_UNIX;
    strlcpy(sun.sun_path, parent_sock, sizeof(sun.sun_path));

    unlink(sun.sun_path);

    /* Same rule as ipc.c had it: the mode is in place before bind()
     * creates the node, rather than left to whatever umask pimd was
     * started with. */
    mask = umask(0077);
    if (bind(sd, (struct sockaddr *)&sun, sizeof(sun)) < 0 || listen(sd, 1)) {
	int err = errno;

	umask(mask);
	close(sd);
	errno = err;

	return -1;
    }
    umask(mask);

    return sd;
}

static int parent_loop(int sd)
{
    for (;;) {
	struct priv_req req;
	struct priv_rep rep;
	int fd = -1;

	if (msg_recv(sd, &req, sizeof(req), NULL))
	    break;		/* The child is gone */

	memset(&rep, 0, sizeof(rep));
	rep.op = req.op;

	switch (req.op) {
	case PRIV_SOCKET:
	    fd = parent_socket(req.u.sock);
	    rep.rc  = fd < 0 ? -1 : 0;
	    rep.err = errno;
	    break;

	case PRIV_SOCKET_RELEASE:
	    parent_release();
	    break;

	case PRIV_MRT_INIT:
	    rep.rc  = kern_mrt_init(parent_fd[PRIV_SOCK_IGMP]);
	    rep.err = errno;
	    break;

	case PRIV_MRT_DONE:
	    rep.rc  = kern_mrt_done(parent_fd[PRIV_SOCK_IGMP]);
	    rep.err = errno;
	    break;

	case PRIV_ADD_VIF:
	    if (req.u.vc.vifc_vifi >= MAXVIFS) {
		rep.rc  = -1;
		rep.err = EINVAL;
		break;
	    }
	    rep.rc  = kern_add_vif(parent_fd[PRIV_SOCK_IGMP], &req.u.vc);
	    rep.err = errno;
	    break;

	case PRIV_DEL_VIF:
	    if (req.u.delvif.vifi >= MAXVIFS) {
		rep.rc  = -1;
		rep.err = EINVAL;
		break;
	    }
	    rep.rc  = kern_del_vif(parent_fd[PRIV_SOCK_IGMP],
				   (vifi_t)req.u.delvif.vifi, &req.u.delvif.vc);
	    rep.err = errno;
	    break;

	case PRIV_CHG_MFC:
	    /* The kernel checks this too, and is the one that matters; it is
	     * checked here as well because a vif index out of a message is
	     * the one field of an mfcctl that indexes anything, and this side
	     * is the boundary. */
	    if (req.u.mc.mfcc_parent >= MAXVIFS) {
		rep.rc  = -1;
		rep.err = EINVAL;
		break;
	    }
	    rep.rc  = kern_chg_mfc(parent_fd[PRIV_SOCK_IGMP], &req.u.mc);
	    rep.err = errno;
	    break;

	case PRIV_DEL_MFC:
	    rep.rc  = kern_del_mfc(parent_fd[PRIV_SOCK_IGMP], &req.u.mc);
	    rep.err = errno;
	    break;

	case PRIV_VIF_CNT:
	    rep.u.vreq = req.u.vreq;
	    rep.rc  = kern_vif_cnt(parent_ioctl_fd(), &rep.u.vreq);
	    rep.err = errno;
	    break;

	case PRIV_SG_CNT:
	    rep.u.sgreq = req.u.sgreq;
	    rep.rc  = kern_sg_cnt(parent_ioctl_fd(), &rep.u.sgreq);
	    rep.err = errno;
	    break;

	case PRIV_IFSCAN:
	    if (parent_ifscan(sd))
		goto gone;
	    continue;		/* Answered already, in several messages */

	case PRIV_IFINDEX:
	    req.u.ifname[sizeof(req.u.ifname) - 1] = 0;
	    rep.count = if_nametoindex(req.u.ifname);
	    rep.rc    = rep.count ? 0 : -1;
	    rep.err   = errno;
	    break;

	case PRIV_CONF_OPEN:
	    fd = open(parent_conf, O_RDONLY | O_CLOEXEC);
	    rep.rc  = fd < 0 ? -1 : 0;
	    rep.err = errno;
	    break;

	case PRIV_TEMPFILE: {
	    FILE *fp = tempfile();

	    if (!fp) {
		rep.rc  = -1;
		rep.err = errno;
		break;
	    }

	    /* fclose() takes the original descriptor with it; the dup keeps
	     * the unnamed file alive until the child is done with it. */
	    fd = dup(fileno(fp));
	    rep.rc  = fd < 0 ? -1 : 0;
	    rep.err = errno;
	    fclose(fp);
	    break;
	}

	case PRIV_PIDFILE:
	    rep.rc  = pidfile(parent_pid);
	    rep.err = errno;
	    break;

	case PRIV_IPC_SOCKET:
	    fd = parent_ipc_socket();
	    rep.rc  = fd < 0 ? -1 : 0;
	    rep.err = errno;
	    break;

	case PRIV_IPC_CLOSE:
	    if (parent_sock)
		unlink(parent_sock);
	    break;

	case PRIV_LOG:
	    req.u.log.msg[sizeof(req.u.log.msg) - 1] = 0;
	    log_emit(req.u.log.severity, req.u.log.syserr, req.u.log.msg);
	    continue;		/* No reply, by design */

	default:
	    /* Not a request this was built to answer.  Replying to it would
	     * put a message on the wire that the other side is not waiting
	     * for, which is the one thing that cannot be recovered from --
	     * so say so and go, rather than paper over it. */
	    /* LOG_WARNING and not LOG_ERR: logit() exits on the latter, and
	     * this side still has the pimctl socket to unlink on its way out. */
	    logit(LOG_WARNING, 0, "Privsep helper asked for operation %u, which does not exist",
		  req.op);
	    goto gone;
	}

	if (msg_send(sd, &rep, sizeof(rep), fd))
	    goto gone;

	if (fd >= 0 && req.op != PRIV_SOCKET)
	    close(fd);		/* The socket kinds are kept, see above */
    }

  gone:
    parent_cleanup();

    /* exit() rather than _exit(): the PID file is removed by the atexit()
     * handler pidfile() installed on this side. */
    exit(0);
}

/*
 * Tear down what only the parent can.  It owns the pimctl socket, and a
 * child that died inside its sandbox could not have unlinked it; the PID
 * file goes with the exit() above.
 */
static void parent_cleanup(void)
{
    int status;

    if (parent_sock)
	unlink(parent_sock);

    if (parent_child > 0)
	while (waitpid(parent_child, &status, WNOHANG) < 0 && errno == EINTR)
	    ;
}

static void parent_signal(int signo)
{
    if (parent_child > 0)
	kill(parent_child, signo);
}

/*
 * Fork the helper.  Returns in the child, with priv_sock set; the parent
 * serves requests until the child is gone and then exits.
 */
int priv_init(const char *user, const char *conf, const char *pid, const char *sock)
{
    char name[64], *group;
    struct sigaction sa;
    struct passwd *pw;
    uid_t uid;
    gid_t gid;
    int sv[2], i;

    /* "user" or "user:group"; without a group the user's own is used.  A
     * name too long to hold is refused rather than truncated, since what
     * is left of one is a different account that may well exist. */
    if (strlcpy(name, user ? user : PRIVSEP_USER, sizeof(name)) >= sizeof(name)) {
	logit(LOG_ERR, 0, "Privilege separation user name is longer than %zu characters",
	      sizeof(name) - 1);
	return -1;
    }

    group = strchr(name, ':');
    if (group)
	*group++ = 0;

    /*
     * The default is nobody, which every system this builds for has, so
     * the usual path finds it.  A name that is not there is a start-up
     * error rather than something to work around: falling back to another
     * account would be choosing one the operator did not, and running as
     * root would give up the whole point.
     */
    pw = getpwnam(name);
    if (!pw) {
	logit(LOG_ERR, 0, "Privilege separation user %s does not exist, "
	      "create it or start with --no-privsep", name);
	return -1;
    }
    uid = pw->pw_uid;
    gid = pw->pw_gid;

    if (group) {
	struct group *gr;

	gr = getgrnam(group);
	if (!gr) {
	    logit(LOG_ERR, 0, "Privilege separation group %s does not exist", group);
	    return -1;
	}
	gid = gr->gr_gid;
    }

    if (uid == 0) {
	logit(LOG_ERR, 0, "Privilege separation user %s is root, refusing", name);
	return -1;
    }

    strlcpy(priv_username, name, sizeof(priv_username));

    for (i = 0; i <= PRIV_SOCK_AUTORP; i++)
	parent_fd[i] = -1;

    parent_conf = strdup(conf);
    parent_pid  = pid  ? strdup(pid)  : NULL;
    parent_sock = sock ? strdup(sock) : NULL;

    if (!parent_conf || (pid && !parent_pid) || (sock && !parent_sock)) {
	logit(LOG_ERR, errno, "Failed allocating memory for the privsep helper");
	return -1;
    }

    /* A write to a socketpair whose far half has gone is EPIPE here and a
     * signal everywhere else, and the default action of that signal is to
     * end the process without a word: the half that dies cannot say what
     * killed it, and the kernel does not log a SIGPIPE either, having no
     * core to take.  That is a daemon that vanishes with an empty log,
     * which is what the FreeBSD runner showed before msg_send() learned to
     * resume a short transfer.  Ignored so the error comes back as a
     * return value that priv_call() and parent_loop() can report. */
    signal(SIGPIPE, SIG_IGN);

    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) < 0 &&
	socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0) {
	logit(LOG_ERR, errno, "Failed creating the privsep socketpair");
	return -1;
    }

    parent_child = fork();
    if (parent_child < 0) {
	logit(LOG_ERR, errno, "Failed forking the privileged helper");
	return -1;
    }

    if (parent_child == 0) {
	close(sv[0]);

	/* Before anything below can fail: with this set, logit() reaches the
	 * parent, which still has a syslog(3) to say it with.  Without it a
	 * child that could not drop its privileges would die quietly. */
	priv_sock = sv[1];

	priv_do_chroot();

	/* Group first: setgid() after setuid() would be refused. */
	if (setgid(gid) || setgroups(1, &gid) || setuid(uid)) {
	    logit(LOG_ERR, errno, "Failed dropping privileges to %s", name);
	    _exit(1);
	}

	if (setuid(0) != -1) {
	    logit(LOG_ERR, 0, "Still able to regain root, refusing to run");
	    _exit(1);
	}

	/*
	 * Die with the parent.  The child notices a parent that exited
	 * cleanly the next time it asks for anything, but a parent that was
	 * killed outright -- which is what a "pkill -F" on the PID file is,
	 * since the file names the parent now -- would otherwise leave it
	 * holding the pimctl socket and answering nothing.  After the uid
	 * drop, not before: Linux clears PR_SET_PDEATHSIG when the
	 * credentials change, exactly so that this cannot be inherited
	 * across a privilege boundary.
	 *
	 * SIGKILL and not SIGTERM, which is not a detail: on SIGTERM
	 * cleanup() (src/main.c) sends a Hello with a zero holdtime on every
	 * vif, and a router that was killed has not said goodbye to anybody.
	 * With SIGTERM here, killing the parent made the child announce a
	 * clean shutdown the operator never asked for -- the neighbours
	 * delete it outright instead of holding it to its Neighbor Liveness
	 * Timer, and a restart is no longer the GenID change of RFC 7761
	 * sec. 4.3.1 that the assert-recover scenario is about.  It failed
	 * exactly there.
	 */
#if defined(HAVE_SYS_PRCTL_H) && defined(PR_SET_PDEATHSIG)
	prctl(PR_SET_PDEATHSIG, SIGKILL);
#elif defined(HAVE_SYS_PROCCTL_H) && defined(PROC_PDEATHSIG_CTL)
	{
	    int sig = SIGKILL;

	    procctl(P_PID, 0, PROC_PDEATHSIG_CTL, &sig);
	}
#endif

	return 0;
    }

    close(sv[1]);

    /* The parent forwards the signals a daemon is sent and otherwise stays
     * out of the way: the state they act on all lives in the child. */
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = parent_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGHUP,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGUSR1, &sa, NULL);
    sigaction(SIGUSR2, &sa, NULL);

    parent_loop(sv[0]);
    /* NOTREACHED */
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "cc-mode"
 * End:
 */
