/*
 * Copyright (c) 1998-2001
 * University of Southern California/Information Sciences Institute.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * Part of this program has been derived from mrouted.
 * The mrouted program is covered by the license in the accompanying file
 * named "LICENSE.mrouted".
 *
 * The mrouted program is COPYRIGHT 1989 by The Board of Trustees of
 * Leland Stanford Junior University.
 *
 */

#include <sys/param.h>
#include <sys/file.h>
#include "defs.h"
#include <sys/socket.h>
#include <net/route.h>
#ifdef HAVE_ROUTING_SOCKETS
#include <net/if_dl.h>
#endif
#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>
#include <sys/time.h>

/* All the BSDs have routing sockets (not Netlink), but only Linux seems
 * to have SIOCGETRPF, which is used in the #else below ... the original
 * authors wanted to merge routesock.c and netlink.c, but I don't know
 * anymore. --Joachim */
#ifdef HAVE_ROUTING_SOCKETS
static union sockunion {
    struct  sockaddr sa;
    struct  sockaddr_in sin;
    struct  sockaddr_dl sdl;
} so_dst, so_ifp;
typedef union sockunion *sup;
const char *rpf_backend = "routing socket";
int routing_socket = -1;
int ifevent_socket = -1;
static int rtm_addrs;
static pid_t pid;
static struct rt_metrics rt_metrics;
static uint32_t rtm_inits;

static struct {
    struct  rt_msghdr m_rtm;
    char    m_space[512];
} m_rtmsg;

/*
 * Local functions definitions.
 */
static int getmsg(struct rt_msghdr *, int, struct rpfctl *rpfinfo);
static int init_ifevent(void);
static void ifevent_read(int fd);

/*
 * The head every routing socket message begins with, whichever of
 * rt_msghdr, if_msghdr, ifa_msghdr and if_announcemsghdr it turns out to
 * be.  Only the type is read here, and an announcement is a good deal
 * shorter than a struct rt_msghdr, so this is what a message has to be
 * long enough for -- asking for the largest of them would drop the
 * shortest unread.
 */
struct ifevent_hdr {
    u_short	ifh_msglen;
    u_char	ifh_version;
    u_char	ifh_type;
};

/*
 * TODO: check again!
 */
#ifdef IRIX
#define ROUNDUP(a) ((a) > 0 ? (1 + (((a) - 1) | (sizeof(__uint64_t) - 1))) \
		    : sizeof(__uint64_t))
#else
#define ROUNDUP(a) ((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) \
		    : sizeof(long))
#endif /* IRIX */

#ifdef HAVE_SA_LEN
#define ADVANCE(x, n) (x += ROUNDUP((n)->sa_len))
#else
#define ADVANCE(x, n) (x += ROUNDUP(sizeof(*(n))))  /* XXX: sizeof(struct sockaddr) */
#endif

/*
 * The raw socket half of the two below, so that the privileged parent can
 * create them without knowing which RPF backend was linked in: this file
 * and src/netlink.c each answer for their own.  Nothing privileged about
 * it -- rts_attach() has no priv_check() -- but the child gets every
 * descriptor from the parent, so that it needs socket(2) for nothing.
 */
int kern_routesock(int ifevent)
{
	/* AF_INET on the event socket narrows it to the messages that carry
	 * an IPv4 address; see init_ifevent() below. */
    return socket(PF_ROUTE, SOCK_RAW, ifevent ? AF_INET : 0);
}

/* Open and initialize the routing socket */
int init_routesock(void)
{
#if 0
    int on = 0;
#endif

    routing_socket = priv_enabled() ? priv_socket(PRIV_SOCK_ROUTE)
				    : kern_routesock(0);
    if (routing_socket < 0) {
	logit(LOG_ERR, errno, "Failed creating routing socket");
	return -1;
    }

    if (fcntl(routing_socket, F_SETFL, O_NONBLOCK) == -1) {
	logit(LOG_ERR, errno, "Failed setting routing socket as non-blocking");
	return -1;
    }

#if 0
    /* XXX: if it is OFF, no queries will succeed (!?) */
    if (setsockopt(routing_socket, SOL_SOCKET, SO_USELOOPBACK, (char *)&on, sizeof(on)) < 0) {
	logit(LOG_ERR, errno , "setsockopt(SO_USELOOPBACK, 0)");
	return -1;
    }
#endif

    init_ifevent();

    return 0;
}

/*
 * A second routing socket, read from the event loop, for the kernel to
 * tell us that the set of interfaces has changed.  The one above cannot
 * do it: k_req_incoming() empties it before every RTM_GET and reads until
 * it finds the answer to that request, so any notification queued on it
 * is thrown away unseen -- deliberately, since an unread queue is what
 * makes the kernel drop the reply it is waiting for.  bird splits the two
 * the same way (sysdep/bsd/krt-sock.c keeps a socket of its own for the
 * asynchronous messages), as does the netlink side of this in
 * src/netlink.c.
 *
 * AF_INET narrows it to the messages that carry an IPv4 address, which the
 * address ones do; RTM_IFINFO and RTM_IFANNOUNCE carry none and reach
 * every routing socket whatever its protocol.  The IPv6 and link layer
 * churn that says nothing about our vifs is left in the kernel.
 *
 * Failing to open it is not fatal: RPF lookups, which pimd cannot run
 * without, go through the other socket.  What is lost is noticing an
 * interface configured after start-up.
 */
static int init_ifevent(void)
{
    int val;

    ifevent_socket = priv_enabled() ? priv_socket(PRIV_SOCK_IFEVENT)
				    : kern_routesock(1);
    if (ifevent_socket < 0) {
	logit(LOG_WARNING, errno, "Failed creating routing socket for interface events");
	return -1;
    }

    /* There is no way to ask a routing socket for the four message types
     * below and no others, so this queue also carries every unicast route
     * change on the router.  Room for a burst of them, and, where the
     * kernel can say so, an error on the read when there was not enough:
     * a notification dropped in silence would leave the vif table wrong
     * until the periodic rescan in age_vifs() came round. */
    val = 256 * 1024;
    if (setsockopt(ifevent_socket, SOL_SOCKET, SO_RCVBUF, &val, sizeof(val)) < 0)
	logit(LOG_WARNING, errno, "Failed growing the interface event socket receive buffer");
#ifdef SO_RERROR
    val = 1;
    if (setsockopt(ifevent_socket, SOL_SOCKET, SO_RERROR, &val, sizeof(val)) < 0)
	logit(LOG_WARNING, errno, "Failed asking for interface event overflow errors");
#endif

    if (fcntl(ifevent_socket, F_SETFL, O_NONBLOCK) == -1) {
	logit(LOG_WARNING, errno, "Failed setting interface event socket as non-blocking");
	close(ifevent_socket);
	ifevent_socket = -1;
	return -1;
    }

    if (register_input_handler(ifevent_socket, ifevent_read) < 0) {
	logit(LOG_WARNING, 0, "Failed registering interface event handler");
	close(ifevent_socket);
	ifevent_socket = -1;
	return -1;
    }

    return 0;
}

/*
 * Drain the notifications and ask for one rescan if any of them was about
 * an interface or an address.  Nothing here is parsed beyond the message
 * type: what the kernel has is read back with getifaddrs() by the scan
 * itself, which is the same view init_vifs() was built from, rather than
 * pieced together from the messages.
 */
static void ifevent_read(int fd)
{
    int changed = 0;

    while (1) {
	union {
	    struct ifevent_hdr ifh;
	    char buf[2048];
	} m;
	ssize_t len;

	/* One message per read on a routing socket, and one that does not
	 * fit is truncated rather than continued in the next */
	len = read(fd, &m, sizeof(m));
	if (len < 0) {
	    if (errno == EINTR)
		continue;

	    if (errno == EAGAIN || errno == EWOULDBLOCK)
		break;

	    /* SO_RERROR above: the kernel dropped notifications it could
	     * not queue, so what we have read is no longer the whole
	     * story.  Scan, rather than guess at what was lost. */
	    if (errno == ENOBUFS) {
		logit(LOG_WARNING, 0, "Interface events overflowed, rescanning");
		changed = 1;
		break;
	    }

	    logit(LOG_WARNING, errno, "Failed reading interface events");
	    break;
	}

	/* Everything below reads the head, and a message too short to hold
	 * one says nothing we can act on.  Skipped rather than stopped on:
	 * read() has taken it off the socket either way, and leaving the
	 * rest of the queue there only brings us straight back here. */
	if (len < (ssize_t)sizeof(m.ifh))
	    continue;

	if (m.ifh.ifh_version != RTM_VERSION) {
	    logit(LOG_WARNING, 0, "Routing socket message version %u, expected %u",
		  (u_int)m.ifh.ifh_version, (u_int)RTM_VERSION);
	    continue;
	}

	switch (m.ifh.ifh_type) {
#ifdef RTM_IFANNOUNCE
	    case RTM_IFANNOUNCE:	/* an interface arrived or left */
#endif
	    case RTM_IFINFO:		/* ... or changed its flags */
	    case RTM_NEWADDR:
	    case RTM_DELADDR:
		IF_DEBUG(DEBUG_IF)
		    logit(LOG_DEBUG, 0, "routesock: interface event %u", (u_int)m.ifh.ifh_type);
		changed = 1;
		break;

	    default:
		break;
	}
    }

    if (changed)
	rescan_vifs_request();
}

void routesock_clean(void)
{
    if (routing_socket >= 0)
	close(routing_socket);
    routing_socket = -1;

    if (ifevent_socket >= 0)
	close(ifevent_socket);
    ifevent_socket = -1;
}

/* get the rpf neighbor info */
int k_req_incoming(uint32_t source, struct rpfctl *rpf)
{
    int rlen, l, flags = RTF_STATIC;
    sup su;
    static int seq;
    char *cp = m_rtmsg.m_space;
    struct rpfctl rpfinfo;
    struct timeval wtime;
    fd_set fdbits;

/* TODO: a hack!!!! */
#ifdef HAVE_SA_LEN
#define NEXTADDR(w, u)				\
    if (rtm_addrs & (w)) {			\
	l = ROUNDUP(u.sa.sa_len);		\
	memcpy(cp, &(u), l);			\
	cp += l;				\
    }
#else
#define NEXTADDR(w, u)				\
    if (rtm_addrs & (w)) {			\
	l = ROUNDUP(sizeof(struct sockaddr));	\
	memcpy(cp, &(u), l);			\
	cp += l;				\
    }
#endif /* HAVE_SA_LEN */

    /* initialize */
    rpf->source.s_addr      = source;
    rpf->rpfneighbor.s_addr = INADDR_ANY_N;
    rpf->metric             = RPF_METRIC_UNKNOWN;
    rpf->pref               = RPF_PREF_UNKNOWN;
    /*
     * check if local address or directly connected before calling the
     * routing socket
     */
    rpf->iif = find_vif_direct_local(source, FALSE);
    if (rpf->iif != NO_VIF) {
	rpf->rpfneighbor.s_addr = source;
	return TRUE;
    }

    /*
     * Nothing in 169.254/16 is ever routed, RFC 3927 sec. 2.7 forbids
     * forwarding a link-local packet at all, so whatever the kernel
     * answers here cannot be a path to it.  config.c gives the SSM range
     * a static RP of 169.254.0.1, on purpose, precisely because the
     * address leads nowhere, and every RP lookup asks for it.
     */
    if (IN_LINK_LOCAL_RANGE(source)) {
	IF_DEBUG(DEBUG_RPF) {
	    logit(LOG_DEBUG, 0, "k_req_incoming: link-local source %s is not routable",
		  inet_fmt(source, s1, sizeof(s1)));
	}

	return FALSE;
    }

    /* prepare the routing socket params */
    rtm_addrs |= RTA_DST;
    rtm_addrs |= RTA_IFP;
    su = &so_dst;
    su->sin.sin_family = AF_INET;
#ifdef HAVE_SA_LEN
    su->sin.sin_len = sizeof(struct sockaddr_in);
#endif
    su->sin.sin_addr.s_addr = source;

    if (inet_lnaof(su->sin.sin_addr) == INADDR_ANY) {
	IF_DEBUG(DEBUG_RPF) {
	    logit(LOG_DEBUG, 0, "k_req_incoming: Invalid source %s",
		  inet_fmt(source, s1, sizeof(s1)));
	}

	return FALSE;
    }

    so_ifp.sa.sa_family = AF_LINK;
#ifdef HAVE_SA_LEN
    so_ifp.sa.sa_len = sizeof(struct sockaddr_dl);
#endif
    flags |= RTF_UP;
    flags |= RTF_HOST;
    flags |= RTF_GATEWAY;

    /*
     * Nothing else ever reads this socket and the kernel broadcasts every
     * routing change to it, so everything that happened since the last
     * lookup is still queued.  Once that fills the receive buffer the
     * kernel drops the reply we are about to ask for, and the leftovers
     * are then read in its place below until the wait times out, so empty
     * it before asking.
     */
    while (read(routing_socket, &m_rtmsg, sizeof(m_rtmsg)) > 0)
	;

    errno = 0;
    memset (&m_rtmsg, 0, sizeof(m_rtmsg));

#define rtm m_rtmsg.m_rtm
    rtm.rtm_type        = RTM_GET;
    rtm.rtm_flags       = flags;
    rtm.rtm_version     = RTM_VERSION;
    rtm.rtm_seq         = ++seq;
    rtm.rtm_addrs       = rtm_addrs;
    rtm.rtm_rmx         = rt_metrics;
    rtm.rtm_inits       = rtm_inits;

    NEXTADDR(RTA_DST, so_dst);
    NEXTADDR(RTA_IFP, so_ifp);
    rtm.rtm_msglen = l = cp - (char *)&m_rtmsg;

    rlen = write(routing_socket, &m_rtmsg, l);
    if (rlen <= 0) {
	IF_DEBUG(DEBUG_RPF | DEBUG_KERN) {
	    if (errno == ESRCH)
		logit(LOG_DEBUG, 0, "Writing to routing socket: no such route");
	    else
		logit(LOG_DEBUG, 0, "Error writing to routing socket");
	}

	return FALSE;
    }

    pid = getpid();

    while (1) {
	wtime.tv_sec = 0;
	wtime.tv_usec = 100 * 1000;

	FD_ZERO(&fdbits);
	FD_SET(routing_socket, &fdbits);

	rlen = select(routing_socket + 1, &fdbits, 0, 0, &wtime);
	if (rlen == 0) {
	    IF_DEBUG(DEBUG_RPF | DEBUG_KERN)
		logit(LOG_DEBUG, 0, "Timeout waiting for reply from routing socket for %s",
		      inet_fmt(source, s1, sizeof(s1)));

	    return FALSE;
	}

	if (rlen < 0) {
	    switch (errno) {
		case EINTR:
		    /* FALLTHROUGH */
		case EAGAIN:
		    continue;	/* Signalled, retry syscall. */

		default:
		    IF_DEBUG(DEBUG_RPF | DEBUG_KERN)
			logit(LOG_DEBUG, errno, "Select error on routing socket for %s",
			      inet_fmt(source, s1, sizeof(s1)));
		    return FALSE;
	    }
	}

	if (FD_ISSET(routing_socket, &fdbits)) {
	    rlen = read(routing_socket, &m_rtmsg, sizeof(m_rtmsg));
	    if (rlen < 0) {
		if (errno == EINTR)
		    continue;	/* Signalled, retry syscall. */

		IF_DEBUG(DEBUG_RPF | DEBUG_KERN)
		    logit(LOG_DEBUG, errno, "Failed getting route for %s",
			  inet_fmt(source, s1, sizeof(s1)));

		return FALSE;
	    }

	    if (rlen > 0 && (rtm.rtm_seq != seq || rtm.rtm_pid != pid)) {
		IF_DEBUG(DEBUG_RPF | DEBUG_KERN)
		    logit(LOG_DEBUG, 0, "Reply not for me, retrying: want %d(%ld) got %d(%ld)",
			  seq, (long) pid, rtm.rtm_seq, (long) rtm.rtm_pid);
		continue;
	    }
	}

	break;
    }

    memset(&rpfinfo, 0, sizeof(rpfinfo));
    if (getmsg(&rtm, l, &rpfinfo)) {
	rpf->rpfneighbor.s_addr = rpfinfo.rpfneighbor.s_addr;
	rpf->iif = rpfinfo.iif;
	rpf->metric = rpfinfo.metric;
    }
#undef rtm

    return TRUE;
}

static void find_sockaddrs(struct rt_msghdr *rtm, struct sockaddr **dst, struct sockaddr **gate,
			   struct sockaddr **mask, struct sockaddr_dl **ifp)
{
    char *cp = (char *)(rtm + 1);
    struct sockaddr *sa;
    unsigned int i;

    if (!rtm->rtm_addrs)
	return;

    /* Unsigned, so the bit walks off the top to 0 rather than overflowing */
    for (i = 1; i; i <<= 1) {
	if (i & rtm->rtm_addrs) {
	    sa = (struct sockaddr *)cp;

	    switch (i) {
		case RTA_DST:
		    *dst = sa;
		    break;

		case RTA_GATEWAY:
		    *gate = sa;
		    break;

		case RTA_NETMASK:
		    *mask = sa;
		    break;

		case RTA_IFP:
		    if (sa->sa_family == AF_LINK  && ((struct sockaddr_dl *)sa)->sdl_nlen)
			*ifp = (struct sockaddr_dl *)sa;
		    break;
	    }
	    ADVANCE(cp, sa);
	}
    }
}

/*
 * Returns TRUE on success, FALSE otherwise. rpfinfo contains the result.
 */
static int getmsg(struct rt_msghdr *rtm, int msglen __attribute__((unused)), struct rpfctl *rpf)
{
    struct sockaddr *dst = NULL, *gate = NULL, *mask = NULL;
    struct sockaddr_dl *ifp = NULL;
    struct in_addr in;
    struct uvif *v;
    vifi_t vifi;

    if (!rpf) {
	logit(LOG_WARNING, 0, "Missing rpf pointer to routesock.c:getmsg()!");
	return FALSE;
    }

    rpf->iif = NO_VIF;
    rpf->rpfneighbor.s_addr = INADDR_ANY;
    rpf->metric = RPF_METRIC_UNKNOWN;

    /* MRIB.pref of sec. 4.6.3 is never anything else here: a PF_ROUTE
     * reply says what the route costs, in rtm_rmx, and never which routing
     * protocol installed it -- rtsock.c fills the metrics and no origin --
     * so `assert-preference rib` has nothing to read on this backend and
     * the `distance` of pimd.conf stands.  netlink.c is the build that can
     * answer it.
     */
    rpf->pref = RPF_PREF_UNKNOWN;

    /* MRIB.metric, which RFC 7761 sec. 4.6.3 wants in the Assert.  FreeBSD
     * keeps the per-nexthop metric `route -metric` sets in rt_metrics and
     * fills it into every reply (sys/net/rtsock.c); the routing sockets
     * that have no such field leave pimd with the `metric` of pimd.conf.
     */
#ifdef HAVE_STRUCT_RT_METRICS_RMX_METRIC
    if (rtm->rtm_rmx.rmx_metric < RPF_METRIC_UNKNOWN)
	rpf->metric = (uint32_t)rtm->rtm_rmx.rmx_metric;
#endif

    in = ((struct sockaddr_in *)&so_dst)->sin_addr;
    IF_DEBUG(DEBUG_RPF)
	logit(LOG_DEBUG, 0, "route to: %s", inet_fmt(in.s_addr, s1, sizeof(s1)));

    find_sockaddrs(rtm, &dst, &gate, &mask, &ifp);

    if (!ifp) {			/* No incoming interface */
	IF_DEBUG(DEBUG_RPF)
	    logit(LOG_DEBUG, 0, "No incoming interface for destination %s", inet_fmt(in.s_addr, s1, sizeof(s1)));

	return FALSE;
    }

    if (dst && mask)
	mask->sa_family = dst->sa_family;

    if (dst) {
	in = ((struct sockaddr_in *)dst)->sin_addr;
	IF_DEBUG(DEBUG_RPF)
	    logit(LOG_DEBUG, 0, " destination is: %s", inet_fmt(in.s_addr, s1, sizeof(s1)));
    }

    if (gate && (rtm->rtm_flags & RTF_GATEWAY)) {
	in = ((struct sockaddr_in *)gate)->sin_addr;
	IF_DEBUG(DEBUG_RPF)
	    logit(LOG_DEBUG, 0, " gateway is: %s", inet_fmt(in.s_addr, s1, sizeof(s1)));

	rpf->rpfneighbor = in;
    }

    for (vifi = 0, v = uvifs; vifi < numvifs; ++vifi, ++v) {
	/* get the number of the interface by matching the name */
	if ((strlen(v->uv_name) == ifp->sdl_nlen)
	    && !(strncmp(v->uv_name, ifp->sdl_data, ifp->sdl_nlen)))
	    break;
    }

    /* Found inbound interface in vifi */
    rpf->iif = vifi;

    IF_DEBUG(DEBUG_RPF)
	logit(LOG_DEBUG, 0, " iif is %d", vifi);

    if (vifi >= numvifs) {
	IF_DEBUG(DEBUG_RPF)
	    logit(LOG_DEBUG, 0, "Invalid incoming interface for destination %s, because of invalid virtual interface",
		  inet_fmt(in.s_addr, s1, sizeof(s1)));

	return FALSE;		/* invalid iif */
    }

    return TRUE;
}


#else /* !HAVE_ROUTING_SOCKETS -- if we want to run on Linux without Netlink */

const char *rpf_backend = "SIOCGETRPF";

/* API compat dummy. */
int init_routesock(void)
{
    routing_socket = dup(udp_socket);
}

/* API compat dummy. */
void routesock_clean(void)
{
    if (routing_socket >= 0)
	close(routing_socket);
    routing_socket = -1;
}

/*
 * Return in rpf the incoming interface and the next hop router
 * toward source.
 */
/* TODO: check whether next hop router address is in network or host order */
int k_req_incoming(uint32_t source, struct rpfctl *rpf)
{
    rpf->source.s_addr      = source;
    rpf->iif                = NO_VIF;     /* Initialize, will be changed in kernel */
    rpf->rpfneighbor.s_addr = INADDR_ANY; /* Initialize */

    if (ioctl(routing_socket, SIOCGETRPF, rpf) < 0) {
	logit(LOG_WARNING, errno, "Failed ioctl SIOCGETRPF in k_req_incoming()");
	return FALSE;
    }

    /* After the call: the kernel side of SIOCGETRPF knows nothing of the
     * two fields, so whatever it left there is not an answer. */
    rpf->metric = RPF_METRIC_UNKNOWN;
    rpf->pref   = RPF_PREF_UNKNOWN;

    return TRUE;
}
#endif /* HAVE_ROUTING_SOCKETS */

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "cc-mode"
 * End:
 */
