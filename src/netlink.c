/*
 * Fred Griffoul <griffoul@ccrle.nec.de> sent me this file to use
 * when compiling pimd under Linux.
 *
 * There was no copyright message or author name, so I assume he was the
 * author, and deserves the copyright/credit for it: 
 *
 * COPYRIGHT/AUTHORSHIP by Fred Griffoul <griffoul@ccrle.nec.de>
 * (until proven otherwise).
 */

#include <sys/param.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdlib.h>
#include <strings.h>
#include <paths.h>
#include "defs.h"

/*
 * FreeBSD 13.2 and later speak the same protocol through netlink(4), and
 * its headers spell the RTM_*, RTN_*, RTA_* and nlmsghdr/rtmsg/rtattr the
 * parser below uses the Linux way, under "#ifndef _KERNEL" in
 * netlink/route/route.h.  Only the include line differs.
 */
#ifdef HAVE_NETLINK_NETLINK_ROUTE_H
#include <netlink/netlink.h>
#include <netlink/netlink_route.h>
#else
#include <linux/rtnetlink.h>
#endif

const char *rpf_backend = "netlink";

int routing_socket = -1;
static uint32_t pid; /* pid_t, but /usr/include/linux/netlink.h says __u32 ... */
static uint32_t seq;

static int getmsg(struct rtmsg *rtm, int msglen, struct rpfctl *rpf);
static int getroute(uint32_t dst, unsigned int flags, char *buf, size_t len);
static uint32_t fib_metric(uint32_t dst);

static int addattr32(struct nlmsghdr *n, size_t maxlen, int type, uint32_t data)
{
    int len = RTA_LENGTH(4);
    struct rtattr *rta;

    if (NLMSG_ALIGN(n->nlmsg_len) + len > maxlen)
	return -1;

    rta = (struct rtattr *)(((char *)n) + NLMSG_ALIGN(n->nlmsg_len));
    rta->rta_type = type;
    rta->rta_len = len;
    memcpy(RTA_DATA(rta), &data, 4);
    n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + len;

    return 0;
}

static int parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
    while (RTA_OK(rta, len)) {
	if (rta->rta_type <= max)
	    tb[rta->rta_type] = rta;
	rta = RTA_NEXT(rta, len);
    }

    if (len)
	logit(LOG_WARNING, 0, "netlink: Deficit in rtattr %d", len);

    return 0;
}

/* open and initialize the routing socket */
int init_routesock(void)
{
    socklen_t addr_len;
    struct sockaddr_nl local;

    routing_socket = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (routing_socket < 0) {
	logit(LOG_ERR, errno, "Failed creating netlink socket");
	return -1;
    }

    memset(&local, 0, sizeof(local));
    local.nl_family = AF_NETLINK;
    local.nl_groups = 0;
    if (bind(routing_socket, (struct sockaddr *)&local, sizeof(local)) < 0) {
	logit(LOG_ERR, errno, "Failed binding to netlink socket");
	return -1;
    }

    addr_len = sizeof(local);
    if (getsockname(routing_socket, (struct sockaddr *)&local, &addr_len) < 0) {
	logit(LOG_ERR, errno, "Failed netlink getsockname");
	return -1;
    }

    if (addr_len != sizeof(local)) {
	logit(LOG_ERR, 0, "Invalid netlink addr len.");
	return -1;
    }

    if (local.nl_family != AF_NETLINK) {
	logit(LOG_ERR, 0, "Invalid netlink addr family.");
	return -1;
    }

    pid = local.nl_pid;
    seq = time(NULL);

    return 0;
}

void routesock_clean(void)
{
    if (routing_socket > 0)
	close(routing_socket);
    routing_socket = 0;
}

/* get the rpf neighbor info */
int k_req_incoming(uint32_t source, struct rpfctl *rpf)
{
    int l;
    char buf[512];
    struct nlmsghdr *n = (struct nlmsghdr *)buf;

    rpf->source.s_addr      = source;
    rpf->iif                = NO_VIF;     /* Initialize, will be changed in kernel */
    rpf->rpfneighbor.s_addr = INADDR_ANY; /* Initialize */
    rpf->metric             = RPF_METRIC_UNKNOWN;

    /*
     * Nothing in 169.254/16 is ever routed, RFC 3927 sec. 2.7 forbids
     * forwarding a link-local packet at all, so whatever the kernel
     * answers here cannot be a path to it.  config.c gives the SSM range
     * a static RP of 169.254.0.1, on purpose, precisely because the
     * address leads nowhere, and every RP lookup asks for it.
     */
    if (IN_LINK_LOCAL_RANGE(source)) {
	IF_DEBUG(DEBUG_RPF)
	    logit(LOG_DEBUG, 0, "k_req_incoming: link-local source %s is not routable",
		  inet_fmt(source, s1, sizeof(s1)));

	return FALSE;
    }

    IF_DEBUG(DEBUG_RPF)
	logit(LOG_DEBUG, 0, "k_req_incoming: ask path to %s", inet_fmt(rpf->source.s_addr, s1, sizeof(s1)));

    l = getroute(rpf->source.s_addr, 0, buf, sizeof(buf));
    if (l < 0)
	return FALSE;

    if (n->nlmsg_type != RTM_NEWROUTE) {
	errno = -(*(int*)NLMSG_DATA(n));

	if (n->nlmsg_type != NLMSG_ERROR)
	    logit(LOG_WARNING, 0, "Wrong netlink answer type: %d", n->nlmsg_type);
	else IF_DEBUG(DEBUG_RPF | DEBUG_KERN)
	    logit(LOG_DEBUG, errno, "Failed getting route for %s",
		  inet_fmt(rpf->source.s_addr, s1, sizeof(s1)));

	return FALSE;
    }

    /* Cast, so that a reply shorter than the header it announces stays a
     * negative length here rather than becoming a huge unsigned one */
    return getmsg(NLMSG_DATA(n), l - (int)sizeof(*n), rpf);
}

/*
 * Send one RTM_GETROUTE for dst, with rtm_flags set to flags, and read the
 * answer to it into buf.  Returns the length read, or -1.
 */
static int getroute(uint32_t dst, unsigned int flags, char *buf, size_t len)
{
    int l, rlen;
    struct nlmsghdr *n = (struct nlmsghdr *)buf;
    struct rtmsg *r = NLMSG_DATA(n);
    struct sockaddr_nl addr;

    if (len < NLMSG_LENGTH(sizeof(*r)))
	return -1;

    n->nlmsg_type = RTM_GETROUTE;
    n->nlmsg_flags = NLM_F_REQUEST;
    n->nlmsg_len = NLMSG_LENGTH(sizeof(*r));
    n->nlmsg_pid = pid;
    n->nlmsg_seq = ++seq;

    memset(r, 0, sizeof(*r));
    r->rtm_family = AF_INET;
    r->rtm_dst_len = 32;
    r->rtm_flags = flags;
    addattr32(n, len, RTA_DST, dst);
#ifdef CONFIG_RTNL_OLD_IFINFO
    r->rtm_optlen = n->nlmsg_len - NLMSG_LENGTH(sizeof(*r));
#endif
    addr.nl_family = AF_NETLINK;
    addr.nl_groups = 0;
    addr.nl_pid = 0;

    do {
	socklen_t alen = sizeof(addr);

	rlen = sendto(routing_socket, buf, n->nlmsg_len, 0, (struct sockaddr *)&addr, alen);
	if (rlen < 0) {
	    if (errno == EINTR)
		continue;	/* Received signal, retry syscall. */

	    logit(LOG_WARNING, errno, "Error writing to netlink socket");
	    return -1;
	}
    } while (rlen < 0);

    do {
	socklen_t alen = sizeof(addr);

	l = recvfrom(routing_socket, buf, len, 0, (struct sockaddr *)&addr, &alen);
	if (l < 0) {
	    if (errno == EINTR)
		continue;	/* Received signal, retry syscall. */

	    logit(LOG_WARNING, errno, "Error reading from netlink socket");
	    return -1;
	}
    } while (l < 0 || n->nlmsg_seq != seq || n->nlmsg_pid != pid);

    return l;
}

/*
 * The priority of the FIB entry that routes dst, what `ip route` prints as
 * its "metric", or 0 when there is none to be had.
 *
 * The ordinary RTM_GETROUTE k_req_incoming() sends is answered on Linux
 * with the route resolved for dst, and that answer never carries
 * RTA_PRIORITY, whatever the metric of the entry it was resolved from:
 * `ip route get` prints no metric, `ip route get fibmatch` does.
 * RTM_F_FIB_MATCH (Linux 4.13) is what asks for the entry itself.  Only
 * the priority is taken from that answer.  The next hop stays the one
 * the ordinary lookup chose, since the entry of a multipath route lists
 * them all.
 */
static uint32_t fib_metric(uint32_t dst)
{
#ifdef RTM_F_FIB_MATCH
    int l;
    char buf[512];
    struct nlmsghdr *n = (struct nlmsghdr *)buf;
    struct rtmsg *rtm;
    struct rtattr *rta[RTA_MAX + 1];

    l = getroute(dst, RTM_F_FIB_MATCH, buf, sizeof(buf));
    if (l < (int)NLMSG_LENGTH(sizeof(*rtm)) || n->nlmsg_type != RTM_NEWROUTE)
	return 0;

    rtm = NLMSG_DATA(n);
    memset(rta, 0, sizeof(rta));
    parse_rtattr(rta, RTA_MAX, RTM_RTA(rtm), l - (int)NLMSG_LENGTH(sizeof(*rtm)));

    if (rta[RTA_PRIORITY] && RTA_PAYLOAD(rta[RTA_PRIORITY]) >= (int)sizeof(uint32_t))
	return *(uint32_t *)RTA_DATA(rta[RTA_PRIORITY]);
#endif

    return 0;
}

static int getmsg(struct rtmsg *rtm, int msglen, struct rpfctl *rpf)
{
    int ifindex;
    vifi_t vifi;
    struct uvif *v;
    struct rtattr *rta[RTA_MAX + 1];
    
    if (!rpf) {
	logit(LOG_WARNING, 0, "Missing rpf pointer to netlink.c:getmsg()!");
	return FALSE;
    }

    /* The header this reads, before the attribute walk below is told how
     * much is left: that length is `msglen - sizeof(*rtm)`, a subtraction
     * against a size_t, so a reply too short to hold the header would not
     * come out negative there, it would come out as the address space.
     */
    if (msglen < (int)sizeof(*rtm)) {
	logit(LOG_WARNING, 0, "Short netlink reply, %d bytes", msglen);
	return FALSE;
    }

    rpf->iif = NO_VIF;
    rpf->rpfneighbor.s_addr = INADDR_ANY;
    rpf->metric = RPF_METRIC_UNKNOWN;

    /* Only Linux ever says this: FreeBSD's netlink(4) has no RTN_LOCAL
     * ("not supported" in netlink/route/route.h) and answers for one of
     * our own addresses with an ordinary RTN_UNICAST route out of lo0,
     * which is no VIF, so the lookup below fails.  That is what
     * routesock.c does there too, it matches lo0 by name and finds no
     * VIF either, so the daemon sees no change of behaviour.
     */
    if (rtm->rtm_type == RTN_LOCAL) {
	IF_DEBUG(DEBUG_RPF)
	    logit(LOG_DEBUG, 0, "netlink: local address");

	if ((rpf->iif = local_address(rpf->source.s_addr)) != MAXVIFS) {
	    rpf->rpfneighbor.s_addr = rpf->source.s_addr;

	    return TRUE;
	}

	return FALSE;
    }
    
    if (rtm->rtm_type != RTN_UNICAST) {
	IF_DEBUG(DEBUG_RPF)
	    logit(LOG_DEBUG, 0, "netlink: route type is %d", rtm->rtm_type);
	return FALSE;
    }
    
    memset(rta, 0, sizeof(rta));
    parse_rtattr(rta, RTA_MAX, RTM_RTA(rtm), msglen - sizeof(*rtm));
    
    /* RTA_OK() only says an attribute is not longer than what is left of
     * the message, a four byte one with no payload at all passes it, so
     * every attribute read below asks for its bytes first -- as the metric
     * further down already did. */
    if (!rta[RTA_OIF] || RTA_PAYLOAD(rta[RTA_OIF]) < (int)sizeof(uint32_t)) {
	logit(LOG_WARNING, 0, "Missing outbound interface in netlink reply");
	return FALSE;
    }

    /* Get ifindex of outbound interface */
    ifindex = *(int *)RTA_DATA(rta[RTA_OIF]);

    for (vifi = 0, v = uvifs; vifi < numvifs; ++vifi, ++v) {
	if (v->uv_ifindex == ifindex)
	    break;
    }

    if (vifi >= numvifs)
	return FALSE;

    /* Found inbound interface in vifi */
    rpf->iif = vifi;

    IF_DEBUG(DEBUG_RPF)
	logit(LOG_DEBUG, 0, "netlink: vif %d, ifindex=%d", vifi, ifindex);

    if (rta[RTA_GATEWAY] && RTA_PAYLOAD(rta[RTA_GATEWAY]) >= (int)sizeof(uint32_t)) {
	uint32_t gw = *(uint32_t *)RTA_DATA(rta[RTA_GATEWAY]);

	IF_DEBUG(DEBUG_RPF)
	    logit(LOG_DEBUG, 0, "netlink: gateway is %s", inet_fmt(gw, s1, sizeof(s1)));
	rpf->rpfneighbor.s_addr = gw;
    } else {
	rpf->rpfneighbor.s_addr = rpf->source.s_addr;
    }

    /* MRIB.metric, which RFC 7761 sec. 4.6.3 wants in the Assert: on Linux
     * that is the route's priority, what `ip route` prints as "metric".
     * This answer does not carry it there, see fib_metric(), which asks
     * for it; zero is what an ordinary route has, so an entry without one
     * is at metric 0 and not a missing answer.
     *
     * FreeBSD puts the attribute in this answer, filled from
     * nhop_get_metric(), which is the rt_metrics.rmx_metric `route -metric`
     * sets (sys/net/route/nhop_ctl.c), the number routesock.c reads out of
     * a routing socket reply there.  Its default is RT_DEFAULT_METRIC, 1,
     * not 0, so the second lookup is never made there.
     */
    if (rta[RTA_PRIORITY] && RTA_PAYLOAD(rta[RTA_PRIORITY]) >= (int)sizeof(uint32_t))
	rpf->metric = *(uint32_t *)RTA_DATA(rta[RTA_PRIORITY]);
    else
	rpf->metric = fib_metric(rpf->source.s_addr);

    IF_DEBUG(DEBUG_RPF)
	logit(LOG_DEBUG, 0, "netlink: metric is %u", rpf->metric);

    return TRUE;
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "cc-mode"
 * End:
 */
