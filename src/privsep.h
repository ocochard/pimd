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
/*
 * Privilege separation: a privileged parent that owns the descriptors and
 * makes the calls the kernel asks root for, and an unprivileged child that
 * does everything else -- every parser, every timer, every state machine.
 *
 * The parent is needed rather than merely convenient because the kernel
 * checks the caller on every call rather than once on the socket: FreeBSD
 * runs priv_check(PRIV_NETINET_MROUTE) in rip_ctloutput() for every MRT_*
 * setsockopt and in X_mrt_ioctl() for SIOCGETVIFCNT and SIOCGETSGCNT, and
 * Linux checks CAP_NET_ADMIN in ip_mroute_setsockopt() the same way.  So a
 * child that dropped root could not add a VIF or change an MFC even holding
 * the mrouter socket it was handed.
 *
 * The boundary is src/kern.c, which already wraps every one of those calls.
 * The eight k_*() that need privilege call a priv_*() below when separated
 * and the kernel directly when not; the kern_*() half is what the parent
 * runs on the other side.
 *
 * The rule on the wire, in one line: no path and no format string ever
 * crosses from the child to the parent.  A request names a socket by an
 * enum rather than by a domain and protocol, names a file not at all -- the
 * paths are fixed before the fork and live in the parent -- and a log
 * message arrives rendered, to be logged with "%s".
 */
#ifndef PIMD_PRIVSEP_H_
#define PIMD_PRIVSEP_H_

/*
 * The sockets the parent will create, named so that the child cannot ask
 * for a domain, type and protocol of its own choosing.
 */
enum priv_sock {
    PRIV_SOCK_IGMP = 1,		/* raw IGMP, and the mrouter socket    */
    PRIV_SOCK_PIM,		/* raw PIM			       */
    PRIV_SOCK_UDP,		/* UDP, for the interface ioctls       */
    PRIV_SOCK_ROUTE,		/* routing socket / netlink, RPF       */
    PRIV_SOCK_IFEVENT,		/* the same, for interface events      */
};

/*
 * One interface as the scan crosses the wire.  getifaddrs() is a read of
 * the net.route sysctl, which capability mode refuses -- the oid is not
 * CTLFLAG_CAPRD -- so the parent walks the list and the child rebuilds a
 * struct ifaddrs from these, keeping the five fields pimd reads.
 */
struct priv_ifrec {
    char	name[IFNAMSIZ];
    uint32_t	flags;
    uint32_t	ifindex;
    uint16_t	family;		/* of ifa_addr, AF_UNSPEC if there is none */
    uint16_t	have;		/* PRIV_IFREC_* below			   */
    uint32_t	addr;
    uint32_t	netmask;
    uint32_t	dstaddr;
};

#define PRIV_IFREC_ADDR		0x01
#define PRIV_IFREC_NETMASK	0x02
#define PRIV_IFREC_DSTADDR	0x04

/* Records per PRIV_IFSCAN reply, and so the size of the biggest message. */
#define PRIV_IFREC_MAX		48

/* A rendered log line, truncated by the child rather than by the parent. */
#define PRIV_LOG_MAX		512

/*
 * Setup.  priv_init() forks the helper and returns in the child; the parent
 * never comes back from it.  Everything below is called by the child, and
 * does the plain thing in-process when separation is off.
 */
int	priv_init	(const char *user, const char *conf, const char *pid, const char *sock);
int	priv_enabled	(void);
const char *priv_user	(void);
const char *priv_sandbox(void);
const char *priv_chroot_dir(void);
void	priv_sandbox_enter(void);

/* Descriptors and the kernel calls that want privilege. */
int	priv_socket	(enum priv_sock kind);
void	priv_socket_release(void);
int	priv_mrt_init	(void);
int	priv_mrt_done	(void);
int	priv_add_vif	(struct vifctl *vc);
int	priv_del_vif	(vifi_t vifi, struct vifctl *vc);
int	priv_chg_mfc	(struct mfcctl *mc);
int	priv_del_mfc	(struct mfcctl *mc);
int	priv_vif_cnt	(struct sioc_vif_req *req);
int	priv_sg_cnt	(struct sioc_sg_req *req);

/* What the sandbox, rather than the kernel, keeps out of the child. */
int	priv_getifaddrs	(struct ifaddrs **ifap);
void	priv_freeifaddrs(struct ifaddrs *ifa);
unsigned int priv_ifindex(const char *ifname);
FILE   *priv_fopen_conf	(void);
FILE   *priv_tempfile	(void);
int	priv_pidfile	(const char *path);
int	priv_ipc_socket	(void);
void	priv_ipc_close	(void);
void	priv_log	(int severity, int syserr, const char *msg);

#endif /* PIMD_PRIVSEP_H_ */

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "cc-mode"
 * End:
 */
