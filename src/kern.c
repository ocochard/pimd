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

#include "defs.h"

#ifdef RAW_OUTPUT_IS_RAW
int curttl = 0;
#endif

/*
 * XXX: in Some BSD's there is only MRT_ASSERT, but in Linux there are
 *      both MRT_ASSERT and MRT_PIM
 */
#ifndef MRT_PIM
#define MRT_PIM MRT_ASSERT
#endif

#ifdef __linux__ /* Currently only available on Linux  */
# ifndef MRT_TABLE
#  define MRT_TABLE       (MRT_BASE + 9)
# endif
#endif

/*
 * Open/init the multicast routing in the kernel and sets the
 * MRT_PIM (aka MRT_ASSERT) flag in the kernel.
 */
/*
 * The calls the kernel asks root for, with the struct building and the
 * logging left to the k_*() below: these are what the privileged parent of
 * src/privsep.c runs on behalf of an unprivileged child, and what the
 * k_*() call directly when pimd was not separated.  They report through
 * errno rather than through logit(), the parent having nobody to log to
 * but the child it is answering, and the ones with several steps answer
 * with the step that failed so that the caller can keep the message it
 * always printed for it.
 */
int kern_mrt_init(int sd)
{
    int v = 1;

#ifdef MRT_TABLE /* Currently only available on Linux  */
    if (mrt_table_id != 0) {
	if (setsockopt(sd, IPPROTO_IP, MRT_TABLE, &mrt_table_id, sizeof(mrt_table_id)) < 0)
	    return KERN_STEP_TABLE;
    }
#endif

    if (setsockopt(sd, IPPROTO_IP, MRT_INIT, (char *)&v, sizeof(int)) < 0)
	return KERN_STEP_INIT;

    if (setsockopt(sd, IPPROTO_IP, MRT_PIM, (char *)&v, sizeof(int)) < 0)
	return KERN_STEP_PIM;

    return 0;
}

int kern_mrt_done(int sd)
{
    int v = 0;

    if (setsockopt(sd, IPPROTO_IP, MRT_PIM, (char *)&v, sizeof(int)) < 0)
	return KERN_STEP_PIM;

    if (setsockopt(sd, IPPROTO_IP, MRT_DONE, (char *)NULL, 0) < 0)
	return KERN_STEP_INIT;

    return 0;
}

int kern_add_vif(int sd, struct vifctl *vc)
{
    return setsockopt(sd, IPPROTO_IP, MRT_ADD_VIF, (char *)vc, sizeof(*vc));
}

int kern_del_vif(int sd, vifi_t vifi, struct vifctl *vc)
{
    /*
     * Unfortunately Linux MRT_DEL_VIF API differs a bit from the *BSD one.
     * It expects to receive a pointer to struct vifctl that corresponds to
     * the VIF we're going to delete.  *BSD systems on the other hand expect
     * only the index of that VIF.
     */
#ifdef __linux__
    (void)vifi;
    return setsockopt(sd, IPPROTO_IP, MRT_DEL_VIF, (char *)vc, sizeof(*vc));
#else
    (void)vc;
    return setsockopt(sd, IPPROTO_IP, MRT_DEL_VIF, (char *)&vifi, sizeof(vifi));
#endif
}

int kern_chg_mfc(int sd, struct mfcctl *mc)
{
    return setsockopt(sd, IPPROTO_IP, MRT_ADD_MFC, (char *)mc, sizeof(*mc));
}

int kern_del_mfc(int sd, struct mfcctl *mc)
{
    return setsockopt(sd, IPPROTO_IP, MRT_DEL_MFC, (char *)mc, sizeof(*mc));
}

int kern_vif_cnt(int sd, struct sioc_vif_req *vreq)
{
    return ioctl(sd, SIOCGETVIFCNT, (char *)vreq);
}

int kern_sg_cnt(int sd, struct sioc_sg_req *sgreq)
{
    /* XXX: ipmulti-3.5 has a bug in ip_mroute.c, get_sg_cnt(): the return
     * code is always 0, so this is why we need to check wrong_if too. */
    if (ioctl(sd, SIOCGETSGCNT, (char *)sgreq) < 0 || sgreq->wrong_if == 0xffffffff)
	return -1;

    return 0;
}


void k_init_pim(int socket)
{
    int step;

#ifdef MRT_TABLE /* Currently only available on Linux  */
    if (mrt_table_id != 0)
	logit(LOG_INFO, 0, "Initializing multicast routing table id %u", mrt_table_id);
#endif

    if (priv_enabled())
	step = priv_mrt_init();
    else
	step = kern_mrt_init(socket);

    switch (step) {
    case 0:
	break;

    case KERN_STEP_TABLE:
	logit(LOG_WARNING, errno, "Cannot set multicast routing table id");
	logit(LOG_ERR, 0, "Make sure your kernel has CONFIG_IP_MROUTE_MULTIPLE_TABLES=y");
	break;

    case KERN_STEP_INIT:
	if (errno == EADDRINUSE)
	    logit(LOG_ERR, 0, "Another multicast routing application is already running.");
	else
	    logit(LOG_ERR, errno, "Cannot enable multicast routing in kernel");
	break;

    default:
	logit(LOG_ERR, errno, "Cannot set PIM flag in kernel");
	break;
    }
}


/*
 * Stops the multicast routing in the kernel and resets the
 * MRT_PIM (aka MRT_ASSERT) flag in the kernel.
 */
void k_stop_pim(int socket)
{
    int step;

    if (priv_enabled())
	step = priv_mrt_done();
    else
	step = kern_mrt_done(socket);

    if (step == KERN_STEP_PIM)
	logit(LOG_ERR, errno, "Cannot reset PIM flag in kernel");
    else if (step)
	logit(LOG_ERR, errno, "Cannot disable multicast routing in kernel");
}


/*
 * Set the socket sending buffer. `bufsize` is the preferred size,
 * `minsize` is the smallest acceptable size.
 */
void k_set_sndbuf(int socket, int bufsize, int minsize)
{
    int delta = bufsize / 2;

    /*
     * Set the socket buffer.  If we can't set it as large as we
     * want, search around to try to find the highest acceptable
     * value.  The highest acceptable value being smaller than
     * minsize is a fatal error.
     */
    if (setsockopt(socket, SOL_SOCKET, SO_SNDBUF, (char *)&bufsize, sizeof(bufsize)) < 0) {
	bufsize -= delta;
	while (1) {
	    if (delta > 1)
		delta /= 2;

	    if (setsockopt(socket, SOL_SOCKET, SO_SNDBUF, (char *)&bufsize, sizeof(bufsize)) < 0) {
		bufsize -= delta;
	    } else {
		if (delta < 1024)
		    break;
		bufsize += delta;
	    }
	}
	if (bufsize < minsize) {
	    logit(LOG_ERR, 0, "OS-allowed send buffer size %u < app min %u",
		  bufsize, minsize);
	    /*NOTREACHED*/
	}
    }
}


/*
 * Set the socket receiving buffer. `bufsize` is the preferred size,
 * `minsize` is the smallest acceptable size.
 */
void k_set_rcvbuf(int socket, int bufsize, int minsize)
{
    int delta = bufsize / 2;

    /*
     * Set the socket buffer.  If we can't set it as large as we
     * want, search around to try to find the highest acceptable
     * value.  The highest acceptable value being smaller than
     * minsize is a fatal error.
     */
    if (setsockopt(socket, SOL_SOCKET, SO_RCVBUF, (char *)&bufsize, sizeof(bufsize)) < 0) {
	bufsize -= delta;
	while (1) {
	    if (delta > 1)
		delta /= 2;

	    if (setsockopt(socket, SOL_SOCKET, SO_RCVBUF, (char *)&bufsize, sizeof(bufsize)) < 0) {
		bufsize -= delta;
	    } else {
		if (delta < 1024)
		    break;
		bufsize += delta;
	    }
	}

	if (bufsize < minsize) {
	    logit(LOG_ERR, 0, "OS-allowed recv buffer size %u < app min %u", bufsize, minsize);
	    /*NOTREACHED*/
	}
    }
}


/*
 * Set/reset the IP_HDRINCL option. My guess is we don't need it for raw
 * sockets, but having it here won't hurt. Well, unless you are running
 * an older version of FreeBSD (older than 2.2.2). If the multicast
 * raw packet is bigger than 208 bytes, then IP_HDRINCL triggers a bug
 * in the kernel and "panic". The kernel patch for netinet/ip_raw.c
 * coming with this distribution fixes it.
 */
void k_hdr_include(int socket, int val)
{
#ifdef IP_HDRINCL
    if (setsockopt(socket, IPPROTO_IP, IP_HDRINCL, (char *)&val, sizeof(val)) < 0)
	logit(LOG_ERR, errno, "Failed %s IP_HDRINCL on socket %d",
	      ENABLINGSTR(val), socket);
#endif
}


/*
 * For IGMP reports we need to know incoming interface since proxy reporters
 * may use source IP 0.0.0.0, so we cannot rely on find_vif_direct_local().
 */
void k_set_pktinfo(int socket __attribute__((unused)), int val __attribute__((unused)))
{
#ifdef IP_PKTINFO
    if (setsockopt(socket, SOL_IP, IP_PKTINFO, &val, sizeof(val)) < 0)
	logit(LOG_ERR, errno, "Failed %s IP_PKTINFO on socket %d",
	      ENABLINGSTR(val), socket);
#endif
}


/*
 * Set the default TTL for the multicast packets outgoing from this
 * socket.
 * TODO: Does it affect the unicast packets?
 */
void k_set_ttl(int socket __attribute__((unused)), int t)
{
#ifdef RAW_OUTPUT_IS_RAW
    curttl = t;
#else
    uint8_t ttl;

    ttl = t;
    if (setsockopt(socket, IPPROTO_IP, IP_MULTICAST_TTL, (char *)&ttl, sizeof(ttl)) < 0)
	logit(LOG_ERR, errno, "Failed setting IP_MULTICAST_TTL %u on socket %d", ttl, socket);
#endif
}


/*
 * Set/reset the IP_MULTICAST_LOOP. Set/reset is specified by "flag".
 */
void k_set_loop(int socket, int flag)
{
    uint8_t loop;

    loop = flag;
    if (setsockopt(socket, IPPROTO_IP, IP_MULTICAST_LOOP, (char *)&loop, sizeof(loop)) < 0)
	logit(LOG_ERR, errno, "Failed %s IP_MULTICAST_LOOP on socket %d",
	      ENABLINGSTR(flag), socket);
}


/*
 * Set the IP_MULTICAST_IF option on local interface ifa.
 */
void k_set_if(int socket, uint32_t ifa)
{
    struct in_addr adr;

    adr.s_addr = ifa;
    if (setsockopt(socket, IPPROTO_IP, IP_MULTICAST_IF, (char *)&adr, sizeof(adr)) < 0) {
	if (errno == EADDRNOTAVAIL || errno == EINVAL)
	    return;

	logit(LOG_ERR, errno, "Failed setting IP_MULTICAST_IF option on %s",
	      inet_fmt(adr.s_addr, s1, sizeof(s1)));
    }
}


/*
 * Set Router Alert IP option, RFC2113
 */
void k_set_router_alert(int socket)
{
    char router_alert[4];

    router_alert[0] = (uint8_t)IPOPT_RA;
    router_alert[1] = 4;
    router_alert[2] = 0;
    router_alert[3] = 0;

    if (setsockopt(socket, IPPROTO_IP, IP_OPTIONS, router_alert, sizeof(router_alert) )< 0)
	logit(LOG_ERR, errno, "setsockopt IP_OPTIONS IPOPT_RA");
}


#ifndef __linux__
/*
 * Name the interface a multicast membership belongs to, in the terms the
 * kernel resolves: an address it can still place.
 *
 * imr_interface is looked up by address, INADDR_TO_IFP() in
 * sys/netinet/in_mcast.c, and an address the kernel cannot place there is
 * not refused.  It leaves ifp NULL, and both ends of that go wrong for us:
 * imo_match_group() then matches the group on *any* interface, so
 * IP_DROP_MEMBERSHIP takes the membership of whichever VIF comes first in
 * the socket's list, and IP_ADD_MEMBERSHIP picks an interface out of the
 * routing table instead.  A VIF holds an address the kernel may have
 * dropped already -- its interface was destroyed, or renumbered under the
 * running daemon -- and leaving with one of those left pimd deaf on the
 * link it still had, every group gone from a VIF nobody had touched.
 *
 * So ask the interface for an address of its own.  Any of them resolves to
 * the same ifnet, which is all a membership is keyed on, so this is not the
 * "which address is the VIF's" question check_vif_addrs() walks getifaddrs()
 * for.  FALSE means there is no interface left to ask, and the kernel has
 * already dropped everything it held there.
 *
 * Linux is not in this: it names the interface by index, and ip_mc_find_dev()
 * refuses an index it cannot resolve instead of falling back to any of them.
 */
static int mcast_ifaddr(struct uvif *v, struct in_addr *addr)
{
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    strlcpy(ifr.ifr_name, v->uv_name, sizeof(ifr.ifr_name));
    if (ioctl(udp_socket, SIOCGIFADDR, (char *)&ifr) < 0) {
	/* An interface that has been removed is ENODEV on Linux and ENXIO
	 * on *BSD, as check_vif_state() reads them; EADDRNOTAVAIL is one
	 * that has no address for us to name it by. */
	if (errno != ENODEV && errno != ENXIO && errno != EADDRNOTAVAIL)
	    logit(LOG_WARNING, errno, "Failed reading address of %s", v->uv_name);

	return FALSE;
    }

    *addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;

    return TRUE;
}
#endif /* !__linux__ */


/*
 * Join a multicast group on virtual interface 'v'.
 */
void k_join(int socket, uint32_t grp, struct uvif *v)
{
#ifdef __linux__
    struct ip_mreqn mreq;
#else
    struct ip_mreq mreq;
#endif /* __linux__ */

#ifdef __linux__
    mreq.imr_ifindex	      = v->uv_ifindex;
    mreq.imr_address.s_addr   = v->uv_lcl_addr;
#else
    if (!mcast_ifaddr(v, &mreq.imr_interface))
	return;
#endif /* __linux__ */
    mreq.imr_multiaddr.s_addr = grp;

    if (setsockopt(socket, IPPROTO_IP, IP_ADD_MEMBERSHIP,
		   (char *)&mreq, sizeof(mreq)) < 0) {
#ifdef __linux__
	logit(LOG_WARNING, errno,
	      "Cannot join group %s on interface %s (ifindex %d)",
	      inet_fmt(grp, s1, sizeof(s1)), inet_fmt(v->uv_lcl_addr, s2, sizeof(s2)), v->uv_ifindex);
#else
	logit(LOG_WARNING, errno,
	      "Cannot join group %s on interface %s",
	      inet_fmt(grp, s1, sizeof(s1)), inet_fmt(v->uv_lcl_addr, s2, sizeof(s2)));
#endif /* __linux__ */
    }
}


/*
 * Leave a multicast group on virtual interface 'v'.
 */
void k_leave(int socket, uint32_t grp, struct uvif *v)
{
#ifdef __linux__
    struct ip_mreqn mreq;
#else
    struct ip_mreq mreq;
#endif /* __linux__ */

#ifdef __linux__
    mreq.imr_ifindex	      = v->uv_ifindex;
    mreq.imr_address.s_addr   = v->uv_lcl_addr;
#else
    if (!mcast_ifaddr(v, &mreq.imr_interface))
	return;
#endif /* __linux__ */
    mreq.imr_multiaddr.s_addr = grp;

    if (setsockopt(socket, IPPROTO_IP, IP_DROP_MEMBERSHIP, (char *)&mreq, sizeof(mreq)) < 0) {
#ifdef __linux__
	logit(LOG_WARNING, errno,
	      "Cannot leave group %s on interface %s (ifindex %d)",
	      inet_fmt(grp, s1, sizeof(s1)), inet_fmt(v->uv_lcl_addr, s2, sizeof(s2)), v->uv_ifindex);
#else
	logit(LOG_WARNING, errno,
	      "Cannot leave group %s on interface %s",
	      inet_fmt(grp, s1, sizeof(s1)), inet_fmt(v->uv_lcl_addr, s2, sizeof(s2)));
#endif /* __linux__ */
    }
}

/*
 * Fill struct vifctl using corresponding fields from struct uvif.
 */
static void uvif_to_vifctl(struct vifctl *vc, struct uvif *v)
{
    /* XXX: we don't support VIFF_TUNNEL; VIFF_SRCRT is obsolete */
    vc->vifc_flags	     = 0;
    if (v->uv_flags & VIFF_REGISTER)
	vc->vifc_flags      |= VIFF_REGISTER;
#ifdef VIFF_USE_IFINDEX
    else
	vc->vifc_flags      |= VIFF_USE_IFINDEX;

    vc->vifc_lcl_ifindex     = v->uv_ifindex;
#else
    vc->vifc_lcl_addr.s_addr = v->uv_lcl_addr;
#endif
    vc->vifc_threshold       = v->uv_threshold;
    vc->vifc_rate_limit      = v->uv_rate_limit;
    if (v->uv_flags & VIFF_TUNNEL)
	vc->vifc_rmt_addr.s_addr = v->uv_rmt_addr;
    else
	vc->vifc_rmt_addr.s_addr = 0;
}

/*
 * Add a virtual interface in the kernel.
 */
void k_add_vif(int socket, vifi_t vifi, struct uvif *v)
{
    struct vifctl vc;
    int rc;

    vc.vifc_vifi = vifi;
    uvif_to_vifctl(&vc, v);

    if (priv_enabled())
	rc = priv_add_vif(&vc);
    else
	rc = kern_add_vif(socket, &vc);

    if (rc < 0)
	logit(LOG_ERR, errno, "Failed adding VIF %d (MRT_ADD_VIF) for iface %s",
	      vifi, v->uv_name);
}


/*
 * Delete a virtual interface in the kernel.
 */
void k_del_vif(int socket, vifi_t vifi, struct uvif *v)
{
    struct vifctl vc;
    int rc;

    /* Which half of this the kernel reads is kern_del_vif()'s business;
     * the vifctl is built either way, since it is what crosses to the
     * privileged half and both systems are served by one message. */
    memset(&vc, 0, sizeof(vc));
    vc.vifc_vifi = vifi;
    if (v)
	uvif_to_vifctl(&vc, v);

    if (priv_enabled())
	rc = priv_del_vif(vifi, &vc);
    else
	rc = kern_del_vif(socket, vifi, &vc);

    if (rc < 0) {
	if (errno == EADDRNOTAVAIL || errno == EINVAL)
	    return;

	logit(LOG_ERR, errno, "Failed removing VIF %d (MRT_DEL_VIF)", vifi);
    }
}


/*
 * Delete all MFC entries for particular routing entry from the kernel.
 */
int k_del_mfc(int socket, uint32_t source, uint32_t group)
{
    struct mfcctl mc;

    memset(&mc, 0, sizeof(mc));
    mc.mfcc_origin.s_addr   = source;
    mc.mfcc_mcastgrp.s_addr = group;

    if ((priv_enabled() ? priv_del_mfc(&mc) : kern_del_mfc(socket, &mc)) < 0) {
	logit(LOG_WARNING, errno, "Failed removing MFC entry src %s, grp %s",
	      inet_fmt(mc.mfcc_origin.s_addr, s1, sizeof(s1)),
	      inet_fmt(mc.mfcc_mcastgrp.s_addr, s2, sizeof(s2)));

	return FALSE;
    }

    logit(LOG_INFO, 0, "Removed MFC entry src %s, grp %s",
	inet_fmt(mc.mfcc_origin.s_addr, s1, sizeof(s1)),
	inet_fmt(mc.mfcc_mcastgrp.s_addr, s2, sizeof(s2)));

    return TRUE;
}


/*
 * Install/modify a MFC entry in the kernel
 */
int k_chg_mfc(int socket, uint32_t source, uint32_t group, vifi_t iif, uint8_t *oifs, uint32_t rp_addr __attribute__((unused)))
{
    char           input[IFNAMSIZ], output[MAXVIFS * (IFNAMSIZ + 2)] = "";
    vifi_t	   vifi;
    struct uvif   *v;
    struct mfcctl  mc;

    memset(&mc, 0, sizeof(mc));
    mc.mfcc_origin.s_addr    = source;
    mc.mfcc_mcastgrp.s_addr  = group;
    mc.mfcc_parent	     = iif;
    /*
     * draft-ietf-pim-sm-v2-new-05.txt section 4.2 mentions iif is removed
     * at the packet forwarding phase
     */
    PIMD_VIFM_CLR(mc.mfcc_parent, oifs);

    for (vifi = 0, v = uvifs; vifi < numvifs; vifi++, v++) {
	if (PIMD_VIFM_ISSET(vifi, oifs)) {
	    mc.mfcc_ttls[vifi] = v->uv_threshold;
	    if (output[0] != 0)
		strlcat(output, ", ", sizeof(output));
	    strlcat(output, v->uv_name, sizeof(output));
	} else {
	    mc.mfcc_ttls[vifi] = 0;
	}
    }
    strlcpy(input, uvifs[iif].uv_name, sizeof(input));

#ifdef PIM_REG_KERNEL_ENCAP
    mc.mfcc_rp_addr.s_addr = rp_addr;
#endif
    if ((priv_enabled() ? priv_chg_mfc(&mc) : kern_chg_mfc(socket, &mc)) < 0) {
	logit(LOG_WARNING, errno, "Failed adding MFC entry src %s grp %s from %s to %s",
	      inet_fmt(mc.mfcc_origin.s_addr, s1, sizeof(s1)),
	      inet_fmt(mc.mfcc_mcastgrp.s_addr, s2, sizeof(s2)),
	      input, output);

	return FALSE;
    }

    logit(LOG_INFO, 0, "Added kernel MFC entry src %s grp %s from %s to %s",
	  inet_fmt(mc.mfcc_origin.s_addr, s1, sizeof(s1)),
	  inet_fmt(mc.mfcc_mcastgrp.s_addr, s2, sizeof(s2)),
	  input, output);

    return TRUE;
}


/*
 * Get packet counters for particular interface
 * XXX: TODO: currently not used, but keep just in case we need it later.
 */
int k_get_vif_count(vifi_t vifi, struct vif_count *retval)
{
    struct sioc_vif_req vreq;

    memset(&vreq, 0, sizeof(vreq));
    vreq.vifi = vifi;
    if ((priv_enabled() ? priv_vif_cnt(&vreq) : kern_vif_cnt(udp_socket, &vreq)) < 0) {
	logit(LOG_WARNING, errno, "Failed reading kernel packet count (SIOCGETVIFCNT) on vif %d", vifi);

	retval->icount =
	    retval->ocount =
	    retval->ibytes =
	    retval->obytes = 0xffffffff;

	return 1;
    }

    retval->icount = vreq.icount;
    retval->ocount = vreq.ocount;
    retval->ibytes = vreq.ibytes;
    retval->obytes = vreq.obytes;

    return 0;
}


/*
 * Gets the number of packets, bytes, and number op packets arrived
 * on wrong if in the kernel for particular (S,G) entry.
 */
int k_get_sg_cnt(int socket, uint32_t source, uint32_t group, struct sg_count *retval)
{
    struct sioc_sg_req sgreq;

    memset(&sgreq, 0, sizeof(sgreq));
    sgreq.src.s_addr = source;
    sgreq.grp.s_addr = group;
    if ((priv_enabled() ? priv_sg_cnt(&sgreq) : kern_sg_cnt(socket, &sgreq)) < 0) {
	logit(LOG_WARNING, errno, "Failed reading kernel count (SIOCGETSGCNT) for (S,G) on (%s, %s)",
	      inet_fmt(source, s1, sizeof(s1)), inet_fmt(group, s2, sizeof(s2)));
	retval->pktcnt = retval->bytecnt = retval->wrong_if = ~0;

	return 1;
    }

    retval->pktcnt = sgreq.pktcnt;
    retval->bytecnt = sgreq.bytecnt;
    retval->wrong_if = sgreq.wrong_if;

    return 0;
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "cc-mode"
 * End:
 */
