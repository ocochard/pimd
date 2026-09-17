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
 *  $Id: route.c,v 1.39 2003/02/12 21:56:55 pavlin Exp $
 */

#include <limits.h>
#include "defs.h"

#define MRT_IS_LASTHOP(mrt) PIMD_VIFM_LASTHOP_ROUTER(mrt->leaves, mrt->oifs)
#define MRT_IS_RP(mrt)      mrt->incoming == PIMREG_VIF

/* Marian Stagarescu : 07/31/01:
 *
 * Administrative scoped multicast filtering im PIMD.  This allows an
 * interface to be configured as an administrative boundary for the
 * specified scoped address.  Packets belonging to the scoped address
 * will not be forwarded.
 *
 * Please note that in order to minimize the search for the matching
 * groups the implementation is limited to:
 *
 * Packets are stopped from being forwarded by installing a NULL
 * outgoing interface; the user space (pimd) is not up-call-ed any more
 * for these packets which are dropped by kernel (nil oif) except for
 * when we de-install the route are re-create it (timer 3 minute).  uses
 * the VIF acl that was installed via config scoped statements.
 *
 * this is not an all-purpose packet filtering mechanism.  we tried here
 * to achieve the filtering with minimal processing (inspect (g) when we
 * are about to install a route for it).
 */
/*
 * Contributed by Marian Stagarescu <marian@bile.cidera.com>
 * adapted from mrouted: check for scoped multicast addresses
 * install null oif if matched
 */
#define APPLY_SCOPE(g, mp) {			\
	vifi_t i;				\
	for (i = 0; i < numvifs; i++)		\
	    if (scoped_addr(i, g))              \
		PIMD_VIFM_CLRALL((mp)->oifs);	\
    }

/*
 * Global variables
 */

/* To account for header overhead, we apx 1 byte/s = 10 bits/s (bps)
 * Note, in the new spt_threshold setting the rate is in kbps as well! */
spt_threshold_t spt_threshold = {
    .mode     = SPT_THRESHOLD_DEFAULT_MODE,
    .bytes    = SPT_THRESHOLD_DEFAULT_RATE * SPT_THRESHOLD_DEFAULT_INTERVAL / 10 * 1000,
    .packets  = SPT_THRESHOLD_DEFAULT_PACKETS,
    .interval = SPT_THRESHOLD_DEFAULT_INTERVAL,
};

/*
 * Local variables
 */
uint16_t unicast_routing_interval = UCAST_ROUTING_CHECK_INTERVAL;
uint16_t unicast_routing_timer;   /* Used to check periodically for any
				   * change in the unicast routing. */
uint16_t pim_spt_threshold_timer; /* Used for periodic check of spt-threshold
				   * for the RP or the lasthop router. */

/*
 * TODO: XXX: the timers below are not used. Instead, the data rate timer is used.
 */
uint16_t kernel_cache_timer;      /* Used to timeout the kernel cache
				   * entries for idle sources */
uint16_t kernel_cache_interval;

/* to request and compare any route changes */
srcentry_t srcentry_save;
rpentry_t  rpentry_save;

/*
 * Forward declarations
 */
static void   process_cache_miss  (struct igmpmsg *igmpctl);
static void   process_wrong_iif   (struct igmpmsg *igmpctl);
static void   process_whole_pkt   (char *buf, size_t len);
static void   check_spt_threshold (mrtentry_t *mrt);

/*
 * Init some timers
 */
void init_route(void)
{
    SET_TIMER(unicast_routing_timer, unicast_routing_interval);
    SET_TIMER(pim_spt_threshold_timer, spt_threshold.interval);

    /* Initialize the srcentry and rpentry used to save the old routes
     * during unicast routing change discovery process. */
    srcentry_save.prev       = NULL;
    srcentry_save.next       = NULL;
    srcentry_save.address    = INADDR_ANY_N;
    srcentry_save.mrtlink    = NULL;
    srcentry_save.incoming   = NO_VIF;
    srcentry_save.upstream   = NULL;
    srcentry_save.metric     = ~0;
    srcentry_save.preference = ~0;
    srcentry_save.cand_rp    = NULL;

    rpentry_save.prev       = NULL;
    rpentry_save.next       = NULL;
    rpentry_save.address    = INADDR_ANY_N;
    rpentry_save.mrtlink    = NULL;
    rpentry_save.incoming   = NO_VIF;
    rpentry_save.upstream   = NULL;
    rpentry_save.metric     = ~0;
    rpentry_save.preference = ~0;
    rpentry_save.cand_rp    = NULL;
}

/* from mrouted. Contributed by Marian Stagarescu <marian@bile.cidera.com>*/
static int scoped_addr(vifi_t vifi, uint32_t addr)
{
    struct vif_acl *acl;

    for (acl = uvifs[vifi].uv_acl; acl; acl = acl->acl_next) {
	if ((addr & acl->acl_mask) == acl->acl_addr)
	    return 1;
    }

    return 0;
}

/* Return the iif for given address */
vifi_t get_iif(uint32_t address)
{
    struct rpfctl rpfc;

    k_req_incoming(address, &rpfc);
    if (rpfc.iif == NO_VIF || rpfc.rpfneighbor.s_addr == INADDR_ANY_N)
	return NO_VIF;

    return rpfc.iif;
}

/* Return the PIM neighbor toward a source */
/* If route not found or if a local source or if a directly connected source,
 * but is not PIM router, or if the first hop router is not a PIM router,
 * then return NULL.
 */
pim_nbr_entry_t *find_pim_nbr(uint32_t source)
{
    struct rpfctl rpfc;

    if (local_address(source) != NO_VIF)
	return NULL;

    k_req_incoming(source, &rpfc);
    if (rpfc.iif == NO_VIF || rpfc.rpfneighbor.s_addr == INADDR_ANY_N)
	return NULL;

    /* Figure out the nexthop neighbor by checking the reverse path */
    return find_pim_nbr_nexthop(rpfc.iif, rpfc.rpfneighbor.s_addr);
}

/*
 * NBR(I, addr) of RFC 7761 sec. 4.3.4: the neighbor on interface vifi that a
 * next hop out of the routing table stands for.  That is the neighbor whose
 * primary address it is, or failing that the one that has listed it in the
 * Address List option of its Hello -- a router's route to a source may name
 * any address its upstream has on the link, and a Join still goes to the
 * primary one, which is the address the upstream sources its PIM from.
 */
pim_nbr_entry_t *find_pim_nbr_nexthop(vifi_t vifi, uint32_t addr)
{
    pim_nbr_entry_t *nbr;
    uint16_t i;

    if (vifi >= numvifs)
	return NULL;

    nbr = find_pim_nbr_on_vif(vifi, addr);
    if (nbr)
	return nbr;

    for (nbr = uvifs[vifi].uv_pim_neighbors; nbr; nbr = nbr->next) {
	for (i = 0; i < nbr->nsecaddrs; i++) {
	    if (nbr->secaddrs[i] == addr)
		return nbr;
	}
    }

    return NULL;
}

/* Return the neighbor with that address on that interface, i.e. the one we
 * have had a PIM Hello from.  Unlike find_pim_nbr() above this asks nothing
 * of the unicast routing table: it answers whether an address is a neighbor,
 * not which neighbor leads to an address.
 */
/* May this router's PIM messages be acted on, on this interface?
 *
 * RFC 7761 sec. 6.2 asks for the option and, in its last sentence, requires
 * every option of this kind to default to accepting everything -- which is
 * also what keeps a half-written filter from black-holing a domain.  An
 * empty list is that default.
 *
 * Denying a router its Hello is enough on its own: since a Join/Prune, an
 * Assert and a unicast Bootstrap all require a Hello to have been seen
 * first, a router that never becomes a neighbor here can do none of them.
 * The checks in those parsers are what sec. 6.2 names, and they are what
 * keeps the answer right if that ever stops being true.
 */
int pim_nbr_accepted(vifi_t vifi, uint32_t addr)
{
    struct phaddr *pa;

    if (vifi >= numvifs)
	return FALSE;

    if (!uvifs[vifi].uv_nbr_acl)
	return TRUE;

    for (pa = uvifs[vifi].uv_nbr_acl; pa; pa = pa->pa_next) {
	if ((addr & pa->pa_subnetmask) == pa->pa_subnet)
	    return TRUE;
    }

    return FALSE;
}

pim_nbr_entry_t *find_pim_nbr_on_vif(vifi_t vifi, uint32_t addr)
{
    pim_nbr_entry_t *nbr;

    if (vifi >= numvifs)
	return NULL;

    for (nbr = uvifs[vifi].uv_pim_neighbors; nbr; nbr = nbr->next)
	if (nbr->address == addr)
	    return nbr;

    return NULL;
}


/* TODO: check again the exact setup if the source is local or directly
 * connected!!!
 */

/*
 * Set the iif, upstream router, preference and metric for the route
 * toward the source. Return TRUE is the route was found, othewise FALSE.
 * If type==PIM_IIF_SOURCE and if the source is directly connected
 * then the "upstream" is set to NULL. If srcentry==PIM_IIF_RP, then
 * "upstream" in case of directly connected "source" will be that "source"
 * (if it is also PIM router).,
 */
int set_incoming(srcentry_t *src, int type)
{
    struct rpfctl rpfc;
    uint32_t src_addr = src->address;
    uint32_t nbr_addr;
    struct uvif *vif;
    pim_nbr_entry_t *nbr;

    /* Preference will be 0 if directly connected */
    src->metric = 0;
    src->preference = 0;

    /* The source is a local address */
    src->incoming = local_address(src_addr);
    if (src->incoming != NO_VIF) {
	/* iif of (*,G) at RP has to be register_if */
	if (type == PIM_IIF_RP)
	    src->incoming = PIMREG_VIF;

	/* TODO: set the upstream to myself? */
	src->upstream = NULL;
	return TRUE;
    }

    src->incoming = find_vif_direct(src_addr);
    if (src->incoming != NO_VIF) {
	/* The source is directly connected. Check whether we are
	 * looking for real source or RP */
	if (type == PIM_IIF_SOURCE) {
	    src->upstream = NULL;
	    return TRUE;
	}

	/* PIM_IIF_RP */
	nbr_addr = src_addr;
    } else {
	/* TODO: probably need to check the case if the iif is disabled */
	/* Use the lastest resource: the kernel unicast routing table */
	k_req_incoming(src_addr, &rpfc);
	if (rpfc.iif == NO_VIF || rpfc.rpfneighbor.s_addr == INADDR_ANY_N) {
	    /* couldn't find a route */
	    if (!IN_LINK_LOCAL_RANGE(src_addr)) {
		IF_DEBUG(DEBUG_RPF)
		    logit(LOG_DEBUG, 0, "NO ROUTE found for %s", inet_fmt(src_addr, s1, sizeof(s1)));
	    }
	    return FALSE;
	}

	src->incoming = rpfc.iif;
	nbr_addr      = rpfc.rpfneighbor.s_addr;

	/* The metric preference and the metric of RFC 7761 sec. 4.6.3, for a
	 * source that is not directly connected.  The metric is the routing
	 * table's where the kernel gave us one, so that an Assert says how
	 * far this router really is from the source and the election lands
	 * on the router that is closest to it; `metric` in pimd.conf is what
	 * is left when it does not.  The preference stays configured: it is
	 * the routing protocol's administrative distance, and neither the
	 * routing socket nor netlink tells us which protocol the route came
	 * from in a way the other one also tells us.
	 */
	vif = &uvifs[src->incoming];
	src->preference = vif->uv_local_pref;
	if (rpfc.metric != RPF_METRIC_UNKNOWN)
	    src->metric = rpfc.metric;
	else
	    src->metric = vif->uv_local_metric;
    }

    /* The upstream router must be a (PIM router) neighbor, otherwise we
     * are in big trouble ;-) */
    vif = &uvifs[src->incoming];
    nbr = find_pim_nbr_nexthop(src->incoming, nbr_addr);
    if (nbr) {
	/* The upstream router is found in the list of neighbors.
	 * We are safe! */
	src->upstream = nbr;
	IF_DEBUG(DEBUG_RPF)
	    logit(LOG_DEBUG, 0, "For src %s, iif is %s, next hop router is %s",
		  inet_fmt(src_addr, s1, sizeof(s1)), vif->uv_name,
		  inet_fmt(nbr->address, s2, sizeof(s2)));

	return TRUE;
    }

    /* TODO: control the number of messages! */
    logit(LOG_INFO, 0, "For src %s, iif is %s, next hop router is %s: NOT A PIM ROUTER",
	  inet_fmt(src_addr, s1, sizeof(s1)), vif->uv_name,
	  inet_fmt(nbr_addr, s2, sizeof(s2)));
    src->upstream = NULL;

    return FALSE;
}


/*
 * TODO: XXX: currently `source` is not used. Will be used with IGMPv3 where
 * we have source-specific Join/Prune.
 */
void add_leaf(vifi_t vifi, uint32_t source, uint32_t group)
{
    mrtentry_t *mrt;
    mrtentry_t *srcs;
    uint8_t old_oifs[MAXVIFS];
    uint8_t new_oifs[MAXVIFS];
    uint8_t new_leaves[MAXVIFS];
    uint16_t flags;

    /* Don't create routing entries for the LAN scoped addresses */
    if (ntohl(group) <= INADDR_MAX_LOCAL_GROUP) { /* group <= 224.0.0.255? */
	IF_DEBUG(DEBUG_IGMP)
	    logit(LOG_DEBUG, 0, "Not creating routing entry for LAN scoped group %s",
		  inet_fmt(group, s1, sizeof(s1)));
	return;
    }

    /*
     * XXX: only if I am a DR, the IGMP Join should result in creating
     * a PIM MRT state.
     * XXX: Each router must know if it has local members, i.e., whether
     * it is a last-hop router as well. This info is needed so it will
     * know whether is allowed to initiate a SPT switch by sending
     * a PIM (S,G) Join to the high datarate source.
     * However, if a non-DR last-hop router has not received
     * a PIM Join, it should not create a PIM state, otherwise later
     * this state may incorrectly trigger PIM joins.
     * There is a design flow in pimd, so without making major changes
     * the best we can do is that the non-DR last-hop router will
     * record the local members only after it receives PIM Join from the DR
     * (i.e.  after the second or third IGMP Join by the local member).
     * The downside is that a last-hop router may delay the initiation
     * of the SPT switch. Sigh...
     */
     /* Initialize flags */
    flags = MRTF_RP | MRTF_WC;
    if (IN_PIM_SSM_RANGE(group)) {
	mrt = find_route(source, group, MRTF_SG, CREATE);
	flags = MRTF_SG;
    }
    else if (uvifs[vifi].uv_flags & VIFF_DR)
	mrt = find_route(INADDR_ANY_N, group, MRTF_WC, CREATE);
    else
	mrt = find_route(INADDR_ANY_N, group, MRTF_WC, DONT_CREATE);

    if (!mrt)
	return;

    IF_DEBUG(DEBUG_MRT)
	logit(LOG_DEBUG, 0, "Adding oif %s for group %s", uvifs[vifi].uv_name,
	      inet_fmt(group, s1, sizeof(s1)));

    if (PIMD_VIFM_ISSET(vifi, mrt->leaves))
	return;     /* Already a leaf */

    calc_oifs(mrt, old_oifs);
    PIMD_VIFM_COPY(mrt->leaves, new_leaves);
    PIMD_VIFM_SET(vifi, new_leaves);    /* Add the leaf */
    change_interfaces(mrt,
		      mrt->incoming,
		      mrt->joined_oifs,
		      mrt->pruned_oifs,
		      new_leaves,
		      mrt->asserted_oifs, 0);
    calc_oifs(mrt, new_oifs);

    /* Only if I am the DR for that subnet, eventually initiate a Join */
    if (!(uvifs[vifi].uv_flags & VIFF_DR))
	return;

    if ((mrt->flags & MRTF_NEW) || (PIMD_VIFM_ISEMPTY(old_oifs) && (!PIMD_VIFM_ISEMPTY(new_oifs)))) {
	/* A new created entry or the oifs have changed
	 * from NULL to non-NULL. */
	mrt->flags &= ~MRTF_NEW;
	if (mrt->upstream) {
	    send_pim_join(mrt->upstream, mrt, flags, PIM_JOIN_PRUNE_HOLDTIME);
	    jp_timer_set(mrt, PIM_JOIN_PRUNE_PERIOD * 1000);
	}
	else  {
	    jp_timer_fire(mrt); /* Timeout the Join/Prune timer */
	    logit(LOG_DEBUG, 0, "Upstream router not available.");
	}
    }

    /* Check all (S,G) entries and set the inherited "leaf" flag.
     * TODO: XXX: This won't work for IGMPv3, because there we don't know
     * whether the (S,G) leaf oif was inherited from the (*,G) entry or
     * was created by source specific IGMP join.
     */
    for (srcs = mrt->group->mrtlink; srcs; srcs = srcs->grpnext) {
	PIMD_VIFM_COPY(srcs->leaves, new_leaves);
	PIMD_VIFM_SET(vifi, new_leaves);
	change_interfaces(srcs,
			  srcs->incoming,
			  srcs->joined_oifs,
			  srcs->pruned_oifs,
			  new_leaves,
			  srcs->asserted_oifs, 0);
	/* In the case of SG entry we can create MFC directy without waiting for cache miss. */
	if (flags & MRTF_SG) {
	    add_kernel_cache(srcs, srcs->source->address, srcs->group->group, MFC_MOVE_FORCE);
	    k_chg_mfc(igmp_socket, srcs->source->address, srcs->group->group,
		      srcs->incoming, srcs->oifs, srcs->source->address);
	}
    }
}


/*
 * TODO: XXX: currently `source` is not used. To be used with IGMPv3 where
 * we have source-specific joins/prunes.
 */
void delete_leaf(vifi_t vifi, uint32_t source, uint32_t group)
{
    mrtentry_t *mrt;
    mrtentry_t *srcs;
    uint8_t new_oifs[MAXVIFS];
    uint8_t old_oifs[MAXVIFS];
    uint8_t new_leaves[MAXVIFS];

    if (IN_PIM_SSM_RANGE(group))
	mrt = find_route(source, group, MRTF_SG, DONT_CREATE);
    else
	mrt = find_route(INADDR_ANY_N, group, MRTF_WC, DONT_CREATE);

    if (!mrt)
	return;

    if (!PIMD_VIFM_ISSET(vifi, mrt->leaves))
	return;      /* This interface wasn't leaf */

    IF_DEBUG(DEBUG_MRT)
	logit(LOG_DEBUG, 0, "Deleting vif %d for group %s", vifi, inet_fmt(group, s1, sizeof(s1)));

    calc_oifs(mrt, old_oifs);

    /* For SSM, source must match */
    if (!IN_PIM_SSM_RANGE(group) || (mrt->source->address==source)) {
	PIMD_VIFM_COPY(mrt->leaves, new_leaves);
	PIMD_VIFM_CLR(vifi, new_leaves);
	change_interfaces(mrt,
			  mrt->incoming,
			  mrt->joined_oifs,
			  mrt->pruned_oifs,
			  new_leaves,
			  mrt->asserted_oifs, 0);
    }
    calc_oifs(mrt, new_oifs);

    if ((!PIMD_VIFM_ISEMPTY(old_oifs)) && PIMD_VIFM_ISEMPTY(new_oifs)) {
	/* The result oifs have changed from non-NULL to NULL */
	jp_timer_fire(mrt); /* Timeout the Join/Prune timer */

	/* TODO: explicitly call the function below?
	send_pim_join_prune(mrt->upstream->vifi,
			    mrt->upstream,
			    PIM_JOIN_PRUNE_HOLDTIME);
	*/
    }

    /* Check all (S,G) entries and clear the inherited "leaf" flag.
     * TODO: XXX: This won't work for IGMPv3, because there we don't know
     * whether the (S,G) leaf oif was inherited from the (*,G) entry or
     * was created by source specific IGMP join.
     */
    for (srcs = mrt->group->mrtlink; srcs; srcs = srcs->grpnext) {
	PIMD_VIFM_COPY(srcs->leaves, new_leaves);
	PIMD_VIFM_CLR(vifi, new_leaves);
	change_interfaces(srcs,
			  srcs->incoming,
			  srcs->joined_oifs,
			  srcs->pruned_oifs,
			  new_leaves,
			  srcs->asserted_oifs, 0);
    }
}


/*
 * "Prune-Pending Timer Expires" of RFC 7761 sec. 4.5.1 and sec. 4.5.2: the
 * downstream state machine goes to NoInfo and the router owes the LAN a
 * PruneEcho.  The interface is one pimd has just dropped from the outgoing
 * list, and the bitmap says whether a Prune put it on its way out or the
 * Expiry Timer simply ran its full course, which owes nothing.
 */
static void expire_prune_pending(mrtentry_t *mrt, vifi_t vifi)
{
    if (!PIMD_VIFM_ISSET(vifi, mrt->prune_pending_oifs))
	return;

    PIMD_VIFM_CLR(vifi, mrt->prune_pending_oifs);
    send_prune_echo(mrt, vifi);
}

/*
 * The Prune-Pending Timers of an entry that have run out by @now, see
 * prune_pending() in src/pim_proto.c.  The interface leaves the joined set
 * the way an expired Expiry Timer takes it out in age_routes(), and @next is
 * lowered to any timer still running.  Returns TRUE when the caller owes a
 * change_interfaces().
 */
static int expire_prune_pending_timers(mrtentry_t *mrt, uint64_t now, uint64_t *next)
{
    int change = FALSE;
    vifi_t vifi;

    if (PIMD_VIFM_ISEMPTY(mrt->prune_pending_oifs))
	return FALSE;

    for (vifi = 0; vifi < numvifs; vifi++) {
	if (!PIMD_VIFM_ISSET(vifi, mrt->prune_pending_oifs))
	    continue;

	/* Pruned where nothing was joined, or taken out another way since */
	if (!PIMD_VIFM_ISSET(vifi, mrt->joined_oifs)) {
	    PIMD_VIFM_CLR(vifi, mrt->prune_pending_oifs);
	    continue;
	}

	if (mrt->pp_expires[vifi] > now) {
	    if (next && (!*next || mrt->pp_expires[vifi] < *next))
		*next = mrt->pp_expires[vifi];
	    continue;
	}

	PIMD_VIFM_CLR(vifi, mrt->joined_oifs);
	if (!(mrt->flags & MRTF_WC))
	    PIMD_VIFM_CLR(vifi, mrt->sg_joined_oifs);
	RESET_TIMER(mrt->vif_timers[vifi]);
	expire_prune_pending(mrt, vifi);
	change = TRUE;
    }

    return change;
}


/*
 * The two timers of the downstream (S,G,rpt) machine, RFC 7761 sec. 4.5.3, by
 * @now: the Prune-Pending Timer takes an interface on to Prune, the Expiry
 * Timer takes it back to NoInfo.  @next is lowered to a Prune-Pending Timer
 * still running; the Expiry Timer is seconds long and the tick ages it.
 * Returns TRUE when the caller owes a change_interfaces().
 */
static int expire_rpt_timers(mrtentry_t *mrt, uint64_t now, uint64_t *next)
{
    int change = FALSE;
    vifi_t vifi;

    if (PIMD_VIFM_ISEMPTY(mrt->rpt_pruned_oifs) && PIMD_VIFM_ISEMPTY(mrt->rpt_pp_oifs))
	return FALSE;

    for (vifi = 0; vifi < numvifs; vifi++) {
	if (PIMD_VIFM_ISSET(vifi, mrt->rpt_pp_oifs)) {
	    if (mrt->rpt_pp_expires[vifi] > now) {
		if (next && (!*next || mrt->rpt_pp_expires[vifi] < *next))
		    *next = mrt->rpt_pp_expires[vifi];
		continue;
	    }

	    PIMD_VIFM_CLR(vifi, mrt->rpt_pp_oifs);
	    PIMD_VIFM_SET(vifi, mrt->rpt_pruned_oifs);
	    change = TRUE;
	}

	if (!PIMD_VIFM_ISSET(vifi, mrt->rpt_pruned_oifs))
	    continue;

	/* Zero is a HoldTime of 0xffff, held until a Join cancels it */
	if (mrt->rpt_expires[vifi] && mrt->rpt_expires[vifi] <= now) {
	    PIMD_VIFM_CLR(vifi, mrt->rpt_pruned_oifs);
	    change = TRUE;
	}
    }

    return change;
}

/*
 * RFC 7761 sec. 4.5.5:
 *
 *   bool JoinDesired(S,G) {
 *       return( immediate_olist(S,G) != NULL
 *               OR ( KeepaliveTimer(S,G) is running
 *                    AND inherited_olist(S,G) != NULL ) )
 *   }
 *
 * Two questions, and pimd used to answer both with calc_oifs(), which is
 * inherited_olist(S,G) alone: one any-source receiver behind a last hop
 * router was then enough to make it true, and sec. 4.2.2 set the SPTbit of a
 * router that is forwarding off the shared tree.
 *
 * Sec. 4.1.5 builds immediate_olist(S,G) out of source-specific state only,
 * joins(S,G) and pim_include(S,G), and `joined_oifs` and `leaves` are neither
 * as they stand: VOIF_COPY() seeds a new (S,G) with the (*,G)'s copy of both
 * (src/mrt.h), and add_leaf() and delete_leaf() keep pushing (*,G) leaves
 * into every (S,G) of the group.  `sg_joined_oifs` is the half of
 * `joined_oifs` a Join(S,G) really put there, which is joins(S,G).  The
 * leaves have no such half outside the SSM range: add_leaf() ignores the
 * source of an IGMPv3 report for an ASM group, so an interface the (*,G)
 * holds too carries an any-source receiver and nothing of ours, and an SSM
 * group has no (*,G) to subtract.
 *
 * The second question is which entries ever have a Keepalive Timer at all.
 * pimd has no timer of that name -- `entry_timer` is refreshed by
 * control-plane events, deviation M7 in doc/rfc7761-compliance.md -- but the
 * events that start one are few: sec. 4.2 starts it for a directly connected
 * source, and sec. 4.2.1 has CheckSwitchToSpt(S,G) start it when the switch
 * policy says to switch, which here is switch_shortest_path() and MRTF_KAT.
 * An entry that came by its (S,G) state any other way -- an Assert it lost, a
 * Prune(S,G,rpt) it was told about -- has none, and answers FALSE however much
 * the (*,G) gives it to forward.  `spt-threshold infinity` reaches the SPTbit
 * through this, and only this: it returns false in CheckSwitchToSpt(S,G), no
 * Keepalive Timer is started, and the chain sec. 4.2.1 describes stays down.
 */
int join_desired(mrtentry_t *mrt)
{
    uint8_t oifs[MAXVIFS];
    mrtentry_t *grp;
    vifi_t vifi;

    grp = mrt->group->grp_route;

    /* immediate_olist(S,G) = joins(S,G) (+) pim_include(S,G) (-) lost_assert(S,G) */
    for (vifi = 0; vifi < numvifs; vifi++) {
	if (PIMD_VIFM_ISSET(vifi, mrt->pruned_oifs))
	    continue;

	if (PIMD_VIFM_ISSET(vifi, mrt->asserted_oifs) && lost_assert(mrt, vifi))
	    continue;

	/* joins(S,G) */
	if (PIMD_VIFM_ISSET(vifi, mrt->sg_joined_oifs))
	    return TRUE;

	/* pim_include(S,G), and only where we are the DR, which is the rule
	 * merge_local_members() applies */
	if (PIMD_VIFM_ISSET(vifi, mrt->leaves) &&
	    (uvifs[vifi].uv_flags & VIFF_DR) &&
	    !(grp && PIMD_VIFM_ISSET(vifi, grp->leaves)))
	    return TRUE;
    }

    /* KeepaliveTimer(S,G) is running: a directly connected source, sec. 4.2,
     * or one CheckSwitchToSpt(S,G) started for us, sec. 4.2.1 */
    if (!(mrt->flags & MRTF_KAT) && mrt->source->upstream)
	return FALSE;

    /* AND inherited_olist(S,G) != NULL */
    calc_oifs(mrt, oifs);

    return !PIMD_VIFM_ISEMPTY(oifs);
}


/*
 * RFC 7761 sec. 4.2.2, Update_SPTbit(S,G,iif), called as the spec calls it,
 * when a packet arrives:
 *
 *   if ( iif == RPF_interface(S) AND JoinDesired(S,G) == TRUE
 *         AND ( DirectlyConnected(S) == TRUE
 *               OR RPF_interface(S) != RPF_interface(RP(G))
 *               OR inherited_olist(S,G,rpt) == NULL
 *               OR ( ( RPF'(S,G) == RPF'(*,G) ) AND ( RPF'(S,G) != NULL ) )
 *               OR ( I_Am_Assert_Loser(S,G,iif) ) ) )
 *      Set SPTbit(S,G) to TRUE
 *
 * The fourth alternative used to be written the other way round here, as
 * "the two upstream routers differ", which is the one case the spec singles
 * out to *wait* for an Assert(S,G) rather than claim the tree: raising the
 * bit there is what sec. 4.2.2 calls the temporary black hole it exists to
 * prevent.  The assert that resolves it is now the fifth alternative, which
 * pimd can answer since it keeps the assert winner for the incoming
 * interface.
 *
 * The third alternative asks whether anything is still being forwarded off
 * the shared tree for this source.  sec. 4.1.3 spells the list out as
 *
 *   inherited_olist(S,G,rpt) = ( joins(*,G) (-) prunes(S,G,rpt) )
 *                          (+) ( pim_include(*,G) (-) pim_exclude(S,G) )
 *                          (-) ( lost_assert(*,G) (+) lost_assert(S,G,rpt) )
 *
 * which is the (*,G) olist calc_oifs() already keeps, less three terms of
 * (S,G,rpt) state this does not read.  All three subtract, so an empty
 * (*,G) olist is an empty inherited_olist(S,G,rpt) whatever they would have
 * removed: answering the alternative from it can only set the bit where the
 * spec sets it too, and a non-empty one is left alone as before.
 *
 * Asking instead whether a (*,G) exists at all, which is what this did,
 * is not the conservative half of that: it is false exactly when the
 * alternative matters most.  A last hop router that has lost the assert on
 * its own RPF interface holds a (*,G) whose olist is empty, and the two
 * upstream routers then differ -- the (*,G) follows the assert winner while
 * the (S,G) keeps the MRIB next hop -- so the fourth alternative is false
 * as well, and the paragraph after the pseudocode in sec. 4.2.2 says what
 * the third is there for: "item (3) above is needed because there may not
 * be any (*,G) state to trigger an Assert(S,G) to happen".  With all five
 * false the bit is never set, not merely set late, and the router asserts
 * as an RPT forwarder for the life of the entry -- CouldAssert(S,G,I) is
 * false without the bit, so sec. 4.6.1 compares the RPT bit and stops.  Two
 * routers on one LAN then hold Winner on different entries and both keep
 * forwarding; shared-lan-spt of test/freebsd-lab.sh reproduces it under
 * "-j 4 run all".
 */
static void update_sptbit(mrtentry_t *mrt, vifi_t iif)
{
    int directly_connected, different_iif, no_rpt_olist, same_rpf_nbr, assert_loser;
    rpentry_t *rp = NULL;
    mrtentry_t *mwc;

    if (!(mrt->flags & MRTF_SG) || (mrt->flags & MRTF_SPT))
	return;

    if (!mrt->source || iif != mrt->source->incoming)
	return;			/* Not RPF_interface(S) */

    if (!join_desired(mrt))
	return;

    if (mrt->group->active_rp_grp)
	rp = mrt->group->active_rp_grp->rp->rpentry;
    mwc = mrt->group->grp_route;

    directly_connected = !mrt->source->upstream;
    different_iif      = !rp || mrt->source->incoming != rp->incoming;
    no_rpt_olist       = !mwc || PIMD_VIFM_ISEMPTY(mwc->oifs);
    same_rpf_nbr       = mwc && mrt->upstream && mrt->upstream == mwc->upstream;
    assert_loser       = assert_lost_on(mrt, iif);

    if (directly_connected || different_iif || no_rpt_olist || same_rpf_nbr || assert_loser) {
	mrt->flags |= MRTF_SPT;
	mrt->flags &= ~MRTF_RP;
    }
}


/*
 * The other half of that trigger.  Sec. 4.2.2 runs the check above on receipt
 * of every data packet from S, and pimd forwards in the kernel, so the only
 * packets it ever sees are the ones the kernel hands up.  Once an MFC entry is
 * installed with the incoming interface the (S,G) already wants there are
 * none: no further cache miss, and no wrong-iif upcall either, since those
 * carry an iif that is not RPF_interface(S) and update_sptbit() rejects them
 * on its second line.  Whatever was true at that first upcall is what the
 * entry keeps, and the window is narrow: an (S,G) that acquires an outgoing
 * interface a moment after its first packet, or one that switch_shortest_path()
 * creates under a (*,G) and inherits the kernel cache of, never sets the bit at
 * all.  It then asserts as an RPT forwarder for as long as it lives, since
 * CouldAssert(S,G,I) is false without the bit and sec. 4.6.1 compares the bit
 * before either metric.
 *
 * So run the check once per age_routes() pass as well.  "On receipt of data" is
 * the part that has to be answered without the packet: the kernel counts what
 * it forwards, and it matches packets on the incoming interface of the entry
 * holding the MFC, so a count that moved between two passes on an entry whose
 * iif is RPF_interface(S) is data from S received on RPF_interface(S).  Only an
 * entry with a kernel cache of its own is asked.  One still forwarding through
 * the (*,G) it was created under is matched on the shared tree's interface, and
 * there a packet from S on RPF_interface(S) is a wrong-iif upcall that
 * process_wrong_iif() already answers.
 */
static void check_sptbit(mrtentry_t *mrt)
{
    struct sg_count count;
    kernel_cache_t *kc;

    if (!(mrt->flags & MRTF_SG) || (mrt->flags & MRTF_SPT))
	return;

    if (!mrt->source || mrt->incoming != mrt->source->incoming)
	return;			/* Not RPF_interface(S) */

    /* JoinDesired(S,G) is false, so update_sptbit() would return without
     * setting anything.  Answered here so the kernel call below is only made
     * for an entry that can use the answer. */
    if (!join_desired(mrt))
	return;

    kc = mrt->kernel_cache;
    if (!(mrt->flags & MRTF_KERNEL_CACHE) || !kc)
	return;

    if (k_get_sg_cnt(udp_socket, kc->source, kc->group, &count))
	return;

    /* The kernel counter runs from the moment the MFC entry was installed, and
     * an entry whose incoming interface changed since kept it, so the value on
     * its own says nothing about the interface the packets came in on.  The
     * difference between two passes does, which is why the first pass only
     * takes a baseline.  It is kept on the routing entry rather than in the
     * kernel cache entry because check_spt_threshold() uses that one as its own
     * previous value, over its own much longer period.
     */
    if (!mrt->spt_pktcnt || mrt->spt_pktcnt == count.pktcnt) {
	mrt->spt_pktcnt = count.pktcnt;
	return;
    }

    mrt->spt_pktcnt = count.pktcnt;
    update_sptbit(mrt, mrt->incoming);

    if (mrt->flags & MRTF_SPT) {
	IF_DEBUG(DEBUG_MRT)
	    logit(LOG_DEBUG, 0, "SPT bit set for (%s,%s), data from S arriving on %s",
		  inet_fmt(mrt->source->address, s1, sizeof(s1)),
		  inet_fmt(mrt->group->group, s2, sizeof(s2)),
		  uvifs[mrt->incoming].uv_name);

	/* What the entry owes its upstream routers changes with the bit:
	 * join_or_prune() prunes the source off the shared tree once it is on
	 * the shortest path one.  No reason to sit on that until the periodic
	 * timer comes round. */
	jp_timer_fire(mrt);
    }
}



/*
 * Half of a change of upstream router: RFC 7761 sec. 4.5.4 and 4.5.5 pair the
 * Join to the new RPF' with a Prune to the old one, so that the router we no
 * longer take this group from stops forwarding it now rather than when its own
 * downstream state expires.  Only while it is still a neighbor, though: the
 * paths that tear a neighbor or a VIF down reach change_interfaces() too, and
 * there the old upstream is a router that has already gone.
 */
static void prune_old_upstream(mrtentry_t *mrt, pim_nbr_entry_t *old, uint16_t flags)
{
    if (!old || old == mrt->upstream)
	return;

    if (!find_pim_nbr_on_vif(old->vifi, old->address))
	return;

    send_pim_prune(old, mrt, flags, PIM_JOIN_PRUNE_HOLDTIME);
}

/*
 * Local members on a subnet are ours to forward to only while we are the DR
 * there, so a change of that role changes what every entry with a member on
 * that interface forwards.  Nothing else recomputes them: `leaves` itself is
 * unchanged, only what it contributes to the outgoing interfaces.
 */
void recalc_local_members(vifi_t vifi)
{
    grpentry_t *grp;
    mrtentry_t *mrt;

    for (grp = grplist; grp; grp = grp->next) {
	mrt = grp->grp_route;
	if (mrt && PIMD_VIFM_ISSET(vifi, mrt->leaves))
	    change_interfaces(mrt, mrt->incoming, mrt->joined_oifs,
			      mrt->pruned_oifs, mrt->leaves,
			      mrt->asserted_oifs, MFC_UPDATE_FORCE);

	for (mrt = grp->mrtlink; mrt; mrt = mrt->grpnext) {
	    if (PIMD_VIFM_ISSET(vifi, mrt->leaves))
		change_interfaces(mrt, mrt->incoming, mrt->joined_oifs,
				  mrt->pruned_oifs, mrt->leaves,
				  mrt->asserted_oifs, MFC_UPDATE_FORCE);
	}
    }
}

/*
 * Add the interfaces with local members to the outgoing interfaces, which
 * RFC 7761 sec. 4.1.5 does only where we are the DR:
 *
 *   pim_include(*,G) = { all interfaces I such that:
 *      ( ( I_am_DR( I ) AND lost_assert(*,G,I) == FALSE )
 *        OR AssertWinner(*,G,I) == me ) AND local_receiver_include(*,G,I) }
 *
 * The lost_assert() half is the `asserted_oifs` that calc_oifs() subtracts
 * just after this.  The AssertWinner() half needs per-interface winner state
 * pimd does not keep, and its absence costs nothing here: an interface a
 * non-DR forwards on for a reason of its own is in `joined_oifs`, and one it
 * forwards on for no other reason than a local member is one it no longer
 * forwards on at all, so it cannot be in an assert to begin with.
 */
static void merge_local_members(uint8_t *oifs, uint8_t *leaves)
{
    vifi_t vifi;

    for (vifi = 0; vifi < numvifs; vifi++) {
	if (!PIMD_VIFM_ISSET(vifi, leaves))
	    continue;

	if (!(uvifs[vifi].uv_flags & VIFF_DR))
	    continue;

	PIMD_VIFM_SET(vifi, oifs);
    }
}

void calc_oifs(mrtentry_t *mrt, uint8_t *oifs_ptr)
{
    uint8_t oifs[MAXVIFS];
    mrtentry_t *grp;
    vifi_t vifi;

    /*
     * oifs =
     * (((copied_outgoing + my_join) - my_prune) + my_leaves)
     *              - my_asserted_oifs - incoming_interface,
     * i.e. `leaves` have higher priority than `prunes`, but lower priority
     * than `asserted`. The incoming interface is always deleted from the oifs
     *
     * The two halves are the two RFC 7761 sec. 4.1.5 builds, and they do not
     * lose the same interfaces to an assert:
     *
     *   inherited_olist(S,G,rpt) = ( joins(*,G) (-) prunes(S,G,rpt) )
     *       (+) ( pim_include(*,G) (-) pim_exclude(S,G) )
     *       (-) ( lost_assert(*,G) (+) lost_assert(S,G,rpt) )
     *   inherited_olist(S,G) = inherited_olist(S,G,rpt)
     *       (+) joins(S,G) (+) pim_include(S,G) (-) lost_assert(S,G)
     *
     * prunes(S,G,rpt) is this entry's `rpt_pruned_oifs`, the Prune state of
     * the downstream (S,G,rpt) machine in src/pim_proto.c, and it is taken
     * off joins(*,G) alone: not off pim_include(*,G), and not off joins(S,G),
     * which is where pimd used to put it by marking the interface in
     * `pruned_oifs`, taking a Join(S,G) some other router still wanted with
     * it.  lost_assert(*,G) is the (*,G) entry's own `asserted_oifs`,
     * subtracted from the inherited half alone.  The other two are this entry's, and
     * lost_assert_rpt() (src/pim_proto.c) is which of them applies: until
     * SPTbit(S,G) is set sec. 4.2 forwards off inherited_olist(S,G,rpt) and
     * the answer is lost_assert(S,G,rpt), plain assert state, taking the
     * interface away wherever it came from.  Once it is set the olist is
     * inherited_olist(S,G) and the answer is lost_assert(S,G), which also
     * asks whether the winner would still beat us now that we assert from
     * the shortest path tree, sec. 4.6.5.
     *
     * This is the forwarding olist and only that.  join_desired()
     * (src/route.c) builds the state-maintenance ones of sec. 4.1.5, which
     * subtract lost_assert(S,G) whatever the bit says; the two answers part
     * company exactly where sec. 4.6.5's Note says they must.
     */

    if (!mrt) {
	PIMD_VIFM_CLRALL(oifs_ptr);
	return;
    }

    PIMD_VIFM_CLRALL(oifs);
    if (mrt->flags & MRTF_SG) {
	/* (S,G) entry. Merge with the oifs from (*,G) */
	grp = mrt->group->grp_route;
	if (grp) {
	    PIMD_VIFM_MERGE(oifs, grp->joined_oifs, oifs);
	    PIMD_VIFM_CLR_MASK(oifs, grp->pruned_oifs);
	    /* prunes(S,G,rpt) */
	    PIMD_VIFM_CLR_MASK(oifs, mrt->rpt_pruned_oifs);
	    merge_local_members(oifs, grp->leaves);
	    /* lost_assert(*,G) */
	    PIMD_VIFM_CLR_MASK(oifs, grp->asserted_oifs);
	}
    }

    /* Calculate my own stuff.  An (S,G) entry's joined_oifs holds, beside
     * joins(S,G), the copy of joins(*,G) VOIF_COPY() seeded it with, and
     * prunes(S,G,rpt) take the source off that copy as they do off the
     * (*,G) itself -- but not off an interface a Join(S,G) holds. */
    for (vifi = 0; vifi < numvifs; vifi++) {
	if (!PIMD_VIFM_ISSET(vifi, mrt->joined_oifs))
	    continue;

	if ((mrt->flags & MRTF_SG) && PIMD_VIFM_ISSET(vifi, mrt->rpt_pruned_oifs) &&
	    !PIMD_VIFM_ISSET(vifi, mrt->sg_joined_oifs))
	    continue;

	PIMD_VIFM_SET(vifi, oifs);
    }
    PIMD_VIFM_CLR_MASK(oifs, mrt->pruned_oifs);
    merge_local_members(oifs, mrt->leaves);

    /* lost_assert(S,G) or lost_assert(S,G,rpt) here, and lost_assert(*,G)
     * where this entry is the (*,G) itself */
    for (vifi = 0; vifi < numvifs; vifi++) {
	if (PIMD_VIFM_ISSET(vifi, mrt->asserted_oifs) && lost_assert_rpt(mrt, vifi))
	    PIMD_VIFM_CLR(vifi, oifs);
    }

    PIMD_VIFM_COPY(oifs, oifs_ptr);
}

/*
 * inherited_olist(S,G,rpt) of RFC 7761 sec. 4.1.5, which PruneDesired(S,G,rpt)
 * reads.  Not what calc_oifs() forwards off: that one subtracts assert state
 * once over both halves, and keeps its own reasons for it.
 *
 *   inherited_olist(S,G,rpt) = ( joins(*,G) (-) prunes(S,G,rpt) )
 *       (+) ( pim_include(*,G) (-) pim_exclude(S,G) )
 *       (-) ( lost_assert(*,G) (+) lost_assert(S,G,rpt) )
 *
 * pim_exclude(S,G) is IGMPv3 EXCLUDE state pimd does not keep for an ASM
 * group, and subtracting nothing for it can only leave the list non-empty
 * where the spec's is empty, which is the side PruneDesired(S,G,rpt) wants to
 * err on: a Prune not sent costs traffic nobody asked for, one sent wrongly
 * costs traffic somebody did.
 */
static void calc_rpt_oifs(mrtentry_t *mrt, uint8_t *oifs)
{
    mrtentry_t *grp = mrt->group->grp_route;
    vifi_t vifi;

    PIMD_VIFM_CLRALL(oifs);
    if (!grp)
	return;

    PIMD_VIFM_MERGE(oifs, grp->joined_oifs, oifs);
    PIMD_VIFM_CLR_MASK(oifs, grp->pruned_oifs);
    PIMD_VIFM_CLR_MASK(oifs, mrt->rpt_pruned_oifs);
    merge_local_members(oifs, grp->leaves);
    PIMD_VIFM_CLR_MASK(oifs, grp->asserted_oifs);

    /* lost_assert(S,G,rpt,I): never on RPF_interface(RP(G)), nor on
     * RPF_interface(S) once SPTbit(S,G) is set */
    for (vifi = 0; vifi < numvifs; vifi++) {
	if (vifi == grp->incoming)
	    continue;
	if (vifi == mrt->source->incoming && (mrt->flags & MRTF_SPT))
	    continue;
	if (assert_lost_on(mrt, vifi))
	    PIMD_VIFM_CLR(vifi, oifs);
    }
}

/*
 * PruneDesired(S,G,rpt) of RFC 7761 sec. 4.5.7:
 *
 *   bool PruneDesired(S,G,rpt) {
 *        return ( RPTJoinDesired(G) AND
 *                 ( inherited_olist(S,G,rpt) == NULL
 *                   OR (SPTbit(S,G)==TRUE
 *                       AND (RPF'(*,G) != RPF'(S,G)) )))
 *   }
 *
 * RPTJoinDesired(G) is JoinDesired(*,G), which is the (*,G) olist being
 * non-empty.
 */
int prune_desired_rpt(mrtentry_t *mrt)
{
    uint8_t oifs[MAXVIFS];
    mrtentry_t *mwc;

    if (!mrt || !(mrt->flags & MRTF_SG) || !mrt->source)
	return FALSE;

    mwc = mrt->group->grp_route;
    if (!mwc || PIMD_VIFM_ISEMPTY(mwc->oifs))
	return FALSE;

    if ((mrt->flags & MRTF_SPT) && mrt->upstream != mwc->upstream)
	return TRUE;

    calc_rpt_oifs(mrt, oifs);

    return PIMD_VIFM_ISEMPTY(oifs);
}

/*
 * Set the iif, join/prune/leaves/asserted interfaces. Calculate and
 * set the oifs.
 * Return 1 if oifs change from NULL to not-NULL.
 * Return -1 if oifs change from non-NULL to NULL
 *  else return 0
 * If the iif change or if the oifs change from NULL to non-NULL
 * or vice-versa, then schedule that mrtentry join/prune timer to
 * timeout immediately.
 */
int change_interfaces(mrtentry_t *mrt,
		      vifi_t new_iif,
		      uint8_t *new_joined_oifs_,
		      uint8_t *new_pruned_oifs,
		      uint8_t *new_leaves_,
		      uint8_t *new_asserted_oifs,
		      uint16_t flags)
{
    uint8_t new_joined_oifs[MAXVIFS];  /* The oifs for that particular mrtentry */
    uint8_t old_joined_oifs[MAXVIFS] __attribute__ ((unused));
    uint8_t old_pruned_oifs[MAXVIFS] __attribute__ ((unused));
    uint8_t old_leaves[MAXVIFS] __attribute__ ((unused));
    uint8_t new_leaves[MAXVIFS];
    uint8_t old_asserted_oifs[MAXVIFS] __attribute__ ((unused));
    uint8_t new_real_oifs[MAXVIFS];    /* The result oifs */
    uint8_t old_real_oifs[MAXVIFS];
    vifi_t      old_iif;
    vifi_t      vifi;
    rpentry_t   *rp;
    cand_rp_t   *cand_rp;
    kernel_cache_t *kc;
    rp_grp_entry_t *rp_grp;
    grpentry_t     *grp;
    mrtentry_t     *srcs;
    mrtentry_t     *mwc;
    mrtentry_t     *mrp;
    int delete_mrt_flag;
    int result;
    int fire_timer_flag;

    if (!mrt)
	return 0;

    /* When iif changes, discover new upstream pim nbr */
    if (new_iif != mrt->incoming && mrt->source && mrt->source->address) {
	pim_nbr_entry_t *old_upstream = mrt->upstream;

	mrt->upstream = find_pim_nbr(mrt->source->address);
	prune_old_upstream(mrt, old_upstream,
			   (mrt->flags & MRTF_WC) ? (MRTF_RP | MRTF_WC) : MRTF_SG);
    }

    PIMD_VIFM_COPY(new_joined_oifs_, new_joined_oifs);
    PIMD_VIFM_COPY(new_leaves_, new_leaves);

    old_iif = mrt->incoming;
    PIMD_VIFM_COPY(mrt->joined_oifs, old_joined_oifs);
    PIMD_VIFM_COPY(mrt->leaves, old_leaves);
    PIMD_VIFM_COPY(mrt->pruned_oifs, old_pruned_oifs);
    PIMD_VIFM_COPY(mrt->asserted_oifs, old_asserted_oifs);

    PIMD_VIFM_COPY(mrt->oifs, old_real_oifs);

    mrt->incoming = new_iif;
    PIMD_VIFM_COPY(new_joined_oifs, mrt->joined_oifs);
    PIMD_VIFM_COPY(new_pruned_oifs, mrt->pruned_oifs);
    PIMD_VIFM_COPY(new_leaves, mrt->leaves);
    PIMD_VIFM_COPY(new_asserted_oifs, mrt->asserted_oifs);
    calc_oifs(mrt, new_real_oifs);

    if (PIMD_VIFM_ISEMPTY(old_real_oifs)) {
	if (PIMD_VIFM_ISEMPTY(new_real_oifs))
	    result = 0;
	else
	    result = 1;
    } else {
	if (PIMD_VIFM_ISEMPTY(new_real_oifs))
	    result = -1;
	else
	    result = 0;
    }

    if ((PIMD_VIFM_SAME(new_real_oifs, old_real_oifs))
	&& (new_iif == old_iif)
	&& !(flags & MFC_UPDATE_FORCE))
	return 0;		/* Nothing to change */

    if ((result != 0) || (new_iif != old_iif) || (flags & MFC_UPDATE_FORCE)) {
	jp_timer_fire(mrt);
    }
    PIMD_VIFM_COPY(new_real_oifs, mrt->oifs);

    /* "CouldAssert(S,G,I) -> FALSE" in the Winner state of RFC 7761
     * sec. 4.6.1 and sec. 4.6.2: an interface we won an Assert on and no
     * longer forward to gets an AssertCancel, so whoever we beat takes over
     * now instead of at Assert_Time.
     */
    for (vifi = 0; vifi < numvifs; vifi++) {
	if (!assert_winner_is_me(mrt, vifi))
	    continue;

	if (!PIMD_VIFM_ISSET(vifi, new_real_oifs))
	    send_pim_assert_cancel(mrt, vifi);
    }

    if (mrt->flags & MRTF_WC) {
	/* (*,G) entry */
	if (PIMD_VIFM_ISEMPTY(new_real_oifs)) {
	    delete_mrt_flag = TRUE;
	} else {
	    delete_mrt_flag = FALSE;
	}

	if (mrt->flags & MRTF_KERNEL_CACHE) {
	    if (delete_mrt_flag == TRUE) {
		delete_mrtentry_all_kernel_cache(mrt);
	    } else {
		for (kc = mrt->kernel_cache; kc; kc = kc->next)
		    k_chg_mfc(igmp_socket, kc->source,
			      kc->group, new_iif,
			      new_real_oifs, mrt->group->rpaddr);
	    }
	}

	/* Update all (S,G) entries for this group.
	 * For the (S,G)RPbit entries the iif is the iif toward the RP;
	 * The particular (S,G) oifs are not changed, but the change in the
	 * (*,G) oifs may affect the real oifs.
	 */
	fire_timer_flag = FALSE;
	for (srcs = mrt->group->mrtlink; srcs; srcs = srcs->grpnext) {
	    if (srcs->flags & MRTF_RP) {
		if (change_interfaces(srcs, new_iif,
				      srcs->joined_oifs,
				      srcs->pruned_oifs,
				      srcs->leaves,
				      srcs->asserted_oifs, flags))
		    fire_timer_flag = TRUE;
	    } else {
		if (change_interfaces(srcs, srcs->incoming,
				      srcs->joined_oifs,
				      srcs->pruned_oifs,
				      srcs->leaves,
				      srcs->asserted_oifs, flags))
		    fire_timer_flag = TRUE;
	    }
	}

	if (fire_timer_flag == TRUE)
	    jp_timer_fire(mrt);

	if (delete_mrt_flag == TRUE) {
	    /* TODO: XXX: the oifs are NULL. Send a Prune message? */
	}

	return result;		/* (*,G) */
    }

    /* (S,G) entry */
    if (mrt->flags & MRTF_SG) {
	mrp = mrt->group->active_rp_grp->rp->rpentry->mrtlink;
	mwc = mrt->group->grp_route;

#ifdef KERNEL_MFC_WC_G
	mrtentry_t *tmp;

	/* Check whether (*,*,RP) or (*,G) have different (iif,oifs) from
	 * the (S,G). If "yes", then forbid creating (*,G) MFC. */
	for (tmp = mrp; 1; tmp = mwc) {
	    while (1) {
		uint8_t oifs[MAXVIFS];

		if (!tmp)
		    break;

		if (tmp->flags & MRTF_MFC_CLONE_SG)
		    break;

		if (tmp->incoming != mrt->incoming) {
		    delete_single_kernel_cache_addr(tmp, INADDR_ANY_N, mrt->group->group);
		    tmp->flags |= MRTF_MFC_CLONE_SG;
		    break;
		}

		calc_oifs(tmp, oifs);
		if (!(PIMD_VIFM_SAME(new_real_oifs, oifs)))
		    tmp->flags |= MRTF_MFC_CLONE_SG;

		break;
	    }

	    if (tmp == mwc)
		break;
	}
#endif /* KERNEL_MFC_WC_G */

	if (PIMD_VIFM_ISEMPTY(new_real_oifs)) {
	    delete_mrt_flag = TRUE;

	    /* Nowhere left to forward this source, so we no longer want it:
	     * JoinDesired(S,G) has gone false, which RFC 7761 sec. 4.2.2
	     * gives as the one event that clears the SPTbit.  Leaving it set
	     * on an entry we are about to prune had the entry keep claiming
	     * the shortest path tree in an assert, and keep asking the RP to
	     * prune a source it no longer forwards.
	     */
	    mrt->flags &= ~MRTF_SPT;
	} else {
	    delete_mrt_flag = FALSE;
	}

	if (mrt->flags & MRTF_KERNEL_CACHE) {
	    if (delete_mrt_flag == TRUE)
		delete_mrtentry_all_kernel_cache(mrt);
	    else
		k_chg_mfc(igmp_socket, mrt->source->address,
			  mrt->group->group, new_iif, new_real_oifs,
			  mrt->group->rpaddr);
	}

	if (old_iif != new_iif) {
	    if (mrt->source && new_iif == mrt->source->incoming) {
		/* For example, if this was (S,G)RPbit with iif toward the RP,
		 * and now switch to the Shortest Path.
		 * The setup of MRTF_SPT flag must be
		 * done by the external calling function (triggered only
		 * by receiving of a data from the source.)
		 */
		mrt->flags &= ~MRTF_RP;
		/* TODO: XXX: delete? Check again where will be the best
		 * place to set it.
		mrt->flags |= MRTF_SPT;
		*/
	    }

	    if ((mwc && mwc->incoming == new_iif) ||
		(mrp && mrp->incoming == new_iif)) {
		/* The new iif points toward the RP, so this entry is back on
		 * the shared tree.  It does not clear the SPTbit with it: RFC
		 * 2362 sec. 2.10 had a routing change do that, RFC 7761
		 * sec. 4.2.2 leaves JoinDesired(S,G) going false as the only
		 * thing that does, and its sec. 4.2.2 condition 4 would in
		 * fact *set* the bit where the two RPF neighbors agree.
		 */
		mrt->flags |= MRTF_RP;
	    }
	}

	/* TODO: XXX: if this is (S,G)RPbit entry and the oifs==(*,G)oifs,
	 * then delete the (S,G) entry?? The same if we have (*,*,RP) ? */
	if (delete_mrt_flag == TRUE) {
	    /* TODO: XXX: the oifs are NULL. Send a Prune message ? */
	}

	/* TODO: XXX: have the feeling something is missing.... */
	return result;		/* (S,G) */
    }

    return result;
}


/* TODO: implement it. Required to allow changing of the physical interfaces
 * configuration without need to restart pimd.
 */
int delete_vif_from_mrt(vifi_t vifi __attribute__((unused)))
{
    return TRUE;
}


void process_kernel_call(ssize_t recvlen)
{
    struct igmpmsg *igmpctl = (struct igmpmsg *)igmp_recv_buf;

    /* accept_igmp() lets us in on an IP header's worth of bytes, and struct
     * igmpmsg happens to be laid out to that same size -- "note the
     * convenient similarity to an IP packet", as the kernel header puts it.
     * Happening to be is not a guarantee, and the message an upcall carries
     * behind its header is not covered by it at all, so say what is needed
     * here rather than inherit a check written for something else.
     */
    if (recvlen < (ssize_t)sizeof(struct igmpmsg)) {
	logit(LOG_WARNING, 0, "Kernel upcall too short (%zd bytes) for its header", recvlen);
	return;
    }

    switch (igmpctl->im_msgtype) {
	case IGMPMSG_NOCACHE:
	    process_cache_miss(igmpctl);
	    break;

	case IGMPMSG_WRONGVIF:
	    process_wrong_iif(igmpctl);
	    break;

	case IGMPMSG_WHOLEPKT:
	    process_whole_pkt(igmp_recv_buf, (size_t)recvlen - sizeof(struct igmpmsg));
	    break;

	default:
	    IF_DEBUG(DEBUG_KERN)
		logit(LOG_DEBUG, 0, "Unknown IGMP message type from kernel: %d", igmpctl->im_msgtype);
	    break;
    }
}


/*
 * The (S,G) entries made as the DR for data from directly connected sources,
 * which local-sg-limit caps.  FREE_MRTENTRY() (src/mrt.h) gives one back
 * whichever path frees the entry.
 */
uint32_t local_sg_entries = 0;

/*
 * The (S,G) entry for a packet from @source, directly connected on a LAN
 * this router is the DR for, to @group, or NULL where there is none to be had.
 *
 * Every group such a packet names that has no entry yet gets one, along with
 * a source entry, a group entry, an RPF lookup and a kernel cache entry, and
 * whoever sends it chooses the group and, on its own subnet, the source:
 * RFC 7761 sec. 6.4's first attack.  Unbounded, one host on the LAN decides
 * how much this router holds, and the default build exits when an
 * allocation finally fails.  So the entries are counted, and past
 * local_sg_limit no new one is made.  An entry that already exists, for
 * whatever reason it was made, is always returned.  What a refused source
 * loses is the Register: it is not forwarded beyond its LAN, and each of its
 * packets stays a cache miss.
 */
static mrtentry_t *local_sg_entry(uint32_t source, uint32_t group)
{
    static int warned = FALSE;
    mrtentry_t *mrt;

    mrt = find_route(source, group, MRTF_SG, DONT_CREATE);
    if (mrt)
	return mrt;

    if (local_sg_entries >= local_sg_limit) {
	if (!warned) {
	    logit(LOG_WARNING, 0, "local-sg-limit %u reached, no more (S,G) state for local sources",
		  local_sg_limit);
	    warned = TRUE;
	}
	IF_DEBUG(DEBUG_MRT)
	    logit(LOG_NOTICE, 0, "Not holding (%s,%s), local-sg-limit %u reached",
		  inet_fmt(source, s1, sizeof(s1)), inet_fmt(group, s2, sizeof(s2)), local_sg_limit);
	return NULL;
    }
    warned = FALSE;

    mrt = find_route(source, group, MRTF_SG, CREATE);
    if (!mrt)
	return NULL;

    if (mrt->flags & MRTF_NEW) {
	mrt->flags &= ~MRTF_NEW;
	mrt->limit_count = &local_sg_entries;
	local_sg_entries++;
    }

    return mrt;
}

/*
 * TODO: when cache miss, check the iif, because probably ASSERTS
 * shoult take place
 */
static void process_cache_miss(struct igmpmsg *igmpctl)
{
    uint32_t source, mfc_source;
    uint32_t group;
    vifi_t iif;
    mrtentry_t *mrt;
    mrtentry_t *mrp;

    /* When there is a cache miss, we check only the header of the packet
     * (and only it should be sent up by the kernel. */

    group  = igmpctl->im_dst.s_addr;
    source = mfc_source = igmpctl->im_src.s_addr;
    iif    = igmpctl->im_vif;

    /* im_vif is one byte of the message the kernel wrote; uvifs[] is
     * MAXVIFS entries and only numvifs of them are in service, so anything
     * outside that is a read past what we know rather than an interface we
     * could act on.  The very next line indexes with it.
     */
    if (iif >= numvifs) {
	logit(LOG_WARNING, 0, "Kernel cache miss on VIF #%u, only %u in service",
	      (unsigned)iif, (unsigned)numvifs);
	return;
    }

    IF_DEBUG(DEBUG_MRT)
	logit(LOG_DEBUG, 0, "Cache miss, src %s, dst %s, iif %s",
	      inet_fmt(source, s1, sizeof(s1)), inet_fmt(group, s2, sizeof(s2)), uvifs[iif].uv_name);

    /* TODO: XXX: check whether the kernel generates cache miss for the LAN scoped addresses */
    if (ntohl(group) <= INADDR_MAX_LOCAL_GROUP)
	return; /* Don't create routing entries for the LAN scoped addresses */

    /* TODO: check if correct in case the source is one of my addresses */
    /* If I am the DR for this source, create (S,G) and add the register_vif
     * to the oifs. */

    if ((uvifs[iif].uv_flags & VIFF_DR) && (find_vif_direct_local(source, TRUE) == iif)) {
	mrt = local_sg_entry(source, group);
	if (!mrt)
	    return;

	/* Set PIMREG_VIF as outgoing interface only where a Register could
	 * follow: not when I am the RP, and not for a group in the SSM
	 * range, which RFC 7761 sec. 4.8.1 rule 3 has no Register for at
	 * all.  send_pim_register() already refuses to build one, so
	 * nothing ever went on the wire -- but the vif went into the oifs
	 * regardless, the RP asked about for an SSM group being the
	 * invented link-local one or whatever covers the range and never
	 * this router.
	 *
	 * Nothing took it back out either: the Register-Stop that prunes it
	 * for an ASM source cannot arrive for a group nobody is the RP of.
	 * So the kernel raised an IGMPMSG_WHOLEPKT upcall for every packet
	 * of every directly connected SSM source, and send_pim_register()
	 * dropped each one -- the whole SSM data rate crossing into user
	 * space and back, on the one router guaranteed to see all of it.
	 */
	/* An RP in an Anycast-RP set with other members is the exception to
	 * the first half: RFC 4610 sec. 5.1 counts a source registered by
	 * "the router itself" as internal like any other, and the only way
	 * the other members learn of it is a Register from this router.
	 * send_pim_register() sends it to them rather than to itself.
	 */
	if ((!i_am_rp(mrt->group->rpaddr) || anycast_rp_peers(mrt->group->rpaddr)) &&
	    !IN_PIM_SSM_RANGE(group))
	    PIMD_VIFM_SET(PIMREG_VIF, mrt->joined_oifs);
	change_interfaces(mrt,
			  mrt->incoming,
			  mrt->joined_oifs,
			  mrt->pruned_oifs,
			  mrt->leaves,
			  mrt->asserted_oifs, 0);
    } else {
	mrt = find_route(source, group, MRTF_SG | MRTF_WC, DONT_CREATE);
	if (!mrt)
	    return;

	if (IN_PIM_SSM_RANGE(group))
	    switch_shortest_path(source, group);
	else
	    check_spt_threshold(mrt);
    }

    /* TODO: if there are too many cache miss for the same (S,G),
     * install negative cache entry in the kernel (oif==NULL) to prevent
     * too many upcalls. */

    if (mrt->incoming == iif) {
	/* The source is alive, restart the (S,G) entry timer.  This has to
	 * happen even when the oif list is empty: a router that is both the
	 * DR for a directly connected source and the RP for the group adds
	 * neither the register vif nor any leaf to the oifs, so nothing else
	 * would ever refresh the timer.  age_routes() then deletes the entry
	 * on its next run and every packet of an active source recreates it,
	 * which is why sources appear and disappear from `pimctl show mrt`.
	 */
	/* TODO: check that the RPbit is not set? */
	/* TODO: XXX: TIMER implem. dependency! */
	if ((mrt->flags & MRTF_SG) && mrt->entry_timer < PIM_DATA_TIMEOUT)
	    SET_TIMER(mrt->entry_timer, PIM_DATA_TIMEOUT);

	if (!PIMD_VIFM_ISEMPTY(mrt->oifs)) {
	    uint32_t rp_addr;

	    update_sptbit(mrt, iif);

	    rp_addr = mrt->group->rpaddr;

	    mfc_source = source;
#ifdef KERNEL_MFC_WC_G
	    if (mrt->flags & MRTF_WC)
		if (!(mrt->flags & MRTF_MFC_CLONE_SG))
		    mfc_source = INADDR_ANY_N;
#endif /* KERNEL_MFC_WC_G */

	    add_kernel_cache(mrt, mfc_source, group, MFC_MOVE_FORCE);

	    APPLY_SCOPE(group, mrt);
	    k_chg_mfc(igmp_socket, mfc_source, group, iif, mrt->oifs, rp_addr);

	}

	return;			/* iif match */
    }

    /* The iif doesn't match */
    if (mrt->flags & MRTF_SG) {
	/* Arrived on wrong interface */
	if (mrt->flags & MRTF_SPT)
	    return;

	mrp = mrt->group->grp_route;
	if (!mrp)
	    mrp = mrt->group->active_rp_grp->rp->rpentry->mrtlink;

	if (mrp) {
	    /* Forward on (*,G) or (*,*,RP) */
	    if (mrp->incoming == iif) {
#ifdef KERNEL_MFC_WC_G
		if (!(mrp->flags & MRTF_MFC_CLONE_SG))
		    mfc_source = INADDR_ANY_N;
#endif /* KERNEL_MFC_WC_G */

		add_kernel_cache(mrp, mfc_source, group, 0);

		/* marian: not sure if we reach here with our scoped traffic? */
		APPLY_SCOPE(group, mrt);
		k_chg_mfc(igmp_socket, mfc_source, group, iif, mrp->oifs, mrt->group->rpaddr);
	    }
	}
    }
}


/*
 * A multicast packet has been received on wrong iif by the kernel.
 * Check for a matching entry. If there is (S,G) with reset SPTbit and
 * the packet was received on the iif toward the source, this completes
 * the switch to the shortest path and triggers (S,G) prune toward the RP
 * (unless I am the RP).
 * Otherwise, if the packet's iif is in the oiflist of the routing entry,
 * trigger an Assert.
 */
static void process_wrong_iif(struct igmpmsg *igmpctl)
{
    uint32_t source;
    uint32_t group;
    vifi_t  iif;
    mrtentry_t *mrt;

    group  = igmpctl->im_dst.s_addr;
    source = igmpctl->im_src.s_addr;
    iif    = igmpctl->im_vif;

    /* Same as in process_cache_miss() above: the index comes out of the
     * upcall and uvifs[] only has numvifs interfaces in it.
     */
    if (iif >= numvifs) {
	logit(LOG_WARNING, 0, "Kernel wrong-iif upcall on VIF #%u, only %u in service",
	      (unsigned)iif, (unsigned)numvifs);
	return;
    }

    IF_DEBUG(DEBUG_MRT)
	logit(LOG_DEBUG, 0, "Wrong iif: src %s, dst %s, iif %s",
	      inet_fmt(source, s1, sizeof(s1)), inet_fmt(group, s2, sizeof(s2)), uvifs[iif].uv_name);

    /* Don't create routing entries for the LAN scoped addresses */
    if (ntohl(group) <= INADDR_MAX_LOCAL_GROUP)
	return;

    /* Ignore if it comes on register vif. register vif is neither SPT iif,
     * neither is used to send asserts out.
     */
    if (uvifs[iif].uv_flags & VIFF_REGISTER)
	return;

    mrt = find_route(source, group, MRTF_SG | MRTF_WC, DONT_CREATE);
    if (!mrt)
	return;

    /*
     * TODO: check again!
     */
    if ((mrt->flags & MRTF_SG) && !(mrt->flags & MRTF_SPT) &&
	mrt->source->incoming == iif) {
	/* Data from S arriving on RPF_interface(S) while the entry still
	 * points at the RP: this is the switch to the shortest path, and
	 * RFC 7761 sec. 4.2.2 decides it like any other, so a router that
	 * has to wait for an Assert(S,G) waits here too and falls through
	 * to sending one.
	 */
	update_sptbit(mrt, iif);

	if (mrt->flags & MRTF_SPT) {
	    /* Move the entry onto that tree rather than only marking it:
	     * the incoming interface, the upstream router and the kernel's
	     * parent vif belong together.  Marking it alone left the Join
	     * fired below going out of the RP-facing interface, and the
	     * next change of the outgoing interfaces pushing the RP-ward
	     * parent back to the kernel, after which every packet from S
	     * arrived on a non-parent vif and was dropped until the unicast
	     * route to S changed.
	     */
	    add_kernel_cache(mrt, source, group, MFC_MOVE_FORCE);
	    k_chg_mfc(igmp_socket, source, group, iif,
		      mrt->oifs, mrt->group->rpaddr);

	    /* The kernel is what this upcall is about: its parent vif is
	     * the stale one, and pimd's own may or may not be.  Where it is
	     * too, move it -- the incoming interface, the upstream router
	     * and the kernel's parent belong together, and marking the
	     * entry alone left the Join fired below going out of the
	     * RP-facing interface and the next change of the outgoing
	     * interfaces pushing the RP-ward parent back down to the
	     * kernel.  MFC_UPDATE_FORCE because change_interfaces() has
	     * nothing of its own to see here: the oifs do not change, and
	     * where the two interfaces already agree it would return
	     * without programming anything at all.
	     */
	    if (mrt->incoming != mrt->source->incoming) {
		change_interfaces(mrt,
				  mrt->source->incoming,
				  mrt->joined_oifs,
				  mrt->pruned_oifs,
				  mrt->leaves,
				  mrt->asserted_oifs, MFC_UPDATE_FORCE);
		mrt->upstream = mrt->source->upstream;
	    }

	    jp_timer_fire(mrt);

	    return;
	}
    }

    /* Trigger an Assert */
    if (PIMD_VIFM_ISSET(iif, mrt->oifs))
	send_pim_assert(source, group, iif, mrt);
}

/*
 * Receives whole packets from the register vif entries
 * in the kernel, and calls the send_pim_register procedure to
 * encapsulate the packets and unicasts them to the RP.
 */
static void process_whole_pkt(char *buf, size_t len)
{
    send_pim_register((char *)(buf + sizeof(struct igmpmsg)), len);
}

mrtentry_t *switch_shortest_path(uint32_t source, uint32_t group)
{
    mrtentry_t *mrt;

    IF_DEBUG(DEBUG_MRT)
	logit(LOG_DEBUG, 0, "Switch shortest path (SPT): src %s, group %s",
	      inet_fmt(source, s1, sizeof(s1)), inet_fmt(group, s2, sizeof(s2)));

    /* TODO: XXX: prepare and send immediately the (S,G) join? */
    mrt = find_route(source, group, MRTF_SG, CREATE);
    if (mrt) {
	if (mrt->flags & MRTF_NEW) {
	    mrt->flags &= ~MRTF_NEW;
	} else if (mrt->flags & MRTF_RP || IN_PIM_SSM_RANGE(group)) {
	    /* (S,G)RPbit with iif toward RP. Reset to (S,G) with iif
	     * toward S. Delete the kernel cache (if any), because
	     * change_interfaces() will reset it with iif toward S
	     * and no data will arrive from RP before the switch
	     * really occurs.
             * For SSM, (S,G)RPbit entry does not exist but switch to
             * SPT must be allowed right away.
	     */
	    mrt->flags &= ~MRTF_RP;
	    mrt->incoming = mrt->source->incoming;
	    mrt->upstream = mrt->source->upstream;
	    delete_mrtentry_all_kernel_cache(mrt);
	    change_interfaces(mrt,
			      mrt->incoming,
			      mrt->joined_oifs,
			      mrt->pruned_oifs,
			      mrt->leaves,
			      mrt->asserted_oifs, 0);
	}

	/* RFC 7761 sec. 4.2.1: CheckSwitchToSpt(S,G) sets KeepaliveTimer(S,G)
	 * when the switch policy says to switch, and the note under it gives
	 * that as what results in the switch -- the timer makes
	 * JoinDesired(S,G) true, the Join(S,G) follows, and only then may
	 * sec. 4.2.2 set the SPTbit.  This is the one place pimd takes that
	 * decision, so it is the one place the timer starts for a source that
	 * is not directly connected.
	 */
	SET_TIMER(mrt->entry_timer, PIM_DATA_TIMEOUT);
	mrt->flags |= MRTF_KAT;
	jp_timer_fire(mrt);
    }

    return mrt;
}

static void try_switch_to_spt(mrtentry_t *mrt, kernel_cache_t *kc)
{
    if (MRT_IS_LASTHOP(mrt) || MRT_IS_RP(mrt)) {
#ifdef KERNEL_MFC_WC_G
	if (kc->source == INADDR_ANY_N) {
	    delete_single_kernel_cache(mrt, kc);
	    mrt->flags |= MRTF_MFC_CLONE_SG;
	    return;
	}
#endif /* KERNEL_MFC_WC_G */

	switch_shortest_path(kc->source, kc->group);
    }
}

/*
 * Check the SPT threshold for a given (*,*,RP) or (*,G) entry
 *
 * XXX: the spec says to start monitoring first the total traffic for
 * all senders for particular (*,*,RP) or (*,G) and if the total traffic
 * exceeds some predefined threshold, then start monitoring the data
 * traffic for each particular sender for this group: (*,G) or
 * (*,*,RP). However, because the kernel cache/traffic info is of the
 * form (S,G), it is easier if we are simply collecting (S,G) traffic
 * all the time.
 *
 * For (*,*,RP) if the number of bytes received between the last check
 * and now exceeds some precalculated value (based on interchecking
 * period and datarate threshold AND if there are directly connected
 * members (i.e. we are their last hop(e) router), then create (S,G) and
 * start initiating (S,G) Join toward the source. The same applies for
 * (*,G).  The spec does not say that if the datarate goes below a given
 * threshold, then will switch back to the shared tree, hence after a
 * switch to the source-specific tree occurs, a source with low
 * datarate, but periodically sending will keep the (S,G) states.
 *
 * If a source with kernel cache entry has been idle after the last time
 * a check of the datarate for the whole routing table, then delete its
 * kernel cache entry.
 */
/*
 * SwitchToSptDesired(S,G) of RFC 7761 sec. 4.2.1 for a source this router
 * has seen one packet of and holds no counters for yet: the policy asks for
 * the shortest path tree at once only where its threshold is zero.
 */
int spt_switch_on_first_packet(void)
{
    switch (spt_threshold.mode) {
    case SPT_PACKETS:
	return spt_threshold.packets == 0;
    case SPT_RATE:
	return spt_threshold.bytes == 0;
    default:
	return FALSE;
    }
}

static void check_spt_threshold(mrtentry_t *mrt)
{
    kernel_cache_t *kc, *kc_next;

    /* XXX: TODO: When we add group-list support to spt-threshold we need
     * to move this infinity check to inside the for-loop ... obviously. */
    if (spt_threshold.mode == SPT_INF)
	return;

    for (kc = mrt->kernel_cache; kc; kc = kc_next) {
	uint32_t prev_bytecnt, prev_pktcnt;
	int rc;

	kc_next = kc->next;

	prev_bytecnt = kc->sg_count.bytecnt;
	prev_pktcnt  = kc->sg_count.pktcnt;

	rc = k_get_sg_cnt(udp_socket, kc->source, kc->group, &kc->sg_count);
	if (rc || prev_bytecnt == kc->sg_count.bytecnt) {
	    /*
	     * Either (for whatever reason) there is no such routing
	     * entry, or that particular (S,G) was idle.
	     *
	     * Note: This code path used to delete the routing entry
	     *       from the kernel.  This caused issues on unicast
	     *       routing changes, GitHub issue #79.  Now we let
	     *       it linger and be removed on IGMPMSG_WRONGVIF.
	     */
	    continue;
	}

	IF_DEBUG(DEBUG_MRT)
	    logit(LOG_DEBUG, 0, "Checking SPT threshold for (%s,%s) pkt cnt now %d vs %d",
		  inet_fmt(kc->source, s1, sizeof(s1)), inet_fmt(kc->group, s2, sizeof(s2)),
		  kc->sg_count.pktcnt, prev_pktcnt);

	/* Check spt-threshold for forwarder and RP, should we switch to
	 * source specific tree (SPT).  Need to check only when we have
	 * (S,G)RPbit in the forwarder or the RP itself. */
	switch (spt_threshold.mode) {
	    case SPT_RATE:
		if (prev_bytecnt + spt_threshold.bytes < kc->sg_count.bytecnt)
		    try_switch_to_spt(mrt, kc);
		break;

	    case SPT_PACKETS:
		if (prev_pktcnt + spt_threshold.packets < kc->sg_count.pktcnt)
		    try_switch_to_spt(mrt, kc);
		break;

	    default:
		;		/* INF not handled here yet. */
	}

	/* XXX: currently the spec doesn't say to switch back to the
	 * shared tree if low datarate, but if needed to implement, the
	 * check must be done here. Don't forget to check whether I am a
	 * forwarder for that source. */
    }
}


/*
 * The routing entry timers that cannot wait for the tick: the Join Timer of
 * RFC 7761 sec. 4.5.4 and sec. 4.5.5, the Prune-Pending Timer of sec. 4.5.1
 * and sec. 4.5.2, and the Assert Timer of sec. 4.6.
 *
 * Every other timer on a routing entry is a count of seconds age_routes()
 * takes TIMER_INTERVAL off, and these used to be too.  That held every
 * triggered Join and Prune back to the next tick, made t_override, drawn from
 * rand(0, 2.5 s), a whole number of ticks, ran a 3-second Prune-Pending Timer
 * out on whichever tick came first, and left the 3 seconds between a winner's
 * Assert resend and its losers' Assert_Time to the tick phase.  Each is a
 * deadline on the monotonic clock instead.  age_routes() still acts on what
 * has come due by the tick, and a deadline the tick would be late for gets a
 * pass of its own, route_timers_run(), for when it runs out.
 */
static uint64_t route_timers_at;	/* When the pass scheduled last runs, 0 none */

static void route_timers_run(void *arg);

void route_timers_schedule(uint64_t when)
{
    uint64_t now = timer_now();

    /* A pass already scheduled for no later will do: it schedules the next
     * one itself.  One overdue is either about to run or went with the whole
     * queue in restart(), and one more pass than needed costs a walk of the
     * table and nothing else. */
    if (route_timers_at && route_timers_at <= when && route_timers_at > now)
	return;

    if (timer_set_ms(when > now ? (int)MIN(when - now, INT_MAX) : 0, route_timers_run, NULL))
	route_timers_at = when;
}

/* The Join Timer.  Only a timer due before the next tick gets a pass: the
 * periodic Joins of every entry are what the tick is for. */
void jp_timer_set(mrtentry_t *mrt, uint32_t msec)
{
    mrt->jp_expires = timer_now() + msec;
    if (msec < TIMER_INTERVAL * 1000)
	route_timers_schedule(mrt->jp_expires);
}

/* "Send Join" and "Send Prune": due now, and due already for a pass that
 * has taken the time before this call. */
void jp_timer_fire(mrtentry_t *mrt)
{
    mrt->jp_expires = 0;
    route_timers_schedule(timer_now());
}

/* Milliseconds left, 0 when due */
uint32_t jp_timer_left(mrtentry_t *mrt)
{
    uint64_t now = timer_now();

    if (mrt->jp_expires <= now)
	return 0;

    return MIN(mrt->jp_expires - now, UINT32_MAX);
}

/*
 * What an expired Join Timer sends upstream, given the action join_or_prune()
 * worked out.  A Join goes on every expiry, that is the periodic refresh.  A
 * Prune goes on the first only: sec. 4.5.4 and sec. 4.5.5 send it on the
 * transition to NotJoined and stop the timer there, where pimd went on
 * sending it every period.  The timer keeps running here all the same, so
 * that a transition back to Joined which nothing fires the timer for is still
 * picked up within a period.  An (S,G)RPbit entry is left out: its Prune is
 * the (S,G,rpt) one, which sec. 4.5.8 repeats with every Join(*,G), and the
 * upstream router forgets it once the HoldTime is out.
 */
static int jp_timer_action(mrtentry_t *mrt, int action)
{
    if ((mrt->flags & (MRTF_RP | MRTF_WC)) == MRTF_RP)
	return action;

    if (action == PIM_ACTION_JOIN) {
	mrt->flags &= ~MRTF_PRUNE_SENT;
    } else if (action == PIM_ACTION_PRUNE) {
	if (mrt->flags & MRTF_PRUNE_SENT)
	    return PIM_ACTION_NOTHING;
	mrt->flags |= MRTF_PRUNE_SENT;
    }

    return action;
}

/*
 * The (*,G) Join Timer, if it is due by @now.  Returns what the entry asked
 * for, which the group's (S,G) entries read, or PIM_ACTION_NOTHING when the
 * timer was not due.
 */
static int jp_timer_expire_wc(mrtentry_t *mrt_grp, rpentry_t *rp, uint64_t now)
{
    int grp_action, action;

    if (mrt_grp->jp_expires > now)
	return PIM_ACTION_NOTHING;

    grp_action = join_or_prune(mrt_grp, mrt_grp->upstream);
    action = jp_timer_action(mrt_grp, grp_action);
    if (action != PIM_ACTION_NOTHING)
	add_jp_entry(mrt_grp->upstream,
		     PIM_JOIN_PRUNE_HOLDTIME,
		     mrt_grp->group->group,
		     SINGLE_GRP_MSKLEN,
		     rp->address,
		     SINGLE_SRC_MSKLEN,
		     MRTF_RP | MRTF_WC,
		     action);
    jp_timer_set(mrt_grp, PIM_JOIN_PRUNE_PERIOD * 1000);

    return grp_action;
}

/* The (S,G) and (S,G)RPbit Join Timer, if it is due by @now, @grp_action
 * being what the group's (*,G) timer asked for in the same pass. */
static void jp_timer_expire_sg(mrtentry_t *mrt_srcs, rpentry_t *rp, int grp_action, uint64_t now)
{
    int src_action = PIM_ACTION_NOTHING, src_action_rp = PIM_ACTION_NOTHING;
    int dont_calc_action = FALSE;
    mrtentry_t *mrt_wide;
    int action;

    mrt_wide = mrt_srcs->group->grp_route;

    if (grp_action != PIM_ACTION_NOTHING) {
	src_action_rp    = join_or_prune(mrt_srcs, rp->upstream);
	src_action       = src_action_rp;
	dont_calc_action = TRUE;

	if (src_action_rp == PIM_ACTION_JOIN) {
	    if (grp_action == PIM_ACTION_PRUNE)
		jp_timer_fire(mrt_srcs);
	} else if (src_action_rp == PIM_ACTION_PRUNE) {
	    if (grp_action == PIM_ACTION_JOIN)
		jp_timer_fire(mrt_srcs);
	}
    }

    if (mrt_srcs->jp_expires > now)
	return;

    if ((dont_calc_action != TRUE) || (rp->upstream != mrt_srcs->upstream))
	src_action = join_or_prune(mrt_srcs, mrt_srcs->upstream);

    action = jp_timer_action(mrt_srcs, src_action);
    if (action != PIM_ACTION_NOTHING) {
	add_jp_entry(mrt_srcs->upstream,
		     PIM_JOIN_PRUNE_HOLDTIME,
		     mrt_srcs->group->group,
		     SINGLE_GRP_MSKLEN,
		     mrt_srcs->source->address,
		     SINGLE_SRC_MSKLEN,
		     mrt_srcs->flags & MRTF_RP,
		     action);
	if (action == PIM_ACTION_PRUNE && (mrt_srcs->flags & MRTF_RP))
	    mrt_srcs->flags |= MRTF_RPT_PRUNED;
    }

    if (mrt_wide) {
	/* Have both (S,G) and (*,G) (or (*,*,RP)).
	 * Check if need to send (S,G) PRUNE toward RP */
	if (mrt_srcs->upstream != mrt_wide->upstream) {
	    if (dont_calc_action != TRUE)
		src_action_rp = join_or_prune(mrt_srcs, mrt_wide->upstream);

	    /* XXX: TODO: do error check if
	     * src_action == PIM_ACTION_JOIN, which
	     * should be an error. */
	    if (src_action_rp == PIM_ACTION_PRUNE) {
		add_jp_entry(mrt_wide->upstream,
			     PIM_JOIN_PRUNE_HOLDTIME,
			     mrt_srcs->group->group,
			     SINGLE_GRP_MSKLEN,
			     mrt_srcs->source->address,
			     SINGLE_SRC_MSKLEN,
			     MRTF_RP,
			     src_action_rp);
		mrt_srcs->flags |= MRTF_RPT_PRUNED;
	    }
	}
    }
    jp_timer_set(mrt_srcs, PIM_JOIN_PRUNE_PERIOD * 1000);
}

/*
 * The triggered half of the upstream (S,G,rpt) state machine of RFC 7761
 * sec. 4.5.7, which pimd did not have: it sent the Prune(S,G,rpt) off the
 * Join Timer and never a Join(S,G,rpt), so a router could neither take back
 * its own Prune nor override somebody else's.  The Prune itself stays the
 * Join Timer's, see jp_timer_expire_sg(), which marks the entry
 * MRTF_RPT_PRUNED when it sends one.  Two things send the Join:
 *
 *  - PruneDesired(S,G,rpt) -> False in the Pruned state, a source we want
 *    again, at once;
 *  - the Override Timer, which rpt_see_prune() in src/pim_proto.c sets for
 *    a neighbor's Prune we do not want, when it runs out.
 *
 * RPTJoinDesired(G) -> False is RPTNotJoined(G) and cancels both.  @next is
 * lowered to an Override Timer still running.
 */
static void rpt_timers_expire(mrtentry_t *mrt, uint64_t now, uint64_t *next)
{
    mrtentry_t *mwc = mrt->group->grp_route;
    int send = FALSE;

    if (!(mrt->flags & MRTF_SG) || !mrt->source)
	return;

    if (!mwc || !mwc->upstream || PIMD_VIFM_ISEMPTY(mwc->oifs)) {
	mrt->flags &= ~MRTF_RPT_PRUNED;
	mrt->rpt_override = 0;
	return;
    }

    if (prune_desired_rpt(mrt)) {
	mrt->rpt_override = 0;
	return;
    }

    if (mrt->flags & MRTF_RPT_PRUNED) {
	mrt->flags &= ~MRTF_RPT_PRUNED;
	send = TRUE;
    } else if (mrt->rpt_override) {
	if (mrt->rpt_override > now) {
	    if (next && (!*next || mrt->rpt_override < *next))
		*next = mrt->rpt_override;
	    return;
	}
	send = TRUE;
    }

    if (!send)
	return;

    mrt->rpt_override = 0;
    add_jp_entry(mwc->upstream,
		 PIM_JOIN_PRUNE_HOLDTIME,
		 mrt->group->group,
		 SINGLE_GRP_MSKLEN,
		 mrt->source->address,
		 SINGLE_SRC_MSKLEN,
		 MRTF_RP,
		 PIM_ACTION_JOIN);
}

/* Send all pending Join/Prune messages */
static void jp_flush(void)
{
    pim_nbr_entry_t *nbr;
    struct uvif *v;
    vifi_t vifi;

    for (vifi = 0, v = &uvifs[0]; vifi < numvifs; vifi++, v++) {
	for (nbr = v->uv_pim_neighbors; nbr; nbr = nbr->next)
	    pack_and_send_jp_message(nbr);
    }
}

/*
 * The Prune-Pending and Assert Timers of one entry, for route_timers_run():
 * what age_routes() does with them on the tick, and @next lowered to the
 * earliest of them still running.
 */
static void route_timers_expire_oifs(mrtentry_t *mrt, uint64_t now, uint64_t *next)
{
    int change = FALSE;
    vifi_t vifi;

    if (expire_prune_pending_timers(mrt, now, next))
	change = TRUE;
    if (expire_rpt_timers(mrt, now, next))
	change = TRUE;
    if (age_asserts(mrt, TRUE))
	change = TRUE;

    if (mrt->asserts && (mrt->flags & MRTF_ASSERTED)) {
	for (vifi = 0; vifi < numvifs; vifi++) {
	    uint64_t expires = mrt->asserts[vifi].expires;

	    if (mrt->asserts[vifi].winner != INADDR_ANY_N && expires &&
		(!*next || expires < *next))
		*next = expires;
	}
    }

    if (change)
	change_interfaces(mrt,
			  mrt->incoming,
			  mrt->joined_oifs,
			  mrt->pruned_oifs,
			  mrt->leaves,
			  mrt->asserted_oifs, 0);
}

/*
 * The pass route_timers_schedule() asks for: the Join, Prune-Pending and
 * Assert Timers alone, over the same walk age_routes() makes, and nothing
 * else aged.  Scheduled again for the earliest Prune-Pending or Assert Timer
 * left, and for the earliest Join Timer the next tick would be late for.
 */
static void route_timers_run(void *arg __attribute__((unused)))
{
    uint64_t now = timer_now(), next = 0, next_jp = 0;
    rp_grp_entry_t *rp_grp;
    cand_rp_t *cand_rp;
    grpentry_t *grp;
    mrtentry_t *mrt, *mrt_next;
    int grp_action;

    route_timers_at = 0;

    for (cand_rp = cand_rp_list; cand_rp; cand_rp = cand_rp->next) {
	for (rp_grp = cand_rp->rp_grp_next; rp_grp; rp_grp = rp_grp->rp_grp_next) {
	    for (grp = rp_grp->grplink; grp; grp = grp->rpnext) {
		grp_action = PIM_ACTION_NOTHING;
		mrt = grp->grp_route;
		if (mrt) {
		    route_timers_expire_oifs(mrt, now, &next);
		    grp_action = jp_timer_expire_wc(mrt, cand_rp->rpentry, now);
		    if (!next_jp || mrt->jp_expires < next_jp)
			next_jp = mrt->jp_expires;
		}

		for (mrt = grp->mrtlink; mrt; mrt = mrt_next) {
		    mrt_next = mrt->grpnext;
		    route_timers_expire_oifs(mrt, now, &next);
		    jp_timer_expire_sg(mrt, cand_rp->rpentry, grp_action, now);
		    rpt_timers_expire(mrt, now, &next);
		    if (!next_jp || mrt->jp_expires < next_jp)
			next_jp = mrt->jp_expires;
		}
	    }
	}
    }

    jp_flush();

    now = timer_now();
    if (next_jp && next_jp < now + TIMER_INTERVAL * 1000 && (!next || next_jp < next))
	next = next_jp;
    if (next)
	route_timers_schedule(next);
}


/*
 * Scan the whole routing table and timeout a bunch of timers:
 *  - oifs timers
 *  - Join/Prune timer
 *  - routing entry
 *  - Assert timer
 *  - Register-Suppression timer
 *
 *  - If the global timer for checking the unicast routing has expired, perform
 *  also iif/upstream router change verification
 *  - If the global timer for checking the data rate has expired, check the
 *  number of bytes forwarded after the lastest timeout. If bigger than
 *  a given threshold, then switch to the shortest path.
 *  If `number_of_bytes == 0`, then delete the kernel cache entry.
 *
 * Only the entries which have the Join/Prune timer expired are sent.
 * In the special case when we have ~(S,G)RPbit Prune entry, we must
 * include any (*,G) or (*,*,RP) XXX: ???? what and why?
 *
 * Below is a table which summarizes the segmantic rules.
 *
 * On the left side is "if A must be included in the J/P message".
 * On the top is "shall/must include B?"
 * "Y" means "MUST include"
 * "SY" means "SHOULD include"
 * "N" means  "NO NEED to include"
 * (G is a group that matches to RP)
 *
 *              -----------||-----------||-----------
 *            ||  (*,*,RP) ||   (*,G)   ||   (S,G)   ||
 *            ||-----------||-----------||-----------||
 *            ||  J  |  P  ||  J  |  P  ||  J  |  P  ||
 * ==================================================||
 *          J || n/a | n/a ||  N  |  Y  ||  N  |  Y  ||
 * (*,*,RP) -----------------------------------------||
 *          P || n/a | n/a ||  SY |  N  ||  SY |  N  ||
 * ==================================================||
 *          J ||  N  |  N  || n/a | n/a ||  N  |  Y  ||
 *   (*,G)  -----------------------------------------||
 *          P ||  N  |  N  || n/a | n/a ||  SY |  N  ||
 * ==================================================||
 *          J ||  N  |  N  ||  N  |  N  || n/a | n/a ||
 *   (S,G)  -----------------------------------------||
 *          P ||  N  |  N  ||  N  |  N  || n/a | n/a ||
 * ==================================================
 *
 */
void age_routes(void)
{
    cand_rp_t  *cand_rp;
    grpentry_t *grp;
    grpentry_t *grp_next;
    mrtentry_t *mrt_grp;
    mrtentry_t *mrt_srcs;
    mrtentry_t *mrt_srcs_next;
    rp_grp_entry_t *rp_grp;
    vifi_t  vifi;
    int change_flag;
    int grp_action;
    uint64_t now = timer_now();
    rpentry_t *rp;
    int update_src_iif;
    uint8_t new_pruned_oifs[MAXVIFS];
    uint8_t ucast_flag = FALSE;
    uint8_t rate_flag = FALSE;

    /*
     * Timing out of the global `unicast_routing_timer`
     * and `data_rate_timer`
     */
    IF_TIMEOUT(unicast_routing_timer) {
	ucast_flag = TRUE;
	SET_TIMER(unicast_routing_timer, unicast_routing_interval);
    }

    IF_TIMEOUT(pim_spt_threshold_timer) {
	rate_flag = TRUE;
	SET_TIMER(pim_spt_threshold_timer, spt_threshold.interval);
    }

    /* Scan the candidate RPs, tracking the unicast route to each */
    for (cand_rp = cand_rp_list; cand_rp; cand_rp = cand_rp->next) {
	int update_rp_iif;

	rp = cand_rp->rpentry;

	/* Need to save only `incoming` and `upstream` to discover
	 * unicast route changes. `metric` and `preference` are not
	 * interesting for us.
	 */
	rpentry_save.incoming = rp->incoming;
	rpentry_save.upstream = rp->upstream;

	update_rp_iif = FALSE;
	if ((ucast_flag == TRUE) && !i_am_rp(rp->address)) {
	    /* I am not the RP. If I was the RP, then the iif is
	     * register_vif and no need to reset it. */
	    if (set_incoming(rp, PIM_IIF_RP) != TRUE) {
		/* TODO: XXX: no route to that RP. Panic? There is a high
		 * probability the network is partitioning so immediately
		 * remapping to other RP is not a good idea. Better wait
		 * the Bootstrap mechanism to take care of it and provide
		 * me with correct Cand-RP-Set. */
	    }
	    else {
		if ((rpentry_save.upstream != rp->upstream) ||
		    (rpentry_save.incoming != rp->incoming)) {
		    /* Routing change has occur. Update all (*,G)
		     * and (S,G)RPbit iifs mapping to that RP */
		    update_rp_iif = TRUE;
		}
	    }
	}


	/* Check the (*,G) and (S,G) entries */
	for (rp_grp = cand_rp->rp_grp_next; rp_grp; rp_grp = rp_grp->rp_grp_next) {
	    for (grp = rp_grp->grplink; grp; grp = grp_next) {
		grp_next   = grp->rpnext;
		grp_action = PIM_ACTION_NOTHING;
		mrt_grp    = grp->grp_route;
		mrt_srcs   = grp->mrtlink;

		if (mrt_grp) {
		    /* The (*,G) entry */
		    /* outgoing interfaces timers */
		    change_flag = age_asserts(mrt_grp, FALSE);
		    if (expire_prune_pending_timers(mrt_grp, now, NULL))
			change_flag = TRUE;

		    for (vifi = 0; vifi < numvifs; vifi++) {
			if (PIMD_VIFM_ISSET(vifi, mrt_grp->joined_oifs)) {
			    /* RFC 7761 sec. 4.9.5: a Join/Prune Holdtime of
			     * 0xffff has the receiver "hold the state until
			     * canceled by the appropriate canceling
			     * Join/Prune message".  Held rather than aged,
			     * the way vif.c holds a neighbour whose Hello
			     * said the same; counted down five seconds at a
			     * time it reached zero 18 hours later, which is
			     * neither "until canceled" nor long enough for
			     * the dial-on-demand links the value is for.
			     */
			    if (mrt_grp->vif_timers[vifi] == PIM_HELLO_HOLDTIME_FOREVER)
				continue;

			    IF_TIMEOUT(mrt_grp->vif_timers[vifi]) {
				PIMD_VIFM_CLR(vifi, mrt_grp->joined_oifs);
				expire_prune_pending(mrt_grp, vifi);
				change_flag = TRUE;
			    }
			}
		    }

		    if ((change_flag == TRUE) || (update_rp_iif == TRUE)) {
			pim_nbr_entry_t *old_upstream = mrt_grp->upstream;

			change_interfaces(mrt_grp,
					  rp->incoming,
					  mrt_grp->joined_oifs,
					  mrt_grp->pruned_oifs,
					  mrt_grp->leaves,
					  mrt_grp->asserted_oifs, 0);
			mrt_grp->upstream = rp->upstream;

			/* RFC 7761 sec. 4.5.4, "RPF'(*,G) changes not due to
			 * an Assert": Join the new upstream router.  When the
			 * next hop moves to a different router on the same
			 * interface, change_interfaces() above sees the same
			 * iif and the same oifs and returns without firing
			 * anything, so the Joins went on going to the router
			 * we no longer use until the periodic timer came
			 * round, up to a minute of nothing for that group.
			 */
			if (mrt_grp->upstream != old_upstream) {
			    prune_old_upstream(mrt_grp, old_upstream, MRTF_RP | MRTF_WC);
			    jp_timer_fire(mrt_grp);
			}
		    }

		    /* Check the sources activity */
		    if (rate_flag == TRUE)
			check_spt_threshold(mrt_grp);

		    /* Join/Prune timer */
		    grp_action = jp_timer_expire_wc(mrt_grp, rp, now);

		    /* Register-Suppression timer */
		    /* TODO: to reduce the kernel calls, if the timer
		     * is running, install a negative cache entry in
		     * the kernel?
		     */
		    /* TODO: currently cannot have Register-Suppression
		     * timer for (*,G) entry, but keep this around.
		     */
		    IF_TIMEOUT(mrt_grp->rs_timer) {}

		    /* routing entry.  Held where the Join/Prune that raised it
		     * asked for that, the same sentinel as the outgoing
		     * interface timers above: an entry aged out from under a
		     * held oif is the state gone all the same, which is not
		     * what "until canceled" means.
		     */
		    if (mrt_grp->entry_timer != PIM_HELLO_HOLDTIME_FOREVER &&
			(TIMEOUT(mrt_grp->entry_timer)) && (PIMD_VIFM_ISEMPTY(mrt_grp->leaves)))
			delete_mrtentry(mrt_grp);
		} /* if (mrt_grp) */


		/* For all (S,G) for this group */
		/* XXX: mrt_srcs was set before */
		for (; mrt_srcs; mrt_srcs = mrt_srcs_next) {
		    /* routing entry */
		    mrt_srcs_next = mrt_srcs->grpnext;

		    /* outgoing interfaces timers */
		    change_flag = age_asserts(mrt_srcs, FALSE);
		    if (expire_prune_pending_timers(mrt_srcs, now, NULL))
			change_flag = TRUE;
		    if (expire_rpt_timers(mrt_srcs, now, NULL))
			change_flag = TRUE;

		    for (vifi = 0; vifi < numvifs; vifi++) {
			if (PIMD_VIFM_ISSET(vifi, mrt_srcs->joined_oifs)) {
			    /* TODO: checking for reg_num_vif is slow! */
			    if (vifi != PIMREG_VIF) {
				/* Held until canceled, as above */
				if (mrt_srcs->vif_timers[vifi] == PIM_HELLO_HOLDTIME_FOREVER)
				    continue;

				IF_TIMEOUT(mrt_srcs->vif_timers[vifi]) {
				    PIMD_VIFM_CLR(vifi, mrt_srcs->joined_oifs);
				    PIMD_VIFM_CLR(vifi, mrt_srcs->sg_joined_oifs);
				    expire_prune_pending(mrt_srcs, vifi);
				    change_flag = TRUE;
				}
			    }
			}
		    }

		    update_src_iif = FALSE;
		    if (ucast_flag == TRUE) {
			if (!(mrt_srcs->flags & MRTF_RP)) {
			    /* iif toward the source */
			    srcentry_save.incoming = mrt_srcs->source->incoming;
			    srcentry_save.upstream = mrt_srcs->source->upstream;
			    if (set_incoming(mrt_srcs->source, PIM_IIF_SOURCE) != TRUE) {
				/* XXX: not in the spec!
				 * Cannot find route toward that source.
				 * This is bad. Delete the entry.
				 */
				delete_mrtentry(mrt_srcs);
				continue;
			    }

			    /* iif info found */
			    if ((srcentry_save.incoming != mrt_srcs->source->incoming) ||
				(srcentry_save.upstream != mrt_srcs->source->upstream)) {
				pim_nbr_entry_t *old_upstream = mrt_srcs->upstream;

				/* Route change has occur */
				update_src_iif = TRUE;
				mrt_srcs->incoming = mrt_srcs->source->incoming;
				mrt_srcs->upstream = mrt_srcs->source->upstream;

				/* Prune the router we used to take S from, the
				 * half of RFC 7761 sec. 4.5.5 that pairs with
				 * the Join to the new one. */
				prune_old_upstream(mrt_srcs, old_upstream, MRTF_SG);
			    }
			} else {
			    /* (S,G)RPBit with iif toward RP */
			    if ((rpentry_save.upstream != mrt_srcs->upstream) ||
				(rpentry_save.incoming != mrt_srcs->incoming)) {
				pim_nbr_entry_t *old_upstream = mrt_srcs->upstream;

				update_src_iif = TRUE; /* XXX: a hack */
				/* XXX: setup the iif now! */
				mrt_srcs->incoming = rp->incoming;
				mrt_srcs->upstream = rp->upstream;

				prune_old_upstream(mrt_srcs, old_upstream, MRTF_SG);
			    }
			}
		    }

		    if ((change_flag == TRUE) || (update_src_iif == TRUE))
			/* Flush the changes */
			change_interfaces(mrt_srcs,
					  mrt_srcs->incoming,
					  mrt_srcs->joined_oifs,
					  mrt_srcs->pruned_oifs,
					  mrt_srcs->leaves,
					  mrt_srcs->asserted_oifs, MFC_UPDATE_FORCE);

		    if (rate_flag == TRUE)
			check_spt_threshold(mrt_srcs);

		    /* Sec. 4.2.2 decides SPTbit on receipt of data, which pimd
		     * only sees when the kernel hands it a packet.  Ask the
		     * kernel instead. */
		    check_sptbit(mrt_srcs);

		    /* Join/Prune timer */
		    jp_timer_expire_sg(mrt_srcs, rp, grp_action, now);
		    rpt_timers_expire(mrt_srcs, now, NULL);

		    /* Register-Suppression timer */
		    /* TODO: to reduce the kernel calls, if the timer
		     * is running, install a negative cache entry in
		     * the kernel? */
		    IF_TIMER_SET(mrt_srcs->rs_timer) {
			IF_TIMEOUT(mrt_srcs->rs_timer) {
			    /* Start encapsulating the packets */
			    PIMD_VIFM_COPY(mrt_srcs->pruned_oifs, new_pruned_oifs);
			    PIMD_VIFM_CLR(PIMREG_VIF, new_pruned_oifs);
			    change_interfaces(mrt_srcs,
					      mrt_srcs->incoming,
					      mrt_srcs->joined_oifs,
					      new_pruned_oifs,
					      mrt_srcs->leaves,
					      mrt_srcs->asserted_oifs, 0);
			}
			ELSE {
			    /* The register suppression timer is running. Check
			     * whether it is time to send PIM_NULL_REGISTER.
			     */
			    /* TODO: XXX: TIMER implem. dependency! */
			    if (mrt_srcs->rs_timer <= PIM_REGISTER_PROBE_TIME)
				/* Time to send a PIM_NULL_REGISTER */
				/* XXX: a (bad) hack! This will be sending
				 * periodically NULL_REGISTERS between
				 * PIM_REGISTER_PROBE_TIME and 0. Well,
				 * because PROBE_TIME is 5 secs, it will
				 * happen only once, so it helps to avoid
				 * adding a flag to the routing entry whether
				 * a NULL_REGISTER was sent.
				 */
				send_pim_null_register(mrt_srcs);
			}
		    }

		    /* routing entry, held as the (*,G) one above is */
		    if (mrt_srcs->entry_timer != PIM_HELLO_HOLDTIME_FOREVER &&
			TIMEOUT(mrt_srcs->entry_timer)) {
			if (PIMD_VIFM_ISEMPTY(mrt_srcs->leaves)) {
			    delete_mrtentry(mrt_srcs);
			    continue;
			}
			/* XXX: if DR, Register suppressed,
			 * and leaf oif inherited from (*,G), the
			 * directly connected source is not active anymore,
			 * this (S,G) entry won't timeout. Check if the leaf
			 * oifs are inherited from (*,G); if true. delete the
			 * (S,G) entry.
			 */
			if (mrt_srcs->group->grp_route) {
			    if (PIMD_VIFM_LASTHOP_ROUTER(mrt_srcs->group->grp_route->leaves, mrt_srcs->leaves)) {
				delete_mrtentry(mrt_srcs);
				continue;
			    }
			}
		    }
		} /* End of (S,G) loop */
	    } /* End of (*,G) loop */
	}
    } /* For all cand RPs */

    jp_flush();
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "cc-mode"
 * End:
 */
