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
 *  $Id: pim_proto.c,v 1.47 2003/05/28 22:57:16 pavlin Exp $
 */

#include <arpa/inet.h>
#include "defs.h"

typedef struct {
    uint16_t  holdtime;
    int8_t    holdtime_present;
    uint32_t  dr_prio;
    int8_t    dr_prio_present;
    uint32_t  genid;
    int8_t    lan_delay_present;
    int8_t    tracking_support;
    uint16_t  propagation_delay;
    uint16_t  override_interval;
} pim_hello_opts_t;

/*
 * Local functions definitions.
 */
static int encoded_addr_ok         (uint8_t family, uint8_t etype);
static int group_range_ok          (const pim_encod_grp_addr_t *grp);
static int dr_election             (struct uvif *v);
static int restart_dr_election     (struct uvif *v);
static int parse_pim_hello         (char *msg, size_t len, uint32_t src, pim_hello_opts_t *opts);
static void cache_nbr_settings     (pim_nbr_entry_t *nbr, pim_hello_opts_t *opts);
static int send_pim_register_stop  (uint32_t reg_src, uint32_t reg_dst, uint32_t inner_grp, uint32_t inner_source);
static build_jp_message_t *get_jp_working_buff (void);
static void return_jp_working_buff (pim_nbr_entry_t *pim_nbr);
static void pack_jp_message_grp    (pim_nbr_entry_t *pim_nbr);
static void pack_jp_message_rp     (pim_nbr_entry_t *pim_nbr);
static void send_jp_message        (pim_nbr_entry_t *pim_nbr);
static int flush_packed_groups     (pim_nbr_entry_t *pim_nbr);
static void jp_message_restart     (pim_nbr_entry_t *pim_nbr, build_jp_message_t *bjpm);
static int compare_metrics         (uint32_t local_preference,
				    uint32_t local_metric,
				    uint32_t local_address,
				    uint32_t remote_preference,
				    uint32_t remote_metric,
				    uint32_t remote_address);
static void my_assert_metric       (mrtentry_t *mrt,
				    uint32_t *preference,
				    uint32_t *metric);
static void spt_assert_metric      (mrtentry_t *mrt,
				    uint32_t *preference,
				    uint32_t *metric);
static int  assert_send            (uint32_t source,
				    uint32_t group,
				    vifi_t vifi,
				    uint32_t preference,
				    uint32_t metric);
static void assert_noinfo          (mrtentry_t *mrt, vifi_t vifi);
static int  assert_clear           (mrtentry_t *mrt, vifi_t vifi);
static void assert_neighbor_gone   (vifi_t vifi, uint32_t addr, const char *why);

build_jp_message_t *build_jp_message_pool;
int build_jp_message_pool_counter;

/* Effective_Override_Interval(I), defined with the rest of the LAN Prune
 * Delay plumbing further down; t_override is drawn from it. */
static uint16_t effective_override_interval(vifi_t vifi);

/*
 * t_override: the randomized delay before a triggered Join, so that routers
 * on a LAN do not all answer in the same instant.  RFC 7761 sec. 4.11 wants
 * rand(0, Effective_Override_Interval(I)), which is now a value the link
 * negotiates rather than the Override_Interval default.  The division still
 * quantizes the result to whole seconds, and SET_TIMER cannot express
 * anything finer; that half is T1 in doc/rfc7761-compliance.md.
 */
static uint16_t jp_override_timeout(vifi_t vifi)
{
    return (RANDOM() % effective_override_interval(vifi)) / 1000;
}


/*
 * t_suppressed: how long a router holds off its own Join after hearing an
 * equivalent one from a neighbor.  RFC 7761 sec. 4.11 draws it from
 * rand(1.1 * t_periodic, 1.4 * t_periodic), 66 to 84 seconds at the default
 * period.  The old range started at t_periodic itself, so a suppressed
 * router could still send inside the very period it was suppressed for.
 */
static uint16_t jp_suppression_timeout(void)
{
    return (PIM_JOIN_PRUNE_PERIOD * 11) / 10
	+ RANDOM() % ((PIM_JOIN_PRUNE_PERIOD * 3) / 10 + 1);
}

/*
 * RFC 7761 sec. 4.5.4 and 4.5.5, "See Join(*,G) to RPF'(*,G)" and its (S,G)
 * twin: another router on the upstream interface has just sent the Join we
 * were going to send, so ours can wait.  t_joinsuppress is the smaller of
 * t_suppressed and the HoldTime of the Join overheard, and the Join Timer is
 * only ever raised to it, never lowered.
 *
 * The HoldTime bound is what makes this safe.  The upstream router keeps the
 * interface for as long as the Join it heard asked, and not for as long as
 * we stay quiet: suppressed past that, which a short HoldTime from a router
 * with a faster t_periodic is enough for, we would let the state we want
 * expire upstream.  Silently losing a group for minutes is what this
 * suppression was taken out for, in 892acbe, rather than bounded.
 */
static void jp_suppress(mrtentry_t *mrt, uint16_t holdtime)
{
    uint16_t jp_value = MIN(jp_suppression_timeout(), holdtime);

    if (mrt->jp_timer < jp_value)
	SET_TIMER(mrt->jp_timer, jp_value);
}


/*
 * A neighbor whose GenID changed has restarted, and with it lost the Join
 * state we sent it.  RFC 7761 sec. 4.5.4 and 4.5.5 both answer that with
 * "If the Join Timer is set to expire in more than t_override seconds,
 * reset it so that it expires after t_override seconds", for every entry
 * that neighbor is the upstream of.  Left to the periodic timer, the tree
 * upstream of us is gone for up to a whole Join/Prune period instead.
 */
static void refresh_upstream_joins(pim_nbr_entry_t *nbr)
{
    uint16_t jp_value = jp_override_timeout(nbr->vifi);
    grpentry_t *grp;
    mrtentry_t *mrt;

    for (grp = grplist; grp; grp = grp->next) {
	mrt = grp->grp_route;
	if (mrt && mrt->upstream == nbr && mrt->jp_timer > jp_value)
	    SET_TIMER(mrt->jp_timer, jp_value);

	for (mrt = grp->mrtlink; mrt; mrt = mrt->grpnext) {
	    if (mrt->upstream == nbr && mrt->jp_timer > jp_value)
		SET_TIMER(mrt->jp_timer, jp_value);
	}
    }
}



/************************************************************************
 *                        PIM_HELLO
 ************************************************************************/
int receive_pim_hello(uint32_t src, uint32_t dst __attribute__((unused)), char *msg, size_t len)
{
    vifi_t vifi;
    struct uvif *v;
    size_t bsr_length;
    pim_nbr_entry_t *nbr, *prev_nbr, *new_nbr;
    pim_hello_opts_t opts;
    srcentry_t *srcentry;
    mrtentry_t *mrtentry;

    if (inet_cksum((uint16_t *)msg, len))
	return FALSE;

    vifi = find_vif_direct(src);
    if (vifi == NO_VIF) {
	/* Either a local vif or somehow received PIM_HELLO from
	 * non-directly connected router. Ignore it. */
	if (local_address(src) == NO_VIF) {
	    IF_DEBUG(DEBUG_PIM_HELLO)
		logit(LOG_DEBUG, 0, "Ignoring PIM_HELLO from non-neighbor router %s",
		      inet_fmt(src, s1, sizeof(s1)));
	}

	return FALSE;
    }

    v = &uvifs[vifi];
    if (v->uv_flags & (VIFF_DOWN | VIFF_DISABLED | VIFF_REGISTER))
	return FALSE;    /* Shoudn't come on this interface */

    /* RFC 7761 sec. 6.2's option, "accept-nbr-from" in pimd.conf.  This is
     * the one that does the work: a router refused here never becomes a
     * neighbor, and a Join/Prune, an Assert and a unicast Bootstrap all
     * want a neighbor.  Accepts everything while unconfigured, which the
     * same section requires of every option of this kind.
     */
    if (!pim_nbr_accepted(vifi, src)) {
	IF_DEBUG(DEBUG_PIM_HELLO)
	    logit(LOG_NOTICE, 0, "Ignoring PIM HELLO from %s on %s, not in its accept-nbr-from list",
		  inet_fmt(src, s1, sizeof(s1)), v->uv_name);

	return FALSE;
    }

    /* Get the Holdtime (in seconds) and any DR priority from the message. Return if error. */
    if (parse_pim_hello(msg, len, src, &opts) == FALSE)
	return FALSE;

    IF_DEBUG(DEBUG_PIM_HELLO)
	logit(LOG_DEBUG, 0, "PIM HELLO from %s: holdtime %u, DR priority %u, GenID 0x%04x",
	      inet_fmt(src, s1, sizeof(s1)), opts.holdtime, opts.dr_prio, opts.genid);

    for (prev_nbr = NULL, nbr = v->uv_pim_neighbors; nbr; prev_nbr = nbr, nbr = nbr->next) {
	/* The PIM neighbors are sorted in decreasing order of the
	 * network addresses (note that to be able to compare them
	 * correctly we must translate the addresses in host order.
	 */
	if (ntohl(src) < ntohl(nbr->address))
	    continue;

	if (src == nbr->address) {
	    /* We already have an entry for this host */
	    if (0 == opts.holdtime) {
		/* Looks like we have a nice neighbor who is going down
		 * and wants to inform us by sending "holdtime=0". Thanks
		 * buddy and see you again!
		 */
		IF_DEBUG(DEBUG_PIM_HELLO)
		    logit(LOG_INFO, 0, "PIM HELLO received: neighbor %s going down",
			  inet_fmt(src, s1, sizeof(s1)));
		delete_pim_nbr(nbr);

		return TRUE;
	    }

	    /* https://tools.ietf.org/html/draft-ietf-pim-hello-genid-01 */
	    if (nbr->genid != opts.genid) {
		/* Known neighbor rebooted, update info and resend RP-Set */
		cache_nbr_settings(nbr, &opts);
		refresh_upstream_joins(nbr);
		/* It no longer knows it won any Assert, RFC 7761 sec. 4.6.1
		 * and sec. 4.6.2, "Current Winner's GenID Changes". */
		assert_neighbor_gone(vifi, src, "restarted");
		goto rebooted;
	    }

	    if (nbr->dr_prio != opts.dr_prio) {
		/* New DR priority for neighbor, restart DR election */
		cache_nbr_settings(nbr, &opts);
		goto election;
	    }

	    cache_nbr_settings(nbr, &opts);
	    return TRUE;
	}

	/* No entry for this neighbor. Exit loop to create an entry for it. */
	break;
    }

    /*
     * This is a new neighbor. Create a new entry for it.
     * It must be added right after `prev_nbr`
     */
    IF_DEBUG(DEBUG_PIM_HELLO)
	logit(LOG_INFO, 0, "Received PIM HELLO from new neighbor %s", inet_fmt(src, s1, sizeof(s1)));

    new_nbr = calloc(1, sizeof(pim_nbr_entry_t));
    if (!new_nbr) {
	logit(LOG_ERR, 0, "Ran out of memory in %s()", __func__);
	return FALSE;
    }

    new_nbr->address          = src;
    new_nbr->vifi             = vifi;
    new_nbr->uptime           = time(NULL);
    new_nbr->build_jp_message = NULL;
    new_nbr->next             = nbr;
    new_nbr->prev             = prev_nbr;

    /* Add PIM Hello options */
    cache_nbr_settings(new_nbr, &opts);

    /* Add to linked list of neighbors */
    if (prev_nbr)
	prev_nbr->next  = new_nbr;
    else
	v->uv_pim_neighbors = new_nbr;

    if (new_nbr->next)
	new_nbr->next->prev = new_nbr;

    v->uv_flags &= ~VIFF_NONBRS;
    v->uv_flags |= VIFF_PIM_NBR;

  rebooted:
    /*
     * A new neighbour has come up, let it know we exist too.  First
     * we must send a proper greeting, then we can send bootstrap.
     * See RFC 5059, section 3.5
     */
    IF_DEBUG(DEBUG_PIM_HELLO)
	logit(LOG_INFO, 0, "Sending PIM HELLO to new neighbor %s", inet_fmt(src, s1, sizeof(s1)));
    send_pim_hello(v, pim_timer_hello_holdtime);

    if (v->uv_flags & VIFF_DR) {
	/*
	 * If I am the current DR on that interface, so
	 * send an RP-Set message to the new neighbor.
	 */
	if ((bsr_length = create_pim_bootstrap_message(pim_send_buf)))
	    send_pim_unicast(pim_send_buf, 0, v->uv_mtu, v->uv_lcl_addr, src, PIM_BOOTSTRAP, bsr_length);
    }

  election:
    if (restart_dr_election(v)) {
	/* I was the DR, but not anymore. Remove all register_vif from
	 * oif list for all directly connected sources (for vifi). */

	/* TODO: XXX: first entry is not used! */
	for (srcentry = srclist->next; srcentry; srcentry = srcentry->next) {
	    /* If not directly connected source for vifi */
	    if ((srcentry->incoming != vifi) || srcentry->upstream)
		continue;

	    for (mrtentry = srcentry->mrtlink; mrtentry; mrtentry = mrtentry->srcnext) {

		if (!(mrtentry->flags & MRTF_SG))
		    continue;  /* This is not (S,G) entry */

		/* Remove the register oif */
		PIMD_VIFM_CLR(PIMREG_VIF, mrtentry->joined_oifs);
		change_interfaces(mrtentry,
				  mrtentry->incoming,
				  mrtentry->joined_oifs,
				  mrtentry->pruned_oifs,
				  mrtentry->leaves,
				  mrtentry->asserted_oifs, 0);
	    }
	}
    }

    /*
     * TODO: XXX: does a new neighbor change any routing entries info?
     * Need to trigger joins?
     */

    return TRUE;
}


/*
 * An entry that still names a neighbor on its way out falls back on the next
 * hop the unicast routing table gives, together with that next hop's metric,
 * the way RFC 7761 sec. 4.6.1 has RPF'(S,G) revert to the MRIB when the
 * assert winner's liveness timer expires.  Any assert this neighbor won on
 * the incoming interface goes with it.
 */
static void reset_upstream_router(mrtentry_t *mrt, pim_nbr_entry_t *nbr_delete)
{
    srcentry_t *src = NULL;

    if (mrt->upstream != nbr_delete)
	return;

    if (mrt->flags & MRTF_RP) {
	/* Upstream is toward the RP, not toward the source. */
	if (mrt->group->active_rp_grp)
	    src = mrt->group->active_rp_grp->rp->rpentry;
    } else {
	src = mrt->source;
    }

    if (src && src->upstream != nbr_delete) {
	mrt->upstream   = src->upstream;
	mrt->metric     = src->metric;
	mrt->preference = src->preference;
    } else {
	/* Nothing better to name; age_routes() picks an upstream up again
	 * once the unicast routing table has one.
	 */
	mrt->upstream = NULL;
    }
}


void delete_pim_nbr(pim_nbr_entry_t *nbr_delete)
{
    srcentry_t *src;
    srcentry_t *src_next;
    mrtentry_t *mrt;
    mrtentry_t *mrt_srcs;
    grpentry_t *grp;
    cand_rp_t *cand_rp;
    rp_grp_entry_t *rp_grp;
    rpentry_t  *rp;
    struct uvif *v;

    IF_DEBUG(DEBUG_PIM_HELLO)
	logit(LOG_INFO, 0, "Deleting PIM neighbor %s", inet_fmt(nbr_delete->address, s1, sizeof(s1)));

    v = &uvifs[nbr_delete->vifi];

    /* Delete the entry from the pim_nbrs chain */
    if (nbr_delete->prev)
	nbr_delete->prev->next = nbr_delete->next;
    else
	v->uv_pim_neighbors = nbr_delete->next;

    if (nbr_delete->next)
	nbr_delete->next->prev = nbr_delete->prev;

    /* Remove the DR neighbor reference */
    if (v->uv_pim_neighbor_dr == nbr_delete )
	v->uv_pim_neighbor_dr = NULL;

    return_jp_working_buff(nbr_delete);

    /* That neighbor could've been the DR */
    restart_dr_election(v);

    /* Update the source entries */
    for (src = srclist; src; src = src_next) {
	src_next = src->next;

	if (src->upstream != nbr_delete)
	    continue;

	/* Reset the next hop (PIM) router */
	if (set_incoming(src, PIM_IIF_SOURCE) == FALSE) {
	    /* Coudn't reset it. Sorry, the hext hop router toward that
	     * source is probably not a PIM router, or cannot find route
	     * at all, hence I cannot handle this source and have to
	     * delete it.
	     */
	    logit(LOG_WARNING, 0, "Deleting source entry for source %s", inet_fmt(src->address, s1, sizeof(s1)));
	    delete_srcentry(src);
	} else if (src->upstream) {
	    /* Ignore the local or directly connected sources */
	    /* Browse all MRT entries for this source and reset the
	     * upstream router. Note that the upstream router is not always
	     * toward the source: it could be toward the RP for example.
	     */
	    for (mrt = src->mrtlink; mrt; mrt = mrt->srcnext) {
		if (!(mrt->flags & MRTF_RP)) {
		    mrt->upstream   = src->upstream;
		    mrt->metric     = src->metric;
		    mrt->preference = src->preference;
		    change_interfaces(mrt, src->incoming,
				      mrt->joined_oifs,
				      mrt->pruned_oifs,
				      mrt->leaves,
				      mrt->asserted_oifs, 0);
		}
	    }
	}
    }

    /* Update the RP entries */
    for (cand_rp = cand_rp_list; cand_rp; cand_rp = cand_rp->next) {
	if (cand_rp->rpentry->upstream != nbr_delete)
	    continue;

	rp = cand_rp->rpentry;

	/* Reset the RP entry iif
	 * TODO: check if error setting the iif! */
	if (local_address(rp->address) == NO_VIF) {
	    set_incoming(rp, PIM_IIF_RP);
	} else {
	    rp->incoming = PIMREG_VIF;
	    rp->upstream = NULL;
	}

	mrt = rp->mrtlink;
	if (mrt) {
	    mrt->upstream   = rp->upstream;
	    mrt->metric     = rp->metric;
	    mrt->preference = rp->preference;
	    change_interfaces(mrt,
			      rp->incoming,
			      mrt->joined_oifs,
			      mrt->pruned_oifs,
			      mrt->leaves,
			      mrt->asserted_oifs, 0);
	}

	/* Update the group entries for this RP */
	for (rp_grp = cand_rp->rp_grp_next; rp_grp; rp_grp = rp_grp->rp_grp_next) {
	    for (grp = rp_grp->grplink; grp; grp = grp->rpnext) {

		mrt = grp->grp_route;
		if (mrt) {
		    mrt->upstream   = rp->upstream;
		    mrt->metric     = rp->metric;
		    mrt->preference = rp->preference;
		    change_interfaces(mrt,
				      rp->incoming,
				      mrt->joined_oifs,
				      mrt->pruned_oifs,
				      mrt->leaves,
				      mrt->asserted_oifs, 0);
		}

		/* Update only the (S,G)RPbit entries for this group */
		for (mrt_srcs = grp->mrtlink; mrt_srcs; mrt_srcs = mrt_srcs->grpnext) {
		    if (mrt_srcs->flags & MRTF_RP) {
			mrt_srcs->upstream   = rp->upstream;
			mrt_srcs->metric     = rp->metric;
			mrt_srcs->preference = rp->preference;
			change_interfaces(mrt_srcs,
					  rp->incoming,
					  mrt_srcs->joined_oifs,
					  mrt_srcs->pruned_oifs,
					  mrt_srcs->leaves,
					  mrt_srcs->asserted_oifs, 0);
		    }
		}
	    }
	}
    }

    /*
     * Fix GitHub issue #22: Crash in (S,G) state when neighbor is lost.
     *
     * Every mrtentry_t is linked into a group list, so this sweep sees the
     * entries the loops above cannot.  One whose upstream came from a
     * received Assert names the assert winner, and that is by construction
     * a different neighbor from the one its source or its RP entry points
     * at -- receive_pim_assert() only takes that branch when the two
     * differ.  Such an entry is visited by neither loop above, so the
     * pointer would outlive the free() below and the next Join/Prune pass
     * would write through it in add_jp_entry().
     */
    for (grp = grplist; grp; grp = grp->next) {
	if (grp->grp_route)
	    reset_upstream_router(grp->grp_route, nbr_delete);

	for (mrt_srcs = grp->mrtlink; mrt_srcs; mrt_srcs = mrt_srcs->grpnext)
	    reset_upstream_router(mrt_srcs, nbr_delete);
    }

    /* "NLT Expires" in the Loser state of both Assert state machines: an
     * interface held off for a winner that is gone is loss for nothing. */
    assert_neighbor_gone(nbr_delete->vifi, nbr_delete->address, "went away");

    free(nbr_delete);
}

/*
 * If all PIM routers on a network segment support DR-Priority we use
 * that to elect the DR, and use the highest IP address as the tie
 * breaker.  If any routers does *not* support DR-Priority all routers
 * must use the IP address to elect the DR, this for backwards compat.
 *
 * Returns TRUE if we lost the DR role, elected another router.
 */
static int dr_election(struct uvif *v)
{
    int was_dr = 0, use_dr_prio = 1;
    uint32_t best_dr_prio = 0;
    pim_nbr_entry_t *best_nbr = NULL;
    pim_nbr_entry_t *nbr;

    if (v->uv_flags & VIFF_DR)
	was_dr = 1;

    if (!v->uv_pim_neighbors) {
	/* This was our last neighbor, now we're it. */
	IF_DEBUG(DEBUG_PIM_HELLO)
	    logit(LOG_INFO, 0, "All neighbor PIM routers on %s lost, we are the DR now.", v->uv_name);

	v->uv_flags &= ~VIFF_PIM_NBR;
	v->uv_flags |= (VIFF_NONBRS | VIFF_DR);
	v->uv_pim_neighbor_dr = NULL;

	return FALSE;
    }

    /* Check if all routers on segment advertise DR Priority option
     * in their PIM Hello messages.  Figure out highest prio. */
    for (nbr = v->uv_pim_neighbors; nbr; nbr = nbr->next) {
	if (!nbr->dr_prio_present) {
	    use_dr_prio = 0;
	    break;
	}

	/* Save highest prio / highest IP as best neighbor */
	if (nbr->dr_prio > best_dr_prio)
	{
	    best_nbr = nbr;
	    best_dr_prio = nbr->dr_prio;
	}
    }

    /*
     * RFC4601 sec. 4.3.2
     */
    if (use_dr_prio) {
	IF_DEBUG(DEBUG_PIM_HELLO)
	    logit(LOG_INFO, 0, "All routers in %s segment support DR Priority based DR election.",
		  inet_fmt(v->uv_lcl_addr, s1, sizeof(s1)));

	if (best_dr_prio < v->uv_dr_prio) {
	    v->uv_flags |= VIFF_DR;
	    v->uv_pim_neighbor_dr = NULL;
	    return FALSE;
	}

	if (best_dr_prio == v->uv_dr_prio) {
	    /* Nobody outranked a DR priority of 0, so no neighbor was
	     * recorded above and every one of them ties with us.  The
	     * list heads on the highest address, which is the winner
	     * the tiebreak below is looking for. */
	    if (!best_nbr)
		best_nbr = v->uv_pim_neighbors;

	    goto tiebreak;
	}
    } else {
	best_nbr = v->uv_pim_neighbors;
      tiebreak:
	IF_DEBUG(DEBUG_PIM_HELLO)
	    logit(LOG_INFO, 0, "Using fallback DR election on %s.", v->uv_name);

	if (ntohl(v->uv_lcl_addr) > ntohl(best_nbr->address)) {
	    /* The first address is the new potential remote
	     * DR address, but the local address is the winner. */
	    v->uv_flags |= VIFF_DR;
	    v->uv_pim_neighbor_dr = NULL;
	    return FALSE;
	}
    }

    v->uv_flags &= ~VIFF_DR;
    v->uv_pim_neighbor_dr = best_nbr;

    if (was_dr) {
	IF_DEBUG(DEBUG_PIM_HELLO)
	    logit(LOG_INFO, 0, "We lost DR role on %s in election.", v->uv_name);

	return TRUE;		/* Lost election, clean up. */
    }

    return FALSE;
}


/*
 * Run the election, then let the routing entries follow it: local members
 * count toward the outgoing interfaces only on an interface where we are the
 * DR, so gaining or losing the role changes what we forward onto that subnet.
 */
static int restart_dr_election(struct uvif *v)
{
    int was_dr = (v->uv_flags & VIFF_DR) ? 1 : 0;
    int result;

    result = dr_election(v);

    if (was_dr != ((v->uv_flags & VIFF_DR) ? 1 : 0))
	recalc_local_members(v - uvifs);

    return result;
}

static int validate_pim_opt(uint32_t src, char *str, uint16_t len, uint16_t opt_len)
{
    if (len != opt_len) {
	IF_DEBUG(DEBUG_PIM_HELLO)
	    logit(LOG_INFO, 0, "PIM HELLO %s from %s: invalid OptionLength = %u",
		  str, inet_fmt(src, s1, sizeof(s1)), opt_len);

	return FALSE;
    }

    return TRUE;
}

/*
 * RFC 7761 sec. 4.9.2: unknown options "MUST be ignored and MUST NOT prevent
 * a neighbor relationship from being formed", and neither must a Hello that
 * carries no options at all.  Only an option we do understand, arriving with
 * a length it cannot have, fails the message.
 */
static int parse_pim_hello(char *msg, size_t len, uint32_t src, pim_hello_opts_t *opts)
{
    size_t rec_len;
    uint8_t *data;
    uint16_t opt_type;
    uint16_t opt_len;

    /* Assume no opts. */
    memset(opts, 0, sizeof(*opts));

    /* Body of PIM message */
    msg += sizeof(pim_header_t);

    /* Ignore any data if shorter than (pim_hello header) */
    for (len -= sizeof(pim_header_t); len >= sizeof(pim_hello_t); len -= rec_len) {
	data = (uint8_t *)msg;
	GET_HOSTSHORT(opt_type, data);
	GET_HOSTSHORT(opt_len,  data);

	/* The option has to fit in what is left of the message before its
	 * value is read, not after: validate_pim_opt() compares opt_len
	 * against the length the option is defined to have and never
	 * against the message, so a truncated final option would be read
	 * past the end and only then rejected.
	 */
	rec_len = (sizeof(pim_hello_t) + opt_len);
	if (len < rec_len)
	    return FALSE;

	switch (opt_type) {
	    case PIM_HELLO_HOLDTIME:
		if (validate_pim_opt(src, "Holdtime", PIM_HELLO_HOLDTIME_LEN, opt_len) == FALSE)
		    return FALSE;

		opts->holdtime_present = 1;
		GET_HOSTSHORT(opts->holdtime, data);
		break;

	    case PIM_HELLO_DR_PRIO:
		if (validate_pim_opt(src, "DR Priority", PIM_HELLO_DR_PRIO_LEN, opt_len) == FALSE)
		    return FALSE;

		opts->dr_prio_present = 1;
		GET_HOSTLONG(opts->dr_prio, data);
		break;

	    case PIM_HELLO_GENID:
		if (validate_pim_opt(src, "GenID", PIM_HELLO_GENID_LEN, opt_len) == FALSE)
		    return FALSE;

		GET_HOSTLONG(opts->genid, data);
		break;

	    case PIM_HELLO_LAN_PRUNE_DELAY: {
		uint16_t delay;

		if (validate_pim_opt(src, "LAN Prune Delay", PIM_HELLO_LAN_PRUNE_DELAY_LEN, opt_len) == FALSE)
		    return FALSE;

		GET_HOSTSHORT(delay, data);
		opts->lan_delay_present = 1;
		opts->tracking_support  = (delay & PIM_LAN_PRUNE_DELAY_T_BIT) ? 1 : 0;
		opts->propagation_delay = delay & ~PIM_LAN_PRUNE_DELAY_T_BIT;
		GET_HOSTSHORT(opts->override_interval, data);
		break;
	    }

	    default:
		break;		/* Ignore any unknown options */
	}

	/* Move to the next option */
	msg += rec_len;
    }

    /*
     * RFC 7761 sec. 4.3.2: the Neighbor Liveness Timer is reset to the
     * Holdtime option, "or to Default_Hello_Holdtime if the Hello message
     * does not contain the Holdtime option".  The option is a SHOULD, so a
     * neighbor may legitimately omit it; reading that as the holdtime 0 of
     * a router going down deleted such a neighbor on every Hello.
     */
    if (!opts->holdtime_present)
	opts->holdtime = pim_timer_hello_holdtime;

    return TRUE;
}

static void cache_nbr_settings(pim_nbr_entry_t *nbr, pim_hello_opts_t *opts)
{
    SET_TIMER(nbr->timer,  opts->holdtime);
    nbr->genid           = opts->genid;
    nbr->dr_prio         = opts->dr_prio;
    nbr->dr_prio_present = opts->dr_prio_present;

    /* RFC 7761 sec. 4.3.3.  A neighbor that stops advertising the option
     * takes the whole link back to the defaults, so the absent case is
     * recorded rather than left at what the last Hello said. */
    nbr->lan_delay_present = opts->lan_delay_present;
    nbr->tracking_support  = opts->tracking_support;
    nbr->propagation_delay = opts->propagation_delay;
    nbr->override_interval = opts->override_interval;
}

/*
 * RFC 7761 sec. 4.3.3: "the information provided in the LAN Prune Delay
 * option is not used unless all neighbors on a link advertise the option".
 * A link with no neighbors at all answers TRUE, and the effective values
 * below are then our own, which is what a router alone on a segment would
 * have negotiated with itself.
 */
static int lan_delay_enabled(vifi_t vifi)
{
    pim_nbr_entry_t *nbr;

    for (nbr = uvifs[vifi].uv_pim_neighbors; nbr; nbr = nbr->next) {
	if (!nbr->lan_delay_present)
	    return FALSE;
    }

    return TRUE;
}

/* Effective_Propagation_Delay(I) and Effective_Override_Interval(I) of the
 * same section: the largest value anyone on the link advertises, ours
 * included, or the default where the option is not universal. */
static uint16_t effective_propagation_delay(vifi_t vifi)
{
    uint16_t delay = PIM_MSEC(PIM_PROPAGATION_DELAY);
    pim_nbr_entry_t *nbr;

    if (!lan_delay_enabled(vifi))
	return delay;

    for (nbr = uvifs[vifi].uv_pim_neighbors; nbr; nbr = nbr->next) {
	if (nbr->propagation_delay > delay)
	    delay = nbr->propagation_delay;
    }

    return delay;
}

static uint16_t effective_override_interval(vifi_t vifi)
{
    uint16_t delay = PIM_MSEC(PIM_OVERRIDE_INTERVAL);
    pim_nbr_entry_t *nbr;

    if (!lan_delay_enabled(vifi))
	return delay;

    for (nbr = uvifs[vifi].uv_pim_neighbors; nbr; nbr = nbr->next) {
	if (nbr->override_interval > delay)
	    delay = nbr->override_interval;
    }

    return delay;
}

/*
 * J/P_Override_Interval(I), sec. 4.11: the two effective values added.  The
 * wire carries milliseconds and every timer here is whole seconds, so the
 * sum is rounded up -- a window rounded down is one a downstream router can
 * miss, and the section exists to give it one.
 */
static uint16_t jp_override_interval(vifi_t vifi)
{
    uint32_t msec = effective_propagation_delay(vifi) + effective_override_interval(vifi);

    return (msec + 999) / 1000;
}

/* The Prune-Pending Timer of sec. 4.5.1 and sec. 4.5.2.  The point-to-point
 * flag used to stand in for the single-neighbor test, which is not the same
 * question: a shared segment with one PIM router left on it has nobody to
 * override either. */
static uint16_t prune_pending_delay(vifi_t vifi)
{
    struct uvif *v = &uvifs[vifi];

    if (!v->uv_pim_neighbors || !v->uv_pim_neighbors->next)
	return 0;

    return jp_override_interval(vifi);
}

int send_pim_hello(struct uvif *v, uint16_t holdtime)
{
    char   *buf;
    uint8_t *data;
    size_t  len;

    IF_DEBUG(DEBUG_PIM_HELLO)
	logit(LOG_DEBUG, 0, "Sending PIM HELLO on %s", v->uv_name);

    buf = pim_send_buf + sizeof(struct ip) + sizeof(pim_header_t);
    data = (uint8_t *)buf;
    PUT_HOSTSHORT(PIM_HELLO_HOLDTIME, data);
    PUT_HOSTSHORT(PIM_HELLO_HOLDTIME_LEN, data);
    PUT_HOSTSHORT(holdtime, data);

    /* RFC 7761 sec. 4.3.3 wants this on every multi-access LAN, and an
     * upstream that does not see it falls back to its own defaults -- which
     * for pimd's own downstream neighbors used to mean the option was never
     * on the wire at all.  The T bit stays clear: it advertises the ability
     * to disable Join suppression, which pimd does not have. */
    PUT_HOSTSHORT(PIM_HELLO_LAN_PRUNE_DELAY, data);
    PUT_HOSTSHORT(PIM_HELLO_LAN_PRUNE_DELAY_LEN, data);
    PUT_HOSTSHORT(PIM_MSEC(PIM_PROPAGATION_DELAY), data);
    PUT_HOSTSHORT(PIM_MSEC(PIM_OVERRIDE_INTERVAL), data);

    PUT_HOSTSHORT(PIM_HELLO_DR_PRIO, data);
    PUT_HOSTSHORT(PIM_HELLO_DR_PRIO_LEN, data);
    PUT_HOSTLONG(v->uv_dr_prio, data);

    PUT_HOSTSHORT(PIM_HELLO_GENID, data);
    PUT_HOSTSHORT(PIM_HELLO_GENID_LEN, data);
    PUT_HOSTLONG(v->uv_genid, data);

    len = data - (uint8_t *)buf;
    send_pim(pim_send_buf, v->uv_lcl_addr, allpimrouters_group, PIM_HELLO, len);
    SET_TIMER(v->uv_hello_timer, pim_timer_hello_interval);

    return TRUE;
}


/************************************************************************
 *                        PIM_REGISTER
 ************************************************************************/
/* TODO: XXX: IF THE BORDER BIT IS SET, THEN
 * FORWARD THE WHOLE PACKET FROM USER SPACE
 * AND AT THE SAME TIME IGNORE ANY CACHE_MISS
 * SIGNALS FROM THE KERNEL.
 */
int receive_pim_register(uint32_t reg_src, uint32_t reg_dst, char *msg, size_t len)
{
    uint32_t inner_src, inner_grp;
    pim_register_t *reg;
    struct ip *ip;
    uint32_t is_null;
    mrtentry_t *mrtentry;
    mrtentry_t *mrtentry2;
    rpentry_t *rp;
    uint8_t oifs[MAXVIFS];

    /*
     * If instance specific multicast routing table is in use, check
     * that we are the target of the register packet. Otherwise we
     * might end up responding to register packet belonging to another
     * pimd instance.
     *
     * This is RFC 7761 sec. 4.4.2's "if (outer.dst is not one of my
     * addresses) drop the packet silently".  It used to be gated on
     * cand_rp_flag as well, which dropped every Register on a pimd
     * whose RP came from a static rp-address rather than an election.
     */
    if (mrt_table_id != 0) {
        if (!i_am_rp(reg_dst)) {
            IF_DEBUG(DEBUG_PIM_REGISTER)
                logit(LOG_DEBUG, 0, "PIM register: packet from %s to %s is not destined for us",
		      inet_fmt(reg_src, s1, sizeof(s1)), inet_fmt(reg_dst, s2, sizeof(s2)));

            return FALSE;
        }
    }

    /* RFC 7761 sec. 6.2: the range of senders an RP accepts
     * Register-encapsulated packets from is configurable, and accepts
     * everything until it is configured.  Nothing is sent back to a sender
     * outside it: a Register-Stop would tell a forger it found the RP, and
     * sec. 6.1.2's attacker is anywhere in the network rather than on a
     * link we can see.
     *
     * This is the control plane only, and cannot be otherwise.  The kernel
     * decapsulates a Register and loops the inner packet back on the
     * register vif before the daemon is given its copy of the header --
     * FreeBSD's pim_input() does it in ip_mroute.c and Linux's ipmr is
     * built the same way -- so what this refuses is the state, the
     * Keepalive Timer refresh and the Register-Stop, not the bytes.  An RP
     * that has to keep forged traffic off the shared tree needs a packet
     * filter on IP protocol 103 as well; pimd.conf.5 says so.
     */
    if (!register_accepted_from(reg_src)) {
	IF_DEBUG(DEBUG_PIM_REGISTER)
	    logit(LOG_DEBUG, 0, "PIM register from %s: sender not in the register-accept-from list",
		  inet_fmt(reg_src, s1, sizeof(s1)));

	return FALSE;
    }

    IF_DEBUG(DEBUG_PIM_REGISTER)
        logit(LOG_DEBUG, 0, "Received PIM register: len = %zu from %s",
              len, inet_fmt(reg_src, s1, sizeof(s1)));

    /*
     * Message length validation.
     * This is suppose to be done in the kernel, but some older kernel
     * versions do not pefrorm the check for the NULL register messages.
     */
    if (len < sizeof(pim_header_t) + sizeof(pim_register_t) + sizeof(struct ip)) {
	IF_DEBUG(DEBUG_PIM_REGISTER)
	    logit(LOG_INFO, 0, "PIM register: short packet (len = %zu) from %s",
		  len, inet_fmt(reg_src, s1, sizeof(s1)));

	return FALSE;
    }

    /*
     * XXX: For PIM_REGISTER the checksum does not include
     * the inner IP packet. However, some older routers might
     * create the checksum over the whole packet. Hence,
     * verify the checksum over the first 8 bytes, and if fails,
     * then over the whole Register
     */
    if ((inet_cksum((uint16_t *)msg, sizeof(pim_header_t) + sizeof(pim_register_t)))
	&& (inet_cksum((uint16_t *)msg, len))) {
	IF_DEBUG(DEBUG_PIM_REGISTER)
	    logit(LOG_INFO, 0, "PIM REGISTER from DR %s: invalid PIM header checksum",
		  inet_fmt(reg_src, s1, sizeof(s1)));

	return FALSE;
    }

    /* Lookup register message flags */
    reg = (pim_register_t *)(msg + sizeof(pim_header_t));
    is_null   = ntohl(reg->reg_flags) & PIM_REGISTER_NULL_REGISTER_BIT;

    /* initialize the pointer to the encapsulated packet */
    ip = (struct ip *)(msg + sizeof(pim_header_t) + sizeof(pim_register_t));

    /* check the IP version (especially for the NULL register...see above) */
    if (ip->ip_v != IPVERSION && (! is_null)) {
	IF_DEBUG(DEBUG_PIM_REGISTER)
	    logit(LOG_INFO, 0, "PIM register: incorrect IP version (%d) of the inner packet from %s",
		  ip->ip_v, inet_fmt(reg_src, s1, sizeof(s1)));

	return FALSE;
    }

    /* RFC 7761 sec. 4.9.3, the one rule the receiver of a Null-Register is
     * given: "if the Header Checksum field is non-zero, the recipient
     * SHOULD check the checksum and discard Null-Registers that have a bad
     * checksum ... If the Header Checksum field is zero, the recipient MUST
     * NOT check the checksum."  pimd already follows the surprising half of
     * the same paragraph -- the individual fields are not inspected, and
     * the IP version test above is waived for a Null-Register -- but read
     * neither checksum, so the source and group taken out of that header,
     * and the Register-Stop and Keepalive Timer refresh they drive, rested
     * on nothing at all.
     */
    if (is_null && ip->ip_sum != 0) {
	size_t hlen = (size_t)ip->ip_hl << 2;
	size_t avail = len - sizeof(pim_header_t) - sizeof(pim_register_t);

	/* ip_hl is the sender's to choose and says how much to checksum, so
	 * it is bounded before it is used rather than trusted: the length
	 * test above guarantees one header's worth arrived and no more.
	 */
	if (hlen < sizeof(struct ip) || hlen > avail) {
	    IF_DEBUG(DEBUG_PIM_REGISTER)
		logit(LOG_INFO, 0, "PIM Null-Register from %s: dummy header claims %zu bytes, %zu arrived",
		      inet_fmt(reg_src, s1, sizeof(s1)), hlen, avail);

	    return FALSE;
	}

	if (inet_cksum((uint16_t *)ip, hlen)) {
	    IF_DEBUG(DEBUG_PIM_REGISTER)
		logit(LOG_INFO, 0, "PIM Null-Register from %s: bad checksum in the dummy IP header",
		      inet_fmt(reg_src, s1, sizeof(s1)));

	    return FALSE;
	}
    }

    /* We are keeping all addresses in network order, so no need for ntohl()*/
    inner_src = ip->ip_src.s_addr;
    inner_grp = ip->ip_dst.s_addr;

    /*
     * inner_src and inner_grp must be valid IP unicast and multicast address
     * respectively. XXX: not in the spec.
     * PIM-SSM support: inner_grp must not be in PIM-SSM range
     */
    if ((!inet_valid_host(inner_src)) || (!IN_MULTICAST(ntohl(inner_grp))) || IN_PIM_SSM_RANGE(inner_grp)) {
	if (!inet_valid_host(inner_src))
	    logit(LOG_WARNING, 0, "Inner source address of register message by %s is invalid: %s",
		  inet_fmt(reg_src, s1, sizeof(s1)), inet_fmt(inner_src, s2, sizeof(s2)));

	if (!IN_MULTICAST(ntohl(inner_grp)))
	    logit(LOG_WARNING, 0, "Inner group address of register message by %s is invalid: %s",
		  inet_fmt(reg_src, s1, sizeof(s1)), inet_fmt(inner_grp, s2, sizeof(s2)));

	send_pim_register_stop(reg_dst, reg_src, inner_grp, inner_src);

	return FALSE;
    }

    mrtentry = find_route(inner_src, inner_grp, MRTF_WC, DONT_CREATE);
    if (!mrtentry) {
	IF_DEBUG(DEBUG_PIM_REGISTER)
	    logit(LOG_DEBUG, 0, "Not interested in group %s yet", inet_fmt(inner_grp, s2, sizeof(s2)));

	/* TODO: XXX: shouldn't it be inner_src=INADDR_ANY? Not in the spec. */
	send_pim_register_stop(reg_dst, reg_src, inner_grp, inner_src);

	/*
	 * Creating the (S,G) here, ahead of the next Register, is what
	 * saves the DR a retry.  RFC 7761 sec. 4.4.2 allows it only where
	 * "I_am_RP(G) AND outer.dst == RP(G)" holds though: everywhere else
	 * a Register is answered with a Register-Stop and nothing more.
	 * Without the test any host able to unicast to us makes us hold an
	 * entry, and its source and group entries, for every (S,G) it cares
	 * to name, each for PIM_DATA_TIMEOUT seconds.
	 */
	rp = rp_match(inner_grp);
	if (!i_am_rp(reg_dst) || !rp || rp->address != reg_dst) {
	    IF_DEBUG(DEBUG_PIM_REGISTER)
		logit(LOG_DEBUG, 0, "Not RP in address %s, no state for group %s source %s",
		      inet_fmt(reg_dst, s1, sizeof(s1)), inet_fmt(inner_grp, s2, sizeof(s2)),
		      inet_fmt(inner_src, s3, sizeof(s3)));

	    return TRUE;
	}

        mrtentry = find_route(inner_src, inner_grp, MRTF_SG, CREATE);
        if (!mrtentry || !(mrtentry->flags & MRTF_NEW))
           return TRUE;

        SET_TIMER(mrtentry->entry_timer, PIM_DATA_TIMEOUT);
        mrtentry->flags &= ~MRTF_NEW;
        change_interfaces(mrtentry,
                          mrtentry->incoming,
                          mrtentry->joined_oifs,
                          mrtentry->pruned_oifs,
                          mrtentry->leaves,
                          mrtentry->asserted_oifs, 0);

	return TRUE;
    }

    mrtentry = find_route(inner_src, inner_grp, MRTF_SG | MRTF_WC, DONT_CREATE);

    /* Check if I am the RP for that group */
    if ((local_address(reg_dst) == NO_VIF) || !check_mrtentry_rp(mrtentry, reg_dst)) {
	IF_DEBUG(DEBUG_PIM_REGISTER)
	    logit(LOG_DEBUG, 0, "Not RP in address %s", inet_fmt(reg_dst, s1, sizeof(s1)));

	send_pim_register_stop(reg_dst, reg_src, inner_grp, inner_src);

	return TRUE;
    }

    /* I am the RP */

    if (mrtentry->flags & MRTF_SG) {
	/* (S,G) found */
	/* TODO: check the timer again */
	SET_TIMER(mrtentry->entry_timer, PIM_DATA_TIMEOUT); /* restart timer */
	if (!(mrtentry->flags & MRTF_SPT)) { /* The SPT bit is not set */
	    if (!is_null) {
		calc_oifs(mrtentry, oifs);
		/* RFC 7761 sec. 4.4.2 asks for an empty inherited_olist(S,G)
		 * and nothing else.  Requiring the entry's incoming interface
		 * to be the register vif as well, i.e. that it sits on the
		 * shared tree, left an (S,G) whose iif points at the source
		 * matching neither this arm nor the SPT one below: the RP
		 * then neither forwarded nor suppressed, and the DR went on
		 * encapsulating the whole stream into a router dropping it.
		 */
		if (PIMD_VIFM_ISEMPTY(oifs)) {
		    IF_DEBUG(DEBUG_PIM_REGISTER)
			logit(LOG_DEBUG, 0, "No output intefaces found for group %s source %s",
			      inet_fmt(inner_grp, s1, sizeof(s1)), inet_fmt(inner_src, s2, sizeof(s2)));

		    send_pim_register_stop(reg_dst, reg_src, inner_grp, inner_src);

		    return TRUE;
		}

		return TRUE;
	    }

	    /* TODO: XXX: if NULL_REGISTER and has (S,G) with SPT=0, then..?*/
	    return TRUE;
	}
	else {
	    /* The SPT bit is set */
	    IF_DEBUG(DEBUG_PIM_REGISTER)
		logit(LOG_DEBUG, 0, "SPT bit is set for group %s source %s",
		      inet_fmt(inner_grp, s1, sizeof(s1)), inet_fmt(inner_src, s2, sizeof(s2)));

	    send_pim_register_stop(reg_dst, reg_src, inner_grp, inner_src);

	    return TRUE;
	}
    }
    if (mrtentry->flags & MRTF_WC) {
	/* First PIM Register for this routing entry, log it */
	IF_DEBUG(DEBUG_PIM_REGISTER)
	    logit(LOG_INFO, 0, "Received PIM REGISTER: src %s, group %s",
		  inet_fmt(reg_src, s1, sizeof(s1)), inet_fmt(inner_grp, s2, sizeof(s2)));

	/* (*,G) entry */
	calc_oifs(mrtentry, oifs);
	if (PIMD_VIFM_ISEMPTY(oifs)) {
	    IF_DEBUG(DEBUG_PIM_REGISTER)
		logit(LOG_DEBUG, 0, "No output intefaces found for group %s source %s (*,G)",
		      inet_fmt(inner_grp, s1, sizeof(s1)), inet_fmt(inner_src, s2, sizeof(s2)));

	    /* Name the source rather than sending the RFC 2362 "stop
	     * encapsulating every source of this group": RFC 7761 sec. 4.4.1
	     * says an RP should not send a Register-Stop(*,G), and sec. 4.4.2
	     * has only Register-Stop(S,G) to send here.
	     */
	    send_pim_register_stop(reg_dst, reg_src, inner_grp, inner_src);

	    return FALSE;
	} else { /* XXX: TODO: check with the spec again */
	    if (!is_null) {
		uint32_t mfc_source = inner_src;

		/* Install cache entry in the kernel */
		/* TODO: XXX: probably redundant here, because the
		 * decapsulated mcast packet in the kernel will
		 * result in CACHE_MISS
		 */
#ifdef KERNEL_MFC_WC_G
		if (!(mrtentry->flags & MRTF_MFC_CLONE_SG))
		    mfc_source = INADDR_ANY_N;
#endif /* KERNEL_MFC_WC_G */
		add_kernel_cache(mrtentry, mfc_source, inner_grp, 0);
		k_chg_mfc(igmp_socket, mfc_source, inner_grp,
			  mrtentry->incoming, mrtentry->oifs,
			  mrtentry->group->rpaddr);

		return TRUE;
	    }
	}

	return TRUE;
    }

    /* Shoudn't happen: invalid routing entry? */
    /* XXX: TODO: shoudn't be inner_src=INADDR_ANY? Not in the spec. */
    IF_DEBUG(DEBUG_PIM_REGISTER)
	logit(LOG_DEBUG, 0, "Shoudn't happen: invalid routing entry? (%s, %s, %s, %s)",
	      inet_fmt(reg_dst, s1, sizeof(s1)), inet_fmt(reg_src, s2, sizeof(s2)),
	      inet_fmt(inner_grp, s3, sizeof(s3)), inet_fmt(inner_src, s4, sizeof(s4)));

    send_pim_register_stop(reg_dst, reg_src, inner_grp, inner_src);

    return TRUE;
}


int send_pim_register(char *packet, size_t len)
{
    struct ip  *ip;
    uint32_t     source, group;
    vifi_t	vifi;
    rpentry_t  *rpentry;
    mrtentry_t *mrtentry;
    mrtentry_t *mrtentry2;
    uint32_t     reg_src, reg_dst;
    int		reg_mtu, pktlen = 0;
    char       *buf;

    /* `len` is what the kernel actually handed up behind its own header.
     * Both the addresses read here and the copy further down are inside the
     * encapsulated packet, so neither may be reached on the word of its own
     * ip_len: a header that claims more than arrived would have us send the
     * bytes that follow it in the receive buffer to the RP.
     */
    if (len < sizeof(struct ip)) {
	logit(LOG_WARNING, 0, "Kernel upcall too short (%zu bytes) for the packet to register", len);
	return FALSE;
    }

    ip     = (struct ip *)packet;
    source = ip->ip_src.s_addr;
    group  = ip->ip_dst.s_addr;

    pktlen = ntohs(ip->ip_len);
    if (pktlen < (int)sizeof(struct ip) || (size_t)pktlen > len) {
	logit(LOG_WARNING, 0, "Kernel upcall for %s claims %d bytes, %zu arrived",
	      inet_fmt(group, s1, sizeof(s1)), pktlen, len);
	return FALSE;
    }

    if (IN_PIM_SSM_RANGE(group))
	return FALSE; /* Group is in PIM-SSM range, don't send register. */

    if ((vifi = find_vif_direct_local(source, TRUE)) == NO_VIF)
	return FALSE;

    if (!(uvifs[vifi].uv_flags & VIFF_DR))
	return FALSE;		/* I am not the DR for that subnet */

    rpentry = rp_match(group);
    if (!rpentry)
	return FALSE;		/* No RP for this group */

    if (local_address(rpentry->address) != NO_VIF) {
	/* TODO: XXX: not sure it is working! */
	return FALSE;		/* I am the RP for this group */
    }

    mrtentry = find_route(source, group, MRTF_SG, CREATE);
    if (!mrtentry)
	return FALSE;		/* Cannot create (S,G) state */

    if (mrtentry->flags & MRTF_NEW) {
	/* A new entry, log it */
	reg_src = uvifs[vifi].uv_lcl_addr;
	reg_dst = mrtentry->group->rpaddr;

	IF_DEBUG(DEBUG_PIM_REGISTER)
	    logit(LOG_INFO, 0, "Send PIM REGISTER: src %s dst %s, group %s",
		  inet_fmt(reg_src, s1, sizeof(s1)), inet_fmt(reg_dst, s2, sizeof(s2)),
		  inet_fmt(group, s3, sizeof(s3)));

	mrtentry->flags &= ~MRTF_NEW;
	RESET_TIMER(mrtentry->rs_timer); /* Reset the Register-Suppression timer */
	mrtentry2 = mrtentry->group->grp_route;
	if (!mrtentry2)
	    mrtentry2 = mrtentry->group->active_rp_grp->rp->rpentry->mrtlink;
	if (mrtentry2) {
	    FIRE_TIMER(mrtentry2->jp_timer); /* Timeout the Join/Prune timer */
	    /* TODO: explicitly call this function?
	       send_pim_join_prune(mrtentry2->upstream->vifi,
	       mrtentry2->upstream,
	       PIM_JOIN_PRUNE_HOLDTIME);
	    */
	}
    }
    /* Restart the (S,G) Entry-timer */
    SET_TIMER(mrtentry->entry_timer, PIM_DATA_TIMEOUT);

    IF_TIMER_NOT_SET(mrtentry->rs_timer) {
	/* The Register-Suppression Timer is not running.
	 * Encapsulate the data and send to the RP.
	 */
	buf = pim_send_buf + sizeof(struct ip) + sizeof(pim_header_t);
	memset(buf, 0, sizeof(pim_register_t)); /* No flags set */
	buf += sizeof(pim_register_t);

	/* Copy the data packet at the back of the register packet, at the
	 * length checked against what arrived at the top of this function.
	 */
	memcpy(buf, ip, pktlen);

	pktlen += sizeof(pim_register_t); /* 'sizeof(struct ip) + sizeof(pim_header_t)' added by send_pim()  */
	reg_mtu = uvifs[vifi].uv_mtu; /* XXX: Use PMTU to RP instead! */
	reg_src = uvifs[vifi].uv_lcl_addr;
	reg_dst = mrtentry->group->rpaddr;

	/* `ip` is still the packet the source sent, so its ToS byte is the
	 * ECN bits and the DSCP RFC 7761 sec. 4.4.1 asks us to copy into the
	 * encapsulating header rather than set on our own.
	 */
	send_pim_unicast(pim_send_buf, ip->ip_tos, reg_mtu, reg_src, reg_dst, PIM_REGISTER, pktlen);

	return TRUE;
    }

    return TRUE;
}


int send_pim_null_register(mrtentry_t *mrtentry)
{
    struct ip *ip;
    pim_register_t *pim_register;
    int reg_mtu, pktlen;
    vifi_t vifi;
    uint32_t reg_src, reg_dst;

    /* No directly connected source; no local address */
    if ((vifi = find_vif_direct_local(mrtentry->source->address, TRUE))== NO_VIF)
	return FALSE;

    pim_register = (pim_register_t *)(pim_send_buf + sizeof(struct ip) +
				      sizeof(pim_header_t));
    memset(pim_register, 0, sizeof(pim_register_t));
    pim_register->reg_flags = htonl(pim_register->reg_flags
				    | PIM_REGISTER_NULL_REGISTER_BIT);

    ip = (struct ip *)(pim_register + 1);
    /* set src/dst in dummy hdr */
    ip->ip_v     = IPVERSION;
    ip->ip_hl    = (sizeof(struct ip) >> 2);
    ip->ip_tos   = 0;
    ip->ip_id    = 0;
    ip->ip_off   = 0;
    ip->ip_p     = IPPROTO_PIM;			/* RFC 7761 sec. 4.9.3: 103 */
    ip->ip_len   = htons(sizeof(struct ip));
    ip->ip_ttl   = MINTTL; /* TODO: XXX: check whether need to setup the ttl */
    ip->ip_src.s_addr = mrtentry->source->address;
    ip->ip_dst.s_addr = mrtentry->group->group;
    ip->ip_sum   = 0;
    ip->ip_sum   = inet_cksum((uint16_t *)ip, sizeof(struct ip));

    /* include the dummy ip header */
    pktlen = sizeof(pim_register_t) + sizeof(struct ip);

    reg_mtu = uvifs[vifi].uv_mtu;
    reg_dst = mrtentry->group->rpaddr;
    reg_src = uvifs[vifi].uv_lcl_addr;

    send_pim_unicast(pim_send_buf, 0, reg_mtu, reg_src, reg_dst, PIM_REGISTER, pktlen);

    return TRUE;
}


/************************************************************************
 *                        PIM_REGISTER_STOP
 ************************************************************************/
/* Header, encoded group, encoded source: the whole of what RFC 7761
 * sec. 4.9.4 puts in a Register-Stop, and everything this function reads.
 * pim.c only guarantees a PIM header, so without this a Register-Stop
 * truncated to its header had the parser reading whatever the previous
 * packet left in the receive buffer, and suppressing registers for the
 * (S,G) that came out of it.
 */
#define PIM_REGISTER_STOP_MINLEN (sizeof(pim_header_t) + PIM_ENCODE_GRP_ADDR_LEN \
				  + PIM_ENCODE_UNI_ADDR_LEN)

/* Stop encapsulating this source to the RP: restart the Register-Suppression
 * timer and take the register vif out of the entry's outgoing interfaces.
 * age_routes() puts it back when the timer runs out.
 */
static void suppress_register(mrtentry_t *mrt)
{
    uint8_t pruned_oifs[MAXVIFS];

    SET_TIMER(mrt->rs_timer, (0.5 * PIM_REGISTER_SUPPRESSION_TIMEOUT)
	      + (RANDOM() % (PIM_REGISTER_SUPPRESSION_TIMEOUT + 1)));

    PIMD_VIFM_COPY(mrt->pruned_oifs, pruned_oifs);
    PIMD_VIFM_SET(PIMREG_VIF, pruned_oifs);
    change_interfaces(mrt, mrt->incoming,
		      mrt->joined_oifs, pruned_oifs,
		      mrt->leaves,
		      mrt->asserted_oifs, 0);
}


int receive_pim_register_stop(uint32_t reg_src, uint32_t reg_dst, char *msg, size_t len)
{
    pim_encod_grp_addr_t egaddr;
    pim_encod_uni_addr_t eusaddr;
    uint8_t *data;
    mrtentry_t *mrtentry;
    grpentry_t *grp;

    /* Checksum */
    if (inet_cksum((uint16_t *)msg, len))
	return FALSE;

    /* sanity check for the minimum length */
    if (len < PIM_REGISTER_STOP_MINLEN) {
	IF_DEBUG(DEBUG_PIM_REGISTER)
	    logit(LOG_NOTICE, 0, "Too short Register-Stop message (%zu bytes) from RP %s to %s",
		  len, inet_fmt(reg_src, s1, sizeof(s1)), inet_fmt(reg_dst, s2, sizeof(s2)));

	return FALSE;
    }

    data = (uint8_t *)(msg + sizeof(pim_header_t));
    GET_EGADDR(&egaddr,  data);
    GET_EUADDR(&eusaddr, data);

    if (!encoded_addr_ok(egaddr.addr_family, egaddr.encod_type) ||
	!encoded_addr_ok(eusaddr.addr_family, eusaddr.encod_type)) {
	IF_DEBUG(DEBUG_PIM_REGISTER)
	    logit(LOG_NOTICE, 0, "Ignoring Register-Stop from %s, an encoded address is not IPv4",
		  inet_fmt(reg_src, s1, sizeof(s1)));

	return FALSE;
    }

    IF_DEBUG(DEBUG_PIM_REGISTER)
	logit(LOG_INFO, 0, "Received PIM_REGISTER_STOP from RP %s to %s for src = %s and group = %s",
	      inet_fmt(reg_src, s1, sizeof(s1)), inet_fmt(reg_dst, s2, sizeof(s2)),
	      inet_fmt(eusaddr.unicast_addr, s3, sizeof(s3)),
	      inet_fmt(egaddr.mcast_addr, s4, sizeof(s4)));

    /* TODO: apply the group mask and do register_stop for all grp addresses */
    if (eusaddr.unicast_addr == INADDR_ANY_N) {
	/* An old RP saying RFC 2362's "stop encapsulating all sources for
	 * this group".  RFC 7761 sec. 4.4.1 does not have us send these, but
	 * it does have us accept one, as a Register-Stop(S,G) for every
	 * (S,G) whose Register state machine is not in NoInfo -- i.e. every
	 * source we are registering right now, and none that starts later.
	 */
	grp = find_group(egaddr.mcast_addr);
	if (!grp || !grp->active_rp_grp || grp->rpaddr != reg_src)
	    return FALSE;

	for (mrtentry = grp->mrtlink; mrtentry; mrtentry = mrtentry->grpnext) {
	    if (!(mrtentry->flags & MRTF_SG))
		continue;

	    /* Not registering this source, nothing to suppress. */
	    if (!PIMD_VIFM_ISSET(PIMREG_VIF, mrtentry->joined_oifs))
		continue;

	    suppress_register(mrtentry);
	}

	return TRUE;
    }

    mrtentry = find_route(eusaddr.unicast_addr, egaddr.mcast_addr, MRTF_SG, DONT_CREATE);
    if (!mrtentry)
	return FALSE;

    /* XXX: not in the spec: check if the PIM_REGISTER_STOP originator is
     * really the RP
     */
    if (check_mrtentry_rp(mrtentry, reg_src) == FALSE)
	return FALSE;

    suppress_register(mrtentry);

    return TRUE;
}


/* TODO: optional rate limiting is not implemented yet */
/* Unicasts a REGISTER_STOP message to the DR */
static int
send_pim_register_stop(uint32_t reg_src, uint32_t reg_dst, uint32_t inner_grp, uint32_t inner_src)
{
    char   *buf;
    uint8_t *data;

    /* A Register for a group in the SSM range used to return here without
     * building anything, which left RFC 7761 sec. 4.8.1's second half
     * undone: an RP refuses to forward such a Register, which pimd does,
     * and SHOULD answer it with a Register-Stop, which is the only thing
     * that will ever quiet an SSM-unaware DR down.  Told nothing, it kept
     * encapsulating at the full data rate and the RP kept parsing and
     * discarding one Register per packet for as long as the source sent.
     *
     * The early return dates from when pimd itself might have registered
     * an SSM group; send_pim_register() refuses to build one now, so the
     * only Registers this can answer are somebody else's.
     */
    IF_DEBUG(DEBUG_PIM_REGISTER)
	logit(LOG_INFO, 0, "Send PIM REGISTER STOP from %s to router %s for src = %s and group = %s",
	      inet_fmt(reg_src, s1, sizeof(s1)), inet_fmt(reg_dst, s2, sizeof(s2)),
	      inet_fmt(inner_src, s3, sizeof(s3)), inet_fmt(inner_grp, s4, sizeof(s4)));

    buf  = pim_send_buf + sizeof(struct ip) + sizeof(pim_header_t);
    data = (uint8_t *)buf;
    PUT_EGADDR(inner_grp, SINGLE_GRP_MSKLEN, 0, data);
    PUT_EUADDR(inner_src, data);
    send_pim_unicast(pim_send_buf, 0, 0, reg_src, reg_dst, PIM_REGISTER_STOP, data - (uint8_t *)buf);

    return TRUE;
}


/************************************************************************
 *                        PIM_JOIN_PRUNE
 ************************************************************************/
int join_or_prune(mrtentry_t *mrtentry, pim_nbr_entry_t *upstream_router)
{
    uint8_t entry_oifs[MAXVIFS];
    mrtentry_t *mrtentry_grp;

    if (!mrtentry || !upstream_router)
	return PIM_ACTION_NOTHING;

    calc_oifs(mrtentry, entry_oifs);
    if (mrtentry->flags & MRTF_WC) {
	if (IN_PIM_SSM_RANGE(mrtentry->group->group)) {
	    logit(LOG_DEBUG, 0, "No action for SSM (WC)");
	    return PIM_ACTION_NOTHING;
	}
	/* (*,G) entry */
	/* The (*,G) J/P messages are sent only toward the RP */
	if (upstream_router != mrtentry->upstream)
	    return PIM_ACTION_NOTHING;

	/* TODO: XXX: Can we have (*,*,RP) prune? */
	if (PIMD_VIFM_ISEMPTY(entry_oifs)) {
	    /* NULL oifs */

	    if (!(uvifs[mrtentry->incoming].uv_flags & VIFF_DR))
		/* I am not the DR for that subnet. */
		return PIM_ACTION_PRUNE;

	    if (PIMD_VIFM_ISSET(mrtentry->incoming, mrtentry->leaves))
		/* I am the DR and have local leaves */
		return PIM_ACTION_JOIN;

	    /* Probably the last local member hast timeout */
	    return PIM_ACTION_PRUNE;
	}

	return PIM_ACTION_JOIN;
    }

    if (mrtentry->flags & MRTF_SG) {
	/* (S,G) entry */
	/* TODO: check again */
	if (mrtentry->upstream == upstream_router) {
	    if (!(mrtentry->flags & MRTF_RP)) {
		/* Upstream router toward S.  RFC 7761 sec. 4.5.5 drives this
		 * machine off JoinDesired(S,G), which is state maintenance and
		 * reads the olists of sec. 4.1.5 that subtract lost_assert(S,G)
		 * -- not the one sec. 4.2 forwards off.  Asking calc_oifs()
		 * here, as pimd did, asked the forwarding question of the
		 * Join/Prune machine: a router that lost an assert on the shared
		 * tree to a winner it would beat from the shortest path tree
		 * then pruned the source whose traffic it needs to get there,
		 * and the two never resolved.
		 */
		if (!join_desired(mrtentry)) {
		    if (mrtentry->group->active_rp_grp &&
			i_am_rp(mrtentry->group->rpaddr)) {
			/* (S,G) at the RP. Don't send Join/Prune
			 * (see the end of Section 3.3.2)
			 */
			return PIM_ACTION_NOTHING;
		    }

		    return PIM_ACTION_PRUNE;
		}
		else {
		    return PIM_ACTION_JOIN;
		}
	    }
	    else {
		if (IN_PIM_SSM_RANGE(mrtentry->group->group)) {
		    logit(LOG_DEBUG, 0, "No action for SSM (RP)");
		    return PIM_ACTION_NOTHING;
		}
		/* Upstream router toward RP */
		if (PIMD_VIFM_ISEMPTY(entry_oifs))
		    return PIM_ACTION_PRUNE;
	    }
	}

	/* Looks like the case when the upstream router toward S is
	 * different from the upstream router toward RP
	 */
	if (!mrtentry->group->active_rp_grp)
	    return PIM_ACTION_NOTHING;

	mrtentry_grp = mrtentry->group->grp_route;
	if (!mrtentry_grp) {
	    mrtentry_grp = mrtentry->group->active_rp_grp->rp->rpentry->mrtlink;
	    if (!mrtentry_grp)
		return PIM_ACTION_NOTHING;
	}

	if (mrtentry_grp->upstream != upstream_router)
	    return PIM_ACTION_NOTHING; /* XXX: shoudn't happen */

	if (!(mrtentry->flags & MRTF_RP) && (mrtentry->flags & MRTF_SPT))
	    return PIM_ACTION_PRUNE;
    }

    return PIM_ACTION_NOTHING;
}

/*
 * Log PIM Join/Prune message. Send log event for every join and prune separately.
 * Format of the Join/Prune message starting from dataptr is following:
   ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
   |         Multicast Group Address 1 (Encoded-Group format)      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Number of Joined Sources    |   Number of Pruned Sources    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |        Joined Source Address 1 (Encoded-Source format)        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             .                                 |
   |                             .                                 |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |        Joined Source Address n (Encoded-Source format)        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |        Pruned Source Address 1 (Encoded-Source format)        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             .                                 |
   |                             .                                 |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |        Pruned Source Address n (Encoded-Source format)        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Multicast Group Address m (Encoded-Group format)      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Number of Joined Sources    |   Number of Pruned Sources    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |        Joined Source Address 1 (Encoded-Source format)        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             .                                 |
   |                             .                                 |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |        Joined Source Address n (Encoded-Source format)        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |        Pruned Source Address 1 (Encoded-Source format)        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             .                                 |
   |                             .                                 |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |        Pruned Source Address n (Encoded-Source format)        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
void log_pim_join_prune(uint32_t src, uint8_t *data_ptr, int num_groups, char* ifname)
{
    pim_encod_grp_addr_t encod_group;
    pim_encod_src_addr_t encod_src;
    uint32_t group, source;
    uint16_t num_j_srcs;
    uint16_t num_p_srcs;

    /* Message validity check is done by caller */
    while (num_groups--) {

	GET_EGADDR(&encod_group, data_ptr);
	GET_HOSTSHORT(num_j_srcs, data_ptr);
	GET_HOSTSHORT(num_p_srcs, data_ptr);
	group = encod_group.mcast_addr;

	while (num_j_srcs--) {
	    GET_ESADDR(&encod_src, data_ptr);
	    source = encod_src.src_addr;
	    IF_DEBUG(DEBUG_PIM_JOIN_PRUNE)
		logit(LOG_INFO, 0, "Received PIM JOIN from %s to group %s for source %s on %s",
		      inet_fmt(src, s1, sizeof(s1)), inet_fmt(group, s2, sizeof(s2)),
		      inet_fmt(source, s3, sizeof(s3)), ifname);
	}

	while (num_p_srcs--) {
	    GET_ESADDR(&encod_src, data_ptr);
	    source = encod_src.src_addr;
	    IF_DEBUG(DEBUG_PIM_JOIN_PRUNE)
		logit(LOG_INFO, 0, "Received PIM PRUNE from %s to group %s for source %s on %s",
		      inet_fmt(src, s1, sizeof(s1)), inet_fmt(group, s2, sizeof(s2)),
		      inet_fmt(source, s3, sizeof(s3)), ifname);
	}
    }
}

/* TODO: when parsing, check if we go beyond message size */
/* TODO: too long, simplify it! */
#define PIM_JOIN_PRUNE_MINLEN (4 + PIM_ENCODE_UNI_ADDR_LEN + 4)
/*
 * PruneEcho(*,G), PruneEcho(S,G) and PruneEcho(S,G,rpt), RFC 7761 sec. 4.5.1
 * and sec. 4.5.2: when the Prune-Pending Timer expires and the router really
 * does stop forwarding on the interface, it sends the Prune once more with
 * its own address in the Upstream Neighbor Address field.  "Its purpose is to
 * add additional reliability so that if a Prune that should have been
 * overridden by another router is lost locally on the LAN, then the PruneEcho
 * may be received and cause the override to happen."
 *
 * Not sent on an interface with a single PIM neighbor: there is nobody there
 * whose override could have been lost.  Built here rather than through
 * add_jp_entry(), which addresses a message to a neighbor and this one is
 * addressed to ourselves.
 */
void send_prune_echo(mrtentry_t *mrt, vifi_t vifi)
{
    struct uvif *v = &uvifs[vifi];
    uint32_t source;
    uint8_t flags = USADDR_S_BIT;
    uint8_t *data;
    char *buf;
    size_t len;

    if (!mrt || !mrt->group)
	return;

    if (!v->uv_pim_neighbors || !v->uv_pim_neighbors->next)
	return;

    if (v->uv_flags & (VIFF_DOWN | VIFF_DISABLED | VIFF_REGISTER))
	return;

    if (mrt->flags & MRTF_SG) {
	if (!mrt->source)
	    return;

	source = mrt->source->address;
	if (mrt->flags & MRTF_RP)
	    flags |= USADDR_RP_BIT;
    } else {
	source = mrt->group->rpaddr;
	flags |= USADDR_RP_BIT | USADDR_WC_BIT;
    }

    buf  = pim_send_buf + sizeof(struct ip) + sizeof(pim_header_t);
    data = (uint8_t *)buf;

    PUT_EUADDR(v->uv_lcl_addr, data);	/* Upstream Neighbor Address: ours */
    PUT_BYTE(0, data);			/* Reserved */
    PUT_BYTE(1, data);			/* One group */
    PUT_HOSTSHORT(PIM_JOIN_PRUNE_HOLDTIME, data);
    PUT_EGADDR(mrt->group->group, SINGLE_GRP_MSKLEN, 0, data);
    PUT_HOSTSHORT(0, data);		/* No joined sources */
    PUT_HOSTSHORT(1, data);		/* One pruned source */
    PUT_ESADDR(source, SINGLE_SRC_MSKLEN, flags, data);

    len = data - (uint8_t *)buf;
    IF_DEBUG(DEBUG_PIM_JOIN_PRUNE)
	logit(LOG_INFO, 0, "Send PruneEcho for (%s,%s) on %s",
	      inet_fmt(source, s1, sizeof(s1)),
	      inet_fmt(mrt->group->group, s2, sizeof(s2)), v->uv_name);

    send_pim(pim_send_buf, v->uv_lcl_addr, allpimrouters_group, PIM_JOIN_PRUNE, len);
}

/*
 * "Receive Prune(*,G)" and "Receive Prune(S,G)" of sec. 4.5.1 and sec. 4.5.2:
 * the downstream state machine on I goes to Prune-Pending and starts the
 * Prune-Pending Timer, J/P_Override_Interval(I), or zero where the router has
 * no more than one neighbor on the interface and nobody is left to override.
 *
 * pimd keeps one timer per (entry, interface), the Expiry Timer, so
 * Prune-Pending is that timer lowered to the pending delay.  Nothing is lost
 * by folding the two: "for forwarding purposes, the Prune-Pending state
 * functions exactly like the Join state", and a Join arriving meanwhile
 * raises the timer again, which is the transition back to Join.  What the
 * bitmap adds is which of the two an expiry came from, so that the PruneEcho
 * goes out for a prune and not for a membership that simply ran out.
 *
 * What this replaces was `holdtime/3`, 70 seconds for the usual holdtime and
 * six hours for a Join asking for 0xffff, compounding at every hop.
 */
static void prune_pending(mrtentry_t *mrt, vifi_t vifi)
{
    uint16_t delay = prune_pending_delay(vifi);

    if (delay == 0) {
	/* Nobody to wait for, and nobody to echo to either: a zero delay is
	 * the single-neighbor case, which sec. 4.5.1 excuses the PruneEcho
	 * on.  So the interface is not marked pending at all. */
	FIRE_TIMER(mrt->vif_timers[vifi]);
	return;
    }

    if (mrt->vif_timers[vifi] > delay)
	SET_TIMER(mrt->vif_timers[vifi], delay);

    PIMD_VIFM_SET(vifi, mrt->prune_pending_oifs);
}

int receive_pim_join_prune(uint32_t src, uint32_t dst __attribute__((unused)), char *msg, size_t len)
{
    vifi_t vifi;
    struct uvif *v;
    pim_encod_uni_addr_t eutaddr;
    pim_encod_grp_addr_t egaddr;
    pim_encod_src_addr_t esaddr;
    uint8_t *data;
    uint8_t *data_start;
    uint8_t *data_group_end;
    uint8_t num_groups;
    uint8_t num_groups_tmp;
    uint16_t holdtime;
    uint16_t num_j_srcs;
    uint16_t num_j_srcs_tmp;
    uint16_t num_p_srcs;
    uint32_t source;
    uint32_t group;
    uint32_t s_mask;
    uint32_t g_mask;
    uint8_t s_flags;
    uint8_t reserved __attribute__((unused));
    rpentry_t *rpentry;
    mrtentry_t *mrt;
    mrtentry_t *mrt_srcs;
    mrtentry_t *mrt_rp;
    grpentry_t *grp;
    uint16_t jp_value;
    pim_nbr_entry_t *upstream_router;
    int my_action;
    rp_grp_entry_t *rp_grp;
    uint8_t *data_group_j_start;
    uint8_t *data_group_p_start;
    uint32_t new_join;

    if ((vifi = find_vif_direct(src)) == NO_VIF) {
	/* Either a local vif or somehow received PIM_JOIN_PRUNE from
	 * non-directly connected router. Ignore it.
	 */
	if (local_address(src) == NO_VIF) {
	    IF_DEBUG(DEBUG_PIM_JOIN_PRUNE)
		logit(LOG_INFO, 0, "Ignoring PIM_JOIN_PRUNE from non-directly connected router %s",
		      inet_fmt(src, s1, sizeof(s1)));
	}

	return FALSE;
    }

    /* Checksum */
    if (inet_cksum((uint16_t *)msg, len))
	return FALSE;

    v = &uvifs[vifi];
    if (uvifs[vifi].uv_flags & (VIFF_DOWN | VIFF_DISABLED | VIFF_NONBRS | VIFF_REGISTER))
	return FALSE;    /* Shoudn't come on this interface */

    /* RFC 7761 sec. 4.5: a Join/Prune from an address we have had no PIM
     * Hello from is discarded without further processing.  Being on one of
     * our subnets is not the question, any host there can send this.
     */
    if (!find_pim_nbr_on_vif(vifi, src)) {
	IF_DEBUG(DEBUG_PIM_JOIN_PRUNE)
	    logit(LOG_NOTICE, 0, "Ignoring Join/Prune from %s on %s, no PIM Hello seen from it",
		  inet_fmt(src, s1, sizeof(s1)), v->uv_name);

	return FALSE;
    }

    /* And sec. 6.2's list, which names this message.  A router refused its
     * Hello has no neighbor entry for the test above to find, so this is
     * the same answer twice -- said here because the section says it here.
     */
    if (!pim_nbr_accepted(vifi, src)) {
	IF_DEBUG(DEBUG_PIM_JOIN_PRUNE)
	    logit(LOG_NOTICE, 0, "Ignoring Join/Prune from %s on %s, not in its accept-nbr-from list",
		  inet_fmt(src, s1, sizeof(s1)), v->uv_name);

	return FALSE;
    }

    /* sanity check for the minimum length */
    if (len < PIM_JOIN_PRUNE_MINLEN) {
	IF_DEBUG(DEBUG_PIM_JOIN_PRUNE)
	    logit(LOG_NOTICE, 0, "Too short Join/Prune message (%zu bytes) from %s on %s",
		  len, inet_fmt(src, s1, sizeof(s1)), v->uv_name);

	return FALSE;
    }

    len -= PIM_JOIN_PRUNE_MINLEN;
    data = (uint8_t *)(msg + sizeof(pim_header_t));

    /* Get the target address */
    GET_EUADDR(&eutaddr, data);
    GET_BYTE(reserved, data);
    GET_BYTE(num_groups, data);
    GET_HOSTSHORT(holdtime, data);

    /* sec. 4.9.5 processes the addresses of the upstream neighbor's family
     * and ignores the rest; where that address is not one we can read, the
     * whole message is a message for somebody else.
     */
    if (!encoded_addr_ok(eutaddr.addr_family, eutaddr.encod_type)) {
	IF_DEBUG(DEBUG_PIM_JOIN_PRUNE)
	    logit(LOG_NOTICE, 0, "Ignoring Join/Prune from %s on %s, upstream address family %u type %u is not IPv4",
		  inet_fmt(src, s1, sizeof(s1)), v->uv_name,
		  eutaddr.addr_family, eutaddr.encod_type);
	return FALSE;
    }

    if (num_groups == 0) {
	/* No indication for groups in the message */
	IF_DEBUG(DEBUG_PIM_JOIN_PRUNE)
	    logit(LOG_NOTICE, 0, "No groups in Join/Prune message from %s on %s!",
		  inet_fmt(src, s1, sizeof(s1)), v->uv_name);
	return FALSE;
    }

    IF_DEBUG(DEBUG_PIM_JOIN_PRUNE)
	logit(LOG_INFO, 0, "Received PIM JOIN/PRUNE from %s on %s",
	      inet_fmt(src, s1, sizeof(s1)), v->uv_name);

    /* Sanity check for the message length through all the groups */
    num_groups_tmp = num_groups;
    data_start = data;
    while (num_groups_tmp--) {
        size_t srclen, srcoff;

        /* group addr + #join + #src */
        if (len < PIM_ENCODE_GRP_ADDR_LEN + sizeof(uint32_t)) {
	    IF_DEBUG(DEBUG_PIM_JOIN_PRUNE)
		logit(LOG_NOTICE, 0, "Join/Prune message from %s on %s is"
		      " too short to contain enough data",
		      inet_fmt(src, s1, sizeof(s1)), v->uv_name);
            return FALSE;
        }

	/* The Mask Len of this Encoded-Group, checked here rather than where
	 * it is converted: MASKLEN_TO_MASK() (src/pimd.h) shifts by
	 * 32 - masklen, the byte is the sender's to choose, and the two
	 * passes below convert it at six places.  Bounded and not required
	 * to be SINGLE_GRP_MSKLEN, which sec. 4.9.5.1 asks of a
	 * group-specific set: the (*,*,RP) set RFC 7761 Appendix A removed
	 * carries STAR_STAR_RP_MSKLEN, and the passes below still recognise
	 * one in order to skip it.
	 */
	if (data[PIM_ENCODE_MSKLEN_OFF] > PIM_MAX_MSKLEN) {
	    IF_DEBUG(DEBUG_PIM_JOIN_PRUNE)
		logit(LOG_NOTICE, 0, "Ignoring Join/Prune from %s on %s, group mask length %u is wider than an address",
		      inet_fmt(src, s1, sizeof(s1)), v->uv_name,
		      data[PIM_ENCODE_MSKLEN_OFF]);
	    return FALSE;
	}

	/* And its family and encoding type.  This walk and the two passes
	 * below step over PIM_ENCODE_GRP_ADDR_LEN and
	 * PIM_ENCODE_SRC_ADDR_LEN per record, the IPv4 sizes, so a record
	 * that says it is something else is not merely an address we cannot
	 * use -- it is a record whose fields are not where we will look.
	 */
	if (!encoded_addr_ok(data[PIM_ENCODE_FAMILY_OFF], data[PIM_ENCODE_ETYPE_OFF])) {
	    IF_DEBUG(DEBUG_PIM_JOIN_PRUNE)
		logit(LOG_NOTICE, 0, "Ignoring Join/Prune from %s on %s, group address family %u type %u is not IPv4",
		      inet_fmt(src, s1, sizeof(s1)), v->uv_name,
		      data[PIM_ENCODE_FAMILY_OFF], data[PIM_ENCODE_ETYPE_OFF]);
	    return FALSE;
	}

        len -= (PIM_ENCODE_GRP_ADDR_LEN + sizeof(uint32_t));
        data += PIM_ENCODE_GRP_ADDR_LEN;

        /* joined source addresses and pruned source addresses */
        GET_HOSTSHORT(num_j_srcs, data);
        GET_HOSTSHORT(num_p_srcs, data);
        srclen = (num_j_srcs + num_p_srcs) * PIM_ENCODE_SRC_ADDR_LEN;
        if (len < srclen) {
	    IF_DEBUG(DEBUG_PIM_JOIN_PRUNE)
		logit(LOG_NOTICE, 0, "Join/Prune message from %s on %s is"
		      " too short to contain enough data",
		      inet_fmt(src, s1, sizeof(s1)), v->uv_name);
            return FALSE;
        }

	/* And the Mask Len of every Encoded-Source behind it, which
	 * sec. 4.9.1 does pin to the full address length: "The mask length
	 * MUST be equal to the mask length in bits for the given Address
	 * Family and Encoding Type (32 for IPv4 native) ... A router SHOULD
	 * ignore any messages received with any other mask length."  The
	 * srclen bytes are inside the message by the check just above.
	 */
	for (srcoff = 0; srcoff < srclen; srcoff += PIM_ENCODE_SRC_ADDR_LEN) {
	    if (!encoded_addr_ok(data[srcoff + PIM_ENCODE_FAMILY_OFF],
				 data[srcoff + PIM_ENCODE_ETYPE_OFF])) {
		IF_DEBUG(DEBUG_PIM_JOIN_PRUNE)
		    logit(LOG_NOTICE, 0, "Ignoring Join/Prune from %s on %s, source address family %u type %u is not IPv4",
			  inet_fmt(src, s1, sizeof(s1)), v->uv_name,
			  data[srcoff + PIM_ENCODE_FAMILY_OFF],
			  data[srcoff + PIM_ENCODE_ETYPE_OFF]);
		return FALSE;
	    }

	    if (data[srcoff + PIM_ENCODE_MSKLEN_OFF] == SINGLE_SRC_MSKLEN)
		continue;

	    IF_DEBUG(DEBUG_PIM_JOIN_PRUNE)
		logit(LOG_NOTICE, 0, "Ignoring Join/Prune from %s on %s, source mask length %u is not %u",
		      inet_fmt(src, s1, sizeof(s1)), v->uv_name,
		      data[srcoff + PIM_ENCODE_MSKLEN_OFF], SINGLE_SRC_MSKLEN);
	    return FALSE;
	}

        len -= srclen;
        data += srclen;
    }
    data = data_start;
    num_groups_tmp = num_groups;

    /* Sanity check is done. Log the message */
    log_pim_join_prune(src, data, num_groups, v->uv_name);

    if (eutaddr.unicast_addr != v->uv_lcl_addr) {
	/* if I am not the target of the join message */
	/* Join/Prune suppression code. This either modifies the J/P timers
	 * or triggers an overriding Join.
	 */
	/* Note that if we have (S,G) prune and (*,G) Join, we must send
	 * them in the same message. We don't bother to modify both timers
	 * here. The Join/Prune sending function will take care of that.
	 */
	upstream_router = find_pim_nbr(eutaddr.unicast_addr);
	if (!upstream_router)
	    return FALSE;   /* I have no such neighbor */

	while (num_groups--) {
	    GET_EGADDR(&egaddr, data);
	    GET_HOSTSHORT(num_j_srcs, data);
	    GET_HOSTSHORT(num_p_srcs, data);
	    MASKLEN_TO_MASK(egaddr.masklen, g_mask);
	    group = egaddr.mcast_addr;
	    if (!IN_MULTICAST(ntohl(group))) {
		data += (num_j_srcs + num_p_srcs) * sizeof(pim_encod_src_addr_t);
		continue; /* Ignore this group and jump to the next */
	    }

	    if ((ntohl(group) == CLASSD_PREFIX) && (egaddr.masklen == STAR_STAR_RP_MSKLEN)) {
		/* (*,*,RP) Join suppression */

		while (num_j_srcs--) {
		    GET_ESADDR(&esaddr, data);
		    source = esaddr.src_addr;
		    if (!inet_valid_host(source))
			continue;

		    s_flags = esaddr.flags;
		    MASKLEN_TO_MASK(esaddr.masklen, s_mask);
		    if ((s_flags & USADDR_RP_BIT) && (s_flags & USADDR_WC_BIT)) {
			/* This is the RP address. */
			rpentry = rp_find(source);
			if (!rpentry)
			    continue; /* Don't have such RP. Ignore */

			mrt_rp = rpentry->mrtlink;
			my_action = join_or_prune(mrt_rp, upstream_router);
			if (my_action != PIM_ACTION_JOIN)
			    continue;

			/* Check the holdtime */
			/* TODO: XXX: TIMER implem. dependency! */
			if (mrt_rp->jp_timer > holdtime)
			    continue;

			if ((mrt_rp->jp_timer == holdtime) && (ntohl(src) > ntohl(v->uv_lcl_addr)))
			    continue;

			/* Set the Join/Prune suppression timer for this
			 * routing entry by increasing the current
			 * Join/Prune timer.
			 */
			jp_value = jp_suppression_timeout();
			/* TODO: XXX: TIMER implem. dependency! */
			if (mrt_rp->jp_timer < jp_value)
			    SET_TIMER(mrt_rp->jp_timer, jp_value);
		    }
		} /* num_j_srcs */

		while (num_p_srcs--) {
		    /* TODO: XXX: Can we have (*,*,RP) prune message?
		     * Not in the spec, but anyway, the code below
		     * can handle them: either suppress
		     * the local (*,*,RP) prunes or override the prunes by
		     * sending (*,*,RP) and/or (*,G) and/or (S,G) Join.
		     */
		    GET_ESADDR(&esaddr, data);
		    source = esaddr.src_addr;
		    if (!inet_valid_host(source))
			continue;

		    s_flags = esaddr.flags;
		    MASKLEN_TO_MASK(esaddr.masklen, s_mask);
		    if ((s_flags & USADDR_RP_BIT) && (s_flags & USADDR_WC_BIT)) {
			/* This is the RP address. */
			rpentry = rp_find(source);
			if (!rpentry)
			    continue; /* Don't have such RP. Ignore */

			mrt_rp = rpentry->mrtlink;
			my_action = join_or_prune(mrt_rp, upstream_router);
			if (my_action == PIM_ACTION_PRUNE) {
			    /* TODO: XXX: TIMER implem. dependency! */
			    if ((mrt_rp->jp_timer < holdtime)
				|| ((mrt_rp->jp_timer == holdtime) &&
				    (ntohl(src) > ntohl(v->uv_lcl_addr)))) {
				/* Suppress the Prune */
				jp_value = jp_suppression_timeout();
				if (mrt_rp->jp_timer < jp_value)
				    SET_TIMER(mrt_rp->jp_timer, jp_value);
			    }
			} else if (my_action == PIM_ACTION_JOIN) {
			    /* Override the Prune by scheduling a Join */
			    jp_value = jp_override_timeout(vifi);
			    /* TODO: XXX: TIMER implem. dependency! */
			    if (mrt_rp->jp_timer > jp_value)
				SET_TIMER(mrt_rp->jp_timer, jp_value);
			}

			/* Check all (*,G) and (S,G) matching to this RP.
			 * If my_action == JOIN, then send a Join and override
			 * the (*,*,RP) Prune.
			 */
			for (grp = rpentry->cand_rp->rp_grp_next->grplink; grp; grp = grp->rpnext) {
			    my_action = join_or_prune(grp->grp_route, upstream_router);
			    if (my_action == PIM_ACTION_JOIN) {
				jp_value = jp_override_timeout(vifi);
				/* TODO: XXX: TIMER implem. dependency! */
				if (grp->grp_route->jp_timer > jp_value)
				    SET_TIMER(grp->grp_route->jp_timer, jp_value);
			    }
			    for (mrt_srcs = grp->mrtlink; mrt_srcs; mrt_srcs = mrt_srcs->grpnext) {
				my_action = join_or_prune(mrt_srcs, upstream_router);
				if (my_action == PIM_ACTION_JOIN) {
				    jp_value = jp_override_timeout(vifi);
				    /* TODO: XXX: TIMER implem. dependency! */
				    if (mrt_srcs->jp_timer > jp_value)
					SET_TIMER(mrt_srcs->jp_timer, jp_value);
				}
			    } /* For all (S,G) */
			} /* For all (*,G) */
		    }
		} /* num_p_srcs */
		continue;  /* This was (*,*,RP) suppression */
	    }

	    /* (*,G) or (S,G) suppression */
	    /* TODO: XXX: currently, accumulated groups
	     * (i.e. group_masklen < egaddress_lengt) are not
	     * implemented. Just need to create a loop and apply the
	     * procedure below for all groups matching the prefix.
	     */
	    while (num_j_srcs--) {
		GET_ESADDR(&esaddr, data);
		source = esaddr.src_addr;
		if (!inet_valid_host(source))
		    continue;

		s_flags = esaddr.flags;
		MASKLEN_TO_MASK(esaddr.masklen, s_mask);

		if ((s_flags & USADDR_RP_BIT) && (s_flags & USADDR_WC_BIT)) {
		    /* (*,G) JOIN_REQUEST (toward the RP) */
		    mrt = find_route(INADDR_ANY_N, group, MRTF_WC, DONT_CREATE);
		    if (!mrt)
			continue;

		    my_action = join_or_prune(mrt, upstream_router);
		    if (my_action != PIM_ACTION_JOIN)
			continue;

		    /* (*,G) Join suppresion */
		    if (source != mrt->group->active_rp_grp->rp->rpentry->address)
			continue;  /* The RP address doesn't match. Ignore. */

		    jp_suppress(mrt, holdtime);
		    continue;
		} /* End of (*,G) Join suppression */

		/* (S,G) Join suppresion */
		mrt = find_route(source, group, MRTF_SG, DONT_CREATE);
		if (!mrt)
		    continue;

		my_action = join_or_prune(mrt, upstream_router);
		if (my_action != PIM_ACTION_JOIN)
		    continue;

		jp_suppress(mrt, holdtime);
		continue;
	    }

	    /* Prunes suppression */
	    while (num_p_srcs--) {
		GET_ESADDR(&esaddr, data);
		source = esaddr.src_addr;
		if (!inet_valid_host(source))
		    continue;

		s_flags = esaddr.flags;
		MASKLEN_TO_MASK(esaddr.masklen, s_mask);
		if ((s_flags & USADDR_RP_BIT) && (s_flags & USADDR_WC_BIT)) {
		    /* (*,G) prune suppression */
		    rpentry = rp_match(group);
		    if (!rpentry || (rpentry->address != source))
			continue;  /* No such RP or it is different. Ignore */

		    mrt = find_route(INADDR_ANY_N, group, MRTF_WC, DONT_CREATE);
		    if (!mrt)
			continue;

		    my_action = join_or_prune(mrt, upstream_router);
		    if (my_action == PIM_ACTION_PRUNE) {
			/* TODO: XXX: TIMER implem. dependency! */
			if ((mrt->jp_timer < holdtime)
			    || ((mrt->jp_timer == holdtime)
				&& (ntohl(src) > ntohl(v->uv_lcl_addr)))) {
			    /* Suppress the Prune */
			    jp_value = jp_suppression_timeout();
			    if (mrt->jp_timer < jp_value)
				SET_TIMER(mrt->jp_timer, jp_value);
			}
		    }
		    else if (my_action == PIM_ACTION_JOIN) {
			/* Override the Prune by scheduling a Join */
			jp_value = jp_override_timeout(vifi);
			/* TODO: XXX: TIMER implem. dependency! */
			if (mrt->jp_timer > jp_value)
			    SET_TIMER(mrt->jp_timer, jp_value);
		    }

		    /* Check all (S,G) entries for this group.
		     * If my_action == JOIN, then send the Join and override
		     * the (*,G) Prune.
		     */
		    for (mrt_srcs = mrt->group->mrtlink; mrt_srcs; mrt_srcs = mrt_srcs->grpnext) {
			my_action = join_or_prune(mrt_srcs, upstream_router);
			if (my_action == PIM_ACTION_JOIN) {
			    jp_value = jp_override_timeout(vifi);
			    /* TODO: XXX: TIMER implem. dependency! */
			    if (mrt_srcs->jp_timer > jp_value)
				SET_TIMER(mrt_srcs->jp_timer, jp_value);
			}
		    } /* For all (S,G) */
		    continue;  /* End of (*,G) prune suppression */
		}

		/* (S,G) prune suppression */
		mrt = find_route(source, group, MRTF_SG, DONT_CREATE);
		if (!mrt)
		    continue;

		my_action = join_or_prune(mrt, upstream_router);
		if (my_action == PIM_ACTION_PRUNE) {
		    /* Suppress the (S,G) Prune */
		    /* TODO: XXX: TIMER implem. dependency! */
		    if ((mrt->jp_timer < holdtime)
			|| ((mrt->jp_timer == holdtime)
			    && (ntohl(src) > ntohl(v->uv_lcl_addr)))) {
			jp_value = jp_suppression_timeout();
			if (mrt->jp_timer < jp_value)
			    SET_TIMER(mrt->jp_timer, jp_value);
		    }
		}
		else if (my_action == PIM_ACTION_JOIN) {
		    /* Override the Prune by scheduling a Join */
		    jp_value = jp_override_timeout(vifi);
		    /* TODO: XXX: TIMER implem. dependency! */
		    if (mrt->jp_timer > jp_value)
			SET_TIMER(mrt->jp_timer, jp_value);
		}
	    }  /* while (num_p_srcs--) */
	}  /* while (num_groups--) */
	return TRUE;
    }   /* End of Join/Prune suppression code */

    /* I am the target of this join, so process the message */

    /* The spec says that if there is (*,G) Join, it has priority over
     * old existing ~(S,G) prunes in the routing table.
     * However, if the (*,G) Join and the ~(S,G) prune are in
     * the same message, ~(S,G) has the priority.
     *
     * The code below do:
     *  (2) Check for Prunes. If no prunes, process the Joins.
     *  (3) If there are Prunes:
     *  (3.1) Scan the Join part for existing (*,G) Join.
     *  (3.1.1) If there is (*,G) Join, clear join interface from
     *          the pruned_oifs for all (S,G), but DO NOT flush the
     *          change to the kernel (by using change_interfaces()
     *          for example)
     *  (3.2) After the pruned_oifs are eventually cleared in (3.1.1),
     *        process the Prune part of the message normally
     *        (setting the prune_oifs and flashing the changes to the (kernel).
     *  (3.3) After the Prune part is processed, process the Join part
     *        normally (by applying any changes to the kernel)
     *
     *   If the Join/Prune list is too long, it may result in long processing
     *   overhead. The idea above is not to place any wrong info in the
     *   kernel, because it may result in short-time existing traffic
     *   forwarding on wrong interface.
     *   Hopefully, in the future will find a better way to implement it.
     */
    num_groups_tmp = num_groups;
    data_start = data;

    /*
     * Start processing the groups. If this is (*,*,RP), skip it, but process
     * it at the end.
     */
    data = data_start;
    num_groups_tmp = num_groups;
    while (num_groups_tmp--) {
	GET_EGADDR(&egaddr, data);
	GET_HOSTSHORT(num_j_srcs, data);
	GET_HOSTSHORT(num_p_srcs, data);
	group = egaddr.mcast_addr;
	if (!IN_MULTICAST(ntohl(group))) {
	    data += (num_j_srcs + num_p_srcs) * sizeof(pim_encod_src_addr_t);
	    continue;		/* Ignore this group and jump to the next one */
	}

	if ((ntohl(group) == CLASSD_PREFIX)
	    && (egaddr.masklen == STAR_STAR_RP_MSKLEN)) {
	    /* This is (*,*,RP). Jump to the next group. */
	    data += (num_j_srcs + num_p_srcs) * sizeof(pim_encod_src_addr_t);
	    continue;
	}

	/* May be NULL, and that is not a reason to drop the group set: only
	 * a (*,G) Join needs to agree with us on the RP.  Skipping the whole
	 * set here threw away the (S,G) Joins and every Prune along with it,
	 * so a router with no RP-map yet, or one whose map had just changed,
	 * quietly stopped building downstream state at all.
	 */
	rpentry = rp_match(group);

	data_group_j_start = data;
	data_group_p_start = data + num_j_srcs * sizeof(pim_encod_src_addr_t);
	data_group_end = data + (num_j_srcs + num_p_srcs) * sizeof(pim_encod_src_addr_t);

	/* Scan the Join part for (*,G) Join and then clear the
	 * particular interface from pruned_oifs for all (S,G).
	 * A (*,G) Join naming an RP that is not ours is dropped on its own,
	 * further down; here it only means there is no shared tree of ours
	 * to lift the (S,G) prunes off.
	 */
	num_j_srcs_tmp = num_j_srcs;
	while (num_j_srcs_tmp--) {
	    GET_ESADDR(&esaddr, data);

	    /* An SSM group has no shared tree to lift (S,G) prunes off, so
	     * there is nothing here to look for: RFC 7761 sec. 4.8.1 rule 4
	     * makes the (*,G) macros NULL for one.  See the Join arm below.
	     */
	    if (IN_PIM_SSM_RANGE(group))
		break;

	    if ((esaddr.flags & USADDR_RP_BIT) && (esaddr.flags & USADDR_WC_BIT)) {
		if (!rpentry || rpentry->address != esaddr.src_addr)
		    break;

		mrt = find_route(INADDR_ANY_N, group, MRTF_WC, DONT_CREATE);
		if (mrt) {
		    for (mrt_srcs = mrt->group->mrtlink;
			 mrt_srcs;
			 mrt_srcs = mrt_srcs->grpnext)
			PIMD_VIFM_CLR(vifi, mrt_srcs->pruned_oifs);
		}
		break;
	    }
	}

	data = data_group_p_start;
	/* Process the Prune part first */
	while (num_p_srcs--) {
	    GET_ESADDR(&esaddr, data);
	    source = esaddr.src_addr;
	    if (!inet_valid_host(source))
		continue;

	    s_flags = esaddr.flags;

	    /* RFC 7761 sec. 4.8.1 rule 4: a router MUST NOT forward packets
	     * based on (*,G) state for a group in the SSM range, and the
	     * (*,G) macros are NULL there.  pimd never builds such state of
	     * its own -- add_leaf() picks (S,G) inside the range and
	     * join_or_prune() refuses to send for a (*,G) in it -- but the
	     * receive path had no range test at all, so a Join(*,G) naming
	     * the right RP built one, and calc_oifs() merges a (*,G)'s
	     * joined_oifs into every (S,G) of the group.  That RP is the
	     * invented 169.254.0.1 an SSM range is given, which no router
	     * that learned its RP set from the BSR would name, and any
	     * router that maps SSM groups to an RP of its own would.
	     *
	     * The RP bit is what marks the two entry kinds rule 4 is about,
	     * (*,G) with the WC bit beside it and (S,G,rpt) without; an
	     * (S,G) entry carries neither and is what SSM is made of.
	     */
	    if (IN_PIM_SSM_RANGE(group) && (s_flags & USADDR_RP_BIT)) {
		IF_DEBUG(DEBUG_PIM_JOIN_PRUNE)
		    logit(LOG_NOTICE, 0, "Ignoring a shared tree Prune for SSM group %s from %s on %s",
			  inet_fmt(group, s2, sizeof(s2)),
			  inet_fmt(src, s1, sizeof(s1)), v->uv_name);
		continue;
	    }

	    if (!(s_flags & (USADDR_WC_BIT | USADDR_RP_BIT))) {
		/* (S,G) prune sent toward S */
		mrt = find_route(source, group, MRTF_SG, DONT_CREATE);
		if (!mrt)
		    continue;   /* I don't have (S,G) to prune. Ignore. */

		/* TODO: XXX: increase the entry timer? */
		prune_pending(mrt, vifi);
		IF_TIMER_NOT_SET(mrt->vif_timers[vifi]) {
		    PIMD_VIFM_CLR(vifi, mrt->joined_oifs);
		    PIMD_VIFM_CLR(vifi, mrt->sg_joined_oifs);
		    PIMD_VIFM_SET(vifi, mrt->pruned_oifs);
		    change_interfaces(mrt,
				      mrt->incoming,
				      mrt->joined_oifs,
				      mrt->pruned_oifs,
				      mrt->leaves,
				      mrt->asserted_oifs, 0);
		}
		continue;
	    }

	    if ((s_flags & USADDR_RP_BIT) && (!(s_flags & USADDR_WC_BIT))) {
		/* ~(S,G)RPbit prune sent toward the RP */
		mrt = find_route(source, group, MRTF_SG, DONT_CREATE);
		if (mrt) {
		    SET_TIMER(mrt->entry_timer, holdtime);
		    prune_pending(mrt, vifi);
		    IF_TIMER_NOT_SET(mrt->vif_timers[vifi]) {
			PIMD_VIFM_CLR(vifi, mrt->joined_oifs);
			PIMD_VIFM_CLR(vifi, mrt->sg_joined_oifs);
			PIMD_VIFM_SET(vifi, mrt->pruned_oifs);
			change_interfaces(mrt,
					  mrt->incoming,
					  mrt->joined_oifs,
					  mrt->pruned_oifs,
					  mrt->leaves,
					  mrt->asserted_oifs, 0);
		    }
		    continue;
		}

		/* There is no (S,G) entry. Check for (*,G) */
		mrt = find_route(INADDR_ANY_N, group, MRTF_WC, DONT_CREATE);
		if (mrt) {
		    mrt = find_route(source, group, MRTF_SG | MRTF_RP, CREATE);
		    if (!mrt)
			continue;

		    mrt->flags &= ~MRTF_NEW;
		    RESET_TIMER(mrt->vif_timers[vifi]);
		    /* TODO: XXX: The spec doens't say what value to use for
		     * the entry time. Use the J/P holdtime.
		     */
		    SET_TIMER(mrt->entry_timer, holdtime);
		    /* TODO: XXX: The spec says to delete the oif. However,
		     * its timer only should be lowered, so the prune can be
		     * overwritten on multiaccess LAN. Spec BUG.
		     */
		    PIMD_VIFM_CLR(vifi, mrt->joined_oifs);
		    PIMD_VIFM_SET(vifi, mrt->pruned_oifs);
		    change_interfaces(mrt,
				      mrt->incoming,
				      mrt->joined_oifs,
				      mrt->pruned_oifs,
				      mrt->leaves,
				      mrt->asserted_oifs, 0);
		}
		continue;
	    }

	    if ((s_flags & USADDR_RP_BIT) && (s_flags & USADDR_WC_BIT)) {
		/* (*,G) Prune */
		mrt = find_route(INADDR_ANY_N, group, MRTF_WC, DONT_CREATE);
		if (mrt) {
		    if (mrt->flags & MRTF_WC) {
			/* No RP check here, deliberately: RFC 7761 sec. 4.5.1 has
			 * received Prune(*,G) messages "processed even if the RP
			 * in the message does not match RP(G)".  That is the case
			 * the sentence exists for -- a router tearing down the old
			 * shared tree still names the old RP -- and ignoring it
			 * left us forwarding to that router for the whole expiry
			 * time.
			 */
			prune_pending(mrt, vifi);
			IF_TIMER_NOT_SET(mrt->vif_timers[vifi]) {
			    PIMD_VIFM_CLR(vifi, mrt->joined_oifs);
			    PIMD_VIFM_SET(vifi, mrt->pruned_oifs);
			    change_interfaces(mrt,
					      mrt->incoming,
					      mrt->joined_oifs,
					      mrt->pruned_oifs,
					      mrt->leaves,
					      mrt->asserted_oifs, 0);
			}
			continue;
		    }

		    /* No (*,G) entry, but found (*,*,RP). Create (*,G) */
		    if (mrt->source->address != source)
			continue; /* The RP address doesn't match. */

		    mrt = find_route(INADDR_ANY_N, group, MRTF_WC, CREATE);
		    if (!mrt)
			continue;

		    mrt->flags &= ~MRTF_NEW;
		    RESET_TIMER(mrt->vif_timers[vifi]);
		    /* TODO: XXX: should only lower the oif timer, so it can
		     * be overwritten on multiaccess LAN. Spec bug.
		     */
		    PIMD_VIFM_CLR(vifi, mrt->joined_oifs);
		    PIMD_VIFM_SET(vifi, mrt->pruned_oifs);
		    change_interfaces(mrt,
				      mrt->incoming,
				      mrt->joined_oifs,
				      mrt->pruned_oifs,
				      mrt->leaves,
				      mrt->asserted_oifs, 0);
		} /* (*,G) or (*,*,RP) found */
	    } /* (*,G) prune */
	} /* while (num_p_srcs--) */
	/* End of (S,G) and (*,G) Prune handling */

	/* Jump back to the Join part and process it */
	data = data_group_j_start;
	while (num_j_srcs--) {
	    GET_ESADDR(&esaddr, data);
	    source = esaddr.src_addr;
	    if (!inet_valid_host(source))
		continue;

	    s_flags = esaddr.flags;
	    MASKLEN_TO_MASK(esaddr.masklen, s_mask);

	    /* Rule 4 again, and this is the arm it is really about: the one
	     * above refuses a Prune that would have taken such state away,
	     * this one refuses to build it.  See the Prune loop for why the
	     * RP bit is the test.
	     */
	    if (IN_PIM_SSM_RANGE(group) && (s_flags & USADDR_RP_BIT)) {
		IF_DEBUG(DEBUG_PIM_JOIN_PRUNE)
		    logit(LOG_NOTICE, 0, "Ignoring a shared tree Join for SSM group %s from %s on %s",
			  inet_fmt(group, s2, sizeof(s2)),
			  inet_fmt(src, s1, sizeof(s1)), v->uv_name);
		continue;
	    }

	    if ((s_flags & USADDR_WC_BIT) && (s_flags & USADDR_RP_BIT)) {
		/* (*,G) Join toward RP.  RFC 7761 sec. 4.5.1: "If the RP in
		 * the message does not match RP(G), the Join(*,G) should be
		 * silently dropped", and only it -- the (S,G) and (S,G,rpt)
		 * entries of the same group set are still processed, above
		 * and below.
		 */
		if (!rpentry || rpentry->address != source)
		    continue;

		mrt = find_route(INADDR_ANY_N, group, MRTF_WC, CREATE);
		if (!mrt)
		    continue;

		PIMD_VIFM_SET(vifi, mrt->joined_oifs);
		PIMD_VIFM_CLR(vifi, mrt->pruned_oifs);
		/* "Receive Join(*,G) on interface I" in the Loser state of
		 * RFC 7761 sec. 4.6.2: whoever sent it may know the winner
		 * has died, so give the interface back and let the election
		 * run again if it was wrong. */
		assert_clear(mrt, vifi);
		/* "The Prune-Pending Timer is canceled (without triggering an
		 * expiry event)", sec. 4.5.1 and sec. 4.5.2, and the Expiry
		 * Timer goes back to the maximum of its value and the holdtime.
		 */
		PIMD_VIFM_CLR(vifi, mrt->prune_pending_oifs);
		/* TODO: XXX: TIMER implem. dependency! */
		if (mrt->vif_timers[vifi] < holdtime)
		    SET_TIMER(mrt->vif_timers[vifi], holdtime);
		if (mrt->entry_timer < holdtime)
		    SET_TIMER(mrt->entry_timer, holdtime);
		change_interfaces(mrt,
				  mrt->incoming,
				  mrt->joined_oifs,
				  mrt->pruned_oifs,
				  mrt->leaves,
				  mrt->asserted_oifs, 0);
		if (mrt->flags & MRTF_NEW) {
		    mrt->flags &= ~MRTF_NEW;
		    send_pim_join(mrt->upstream, mrt, MRTF_RP | MRTF_WC, PIM_JOIN_PRUNE_HOLDTIME);
		}
		/* Need to update the (S,G) entries, because of the previous
		 * cleaning of the pruned_oifs. The reason is that if the
		 * oifs for (*,G) weren't changed, the (S,G) entries won't
		 * be updated by change_interfaces()
		 *
		 * Recomputing them is the whole of it.  A Join(*,G) used to
		 * also send a Join(S,G) to every source of the group, record
		 * the interface in each one's joined_oifs and set MRTF_SPT on
		 * them, which RFC 7761 sec. 4.5.1 does not ask for: it gives
		 * "Receive Join(*,G)" two actions, both on the (*,G)
		 * downstream state machine.  The interface reaches the (S,G)
		 * outgoing interfaces through inherited_olist() -- which is
		 * what calc_oifs() computes -- without being join state of
		 * its own, and an (S,G) still sitting on the shared tree must
		 * not claim the shortest path tree in an assert.
		 */
		for (mrt_srcs = mrt->group->mrtlink; mrt_srcs; mrt_srcs = mrt_srcs->grpnext)
		    change_interfaces(mrt_srcs,
				      mrt_srcs->incoming,
				      mrt_srcs->joined_oifs,
				      mrt_srcs->pruned_oifs,
				      mrt_srcs->leaves,
				      mrt_srcs->asserted_oifs, 0);
		continue;
	    }

	    if (!(s_flags & (USADDR_WC_BIT | USADDR_RP_BIT))) {
		/* (S,G) Join toward S */
		if (vifi == get_iif(source))
		    continue;  /* Ignore this (S,G) Join */

		mrt = find_route(source, group, MRTF_SG, CREATE);
		if (!mrt)
		    continue;

		new_join = (PIMD_VIFM_ISSET(vifi, mrt->joined_oifs) == 0);
		PIMD_VIFM_SET(vifi, mrt->joined_oifs);
		/* joins(S,G), which a new entry does not inherit from the
		 * (*,G) the way joined_oifs does -- see sg_joined_oifs in
		 * src/mrt.h and join_desired() in src/route.c */
		PIMD_VIFM_SET(vifi, mrt->sg_joined_oifs);
		PIMD_VIFM_CLR(vifi, mrt->pruned_oifs);
		/* "Receive Join(S,G) on interface I", the same transition in
		 * sec. 4.6.1. */
		assert_clear(mrt, vifi);
		/* "The Prune-Pending Timer is canceled (without triggering an
		 * expiry event)", sec. 4.5.1 and sec. 4.5.2, and the Expiry
		 * Timer goes back to the maximum of its value and the holdtime.
		 */
		PIMD_VIFM_CLR(vifi, mrt->prune_pending_oifs);
		/* TODO: XXX: TIMER implem. dependency! */
		if (mrt->vif_timers[vifi] < holdtime)
		    SET_TIMER(mrt->vif_timers[vifi], holdtime);
		if (mrt->entry_timer < holdtime)
		    SET_TIMER(mrt->entry_timer, holdtime);
		/* If this is a new entry, send immediately the
		 * Join message toward S.
		 */
		if (mrt->flags & MRTF_NEW) {
		    mrt->flags &= ~MRTF_NEW;
		    send_pim_join(mrt->upstream, mrt, MRTF_SG, PIM_JOIN_PRUNE_HOLDTIME);
		}

		/* Note that we must create (S,G) without the RPbit set.
		 * If we already had such entry, change_interfaces() will
		 * reset the RPbit propertly.
		 */
		change_interfaces(mrt,
				  mrt->source->incoming,
				  mrt->joined_oifs,
				  mrt->pruned_oifs,
				  mrt->leaves,
				  mrt->asserted_oifs, 0);
		/* If this is join from new interface and we have incoming data
		 * start forwarding immediately.
		 */
		if (new_join) {
		    add_kernel_cache(mrt, mrt->source->address, mrt->group->group, MFC_MOVE_FORCE);
		    k_chg_mfc(igmp_socket, mrt->source->address, mrt->group->group,
			      mrt->incoming, mrt->oifs, mrt->source->address);
		}
		continue;
	    }
	} /* while (num_j_srcs--) */
	data = data_group_end;
    } /* for all groups */


    return TRUE;
}

/*
 * Function for sending single PIM-JOIN instantly.
 */
void send_pim_join(pim_nbr_entry_t *pim_nbr, mrtentry_t *mrt, uint16_t flags, uint16_t holdtime)
{
    if (!pim_nbr)
        return;

    if (flags & MRTF_SG)
        add_jp_entry(pim_nbr, holdtime, mrt->group->group,
                     SINGLE_GRP_MSKLEN, mrt->source->address,
                     SINGLE_SRC_MSKLEN, 0, PIM_ACTION_JOIN);
    else
        add_jp_entry(pim_nbr, holdtime, mrt->group->group,
                     SINGLE_GRP_MSKLEN, mrt->group->rpaddr,
                     SINGLE_SRC_MSKLEN, flags, PIM_ACTION_JOIN);
    pack_and_send_jp_message(pim_nbr);
}

/*
 * The other half of a change of upstream router: RFC 7761 sec. 4.5.4 and
 * 4.5.5 pair the Join to the new RPF' with a Prune to the old one, so that
 * the router we no longer take this group from stops forwarding it now
 * rather than when its own downstream state expires, up to a J/P holdtime
 * later.  Not for a change caused by an Assert: there the loser is on the
 * same link and the assert itself has already settled who forwards.
 */
void send_pim_prune(pim_nbr_entry_t *pim_nbr, mrtentry_t *mrt, uint16_t flags, uint16_t holdtime)
{
    if (!pim_nbr || !mrt)
	return;

    /* A (*,G) entry carries no source entry, so naming a source off one
     * would read through NULL.  The callers derive the flags from the entry
     * and cannot ask for that today; do not make them the only thing
     * standing between a future caller and a crash.
     */
    if ((flags & MRTF_SG) && !mrt->source)
	return;

    if (flags & MRTF_SG)
	add_jp_entry(pim_nbr, holdtime, mrt->group->group,
		     SINGLE_GRP_MSKLEN, mrt->source->address,
		     SINGLE_SRC_MSKLEN, 0, PIM_ACTION_PRUNE);
    else
	add_jp_entry(pim_nbr, holdtime, mrt->group->group,
		     SINGLE_GRP_MSKLEN, mrt->group->rpaddr,
		     SINGLE_SRC_MSKLEN, flags, PIM_ACTION_PRUNE);
    pack_and_send_jp_message(pim_nbr);
}

/*
 * TODO: NOT USED, probably buggy, but may need it in the future.
 */
/*
 * TODO: create two functions: periodic which timeout the timers
 * and non-periodic which only check but don't timeout the timers.
 */
/*
 * Create and send Join/Prune messages per interface.
 * Only the entries which have the Join/Prune timer expired are included.
 * In the special case when we have ~(S,G)RPbit Prune entry, we must
 * include any (*,G) or (*,*,RP)
 * Currently the whole table is scanned. In the future will have all
 * routing entries linked in a chain with the corresponding upstream
 * pim_nbr_entry.
 *
 * If pim_nbr is not NULL, then send to only this particular PIM neighbor,
 */
int send_periodic_pim_join_prune(vifi_t vifi, pim_nbr_entry_t *pim_nbr, uint16_t holdtime)
{
    grpentry_t      *grp;
    mrtentry_t      *mrt;
    uint32_t         addr;
    struct uvif     *v;
    pim_nbr_entry_t *nbr;
    cand_rp_t       *cand_rp;

    /* Walk through all routing entries. The iif must match to include the
     * entry. Check first the (*,G) entry and then all associated (S,G).
     * At the end of the message will add any (*,*,RP) entries.
     * TODO: check other PIM-SM implementations and decide the more
     * appropriate place to put the (*,*,RP) entries: in the beginning of the
     * message or at the end.
     */

    v = &uvifs[vifi];

    /* Check the (*,G) and (S,G) entries */
    for (grp = grplist; grp; grp = grp->next) {
	mrt = grp->grp_route;
	/* TODO: XXX: TIMER implem. dependency! */
	if (mrt && (mrt->incoming == vifi) && (mrt->jp_timer <= TIMER_INTERVAL)) {

	    /* If join/prune to a particular neighbor only was specified */
	    if (pim_nbr && mrt->upstream != pim_nbr)
		continue;

	    /* Don't send (*,G) or (S,G,rpt) Join/Prune */
	    /* TODO: this handles (S,G,rpt) Join/Prune? */
	    if (!(mrt->flags & MRTF_SG) && IN_PIM_SSM_RANGE(grp->group)) {
		logit(LOG_DEBUG, 0, "Skip j/p for SSM (!SG)");
		continue;
	    }

	    /* TODO: XXX: The J/P suppression timer is not in the spec! */
	    if (!PIMD_VIFM_ISEMPTY(mrt->joined_oifs) || (v->uv_flags & VIFF_DR)) {
		add_jp_entry(mrt->upstream, holdtime,
			     grp->group,
			     SINGLE_GRP_MSKLEN,
			     grp->rpaddr,
			     SINGLE_SRC_MSKLEN, 0, PIM_ACTION_JOIN);
	    }
	    /* TODO: XXX: TIMER implem. dependency! */
	    if (PIMD_VIFM_ISEMPTY(mrt->joined_oifs)
		&& (!(v->uv_flags & VIFF_DR))
		&& (mrt->jp_timer <= TIMER_INTERVAL)) {
		add_jp_entry(mrt->upstream, holdtime,
			     grp->group, SINGLE_GRP_MSKLEN,
			     grp->rpaddr,
			     SINGLE_SRC_MSKLEN, 0, PIM_ACTION_PRUNE);
	    }
	}

	/* Check the (S,G) entries */
	for (mrt = grp->mrtlink; mrt; mrt = mrt->grpnext) {
	    /* If join/prune to a particular neighbor only was specified */
	    if (pim_nbr && mrt->upstream != pim_nbr)
		continue;

	    if (mrt->flags & MRTF_RP) {
		/* RPbit set */
		addr = mrt->source->address;
		if (PIMD_VIFM_ISEMPTY(mrt->joined_oifs) || find_vif_direct_local(addr, TRUE) != NO_VIF) {
		    /* TODO: XXX: TIMER implem. dependency! */
		    if (grp->grp_route &&
			grp->grp_route->incoming == vifi &&
			grp->grp_route->jp_timer <= TIMER_INTERVAL)
			/* S is directly connected. Send toward RP */
			add_jp_entry(grp->grp_route->upstream,
				     holdtime,
				     grp->group, SINGLE_GRP_MSKLEN,
				     addr, SINGLE_SRC_MSKLEN,
				     MRTF_RP, PIM_ACTION_PRUNE);
		}
	    }
	    else {
		/* RPbit cleared */
		if (PIMD_VIFM_ISEMPTY(mrt->joined_oifs)) {
		    /* TODO: XXX: TIMER implem. dependency! */
		    if (mrt->incoming == vifi && mrt->jp_timer <= TIMER_INTERVAL)
			add_jp_entry(mrt->upstream, holdtime,
				     grp->group, SINGLE_GRP_MSKLEN,
				     mrt->source->address,
				     SINGLE_SRC_MSKLEN, 0, PIM_ACTION_PRUNE);
		} else {
		    logit(LOG_DEBUG, 0 , "Joined not empty, group %s",
			  inet_ntoa(*(struct in_addr *)&grp->group));
		    /* TODO: XXX: TIMER implem. dependency! */
		    if (mrt->incoming == vifi && mrt->jp_timer <= TIMER_INTERVAL)
			add_jp_entry(mrt->upstream, holdtime,
				     grp->group, SINGLE_GRP_MSKLEN,
				     mrt->source->address,
				     SINGLE_SRC_MSKLEN, 0, PIM_ACTION_JOIN);
		}
		/* TODO: XXX: TIMER implem. dependency! */
		if ((mrt->flags & MRTF_SPT) &&
		    grp->grp_route &&
		    mrt->incoming != grp->grp_route->incoming &&
		    grp->grp_route->incoming == vifi &&
		    grp->grp_route->jp_timer <= TIMER_INTERVAL)
		    add_jp_entry(grp->grp_route->upstream, holdtime,
				 grp->group, SINGLE_GRP_MSKLEN,
				 mrt->source->address,
				 SINGLE_SRC_MSKLEN, MRTF_RP,
				 PIM_ACTION_PRUNE);
	    }
	}
    }

    /* Send all pending Join/Prune messages */
    for (nbr = v->uv_pim_neighbors; nbr; nbr = nbr->next) {
	/* If join/prune to a particular neighbor only was specified */
	if (pim_nbr && (nbr != pim_nbr))
	    continue;

	pack_and_send_jp_message(nbr);
    }

    return TRUE;
}


/*
 * How large the Join/Prune message would be once the group set in the
 * working area is packed into it and one more source entry is added.  The
 * group set costs its own header the first time anything lands in it.
 */
static uint32_t jp_pending_size(build_jp_message_t *bjpm, int new_grp, int rp_flag)
{
    uint32_t size = bjpm->jp_message_size;

    if (bjpm->join_list_size + bjpm->prune_list_size) {
	size += sizeof(pim_jp_encod_grp_t);
	size += bjpm->join_list_size;
	size += bjpm->prune_list_size;
    } else if (new_grp == TRUE) {
	size += sizeof(pim_jp_encod_grp_t);
    }

    if (bjpm->rp_list_join_size + bjpm->rp_list_prune_size) {
	size += sizeof(pim_jp_encod_grp_t);
	size += bjpm->rp_list_join_size;
	size += bjpm->rp_list_prune_size;
    } else if (rp_flag == TRUE) {
	size += sizeof(pim_jp_encod_grp_t);
    }

    /* Check also would the new entry push us over the limit. */
    return size + sizeof(pim_encod_src_addr_t);
}

/*
 * The overflow rule of RFC 7761 sec. 4.9.5.2: when more (S,G,rpt) Prunes
 * are pending than one message can carry, the ones that go are the N
 * numerically smallest source addresses in network byte order, and the rest
 * are ignored rather than sent in a message of their own.
 *
 * The list is not reordered -- sec. 4.9.5 says the order inside a source
 * list does not matter -- so this looks for the largest (S,G,rpt) Prune
 * already in it and gives up its place, or leaves the new entry out when it
 * is the largest itself.  Only the entries carrying the RP bit are the
 * section's to drop: a plain (S,G) Prune sharing the group set is a prune in
 * its own right and not a qualifier of the (*,G) Join.
 *
 * Returns TRUE either way.  An entry the section tells us to leave out is
 * not a failure to add one.
 */
static int jp_prune_keep_smallest(build_jp_message_t *bjpm, uint32_t source, uint8_t src_msklen)
{
    uint8_t *entry, *largest = NULL;
    uint32_t off, dropped;

    for (off = 0; off + PIM_ENCODE_SRC_ADDR_LEN <= bjpm->prune_list_size;
	 off += PIM_ENCODE_SRC_ADDR_LEN) {
	entry = bjpm->prune_list + off;

	if (!(entry[2] & USADDR_RP_BIT))
	    continue;

	if (!largest || memcmp(entry + 4, largest + 4, sizeof(uint32_t)) > 0)
	    largest = entry;
    }

    /* Network byte order is big endian, so memcmp() over the four address
     * bytes is the comparison the section asks for. */
    if (!largest || memcmp(largest + 4, &source, sizeof(source)) < 0) {
	IF_DEBUG(DEBUG_PIM_JOIN_PRUNE)
	    logit(LOG_INFO, 0, "Join/Prune group set full, leaving out Prune(%s,G,rpt)",
		  inet_fmt(source, s1, sizeof(s1)));

	return TRUE;
    }

    memcpy(&dropped, largest + 4, sizeof(dropped));
    IF_DEBUG(DEBUG_PIM_JOIN_PRUNE)
	logit(LOG_INFO, 0, "Join/Prune group set full, Prune(%s,G,rpt) takes the place of %s",
	      inet_fmt(source, s1, sizeof(s1)), inet_fmt(dropped, s2, sizeof(s2)));

    entry = largest;
    PUT_ESADDR(source, src_msklen, USADDR_S_BIT | USADDR_RP_BIT, entry);

    return TRUE;
}

int add_jp_entry(pim_nbr_entry_t *pim_nbr, uint16_t holdtime, uint32_t group,
		 uint8_t grp_msklen, uint32_t source, uint8_t src_msklen,
		 uint16_t addr_flags, uint8_t join_prune)
{
    build_jp_message_t *bjpm;
    uint8_t *data;
    uint8_t flags = 0;
    int rp_flag;
    int new_grp = FALSE;

    bjpm = pim_nbr->build_jp_message;

    if (group == htonl(CLASSD_PREFIX) && grp_msklen == STAR_STAR_RP_MSKLEN) {
	rp_flag = TRUE;
    } else {
	rp_flag = FALSE;

	if (bjpm) {
	    if ((bjpm->curr_group != group)
	        || (bjpm->curr_group_msklen != grp_msklen)
	        || (bjpm->holdtime != holdtime)) {

		new_grp = TRUE;
	    }
	}
    }

    if (bjpm) {
	if (new_grp == TRUE)
	    pack_jp_message_grp(pim_nbr);

	/* Check if we have already 254 groups. */
	if (*bjpm->num_groups_ptr == ((uint8_t)~0 - 1)) {
	    pack_and_send_jp_message(pim_nbr);
	    bjpm = pim_nbr->build_jp_message;	/* The buffer will be freed */
	}
    }

    if (bjpm) {
	/*
	 * RFC 7761 sec. 4.9.5.2: a group set carrying a (*,G) Joined entry
	 * says the router wants the whole group off the shared tree except
	 * for the sources it prunes in the same set, so that list of
	 * (S,G,rpt) Prunes MUST NOT be split across messages.  An upstream
	 * that reads the Join(*,G) without the tail moves every (S,G,rpt) it
	 * holds for the group to NoInfo, and the sources in the tail flood
	 * the shared tree until the next period repeats the mistake.
	 *
	 * Flushing on size alone is what split it.  Send the group sets
	 * already packed instead and leave this one in the working area, so
	 * that the split falls between sets rather than through the middle of
	 * one.
	 */
	int unsplittable = rp_flag == FALSE && new_grp == FALSE && bjpm->curr_group_wc;

	/* TODO: Should check the jp_message_size also against MTU. */
	if (jp_pending_size(bjpm, new_grp, rp_flag) > MAX_JP_MESSAGE_SIZE) {
	    if (unsplittable) {
		flush_packed_groups(pim_nbr);
	    } else {
		pack_and_send_jp_message(pim_nbr);
		bjpm = pim_nbr->build_jp_message;	/* The buffer will be freed */
	    }
	}

	/* A message to itself was not enough, so more (S,G,rpt) Prunes are
	 * pending than any one message can carry.  The same section says
	 * which N to send and to ignore the rest; anything else in the set
	 * still has to go out, split or not. */
	if (bjpm && jp_pending_size(bjpm, new_grp, rp_flag) > MAX_JP_MESSAGE_SIZE) {
	    if (unsplittable && join_prune == PIM_ACTION_PRUNE && (addr_flags & MRTF_RP))
		return jp_prune_keep_smallest(bjpm, source, src_msklen);

	    pack_and_send_jp_message(pim_nbr);
	    bjpm = pim_nbr->build_jp_message;	/* The buffer will be freed */
	}
    }

    if (!bjpm) {
	bjpm = get_jp_working_buff();
	if (!bjpm) {
	    logit(LOG_ERR, 0, "Failed allocating working buffer in add_jp_entry()");
	    return FALSE;
	}

	pim_nbr->build_jp_message = bjpm;
	bjpm->holdtime = holdtime;
	jp_message_restart(pim_nbr, bjpm);

	if (rp_flag == FALSE)
	    new_grp = TRUE;
    }

    if (new_grp == TRUE) {
	bjpm->curr_group = group;
	bjpm->curr_group_msklen = grp_msklen;
	bjpm->curr_group_wc = FALSE;
    }

    switch (join_prune) {
	case PIM_ACTION_JOIN:
	    if (rp_flag == TRUE)
		data = bjpm->rp_list_join + bjpm->rp_list_join_size;
	    else
		data = bjpm->join_list + bjpm->join_list_size;
	    break;

	case PIM_ACTION_PRUNE:
	    if (rp_flag == TRUE)
		data = bjpm->rp_list_prune + bjpm->rp_list_prune_size;
	    else
		data = bjpm->prune_list + bjpm->prune_list_size;
	    break;

	default:
	    return FALSE;
    }

    flags |= USADDR_S_BIT;   /* Mandatory for PIMv2 */
    if (addr_flags & MRTF_RP)
	flags |= USADDR_RP_BIT;
    if (addr_flags & MRTF_WC)
	flags |= USADDR_WC_BIT;
    PUT_ESADDR(source, src_msklen, flags, data);

    /* The WC bit on a Joined entry is what makes this group set one sec.
     * 4.9.5.2 will not let us split, from here until it is packed. */
    if (rp_flag == FALSE && join_prune == PIM_ACTION_JOIN && (flags & USADDR_WC_BIT))
	bjpm->curr_group_wc = TRUE;

    switch (join_prune) {
	case PIM_ACTION_JOIN:
	    if (rp_flag == TRUE) {
		bjpm->rp_list_join_size = data - bjpm->rp_list_join;
		bjpm->rp_list_join_number++;
	    } else {
		bjpm->join_list_size = data - bjpm->join_list;
		bjpm->join_addr_number++;
	    }
	    break;

	case PIM_ACTION_PRUNE:
	    if (rp_flag == TRUE) {
		bjpm->rp_list_prune_size = data - bjpm->rp_list_prune;
		bjpm->rp_list_prune_number++;
	    } else {
		bjpm->prune_list_size = data - bjpm->prune_list;
		bjpm->prune_addr_number++;
	    }
	    break;

	default:
	    return FALSE;
    }

    return TRUE;
}


static build_jp_message_t *get_jp_working_buff(void)
{
    build_jp_message_t *bjpm;

    if (build_jp_message_pool_counter == 0) {
	bjpm = calloc(1, sizeof(build_jp_message_t));
	if (!bjpm)
	    return NULL;

	bjpm->next = NULL;

	bjpm->jp_message_size = 0;
	bjpm->jp_message = calloc(1, MAX_JP_MESSAGE_SIZE + sizeof(pim_jp_header_t));
	if (!bjpm->jp_message) {
	    free(bjpm);
	    return NULL;
	}

	bjpm->join_list_size = 0;
	bjpm->join_addr_number = 0;
	bjpm->join_list = calloc(1, MAX_JP_MESSAGE_SIZE - sizeof(pim_jp_encod_grp_t));
	if (!bjpm->join_list) {
	    free(bjpm->jp_message);
	    free(bjpm);
	    return NULL;
	}

	bjpm->prune_list_size = 0;
	bjpm->prune_addr_number = 0;
	bjpm->prune_list = calloc(1, MAX_JP_MESSAGE_SIZE - sizeof(pim_jp_encod_grp_t));
	if (!bjpm->prune_list) {
	    free(bjpm->join_list);
	    free(bjpm->jp_message);
	    free(bjpm);
	    return NULL;
	}

	bjpm->rp_list_join_size = 0;
	bjpm->rp_list_join_number = 0;
	bjpm->rp_list_join = calloc(1, MAX_JP_MESSAGE_SIZE - sizeof(pim_jp_encod_grp_t));
	if (!bjpm->rp_list_join) {
	    free(bjpm->prune_list);
	    free(bjpm->join_list);
	    free(bjpm->jp_message);
	    free(bjpm);
	    return NULL;
	}

	bjpm->rp_list_prune_size = 0;
	bjpm->rp_list_prune_number = 0;
	bjpm->rp_list_prune = calloc(1, MAX_JP_MESSAGE_SIZE - sizeof(pim_jp_encod_grp_t));
	if (!bjpm->rp_list_prune) {
	    free(bjpm->rp_list_join);
	    free(bjpm->prune_list);
	    free(bjpm->join_list);
	    free(bjpm->jp_message);
	    free(bjpm);
	    return NULL;
	}

	bjpm->curr_group = INADDR_ANY_N;
	bjpm->curr_group_msklen = 0;
	bjpm->curr_group_wc = FALSE;
	bjpm->holdtime = 0;

	return bjpm;
    }

    bjpm = build_jp_message_pool;
    build_jp_message_pool = build_jp_message_pool->next;
    build_jp_message_pool_counter--;
    bjpm->jp_message_size   = 0;
    bjpm->join_list_size    = 0;
    bjpm->join_addr_number  = 0;
    bjpm->prune_list_size   = 0;
    bjpm->prune_addr_number = 0;
    bjpm->curr_group        = INADDR_ANY_N;
    bjpm->curr_group_msklen = 0;
    bjpm->curr_group_wc     = FALSE;

    return bjpm;
}


static void return_jp_working_buff(pim_nbr_entry_t *pim_nbr)
{
    build_jp_message_t *bjpm = pim_nbr->build_jp_message;

    if (!bjpm)
	return;

    /* Don't waste memory by keeping too many free buffers */
    /* TODO: check/modify the definitions for POOL_NUMBER and size */
    if (build_jp_message_pool_counter >= MAX_JP_MESSAGE_POOL_NUMBER) {
	free(bjpm->jp_message);
	free(bjpm->join_list);
	free(bjpm->prune_list);
	free(bjpm->rp_list_join);
	free(bjpm->rp_list_prune);
	free(bjpm);
    } else {
	bjpm->next = build_jp_message_pool;
	build_jp_message_pool = bjpm;
	build_jp_message_pool_counter++;
    }

    pim_nbr->build_jp_message = NULL;
}


static void pack_jp_message_grp(pim_nbr_entry_t *pim_nbr)
{
    build_jp_message_t *bjpm;
    uint8_t *data;

    bjpm = pim_nbr->build_jp_message;
    if (!bjpm)
	return;

    if (bjpm->join_list_size + bjpm->prune_list_size) {
	data = bjpm->jp_message + bjpm->jp_message_size;
	PUT_EGADDR(bjpm->curr_group, bjpm->curr_group_msklen, 0, data);
	PUT_HOSTSHORT(bjpm->join_addr_number, data);
	PUT_HOSTSHORT(bjpm->prune_addr_number, data);
	memcpy(data, bjpm->join_list, bjpm->join_list_size);
	data += bjpm->join_list_size;
	memcpy(data, bjpm->prune_list, bjpm->prune_list_size);
	data += bjpm->prune_list_size;
	bjpm->jp_message_size = (data - bjpm->jp_message);
	bjpm->curr_group = INADDR_ANY_N;
	bjpm->curr_group_msklen = 0;
	bjpm->curr_group_wc = FALSE;
	bjpm->join_list_size = 0;
	bjpm->join_addr_number = 0;
	bjpm->prune_list_size = 0;
	bjpm->prune_addr_number = 0;
	(*bjpm->num_groups_ptr)++;
    }
}

static void pack_jp_message_rp(pim_nbr_entry_t *pim_nbr)
{
    build_jp_message_t *bjpm;
    uint8_t *data;

    bjpm = pim_nbr->build_jp_message;
    if (!bjpm)
	return;

    if (bjpm->rp_list_join_size + bjpm->rp_list_prune_size) {
	data = bjpm->jp_message + bjpm->jp_message_size;
	PUT_EGADDR(htonl(CLASSD_PREFIX), STAR_STAR_RP_MSKLEN, 0, data);
	PUT_HOSTSHORT(bjpm->rp_list_join_number, data);
	PUT_HOSTSHORT(bjpm->rp_list_prune_number, data);
	memcpy(data, bjpm->rp_list_join, bjpm->rp_list_join_size);
	data += bjpm->rp_list_join_size;
	memcpy(data, bjpm->rp_list_prune, bjpm->rp_list_prune_size);
	data += bjpm->rp_list_prune_size;
	bjpm->jp_message_size = (data - bjpm->jp_message);
	bjpm->rp_list_join_size = 0;
	bjpm->rp_list_join_number = 0;
	bjpm->rp_list_prune_size = 0;
	bjpm->rp_list_prune_number = 0;
	(*bjpm->num_groups_ptr)++;
    }
}


void pack_and_send_jp_message(pim_nbr_entry_t *pim_nbr)
{
    if (!pim_nbr)
	return;

    pack_jp_message_grp(pim_nbr);
    pack_jp_message_rp(pim_nbr);
    send_jp_message(pim_nbr);
}


/* The wire half, split out so that a group set that may not be split can
 * send the sets packed ahead of it and go on being built. */
static void jp_message_send(pim_nbr_entry_t *pim_nbr, build_jp_message_t *bjpm)
{
    vifi_t vifi = pim_nbr->vifi;

    memcpy(pim_send_buf + sizeof(struct ip) + sizeof(pim_header_t),
	   bjpm->jp_message, bjpm->jp_message_size);
    IF_DEBUG(DEBUG_PIM_JOIN_PRUNE)
	logit(LOG_INFO, 0, "Send PIM JOIN/PRUNE from %s on %s",
	      inet_fmt(uvifs[vifi].uv_lcl_addr, s1, sizeof(s1)), uvifs[vifi].uv_name);
    send_pim(pim_send_buf, uvifs[vifi].uv_lcl_addr, allpimrouters_group,
	     PIM_JOIN_PRUNE, bjpm->jp_message_size);
}

/* An empty Join/Prune message: the upstream neighbor, the holdtime already
 * chosen for this buffer, and no group sets yet. */
static void jp_message_restart(pim_nbr_entry_t *pim_nbr, build_jp_message_t *bjpm)
{
    uint8_t *data = bjpm->jp_message;

    PUT_EUADDR(pim_nbr->address, data);
    PUT_BYTE(0, data);			/* Reserved */
    bjpm->num_groups_ptr = data++;	/* The pointer for numgroups */
    *(bjpm->num_groups_ptr) = 0;	/* Zero groups */
    PUT_HOSTSHORT(bjpm->holdtime, data);
    bjpm->jp_message_size = data - bjpm->jp_message;
}

/*
 * Send the group sets already packed and start a new message, leaving the
 * one still under construction in the working area.  RFC 7761 sec. 4.9.5.2
 * lets a router split its Join/Prune information across messages but not a
 * group set that carries a (*,G) Join, so the split has to fall between
 * sets.
 *
 * Returns TRUE if anything went out, FALSE when that set is the only thing
 * in the message and there is nothing to make room with.
 */
static int flush_packed_groups(pim_nbr_entry_t *pim_nbr)
{
    build_jp_message_t *bjpm = pim_nbr->build_jp_message;

    if (!bjpm || !bjpm->num_groups_ptr || *bjpm->num_groups_ptr == 0)
	return FALSE;

    /* A (*,*,RP) set is a group set of its own and has no reason to wait
     * behind this one. */
    pack_jp_message_rp(pim_nbr);

    jp_message_send(pim_nbr, bjpm);
    jp_message_restart(pim_nbr, bjpm);

    return TRUE;
}

static void send_jp_message(pim_nbr_entry_t *pim_nbr)
{
    build_jp_message_t *bjpm;

    bjpm = pim_nbr->build_jp_message;
    if (!bjpm)
	return;

    jp_message_send(pim_nbr, bjpm);
    return_jp_working_buff(pim_nbr);
}


/************************************************************************
 *                        PIM_ASSERT
 ************************************************************************/
/* Header, encoded group, encoded source, then the preference and the
 * metric: everything receive_pim_assert() reads before it has looked at
 * anything in the message.  pim.c only guarantees a PIM header, so
 * without this an Assert truncated to its header had the parser reading
 * whatever the previous packet left in the receive buffer.
 */
#define PIM_ASSERT_MINLEN (sizeof(pim_header_t) + PIM_ENCODE_GRP_ADDR_LEN	\
			   + PIM_ENCODE_UNI_ADDR_LEN + 2 * sizeof(uint32_t))

/* infinite_assert_metric(), RFC 7761 sec. 4.6.3: {1, infinity, infinity, 0}.
 * The RPT bit is the top bit of the preference field, so "infinity" is the
 * rest of it.  An Assert carrying this loses to every real metric, which is
 * the whole of what sec. 4.6.4 needs an AssertCancel to be.
 */
#define PIM_ASSERT_INFINITE_PREFERENCE	(PIM_ASSERT_RPT_BIT | 0x7fffffff)
#define PIM_ASSERT_INFINITE_METRIC	0xffffffff

/*
 * The three states of RFC 7761 sec. 4.6.1 and sec. 4.6.2: NoInfo holds no
 * winner, and the `is_winner` flag of struct assert_state tells the other
 * two apart.  Not the interface's own address, which renumber_vif() can
 * replace under an entry that is holding assert state -- see src/mrt.h.
 */
static struct assert_state *assert_state(mrtentry_t *mrt, vifi_t vifi)
{
    if (!mrt || !mrt->asserts || vifi >= numvifs)
	return NULL;

    return &mrt->asserts[vifi];
}

int assert_winner_is_me(mrtentry_t *mrt, vifi_t vifi)
{
    struct assert_state *as = assert_state(mrt, vifi);

    return as && as->winner != INADDR_ANY_N && as->is_winner;
}

int assert_lost_on(mrtentry_t *mrt, vifi_t vifi)
{
    struct assert_state *as = assert_state(mrt, vifi);

    return as && as->winner != INADDR_ANY_N && !as->is_winner;
}

/*
 * lost_assert(S,G,I) of sec. 4.6.5, which is more than "I am Assert Loser":
 * it is that, and the winner's metric being better than spt_assert_metric(S,I)
 * as well.  The Note under the macro says what the third term is for -- "the
 * transition phase when a router has (S,G) join state but has not yet set
 * the SPTbit.  In this case, it needs to ignore the assert state if it will
 * win the assert once the SPTbit is set" -- so the term is asked exactly
 * where the bit is still clear, and gating it on the bit, as pimd did, is
 * the one reading that makes it dead code.
 *
 * This is the macro the state-maintenance olists subtract, sec. 4.1.5:
 * immediate_olist(S,G), which JoinDesired(S,G) is read off, and the
 * source-specific half of inherited_olist(S,G).  Forwarding asks
 * lost_assert_rpt() below instead.  A (*,G) entry has no third term to ask:
 * lost_assert(*,G,I) stops at "not me", and so the two agree there.
 */
int lost_assert(mrtentry_t *mrt, vifi_t vifi)
{
    struct assert_state *as = assert_state(mrt, vifi);
    uint32_t preference, metric;

    if (!assert_lost_on(mrt, vifi))
	return FALSE;

    /* "if RPF_interface(S) == I: return FALSE" */
    if (vifi == mrt->incoming)
	return FALSE;

    if (!(mrt->flags & MRTF_SG) || (mrt->flags & MRTF_RP))
	return TRUE;

    spt_assert_metric(mrt, &preference, &metric);

    /* compare_metrics() answers for its first pair, so ask it whether the
     * winner beats what we would assert with from the shortest path tree. */
    return compare_metrics(as->preference, as->metric, as->winner,
			   preference, metric, uvifs[vifi].uv_lcl_addr);
}

/*
 * lost_assert(S,G,rpt,I) of the same section, and lost_assert(*,G,I) where
 * the entry is the (*,G) itself: the same winner, read without the metric
 * comparison.  This is the one the olist sec. 4.2 forwards off subtracts,
 * because until SPTbit(S,G) is set what it forwards off is
 * inherited_olist(S,G,rpt) -- a router that has decided to take the source
 * off the shared tree, and would win the election once it does, still must
 * not forward there while the winner is the one delivering the traffic.
 *
 * Keeping the two apart is what breaks the deadlock the Note describes: the
 * router goes on asking for the source it needs to reach the shortest path
 * tree while it stops forwarding what it has not got yet.
 */
int lost_assert_rpt(mrtentry_t *mrt, vifi_t vifi)
{
    if ((mrt->flags & MRTF_SG) && !(mrt->flags & MRTF_RP) && !(mrt->flags & MRTF_SPT))
	return assert_lost_on(mrt, vifi) && vifi != mrt->incoming;

    return lost_assert(mrt, vifi);
}

/* Does any interface hold assert state?  MRTF_ASSERTED mirrors that, for the
 * dumps and for the entries whose upstream came from an Assert on the iif. */
static void assert_update_flag(mrtentry_t *mrt)
{
    vifi_t vifi;

    mrt->flags &= ~MRTF_ASSERTED;
    if (!mrt->asserts)
	return;

    for (vifi = 0; vifi < numvifs; vifi++) {
	if (mrt->asserts[vifi].winner != INADDR_ANY_N) {
	    mrt->flags |= MRTF_ASSERTED;
	    return;
	}
    }
}

/* Actions A1 and A3: we sent the Assert, so we own the interface until
 * Assert_Time, and rearm short of it to resend before the losers time out. */
static void assert_won(mrtentry_t *mrt, vifi_t vifi, uint32_t source,
		       uint32_t preference, uint32_t metric)
{
    struct assert_state *as = assert_state(mrt, vifi);

    /* An interface with no address of its own has none to win an election
     * with, and a zero winner reads back as NoInfo, which would leave the
     * timer running with nothing to expire. */
    if (!as || uvifs[vifi].uv_lcl_addr == INADDR_ANY_N)
	return;

    as->winner     = uvifs[vifi].uv_lcl_addr;
    as->is_winner  = TRUE;
    as->preference = preference;
    as->metric     = metric;
    as->source     = source;
    SET_TIMER(as->timer, PIM_ASSERT_WINNER_TIMEOUT);
    mrt->flags |= MRTF_ASSERTED;
}

/* Actions A2 and A6: store the new winner and what it won with, and hold it
 * for Assert_Time.  The metric is the winner's, never ours to advertise. */
static void assert_lost(mrtentry_t *mrt, vifi_t vifi, uint32_t winner,
			uint32_t preference, uint32_t metric)
{
    struct assert_state *as = assert_state(mrt, vifi);

    if (!as)
	return;

    as->winner     = winner;
    as->is_winner  = FALSE;
    as->preference = preference;
    as->metric     = metric;
    SET_TIMER(as->timer, PIM_ASSERT_TIMEOUT);
    mrt->flags |= MRTF_ASSERTED;

    IF_DEBUG(DEBUG_PIM_ASSERT)
	logit(LOG_INFO, 0, "Assert lost on %s for group %s, winner %s",
	      uvifs[vifi].uv_name,
	      inet_fmt(mrt->group ? mrt->group->group : INADDR_ANY_N, s1, sizeof(s1)),
	      inet_fmt(winner, s2, sizeof(s2)));
}

/* Actions A5: delete the assert information, i.e. back to NoInfo. */
static void assert_noinfo(mrtentry_t *mrt, vifi_t vifi)
{
    struct assert_state *as = assert_state(mrt, vifi);

    if (!as)
	return;

    as->winner     = INADDR_ANY_N;
    as->is_winner  = FALSE;
    as->preference = 0;
    as->metric     = 0;
    as->source     = INADDR_ANY_N;
    RESET_TIMER(as->timer);
    assert_update_flag(mrt);
}

/*
 * Actions A5 on one downstream interface, plus the oif it took away.  The
 * "Receive Join(S,G) on interface I" and "Assert Timer Expires" transitions
 * of the Loser state both land here; sec. 4.6.1 wants the normal Join/Prune
 * mechanisms to operate again, and in pimd that means the interface coming
 * back out of `asserted_oifs`.
 *
 * Returns TRUE if the oif list has to be recomputed.
 */
static int assert_clear(mrtentry_t *mrt, vifi_t vifi)
{
    int restore;

    if (!assert_state(mrt, vifi))
	return FALSE;

    /* Only the Loser state has these transitions.  A Join arriving on an
     * interface we won is the downstream router asking for the traffic we
     * are already forwarding there, and dropping the winner state for it
     * would stop the resend of Actions A3 and the AssertCancel of Actions
     * A4 that the interface still owes.
     */
    if (assert_winner_is_me(mrt, vifi))
	return FALSE;

    restore = PIMD_VIFM_ISSET(vifi, mrt->asserted_oifs) != 0;
    if (restore)
	PIMD_VIFM_CLR(vifi, mrt->asserted_oifs);

    assert_noinfo(mrt, vifi);

    return restore;
}

/*
 * Actions A4: the winner is about to stop forwarding on I, so it sends an
 * Assert with an infinite metric -- the AssertCancel of sec. 4.6.4 -- and
 * returns to NoInfo.  Without it the losers wait Assert_Time out before
 * anything takes over, which is the difference between a subnet that
 * converges in a second and one that black-holes the group for three
 * minutes.  Item 8 of the design list at sec. 4.10 is the rationale.
 */
void send_pim_assert_cancel(mrtentry_t *mrt, vifi_t vifi)
{
    struct assert_state *as = assert_state(mrt, vifi);

    if (!as || !mrt->group)
	return;

    if (!(uvifs[vifi].uv_flags & (VIFF_DOWN | VIFF_DISABLED)))
	assert_send(as->source, mrt->group->group, vifi,
		    PIM_ASSERT_INFINITE_PREFERENCE, PIM_ASSERT_INFINITE_METRIC);

    assert_noinfo(mrt, vifi);
}

/*
 * The Assert Timer of sec. 4.6.1 and sec. 4.6.2, aged once per
 * age_routes() pass: a winner resends and rearms (Actions A3), a loser
 * returns to NoInfo and gives the interface back (Actions A5).  One timer
 * per interface, because two LANs that assert independently expire
 * independently.
 *
 * The Loser state has a second way out that is aged here rather than
 * timed, "my metric becomes better than the assert winner's metric": the
 * routing table moved under us and the election we lost is now ours to
 * win.  It is worth asking once per pass only because that metric is the
 * routing table's, so it can change without pimd doing anything; while it
 * was a constant from pimd.conf, nothing but a Join or the timer could
 * ever take a loser out of the state.  Both machines ask it of downstream
 * interfaces alone: on RPF_interface(S) the answer is CouldAssert(S,G,I)
 * == FALSE, i.e. an infinite metric, which is never better than anything.
 *
 * Returns TRUE if any oif came back, i.e. if the caller owes a
 * change_interfaces().
 */
int age_asserts(mrtentry_t *mrt)
{
    int change = FALSE;
    vifi_t vifi;

    if (!mrt->asserts)
	return FALSE;

    for (vifi = 0; vifi < numvifs; vifi++) {
	struct assert_state *as = &mrt->asserts[vifi];
	uint32_t preference, metric;

	if (as->winner == INADDR_ANY_N)
	    continue;

	if (!as->is_winner && vifi != mrt->incoming) {
	    my_assert_metric(mrt, &preference, &metric);

	    /* Actions A5, and sec. 4.6.1 lets the normal Join/Prune
	     * mechanisms operate again: we re-assert and win it back once
	     * packets from the source flow on the interface once more.
	     */
	    if (compare_metrics(preference, metric, uvifs[vifi].uv_lcl_addr,
				as->preference, as->metric, as->winner) == TRUE) {
		IF_DEBUG(DEBUG_PIM_ASSERT)
		    logit(LOG_INFO, 0, "Assert winner %s on %s no longer has the better metric, resuming",
			  inet_fmt(as->winner, s1, sizeof(s1)), uvifs[vifi].uv_name);

		if (assert_clear(mrt, vifi))
		    change = TRUE;

		continue;
	    }
	}

	IF_TIMEOUT(as->timer) {
	    if (!as->is_winner) {
		if (assert_clear(mrt, vifi))
		    change = TRUE;
		continue;
	    }

	    /* Actions A3, which is Actions A1 sent a second time. */
	    if (!mrt->group || !send_pim_assert(as->source, mrt->group->group, vifi, mrt))
		assert_noinfo(mrt, vifi);
	}
    }

    return change;
}

/*
 * "Current Winner's GenID Changes or NLT Expires" -- the Loser state of both
 * state machines, Actions A5.  The winner's router or interface has gone
 * down and may have come back up, so it no longer knows it won; holding the
 * interface off for the rest of Assert_Time costs up to three minutes of
 * complete loss for nothing.
 */
static void assert_forget_winner(mrtentry_t *mrt, vifi_t vifi, uint32_t addr,
				 const char *why)
{
    struct assert_state *as;

    /* No assert state on any interface, which is the usual answer: a router
     * holds it only where it has contended for a link.  One flag test, so
     * that a neighbor restarting does not cost a walk of every interface of
     * every routing entry to find nothing. */
    if (!mrt || !(mrt->flags & MRTF_ASSERTED))
	return;

    /* And only the interface the neighbor is on.  An Assert from it was
     * received there and nowhere else, so its address cannot be the winner
     * of an election held on another link -- where the same address may
     * well be some other router's, which is what two interfaces numbered
     * out of the same private range look like. */
    as = assert_state(mrt, vifi);
    if (!as || as->winner != addr)
	return;

    if (assert_clear(mrt, vifi)) {
	/* The other ways out of the Loser state each say so, and this one
	 * left no trace at all -- which also made it the one transition of
	 * sec. 4.6 that nothing could be written a test against.  `why`
	 * tells the two events that land here apart: "Current Winner's
	 * GenID Changes" is a router that is already back, "NLT Expires"
	 * is one that is not, and a graceful shutdown reaches the second
	 * through the zero holdtime Hello of cleanup() (src/main.c), so
	 * only a router that was cut off reaches the first at all. */
	IF_DEBUG(DEBUG_PIM_ASSERT)
	    logit(LOG_INFO, 0, "Assert winner %s on %s %s, resuming %s",
		  inet_fmt(addr, s1, sizeof(s1)), uvifs[vifi].uv_name, why,
		  inet_fmt(mrt->group ? mrt->group->group : INADDR_ANY_N, s2, sizeof(s2)));

	change_interfaces(mrt, mrt->incoming, mrt->joined_oifs,
			  mrt->pruned_oifs, mrt->leaves,
			  mrt->asserted_oifs, 0);
    }
}

static void assert_neighbor_gone(vifi_t vifi, uint32_t addr, const char *why)
{
    grpentry_t *grp, *grp_next;
    mrtentry_t *mrt, *mrt_next;

    if (addr == INADDR_ANY_N || vifi >= numvifs)
	return;

    /* Every mrtentry_t is either a group's grp_route or on its mrtlink, so
     * this pair of loops is the whole routing table.  The next pointers are
     * saved because assert_forget_winner() ends in change_interfaces(). */
    for (grp = grplist; grp; grp = grp_next) {
	grp_next = grp->next;
	assert_forget_winner(grp->grp_route, vifi, addr, why);

	for (mrt = grp->mrtlink; mrt; mrt = mrt_next) {
	    mrt_next = mrt->grpnext;
	    assert_forget_winner(mrt, vifi, addr, why);
	}
    }
}

/*
 * What one run of one of the two Assert state machines did with the
 * message.  Sec. 4.6.2 needs no more than this: the (*,G) machine may run
 * only if the (S,G) one held no state and did not move.  ASSERT_CANCELLED
 * is the one case where it may run anyway -- see receive_pim_assert().
 */
#define ASSERT_NOTHING	0
#define ASSERT_MOVED	1
#define ASSERT_CANCELLED	2

/*
 * One run of a per-interface Assert state machine: sec. 4.6.1's on an (S,G)
 * entry, sec. 4.6.2's on a (*,G) one, `wc` saying which of the two this is.
 * They are two machines with two sets of events, and the RPT bit of the
 * message is what tells the events apart.  Every transition the (*,G)
 * machine has out of NoInfo, and every one that replaces the winner it
 * holds, is on an Assert carrying the bit; the (S,G) machine answers one
 * without the bit with a metric of its own, and one with the bit only from
 * the shortest path tree, which is what CouldAssert(S,G,I) asks for.
 *
 * `mrt` is the entry this machine reads its metric and its interfaces from.
 * `own` is the entry holding its per-interface state, the same entry except
 * for an (S,G) machine that has no (S,G) entry yet: there the state is
 * NoInfo by definition, the metric and the olist are the ones the (*,G)
 * lends it through inherited_olist(S,G), and an entry of its own is created
 * only once it has Loser state to keep.
 *
 * Returns ASSERT_MOVED if the machine took the message, which is what keeps
 * the (*,G) machine out of it, and ASSERT_CANCELLED if it took it by giving
 * the interface back, which does not.
 */
static int assert_machine(mrtentry_t *mrt, mrtentry_t *own, vifi_t vifi, int wc,
			  uint32_t src, uint32_t source, uint32_t group,
			  uint32_t rptbit, uint32_t assert_preference,
			  uint32_t assert_metric)
{
    srcentry_t *orig_src;
    uint32_t local_preference, local_metric;
    struct assert_state *as;
    struct uvif *v;
    uint8_t local_wins;
    uint16_t jp_value;

    if (!mrt)
	return ASSERT_NOTHING;

    v = &uvifs[vifi];

    /*
     * RFC 7761 sec. 4.6.1 keys the NoInfo-to-Loser transition on
     * AssertTrackingDesired(S,G,I), which is join state, local membership or
     * the interface being upstream -- it says nothing about traffic.  pimd
     * used to require MRTF_KERNEL_CACHE here, and that cache is torn down
     * the moment the oif list empties, which is exactly what losing an
     * assert does: the loser was then deaf to every later Assert on the
     * interface, its winner's resend and the AssertCancel of sec. 4.6.4
     * included, and could only leave the Loser state when its own timer ran
     * out.  Ask whether the interface interests us, which is the question
     * the spec asks.
     */
    if (!(mrt->flags & MRTF_KERNEL_CACHE) &&
	vifi != mrt->incoming &&
	!PIMD_VIFM_ISSET(vifi, mrt->joined_oifs) &&
	!PIMD_VIFM_ISSET(vifi, mrt->leaves) &&
	!PIMD_VIFM_ISSET(vifi, mrt->asserted_oifs)) {
	/* Nothing here cares about this interface. Ignore the assert */
	return ASSERT_NOTHING;
    }

    /* Prepare the local preference and metric, RPT bit included */
    my_assert_metric(mrt, &local_preference, &local_metric);

    /* An interface we lost an Assert on is no longer in `oifs` -- that is
     * what losing does -- so testing `oifs` alone made every later Assert on
     * it unreachable, the AssertCancel of RFC 7761 sec. 4.6.4 included, and
     * left the Loser state with no transition out of it but its own timer.
     * The interface is still downstream while assert state holds it out.
     *
     * An (S,G) machine with no (S,G) entry yet reads that state off the
     * (*,G) it already borrows its metric and its olist from.  Anything
     * narrower leaves it unreachable for as long as the (*,G) is the loser
     * on the interface, which is the one state a last hop router held on
     * the shared tree beside a router on the shortest path tree is in:
     * sec. 4.6.1 gates the NoInfo-to-Loser transition on
     * AssertTrackingDesired(S,G,I), which is join and membership state and
     * says nothing about the outgoing interfaces.
     */
    if (PIMD_VIFM_ISSET(vifi, mrt->oifs) ||
	(vifi != mrt->incoming && assert_lost_on(own ? own : mrt, vifi))) {
	/* The ASSERT has arrived on oif */
	as = own ? assert_state(own, vifi) : NULL;

	if (as && assert_lost_on(own, vifi)) {
	    /* "I am Assert Loser", sec. 4.6.1 and sec. 4.6.2.  Only the
	     * current winner can take us out of it, and a preferred Assert
	     * from anyone can replace it.
	     */
	    if (src == as->winner) {
		/* Inferior to our own metric, an AssertCancel included:
		 * back to NoInfo and let Join/Prune operate again.  Neither
		 * machine asks for the RPT bit here, sec. 4.6.4. */
		if (compare_metrics(local_preference, local_metric, v->uv_lcl_addr,
				    assert_preference, assert_metric, src) == TRUE) {
		    IF_DEBUG(DEBUG_PIM_ASSERT)
			logit(LOG_INFO, 0, "Assert winner %s on %s gave up %s, resuming",
			      inet_fmt(src, s1, sizeof(s1)), v->uv_name,
			      inet_fmt(group, s2, sizeof(s2)));

		    if (assert_clear(own, vifi))
			change_interfaces(own, own->incoming, own->joined_oifs,
					  own->pruned_oifs, own->leaves,
					  own->asserted_oifs, 0);

		    return ASSERT_CANCELLED;
		}

		/* Acceptable Assert from the current winner: Actions A2, it
		 * keeps the interface and refreshes the timer.  The (*,G)
		 * machine takes it only with the RPT bit set. */
		if (wc && !rptbit)
		    return ASSERT_NOTHING;

		assert_lost(own, vifi, src, assert_preference, assert_metric);

		return ASSERT_MOVED;
	    }

	    /* From anyone else, only an Assert better than the one the
	     * winner holds changes anything: Actions A2 again, and again
	     * only with the RPT bit set for the (*,G) machine. */
	    if (wc && !rptbit)
		return ASSERT_NOTHING;

	    if (compare_metrics(as->preference, as->metric, as->winner,
				assert_preference, assert_metric, src) == FALSE) {
		assert_lost(own, vifi, src, assert_preference, assert_metric);

		return ASSERT_MOVED;
	    }

	    return ASSERT_NOTHING;
	}

	/* NoInfo, or "I am Assert Winner".  The (*,G) machine leaves NoInfo
	 * only for an Assert with the RPT bit set, sec. 4.6.2; one without
	 * it is the (S,G) machine's, which has already had it.  The Winner
	 * state answers either, Actions A3.
	 */
	if (wc && !rptbit && !(own && assert_winner_is_me(own, vifi)))
	    return ASSERT_NOTHING;

	/* And the (S,G) machine leaves NoInfo on an Assert that carries the
	 * bit only when CouldAssert(S,G,I) holds, which needs SPTbit(S,G):
	 * an RPT forwarder has no (S,G) answer to give, so the message goes
	 * on to the (*,G) machine instead.
	 */
	if (!wc && rptbit && !(mrt->flags & MRTF_SPT) &&
	    !(own && assert_winner_is_me(own, vifi)))
	    return ASSERT_NOTHING;

	local_wins = compare_metrics(local_preference, local_metric,
				     v->uv_lcl_addr, assert_preference,
				     assert_metric, src);

	if (local_wins == TRUE) {
	    /* Actions A1, or Actions A3 from the Winner state: the
	     * interface is ours and we say so. */
	    send_pim_assert(source, group, vifi, own ? own : mrt);

	    return ASSERT_MOVED;
	}

	/* We lost, and sec. 4.6.1 has no NoInfo-to-Loser transition for an
	 * Assert with the RPT bit set: that one is the (*,G) machine's, and
	 * losing it there is what takes the group off this interface.
	 */
	if (!wc && rptbit)
	    return ASSERT_NOTHING;

	if (!own) {
	    /* Loser state to keep, so the (S,G) machine needs an entry of
	     * its own now.
	     */
	    own = find_route(source, group, MRTF_SG, CREATE);
	    if (!own)
		return ASSERT_NOTHING;

	    if (own->flags & MRTF_NEW) {
		own->flags &= ~MRTF_NEW;
		/* TODO: XXX: The spec doesn't say what entry timer value
		 * to use when the routing entry is created because of asserts.
		 */
		SET_TIMER(own->entry_timer, PIM_DATA_TIMEOUT);
	    }
	}

	/* Actions A6: "I am Assert Loser" on this interface.  The interface
	 * leaves the olist with it, which is lost_assert(S,G,I) of
	 * sec. 4.6.5 as pimd spells it.
	 */
	PIMD_VIFM_SET(vifi, own->asserted_oifs);
	assert_lost(own, vifi, src, assert_preference, assert_metric);

	/* TODO: XXX: check that the timer of all affected routing entries
	 * has been restarted.
	 */
	change_interfaces(own,
			  own->incoming,
			  own->joined_oifs,
			  own->pruned_oifs,
			  own->leaves,
			  own->asserted_oifs, 0);

	return ASSERT_MOVED;
    } /* End of assert received on oif */


    if (own && own->incoming == vifi) {
	/* Assert received on iif */
	if (rptbit) {
	    if (!(own->flags & MRTF_RP))
		return ASSERT_NOTHING; /* The locally used upstream router
					* will win the assert, so don't
					* change it.
					*/
	}

	/* Ignore assert message if we do not have an upstream router */
	if (own->upstream == NULL)
	    return ASSERT_NOTHING;

	as = assert_state(own, vifi);
	if (as && as->winner == own->upstream->address) {
	    /* Already lost this interface, so the assert to beat is the
	     * winner's, per the Loser state of RFC 7761 sec. 4.6.1, not a
	     * metric of our own.
	     */
	    local_preference = as->preference;
	    local_metric     = as->metric;
	} else {
	    my_assert_metric(own, &local_preference, &local_metric);
	}

	local_wins = compare_metrics(local_preference, local_metric,
				     own->upstream->address,
				     assert_preference, assert_metric, src);

	if (local_wins == TRUE)
	    return ASSERT_NOTHING;

	/* The upstream must be changed to the winner.  Keep what it won
	 * with as the winner's, not as this entry's own metric: sec. 4.6.3
	 * has us assert with the metric the unicast routing table gives,
	 * and copying the winner's into `metric` had us advertise it as
	 * ours on every other interface, where it beat routers that really
	 * are closer to the source.
	 */
	assert_lost(own, vifi, src, assert_preference, assert_metric);
	own->upstream = find_pim_nbr(src);

	/* RFC 7761 sec. 4.5.5, "RPF'(S,G) changes due to an Assert": "If the
	 * Join Timer is set to expire in more than t_override seconds, reset
	 * it so that it expires after t_override seconds."  Our downstream
	 * receivers are behind the assert winner now, and it does not know
	 * about them until we say so; waiting for the periodic Join left
	 * them without the group for up to a whole period.
	 */
	jp_value = jp_override_timeout(vifi);
	if (own->jp_timer > jp_value)
	    SET_TIMER(own->jp_timer, jp_value);

	/* Check if the upstream router is different from the original one.
	 * Read the entry the routing table names it on the way
	 * reset_upstream_router() above does: a group is left holding its
	 * routing entries but no active_rp_grp when the RP set it matched
	 * goes away, and an entry that cannot name its original upstream
	 * cannot be back on it either, so leave the assert state alone.
	 */
	if (own->flags & MRTF_RP)
	    orig_src = own->group->active_rp_grp
		? own->group->active_rp_grp->rp->rpentry
		: NULL;
	else
	    orig_src = own->source;

	if (orig_src && own->upstream == orig_src->upstream) {
	    /* Back on the upstream the routing table names, so there is no
	     * winner to keep a metric for. */
	    assert_noinfo(own, vifi);
	}

	return ASSERT_MOVED;
    }

    return ASSERT_NOTHING;
}

int receive_pim_assert(uint32_t src, uint32_t dst, char *msg, size_t len)
{
    vifi_t vifi;
    pim_encod_uni_addr_t eusaddr;
    pim_encod_grp_addr_t egaddr;
    uint32_t source, group;
    mrtentry_t *sg, *wc;
    uint8_t *data;
    struct uvif *v;
    uint32_t assert_preference;
    uint32_t assert_metric;
    uint32_t assert_rptbit;
    int held, rc;

    (void)dst;

    vifi = find_vif_direct(src);
    if (vifi == NO_VIF) {
	/* Either a local vif or somehow received PIM_ASSERT from
	 * non-directly connected router. Ignore it.
	 */
	if (local_address(src) == NO_VIF) {
	    IF_DEBUG(DEBUG_PIM_ASSERT)
		logit(LOG_INFO, 0, "Ignoring PIM_ASSERT from non-directly connected router %s",
		      inet_fmt(src, s1, sizeof(s1)));
	}

	return FALSE;
    }

    /* Checksum */
    if (inet_cksum((uint16_t *)msg, len))
	return FALSE;

    v = &uvifs[vifi];
    if (uvifs[vifi].uv_flags & (VIFF_DOWN | VIFF_DISABLED | VIFF_NONBRS | VIFF_REGISTER))
	return FALSE;    /* Shoudn't come on this interface */

    /* RFC 7761 sec. 4.6: an Assert from an address we have had no PIM Hello
     * from is discarded without further processing.  Otherwise any host on
     * the LAN can win an election it is not even taking part in.
     */
    if (!pim_nbr_accepted(vifi, src)) {
	IF_DEBUG(DEBUG_PIM_ASSERT)
	    logit(LOG_NOTICE, 0, "Ignoring Assert from %s on %s, not in its accept-nbr-from list",
		  inet_fmt(src, s1, sizeof(s1)), v->uv_name);

	return FALSE;
    }

    if (!find_pim_nbr_on_vif(vifi, src)) {
	IF_DEBUG(DEBUG_PIM_ASSERT)
	    logit(LOG_NOTICE, 0, "Ignoring Assert from %s on %s, no PIM Hello seen from it",
		  inet_fmt(src, s1, sizeof(s1)), v->uv_name);

	return FALSE;
    }

    /* sanity check for the minimum length */
    if (len < PIM_ASSERT_MINLEN) {
	IF_DEBUG(DEBUG_PIM_ASSERT)
	    logit(LOG_NOTICE, 0, "Too short Assert message (%zu bytes) from %s on %s",
		  len, inet_fmt(src, s1, sizeof(s1)), v->uv_name);

	return FALSE;
    }

    data = (uint8_t *)(msg + sizeof(pim_header_t));

    /* Get the group and source addresses */
    GET_EGADDR(&egaddr, data);
    GET_EUADDR(&eusaddr, data);

    if (!encoded_addr_ok(egaddr.addr_family, egaddr.encod_type) ||
	!encoded_addr_ok(eusaddr.addr_family, eusaddr.encod_type)) {
	IF_DEBUG(DEBUG_PIM_ASSERT)
	    logit(LOG_NOTICE, 0, "Ignoring Assert from %s on %s, an encoded address is not IPv4",
		  inet_fmt(src, s1, sizeof(s1)), v->uv_name);

	return FALSE;
    }

    /* Get the metric related info */
    GET_HOSTLONG(assert_preference, data);
    GET_HOSTLONG(assert_metric, data);
    assert_rptbit = assert_preference & PIM_ASSERT_RPT_BIT;

    source = eusaddr.unicast_addr;
    group = egaddr.mcast_addr;

    IF_DEBUG(DEBUG_PIM_ASSERT)
	logit(LOG_INFO, 0, "Received PIM ASSERT from %s for group %s and source %s",
	      inet_fmt(src, s1, sizeof(s1)), inet_fmt(group, s2, sizeof(s2)),
	      inet_fmt(source, s3, sizeof(s3)));

    /*
     * Both addresses are attacker input and both are about to be used as
     * routing table keys, the find_route(..., CREATE) in assert_machine()
     * included.  Every other receive_*() in this file screens them before
     * that point -- receive_pim_register() at the inner header,
     * receive_pim_join_prune() once per group and once per source -- and
     * this one did not, so an Assert could seed an entry on a group that is
     * not multicast at all, or on a loopback, class E or multicast
     * "source", and hand those on to set_incoming() and k_chg_mfc().
     *
     * A (*,G) Assert carries a zero source, RFC 7761 sec. 4.9.6, which is
     * not a host address and has to stay allowed: it is what tells
     * receive_pim_assert() below that there is no (S,G) machine to run.
     */
    if (!IN_MULTICAST(ntohl(group))) {
	IF_DEBUG(DEBUG_PIM_ASSERT)
	    logit(LOG_NOTICE, 0, "Ignoring Assert from %s on %s, %s is not a multicast group",
		  inet_fmt(src, s1, sizeof(s1)), v->uv_name,
		  inet_fmt(group, s2, sizeof(s2)));

	return FALSE;
    }

    if (source != INADDR_ANY_N && !inet_valid_host(source)) {
	IF_DEBUG(DEBUG_PIM_ASSERT)
	    logit(LOG_NOTICE, 0, "Ignoring Assert from %s on %s, %s is not a valid source",
		  inet_fmt(src, s1, sizeof(s1)), v->uv_name,
		  inet_fmt(source, s2, sizeof(s2)));

	return FALSE;
    }

    /*
     * Sec. 4.6 defines two Assert state machines, an (S,G) one and a (*,G)
     * one, and sec. 4.6.2 fixes the order they run in: the message is
     * matched against the (S,G) machine first, and reaches the (*,G) one
     * only if the (S,G) machine is in NoInfo both before and after -- an
     * Assert that moved it belongs to that machine alone.  A (*,G) Assert
     * carries the source of the data packet that triggered it or zero,
     * sec. 4.9.6, and with zero there is no (S,G) machine to run at all.
     *
     * pimd used to pick one entry for both machines, the longest match
     * preferring one with a kernel cache, and run a single election on it,
     * so a router holding both (S,G) and (*,G) state for a group could keep
     * assert state for only one of the two per interface.
     */
    wc = find_route(INADDR_ANY_N, group, MRTF_WC, DONT_CREATE);
    sg = source != INADDR_ANY_N
	? find_route(source, group, MRTF_SG, DONT_CREATE)
	: NULL;

    if (source != INADDR_ANY_N) {
	/* NoInfo before the message is the other half of what sec. 4.6.2
	 * asks: state we already hold on this interface keeps the (*,G)
	 * machine out even where this message changes nothing. */
	held = sg && (assert_lost_on(sg, vifi) || assert_winner_is_me(sg, vifi));

	rc = assert_machine(sg ? sg : wc, sg, vifi, FALSE, src, source, group,
			    assert_rptbit, assert_preference, assert_metric);
	if (rc == ASSERT_MOVED)
	    return TRUE;

	/* The exception, and the whole of why the (S,G) machine returns its
	 * two answers apart.  An AssertCancel, sec. 4.6.4, is the one message
	 * that hands the interface back rather than taking it, and a router
	 * that lost both machines to the same winner -- the (*,G) first, on
	 * the shared tree, and the (S,G) once the winner moved to the
	 * shortest path tree -- has two Loser states to leave on it.  Stop at
	 * the (S,G) one, as the ordering of sec. 4.6.2 reads, and the (*,G)
	 * goes on holding the interface out of its olist until Assert_Time
	 * runs out, which is the black hole the cancel exists to prevent.
	 */
	if (rc == ASSERT_NOTHING && held)
	    return TRUE;
    }

    assert_machine(wc, wc, vifi, TRUE, src, source, group, assert_rptbit,
		   assert_preference, assert_metric);

    return TRUE;
}


/* The wire half, shared by an Assert and the AssertCancel that is one with
 * an infinite metric, sec. 4.6.4. */
static int assert_send(uint32_t source, uint32_t group, vifi_t vifi,
		       uint32_t preference, uint32_t metric)
{
    uint8_t *data;
    uint8_t *data_start;

    /* Don't send assert if the outgoing interface a tunnel or register vif */
    /* TODO: XXX: in the code above asserts are accepted over VIFF_TUNNEL.
     * Check if anything can go wrong if asserts are accepted and/or
     * sent over VIFF_TUNNEL.
     */
    if (vifi >= numvifs || (uvifs[vifi].uv_flags & (VIFF_REGISTER | VIFF_TUNNEL)))
	return FALSE;

    data = (uint8_t *)(pim_send_buf + sizeof(struct ip) + sizeof(pim_header_t));
    data_start = data;
    PUT_EGADDR(group, SINGLE_GRP_MSKLEN, 0, data);
    PUT_EUADDR(source, data);
    PUT_HOSTLONG(preference, data);
    PUT_HOSTLONG(metric, data);

    IF_DEBUG(DEBUG_PIM_ASSERT)
	logit(LOG_INFO, 0, "Send PIM ASSERT%s from %s for group %s and source %s",
	      metric == PIM_ASSERT_INFINITE_METRIC ? " CANCEL" : "",
	      inet_fmt(uvifs[vifi].uv_lcl_addr, s1, sizeof(s1)),
	      inet_fmt(group, s2, sizeof(s2)),
	      inet_fmt(source, s3, sizeof(s3)));

    send_pim(pim_send_buf, uvifs[vifi].uv_lcl_addr, allpimrouters_group,
	     PIM_ASSERT, data - data_start);

    return TRUE;
}

/*
 * Actions A1 of RFC 7761 sec. 4.6.1 and sec. 4.6.2, and Actions A3, which
 * is the same message sent again: whoever sends an Assert on an interface
 * claims it, so record ourselves as the winner there and arm the timer that
 * makes us resend before the losers give the interface back.
 */
int send_pim_assert(uint32_t source, uint32_t group, vifi_t vifi, mrtentry_t *mrt)
{
    uint32_t local_preference;
    uint32_t local_metric;

    my_assert_metric(mrt, &local_preference, &local_metric);

    if (!assert_send(source, group, vifi, local_preference, local_metric))
	return FALSE;

    assert_won(mrt, vifi, source, local_preference, local_metric);

    return TRUE;
}


/* Return TRUE if the local win, otherwise FALSE */
/*
 * RFC 7761 sec. 4.6.1, my_assert_metric(): an Assert may only carry the
 * shortest path tree metric, the one with the RPT bit clear, when
 * CouldAssert(S,G,I) holds, and that in turn requires SPTbit(S,G) to be
 * set.  Everything else forwarding the group has to assert as an RPT
 * forwarder, with the metric towards the RP and the bit set, so that a
 * neighbor which really is on the shortest path tree beats it on the bit
 * before either metric or address is looked at.
 *
 * MRTF_SPT is that SPTbit: process_cache_miss() and process_wrong_iif()
 * (src/route.c) set it once an (S,G) iif or upstream router differs from
 * the (*,G) the entry was built under, i.e. once we really did leave the
 * shared tree.  The (S,G) that a cache miss creates underneath a (*,G)
 * keeps it clear, and must not claim a tree it never joined: doing so used
 * to hand it a tie on preference and metric and let the address tiebreak
 * decide an election the spec had already answered.
 */
/*
 * spt_assert_metric(S,I), sec. 4.6.3: MRIB.pref(S)/MRIB.metric(S), so it
 * comes off the source entry rather than off this entry -- what the unicast
 * routing table says, never a value another router asserted at us.  It is
 * what we would assert with once SPTbit(S,G) is set, which is why
 * lost_assert() below weighs a winner against it.
 */
static void spt_assert_metric(mrtentry_t *mrt, uint32_t *preference, uint32_t *metric)
{
    if (mrt->source) {
	*preference = mrt->source->preference & ~PIM_ASSERT_RPT_BIT;
	*metric     = mrt->source->metric;

	return;
    }

    *preference = mrt->preference & ~PIM_ASSERT_RPT_BIT;
    *metric     = mrt->metric;
}

static void my_assert_metric(mrtentry_t *mrt, uint32_t *preference, uint32_t *metric)
{
    mrtentry_t *mrp = NULL;

    if (mrt->flags & MRTF_SPT) {
	spt_assert_metric(mrt, preference, metric);

	return;
    }

    /* rpt_assert_metric(G,I) is MRIB.pref(RP(G))/MRIB.metric(RP(G)), for the
     * same reason.  On an (S,G) that never left the shared tree that is the
     * RP's metric, not that of the entry we happen to be forwarding off. */
    if (mrt->group && mrt->group->active_rp_grp && mrt->group->active_rp_grp->rp) {
	rpentry_t *rp = mrt->group->active_rp_grp->rp->rpentry;

	*preference = rp->preference | PIM_ASSERT_RPT_BIT;
	*metric     = rp->metric;

	return;
    }

    if (mrt->group)
	mrp = mrt->group->grp_route;
    if (!mrp)
	mrp = mrt;

    *preference = mrp->preference | PIM_ASSERT_RPT_BIT;
    *metric     = mrp->metric;
}

static int compare_metrics(uint32_t local_preference, uint32_t local_metric, uint32_t local_address,
			   uint32_t remote_preference, uint32_t remote_metric, uint32_t remote_address)
{
    /* Now lets see who has a smaller gun (aka "asserts war") */
    /* FYI, the smaller gun...err metric wins, but if the same
     * caliber, then the bigger network address wins. The order of
     * threatment is: preference, metric, address.
     */
    /* The RPT bits are already included as the most significant bits
     * of the preferences.
     */
    if (remote_preference > local_preference)
	return TRUE;

    if (remote_preference < local_preference)
	return FALSE;

    if (remote_metric > local_metric)
	return TRUE;

    if (remote_metric < local_metric)
	return FALSE;

    if (ntohl(local_address) > ntohl(remote_address))
	return TRUE;

    return FALSE;
}


/************************************************************************
 *                        PIM_BOOTSTRAP
 ************************************************************************/
#define PIM_BOOTSTRAP_MINLEN (PIM_MINLEN + PIM_ENCODE_UNI_ADDR_LEN)
/* One RP record inside a Bootstrap group record: the encoded RP address,
 * its holdtime, its priority and a reserved byte.  Every loop that walks
 * them is driven by a count taken off the wire, so each one has to check
 * this much is still there before reading.
 */
/*
 * Is this an encoded address a PIM-SM router for IPv4 can read?
 *
 * RFC 7761 sec. 4.9.1 opens every encoded address with an address family
 * and an encoding type, and pimd read both into a struct that nothing ever
 * looked at.  The cost is not the address, which is garbage either way, but
 * the length: an Encoded-Unicast is 6 bytes for IPv4 and 18 for IPv6, and
 * every walk over these messages is written around the IPv4 strides, so a
 * record that declares another family is read at offsets that have nothing
 * to do with where its fields are -- source counts and flags taken out of
 * the middle of addresses.  Sec. 4.9.5 asks for the addresses of the
 * upstream neighbor's family to be processed and the rest ignored, and that
 * cannot be done without reading the field that says which family it is.
 */
static int encoded_addr_ok(uint8_t family, uint8_t etype)
{
    return family == ADDRF_IPv4 && etype == ADDRT_IPv4;
}

/*
 * And is this Encoded-Group a range this router may install?
 *
 * The B bit says the range is Bidirectional-PIM's, which pimd does not
 * implement; RFC 5059 sec. 3.6 says in so many words that an implementation
 * of one protocol must not treat the other's ranges as its own, and
 * installing a Bidir range as an ordinary PIM-SM one is exactly that -- an
 * RP is picked for it, Joins are sent toward that RP and traffic is
 * register-encapsulated to it, none of which a Bidir range means.  The Z
 * bit says the range belongs to an administrative scope zone, and pimd has
 * no scope zones, so the honest answer to one is the same: refuse it rather
 * than treat it as global.
 */
static int group_range_ok(const pim_encod_grp_addr_t *grp)
{
    if (!encoded_addr_ok(grp->addr_family, grp->encod_type))
	return FALSE;

    return !(grp->reserved & (EGADDR_B_BIT | EGADDR_Z_BIT));
}

#define PIM_BOOTSTRAP_RP_RECORD_LEN (PIM_ENCODE_UNI_ADDR_LEN + sizeof(uint16_t) \
				     + sizeof(uint8_t) + sizeof(uint8_t))
int receive_pim_bootstrap(uint32_t src, uint32_t dst, char *msg, size_t len)
{
    uint8_t               *data;
    uint8_t               *max_data;
    uint8_t               *scan;
    int                   no_forward;
    uint16_t              new_bsr_fragment_tag;
    uint8_t               new_bsr_hash_masklen;
    uint8_t               new_bsr_priority;
    pim_encod_uni_addr_t new_bsr_uni_addr;
    uint32_t              new_bsr_address;
    struct rpfctl        rpfc;
    pim_nbr_entry_t      *n, *rpf_neighbor __attribute__((unused));
    uint32_t              neighbor_addr;
    vifi_t               vifi, incoming = NO_VIF;
    int                  min_datalen;
    pim_encod_grp_addr_t curr_group_addr;
    pim_encod_uni_addr_t curr_rp_addr;
    uint8_t               curr_rp_count;
    uint8_t               curr_frag_rp_count;
    uint16_t              reserved_short __attribute__((unused));
    uint16_t              curr_rp_holdtime;
    uint8_t               curr_rp_priority;
    uint8_t               reserved_byte __attribute__((unused));
    uint32_t              curr_group_mask;
    uint32_t              prefix_h;
    grp_mask_t           *grp_mask;
    grp_mask_t           *grp_mask_next;
    rp_grp_entry_t       *grp_rp;
    rp_grp_entry_t       *grp_rp_next;

    /* Checksum */
    if (inet_cksum((uint16_t *)msg, len))
	return FALSE;

    if (find_vif_direct(src) == NO_VIF) {
	/* Either a local vif or somehow received PIM_BOOTSTRAP from
	 * non-directly connected router. Ignore it.
	 */
	if (local_address(src) == NO_VIF) {
	    IF_DEBUG(DEBUG_PIM_BOOTSTRAP)
		logit(LOG_INFO, 0, "Ignoring PIM_BOOTSTRAP from non-neighbor router %s",
		      inet_fmt(src, s1, sizeof(s1)));
	}

	return FALSE;
    }

    /* sanity check for the minimum length */
    if (len < PIM_BOOTSTRAP_MINLEN) {
	IF_DEBUG(DEBUG_PIM_BOOTSTRAP)
	    logit(LOG_NOTICE, 0, "Bootstrap message size(%zu) is too short from %s",
		  len, inet_fmt(src, s1, sizeof(s1)));

	return FALSE;
    }

    no_forward = ((pim_header_t *)msg)->pim_reserved & PIM_BOOTSTRAP_NO_FORWARD;

    data = (uint8_t *)(msg + sizeof(pim_header_t));

    /* Parse the PIM_BOOTSTRAP message */
    GET_HOSTSHORT(new_bsr_fragment_tag, data);
    GET_BYTE(new_bsr_hash_masklen, data);
    GET_BYTE(new_bsr_priority, data);
    GET_EUADDR(&new_bsr_uni_addr, data);
    new_bsr_address = new_bsr_uni_addr.unicast_addr;

    if (!encoded_addr_ok(new_bsr_uni_addr.addr_family, new_bsr_uni_addr.encod_type)) {
	IF_DEBUG(DEBUG_PIM_BOOTSTRAP)
	    logit(LOG_NOTICE, 0, "Ignoring Bootstrap from %s, BSR address family %u type %u is not IPv4",
		  inet_fmt(src, s1, sizeof(s1)),
		  new_bsr_uni_addr.addr_family, new_bsr_uni_addr.encod_type);

	return FALSE;
    }

    /* The Hash Mask Len decides the group-to-RP mapping for the whole
     * domain, and it is a byte off the wire.  Refused here, before
     * anything is committed or forwarded, because MASKLEN_TO_MASK()
     * (src/pimd.h) would shift by 32 - masklen with it.
     */
    if (new_bsr_hash_masklen > PIM_MAX_MSKLEN) {
	IF_DEBUG(DEBUG_PIM_BOOTSTRAP)
	    logit(LOG_NOTICE, 0, "Ignoring Bootstrap from %s, hash mask length %u is wider than an address",
		  inet_fmt(src, s1, sizeof(s1)), new_bsr_hash_masklen);

	return FALSE;
    }

    if (local_address(new_bsr_address) != NO_VIF)
	return FALSE; /* The new BSR is one of my local addresses */

    /*
     * Compare the current BSR priority with the priority of the BSR
     * included in the message.
     */
    /* TODO: if I am just starting and will become the BSR,
     * I should accept the message coming from the current BSR and get the
     * current Cand-RP-Set.
     */
    if ((curr_bsr_priority > new_bsr_priority) ||
	((curr_bsr_priority == new_bsr_priority)
	 && (ntohl(curr_bsr_address) > ntohl(new_bsr_address)))) {
	/* The message's BSR is less preferred than the current BSR */
	return FALSE;  /* Ignore the received BSR message */
    }

    IF_DEBUG(DEBUG_PIM_BOOTSTRAP)
	logit(LOG_INFO, 0, "Received PIM Bootstrap candidate %s, priority %d",
	      inet_fmt(new_bsr_address, s1, sizeof(s1)), new_bsr_priority);

    /* Check the iif, if this was PIM-ROUTERS multicast */
    if (dst == allpimrouters_group) {
	if (no_forward) {
	    /* RFC 5059 sec. 3.5.1: the No-Forward bit is what waives the
	     * RPF check, this being the refresh a DR hands a router that
	     * has just come up rather than a message travelling the tree.
	     * Put through the check anyway, it was dropped unless the
	     * sender happened to be the RPF neighbour toward the BSR --
	     * which the router that sends it has no reason to be.
	     *
	     * What does not go with the RPF check is sec. 6.2's rule: this
	     * is still a protocol message, and still only acceptable from a
	     * router we have had a Hello from.
	     */
	    incoming = find_vif_direct(src);
	    if (incoming == NO_VIF || !find_pim_nbr_on_vif(incoming, src)) {
		IF_DEBUG(DEBUG_PIM_BOOTSTRAP)
		    logit(LOG_NOTICE, 0, "Ignoring No-Forward Bootstrap from %s, no PIM Hello seen from it",
			  inet_fmt(src, s1, sizeof(s1)));

		return FALSE;
	    }

	    goto sender_ok;
	}

	k_req_incoming(new_bsr_address, &rpfc);
	if (rpfc.iif == NO_VIF || rpfc.rpfneighbor.s_addr == INADDR_ANY_N) {
	    /* coudn't find a route to the BSR */
	    return FALSE;
	}

	neighbor_addr = rpfc.rpfneighbor.s_addr;
	incoming = rpfc.iif;
	if (uvifs[incoming].uv_flags & (VIFF_DISABLED | VIFF_DOWN | VIFF_REGISTER))
	    return FALSE;	/* Shoudn't arrive on that interface */

	/* Find the upstream router */
	for (n = uvifs[incoming].uv_pim_neighbors; n; n = n->next) {
	    if (ntohl(neighbor_addr) < ntohl(n->address))
		continue;

	    if (neighbor_addr == n->address) {
		rpf_neighbor = n;
		break;
	    }

	    return FALSE;	/* No neighbor toward BSR found */
	}

	if (!n || n->address != src)
	    return FALSE;	/* Sender of this message is not the RPF neighbor */

    } else {
	if (local_address(dst) == NO_VIF) {
	    /* TODO: XXX: this situation should be handled earlier:
	     * The destination is neither ALL_PIM_ROUTERS neither me
	     */
	    return FALSE;
	}

	/* Probably unicasted from the current DR */
	if (cand_rp_list) {
	    struct cand_rp *rp;

	    /* We have a Cand-RP-list already, check for static ones ... */
	    for (rp = cand_rp_list; rp; rp = rp->next) {
		rpentry_t *entry = rp->rpentry;

		/* Skip static/configured ones */
		if (entry->adv_holdtime == (uint16_t)0xffffff)
		    continue;

		/* Ignore this guy. */
		return FALSE;
	    }
	}

	for (vifi = 0; vifi < numvifs; vifi++) {
	    if (uvifs[vifi].uv_flags & (VIFF_DISABLED | VIFF_DOWN | VIFF_REGISTER))
		continue;

	    if (uvifs[vifi].uv_lcl_addr == dst) {
		incoming = vifi;
		break;
	    }
	}

	if (incoming == NO_VIF) {
	    /* Cannot find the receiving iif toward that DR */
	    IF_DEBUG(DEBUG_RPF | DEBUG_PIM_BOOTSTRAP)
		logit(LOG_INFO, 0, "Unicast boostrap message from %s to %s ignored: cannot find iif",
		      inet_fmt(src, s1, sizeof(s1)), inet_fmt(dst, s2, sizeof(s2)));

	    return FALSE;
	}

	/* RFC 7761 sec. 6.2: "a PIM router SHOULD NOT accept protocol
	 * messages from a router from which it has not yet received a valid
	 * Hello message".  The multicast branch above gets that for free,
	 * having to match the sender against the RPF neighbor toward the
	 * BSR, and Join/Prune and Assert ask for it directly; this branch
	 * asked only that the sender be on a subnet we have a vif on, which
	 * every host on that subnet is: any of them could hand a booting
	 * router the RP set for the whole domain, and nothing in such a
	 * message is RPF checked before we flood it onward.
	 *
	 * This does not close the window RFC 5059 sec. 3.5.2 opens it for.
	 * The sender of a unicast Bootstrap is a DR answering a Hello it
	 * has just had from us, and receive_pim_hello() above sends its own
	 * Hello on the same path immediately before the Bootstrap, so the
	 * Hello that makes it a neighbor is already on the wire ahead of
	 * it.  Should that Hello be lost, what is lost with it is one
	 * unicast delivery of the RP set and not the RP set: the BSR floods
	 * the same message to ALL-PIM-ROUTERS every my_bsr_adv_period, and
	 * the multicast branch above accepts it.
	 */
	if (!find_pim_nbr_on_vif(incoming, src)) {
	    IF_DEBUG(DEBUG_PIM_BOOTSTRAP)
		logit(LOG_NOTICE, 0, "Ignoring unicast Bootstrap from %s on %s, no PIM Hello seen from it",
		      inet_fmt(src, s1, sizeof(s1)), uvifs[incoming].uv_name);

	    return FALSE;
	}
	/* TODO: check I am really the DR */
    }

  sender_ok:
    max_data = (uint8_t *)msg + len;
    /* TODO: XXX: this 22 is HARDCODING!!! Do a bunch of definitions
     * and make it stylish!
     */
    min_datalen = 22;

    /* Walk the group sets before acting on any of them.  Everything past
     * this point changes state the rest of the domain can see -- the BSR
     * address, priority and fragment tag, the segmented RP list -- and
     * forwards the message onward, while the loop that actually reads the
     * sets runs last of all.  Rejecting a malformed set down there would
     * mean having already moved the BSR and flooded the message, so one
     * mask length wider than an address would cost a domain its RP set
     * whichever way the check went.  Refuse it here, where refusing is
     * still free.
     */
    scan = data;
    while (scan + min_datalen <= max_data) {
	uint8_t frag_rp_count;

	if (scan[PIM_ENCODE_MSKLEN_OFF] > PIM_MAX_MSKLEN) {
	    IF_DEBUG(DEBUG_PIM_BOOTSTRAP)
		logit(LOG_NOTICE, 0, "Ignoring Bootstrap from %s, group mask length %u is wider than an address",
		      inet_fmt(src, s1, sizeof(s1)), scan[PIM_ENCODE_MSKLEN_OFF]);

	    return FALSE;
	}

	if (!encoded_addr_ok(scan[PIM_ENCODE_FAMILY_OFF], scan[PIM_ENCODE_ETYPE_OFF])) {
	    IF_DEBUG(DEBUG_PIM_BOOTSTRAP)
		logit(LOG_NOTICE, 0, "Ignoring Bootstrap from %s, group address family %u type %u is not IPv4",
		      inet_fmt(src, s1, sizeof(s1)),
		      scan[PIM_ENCODE_FAMILY_OFF], scan[PIM_ENCODE_ETYPE_OFF]);

	    return FALSE;
	}

	/* The B and Z bits of this range are not checked here.  They cost
	 * the range and not the message -- unlike the three above, nothing
	 * about where the next set begins is in doubt -- so the loop that
	 * installs the ranges is where they are answered, with a continue.
	 *
	 * RP count, fragment RP count, reserved, then that many records
	 */
	scan += PIM_ENCODE_GRP_ADDR_LEN;
	frag_rp_count = scan[1];
	scan += sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint16_t);

	if ((size_t)(max_data - scan) < frag_rp_count * PIM_BOOTSTRAP_RP_RECORD_LEN) {
	    IF_DEBUG(DEBUG_PIM_BOOTSTRAP)
		logit(LOG_NOTICE, 0, "Ignoring Bootstrap from %s, %u RP record(s) run past the end",
		      inet_fmt(src, s1, sizeof(s1)), frag_rp_count);

	    return FALSE;
	}

	scan += frag_rp_count * PIM_BOOTSTRAP_RP_RECORD_LEN;
    }

    if (cand_rp_flag == TRUE) {
	/* If change in the BSR address, schedule immediate Cand-RP-Adv */
	/* TODO: use some random delay? */
	if (new_bsr_address != curr_bsr_address)
	    SET_TIMER(pim_cand_rp_adv_timer, 0);
    }

    /* Forward the BSR Message first and then update the RP-set list.
     *
     * RFC 5059 sec. 3.4 names the two that are not forwarded: one whose
     * No-Forward bit is set, and one that was unicast to us.  pimd passed
     * both on -- the first with the bit still set, which told every router
     * downstream to accept it without an RPF check of its own, and the
     * second in the teeth of a section that says it is not forwarded.
     */
    if (!no_forward && dst == allpimrouters_group) {
	for (vifi = 0; vifi < numvifs; vifi++) {
	    if (vifi == incoming)
		continue;

	    if (uvifs[vifi].uv_flags & (VIFF_DISABLED | VIFF_DOWN | VIFF_REGISTER | VIFF_NONBRS))
		continue;

	    memcpy(pim_send_buf + sizeof(struct ip), msg, len);
	    send_pim(pim_send_buf, uvifs[vifi].uv_lcl_addr, allpimrouters_group,
		     PIM_BOOTSTRAP, len - sizeof(pim_header_t));
	}
    }

    if (new_bsr_fragment_tag != curr_bsr_fragment_tag || new_bsr_address != curr_bsr_address) {
	/* Throw away the old segment */
	delete_rp_list(&segmented_cand_rp_list, &segmented_grp_mask_list);
    }

    curr_bsr_address      = new_bsr_address;
    curr_bsr_priority     = new_bsr_priority;
    curr_bsr_fragment_tag = new_bsr_fragment_tag;
    MASKLEN_TO_MASK(new_bsr_hash_masklen, curr_bsr_hash_mask);
    SET_TIMER(pim_bootstrap_timer, my_bsr_timeout);

    while (data + min_datalen <= max_data) {
	GET_EGADDR(&curr_group_addr, data);
	GET_BYTE(curr_rp_count, data);
	GET_BYTE(curr_frag_rp_count, data);
	GET_HOSTSHORT(reserved_short, data);

	/* The mask length, family and encoding type are the pre-pass's,
	 * checked before any of this was committed; left unchecked the mask
	 * length shifted by the count modulo 32, so a masklen of 200 for
	 * 224.0.0.0 installed 224.0.0.0/8 and a range nobody advertised
	 * displaced the domain's RP set.  What is left to do here is the
	 * B and Z bits, which cost this range and not the message.
	 */
	if (!group_range_ok(&curr_group_addr)) {
	    IF_DEBUG(DEBUG_PIM_BOOTSTRAP)
		logit(LOG_NOTICE, 0, "Skipping %s from %s, a range this router does not implement",
		      inet_fmt(curr_group_addr.mcast_addr, s2, sizeof(s2)),
		      inet_fmt(src, s1, sizeof(s1)));

	    /* Past its RP records, which is where the next set begins */
	    while (curr_frag_rp_count-- && data + PIM_BOOTSTRAP_RP_RECORD_LEN <= max_data)
		data += PIM_BOOTSTRAP_RP_RECORD_LEN;

	    continue;
	}

	MASKLEN_TO_MASK(curr_group_addr.masklen, curr_group_mask);
	if (curr_rp_count == 0) {
	    delete_grp_mask(&cand_rp_list, &grp_mask_list,
			    curr_group_addr.mcast_addr, curr_group_mask);
	    continue;
	}

	if (curr_rp_count == curr_frag_rp_count) {
	    /* Add all RPs */
	    while (curr_frag_rp_count--) {
		if (data + PIM_BOOTSTRAP_RP_RECORD_LEN > max_data) {
		    IF_DEBUG(DEBUG_PIM_BOOTSTRAP)
			logit(LOG_NOTICE, 0, "Truncated Bootstrap message from %s,"
			      " RP count runs past the end", inet_fmt(src, s1, sizeof(s1)));

		    return FALSE;
		}

		GET_EUADDR(&curr_rp_addr, data);
		GET_HOSTSHORT(curr_rp_holdtime, data);
		GET_BYTE(curr_rp_priority, data);
		GET_BYTE(reserved_byte, data);
		MASKLEN_TO_MASK(curr_group_addr.masklen, curr_group_mask);
		add_rp_grp_entry(&cand_rp_list, &grp_mask_list,
				 curr_rp_addr.unicast_addr, curr_rp_priority,
				 curr_rp_holdtime, curr_group_addr.mcast_addr,
				 curr_group_mask,
				 curr_bsr_hash_mask,
				 curr_bsr_fragment_tag);
	    }
	    continue;
	}

	/*
	 * This is a partial list of the RPs for this group prefix.
	 * Save until all segments arrive.
	 */
	prefix_h = ntohl(curr_group_addr.mcast_addr & curr_group_mask);
	for (grp_mask = segmented_grp_mask_list; grp_mask; grp_mask = grp_mask->next) {
	    if (ntohl(grp_mask->group_addr & grp_mask->group_mask) > prefix_h)
		continue;

	    break;
	}

	if (grp_mask
	    && (grp_mask->group_addr == curr_group_addr.mcast_addr)
	    && (grp_mask->group_mask == curr_group_mask)
	    && (grp_mask->group_rp_number + curr_frag_rp_count == curr_rp_count)) {
	    /* All missing PRs have arrived. Add all RP entries */
	    while (curr_frag_rp_count--) {
		if (data + PIM_BOOTSTRAP_RP_RECORD_LEN > max_data) {
		    IF_DEBUG(DEBUG_PIM_BOOTSTRAP)
			logit(LOG_NOTICE, 0, "Truncated Bootstrap message from %s,"
			      " RP count runs past the end", inet_fmt(src, s1, sizeof(s1)));

		    return FALSE;
		}

		GET_EUADDR(&curr_rp_addr, data);
		GET_HOSTSHORT(curr_rp_holdtime, data);
		GET_BYTE(curr_rp_priority, data);
		GET_BYTE(reserved_byte, data);
		MASKLEN_TO_MASK(curr_group_addr.masklen, curr_group_mask);
		add_rp_grp_entry(&cand_rp_list,
				 &grp_mask_list,
				 curr_rp_addr.unicast_addr,
				 curr_rp_priority,
				 curr_rp_holdtime,
				 curr_group_addr.mcast_addr,
				 curr_group_mask,
				 curr_bsr_hash_mask,
				 curr_bsr_fragment_tag);
	    }

	    /* Add the rest from the previously saved segments */
	    for (grp_rp = grp_mask->grp_rp_next; grp_rp; grp_rp = grp_rp->grp_rp_next) {
		add_rp_grp_entry(&cand_rp_list,
				 &grp_mask_list,
				 grp_rp->rp->rpentry->address,
				 grp_rp->priority,
				 grp_rp->holdtime,
				 curr_group_addr.mcast_addr,
				 curr_group_mask,
				 curr_bsr_hash_mask,
				 curr_bsr_fragment_tag);
	    }
	    delete_grp_mask(&segmented_cand_rp_list,
			    &segmented_grp_mask_list,
			    curr_group_addr.mcast_addr,
			    curr_group_mask);
	} else {
	    /* Add the partially received RP-list to the group of pending RPs*/
	    while (curr_frag_rp_count--) {
		if (data + PIM_BOOTSTRAP_RP_RECORD_LEN > max_data) {
		    IF_DEBUG(DEBUG_PIM_BOOTSTRAP)
			logit(LOG_NOTICE, 0, "Truncated Bootstrap message from %s,"
			      " RP count runs past the end", inet_fmt(src, s1, sizeof(s1)));

		    return FALSE;
		}

		GET_EUADDR(&curr_rp_addr, data);
		GET_HOSTSHORT(curr_rp_holdtime, data);
		GET_BYTE(curr_rp_priority, data);
		GET_BYTE(reserved_byte, data);
		MASKLEN_TO_MASK(curr_group_addr.masklen, curr_group_mask);
		add_rp_grp_entry(&segmented_cand_rp_list,
				 &segmented_grp_mask_list,
				 curr_rp_addr.unicast_addr,
				 curr_rp_priority,
				 curr_rp_holdtime,
				 curr_group_addr.mcast_addr,
				 curr_group_mask,
				 curr_bsr_hash_mask,
				 curr_bsr_fragment_tag);
	    }
	}
    }

    /* Garbage collection. Check all group prefixes and if the
     * fragment_tag for a group-prefix is the same as curr_bsr_fragment_tag,
     * then remove all RPs for this group-prefix which have different
     * fragment tag.
     *
     * Except a statically configured one, which never carried this BSR's
     * tag and was never this BSR's to collect.  An "rp-address" with no
     * group covers 224.0.0.0/4, the same prefix a Candidate-RP advertised
     * under "group-prefix 224.0.0.0 masklen 4" lands on, so the two share
     * one grp_mask_t and the first Bootstrap for it used to delete
     * pimd.conf's RP outright -- leaving a router whose BSR later died
     * with no RP at all until it was sent a SIGHUP.  RFC 7761 sec. 4.7
     * requires both sources to be supported; it gives no precedence rule,
     * and this is not one: the learned RPs are kept beside the static
     * entry and rp_match() picks between them as it always did.
     */
    for (grp_mask = grp_mask_list; grp_mask; grp_mask = grp_mask_next) {
	grp_mask_next = grp_mask->next;

	if (grp_mask->fragment_tag == curr_bsr_fragment_tag) {
	    for (grp_rp = grp_mask->grp_rp_next; grp_rp; grp_rp = grp_rp_next) {
		grp_rp_next = grp_rp->grp_rp_next;

		if (grp_rp->is_static)
		    continue;

		if (grp_rp->fragment_tag != curr_bsr_fragment_tag)
		    delete_rp_grp_entry(&cand_rp_list, &grp_mask_list, grp_rp);
	    }
	}
    }

    /* Cleanup also the list used by incompleted segments */
    for (grp_mask = segmented_grp_mask_list; grp_mask; grp_mask = grp_mask_next) {
	grp_mask_next = grp_mask->next;

	if (grp_mask->fragment_tag == curr_bsr_fragment_tag) {
	    for (grp_rp = grp_mask->grp_rp_next; grp_rp; grp_rp = grp_rp_next) {
		grp_rp_next = grp_rp->grp_rp_next;

		if (grp_rp->fragment_tag != curr_bsr_fragment_tag)
		    delete_rp_grp_entry(&segmented_cand_rp_list, &segmented_grp_mask_list, grp_rp);
	    }
	}
    }

    return TRUE;
}


void send_pim_bootstrap(void)
{
    size_t len;
    vifi_t vifi;

    if ((len = create_pim_bootstrap_message(pim_send_buf))) {
	for (vifi = 0; vifi < numvifs; vifi++) {
	    if (uvifs[vifi].uv_flags & (VIFF_DISABLED | VIFF_DOWN | VIFF_REGISTER))
		continue;

	    send_pim(pim_send_buf, uvifs[vifi].uv_lcl_addr,
		     allpimrouters_group, PIM_BOOTSTRAP, len);
	}
    }
}


/************************************************************************
 *                        PIM_CAND_RP_ADV
 ************************************************************************/
/*
 * If I am the Bootstrap router, process the advertisement, otherwise
 * ignore it.
 */
#define PIM_CAND_RP_ADV_MINLEN (PIM_MINLEN + PIM_ENCODE_UNI_ADDR_LEN)
int receive_pim_cand_rp_adv(uint32_t src, uint32_t dst __attribute__((unused)), char *msg, size_t len)
{
    uint8_t prefix_cnt;
    uint8_t priority;
    uint16_t holdtime;
    pim_encod_uni_addr_t euaddr;
    pim_encod_grp_addr_t egaddr;
    uint8_t *data_ptr;
    uint8_t *max_data;
    uint32_t grp_mask;

    /* Checksum */
    if (inet_cksum((uint16_t *)msg, len))
	return FALSE;

    /* if I am not the bootstrap RP, then do not accept the message */
    if (cand_bsr_flag == FALSE || curr_bsr_address != my_bsr_address)
	return FALSE;

    /* sanity check for the minimum length */
    if (len < PIM_CAND_RP_ADV_MINLEN) {
	IF_DEBUG(DEBUG_PIM_CAND_RP)
	    logit(LOG_NOTICE, 0, "cand_RP message size(%zu) is too short from %s",
		  len, inet_fmt(src, s1, sizeof(s1)));

	return FALSE;
    }

    data_ptr = (uint8_t *)(msg + sizeof(pim_header_t));
    max_data = (uint8_t *)msg + len;
    /* Parse the CAND_RP_ADV message */
    GET_BYTE(prefix_cnt, data_ptr);
    GET_BYTE(priority, data_ptr);
    GET_HOSTSHORT(holdtime, data_ptr);
    GET_EUADDR(&euaddr, data_ptr);

    if (!encoded_addr_ok(euaddr.addr_family, euaddr.encod_type)) {
	IF_DEBUG(DEBUG_PIM_CAND_RP)
	    logit(LOG_NOTICE, 0, "Ignoring cand-RP from %s, RP address family %u type %u is not IPv4",
		  inet_fmt(src, s1, sizeof(s1)), euaddr.addr_family, euaddr.encod_type);

	return FALSE;
    }

    /* Is holdtime in MUST BE interval? (RFC5059 section 3.3) */
    if (holdtime != 0 && holdtime <= my_bsr_adv_period)
	holdtime = recommended_rp_holdtime;
    if (prefix_cnt == 0) {
	/* The default 224.0.0.0 and masklen of 4 */
	MASKLEN_TO_MASK(ALL_MCAST_GROUPS_LEN, grp_mask);
	add_rp_grp_entry(&cand_rp_list, &grp_mask_list,
			 euaddr.unicast_addr, priority, holdtime,
			 htonl(ALL_MCAST_GROUPS_ADDR), grp_mask,
			 my_bsr_hash_mask,
			 curr_bsr_fragment_tag);

	return TRUE;
    }

    while (prefix_cnt--) {
	if (data_ptr + PIM_ENCODE_GRP_ADDR_LEN > max_data) {
	    IF_DEBUG(DEBUG_PIM_CAND_RP)
		logit(LOG_NOTICE, 0, "Truncated cand_RP message from %s,"
		      " prefix count runs past the end", inet_fmt(src, s1, sizeof(s1)));

	    return FALSE;
	}

	GET_EGADDR(&egaddr, data_ptr);

	/* Same byte, same shift, and here one bad prefix need not cost the
	 * rest: every iteration of this loop consumes exactly one
	 * Encoded-Group, so skipping one leaves data_ptr where the next
	 * begins.  sec. 4.9.1 and RFC 5059 sec. 3.3 both have the advertised
	 * group prefixes carry a real mask length, so a wider one is the
	 * sender's error and not a range to install.
	 */
	if (egaddr.masklen > PIM_MAX_MSKLEN) {
	    IF_DEBUG(DEBUG_PIM_CAND_RP)
		logit(LOG_NOTICE, 0, "Skipping group prefix from %s, mask length %u is wider than an address",
		      inet_fmt(src, s1, sizeof(s1)), egaddr.masklen);
	    continue;
	}

	/* And a family we cannot read, or a range we do not implement */
	if (!group_range_ok(&egaddr)) {
	    IF_DEBUG(DEBUG_PIM_CAND_RP)
		logit(LOG_NOTICE, 0, "Skipping %s from %s, a range this router does not implement",
		      inet_fmt(egaddr.mcast_addr, s2, sizeof(s2)),
		      inet_fmt(src, s1, sizeof(s1)));
	    continue;
	}

	MASKLEN_TO_MASK(egaddr.masklen, grp_mask);
	/* Do not advertise internal virtual RP for SSM groups */
	if (!IN_PIM_SSM_RANGE(egaddr.mcast_addr)) {
	    add_rp_grp_entry(&cand_rp_list, &grp_mask_list,
			     euaddr.unicast_addr, priority, holdtime,
			     egaddr.mcast_addr, grp_mask,
			     my_bsr_hash_mask,
			     curr_bsr_fragment_tag);
	}
    }

    return TRUE;
}


int send_pim_cand_rp_adv(void)
{
    uint8_t prefix_cnt;
    uint32_t mask;
    pim_encod_grp_addr_t addr;
    uint8_t *data;

    if (!inet_valid_host(curr_bsr_address))
	return FALSE;  /* No BSR yet */

    if (curr_bsr_address == my_bsr_address) {
	/* I am the BSR and have to include my own group-prefix stuff */
	prefix_cnt = *cand_rp_adv_message.prefix_cnt_ptr;
	if (prefix_cnt == 0) {
	    /* The default 224.0.0.0 and masklen of 4 */
	    MASKLEN_TO_MASK(ALL_MCAST_GROUPS_LEN, mask);
	    add_rp_grp_entry(&cand_rp_list, &grp_mask_list,
			     my_cand_rp_address, my_cand_rp_priority,
			     my_cand_rp_holdtime,
			     htonl(ALL_MCAST_GROUPS_ADDR), mask,
			     my_bsr_hash_mask,
			     curr_bsr_fragment_tag);
	    return TRUE;
	}

	/* TODO: hardcoding!! */
	data = cand_rp_adv_message.buffer + (4 + 6);
	while (prefix_cnt--) {
	    GET_EGADDR(&addr, data);
	    MASKLEN_TO_MASK(addr.masklen, mask);
	    add_rp_grp_entry(&cand_rp_list,
			     &grp_mask_list,
			     my_cand_rp_address, my_cand_rp_priority,
			     my_cand_rp_holdtime,
			     addr.mcast_addr, mask,
			     my_bsr_hash_mask,
			     curr_bsr_fragment_tag);
	    /* TODO: Check for len */
	}

	return TRUE;
    }

    data = (uint8_t *)(pim_send_buf + sizeof(struct ip) + sizeof(pim_header_t));
    memcpy(data, cand_rp_adv_message.buffer, cand_rp_adv_message.message_size);
    send_pim_unicast(pim_send_buf, 0, 0, my_cand_rp_address, curr_bsr_address,
		     PIM_CAND_RP_ADV, cand_rp_adv_message.message_size);

    return TRUE;
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "cc-mode"
 * End:
 */
