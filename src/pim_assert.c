/*
 * pim_assert.c - the Assert decisions of RFC 7761 sec. 4.6 that read no state
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
 * Every Assert election pimd holds comes down to the comparison here, and
 * the state machines of src/pim_proto.c around it decide what to do with
 * the answer.  It includes libc and pimd.h and nothing else of the
 * daemon's, so that test/cbmc/assert.c can prove it alone against the
 * order sec. 4.6.3 writes down.
 */

#include <stdint.h>
#include <sys/types.h>
#include <netinet/in.h>

#include "pimd.h"

/*
 * Does the local metric beat the remote one?  Sec. 4.6.3 compares the
 * rpt_bit_flag, the metric_preference and the route_metric in that order,
 * the first lower value winning, and breaks a tie on the primary IP
 * address, the higher one winning.  The RPT bit travels as the top bit of
 * the preference, which makes the first two fields one 32-bit comparison.
 * Addresses are in network order, as pimd keeps them.  Returns 1 (TRUE)
 * where the local metric wins and 0 (FALSE) where it does not, which is
 * also the answer for two equal metrics from the same address.
 */
int compare_metrics(uint32_t local_preference, uint32_t local_metric, uint32_t local_address,
		    uint32_t remote_preference, uint32_t remote_metric, uint32_t remote_address)
{
    if (remote_preference > local_preference)
	return 1;

    if (remote_preference < local_preference)
	return 0;

    if (remote_metric > local_metric)
	return 1;

    if (remote_metric < local_metric)
	return 0;

    if (ntohl(local_address) > ntohl(remote_address))
	return 1;

    return 0;
}

/*
 * One Assert, received on one interface, through one of the two machines:
 * sec. 4.6.1's for an (S,G) entry and sec. 4.6.2's for a (*,G) one.  The
 * caller has read the entry into `v` and acts on the answer, one of the
 * ASSERT_ACT_* of pimd.h; nothing here touches state.  They are two
 * machines with two sets of events, and the RPT bit of the message is what
 * tells the events apart.  Every transition the (*,G) machine has out of
 * NoInfo, and every one that replaces the winner it holds, is on an Assert
 * carrying the bit; the (S,G) machine answers one without the bit with a
 * metric of its own, and one with the bit only from the shortest path
 * tree, which is what CouldAssert(S,G,I) asks for.
 */
int assert_decide(const struct assert_view *v)
{
    uint32_t rptbit = v->pref & PIM_ASSERT_RPT_BIT;
    int winner = v->winner != 0 && v->is_winner;
    int loser  = v->winner != 0 && !v->is_winner;

    /* AssertTrackingDesired, as pimd approximates it: join state, local
     * membership, assert state or the interface being upstream */
    if (!v->tracking)
	return ASSERT_ACT_NONE;

    if (v->where == ASSERT_DOWNSTREAM) {
	if (v->has_state && loser) {
	    /* "I am Assert Loser".  Only the current winner can take us out
	     * of it, and a preferred Assert from anyone can replace it. */
	    if (v->src == v->winner) {
		/* Inferior to our own metric, an AssertCancel included: back
		 * to NoInfo, and Join/Prune operates again.  Neither machine
		 * asks for the RPT bit here, sec. 4.6.4. */
		if (compare_metrics(v->my_pref, v->my_metric, v->my_addr,
				    v->pref, v->metric, v->src))
		    return ASSERT_ACT_CLEAR;

		/* Acceptable Assert from the current winner: A2, it keeps
		 * the interface.  The (*,G) machine takes it only with the
		 * RPT bit set, and the (S,G) machine only with it clear:
		 * sec. 4.6.1 has no event for the other, which used to
		 * refresh the Assert Timer and store the shared tree's
		 * metric as the winner's.  A preferred Assert is A2 from
		 * anyone, the winner included, and for the (S,G) machine
		 * whatever the bit. */
		if (compare_metrics(v->pref, v->metric, v->src,
				    v->win_pref, v->win_metric, v->winner) &&
		    (!v->wc || rptbit))
		    return ASSERT_ACT_STORE;

		if (v->wc ? !rptbit : rptbit != 0)
		    return ASSERT_ACT_NONE;

		return ASSERT_ACT_STORE;
	    }

	    /* From anyone else only an Assert better than the winner's
	     * changes anything: A2, and only with the RPT bit for (*,G) */
	    if (v->wc && !rptbit)
		return ASSERT_ACT_NONE;

	    if (!compare_metrics(v->win_pref, v->win_metric, v->winner,
				 v->pref, v->metric, v->src))
		return ASSERT_ACT_STORE;

	    return ASSERT_ACT_NONE;
	}

	/* NoInfo, or "I am Assert Winner".  The (*,G) machine leaves NoInfo
	 * only on an Assert with the RPT bit set, sec. 4.6.2; one without it
	 * is the (S,G) machine's.  The Winner state answers either, A3. */
	if (v->wc && !rptbit && !winner)
	    return ASSERT_ACT_NONE;

	/* And the (S,G) machine leaves NoInfo on an Assert with the bit only
	 * when CouldAssert(S,G,I) holds, which needs SPTbit(S,G) */
	if (!v->wc && rptbit && !v->spt && !winner)
	    return ASSERT_ACT_NONE;

	/* A1, or A3 from the Winner state: the interface is ours */
	if (compare_metrics(v->my_pref, v->my_metric, v->my_addr,
			    v->pref, v->metric, v->src))
	    return ASSERT_ACT_SEND;

	/* We lost, and sec. 4.6.1 has no NoInfo-to-Loser transition for an
	 * Assert with the RPT bit: that one is the (*,G) machine's.  The
	 * Winner state has one, "Receive Preferred Assert", whatever the bit.
	 */
	if (!v->wc && rptbit && !winner)
	    return ASSERT_ACT_NONE;

	/* A6, or A2 from the Winner state */
	return ASSERT_ACT_LOSE;
    }

    if (v->where == ASSERT_UPSTREAM) {
	/* The RPF interface.  CouldAssert is FALSE there, so this router
	 * never wins: sec. 4.6.1 and sec. 4.6.2 have it lose to any
	 * acceptable Assert, replace the winner only with a preferred one,
	 * and go back to NoInfo on an inferior Assert from the winner.
	 * RPF' follows the winner, sec. 4.1.6.
	 *
	 * The winner's AssertCancel first, for either machine: it carries
	 * the RPT bit whatever the machine, sec. 4.6.4, and the test of the
	 * bit below refused it for an (S,G) entry before it was looked at,
	 * which left RPF'(S,G) naming a router that had said it would stop
	 * forwarding, until Assert_Time.  test/cbmc/assert.c found it. */
	if (loser && v->src == v->winner &&
	    v->pref == PIM_ASSERT_INFINITE_PREFERENCE &&
	    v->metric == PIM_ASSERT_INFINITE_METRIC)
	    return ASSERT_ACT_CLEAR;

	if (rptbit) {
	    /* An Assert with the RPT bit is the (*,G) machine's here, every
	     * transition sec. 4.6.1 has on the RPF interface being on one
	     * without it.  An (S,G) entry on the shared tree -- MRTF_RP, the
	     * (S,G,rpt) state -- used to take it as well, follow the winner
	     * itself and so keep the (*,G) machine out of the message,
	     * leaving RPF'(*,G) and the whole group's Joins on the router
	     * that had lost.  RPF'(S,G,rpt) is RPF'(*,G), sec. 4.1.6, and
	     * src/pim_proto.c carries the (*,G)'s over to it. */
	    if (!v->wc)
		return ASSERT_ACT_NONE;
	} else if (v->wc) {
	    /* Sec. 4.6.2 moves the (*,G) machine here only on an Assert with
	     * the RPT bit; one without it is the (S,G) machine's, by
	     * AssertTrackingDesired(S,G,I)'s last clause. */
	    return ASSERT_ACT_NONE;
	}

	if (!v->has_upstream || !v->has_state)
	    return ASSERT_ACT_NONE;

	if (v->winner != 0) {
	    if (compare_metrics(v->win_pref, v->win_metric, v->winner,
				v->pref, v->metric, v->src)) {
		if (v->src != v->winner)
		    return ASSERT_ACT_NONE;

		/* The winner's Assert, worse than the one it won with.  Here
		 * that is still an acceptable one, A2: my_assert_metric is
		 * infinite on the RPF interface, so no Assert is inferior to
		 * it and only the cancel above ends the state.  pimd used to
		 * clear on it, sending its Joins back to the routing table's
		 * neighbor while the winner went on forwarding. */
		return ASSERT_ACT_STORE;
	    }

	    /* Its Assert again, A2 */
	    if (v->src == v->winner)
		return ASSERT_ACT_STORE;
	} else if (v->pref == PIM_ASSERT_INFINITE_PREFERENCE &&
		   v->metric == PIM_ASSERT_INFINITE_METRIC) {
	    /* An AssertCancel from a router that won nothing here */
	    return ASSERT_ACT_NONE;
	}

	/* A6, or A2 for a preferred Assert: a new winner, and the Joins go
	 * to it */
	return ASSERT_ACT_FOLLOW;
    }

    return ASSERT_ACT_NONE;
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "cc-mode"
 * End:
 */
