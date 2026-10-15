/*
 * pim_jp.c - the downstream Join/Prune decisions of RFC 7761 sec. 4.5 that
 *            read no state
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
 * The three per-interface machines a router keeps for what its downstream
 * neighbors ask of it, sec. 4.5.1 to 4.5.3, as a state and an event in and
 * an action out.  The routing table, the timers and the sends stay in
 * src/pim_proto.c and src/route.c, which read the state off an entry and
 * write the action back.  It includes libc and pimd.h and nothing else of
 * the daemon's, so that test/cbmc/jp.c can prove it alone against the
 * tables of the RFC, and the bits an entry keeps each state in with it.
 */

#include <stdint.h>
#include <sys/types.h>
#include <netinet/in.h>

#include "pimd.h"

static struct jp_act jp_act(int state, int et, int ppt, int echo)
{
    struct jp_act a;

    a.state = (uint8_t)state;
    a.et    = (uint8_t)et;
    a.ppt   = (uint8_t)ppt;
    a.echo  = (uint8_t)echo;

    return a;
}

/*
 * Figures 2 and 3, the (*,G) and the (S,G) machines, which are the same
 * table.  @ppt_zero is a Prune-Pending Timer of zero, the router having one
 * neighbor or none on the interface: the timer "expire[s] immediately", so
 * the Prune that starts it is answered with where its expiry goes, NoInfo,
 * and without the PruneEcho sec. 4.5.1 says "need not be sent" there.
 */
struct jp_act jp_ds_decide(int state, int event, int ppt_zero)
{
    switch (event) {
	case JP_EV_JOIN:
	    if (state == JP_DS_NI)
		return jp_act(JP_DS_J, JP_ET_SET, JP_PPT_KEEP, 0);
	    if (state == JP_DS_PP)
		return jp_act(JP_DS_J, JP_ET_MAX, JP_PPT_CANCEL, 0);
	    return jp_act(JP_DS_J, JP_ET_MAX, JP_PPT_KEEP, 0);

	case JP_EV_PRUNE:
	    if (state != JP_DS_J)
		break;
	    if (ppt_zero)
		return jp_act(JP_DS_NI, JP_ET_CANCEL, JP_PPT_KEEP, 0);
	    return jp_act(JP_DS_PP, JP_ET_KEEP, JP_PPT_START, 0);

	case JP_EV_PPT:
	    if (state != JP_DS_PP)
		break;
	    return jp_act(JP_DS_NI, JP_ET_CANCEL, JP_PPT_KEEP, 1);

	case JP_EV_ET:
	    if (state == JP_DS_NI)
		break;
	    return jp_act(JP_DS_NI, JP_ET_KEEP,
			  state == JP_DS_PP ? JP_PPT_CANCEL : JP_PPT_KEEP, 0);
    }

    return jp_act(state, JP_ET_KEEP, JP_PPT_KEEP, 0);
}

/*
 * Figure 4, the (S,G,rpt) machine, five states of which two, PruneTmp and
 * Prune-Pending-Tmp, last only while one message is read: a Join(*,G) puts
 * the interface there, a Prune(S,G,rpt) later in the message takes it back,
 * and the end of the message without one leaves it in NoInfo.  @ppt_zero as
 * for jp_ds_decide(), where the immediate expiry goes to Prune.
 */
struct jp_act rpt_ds_decide(int state, int event, int ppt_zero)
{
    switch (event) {
	case RPT_EV_JOIN_WC:
	    if (state == RPT_DS_P)
		return jp_act(RPT_DS_PT, JP_ET_KEEP, JP_PPT_KEEP, 0);
	    if (state == RPT_DS_PP)
		return jp_act(RPT_DS_PPT, JP_ET_KEEP, JP_PPT_KEEP, 0);
	    break;

	case RPT_EV_JOIN_RPT:
	    if (state == RPT_DS_P || state == RPT_DS_PP)
		return jp_act(RPT_DS_NI, JP_ET_CANCEL, JP_PPT_CANCEL, 0);
	    break;

	case RPT_EV_PRUNE_RPT:
	    if (state == RPT_DS_NI) {
		if (ppt_zero)
		    return jp_act(RPT_DS_P, JP_ET_SET, JP_PPT_KEEP, 0);
		return jp_act(RPT_DS_PP, JP_ET_SET, JP_PPT_START, 0);
	    }
	    if (state == RPT_DS_P || state == RPT_DS_PT)
		return jp_act(RPT_DS_P, JP_ET_MAX, JP_PPT_KEEP, 0);
	    if (state == RPT_DS_PPT)
		return jp_act(RPT_DS_PP, JP_ET_MAX, JP_PPT_KEEP, 0);
	    break;

	case RPT_EV_EOM:
	    if (state == RPT_DS_PT)
		return jp_act(RPT_DS_NI, JP_ET_CANCEL, JP_PPT_KEEP, 0);
	    if (state == RPT_DS_PPT)
		return jp_act(RPT_DS_NI, JP_ET_CANCEL, JP_PPT_CANCEL, 0);
	    break;

	case RPT_EV_PPT:
	    if (state == RPT_DS_PP)
		return jp_act(RPT_DS_P, JP_ET_KEEP, JP_PPT_KEEP, 0);
	    break;

	case RPT_EV_ET:
	    if (state == RPT_DS_P)
		return jp_act(RPT_DS_NI, JP_ET_KEEP, JP_PPT_KEEP, 0);
	    break;
    }

    return jp_act(state, JP_ET_KEEP, JP_PPT_KEEP, 0);
}

/*
 * The Expiry Timer an (S,G,rpt) action leaves, as deadlines on the monotonic
 * clock where zero is a HoldTime of 0xffff, held until a Join cancels it.
 * JP_ET_SET is "started and set to the HoldTime"; JP_ET_MAX is "restarted
 * and is then set to the maximum of its current value and the HoldTime",
 * held being longer than any deadline.  Anything else leaves @cur.
 */
uint64_t rpt_et_after(int et, uint64_t cur, uint64_t want)
{
    if (et == JP_ET_SET)
	return want;

    if (et == JP_ET_MAX && cur && (!want || want > cur))
	return want;

    return cur;
}

/*
 * The Expiry Timer a (*,G) or (S,G) action leaves, `vif_timers` in seconds
 * where 0xffff is held: sec. 4.5.1 and 4.5.2's "set to the HoldTime" for
 * JP_ET_SET and "restarted and is then set to the maximum of its current
 * value and the HoldTime" for JP_ET_MAX, held being the largest there is;
 * JP_ET_CANCEL stops it.  Anything else leaves @cur.  The (S,G,rpt) twin
 * above works on deadlines rather than a countdown, which is why the two
 * are apart.
 */
uint16_t jp_et_after(int et, uint16_t cur, uint16_t holdtime)
{
    if (et == JP_ET_SET)
	return holdtime;

    if (et == JP_ET_MAX && cur < holdtime)
	return holdtime;

    if (et == JP_ET_CANCEL)
	return 0;

    return cur;
}

/*
 * The state of the (*,G) or (S,G) machine in an entry's bits.  Join is
 * `joined_oifs` on a (*,G) entry and `sg_joined_oifs` on an (S,G) one,
 * whose `joined_oifs` also holds the copy of joins(*,G) VOIF_COPY()
 * seeded it with; Prune-Pending is `prune_pending_oifs` on top of either.
 */
int jp_ds_read(struct jp_ds_bits b, int wc)
{
    if (!(wc ? b.joined : b.sg_joined))
	return JP_DS_NI;

    return b.pp ? JP_DS_PP : JP_DS_J;
}

/*
 * And @state written into them.  NoInfo also takes out of an (S,G) entry
 * the copy of the (*,G)'s joins, which is how an Expiry Timer the copy
 * shares ages it out; a (*,G) has no bit of its own to keep apart.
 */
struct jp_ds_bits jp_ds_write(struct jp_ds_bits b, int wc, int state)
{
    b.joined = state != JP_DS_NI;
    if (!wc)
	b.sg_joined = b.joined;
    b.pp = state == JP_DS_PP;

    return b;
}

/*
 * The state of the (S,G,rpt) machine in an entry's bits: Prune in
 * `rpt_pruned_oifs`, Prune-Pending in `rpt_pp_oifs`, NoInfo in neither.
 * @tmp is a Join(*,G) read earlier in the group set being processed, which
 * makes the two the transient PruneTmp and Prune-Pending-Tmp; they forward
 * as Prune and Prune-Pending do, so the bits need not tell them apart.
 */
int rpt_ds_read(struct rpt_ds_bits b, int tmp)
{
    if (b.pruned)
	return tmp ? RPT_DS_PT : RPT_DS_P;

    if (b.pp)
	return tmp ? RPT_DS_PPT : RPT_DS_PP;

    return RPT_DS_NI;
}

struct rpt_ds_bits rpt_ds_write(int state)
{
    struct rpt_ds_bits b;

    b.pruned = state == RPT_DS_P || state == RPT_DS_PT;
    b.pp     = state == RPT_DS_PP || state == RPT_DS_PPT;

    return b;
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "cc-mode"
 * End:
 */
