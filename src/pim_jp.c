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
 * tables of the RFC.
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

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "cc-mode"
 * End:
 */
