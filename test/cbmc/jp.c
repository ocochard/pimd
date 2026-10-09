/*
 * jp.c - prove src/pim_jp.c decides as RFC 7761 sec. 4.5.1 to 4.5.3 say
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
 * A harness for cbmc(1), not a program: run.sh compiles it alone, with
 * SOURCE naming src/pim_jp.c or a mutant of it.
 *
 *   proof_ds      jp_ds_decide() against Figures 2 and 3, the (*,G) and
 *                 (S,G) downstream machines, one assertion per state and
 *                 event so that each disagreement is reported apart
 *   proof_rpt     rpt_ds_decide() against Figure 4, the (S,G,rpt) one
 *   proof_et      rpt_et_after() against the prose of sec. 4.5.3: "set to
 *                 the HoldTime" and "the maximum of its current value and
 *                 the HoldTime", a held HoldTime being the longest
 *
 * The tables below are the RFC's, cell by cell, with one reading made
 * explicit: a Prune-Pending Timer of zero "expire[s] immediately", so a
 * Prune that starts one is answered with where its expiry leads.  For the
 * (*,G) and (S,G) machines that is NoInfo, and the PruneEcho "need not be
 * sent" -- a zero timer is the single-neighbor case.  A cell of "-" is the
 * state kept and both timers left alone.
 */

#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>

#include SOURCE

uint32_t nondet_uint32_t(void);
uint64_t nondet_uint64_t(void);

void proof_ds(void);
void proof_rpt(void);
void proof_et(void);

static int same(struct jp_act a, int state, int et, int ppt, int echo)
{
    return a.state == state && a.et == et && a.ppt == ppt && a.echo == echo;
}

#define KEPT(a, s) same((a), (s), JP_ET_KEEP, JP_PPT_KEEP, 0)

void proof_ds(void)
{
    int state = (int)(nondet_uint32_t() % 3);
    int event = (int)(nondet_uint32_t() % 4);
    int zero  = (int)(nondet_uint32_t() & 1);
    struct jp_act a = jp_ds_decide(state, event, zero);

    if (state == JP_DS_NI) {
	if (event == JP_EV_JOIN)	/* -> J, start ET */
	    __CPROVER_assert(same(a, JP_DS_J, JP_ET_SET, JP_PPT_KEEP, 0), "NI: Join starts ET");
	else				/* Prune -> NI; no timer runs */
	    __CPROVER_assert(KEPT(a, JP_DS_NI), "NI: nothing else moves it");
    }

    if (state == JP_DS_J) {
	if (event == JP_EV_JOIN)
	    __CPROVER_assert(same(a, JP_DS_J, JP_ET_MAX, JP_PPT_KEEP, 0), "J: Join restarts ET to the max");
	if (event == JP_EV_PRUNE && !zero)
	    __CPROVER_assert(same(a, JP_DS_PP, JP_ET_KEEP, JP_PPT_START, 0), "J: Prune starts PPT");
	if (event == JP_EV_PRUNE && zero)
	    __CPROVER_assert(same(a, JP_DS_NI, JP_ET_CANCEL, JP_PPT_KEEP, 0), "J: Prune with a zero PPT is NoInfo");
	if (event == JP_EV_PPT)		/* no PPT runs in J */
	    __CPROVER_assert(KEPT(a, JP_DS_J), "J: PPT is not running");
	if (event == JP_EV_ET)
	    __CPROVER_assert(same(a, JP_DS_NI, JP_ET_KEEP, JP_PPT_KEEP, 0), "J: ET expiry is NoInfo");
    }

    if (state == JP_DS_PP) {
	if (event == JP_EV_JOIN)
	    __CPROVER_assert(same(a, JP_DS_J, JP_ET_MAX, JP_PPT_CANCEL, 0), "PP: Join cancels PPT, ET to the max");
	if (event == JP_EV_PRUNE)
	    __CPROVER_assert(KEPT(a, JP_DS_PP), "PP: Prune changes nothing");
	if (event == JP_EV_PPT)
	    __CPROVER_assert(same(a, JP_DS_NI, JP_ET_CANCEL, JP_PPT_KEEP, 1), "PP: PPT expiry is NoInfo and PruneEcho");
	if (event == JP_EV_ET)
	    __CPROVER_assert(same(a, JP_DS_NI, JP_ET_KEEP, JP_PPT_CANCEL, 0), "PP: ET expiry is NoInfo");
    }
}

void proof_rpt(void)
{
    int state = (int)(nondet_uint32_t() % 5);
    int event = (int)(nondet_uint32_t() % 6);
    int zero  = (int)(nondet_uint32_t() & 1);
    struct jp_act a = rpt_ds_decide(state, event, zero);

    /* The transient states last one message: no timer expires in them, and
     * the Join(*,G) that makes them is not seen twice in one group set */
    __CPROVER_assume(!((state == RPT_DS_PT || state == RPT_DS_PPT) &&
		       (event == RPT_EV_PPT || event == RPT_EV_ET || event == RPT_EV_JOIN_WC)));

    if (state == RPT_DS_NI) {
	if (event == RPT_EV_PRUNE_RPT && !zero)
	    __CPROVER_assert(same(a, RPT_DS_PP, JP_ET_SET, JP_PPT_START, 0), "NI: Prune starts PPT and ET");
	else if (event == RPT_EV_PRUNE_RPT)
	    __CPROVER_assert(same(a, RPT_DS_P, JP_ET_SET, JP_PPT_KEEP, 0), "NI: Prune with a zero PPT is Prune");
	else
	    __CPROVER_assert(KEPT(a, RPT_DS_NI), "NI: nothing else moves it");
    }

    if (state == RPT_DS_P) {
	if (event == RPT_EV_JOIN_WC)
	    __CPROVER_assert(KEPT(a, RPT_DS_PT), "P: Join(*,G) is PruneTmp");
	if (event == RPT_EV_JOIN_RPT)
	    __CPROVER_assert(same(a, RPT_DS_NI, JP_ET_CANCEL, JP_PPT_CANCEL, 0), "P: Join(S,G,rpt) is NoInfo");
	if (event == RPT_EV_PRUNE_RPT)
	    __CPROVER_assert(same(a, RPT_DS_P, JP_ET_MAX, JP_PPT_KEEP, 0), "P: Prune restarts ET to the max");
	if (event == RPT_EV_EOM || event == RPT_EV_PPT)
	    __CPROVER_assert(KEPT(a, RPT_DS_P), "P: end of message and PPT change nothing");
	if (event == RPT_EV_ET)
	    __CPROVER_assert(same(a, RPT_DS_NI, JP_ET_KEEP, JP_PPT_KEEP, 0), "P: ET expiry is NoInfo");
    }

    if (state == RPT_DS_PP) {
	if (event == RPT_EV_JOIN_WC)
	    __CPROVER_assert(KEPT(a, RPT_DS_PPT), "PP: Join(*,G) is Prune-Pending-Tmp");
	if (event == RPT_EV_JOIN_RPT)
	    __CPROVER_assert(same(a, RPT_DS_NI, JP_ET_CANCEL, JP_PPT_CANCEL, 0), "PP: Join(S,G,rpt) is NoInfo");
	if (event == RPT_EV_PRUNE_RPT || event == RPT_EV_EOM || event == RPT_EV_ET)
	    __CPROVER_assert(KEPT(a, RPT_DS_PP), "PP: Prune, end of message and ET change nothing");
	if (event == RPT_EV_PPT)
	    __CPROVER_assert(same(a, RPT_DS_P, JP_ET_KEEP, JP_PPT_KEEP, 0), "PP: PPT expiry is Prune");
    }

    if (state == RPT_DS_PT) {
	if (event == RPT_EV_JOIN_RPT)
	    __CPROVER_assert(KEPT(a, RPT_DS_PT), "P': Join(S,G,rpt) changes nothing");
	if (event == RPT_EV_PRUNE_RPT)
	    __CPROVER_assert(same(a, RPT_DS_P, JP_ET_MAX, JP_PPT_KEEP, 0), "P': Prune is Prune, ET to the max");
	if (event == RPT_EV_EOM)
	    __CPROVER_assert(same(a, RPT_DS_NI, JP_ET_CANCEL, JP_PPT_KEEP, 0), "P': end of message is NoInfo");
    }

    if (state == RPT_DS_PPT) {
	if (event == RPT_EV_JOIN_RPT)
	    __CPROVER_assert(KEPT(a, RPT_DS_PPT), "PP': Join(S,G,rpt) changes nothing");
	if (event == RPT_EV_PRUNE_RPT)
	    __CPROVER_assert(same(a, RPT_DS_PP, JP_ET_MAX, JP_PPT_KEEP, 0), "PP': Prune is Prune-Pending, ET to the max");
	if (event == RPT_EV_EOM)
	    __CPROVER_assert(same(a, RPT_DS_NI, JP_ET_CANCEL, JP_PPT_CANCEL, 0), "PP': end of message is NoInfo");
    }
}

void proof_et(void)
{
    int et = (int)(nondet_uint32_t() % 4);
    uint64_t cur  = nondet_uint64_t();
    uint64_t want = nondet_uint64_t();
    uint64_t got = rpt_et_after(et, cur, want);

    /* Zero is held: longer than any deadline */
    if (et == JP_ET_SET)
	__CPROVER_assert(got == want, "SET: the HoldTime");
    if (et == JP_ET_MAX && (cur == 0 || want == 0))
	__CPROVER_assert(got == 0, "MAX: a held one stays or becomes held");
    if (et == JP_ET_MAX && cur && want)
	__CPROVER_assert(got == (cur > want ? cur : want), "MAX: the later deadline");
    if (et == JP_ET_KEEP || et == JP_ET_CANCEL)
	__CPROVER_assert(got == cur, "KEEP and CANCEL leave it");
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "cc-mode"
 * End:
 */
