/*
 * assert.c - prove src/pim_assert.c decides as RFC 7761 sec. 4.6.3 says
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
 * SOURCE naming src/pim_assert.c or a mutant of it.  Where the other
 * harnesses ask whether a decoder stays inside its buffer, this one asks
 * whether a decision is the one the RFC makes, over every input:
 *
 *   proof_spec        compare_metrics() is exactly the order of sec.
 *                     4.6.3, written here from the fields and from the
 *                     bytes of the addresses rather than from the 32-bit
 *                     compares and ntohl() the code uses
 *   proof_strict      never both win, and where the addresses differ one
 *                     always does
 *   proof_transitive  over any three metrics
 *   proof_cancel      infinite_assert_metric(), the AssertCancel of sec.
 *                     4.6.4, never beats a metric that is not infinite,
 *                     and pimd.h spells it as sec. 4.6.3 does
 *
 * What an order cannot say is the RFC's other two words: "an assert is
 * never considered acceptable if its metric is infinite", and "never
 * considered inferior if my_assert_metric is infinite".  Two infinite
 * metrics compare by address here, and it is up to the state machines in
 * src/pim_proto.c not to ask.
 */

#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>

#include SOURCE

uint32_t nondet_uint32_t(void);

void proof_spec(void);
void proof_strict(void);
void proof_transitive(void);
void proof_cancel(void);

/* assert_metric of sec. 4.6.3, as the RFC writes it */
struct metric {
    uint32_t rpt;		/* rpt_bit_flag, 0 or 1 */
    uint32_t pref;		/* metric_preference, 31 bits */
    uint32_t route;		/* route_metric */
    uint8_t  addr[4];		/* ip_address, as it goes on the wire */
};

/* The wire's preference field: the RPT bit on top of 31 bits of preference */
static struct metric metric_of(uint32_t preference, uint32_t route, uint32_t addr)
{
    struct metric m;

    m.rpt   = preference >> 31;
    m.pref  = preference & 0x7fffffff;
    m.route = route;
    memcpy(m.addr, &addr, sizeof(m.addr));

    return m;
}

/* "the first lower value wins", and then "the highest IP address" */
static int spec_wins(const struct metric *a, const struct metric *b)
{
    int i;

    if (a->rpt != b->rpt)
	return a->rpt < b->rpt;
    if (a->pref != b->pref)
	return a->pref < b->pref;
    if (a->route != b->route)
	return a->route < b->route;
    for (i = 0; i < 4; i++) {
	if (a->addr[i] != b->addr[i])
	    return a->addr[i] > b->addr[i];
    }

    return 0;
}

static int wins(uint32_t p1, uint32_t m1, uint32_t a1, uint32_t p2, uint32_t m2, uint32_t a2)
{
    return compare_metrics(p1, m1, a1, p2, m2, a2);
}

void proof_spec(void)
{
    uint32_t p1 = nondet_uint32_t(), m1 = nondet_uint32_t(), a1 = nondet_uint32_t();
    uint32_t p2 = nondet_uint32_t(), m2 = nondet_uint32_t(), a2 = nondet_uint32_t();
    struct metric x = metric_of(p1, m1, a1), y = metric_of(p2, m2, a2);
    int r = wins(p1, m1, a1, p2, m2, a2);

    __CPROVER_assert(r == 0 || r == 1, "the answer is TRUE or FALSE");
    __CPROVER_assert(r == spec_wins(&x, &y), "the local metric wins exactly where sec. 4.6.3 says");
}

void proof_strict(void)
{
    uint32_t p1 = nondet_uint32_t(), m1 = nondet_uint32_t(), a1 = nondet_uint32_t();
    uint32_t p2 = nondet_uint32_t(), m2 = nondet_uint32_t(), a2 = nondet_uint32_t();
    int ab = wins(p1, m1, a1, p2, m2, a2);
    int ba = wins(p2, m2, a2, p1, m1, a1);

    __CPROVER_assert(!(ab && ba), "two routers never both win");
    __CPROVER_assert(a1 == a2 || ab || ba, "of two routers, one wins");
}

void proof_transitive(void)
{
    uint32_t p1 = nondet_uint32_t(), m1 = nondet_uint32_t(), a1 = nondet_uint32_t();
    uint32_t p2 = nondet_uint32_t(), m2 = nondet_uint32_t(), a2 = nondet_uint32_t();
    uint32_t p3 = nondet_uint32_t(), m3 = nondet_uint32_t(), a3 = nondet_uint32_t();

    __CPROVER_assume(wins(p1, m1, a1, p2, m2, a2));
    __CPROVER_assume(wins(p2, m2, a2, p3, m3, a3));
    __CPROVER_assert(wins(p1, m1, a1, p3, m3, a3), "an election has one winner whatever the order");
}

void proof_cancel(void)
{
    uint32_t p = nondet_uint32_t(), m = nondet_uint32_t();
    uint32_t a1 = nondet_uint32_t(), a2 = nondet_uint32_t();
    struct metric inf = metric_of(PIM_ASSERT_INFINITE_PREFERENCE, PIM_ASSERT_INFINITE_METRIC, 0);

    __CPROVER_assert(inf.rpt == 1 && inf.pref == 0x7fffffff && inf.route == 0xffffffff,
		     "pimd.h spells infinite_assert_metric() as {1, infinity, infinity}");

    __CPROVER_assume(!(p == PIM_ASSERT_INFINITE_PREFERENCE && m == PIM_ASSERT_INFINITE_METRIC));
    __CPROVER_assert(!wins(PIM_ASSERT_INFINITE_PREFERENCE, PIM_ASSERT_INFINITE_METRIC, a1, p, m, a2),
		     "an AssertCancel beats no real metric");
    __CPROVER_assert(wins(p, m, a2, PIM_ASSERT_INFINITE_PREFERENCE, PIM_ASSERT_INFINITE_METRIC, a1),
		     "and every real metric beats it");
}

/*
 * assert_decide() against the two tables, Figure 8 of sec. 4.6.1 for the
 * (S,G) machine and Figure 9 of sec. 4.6.2 for the (*,G) one, for the
 * events an Assert message is.  The terms are the RFC's:
 *
 *   preferred   better than the current winner's metric
 *   acceptable  better than my_assert_metric, and never infinite
 *   inferior    worse than my_assert_metric, and never where that is
 *               infinite
 *
 * my_assert_metric is infinite on the RPF interface, CouldAssert being
 * FALSE there, so on the upstream side nothing is inferior and every
 * Assert but a cancel is acceptable.  CouldAssert and AssertTrackingDesired
 * are what pimd approximates them with: CouldAssert(*,G,I) is the
 * interface being downstream, CouldAssert(S,G,I) that and SPTbit(S,G), and
 * AssertTrackingDesired is `tracking` -- the approximation is M21 of
 * doc/rfc7761-compliance.md, and the tables are what is proven here.
 */
static int spec_decide(const struct assert_view *v)
{
    int rpt = (v->pref & PIM_ASSERT_RPT_BIT) != 0;
    int cancel = v->pref == PIM_ASSERT_INFINITE_PREFERENCE &&
	v->metric == PIM_ASSERT_INFINITE_METRIC;
    int noinfo = v->winner == 0;
    int winner = !noinfo && v->is_winner;
    int from_winner = !noinfo && v->src == v->winner;
    int preferred = !noinfo &&
	!compare_metrics(v->win_pref, v->win_metric, v->winner, v->pref, v->metric, v->src);
    int acceptable, inferior, could;

    /* Deviation, M21: pimd answers no Assert at all on an interface its
     * AssertTrackingDesired approximation says it does not track, where the
     * tables ask for it only on the way from NoInfo to Loser */
    if (!v->tracking)
	return ASSERT_ACT_NONE;

    if (v->where == ASSERT_DOWNSTREAM) {
	inferior   = compare_metrics(v->my_pref, v->my_metric, v->my_addr,
				     v->pref, v->metric, v->src);
	acceptable = !inferior && !cancel;
	could      = v->wc ? 1 : v->spt;

	if (noinfo) {
	    if (v->wc) {
		if (rpt && inferior && could)
		    return ASSERT_ACT_SEND;			/* A1 */
		if (rpt && acceptable && v->tracking)
		    return ASSERT_ACT_LOSE;			/* A2 */
		return ASSERT_ACT_NONE;
	    }
	    if (!rpt && inferior)
		return ASSERT_ACT_SEND;				/* A1 */
	    if (rpt && could)
		return ASSERT_ACT_SEND;				/* A1 */
	    if (!rpt && acceptable && v->tracking)
		return ASSERT_ACT_LOSE;				/* A6 */
	    return ASSERT_ACT_NONE;
	}

	/* "Receive Preferred Assert ... an assert that has a better metric
	 * than our own": the winner is this router, and its metric is the
	 * one it would assert with now, not the one it stored at A1, which
	 * the routing table may have moved since */
	if (winner) {
	    if (inferior)
		return ASSERT_ACT_SEND;				/* A3 */
	    return ASSERT_ACT_LOSE;				/* A2 */
	}

	/* Loser.  A message from the winner says what its metric is now,
	 * so an inferior one ends the state even where it would also beat
	 * the metric stored for it. */
	if (from_winner && (inferior || cancel))
	    return ASSERT_ACT_CLEAR;				/* A5 */
	if (preferred && (!v->wc || rpt))
	    return ASSERT_ACT_STORE;				/* A2 */
	if (from_winner && acceptable && (v->wc ? rpt : !rpt))
	    return ASSERT_ACT_STORE;				/* A2 */
	return ASSERT_ACT_NONE;
    }

    if (v->where == ASSERT_UPSTREAM) {
	acceptable = !cancel;

	if (noinfo) {
	    if ((v->wc ? rpt : !rpt) && acceptable && v->tracking)
		return ASSERT_ACT_FOLLOW;			/* A6, A2 */
	    return ASSERT_ACT_NONE;
	}

	if (from_winner && cancel)
	    return ASSERT_ACT_CLEAR;				/* A5 */
	if (preferred && (!v->wc || rpt))
	    return from_winner ? ASSERT_ACT_STORE : ASSERT_ACT_FOLLOW;	/* A2 */
	if (from_winner && acceptable && (v->wc ? rpt : !rpt))
	    return ASSERT_ACT_STORE;				/* A2 */
	return ASSERT_ACT_NONE;
    }

    return ASSERT_ACT_NONE;
}

void proof_decide(void);

void proof_decide(void)
{
    struct assert_view v;
    int got, want, noinfo, winner;

    v.wc           = nondet_uint32_t() & 1;
    v.tracking     = nondet_uint32_t() & 1;
    v.where        = (int)(nondet_uint32_t() % 3);
    v.has_state    = nondet_uint32_t() & 1;
    v.spt          = nondet_uint32_t() & 1;
    v.rp_entry     = nondet_uint32_t() & 1;
    v.has_upstream = nondet_uint32_t() & 1;
    v.winner       = nondet_uint32_t();
    v.is_winner    = nondet_uint32_t() & 1;
    v.win_pref     = nondet_uint32_t();
    v.win_metric   = nondet_uint32_t();
    v.my_pref      = nondet_uint32_t();
    v.my_metric    = nondet_uint32_t();
    v.my_addr      = nondet_uint32_t();
    v.src          = nondet_uint32_t();
    v.pref         = nondet_uint32_t();
    v.metric       = nondet_uint32_t();

    /* What the caller guarantees: no state without a slot to keep it in,
     * a winner that is this router is stored under its own address, an
     * Assert is never from this router, and the (*,G) entry carries
     * MRTF_RP.  And what the tables leave out: my_assert_metric is not
     * infinite on a downstream interface, and nothing wins upstream, where
     * this router has no RPF neighbor only while it has no route. */
    __CPROVER_assume(v.has_state || v.winner == 0);
    __CPROVER_assume(!v.is_winner || v.winner == v.my_addr);
    __CPROVER_assume(v.src != v.my_addr && v.src != 0);
    __CPROVER_assume(!v.wc || v.rp_entry);
    /* my_assert_metric(): spt_assert_metric, RPT bit clear, where the
     * (S,G) machine has SPTbit; rpt_assert_metric, bit set, otherwise */
    __CPROVER_assume(((v.my_pref & PIM_ASSERT_RPT_BIT) == 0) == (!v.wc && v.spt));
    __CPROVER_assume(!(v.my_pref == PIM_ASSERT_INFINITE_PREFERENCE &&
		       v.my_metric == PIM_ASSERT_INFINITE_METRIC));
    __CPROVER_assume(v.where != ASSERT_UPSTREAM || (v.has_state && v.has_upstream &&
						    !(v.winner && v.is_winner)));
    /* And what assert_decide() itself keeps true of the state it leaves,
     * which is why it is not proven here: no transition stores an
     * infinite metric as the winner's, and an (S,G) entry without MRTF_RP
     * stores no winner off an Assert with the RPT bit on its RPF
     * interface. */
    __CPROVER_assume(v.winner == 0 || !(v.win_pref == PIM_ASSERT_INFINITE_PREFERENCE &&
					v.win_metric == PIM_ASSERT_INFINITE_METRIC));
    __CPROVER_assume(!(v.where == ASSERT_UPSTREAM && !v.wc && !v.rp_entry && v.winner) ||
		     !(v.win_pref & PIM_ASSERT_RPT_BIT));

    got  = assert_decide(&v);
    want = spec_decide(&v);
    noinfo = v.winner == 0;
    winner = !noinfo && v.is_winner;

    __CPROVER_assert(!(!v.wc && v.where == ASSERT_DOWNSTREAM && noinfo) || got == want,
		     "(S,G) machine, downstream, NoInfo");
    __CPROVER_assert(!(!v.wc && v.where == ASSERT_DOWNSTREAM && winner) || got == want,
		     "(S,G) machine, downstream, Winner");
    __CPROVER_assert(!(!v.wc && v.where == ASSERT_DOWNSTREAM && !noinfo && !winner) || got == want,
		     "(S,G) machine, downstream, Loser");
    __CPROVER_assert(!(!v.wc && v.where == ASSERT_UPSTREAM && noinfo) || got == want,
		     "(S,G) machine, RPF interface, NoInfo");
    __CPROVER_assert(!(!v.wc && v.where == ASSERT_UPSTREAM && !noinfo) || got == want,
		     "(S,G) machine, RPF interface, Loser");
    __CPROVER_assert(!(v.wc && v.where == ASSERT_DOWNSTREAM && noinfo) || got == want,
		     "(*,G) machine, downstream, NoInfo");
    __CPROVER_assert(!(v.wc && v.where == ASSERT_DOWNSTREAM && winner) || got == want,
		     "(*,G) machine, downstream, Winner");
    __CPROVER_assert(!(v.wc && v.where == ASSERT_DOWNSTREAM && !noinfo && !winner) || got == want,
		     "(*,G) machine, downstream, Loser");
    __CPROVER_assert(!(v.wc && v.where == ASSERT_UPSTREAM && noinfo) || got == want,
		     "(*,G) machine, RPF interface, NoInfo");
    __CPROVER_assert(!(v.wc && v.where == ASSERT_UPSTREAM && !noinfo) || got == want,
		     "(*,G) machine, RPF interface, Loser");
    __CPROVER_assert(v.where != ASSERT_ELSEWHERE || got == ASSERT_ACT_NONE,
		     "an interface neither machine is on");
}
