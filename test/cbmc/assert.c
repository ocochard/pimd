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
