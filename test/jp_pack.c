/*
 * jp_pack - what add_jp_entry() puts in each Join/Prune when one is not enough
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
 * RFC 7761 sec. 4.9.5.2: a group set carrying a Join(*,G) may not be split
 * across messages, and when its (S,G,rpt) Prunes are more than one message
 * holds, the numerically smallest go and the rest are ignored.  The
 * jp-pack scenario of test/lab.sh asserts the second rule over the wire,
 * with the Prunes added in ascending order, which never takes the path of
 * jp_prune_keep_smallest() that gives a larger one's place to a smaller
 * one; and nothing in a lab can have two groups' entries packed into the
 * same message on cue, which is what flush_packed_groups() is for.  This
 * drives add_jp_entry() itself, inside the router of fuzz/router.c, and
 * reads each message it sends back with pim_parse_jp().
 *
 * The messages are caught at send_pim(), which the link wraps
 * (-Wl,--wrap=send_pim, test/Makefile.am): the router has no socket, and
 * the caught copy is what the wire would have carried.
 *
 *   1. A set of Join(S,G) for one group, then a Join(*,G) for another and
 *      Prune(S,G,rpt) after it, together more than a message holds: the
 *      first message carries the first group whole and the second the
 *      other whole.  The control is the same with no Join(*,G), where the
 *      split may fall inside the second set, and has to, or the step never
 *      reached the overflow it is about.
 *   2. One Join(*,G) and more Prune(S,G,rpt) than fit, in descending
 *      order, so that every one past the limit takes a larger one's place:
 *      one message, whose Prunes are the smallest of them.  The control is
 *      the ascending order the lab uses, which has to give the same set.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "defs.h"
#include "fuzz/router.h"

#define HOLDTIME	210
#define GROUP_A		0xe1010101	/* 225.1.1.1 */
#define GROUP_B		0xe1010102	/* 225.1.1.2 */
#define SRC_BASE	0x0a010000	/* 10.1.0.0, sources counted from */
#define MANY		90		/* more Prunes than one message holds */

/* The messages caught, from the PIM header on */
#define MAX_MSGS	8
static uint8_t msgs[MAX_MSGS][SEND_BUF_SIZE];
static size_t msg_len[MAX_MSGS];
static int nmsgs;

static int failed;

void __wrap_send_pim(char *buf, uint32_t src, uint32_t dst, int type, size_t len);

void __wrap_send_pim(char *buf, uint32_t src, uint32_t dst, int type, size_t len)
{
    size_t whole = sizeof(pim_header_t) + len;

    (void)src;
    (void)dst;

    if (type != PIM_JOIN_PRUNE)
	return;

    if (nmsgs == MAX_MSGS || whole > sizeof(msgs[0])) {
	printf("FAIL: more Join/Prune messages than this test expects\n");
	failed = 1;
	return;
    }

    memcpy(msgs[nmsgs], buf + sizeof(struct ip), whole);
    msg_len[nmsgs++] = whole;
}

static void check(int ok, const char *what)
{
    printf("%s: %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok)
	failed = 1;
}

/* One group set of a caught message, as counts and addresses */
struct set {
    uint32_t group;		/* host order */
    unsigned num_j, num_p;
    uint32_t j[MANY + 1], p[MANY + 1];	/* host order */
    uint8_t  p_flags[MANY + 1];
};

/* The group sets of message @m, or -1 where it does not parse */
static int sets_of(int m, struct set *sets, int max)
{
    const uint8_t *g;
    pim_jp_grp_t grp;
    pim_jp_src_t src;
    pim_jp_t jp;
    unsigned i, n;

    if (pim_parse_jp(msgs[m], msg_len[m], &jp) != PIM_JP_OK)
	return -1;

    g = jp.groups;
    for (n = 0; n < jp.num_groups && (int)n < max; n++) {
	g = pim_jp_group(g, &grp);
	sets[n].group = ntohl(grp.group);
	sets[n].num_j = grp.num_j;
	sets[n].num_p = grp.num_p;
	if (grp.num_j > MANY + 1 || grp.num_p > MANY + 1)
	    return -1;
	for (i = 0; i < grp.num_j; i++) {
	    pim_jp_source(&grp, i, &src);
	    sets[n].j[i] = ntohl(src.addr);
	}
	for (i = 0; i < grp.num_p; i++) {
	    pim_jp_source(&grp, grp.num_j + i, &src);
	    sets[n].p[i] = ntohl(src.addr);
	    sets[n].p_flags[i] = src.flags;
	}
    }

    return (int)n;
}

/* The neighbour every message is addressed to: the first the router has */
static pim_nbr_entry_t *neighbour(void)
{
    vifi_t vifi;

    for (vifi = 0; vifi < numvifs; vifi++) {
	if (uvifs[vifi].uv_pim_neighbors)
	    return uvifs[vifi].uv_pim_neighbors;
    }

    return NULL;
}

/* Whatever the router's own build left queued goes, and is forgotten */
static void drain(pim_nbr_entry_t *nbr)
{
    pack_and_send_jp_message(nbr);
    nmsgs = 0;
}

static void join_sg(pim_nbr_entry_t *nbr, uint32_t group, uint32_t source)
{
    add_jp_entry(nbr, HOLDTIME, htonl(group), SINGLE_GRP_MSKLEN, htonl(source),
		 SINGLE_SRC_MSKLEN, 0, PIM_ACTION_JOIN);
}

static void join_wc(pim_nbr_entry_t *nbr, uint32_t group, uint32_t rp)
{
    add_jp_entry(nbr, HOLDTIME, htonl(group), SINGLE_GRP_MSKLEN, htonl(rp),
		 SINGLE_SRC_MSKLEN, MRTF_RP | MRTF_WC, PIM_ACTION_JOIN);
}

static void prune_rpt(pim_nbr_entry_t *nbr, uint32_t group, uint32_t source)
{
    add_jp_entry(nbr, HOLDTIME, htonl(group), SINGLE_GRP_MSKLEN, htonl(source),
		 SINGLE_SRC_MSKLEN, MRTF_RP, PIM_ACTION_PRUNE);
}

/*
 * Step 1, and its control with @wc false.  Returns how many messages the
 * second group's entries ended up in.
 */
static int two_groups(pim_nbr_entry_t *nbr, int wc, unsigned *a_joins, unsigned *b_entries)
{
    struct set sets[4];
    unsigned i;
    int m, n, s, b_msgs = 0;

    drain(nbr);
    for (i = 0; i < 30; i++)
	join_sg(nbr, GROUP_A, SRC_BASE + i);
    if (wc)
	join_wc(nbr, GROUP_B, SRC_BASE + 0xff00);
    for (i = 0; i < 40; i++)
	prune_rpt(nbr, GROUP_B, SRC_BASE + 0x100 + i);
    pack_and_send_jp_message(nbr);

    *a_joins = *b_entries = 0;
    for (m = 0; m < nmsgs; m++) {
	int has_b = 0;

	n = sets_of(m, sets, 4);
	if (n < 0) {
	    check(0, "a message the packer sent parses");
	    return -1;
	}
	for (s = 0; s < n; s++) {
	    if (sets[s].group == GROUP_A)
		*a_joins += sets[s].num_j;
	    if (sets[s].group == GROUP_B) {
		*b_entries += sets[s].num_j + sets[s].num_p;
		has_b = 1;
	    }
	}
	b_msgs += has_b;
    }

    return b_msgs;
}

/* Step 2, in descending order or not: the Prunes of the one message sent */
static int one_group(pim_nbr_entry_t *nbr, int descending, struct set *set)
{
    unsigned i;

    drain(nbr);
    join_wc(nbr, GROUP_B, SRC_BASE + 0xff00);
    for (i = 0; i < MANY; i++)
	prune_rpt(nbr, GROUP_B, SRC_BASE + 0x100 + (descending ? MANY - 1 - i : i));
    pack_and_send_jp_message(nbr);

    if (nmsgs != 1 || sets_of(0, set, 1) != 1)
	return 0;

    return 1;
}

static int cmp_u32(const void *a, const void *b)
{
    uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;

    return x < y ? -1 : x > y;
}

int main(void)
{
    struct set asc, desc;
    pim_nbr_entry_t *nbr;
    unsigned a_joins, b_entries, i;
    int b_msgs, smallest;

    /* The reset is what makes the routing table exist, see fuzz_ipc.c */
    fuzz_router_init("jp_pack");
    fuzz_router_reset();
    fuzz_router_build();

    nbr = neighbour();
    if (!nbr) {
	printf("FAIL: the router has no neighbour to address a Join/Prune to\n");
	return 1;
    }

    /* 1. The control first: with no Join(*,G) the second set may split */
    b_msgs = two_groups(nbr, 0, &a_joins, &b_entries);
    check(b_msgs == 2 && b_entries == 40,
	  "control: Prunes alone are split across two messages, so the overflow is reached");

    b_msgs = two_groups(nbr, 1, &a_joins, &b_entries);
    check(nmsgs == 2, "a Join(*,G) set that overflows goes in a message after the one packed before it");
    check(a_joins == 30, "the first group's 30 Joins all went out");
    check(b_msgs == 1 && b_entries == 41,
	  "and the Join(*,G) set went out whole, its Join and 40 Prunes in one message");

    /* 2. The control is the order the lab uses */
    if (!one_group(nbr, 0, &asc)) {
	check(0, "control: ascending Prunes give one message of one group set");
	return 1;
    }
    check(asc.num_j == 1 && asc.num_p > 0 && asc.num_p < MANY,
	  "control: ascending Prunes are cut to what one message holds");
    smallest = 1;
    for (i = 0; i < asc.num_p; i++)
	smallest &= asc.p[i] == SRC_BASE + 0x100 + i;
    check(smallest, "control: and the ones kept are the smallest");

    if (!one_group(nbr, 1, &desc)) {
	check(0, "descending Prunes give one message of one group set");
	return 1;
    }
    check(desc.num_j == 1 && desc.num_p == asc.num_p,
	  "descending Prunes are cut to the same count");
    qsort(desc.p, desc.num_p, sizeof(desc.p[0]), cmp_u32);
    smallest = 1;
    for (i = 0; i < desc.num_p; i++)
	smallest &= desc.p[i] == asc.p[i];
    check(smallest, "and the ones kept are the same smallest, each having taken a larger one's place");
    smallest = 1;
    for (i = 0; i < desc.num_p; i++)
	smallest &= (desc.p_flags[i] & USADDR_RP_BIT) && (desc.p_flags[i] & USADDR_S_BIT);
    check(smallest, "with the RP and S bits on every replacement");

    return failed;
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "cc-mode"
 * End:
 */
