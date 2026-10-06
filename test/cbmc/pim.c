/*
 * pim.c - prove src/pim_parse.c over every message up to a length
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
 * SOURCE naming src/pim_parse.c or a mutant of it, which this file includes
 * so that the static steps are in reach.  autorp.c beside it explains the
 * method; the proofs here are, each an entry point for cbmc --function:
 *
 *   proof_hello_opt    one Hello option, from any cursor on any message
 *   proof_hello_addr   one Address List entry, anywhere a list can be
 *   proof_hello_addrs  the Address List check, for lists up to MAXLEN
 *   proof_hello        a whole Hello, for messages up to MAXLEN
 *   proof_jp_hdr       a Join/Prune header, for any message
 *   proof_jp_set       one group set, from any cursor on any message
 *   proof_jp_srcs      the source check of one set, up to MAXLEN
 *   proof_jp_group     the group set accessor, wherever a set can be
 *   proof_jp_source    the source accessor, for any entry of any set
 *   proof_jp           a whole Join/Prune, for messages up to MAXLEN,
 *                      read back through the accessors as the caller does
 *   proof_bsr_hdr      a Bootstrap header, for any message
 *   proof_bsr_set      one Bootstrap group set, from any cursor
 *   proof_bsr_group    the group set accessor, wherever a set can be
 *   proof_bsr_rp       the RP record accessor, for any record of any set
 *   proof_bsr          a whole Bootstrap, for messages up to MAXLEN, read
 *                      back through the accessors as the caller does
 *   proof_crp          a whole Candidate-RP-Advertisement and every prefix
 *                      of it, for any message
 *
 * The first two have no loop and cover every length an IP datagram can
 * carry.  Beside memory safety, what they assert is the contract
 * receive_pim_hello() relies on:
 *
 *   - an option is refused before its value is read when it does not fit,
 *     and the cursor is not moved by a refusal;
 *   - an option read consumes its header and exactly the length it gave,
 *     and the fields of a known option are the bytes sec. 4.9.2 puts them
 *     at, a known option of another length refusing the message;
 *   - an Address List the decoder keeps lies inside the message, is a
 *     whole number of entries, and every entry is IPv4;
 *   - pim_hello_addr() reads entry i and nothing else;
 *   - a Join/Prune is refused unless every group set the header counts and
 *     every source each set counts lies inside the message, with every
 *     address IPv4 and every mask length one MASKLEN_TO_MASK() can take,
 *     so that the accessors, walked the way receive_pim_join_prune()
 *     walks them, never leave the message;
 *   - the same of a Bootstrap's group sets and RP records, the next set
 *     always behind the RP records the fragment count says, so that no
 *     walk can read one set's records as another set;
 *   - a Candidate-RP-Advertisement hands out no more prefixes than it
 *     holds, whatever its count says.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include SOURCE

#ifndef MAXLEN
#define MAXLEN 32
#endif

/* The largest IP payload, which bounds what reaches accept_pim() */
#define DATAGRAM_MAX 65515

size_t nondet_size_t(void);
uint16_t nondet_uint16_t(void);
uint32_t nondet_uint32_t(void);
uint8_t nondet_uint8_t(void);

static uint8_t *message(size_t *len, size_t max)
{
    uint8_t *buf;

    *len = nondet_size_t();
    __CPROVER_assume(*len <= max);
    buf = malloc(*len);
    __CPROVER_assume(buf != NULL);

    return buf;
}

static uint16_t be16(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

static uint32_t be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

void proof_hello_opt(void);
void proof_hello_addr(void);
void proof_hello_addrs(void);
void proof_hello(void);
void proof_jp_hdr(void);
void proof_jp_set(void);
void proof_jp_srcs(void);
void proof_jp_group(void);
void proof_jp_source(void);
void proof_jp(void);
void proof_bsr_hdr(void);
void proof_bsr_set(void);
void proof_bsr_group(void);
void proof_bsr_rp(void);
void proof_bsr(void);
void proof_crp(void);

void proof_hello_opt(void)
{
    pim_hello_opts_t opts;
    struct pim_cursor c, before;
    uint16_t type, olen;
    uint8_t *buf;
    size_t len, off;
    int rc;

    buf = message(&len, DATAGRAM_MAX);
    off = nondet_size_t();
    __CPROVER_assume(off <= len);
    c.p    = buf + off;
    c.left = len - off;
    before = c;
    memset(&opts, 0, sizeof(opts));

    rc = pim_parse_hello_opt(&c, &opts);
    __CPROVER_assert(c.p + c.left == buf + len, "the cursor stays on the message");

    if (rc == PIM_HELLO_END) {
	__CPROVER_assert(before.left < 4, "the walk ends only where no option fits");
	__CPROVER_assert(c.p == before.p, "and moves nothing");
	free(buf);
	return;
    }

    __CPROVER_assert(before.left >= 4, "an option header that fits is read");
    type = be16(before.p);
    olen = be16(before.p + 2);

    switch (rc) {
    case PIM_HELLO_SHORT:
	__CPROVER_assert(before.left < 4 + (size_t)olen, "only an option that does not fit is short");
	__CPROVER_assert(c.p == before.p, "and a refusal moves nothing");
	break;

    case PIM_HELLO_BADOPTLEN:
	__CPROVER_assert((type == PIM_HELLO_HOLDTIME && olen != PIM_HELLO_HOLDTIME_LEN) ||
			 (type == PIM_HELLO_DR_PRIO && olen != PIM_HELLO_DR_PRIO_LEN) ||
			 (type == PIM_HELLO_GENID && olen != PIM_HELLO_GENID_LEN) ||
			 (type == PIM_HELLO_LAN_PRUNE_DELAY &&
			  olen != PIM_HELLO_LAN_PRUNE_DELAY_LEN),
			 "only a known option of another length is refused");
	__CPROVER_assert(opts.bad_type == type && opts.bad_len == olen, "and it says which");
	__CPROVER_assert(c.p == before.p, "and a refusal moves nothing");
	break;

    case PIM_HELLO_OPT:
	__CPROVER_assert(c.left + 4 + olen == before.left, "an option is its header and its length");
	if (type == PIM_HELLO_HOLDTIME)
	    __CPROVER_assert(opts.holdtime_present && opts.holdtime == be16(before.p + 4),
			     "the holdtime is the value");
	if (type == PIM_HELLO_DR_PRIO)
	    __CPROVER_assert(opts.dr_prio_present && opts.dr_prio == be32(before.p + 4),
			     "the DR priority is the value");
	if (type == PIM_HELLO_GENID)
	    __CPROVER_assert(opts.genid == be32(before.p + 4), "the GenID is the value");
	if (type == PIM_HELLO_LAN_PRUNE_DELAY)
	    __CPROVER_assert(opts.lan_delay_present &&
			     opts.tracking_support == (before.p[4] >> 7) &&
			     opts.propagation_delay == (be16(before.p + 4) & 0x7fff) &&
			     opts.override_interval == be16(before.p + 6),
			     "the LAN Prune Delay is the T bit and two values");
	if (type == PIM_HELLO_ADDR_LIST)
	    __CPROVER_assert(opts.addr_list == before.p + 4 && opts.addr_list_len == olen,
			     "an Address List is the option's value");
	break;

    default:
	__CPROVER_assert(0, "a step ends in an option, an end or a refusal");
    }
    free(buf);
}

void proof_hello_addr(void)
{
    pim_hello_opts_t opts;
    uint8_t *buf;
    size_t len, off;
    uint16_t n, i;
    uint32_t addr;

    buf = message(&len, DATAGRAM_MAX);
    off = nondet_size_t();
    n   = nondet_uint16_t();
    i   = nondet_uint16_t();
    __CPROVER_assume(off <= len && (size_t)n * PIM_ENCODE_UNI_ADDR_LEN <= len - off);
    __CPROVER_assume(i < n);

    memset(&opts, 0, sizeof(opts));
    opts.addr_list     = buf + off;
    opts.addr_list_len = (uint16_t)(n * PIM_ENCODE_UNI_ADDR_LEN);

    addr = pim_hello_addr(&opts, i);
    __CPROVER_assert(memcmp(&addr, opts.addr_list + (size_t)i * PIM_ENCODE_UNI_ADDR_LEN + 2, 4) == 0,
		     "entry i is the four bytes after its family and type, network order");
    free(buf);
}

void proof_hello_addrs(void)
{
    pim_hello_opts_t opts;
    uint8_t *buf;
    size_t len, k;

    buf = message(&len, MAXLEN);
    memset(&opts, 0, sizeof(opts));
    opts.addr_list     = buf;
    opts.addr_list_len = (uint16_t)len;

    pim_parse_hello_addrs(&opts);

    if (opts.addr_list) {
	__CPROVER_assert(opts.addr_list == buf && opts.addr_list_len == len &&
			 len % PIM_ENCODE_UNI_ADDR_LEN == 0, "a list kept is the whole option");
	k = nondet_size_t();
	__CPROVER_assume(k < len / PIM_ENCODE_UNI_ADDR_LEN);
	__CPROVER_assert(buf[k * 6] == ADDRF_IPv4 && buf[k * 6 + 1] == ADDRT_IPv4,
			 "and every entry of it is IPv4");
    } else {
	__CPROVER_assert(opts.addr_list_len == 0 && opts.addr_list_refused, "a list refused says why");
    }
    free(buf);
}

void proof_hello(void)
{
    pim_hello_opts_t opts;
    uint8_t *buf;
    size_t len;
    uint16_t i;
    int rc;

    buf = message(&len, MAXLEN);
    rc = pim_parse_hello(buf, len, &opts);

    __CPROVER_assert(rc == PIM_HELLO_OK || rc == PIM_HELLO_SHORT || rc == PIM_HELLO_BADOPTLEN,
		     "a Hello ends in a verdict");
    if (len < sizeof(pim_header_t))
	__CPROVER_assert(rc == PIM_HELLO_SHORT, "a message without a header is refused");

    if (rc == PIM_HELLO_OK && opts.addr_list) {
	__CPROVER_assert(opts.addr_list >= buf + sizeof(pim_header_t) &&
			 opts.addr_list + opts.addr_list_len <= buf + len,
			 "a list kept lies inside the message");
	i = nondet_uint16_t();
	__CPROVER_assume(i < opts.addr_list_len / PIM_ENCODE_UNI_ADDR_LEN);
	(void)pim_hello_addr(&opts, i);
    }
    free(buf);
}

void proof_jp_hdr(void)
{
    struct pim_cursor c;
    pim_jp_t jp;
    uint8_t *buf;
    size_t len;
    int rc;

    buf = message(&len, DATAGRAM_MAX);
    memset(&jp, 0, sizeof(jp));
    rc = pim_parse_jp_hdr(&c, buf, len, &jp);

    if (len < PIM_JOIN_PRUNE_MINLEN) {
	__CPROVER_assert(rc == PIM_JP_SHORT, "a message without a header is refused");
    } else if (rc == PIM_JP_OK) {
	__CPROVER_assert(buf[4] == ADDRF_IPv4 && buf[5] == ADDRT_IPv4, "the upstream is IPv4");
	__CPROVER_assert(memcmp(&jp.upstream, buf + 6, 4) == 0, "the upstream is bytes 6 to 9");
	__CPROVER_assert(jp.num_groups == buf[11] && jp.num_groups > 0, "the group count is byte 11");
	__CPROVER_assert(jp.holdtime == be16(buf + 12), "the holdtime is bytes 12 and 13");
	__CPROVER_assert(c.p == buf + PIM_JOIN_PRUNE_MINLEN && c.p + c.left == buf + len &&
			 jp.groups == c.p, "the cursor covers the rest of the message");
    } else {
	__CPROVER_assert(rc == PIM_JP_UPSTREAM || rc == PIM_JP_NOGROUPS, "a header ends in a verdict");
    }
    free(buf);
}

void proof_jp_set(void)
{
    struct pim_cursor c, before, srcs;
    pim_jp_t jp;
    uint8_t *buf;
    size_t len, off, srclen;
    int rc;

    buf = message(&len, DATAGRAM_MAX);
    off = nondet_size_t();
    __CPROVER_assume(off <= len);
    c.p    = buf + off;
    c.left = len - off;
    before = c;
    memset(&jp, 0, sizeof(jp));

    rc = pim_parse_jp_set(&c, &jp, &srcs);
    __CPROVER_assert(c.p + c.left == buf + len, "the cursor stays on the message");

    if (rc != PIM_JP_OK) {
	__CPROVER_assert(rc == PIM_JP_TRUNCATED || rc == PIM_JP_GRP_MASKLEN ||
			 rc == PIM_JP_GRP_FAMILY, "a set ends in a verdict");
	if (before.left >= PIM_JP_GRP_SET_LEN && rc == PIM_JP_TRUNCATED)
	    __CPROVER_assert(before.left - PIM_JP_GRP_SET_LEN <
			     ((size_t)be16(before.p + 8) + be16(before.p + 10)) * 8,
			     "only a set whose sources do not fit is truncated");
	free(buf);
	return;
    }

    srclen = ((size_t)be16(before.p + 8) + be16(before.p + 10)) * PIM_ENCODE_SRC_ADDR_LEN;
    __CPROVER_assert(before.p[3] <= PIM_MAX_MSKLEN, "the group mask is one an address can have");
    __CPROVER_assert(before.p[0] == ADDRF_IPv4 && before.p[1] == ADDRT_IPv4, "the group is IPv4");
    __CPROVER_assert(srcs.p == before.p + PIM_JP_GRP_SET_LEN && srcs.left == srclen,
		     "the sources are what the counts say, right behind the counts");
    __CPROVER_assert(c.p == srcs.p + srclen, "and the next set is right behind them");
    free(buf);
}

void proof_jp_srcs(void)
{
    struct pim_cursor srcs;
    pim_jp_t jp;
    uint8_t *buf;
    size_t len, k;
    int rc;

    buf = message(&len, MAXLEN);
    __CPROVER_assume(len % PIM_ENCODE_SRC_ADDR_LEN == 0);
    srcs.p    = buf;
    srcs.left = len;
    memset(&jp, 0, sizeof(jp));

    rc = pim_parse_jp_srcs(&srcs, &jp);
    k = nondet_size_t();
    __CPROVER_assume(k < len / PIM_ENCODE_SRC_ADDR_LEN);
    if (rc == PIM_JP_OK)
	__CPROVER_assert(buf[k * 8] == ADDRF_IPv4 && buf[k * 8 + 1] == ADDRT_IPv4 &&
			 buf[k * 8 + 3] == SINGLE_SRC_MSKLEN,
			 "every source taken is an IPv4 host");
    else
	__CPROVER_assert(rc == PIM_JP_SRC_FAMILY || rc == PIM_JP_SRC_MASKLEN,
			 "a source list ends in a verdict");
    free(buf);
}

void proof_jp_group(void)
{
    pim_jp_grp_t g;
    const uint8_t *next;
    uint8_t *buf;
    size_t len, off;

    buf = message(&len, DATAGRAM_MAX);
    off = nondet_size_t();
    __CPROVER_assume(off <= len && len - off >= PIM_JP_GRP_SET_LEN);
    __CPROVER_assume(((size_t)be16(buf + off + 8) + be16(buf + off + 10)) * 8 <=
		     len - off - PIM_JP_GRP_SET_LEN);

    next = pim_jp_group(buf + off, &g);
    __CPROVER_assert(memcmp(&g.group, buf + off + 4, 4) == 0 && g.masklen == buf[off + 3],
		     "the group and its mask are the Encoded-Group's");
    __CPROVER_assert(g.num_j == be16(buf + off + 8) && g.num_p == be16(buf + off + 10),
		     "the counts follow it");
    __CPROVER_assert(g.srcs == buf + off + PIM_JP_GRP_SET_LEN &&
		     next == g.srcs + ((size_t)g.num_j + g.num_p) * 8 && next <= buf + len,
		     "and the next set is behind the sources, inside the message");
    free(buf);
}

void proof_jp_source(void)
{
    pim_jp_grp_t g;
    pim_jp_src_t e;
    uint8_t *buf;
    size_t len, off;
    uint32_t i;

    buf = message(&len, DATAGRAM_MAX);
    off = nondet_size_t();
    g.num_j = nondet_uint16_t();
    g.num_p = nondet_uint16_t();
    i = nondet_uint32_t();
    __CPROVER_assume(off <= len && ((size_t)g.num_j + g.num_p) * 8 <= len - off);
    __CPROVER_assume(i < (uint32_t)g.num_j + g.num_p);
    g.srcs = buf + off;

    pim_jp_source(&g, i, &e);
    __CPROVER_assert(e.flags == g.srcs[(size_t)i * 8 + 2] && e.masklen == g.srcs[(size_t)i * 8 + 3] &&
		     memcmp(&e.addr, g.srcs + (size_t)i * 8 + 4, 4) == 0,
		     "entry i is the eight bytes at i, flags, mask and address");
    free(buf);
}

void proof_jp(void)
{
    const uint8_t *set;
    pim_jp_grp_t g;
    pim_jp_src_t e;
    pim_jp_t jp;
    uint8_t *buf, n;
    size_t len;
    uint32_t i;
    int rc;

    buf = message(&len, MAXLEN);
    rc = pim_parse_jp(buf, len, &jp);
    if (rc != PIM_JP_OK) {
	free(buf);
	return;
    }

    /* What receive_pim_join_prune() does with it, in its two passes */
    set = jp.groups;
    for (n = jp.num_groups; n > 0; n--) {
	set = pim_jp_group(set, &g);
	__CPROVER_assert(set <= buf + len, "every set the header counts is inside the message");
	__CPROVER_assert(g.masklen <= PIM_MAX_MSKLEN, "and its mask can be converted");
	if ((uint32_t)g.num_j + g.num_p > 0) {
	    i = nondet_uint32_t();
	    __CPROVER_assume(i < (uint32_t)g.num_j + g.num_p);
	    pim_jp_source(&g, i, &e);
	    __CPROVER_assert(e.masklen == SINGLE_SRC_MSKLEN, "and every source is a host");
	}
    }
    free(buf);
}

void proof_bsr_hdr(void)
{
    struct pim_cursor c;
    pim_bsr_t bsr;
    uint8_t *buf;
    size_t len;
    int rc;

    buf = message(&len, DATAGRAM_MAX);
    memset(&bsr, 0, sizeof(bsr));
    rc = pim_parse_bsr_hdr(&c, buf, len, &bsr);

    if (len < PIM_BOOTSTRAP_MINLEN) {
	__CPROVER_assert(rc == PIM_BSR_SHORT, "a message without a header is refused");
    } else if (rc == PIM_BSR_OK) {
	__CPROVER_assert(bsr.frag_tag == be16(buf + 4) && bsr.hash_masklen == buf[6] &&
			 bsr.priority == buf[7], "tag, hash mask and priority are bytes 4 to 7");
	__CPROVER_assert(bsr.hash_masklen <= PIM_MAX_MSKLEN, "and the hash mask can be converted");
	__CPROVER_assert(buf[8] == ADDRF_IPv4 && buf[9] == ADDRT_IPv4 &&
			 memcmp(&bsr.bsr, buf + 10, 4) == 0, "the BSR is an IPv4 address at 8");
	__CPROVER_assert(bsr.no_forward == (buf[1] & PIM_BOOTSTRAP_NO_FORWARD),
			 "No-Forward is the top bit of the reserved byte");
	__CPROVER_assert(c.p == buf + PIM_BOOTSTRAP_MINLEN && bsr.sets == c.p &&
			 c.p + c.left == buf + len, "the cursor covers the rest of the message");
    } else {
	__CPROVER_assert(rc == PIM_BSR_FAMILY || rc == PIM_BSR_HASH_MASKLEN,
			 "a header ends in a verdict");
    }
    free(buf);
}

void proof_bsr_set(void)
{
    struct pim_cursor c, before;
    pim_bsr_t bsr;
    uint8_t *buf;
    size_t len, off;
    int rc;

    buf = message(&len, DATAGRAM_MAX);
    off = nondet_size_t();
    __CPROVER_assume(off <= len && len - off >= PIM_BSR_GRP_SET_LEN + PIM_BSR_RP_LEN);
    c.p    = buf + off;
    c.left = len - off;
    before = c;
    memset(&bsr, 0, sizeof(bsr));

    rc = pim_parse_bsr_set(&c, &bsr);
    __CPROVER_assert(c.p + c.left == buf + len, "the cursor stays on the message");
    if (rc == PIM_BSR_OK) {
	__CPROVER_assert(before.p[3] <= PIM_MAX_MSKLEN, "the group mask can be converted");
	__CPROVER_assert(before.p[0] == ADDRF_IPv4 && before.p[1] == ADDRT_IPv4, "the group is IPv4");
	__CPROVER_assert(c.p == before.p + PIM_BSR_GRP_SET_LEN + (size_t)before.p[9] * PIM_BSR_RP_LEN,
			 "the next set is behind the fragment's RP records");
    } else {
	__CPROVER_assert(rc == PIM_BSR_GRP_MASKLEN || rc == PIM_BSR_GRP_FAMILY ||
			 rc == PIM_BSR_TRUNCATED, "a set ends in a verdict");
	__CPROVER_assert(c.p == before.p, "and a refusal moves nothing");
    }
    free(buf);
}

void proof_bsr_group(void)
{
    pim_bsr_grp_t g;
    const uint8_t *next;
    uint8_t *buf;
    size_t len, off;

    buf = message(&len, DATAGRAM_MAX);
    off = nondet_size_t();
    __CPROVER_assume(off <= len && len - off >= PIM_BSR_GRP_SET_LEN);
    __CPROVER_assume((size_t)buf[off + 9] * PIM_BSR_RP_LEN <= len - off - PIM_BSR_GRP_SET_LEN);

    next = pim_bsr_group(buf + off, &g);
    __CPROVER_assert(g.grp.addr_family == buf[off] && g.grp.masklen == buf[off + 3] &&
		     memcmp(&g.grp.mcast_addr, buf + off + 4, 4) == 0,
		     "the Encoded-Group is the first eight bytes");
    __CPROVER_assert(g.rp_count == buf[off + 8] && g.frag_rp_count == buf[off + 9],
		     "the counts follow it");
    __CPROVER_assert(g.rps == buf + off + PIM_BSR_GRP_SET_LEN &&
		     next == g.rps + (size_t)g.frag_rp_count * PIM_BSR_RP_LEN && next <= buf + len,
		     "and the next set is behind the fragment's records, inside the message");
    free(buf);
}

void proof_bsr_rp(void)
{
    pim_bsr_grp_t g;
    pim_bsr_rp_t r;
    uint8_t *buf, i;
    size_t len, off;

    buf = message(&len, DATAGRAM_MAX);
    off = nondet_size_t();
    memset(&g, 0, sizeof(g));
    g.frag_rp_count = nondet_uint8_t();
    i = nondet_uint8_t();
    __CPROVER_assume(off <= len && (size_t)g.frag_rp_count * PIM_BSR_RP_LEN <= len - off);
    __CPROVER_assume(i < g.frag_rp_count);
    g.rps = buf + off;

    pim_bsr_rp(&g, i, &r);
    __CPROVER_assert(memcmp(&r.addr, g.rps + (size_t)i * 10 + 2, 4) == 0 &&
		     r.holdtime == be16(g.rps + (size_t)i * 10 + 6) &&
		     r.priority == g.rps[(size_t)i * 10 + 8],
		     "record i is the ten bytes at i: address, holdtime, priority");
    free(buf);
}

void proof_bsr(void)
{
    const uint8_t *set;
    pim_bsr_grp_t g;
    pim_bsr_rp_t r;
    pim_bsr_t bsr;
    uint8_t *buf, i;
    size_t len;
    unsigned n;

    buf = message(&len, MAXLEN);
    if (pim_parse_bsr(buf, len, &bsr) != PIM_BSR_OK) {
	free(buf);
	return;
    }

    /* What receive_pim_bootstrap() does with it */
    set = bsr.sets;
    for (n = 0; n < bsr.num_sets; n++) {
	set = pim_bsr_group(set, &g);
	__CPROVER_assert(set <= buf + len, "every set walked is inside the message");
	__CPROVER_assert(g.grp.masklen <= PIM_MAX_MSKLEN && g.grp.addr_family == ADDRF_IPv4 &&
			 g.grp.encod_type == ADDRT_IPv4, "and was checked");
	if (g.frag_rp_count > 0) {
	    i = nondet_uint8_t();
	    __CPROVER_assume(i < g.frag_rp_count);
	    pim_bsr_rp(&g, i, &r);
	}
    }
    __CPROVER_assert((size_t)(set - buf) + PIM_BSR_GRP_SET_LEN + PIM_BSR_RP_LEN > len,
		     "and the walk stops only where no whole set is left");
    free(buf);
}

void proof_crp(void)
{
    pim_encod_grp_addr_t grp;
    pim_crp_t crp;
    uint8_t *buf, i;
    size_t len;
    int rc;

    buf = message(&len, DATAGRAM_MAX);
    rc = pim_parse_crp(buf, len, &crp);

    if (len < PIM_CAND_RP_ADV_MINLEN) {
	__CPROVER_assert(rc == PIM_CRP_SHORT, "a message without a header is refused");
    } else if (rc == PIM_CRP_OK) {
	__CPROVER_assert(crp.prefix_cnt == buf[4] && crp.priority == buf[5] &&
			 crp.holdtime == be16(buf + 6), "count, priority and holdtime are bytes 4 to 7");
	__CPROVER_assert(buf[8] == ADDRF_IPv4 && buf[9] == ADDRT_IPv4 &&
			 memcmp(&crp.rp, buf + 10, 4) == 0, "the RP is an IPv4 address at 8");
	__CPROVER_assert(crp.prefixes == buf + PIM_CAND_RP_ADV_MINLEN && crp.num_prefixes <= crp.prefix_cnt &&
			 (size_t)crp.num_prefixes * PIM_ENCODE_GRP_ADDR_LEN <= len - PIM_CAND_RP_ADV_MINLEN,
			 "no more prefixes than the count claims and the message holds");
	__CPROVER_assert(crp.num_prefixes == crp.prefix_cnt ||
			 ((size_t)crp.num_prefixes + 1) * PIM_ENCODE_GRP_ADDR_LEN > len - PIM_CAND_RP_ADV_MINLEN,
			 "and fewer only where the next one does not fit");
	if (crp.num_prefixes > 0) {
	    i = nondet_uint8_t();
	    __CPROVER_assume(i < crp.num_prefixes);
	    pim_crp_prefix(&crp, i, &grp);
	    __CPROVER_assert(grp.masklen == crp.prefixes[(size_t)i * 8 + 3] &&
			     memcmp(&grp.mcast_addr, crp.prefixes + (size_t)i * 8 + 4, 4) == 0,
			     "prefix i is the eight bytes at i");
	}
    } else {
	__CPROVER_assert(rc == PIM_CRP_FAMILY, "a header ends in a verdict");
    }
    free(buf);
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "cc-mode"
 * End:
 */
