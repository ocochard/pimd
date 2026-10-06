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
 *   - pim_hello_addr() reads entry i and nothing else.
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

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "cc-mode"
 * End:
 */
