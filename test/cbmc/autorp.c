/*
 * autorp.c - prove src/autorp_parse.c over every message up to a length
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
 * SOURCE naming src/autorp_parse.c or a mutant of it, which this file
 * includes so that the static step function is in reach.  Three proofs,
 * each an entry point given to cbmc --function:
 *
 *   proof_hdr   autorp_parse_hdr(), for any datagram
 *   proof_step  autorp_parse_step(), from any cursor on any datagram
 *   proof_next  autorp_parse_next(), the loop over the step, for every
 *               message up to MAXLEN bytes
 *
 * The first two have no loop, so the length they cover is every length a
 * UDP payload can have and not a bound picked for speed; the third is
 * bounded because a loop has to be unwound, and what it has to show is
 * only what the loop adds, the step being proven already.  Walking whole
 * messages instead -- the first version of this file -- took 5m19s at 64
 * bytes and four times longer per doubling.
 *
 * Every buffer is allocated at exactly its length, so a read one byte past
 * it is a bounds violation rather than a read of the next field, and its
 * bytes and length are nondeterministic: what CBMC answers is whether *any*
 * input breaks one of the assertions below or the ones it adds itself
 * (bounds, pointer, overflow, shift, conversion).  Beside memory safety,
 * they are the contract accept_autorp() relies on:
 *
 *   - the header is refused if and only if the buffer cannot hold one, and
 *     the cursor it opens covers the rest of the buffer exactly;
 *   - a step never takes the cursor off the buffer: p + left stays its end;
 *   - a prefix is the six bytes the cursor just stepped over, decoded the
 *     way sec. 4 lays them out, so the fields are the message's and not
 *     some other offset's;
 *   - a step that is not a verdict consumes six bytes, so the walk ends,
 *     and every block it opens or prefix it yields is counted down;
 *   - DONE and SHORT stay put however often they are asked again.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include SOURCE

#ifndef MAXLEN
#define MAXLEN 32
#endif

/* The largest payload a UDP datagram can carry, which bounds what reaches
 * accept_autorp() whatever the socket buffer is. */
#define DATAGRAM_MAX 65507

size_t nondet_size_t(void);
unsigned nondet_unsigned(void);
uint32_t nondet_uint32_t(void);

/* A buffer of exactly *len bytes, *len anything up to max, bytes unknown */
static uint8_t *message(size_t *len, size_t max)
{
    uint8_t *buf;

    *len = nondet_size_t();
    __CPROVER_assume(*len <= max);
    buf = malloc(*len);
    __CPROVER_assume(buf != NULL);

    return buf;
}

/* A cursor anywhere on buf, with counts a header and an RP block can make */
static void anywhere(struct autorp_cursor *c, uint8_t *buf, size_t len)
{
    size_t off = nondet_size_t();

    __CPROVER_assume(off <= len);
    c->p       = buf + off;
    c->left    = len - off;
    c->rpcnt   = nondet_unsigned();
    c->grpcnt  = nondet_unsigned();
    c->rp_addr = nondet_uint32_t();
    __CPROVER_assume(c->rpcnt <= 255 && c->grpcnt <= 255);
}

void proof_hdr(void);
void proof_step(void);
void proof_next(void);

void proof_hdr(void)
{
    struct autorp_cursor cur;
    struct autorp_hdr hdr;
    uint8_t *buf;
    size_t len;

    buf = message(&len, DATAGRAM_MAX);
    if (autorp_parse_hdr(&cur, &hdr, buf, len)) {
	__CPROVER_assert(len < AUTORP_HDR_LEN, "a header that fits is taken");
    } else {
	__CPROVER_assert(len >= AUTORP_HDR_LEN, "a header that does not fit is refused");
	__CPROVER_assert(cur.p == buf + AUTORP_HDR_LEN && cur.p + cur.left == buf + len,
			 "the cursor covers the rest of the buffer");
	__CPROVER_assert(cur.rpcnt == buf[1] && hdr.rpcnt == buf[1] && cur.grpcnt == 0,
			 "the RP count is the second byte, and no block is open");
	__CPROVER_assert(hdr.version == (unsigned)(buf[0] >> 4) &&
			 hdr.type == (unsigned)(buf[0] & 0x0f),
			 "version and type are the two nibbles of the first byte");
	__CPROVER_assert(hdr.holdtime == (uint16_t)((buf[2] << 8) | buf[3]),
			 "the holdtime is bytes 2 and 3, network order");
    }
    free(buf);
}

void proof_step(void)
{
    struct autorp_wire_prefix pfx;
    struct autorp_cursor cur, before;
    uint8_t *buf;
    size_t len;
    int rc;

    buf = message(&len, DATAGRAM_MAX);
    anywhere(&cur, buf, len);
    before = cur;

    rc = autorp_parse_step(&cur, &pfx);
    __CPROVER_assert(cur.p + cur.left == buf + len, "the cursor stays on the buffer");

    switch (rc) {
    case AUTORP_PARSE_PREFIX:
	__CPROVER_assert(before.grpcnt > 0, "a prefix belongs to an open block");
	__CPROVER_assert(cur.left + AUTORP_GRP_LEN == before.left, "a prefix is six bytes");
	__CPROVER_assert(pfx.negative == (cur.p[-6] & 1), "the N bit is the low bit");
	__CPROVER_assert(pfx.masklen == cur.p[-5], "the mask length follows it");
	__CPROVER_assert(memcmp(&pfx.group_addr, cur.p - 4, 4) == 0,
			 "the group is the last four bytes");
	__CPROVER_assert(pfx.rp_addr == before.rp_addr, "the RP is the block's");
	__CPROVER_assert(cur.grpcnt == before.grpcnt - 1 && cur.rpcnt == before.rpcnt,
			 "a prefix counts down its block");
	break;

    case AUTORP_PARSE_BLOCK:
	__CPROVER_assert(before.grpcnt == 0 && before.rpcnt > 0,
			 "a block opens once the last one is done, and only if announced");
	__CPROVER_assert(cur.left + AUTORP_RP_LEN == before.left, "an RP block is six bytes");
	__CPROVER_assert(memcmp(&cur.rp_addr, cur.p - 6, 4) == 0, "the RP is its first four");
	__CPROVER_assert(cur.grpcnt == cur.p[-1], "the group count is its last byte");
	__CPROVER_assert(cur.rpcnt == before.rpcnt - 1, "a block opened is a block counted");
	break;

    case AUTORP_PARSE_DONE:
	__CPROVER_assert(before.rpcnt == 0 && before.grpcnt == 0,
			 "done means every block was read");
	/* fall through */
    case AUTORP_PARSE_SHORT_RP:
    case AUTORP_PARSE_SHORT_GRP:
	__CPROVER_assert(cur.p == before.p && cur.left == before.left &&
			 cur.rpcnt == before.rpcnt && cur.grpcnt == before.grpcnt &&
			 cur.rp_addr == before.rp_addr, "a verdict consumes nothing");
	break;

    default:
	__CPROVER_assert(0, "a step ends in a prefix, a block or a verdict");
    }
    free(buf);
}

void proof_next(void)
{
    struct autorp_wire_prefix pfx;
    struct autorp_cursor cur, before;
    uint8_t *buf;
    size_t len;
    int rc;

    buf = message(&len, MAXLEN);
    anywhere(&cur, buf, len);

    rc = autorp_parse_next(&cur, &pfx);
    __CPROVER_assert(cur.p + cur.left == buf + len, "the cursor stays on the buffer");

    if (rc != AUTORP_PARSE_PREFIX) {
	__CPROVER_assert(rc == AUTORP_PARSE_DONE || rc == AUTORP_PARSE_SHORT_RP ||
			 rc == AUTORP_PARSE_SHORT_GRP, "the loop ends in a verdict");
	before = cur;
	__CPROVER_assert(autorp_parse_next(&cur, &pfx) == rc, "the verdict is asked again");
	__CPROVER_assert(cur.p == before.p && cur.left == before.left, "and consumes nothing");
    }
    free(buf);
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "cc-mode"
 * End:
 */
