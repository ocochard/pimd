/*
 * igmp.c - prove src/igmp_parse.c over every report up to a length
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
 * SOURCE naming src/igmp_parse.c or a mutant of it.  autorp.c beside it
 * explains the method; the proofs are, each an entry point for --function:
 *
 *   proof_packet    the IP and IGMP headers accept_igmp() is handed, for
 *                   any packet
 *   proof_report    the report header, for any message
 *   proof_record    one group record, from any cursor on any message
 *   proof_source    the source accessor, for any source of any record
 *   proof_walk      a whole report, for messages up to MAXLEN, read back
 *                   the way accept_membership_report() reads it
 *
 * The first three have no loop and cover every length an IP datagram can
 * carry.  Beside memory safety, what they assert is the contract
 * accept_igmp() and accept_membership_report() rely on:
 *
 *   - a packet is read behind its IP header only when the header length
 *     is one a header can have and the packet holds, and behind that only
 *     when an IGMP header fits; a query's version is its length's;
 *   - a record is handed out only when all of it, sources and auxiliary
 *     data, is inside the message, and the next one begins behind it;
 *   - a refusal moves nothing, and every record handed out is counted;
 *   - a source is the four bytes at its index and nothing else.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include SOURCE

#ifndef MAXLEN
#define MAXLEN 32
#endif

#define DATAGRAM_MAX 65515

size_t nondet_size_t(void);
uint16_t nondet_uint16_t(void);
unsigned nondet_unsigned(void);

static uint8_t *message(size_t *len, size_t max)
{
    uint8_t *buf;

    *len = nondet_size_t();
    __CPROVER_assume(*len <= max);
    buf = malloc(*len);
    __CPROVER_assume(buf != NULL);

    return buf;
}

void proof_packet(void);
void proof_report(void);
void proof_record(void);
void proof_source(void);
void proof_walk(void);

void proof_packet(void)
{
    igmp_pkt_t pkt;
    uint8_t *buf;
    size_t len, hlen;
    int rc;

    buf = message(&len, DATAGRAM_MAX);
    rc = igmp_parse_packet(buf, len, &pkt);

    if (len < 20) {
	__CPROVER_assert(rc == IGMP_PKT_SHORT, "a packet without an IP header is refused");
	free(buf);
	return;
    }
    __CPROVER_assert(memcmp(&pkt.src, buf + 12, 4) == 0 && memcmp(&pkt.dst, buf + 16, 4) == 0,
		     "source and destination are the IP header's");
    if (buf[9] == 0) {
	__CPROVER_assert(rc == IGMP_PKT_UPCALL, "protocol zero is the kernel's");
	free(buf);
	return;
    }

    hlen = (size_t)(buf[0] & 0x0f) * 4;
    if (hlen < 20 || hlen > len) {
	__CPROVER_assert(rc == IGMP_PKT_BAD_HLEN, "a header length the packet cannot have is refused");
    } else if (len - hlen < 8) {
	__CPROVER_assert(rc == IGMP_PKT_SHORT_IGMP, "and so is no room for an IGMP header");
    } else {
	__CPROVER_assert(rc == IGMP_PKT_OK && pkt.igmp == buf + hlen && pkt.ipdatalen == len - hlen,
			 "the IGMP message is everything behind the header");
	__CPROVER_assert(pkt.type == buf[hlen] && pkt.code == buf[hlen + 1] &&
			 memcmp(&pkt.group, buf + hlen + 4, 4) == 0,
			 "type, code and group are the IGMP header's");
	__CPROVER_assert(pkt.query_version ==
			 (pkt.ipdatalen == 8 ? (pkt.code == 0 ? 1 : 2) : pkt.ipdatalen >= 12 ? 3 : 0),
			 "a query's version is its length's, RFC 3376 sec. 7.1");
    }
    free(buf);
}

void proof_report(void)
{
    struct igmpv3_cursor c;
    uint16_t ngrec;
    uint8_t *buf, type;
    size_t len;
    int rc;

    buf = message(&len, DATAGRAM_MAX);
    rc = igmpv3_parse_report(buf, len, &c, &type, &ngrec);

    if (len < 8) {
	__CPROVER_assert(rc == IGMPV3_SHORT, "a report without a header is refused");
    } else {
	__CPROVER_assert(rc == IGMPV3_OK && type == buf[0] &&
			 ngrec == (uint16_t)((buf[6] << 8) | buf[7]) && c.ngrec == ngrec,
			 "the type is byte 0 and the record count bytes 6 and 7");
	__CPROVER_assert(c.p == buf + 8 && c.p + c.left == buf + len,
			 "the cursor covers the rest of the report");
    }
    free(buf);
}

void proof_record(void)
{
    struct igmpv3_cursor c, before;
    igmpv3_rec_t rec;
    uint8_t *buf;
    size_t len, off;
    int rc;

    buf = message(&len, DATAGRAM_MAX);
    off = nondet_size_t();
    __CPROVER_assume(off <= len);
    c.p     = buf + off;
    c.left  = len - off;
    c.ngrec = nondet_unsigned();
    __CPROVER_assume(c.ngrec <= 65535);
    before = c;

    rc = igmpv3_parse_record(&c, &rec);
    __CPROVER_assert(c.p + c.left == buf + len, "the cursor stays on the report");

    switch (rc) {
    case IGMPV3_RECORD:
	__CPROVER_assert(before.ngrec > 0 && c.ngrec == before.ngrec - 1, "a record handed out is counted");
	__CPROVER_assert(rec.type == before.p[0] && rec.nsrcs == ((before.p[2] << 8) | before.p[3]) &&
			 memcmp(&rec.group, before.p + 4, 4) == 0,
			 "type, source count and group are the record header's");
	__CPROVER_assert(rec.size == 8 + (size_t)rec.nsrcs * 4 + (size_t)before.p[1] * 4,
			 "a record is its header, its sources and its auxiliary words");
	__CPROVER_assert(rec.srcs == before.p + 8 && c.p == before.p + rec.size &&
			 c.left + rec.size == before.left,
			 "all of it is inside the report, and the next one is behind it");
	break;

    case IGMPV3_DONE:
	__CPROVER_assert(before.ngrec == 0, "done only when every record was read");
	/* fall through */
    case IGMPV3_SHORT_HDR:
    case IGMPV3_SHORT_REC:
	__CPROVER_assert(c.p == before.p && c.left == before.left && c.ngrec == before.ngrec,
			 "a verdict moves nothing");
	if (rc == IGMPV3_SHORT_HDR)
	    __CPROVER_assert(before.left < 8, "only a header that does not fit is short");
	if (rc == IGMPV3_SHORT_REC)
	    __CPROVER_assert(before.left < rec.size, "only a record that does not fit is short");
	break;

    default:
	__CPROVER_assert(0, "a step ends in a record or a verdict");
    }
    free(buf);
}

void proof_source(void)
{
    igmpv3_rec_t rec;
    uint8_t *buf;
    size_t len, off;
    uint16_t i;
    uint32_t addr;

    buf = message(&len, DATAGRAM_MAX);
    off = nondet_size_t();
    rec.nsrcs = nondet_uint16_t();
    i = nondet_uint16_t();
    __CPROVER_assume(off <= len && (size_t)rec.nsrcs * 4 <= len - off && i < rec.nsrcs);
    rec.srcs = buf + off;

    addr = igmpv3_source(&rec, i);
    __CPROVER_assert(memcmp(&addr, rec.srcs + (size_t)i * 4, 4) == 0, "source i is the four bytes at i");
    free(buf);
}

void proof_walk(void)
{
    struct igmpv3_cursor c;
    igmpv3_rec_t rec;
    uint16_t ngrec, i;
    uint8_t *buf, type;
    size_t len;
    int rc;

    buf = message(&len, MAXLEN);
    if (igmpv3_parse_report(buf, len, &c, &type, &ngrec) != IGMPV3_OK) {
	free(buf);
	return;
    }

    while ((rc = igmpv3_parse_record(&c, &rec)) == IGMPV3_RECORD) {
	__CPROVER_assert(rec.srcs + (size_t)rec.nsrcs * 4 <= buf + len,
			 "every source of a record handed out is inside the report");
	if (rec.nsrcs > 0) {
	    i = nondet_uint16_t();
	    __CPROVER_assume(i < rec.nsrcs);
	    (void)igmpv3_source(&rec, i);
	}
    }
    __CPROVER_assert(rc == IGMPV3_DONE || rc == IGMPV3_SHORT_HDR || rc == IGMPV3_SHORT_REC,
		     "the walk ends in a verdict");
    free(buf);
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "cc-mode"
 * End:
 */
