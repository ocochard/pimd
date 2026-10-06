/*
 * igmp_parse.c - the bytes of an IGMPv3 report, and nothing else
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
 * The decoding half of accept_membership_report() in src/igmp_proto.c,
 * the format of RFC 3376 sec. 4.2.  This file includes libc and igmpv3.h
 * and nothing else of the daemon's, deliberately: test/cbmc/igmp.c
 * compiles it alone and proves it reads nothing outside the buffer.  The
 * fields are read at the offsets of the wire rather than through struct
 * igmpv3_grec, whose 32-bit members a record at an odd offset would leave
 * unaligned.
 *
 * The record count and every source count are the sender's and bound
 * nothing; each step asks the buffer first.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>

#include "igmpv3.h"

#define IGMPV3_REPORT_HDRLEN	8	/* type, reserved, checksum, reserved, count */
#define IGMPV3_REC_HDRLEN	8	/* type, aux len, source count, group */

/* The report header: its type, which accept_group_report() is told, and
 * the record count, and a cursor over the records behind it. */
int igmpv3_parse_report(const void *report, size_t len, struct igmpv3_cursor *c,
			uint8_t *type, uint16_t *ngrec)
{
    const uint8_t *p = report;

    if (len < IGMPV3_REPORT_HDRLEN)
	return IGMPV3_SHORT;

    *type  = p[0];
    *ngrec = (uint16_t)((p[6] << 8) | p[7]);

    c->p     = p + IGMPV3_REPORT_HDRLEN;
    c->left  = len - IGMPV3_REPORT_HDRLEN;
    c->ngrec = *ngrec;

    return IGMPV3_OK;
}

/*
 * The next group record, whole.  RFC 3376 sec. 4.2.6: Aux Data Len is in
 * units of 32-bit words, and the record ends behind it, which is where the
 * next one begins.  A refusal moves nothing, so asked again it says the
 * same.
 */
int igmpv3_parse_record(struct igmpv3_cursor *c, igmpv3_rec_t *rec)
{
    const uint8_t *p = c->p;

    if (c->ngrec == 0)
	return IGMPV3_DONE;

    if (c->left < IGMPV3_REC_HDRLEN)
	return IGMPV3_SHORT_HDR;

    rec->type  = p[0];
    rec->nsrcs = (uint16_t)((p[2] << 8) | p[3]);
    memcpy(&rec->group, p + 4, sizeof(rec->group));
    rec->srcs  = p + IGMPV3_REC_HDRLEN;
    rec->size  = IGMPV3_REC_HDRLEN + (size_t)rec->nsrcs * sizeof(uint32_t) + (size_t)p[1] * 4;

    if (c->left < rec->size)
	return IGMPV3_SHORT_REC;

    c->p     += rec->size;
    c->left  -= rec->size;
    c->ngrec -= 1;

    return IGMPV3_RECORD;
}

/* Source i of a record, i < nsrcs, in network order */
uint32_t igmpv3_source(const igmpv3_rec_t *rec, uint16_t i)
{
    uint32_t addr;

    memcpy(&addr, rec->srcs + (size_t)i * sizeof(uint32_t), sizeof(addr));

    return addr;
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "cc-mode"
 * End:
 */
