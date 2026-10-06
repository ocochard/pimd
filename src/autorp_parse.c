/*
 * autorp_parse.c - the bytes of an Auto-RP message, and nothing else
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
 * The decoding half of accept_autorp(), the format of
 * doc/pim-autorp-spec01.txt sec. 4 walked with a cursor.  This file
 * includes libc and autorp.h and nothing of the daemon's, deliberately:
 * test/cbmc/autorp.c compiles it alone and proves it reads nothing outside
 * the buffer, and a dependency on the daemon's globals would make that
 * proof a model of the daemon instead.
 *
 * The counts in the header say how much is supposed to follow and bound
 * nothing.  Every step below asks the buffer first.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "autorp.h"

/*
 * The header, and a cursor over what follows it.  Fails on a buffer too
 * short to hold one, and only then: version and type are the caller's.
 */
int autorp_parse_hdr(struct autorp_cursor *c, struct autorp_hdr *hdr,
		     const void *buf, size_t len)
{
    const uint8_t *p = buf;

    if (len < AUTORP_HDR_LEN)
	return -1;

    hdr->version  = AUTORP_VERSION_OF(p[0]);
    hdr->type     = AUTORP_TYPE_OF(p[0]);
    hdr->rpcnt    = p[1];
    hdr->holdtime = (uint16_t)((p[2] << 8) | p[3]);
    /* p[4..7] reserved, sent as 0 and ignored on reception, sec. 4 */

    c->p       = p + AUTORP_HDR_LEN;
    c->left    = len - AUTORP_HDR_LEN;
    c->rpcnt   = hdr->rpcnt;
    c->grpcnt  = 0;
    c->rp_addr = 0;

    return 0;
}

/* What autorp_parse_step() says besides the verdicts of autorp.h */
#define AUTORP_PARSE_BLOCK	-1	/* an RP block opened, nothing to yield yet */

/*
 * One step of the walk, which reads at most one RP block or one prefix:
 * no loop, so test/cbmc/ proves it for a buffer of any length rather than
 * of every length up to a bound.  autorp_parse_next() is the loop over it.
 */
static int autorp_parse_step(struct autorp_cursor *c, struct autorp_wire_prefix *prefix)
{
    if (c->grpcnt > 0) {
	if (c->left < AUTORP_GRP_LEN)
	    return AUTORP_PARSE_SHORT_GRP;

	prefix->rp_addr  = c->rp_addr;
	prefix->negative = AUTORP_GRP_NEGATIVE(c->p[0]);
	prefix->masklen  = c->p[1];
	memcpy(&prefix->group_addr, c->p + 2, sizeof(prefix->group_addr));

	c->p      += AUTORP_GRP_LEN;
	c->left   -= AUTORP_GRP_LEN;
	c->grpcnt -= 1;

	return AUTORP_PARSE_PREFIX;
    }

    if (c->rpcnt == 0)
	return AUTORP_PARSE_DONE;

    if (c->left < AUTORP_RP_LEN)
	return AUTORP_PARSE_SHORT_RP;

    memcpy(&c->rp_addr, c->p, sizeof(c->rp_addr));
    c->grpcnt = c->p[5];
    /* p[4] holds the RP's PIM version in its low two bits, which pimd has
     * no use for: it speaks PIMv2 and an RP that does not is not one it can
     * register to anyway. */

    c->p     += AUTORP_RP_LEN;
    c->left  -= AUTORP_RP_LEN;
    c->rpcnt -= 1;

    return AUTORP_PARSE_BLOCK;
}

/*
 * The next group prefix, with the RP of the block it is in.  An RP block
 * announcing no prefix is stepped over.  Once it has said DONE or SHORT,
 * it says the same again: nothing is consumed past a block that does not
 * fit.
 */
int autorp_parse_next(struct autorp_cursor *c, struct autorp_wire_prefix *prefix)
{
    int rc;

    while ((rc = autorp_parse_step(c, prefix)) == AUTORP_PARSE_BLOCK)
	;

    return rc;
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "cc-mode"
 * End:
 */
