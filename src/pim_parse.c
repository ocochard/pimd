/*
 * pim_parse.c - the bytes of PIM messages, and nothing else
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
 * The decoding halves of the receive_pim_*() of src/pim_proto.c, the
 * formats of RFC 7761 sec. 4.9.  This file includes libc and pimd.h and
 * nothing else of the daemon's, deliberately: test/cbmc/pim.c compiles it
 * alone and proves it reads nothing outside the buffer, and a dependency on
 * the daemon's globals would make that proof a model of the daemon instead.
 *
 * Each decoder is a loop-free step and a loop over it, because that is the
 * shape a bounded model checker can afford: a step is proven for a message
 * of any length, and the loop only for a few iterations of it.  Lengths
 * read off the wire bound nothing; every step asks the buffer first.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>

#include "pimd.h"

/* A position in a message, and how much of it is left */
struct pim_cursor {
    const uint8_t *p;
    size_t left;
};

/* What pim_parse_hello_opt() says besides the verdicts of pimd.h */
#define PIM_HELLO_OPT		-1	/* one option read			*/
#define PIM_HELLO_END		-2	/* too little left for another one	*/

/*
 * One Hello option, RFC 7761 sec. 4.9.2.  An option that does not fit in
 * what is left of the message is refused before its value is read, not
 * after; a known option of a length it cannot have refuses the message;
 * an unknown one is stepped over, sec. 4.9.2 "MUST be ignored".  An
 * Address List is only recorded here, the last one heard standing, and
 * checked once the walk is done: the check is a loop of its own, and
 * putting it here would put a loop in the step.
 */
static int pim_parse_hello_opt(struct pim_cursor *c, pim_hello_opts_t *opts)
{
    const uint8_t *data = c->p;
    uint16_t opt_type, opt_len;
    size_t rec_len;

    if (c->left < sizeof(pim_hello_t))
	return PIM_HELLO_END;

    GET_HOSTSHORT(opt_type, data);
    GET_HOSTSHORT(opt_len,  data);

    rec_len = sizeof(pim_hello_t) + opt_len;
    if (c->left < rec_len) {
	opts->bad_type = opt_type;
	opts->bad_len  = opt_len;
	return PIM_HELLO_SHORT;
    }

    switch (opt_type) {
	case PIM_HELLO_HOLDTIME:
	    if (opt_len != PIM_HELLO_HOLDTIME_LEN)
		goto badlen;

	    opts->holdtime_present = 1;
	    GET_HOSTSHORT(opts->holdtime, data);
	    break;

	case PIM_HELLO_DR_PRIO:
	    if (opt_len != PIM_HELLO_DR_PRIO_LEN)
		goto badlen;

	    opts->dr_prio_present = 1;
	    GET_HOSTLONG(opts->dr_prio, data);
	    break;

	case PIM_HELLO_GENID:
	    if (opt_len != PIM_HELLO_GENID_LEN)
		goto badlen;

	    GET_HOSTLONG(opts->genid, data);
	    break;

	case PIM_HELLO_LAN_PRUNE_DELAY: {
	    uint16_t delay;

	    if (opt_len != PIM_HELLO_LAN_PRUNE_DELAY_LEN)
		goto badlen;

	    GET_HOSTSHORT(delay, data);
	    opts->lan_delay_present = 1;
	    opts->tracking_support  = (delay & PIM_LAN_PRUNE_DELAY_T_BIT) ? 1 : 0;
	    opts->propagation_delay = delay & ~PIM_LAN_PRUNE_DELAY_T_BIT;
	    GET_HOSTSHORT(opts->override_interval, data);
	    break;
	}

	case PIM_HELLO_ADDR_LIST:
	    opts->addr_list     = data;
	    opts->addr_list_len = opt_len;
	    break;

	default:
	    break;		/* Ignore any unknown options */
    }

    c->p    += rec_len;
    c->left -= rec_len;

    return PIM_HELLO_OPT;

  badlen:
    opts->bad_type = opt_type;
    opts->bad_len  = opt_len;
    return PIM_HELLO_BADOPTLEN;
}

/*
 * RFC 7761 sec. 4.3.4: every address in the option is of one family.  A
 * list that is not all IPv4, or is not a whole number of IPv4 entries, is
 * not one this router can map a next hop through, and is read as no list
 * at all -- which takes the neighbor's secondaries away rather than keeping
 * ones it no longer advertises.  The Hello itself stands: the option being
 * there is no reason to lose the neighbor.
 */
static void pim_parse_hello_addrs(pim_hello_opts_t *opts)
{
    const uint8_t *data = opts->addr_list;
    uint16_t i;

    if (opts->addr_list_len % PIM_ENCODE_UNI_ADDR_LEN) {
	opts->addr_list_refused = PIM_HELLO_ADDRS_LEN;
	goto refused;
    }

    for (i = 0; i < opts->addr_list_len; i += PIM_ENCODE_UNI_ADDR_LEN) {
	uint8_t family = data[i], etype = data[i + 1];

	if (family != ADDRF_IPv4 || etype != ADDRT_IPv4) {
	    opts->addr_list_refused = PIM_HELLO_ADDRS_FAMILY;
	    opts->bad_family        = family;
	    opts->bad_etype         = etype;
	    goto refused;
	}
    }

    return;

  refused:
    opts->bad_len       = opts->addr_list_len;
    opts->addr_list     = NULL;
    opts->addr_list_len = 0;
}

/*
 * A whole Hello, PIM header included.  RFC 7761 sec. 4.9.2: unknown options
 * "MUST be ignored and MUST NOT prevent a neighbor relationship from being
 * formed", and neither must a Hello that carries no options at all.  Only
 * an option we do understand, arriving with a length it cannot have, or
 * one that runs past the message, fails it; bytes too few to be an option
 * after the last one are ignored.
 */
int pim_parse_hello(const void *msg, size_t len, pim_hello_opts_t *opts)
{
    struct pim_cursor c;
    int rc;

    memset(opts, 0, sizeof(*opts));

    if (len < sizeof(pim_header_t))
	return PIM_HELLO_SHORT;

    c.p    = (const uint8_t *)msg + sizeof(pim_header_t);
    c.left = len - sizeof(pim_header_t);

    while ((rc = pim_parse_hello_opt(&c, opts)) == PIM_HELLO_OPT)
	;

    if (rc != PIM_HELLO_END)
	return rc;

    if (opts->addr_list)
	pim_parse_hello_addrs(opts);

    return PIM_HELLO_OK;
}

/*
 * Entry i of a Hello's Address List, in network order.  The caller asks
 * only for i < addr_list_len / PIM_ENCODE_UNI_ADDR_LEN, which
 * pim_parse_hello() has checked is inside the message and IPv4 throughout.
 */
uint32_t pim_hello_addr(const pim_hello_opts_t *opts, uint16_t i)
{
    const uint8_t *data = opts->addr_list + (size_t)i * PIM_ENCODE_UNI_ADDR_LEN;
    pim_encod_uni_addr_t eua;

    GET_EUADDR(&eua, data);

    return eua.unicast_addr;
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "cc-mode"
 * End:
 */
