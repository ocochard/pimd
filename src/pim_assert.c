/*
 * pim_assert.c - the Assert decisions of RFC 7761 sec. 4.6 that read no state
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
 * Every Assert election pimd holds comes down to the comparison here, and
 * the state machines of src/pim_proto.c around it decide what to do with
 * the answer.  It includes libc and pimd.h and nothing else of the
 * daemon's, so that test/cbmc/assert.c can prove it alone against the
 * order sec. 4.6.3 writes down.
 */

#include <stdint.h>
#include <sys/types.h>
#include <netinet/in.h>

#include "pimd.h"

/*
 * Does the local metric beat the remote one?  Sec. 4.6.3 compares the
 * rpt_bit_flag, the metric_preference and the route_metric in that order,
 * the first lower value winning, and breaks a tie on the primary IP
 * address, the higher one winning.  The RPT bit travels as the top bit of
 * the preference, which makes the first two fields one 32-bit comparison.
 * Addresses are in network order, as pimd keeps them.  Returns 1 (TRUE)
 * where the local metric wins and 0 (FALSE) where it does not, which is
 * also the answer for two equal metrics from the same address.
 */
int compare_metrics(uint32_t local_preference, uint32_t local_metric, uint32_t local_address,
		    uint32_t remote_preference, uint32_t remote_metric, uint32_t remote_address)
{
    if (remote_preference > local_preference)
	return 1;

    if (remote_preference < local_preference)
	return 0;

    if (remote_metric > local_metric)
	return 1;

    if (remote_metric < local_metric)
	return 0;

    if (ntohl(local_address) > ntohl(remote_address))
	return 1;

    return 0;
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "cc-mode"
 * End:
 */
