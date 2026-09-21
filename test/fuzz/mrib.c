/*
 * mrib - the unicast routing table a harness answers RPF lookups from
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
 * k_req_incoming() is the one thing the protocol code asks the kernel that
 * a harness cannot leave failing.  Every (S,G) and every RP a message
 * creates goes through set_incoming() (src/route.c), which asks for the
 * path to an address: without an answer the entry gets NO_VIF as its
 * incoming interface and no upstream neighbor, and the far side of every
 * test that reads either -- the assert metrics, the SPT switch, the
 * Join/Prune upstream, the wrong-iif paths -- is unreachable.
 *
 * So this file defines it, and neither netlink.c nor routesock.c is linked:
 * they are members of libpimd.a, and everything outside main.c that
 * references either of them is defined here instead, so a definition here
 * is the one the linker takes and the archive member is never pulled in.
 * Should that stop being true -- a third symbol referenced from outside
 * main.c -- the link fails with a duplicate symbol rather than quietly
 * picking one, which is the failure mode to want, and the fix is to add it
 * below rather than to let the archive member in.
 *
 * kern_routesock() is the second such symbol, and it is here for the link
 * and not for the harness: it is the raw socket half of init_routesock(),
 * which the privileged half of a separated pimd calls so that the
 * unprivileged one needs socket(2) for nothing.  src/privsep.c references
 * it, src/debug.c references src/privsep.c for every log line, and so
 * privsep.o is always pulled in.  Nothing here ever separates privileges,
 * so nothing here ever calls this.
 *
 * What it answers is one small fixed routing table, so the same input gives
 * the same answers on every machine and in CI: the harness's two subnets
 * are directly connected, and everything else is reached through the
 * neighbor on the first of them, which is what a router with a default
 * route through that neighbor sees.  The metric it gives back is the
 * MRIB.metric of RFC 7761 sec. 4.6.3, which is what an assert election
 * compares once the preferences tie, so the two numbers here are one
 * connected route and one that is not.
 */

#include "defs.h"

#include "topology.h"

int kern_routesock(int ifevent)
{
	(void)ifevent;

	/* Not reached: priv_init() is never called in a harness. */
	errno = ENOSYS;

	return -1;
}

int k_req_incoming(uint32_t source, struct rpfctl *rpf)
{
	uint32_t addr = ntohl(source);

	rpf->source.s_addr      = source;
	rpf->iif                = NO_VIF;
	rpf->rpfneighbor.s_addr = INADDR_ANY;
	rpf->metric             = RPF_METRIC_UNKNOWN;

	/* Nothing is routed to a link-local address, which is what the
	 * invented RP of every SSM range is; netlink.c and routesock.c
	 * both refuse it before asking the kernel, so this does too.
	 */
	if (IN_LINK_LOCAL_RANGE(source))
		return FALSE;

	if ((addr & FUZZ_MASK24) == FUZZ_IF0_NET) {
		rpf->iif    = FUZZ_VIF0;
		rpf->metric = FUZZ_METRIC_CONNECTED;

		return TRUE;
	}

	if ((addr & FUZZ_MASK24) == FUZZ_IF1_NET) {
		rpf->iif    = FUZZ_VIF1;
		rpf->metric = FUZZ_METRIC_CONNECTED;

		return TRUE;
	}

	/* The default route: out of the first interface, through the first
	 * of the neighbors the harness installs there.
	 */
	rpf->iif                = FUZZ_VIF0;
	rpf->rpfneighbor.s_addr = htonl(FUZZ_NBR0_ADDR);
	rpf->metric             = FUZZ_METRIC_REMOTE;

	return TRUE;
}
