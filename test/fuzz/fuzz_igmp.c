/*
 * fuzz_igmp - the IGMP parsers and the kernel upcall path, one packet per call
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
 * The other socket pimd reads, and three parsers behind it rather than one:
 *
 *   - IGMP itself, igmp_proto.c, which is what any host on a LAN can send a
 *     router whether or not it is asked to.  The v3 membership report is the
 *     one with a walk in it -- a record count off the wire, a source count
 *     per record, both of them the sender's to choose -- and
 *     IGMP_MAX_SOURCES, the one resource cap doc/rfc7761-compliance.md's A4
 *     entry credits pimd with, is enforced in the middle of it.
 *
 *   - mtrace, trace.c, reached by an IGMP type of its own.  The copy bound
 *     in commit 0e7e7bc was there, a request copied into a fixed buffer
 *     before its length was checked rather than after.
 *
 *   - and the kernel upcall path of route.c, which is not a parser at all
 *     and is the most interesting of the three.  An upcall arrives on this
 *     same socket with an IP protocol of zero, and accept_igmp() hands it to
 *     process_kernel_call(), which reads the buffer as a struct igmpmsg.
 *     V5 and V6 of doc/rfc7761-compliance.md are both there: an upcall read
 *     for more than had been delivered, and a vif index out of it used to
 *     subscript uvifs[] before it was bounded.  Fuzzing it means saying
 *     things the kernel would not say, which is the point -- those two were
 *     found by reading, and what a reader can miss is precisely what a
 *     fuzzer is for.
 *
 * The input is one IP packet, from the IP header on, which is what the
 * daemon is handed: accept_igmp() reads ip_p to tell an upcall from a
 * message and ip_hl to find the IGMP header, and the upcall path reads the
 * same bytes as a structure of its own.  Synthesizing the IP header the way
 * fuzz_pim.c does would put both of those out of reach, so here the header is
 * the input's, and two things are done to the packet before it goes in (a
 * third, poisoning the receive buffer past the end of it so that an over-read
 * is a report rather than a read of stale bytes, belongs to fuzz/router.c and
 * is the whole reason a bug of V5's shape is findable here at all):
 *
 *   - The IGMP checksum is computed last, over the IP data field, the same
 *     way and for the same reason `pimsend -x` recomputes a PIM one: every
 *     message dies at the checksum test in accept_igmp() otherwise, and one
 *     mutant in 65536 reaching a parser is a fuzzer measuring a checksum.
 *     It is skipped where accept_igmp() would not get that far anyway -- a
 *     header that does not fit, an IP data field shorter than IGMP_MINLEN --
 *     and skipped for an upcall, which carries no checksum at all, so those
 *     refusals are reachable rather than papered over.
 *
 *   - The interface the packet arrived on comes from the ToS byte, which
 *     accept_igmp() ignores: its low bit picks one of the two interfaces of
 *     fuzz/topology.h.  That matters because accept_membership_query() and
 *     its kind resolve the vif as find_vif(ifi) first and find_vif_direct(src)
 *     only if that fails, so a report whose source is on one subnet and
 *     whose ifindex is the other -- which a router on a bridged LAN does see
 *     -- is a case only an input that can say both reaches.
 *
 * Everything else is fuzz/router.c: the same two interfaces, three
 * neighbors, RP set, (*,G) and (S,G) that fuzz_pim.c gets, built and torn
 * down per input.  It is not decoration here either.  An IGMP report on an
 * interface pimd has no vif for goes nowhere; a membership that is accepted
 * calls add_leaf(), which reaches find_route() and the RP set behind it; and
 * a v3 report for a group in the SSM range takes a different path from one
 * outside it, which is why the default 232.0.0.0/8 range the configuration
 * leaves in place is part of the state.
 *
 * Running it:
 *
 *   ./configure --enable-fuzz CC=clang				\
 *       CFLAGS="-g -O1 -fno-omit-frame-pointer -fno-strict-aliasing	\
 *               -fsanitize=address,undefined"			\
 *       LDFLAGS="-fsanitize=address,undefined"
 *   make
 *   mkdir work
 *   test/fuzz_igmp -max_len=512 work test/fuzz/corpus/igmp
 *
 * The scratch directory first: libFuzzer writes what it keeps into the first
 * corpus directory it is given, and the committed one holds seeds and
 * crashers rather than a hunt's output.
 *
 * A crash leaves its input in crash-<sha1>.  Replay it with
 *
 *   test/fuzz_igmp_replay crash-<sha1>
 *
 * which is the same harness with a main() instead of a fuzzer, and commit it
 * into corpus/igmp/ so that `make check` replays it everywhere from then on.
 * `igmpv3 -o FILE` writes inputs of this shape, and FUZZ_DEBUG=1 says
 * whether one reached a parser; test/fuzz/README.md has both.
 */

#include "defs.h"

#include "router.h"
#include "topology.h"

/*
 * Longer than this is padding: a v3 report that says everything it can say
 * about a handful of groups fits, and the record walk is reached by the
 * counts in the records rather than by the length of the packet.
 */
#define FUZZ_MAX_SIZE	4096

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/*
 * The IGMP checksum, in place and last, where accept_igmp() will look for
 * it: over the IP data field, which is what inet_cksum() is given there.
 * Anything this cannot place it in is left alone -- the packet is then one
 * accept_igmp() refuses before the checksum test, which is a path worth
 * having.
 */
static void fuzz_igmp_cksum(uint8_t *pkt, size_t size)
{
	struct ip *ip = (struct ip *)pkt;
	size_t iphdrlen, ipdatalen;
	uint8_t *igmp;
	uint16_t sum;

	if (size < sizeof(struct ip) || ip->ip_p == 0)
		return;

	iphdrlen = (size_t)ip->ip_hl << 2;
	if (iphdrlen < sizeof(struct ip) || iphdrlen > size)
		return;

	ipdatalen = size - iphdrlen;
	if (ipdatalen < IGMP_MINLEN)
		return;

	igmp = pkt + iphdrlen;
	igmp[2] = 0;
	igmp[3] = 0;

	sum = inet_cksum((uint16_t *)igmp, ipdatalen);
	memcpy(igmp + 2, &sum, sizeof(sum));
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;

	fuzz_router_init("fuzz_igmp");

	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint8_t pkt[FUZZ_MAX_SIZE];
	int ifi;

	if (size > sizeof(pkt))
		return 0;

	memcpy(pkt, data, size);

	/* The ToS byte, which accept_igmp() ignores: which interface the
	 * kernel said this arrived on.  Absent one, the first.
	 */
	ifi = (size > 1 && (pkt[1] & 0x01)) ? FUZZ_VIF1 : FUZZ_VIF0;

	fuzz_igmp_cksum(pkt, size);

	fuzz_router_reset();
	fuzz_router_build();

	/* Where igmp_read() hands it over, buffer and all, and with the end
	 * of the packet poisoned so that a parser reading past it is a report
	 * rather than a read of whatever the last input left there
	 */
	fuzz_buf_load(igmp_recv_buf, pkt, size);
	accept_igmp(ifi, (ssize_t)size);

	/* Not only for tidiness: a membership this packet created, and the
	 * routing entry under it, have to go before the next input
	 */
	fuzz_router_reset();

	return 0;
}
