/*
 * fuzz_pim - the PIM message parsers, one message per call
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
 * These are the parsers that matter: the seven receive_pim_*() of
 * src/pim_proto.c walk a buffer somebody else filled in, on a router that
 * has to answer PIM from anyone who can reach it.  It is where the bug
 * fixed in src/pim_proto.c was -- receive_pim_assert() parsing 26 bytes out
 * of a message src/pim.c guarantees four of -- and where V1 of
 * doc/rfc7761-compliance.md was, an unbounded parse in
 * receive_pim_register_stop().  Two things already put wrong messages in
 * front of them, and neither scales: the `crafted` scenario of test/lab.sh
 * asserts what a named field being wrong must do, one assertion at a time,
 * and the `fuzz` scenario floods a running daemon with five hundred mutants
 * per type over a real network, which takes jails, root, a kernel and
 * minutes.  This is the same question asked tens of thousands of times a
 * second, with no network, no privileges and no kernel, and with the
 * sanitizers as the verdict: build it -fsanitize=address,undefined or a
 * clean run only proves the parsers do not segfault.
 *
 * The input is one PIM message, from the PIM header on, and nothing else.
 * That is deliberate: it is exactly what `pimsend -b FILE` puts on the wire
 * and what `pimsend -o FILE` writes out, so a crasher found here can be
 * sent at a live daemon and a mutant that killed a daemon in a lab can be
 * committed here, byte for byte.  What the harness supplies around it is
 * the IP header, whose fields belong to the kernel and to src/pim.c rather
 * than to the parsers, and the router the message arrives at.
 *
 * That router is fuzz/router.c, over the addresses of fuzz/topology.h: two
 * interfaces, three neighbors and a host that has sent no Hello, an MRIB in
 * fuzz/mrib.c to answer the RPF lookups with, and this pimd.conf --
 *
 *	bsr-candidate 10.0.1.1 priority 5 interval 30
 *	rp-candidate 10.0.1.1 priority 20 interval 30
 *	rp-address 10.0.1.1 224.0.0.0/4
 *	spt-threshold packets 0 interval 100
 *
 * -- parsed by config.c itself rather than poked into the globals, so that
 * every value derived from those four lines is derived the way the daemon
 * derives it.  Neither candidacy is decoration, and router.c says why.
 *
 * Three fields of the message the harness reads rather than passes on:
 *
 *   - The type nibble, to pick a destination address the message may
 *     legally have arrived at.  src/pim.c drops a message whose
 *     destination does not match the table of RFC 7761 sec. 4.9, so
 *     without this most inputs would die there: Hello, Join/Prune and
 *     Assert are given ALL-PIM-ROUTERS and the unicast types this
 *     router's own address.
 *
 *   - The Reserved byte, as the sender.  pimd ignores it -- sec. 4.9 has
 *     it zero on transmission and unexamined on reception -- so borrowing
 *     it costs the parsers nothing and keeps the input a plain PIM
 *     message: its low two bits pick one of the four senders of
 *     fuzz/topology.h, and the next bit sends a Bootstrap to this router
 *     rather than to the group, which is the unicast Bootstrap of RFC 5059
 *     sec. 3.5.2.  On the wire that byte is ignored, so a crasher replayed
 *     with `pimsend -b` reproduces from whichever jail it is sent out of.
 *
 *   - The checksum, which is computed after the mutation rather than
 *     before, for the reason `pimsend -x` does the same: every
 *     receive_pim_*() opens with inet_cksum() over the whole message, so
 *     one mutant in 65536 would reach a parser at all and the rest would
 *     measure a checksum.  A Register is checksummed over its header
 *     alone, sec. 4.9.3, which is also how pimd verifies one.  The
 *     checksum test itself is what `crafted` asserts.
 *
 * So what this harness cannot see is what the four bytes before the body
 * do: a bad checksum, a version that is not 2, a type nobody defined, a
 * message at the wrong destination.  Those are one comparison each in
 * src/pim.c, all four are asserted by `crafted`, and the whole packet
 * format section of doc/rfc7761-compliance.md is about them.  What it can
 * see is everything after them.
 *
 * One message per call, on state built by the same code path: fuzz/router.c
 * tears the router down and builds it again between inputs, ending in a
 * prologue of five messages -- a Hello from each neighbor, then a Join(*,G)
 * and a Join(S,G) from the one on the second link -- so that an input lands
 * on a router with neighbors, a DR, an RP set, a (*,G) with an outgoing
 * interface and an (S,G) of its own rather than on an empty table.  A bug
 * that needs two attacker-supplied messages in a row is therefore out of
 * reach here and wants a harness whose input is a sequence; that is a second
 * harness, and it would give up the round trip with pimsend that this one
 * has.
 *
 * Running it:
 *
 *   ./configure --enable-fuzz CC=clang				\
 *       CFLAGS="-g -O1 -fno-omit-frame-pointer -fno-strict-aliasing	\
 *               -fsanitize=address,undefined"			\
 *       LDFLAGS="-fsanitize=address,undefined"
 *   make
 *   mkdir work
 *   test/fuzz_pim -max_len=512 work test/fuzz/corpus/pim
 *
 * The scratch directory first: libFuzzer writes what it keeps into the first
 * corpus directory it is given, and the committed one holds seeds and
 * crashers rather than a hunt's output.
 *
 * A crash leaves its input in crash-<sha1>.  Replay it with
 *
 *   test/fuzz_pim_replay crash-<sha1>
 *
 * which is the same harness with a main() instead of a fuzzer, put it on
 * the wire with `pimsend -i ADDR hello -b crash-<sha1>` if it is worth
 * seeing a real daemon do it, then commit it into corpus/pim/ so that
 * `make check` replays it everywhere from then on.
 */

#include "defs.h"

#include "router.h"
#include "topology.h"

/*
 * A PIM message longer than this is padding as far as the parsers are
 * concerned: the longest one that says anything is a Join/Prune or a
 * Bootstrap with every group set it can hold, and libFuzzer spends its time
 * in memcpy() rather than in pim_proto.c.
 */
#define FUZZ_MAX_SIZE	4096

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;

	fuzz_router_init("fuzz_pim");

	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint8_t msg[FUZZ_MAX_SIZE];
	unsigned sender, type;
	uint32_t dst;

	if (size > sizeof(msg))
		return 0;

	memcpy(msg, data, size);

	/* Shorter than a PIM header is a message too, and the one accept_pim()
	 * refuses on the length of the IP data field rather than on anything
	 * in it, so those go in as they come: everything below reads only
	 * bytes that arrived.
	 *
	 * The Reserved byte, which pimd ignores, says who the message is from
	 * and where a Bootstrap was addressed.
	 */
	sender = size > 1 ? msg[1] & 0x03 : 0;
	type   = size > 0 ? msg[0] & 0x0f : PIM_HELLO;

	switch (type) {
		case PIM_HELLO:
		case PIM_JOIN_PRUNE:
		case PIM_ASSERT:
			dst = allpimrouters_group;
			break;

		case PIM_BOOTSTRAP:
			/* Both destinations are legal for this one, RFC 5059
			 * sec. 3.5.2 being why */
			dst = (size > 1 && (msg[1] & 0x04)) ? htonl(FUZZ_IF0_ADDR)
							    : allpimrouters_group;
			break;

		default:
			dst = htonl(FUZZ_IF0_ADDR);
			break;
	}

	fuzz_router_reset();
	fuzz_router_build();

	fuzz_pim_feed(htonl(fuzz_senders[sender]), dst, msg, size);

	/* Not only for tidiness: what the message allocated has to go before
	 * the next input, or a leak reads as unbounded growth
	 */
	fuzz_router_reset();

	return 0;
}
