/*
 * fuzz_autorp - the Auto-RP parser, one datagram per call
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
 * Auto-RP arrives as a UDP datagram from anyone who can reach the group:
 * there is no neighbour relationship behind it, no checksum of its own to
 * pass, and the message says how many RP blocks and how many group
 * prefixes follow.  Two counts and a mask length, all of them bytes off the
 * wire, walking a buffer -- which is the shape of every parser bug this
 * tree has had, and the reason src/autorp.c was fuzzed the day it was
 * written rather than the year after.
 *
 * The input is the payload and nothing else, byte for byte what
 * `test/autorp -o FILE` writes and what `test/autorp -b FILE` sends, so a
 * crasher goes on the wire against a live daemon and anything a lab turns
 * up becomes a seed here.  The UDP and IP headers are the kernel's and are
 * not this parser's to check.
 *
 * The one thing the harness has to choose is the sender, which the daemon
 * takes from the kernel rather than from the message.  It comes from the
 * low two bits of the first reserved byte -- sec. 4 has that word sent as
 * zero and ignored on reception, so borrowing it costs the parser nothing
 * and keeps an input a plain Auto-RP message.
 *
 * Running it:
 *
 *   ./configure --enable-fuzz CC=clang				\
 *       CFLAGS="-g -O1 -fno-omit-frame-pointer -fno-strict-aliasing	\
 *               -fsanitize=address,undefined"			\
 *       LDFLAGS="-fsanitize=address,undefined"
 *   make
 *   mkdir work
 *   test/fuzz_autorp -max_len=512 work test/fuzz/corpus/autorp
 *
 * A crash leaves crash-<sha1>; test/fuzz_autorp_replay replays it, and
 * `make check` replays the whole corpus.
 */

#include "defs.h"

#include "router.h"
#include "topology.h"

#ifndef CONTINUE_ON_ERROR
#error "The fuzz harnesses need --disable-exit-on-error: logit(LOG_ERR) exits"
#endif

/*
 * A message longer than this is padding as far as the parser is concerned:
 * a header, an RP block and a group prefix are twenty bytes, and the
 * longest thing that says something new is a few RPs with a few prefixes
 * each.
 */
#define FUZZ_MAX_SIZE	1024

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;

	fuzz_router_init("fuzz_autorp");

	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint8_t msg[FUZZ_MAX_SIZE];
	unsigned sender;

	if (size > sizeof(msg))
		return 0;

	memcpy(msg, data, size);

	/* The reserved word the daemon ignores says who this is from.  A
	 * message too short to have one comes from the first sender, and
	 * goes in as it is: everything below reads only bytes that arrived.
	 */
	sender = size > 4 ? msg[4] & 0x03 : 0;

	fuzz_router_reset();
	fuzz_router_build();

	accept_autorp(htonl(fuzz_senders[sender]), (char *)msg, size);

	/* Not only for tidiness: the mappings an input made, and the RP set
	 * entries behind them, have to go before the next one or a leak
	 * reads as unbounded growth
	 */
	fuzz_router_reset();

	return 0;
}
