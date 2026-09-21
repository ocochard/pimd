/*
 * router - the pimd a harness runs the parsers inside
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
 * What every harness needs and none of them is about: a router with
 * interfaces, neighbors, an RP set and a routing table, built the way
 * main() builds one and torn down between inputs.  fuzz/router.c has the
 * whole of it, and the header comment there says which parts of the daemon
 * it stands in for.
 */

#ifndef PIMD_FUZZ_ROUTER_H_
#define PIMD_FUZZ_ROUTER_H_

#include "defs.h"

/* The four senders of fuzz/topology.h, in host order, in the order a
 * harness that lets an input choose one indexes them: two neighbors on the
 * first link, one on the second, and a host that has sent no Hello.
 */
extern const uint32_t fuzz_senders[4];

/*
 * Once, before the first input: the buffers, the logging, the sockets that
 * are not sockets, and the pimd.conf on disk.  Takes the program name the
 * logs should carry.
 */
void fuzz_router_init(char *prognm);

/* Per input, in this order: everything an input made goes away, and the
 * router the next one arrives at is built again from the same file.
 */
void fuzz_router_reset(void);
void fuzz_router_build(void);

/*
 * One PIM message into the daemon, with an IP header of the harness's own
 * around it and the checksum computed last -- which is what the prologue of
 * fuzz_router_build() is made of, and what fuzz_pim.c hands its input to.
 * The message is copied, so the caller's buffer may be const.
 */
void fuzz_pim_feed(uint32_t src, uint32_t dst, const uint8_t *msg, size_t len);

/*
 * One packet into a receive buffer, and the end of it made a boundary the
 * sanitizer will enforce: the rest of the buffer is poisoned, so a parser
 * that reads past the message it was handed is caught rather than reading
 * stale bytes of a 128K allocation.  router.c says why that matters.
 * Without ASan it is a memcpy().
 */
void fuzz_buf_load(char *buf, const void *pkt, size_t len);

#endif /* PIMD_FUZZ_ROUTER_H_ */
