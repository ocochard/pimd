/* arc4random() for systems whose C library does not have one
 *
 * Copyright (c) 2026  Olivier Cochard-Labbé <olivier@cochard.me>
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
 */

#include "config.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "defs.h"

/*
 * The BSDs have had arc4random() for decades, but GLIBC only grew one in
 * 2.36 and musl in 1.2.3, so every enterprise Linux still in support
 * needs this.
 *
 * pimd asks for randomness to jitter its protocol timers, to pick a PIM
 * Hello GenID and to tag a BSR bootstrap fragment.  None of those are
 * keys, so this need not be a generator of its own -- but all of them
 * are values a neighbor on the LAN should not be able to predict, which
 * is the part the random() this replaces cannot promise.  So read the
 * kernel's generator instead, a pool at a time, rather than once per
 * call: a Join/Prune storm asks for one of these per suppression
 * decision.
 */

#define POOLSZ	32		/* getentropy() is specified up to 256 bytes */

static uint8_t pool[POOLSZ];
static size_t  avail;		/* unread bytes, at the front of pool[] */

/* getentropy() is in every C library this file is built against: glibc
 * since 2.25, musl since 1.1.20.  It is the getrandom() system call, which
 * needs no file, and so works in the chroot() of the unprivileged half,
 * where /dev/urandom is not. */
static int refill(void)
{
	if (getentropy(pool, sizeof(pool)))
		return -1;

	avail = sizeof(pool);
	return 0;
}

uint32_t arc4random(void)
{
	uint32_t val;

	if (avail < sizeof(val) && refill()) {
		static int seeded = 0;

		/* getentropy() did not answer, which on
		 * any system that reaches this code means something worse
		 * has gone wrong than a guessable hello timer.  Stay up on
		 * a weak value rather than take the router down with it. */
		if (!seeded) {
			srandom((unsigned int)(time(NULL) ^ getpid()));
			seeded = 1;
		}

		return (uint32_t)random();
	}

	avail -= sizeof(val);
	memcpy(&val, &pool[avail], sizeof(val));

	return val;
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
