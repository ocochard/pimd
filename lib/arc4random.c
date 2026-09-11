/* arc4random() for systems whose C library does not have one
 *
 * Copyright (c) 2026  Olivier Cochard-Labbé <cochard@gmail.com>
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

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

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

static int refill(void)
{
	size_t cnt = 0;
	ssize_t num;
	int fd;

#ifdef HAVE_GETENTROPY
	if (!getentropy(pool, sizeof(pool))) {
		avail = sizeof(pool);
		return 0;
	}
#endif

	fd = open("/dev/urandom", O_RDONLY);
	if (fd == -1)
		return -1;

	while (cnt < sizeof(pool)) {
		num = read(fd, &pool[cnt], sizeof(pool) - cnt);
		if (num > 0) {
			cnt += (size_t)num;
			continue;
		}

		/* A short read is a retry, anything else is a dead pool.
		 * Note that num == 0 lands here too: /dev/urandom never
		 * reports EOF, so treat it as failure rather than looping
		 * on it forever. */
		if (num == -1 && (errno == EINTR || errno == EAGAIN))
			continue;

		close(fd);
		return -1;
	}
	close(fd);

	avail = sizeof(pool);
	return 0;
}

uint32_t arc4random(void)
{
	uint32_t val;

	if (avail < sizeof(val) && refill()) {
		static int seeded = 0;

		/* Neither getentropy() nor /dev/urandom answered, which on
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
