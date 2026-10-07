/*
 * pim_encode.c - writing PIM messages into a buffer that has an end
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
 * The PUT_* macros pimd.h used to have wrote wherever their pointer
 * pointed, and each builder that used them carried its own sum of how much
 * would fit.  One
 * of those sums was missing once: create_pim_bootstrap_message() wrote an
 * RP set of 10200 ranges a stranger had advertised past the end of the
 * 128K send buffer.  This is the same writing with the end of the buffer
 * kept beside the pointer.  It includes libc and pimd.h and nothing else
 * of the daemon's, so that test/cbmc/encode.c can prove it alone.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>

#include "pimd.h"

void pim_writer_init(struct pim_writer *w, void *buf, size_t len)
{
    w->p    = buf;
    w->left = len;
    w->full = 0;
}

/* Would n more bytes fit?  For a builder that wants a record whole or not
 * at all, asked before the first field of it. */
int pim_writer_room(const struct pim_writer *w, size_t n)
{
    return !w->full && n <= w->left;
}

/* How much has been written since buf, which is where it started */
size_t pim_writer_used(const struct pim_writer *w, const void *buf)
{
    return (size_t)(w->p - (const uint8_t *)buf);
}

/* n bytes from src, or nothing and the writer full */
static int pim_put(struct pim_writer *w, const void *src, size_t n)
{
    if (!pim_writer_room(w, n)) {
	w->full = 1;
	return 0;
    }

    memcpy(w->p, src, n);
    w->p    += n;
    w->left -= n;

    return 1;
}

/* n bytes already encoded, a list a builder kept apart and copies in whole */
int pim_put_bytes(struct pim_writer *w, const void *src, size_t n)
{
    return pim_put(w, src, n);
}

int pim_put_u8(struct pim_writer *w, uint8_t val)
{
    return pim_put(w, &val, 1);
}

int pim_put_u16(struct pim_writer *w, uint16_t val)
{
    uint8_t b[2] = { (uint8_t)((val >> 8) & 0xff), (uint8_t)(val & 0xff) };

    return pim_put(w, b, sizeof(b));
}

int pim_put_u32(struct pim_writer *w, uint32_t val)
{
    uint8_t b[4] = { (uint8_t)((val >> 24) & 0xff), (uint8_t)((val >> 16) & 0xff),
		     (uint8_t)((val >> 8) & 0xff), (uint8_t)(val & 0xff) };

    return pim_put(w, b, sizeof(b));
}

/* Encoded-Unicast, RFC 7761 sec. 4.9.1, of an address in network order */
int pim_put_euaddr(struct pim_writer *w, uint32_t addr)
{
    uint8_t b[PIM_ENCODE_UNI_ADDR_LEN] = { ADDRF_IPv4, ADDRT_IPv4 };

    memcpy(b + 2, &addr, sizeof(addr));

    return pim_put(w, b, sizeof(b));
}

/* Encoded-Group: the address masked to its length, RFC 7761 sec. 4.9.1 */
int pim_put_egaddr(struct pim_writer *w, uint32_t addr, uint8_t masklen, uint8_t reserved)
{
    uint8_t b[PIM_ENCODE_GRP_ADDR_LEN] = { ADDRF_IPv4, ADDRT_IPv4, reserved, masklen };
    uint32_t mask;

    MASKLEN_TO_MASK(masklen, mask);
    addr &= mask;
    memcpy(b + 4, &addr, sizeof(addr));

    return pim_put(w, b, sizeof(b));
}

/* Encoded-Source: the address masked to its length, sec. 4.9.1 */
int pim_put_esaddr(struct pim_writer *w, uint32_t addr, uint8_t masklen, uint8_t flags)
{
    uint8_t b[PIM_ENCODE_SRC_ADDR_LEN] = { ADDRF_IPv4, ADDRT_IPv4, flags, masklen };
    uint32_t mask;

    MASKLEN_TO_MASK(masklen, mask);
    addr &= mask;
    memcpy(b + 4, &addr, sizeof(addr));

    return pim_put(w, b, sizeof(b));
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "cc-mode"
 * End:
 */
