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

/*
 * Message bodies, behind the PIM header, written field for field as the
 * decoders of src/pim_parse.c read them, so that test/cbmc/roundtrip.c can
 * prove each pair agrees.  Each returns nonzero if the body fitted.
 */

/* A Register-Stop, RFC 7761 sec. 4.9.4: the group and the source */
int pim_encode_register_stop(struct pim_writer *w, uint32_t group, uint32_t source)
{
    pim_put_egaddr(w, group, SINGLE_GRP_MSKLEN, 0);
    pim_put_euaddr(w, source);

    return !w->full;
}

/* An Assert, sec. 4.9.6: the same two, and the metric preference -- RPT
 * bit included -- and the metric */
int pim_encode_assert(struct pim_writer *w, uint32_t group, uint32_t source,
		      uint32_t preference, uint32_t metric)
{
    pim_encode_register_stop(w, group, source);
    pim_put_u32(w, preference);
    pim_put_u32(w, metric);

    return !w->full;
}

/*
 * A Hello's options, RFC 7761 sec. 4.9.2: the Holdtime, the LAN Prune
 * Delay with the T bit clear -- pimd cannot disable Join suppression --
 * the DR Priority, the Generation ID, and an Address List of the @nsec
 * secondary addresses where there are any, sec. 4.3.4.  The delays are in
 * milliseconds.
 */
int pim_encode_hello(struct pim_writer *w, uint16_t holdtime, uint16_t propagation_delay,
		     uint16_t override_interval, uint32_t dr_prio, uint32_t genid,
		     const uint32_t *secaddrs, size_t nsec)
{
    size_t i;

    pim_put_u16(w, PIM_HELLO_HOLDTIME);
    pim_put_u16(w, PIM_HELLO_HOLDTIME_LEN);
    pim_put_u16(w, holdtime);

    pim_put_u16(w, PIM_HELLO_LAN_PRUNE_DELAY);
    pim_put_u16(w, PIM_HELLO_LAN_PRUNE_DELAY_LEN);
    pim_put_u16(w, propagation_delay & ~PIM_LAN_PRUNE_DELAY_T_BIT);
    pim_put_u16(w, override_interval);

    pim_put_u16(w, PIM_HELLO_DR_PRIO);
    pim_put_u16(w, PIM_HELLO_DR_PRIO_LEN);
    pim_put_u32(w, dr_prio);

    pim_put_u16(w, PIM_HELLO_GENID);
    pim_put_u16(w, PIM_HELLO_GENID_LEN);
    pim_put_u32(w, genid);

    if (nsec) {
	/* The option's length is 16 bits; a list longer than it holds is
	 * not written at all rather than written with a wrapped length */
	if (nsec > 0xffff / PIM_ENCODE_UNI_ADDR_LEN) {
	    w->full = 1;
	    return 0;
	}

	pim_put_u16(w, PIM_HELLO_ADDR_LIST);
	pim_put_u16(w, (uint16_t)(nsec * PIM_ENCODE_UNI_ADDR_LEN));
	for (i = 0; i < nsec; i++)
	    pim_put_euaddr(w, secaddrs[i]);
    }

    return !w->full;
}

/*
 * A Candidate-RP-Advertisement, RFC 5059 sec. 4.2, up to its group
 * prefixes: the Prefix Count, zero until the caller knows how many
 * followed -- *@cnt says where it is -- the Priority, the Holdtime and the
 * RP's address.  pim_encode_crp_prefix() writes each prefix after it.
 */
int pim_encode_crp_hdr(struct pim_writer *w, uint8_t priority, uint16_t holdtime,
		       uint32_t rp, uint8_t **cnt)
{
    *cnt = w->p;
    pim_put_u8(w, 0);
    pim_put_u8(w, priority);
    pim_put_u16(w, holdtime);
    pim_put_euaddr(w, rp);

    return !w->full;
}

int pim_encode_crp_prefix(struct pim_writer *w, uint32_t group, uint8_t masklen)
{
    return pim_put_egaddr(w, group, masklen, 0);
}

/*
 * A Null-Register, sec. 4.9.3: the flags word with the N bit, and the
 * dummy IPv4 header of the source and the group a Register of theirs would
 * carry, without options, with @ttl.  Its checksum is left zero for the
 * caller, which has inet_cksum() and this file does not; *@hdr says where
 * the header starts.
 */
int pim_encode_null_register(struct pim_writer *w, uint32_t source, uint32_t group,
			     uint8_t ttl, uint8_t **hdr)
{
    pim_put_u32(w, PIM_REGISTER_NULL_REGISTER_BIT);

    *hdr = w->p;
    pim_put_u8(w, (IP_HDR_V4 << 4) | (IP_HDR_MINLEN >> 2));
    pim_put_u8(w, 0);				/* ToS */
    pim_put_u16(w, IP_HDR_MINLEN);		/* Total length */
    pim_put_u16(w, 0);				/* Id */
    pim_put_u16(w, 0);				/* Fragment offset */
    pim_put_u8(w, ttl);
    pim_put_u8(w, IPPROTO_PIM);			/* 103 */
    pim_put_u16(w, 0);				/* Checksum, the caller's */
    pim_put_bytes(w, &source, sizeof(source));
    pim_put_bytes(w, &group, sizeof(group));

    return !w->full;
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "cc-mode"
 * End:
 */
