/*
 * autorp.h - Auto-RP on the wire
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
 * The message format of doc/pim-autorp-spec01.txt sec. 4, as lengths and
 * offsets rather than as a struct: the fields are not aligned -- a 16-bit
 * holdtime at offset 2, then 4-byte addresses at offsets 8, 14 and on --
 * and a struct with bitfields in it would be a second thing to get right
 * per compiler and per byte order.  src/autorp.c walks the bytes.
 *
 * Both message types carry the same format and differ only in the type
 * nibble, which is why one parser reads both.
 */
#ifndef PIMD_AUTORP_H_
#define PIMD_AUTORP_H_

/* The two groups IANA assigned, and the port, sec. 5 */
#define AUTORP_ANNOUNCE_GROUP	((uint32_t)0xe0000127)	/* 224.0.1.39 */
#define AUTORP_DISCOVERY_GROUP	((uint32_t)0xe0000128)	/* 224.0.1.40 */
#define AUTORP_PORT		496			/* PIM-RP-DISC */

#define AUTORP_VERSION		1	/* "version 1+", sec. 4 */

#define AUTORP_TYPE_ANNOUNCE	1	/* an RP says what it serves	  */
#define AUTORP_TYPE_MAPPING	2	/* an agent says what it resolved */

/*
 * Header: version and type in one byte, RP count, holdtime, reserved word.
 * Then RP count blocks of an address, a byte whose low two bits are the
 * RP's PIM version, and a group count; then that many group prefixes of a
 * byte whose low bit denies the prefix, a mask length and an address.
 */
#define AUTORP_HDR_LEN		8
#define AUTORP_RP_LEN		6
#define AUTORP_GRP_LEN		6

/* The shortest message that says anything: a header, one RP, one prefix */
#define AUTORP_MINLEN		(AUTORP_HDR_LEN + AUTORP_RP_LEN + AUTORP_GRP_LEN)

/*
 * And the longest one pimd builds.  A datagram this router sends has to
 * reach every listener without being fragmented, so it stays under the
 * smallest MTU anything here runs on rather than filling a 64K buffer with
 * RP blocks a receiver may never reassemble.
 */
#define AUTORP_MSG_MAX		1024

#define AUTORP_VERSION_OF(b)	(((b) >> 4) & 0x0f)
#define AUTORP_TYPE_OF(b)	((b) & 0x0f)

#define AUTORP_RP_PIMVER(b)	((b) & 0x03)	/* 0 unknown, 1 v1, 2 v2, 3 both */
#define AUTORP_GRP_NEGATIVE(b)	((b) & 0x01)	/* sec. 4, the N bit	         */

/*
 * A holdtime of zero is "never time out", sec. 4, which is the same thing
 * pimd spells PIM_HELLO_HOLDTIME_FOREVER everywhere else.
 */
#define AUTORP_HOLDTIME_FOREVER	0

/* What the draft calls for where nothing is configured, sec. 3.1 */
#define AUTORP_DEFAULT_INTERVAL	60
#define AUTORP_DEFAULT_HOLDTIME	(3 * AUTORP_DEFAULT_INTERVAL)

/*
 * How far an announcement or a mapping travels.  The draft says nothing
 * about a TTL -- it assumes the two groups are flooded and scoped by
 * whatever the domain does -- and every implementation since has made it a
 * "scope" the sender sets.  15 is IOS's default and FRR's is 31; pimd sends
 * one copy per interface rather than relying on a flooding it does not
 * have, so a small number is the honest one and this is it.
 */
#define AUTORP_DEFAULT_SCOPE	15

/*
 * The decoding half of accept_autorp(), in src/autorp_parse.c: bytes in,
 * fields out, and every bounds check of the message in one place.  It
 * reads no global and calls nothing but memcpy(), which is what lets
 * test/cbmc/ prove it over every buffer up to a length rather than sample
 * it.  What a field *means* -- a version pimd speaks, an RP that is a
 * host, a mask length that is a prefix -- is accept_autorp()'s to decide.
 *
 * A cursor rather than a decoded message: an RP count and a group count
 * of 255 each are 65025 prefixes, and a message that ends inside a block
 * has always had the blocks before it applied, which a parse that refused
 * the whole message would change.
 */
struct autorp_hdr {
    unsigned version;
    unsigned type;
    unsigned rpcnt;
    uint16_t holdtime;
};

struct autorp_wire_prefix {
    uint32_t rp_addr;		/* network order */
    uint32_t group_addr;	/* network order */
    uint8_t  masklen;		/* as sent, not yet checked against 32 */
    int      negative;
};

struct autorp_cursor {
    const uint8_t *p;		/* the next byte to read		*/
    size_t   left;		/* bytes from p to the end of the buffer	*/
    unsigned rpcnt;		/* RP blocks still to read		*/
    unsigned grpcnt;		/* prefixes still to read in this block	*/
    uint32_t rp_addr;		/* the RP of the block being read	*/
};

/* What autorp_parse_next() found */
#define AUTORP_PARSE_DONE	0	/* every block the header announced	*/
#define AUTORP_PARSE_PREFIX	1	/* one prefix, in *prefix		*/
#define AUTORP_PARSE_SHORT_RP	2	/* the buffer ends inside an RP block	*/
#define AUTORP_PARSE_SHORT_GRP	3	/* ... or inside a group prefix		*/

int autorp_parse_hdr(struct autorp_cursor *c, struct autorp_hdr *hdr,
		     const void *buf, size_t len);
int autorp_parse_next(struct autorp_cursor *c, struct autorp_wire_prefix *prefix);

#endif /* PIMD_AUTORP_H_ */

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "cc-mode"
 * End:
 */
