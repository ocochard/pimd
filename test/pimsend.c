/*
 * pimsend - send one PIM-SM message, exactly as told
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
 * A test tool for the receiving side of pimd, and the counterpart of
 * igmpv3.c on the PIM socket.
 *
 * Most of what doc/rfc7761-compliance.md still lists cannot be reproduced
 * by a lab of pimds, because the message that reproduces it is one pimd
 * will not build: every entry of the packet format section, and three of
 * the SSM one.  Two pimds share one reading of the wire, so a field pimd
 * encodes wrongly it also decodes wrongly and the lab stays green.  What
 * those entries want is a sender that will put anything in a field --
 * a mask length wider than an address, a version that is not 2, an address
 * family nobody assigned, a holdtime of 0xffff -- and then stop existing,
 * so that what the router does next is the router's own behaviour.
 *
 * That is all this is.  It builds one message, sends it once and exits.
 * Nothing here is a PIM implementation: it keeps no state, answers
 * nothing, and never becomes a neighbour of anybody unless you tell it to
 * send a Hello.
 *
 * Usage:
 *   pimsend -i IFADDR TYPE [options]
 *
 * TYPE is hello, join, prune, bootstrap, candrp, register, regstop or
 * assert.  Every message is sent to ALL-PIM-ROUTERS unless -d names a
 * destination, which is what a Register, a Register-Stop and the unicast
 * branch of a Bootstrap want.
 *
 * The options that exist to be got wrong apply to whichever message
 * carries the field:
 *
 *   -V VER     PIM version, default 2            (RFC 7761 sec. 4.9)
 *   -T TYPE    override the type nibble
 *   -K         corrupt the checksum
 *   -m LEN     group mask length, default 32     (sec. 4.9.1, 4.9.5.1)
 *   -M LEN     source mask length, default 32    (sec. 4.9.1)
 *   -f FAMILY  address family byte, default 1    (sec. 4.9.1)
 *   -e ENC     encoding type byte, default 0     (sec. 4.9.1)
 *   -B         set the Bidir bit of the group    (RFC 5059 sec. 3.6)
 *   -Z         set the admin-scope bit of the group
 *   -H TIME    holdtime, default per message     (sec. 4.9.2, 4.9.5)
 *   -A ADDR    a Hello Address List entry        (sec. 4.3.4, 4.9.2)
 *
 * Examples, each naming what it is for:
 *
 *   # F3: a group range nobody advertised, over the whole RP set
 *   pimsend -i 10.0.1.10 bootstrap -u 10.0.1.10 -g 224.0.0.0 -m 200 \
 *           -r 10.0.1.10 -p 200
 *
 *   # F3: a Join whose source carries a mask length that is not 32
 *   pimsend -i 10.0.23.3 join -u 10.0.23.2 -g 225.1.2.3 -s 10.0.1.10 -M 7
 *
 *   # A2: a Bootstrap unicast by somebody who never said hello
 *   pimsend -i 10.0.1.10 bootstrap -d 10.0.1.1 -u 10.0.1.10 \
 *           -g 224.0.0.0 -m 4 -r 10.0.1.10 -p 200
 *
 *   # F1: a version pimd does not implement
 *   pimsend -i 10.0.12.1 hello -V 3
 *
 *   # F5: "never time out this neighbour"
 *   pimsend -i 10.0.12.1 hello -H 65535
 */
#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef IPPROTO_PIM
#define IPPROTO_PIM			103
#endif

#define PIM_VERSION			2
#define PIM_ALL_ROUTERS			"224.0.0.13"

#define PIM_HELLO			0
#define PIM_REGISTER			1
#define PIM_REGISTER_STOP		2
#define PIM_JOIN_PRUNE			3
#define PIM_BOOTSTRAP			4
#define PIM_ASSERT			5
#define PIM_CAND_RP_ADV			8

#define PIM_HELLO_HOLDTIME		1
#define PIM_HELLO_DR_PRIO		19
#define PIM_HELLO_GENID			20
#define PIM_HELLO_ADDR_LIST		24

#define PIM_REGISTER_NULL_BIT		0x40000000
#define PIM_BOOTSTRAP_NO_FORWARD	0x80
#define PIM_ASSERT_RPT_BIT		0x80000000

/* Encoded-Source flags, RFC 7761 sec. 4.9.1 */
#define USADDR_RP_BIT			0x1
#define USADDR_WC_BIT			0x2
#define USADDR_S_BIT			0x4

/* Encoded-Group third byte, RFC 7761 sec. 4.9.1 and RFC 5059 sec. 3.6 */
#define EGADDR_B_BIT			0x80
#define EGADDR_Z_BIT			0x01

#define BUFSZ				2048
#define MAX_SOURCES			64

/*
 * How the message is put together.  Everything the caller may want wrong
 * lives here rather than being passed down through a dozen arguments, and
 * every field has the value a correct message would carry until an option
 * moves it.
 */
struct opts {
	int	 version;
	int	 type;			/* -1 until -T overrides it */
	int	 corrupt;
	unsigned gmasklen;
	unsigned smasklen;
	unsigned family;
	unsigned encoding;
	unsigned rec_family;		/* group and source records only */
	unsigned rec_encoding;
	int	 bidir;
	int	 scope;
	long	 holdtime;		/* -1 until -H overrides it */

	struct in_addr group;
	struct in_addr upstream;	/* Join/Prune target, Bootstrap BSR */
	struct in_addr rp;
	struct in_addr sources[MAX_SOURCES];
	int	 nsources;
	struct in_addr secaddrs[MAX_SOURCES];	/* Hello Address List */
	int	 nsecaddrs;
	int	 wildcard;		/* a (*,G) entry rather than (S,G) */
	int	 null_register;
	int	 no_forward;		/* Bootstrap N bit, RFC 5059 sec. 4.1 */
	int	 zerosum;		/* leave the dummy header's checksum 0 */
	int	 rpt;			/* Assert RPT bit */
	unsigned pref;
	unsigned metric;
	unsigned priority;
};

static uint8_t buf[BUFSZ];

static uint16_t cksum(void *data, size_t len)
{
	uint16_t *w = data;
	uint32_t sum = 0;

	while (len > 1) {
		sum += *w++;
		len -= 2;
	}

	if (len == 1)
		sum += *(uint8_t *)w;

	sum = (sum >> 16) + (sum & 0xffff);
	sum += sum >> 16;

	return ~sum;
}

static uint8_t *put_byte(uint8_t *p, unsigned val)
{
	*p++ = val & 0xff;

	return p;
}

static uint8_t *put_short(uint8_t *p, unsigned val)
{
	*p++ = (val >> 8) & 0xff;
	*p++ = val & 0xff;

	return p;
}

static uint8_t *put_long(uint8_t *p, uint32_t val)
{
	*p++ = (val >> 24) & 0xff;
	*p++ = (val >> 16) & 0xff;
	*p++ = (val >> 8) & 0xff;
	*p++ = val & 0xff;

	return p;
}

static uint8_t *put_addr(uint8_t *p, struct in_addr addr)
{
	memcpy(p, &addr, sizeof(addr));

	return p + sizeof(addr);
}

/* Encoded-Unicast-Address: family, encoding type, address */
static uint8_t *put_euaddr(uint8_t *p, const struct opts *o, struct in_addr addr)
{
	p = put_byte(p, o->family);
	p = put_byte(p, o->encoding);

	return put_addr(p, addr);
}

/* Encoded-Group-Address: family, encoding type, B/reserved/Z, mask len */
static uint8_t *put_egaddr(uint8_t *p, const struct opts *o, struct in_addr addr)
{
	unsigned bz = 0;

	if (o->bidir)
		bz |= EGADDR_B_BIT;
	if (o->scope)
		bz |= EGADDR_Z_BIT;

	p = put_byte(p, o->rec_family);
	p = put_byte(p, o->rec_encoding);
	p = put_byte(p, bz);
	p = put_byte(p, o->gmasklen);

	return put_addr(p, addr);
}

/* Encoded-Source-Address: family, encoding type, flags, mask len */
static uint8_t *put_esaddr(uint8_t *p, const struct opts *o, struct in_addr addr,
			   unsigned flags)
{
	p = put_byte(p, o->rec_family);
	p = put_byte(p, o->rec_encoding);
	p = put_byte(p, flags);
	p = put_byte(p, o->smasklen);

	return put_addr(p, addr);
}

static uint8_t *build_hello(uint8_t *p, const struct opts *o)
{
	unsigned holdtime = o->holdtime < 0 ? 105 : (unsigned)o->holdtime;

	p = put_short(p, PIM_HELLO_HOLDTIME);
	p = put_short(p, 2);
	p = put_short(p, holdtime);

	p = put_short(p, PIM_HELLO_DR_PRIO);
	p = put_short(p, 4);
	p = put_long(p, o->priority);

	p = put_short(p, PIM_HELLO_GENID);
	p = put_short(p, 4);
	p = put_long(p, 0x0badcafe);

	/* Only when asked for: a Hello without the option is the one that
	 * has to clear a neighbour's secondaries, RFC 7761 sec. 4.3.4.  -f
	 * and -e reach these addresses like any other encoded unicast one. */
	if (o->nsecaddrs) {
		int i;

		p = put_short(p, PIM_HELLO_ADDR_LIST);
		p = put_short(p, o->nsecaddrs * 6);
		for (i = 0; i < o->nsecaddrs; i++)
			p = put_euaddr(p, o, o->secaddrs[i]);
	}

	return p;
}

/*
 * One group set, its Joined list holding every -s (or the RP for a (*,G)),
 * and an empty Pruned list -- or the other way round for a Prune.
 */
static uint8_t *build_join_prune(uint8_t *p, const struct opts *o, int prune)
{
	unsigned holdtime = o->holdtime < 0 ? 210 : (unsigned)o->holdtime;
	int njoin, nprune, i;

	p = put_euaddr(p, o, o->upstream);
	p = put_byte(p, 0);		/* reserved */
	p = put_byte(p, 1);		/* one group set */
	p = put_short(p, holdtime);

	p = put_egaddr(p, o, o->group);

	njoin  = prune ? 0 : (o->wildcard ? 1 : o->nsources);
	nprune = prune ? (o->wildcard ? 1 : o->nsources) : 0;
	p = put_short(p, njoin);
	p = put_short(p, nprune);

	if (o->wildcard)
		return put_esaddr(p, o, o->rp,
				  USADDR_WC_BIT | USADDR_RP_BIT | USADDR_S_BIT);

	for (i = 0; i < o->nsources; i++)
		p = put_esaddr(p, o, o->sources[i], USADDR_S_BIT);

	return p;
}

/*
 * One group range with one RP in it, which is the shape every entry that
 * wants a Bootstrap needs.  A fragment carrying several is a different
 * test and nothing in the compliance file asks for one yet.
 */
static uint8_t *build_bootstrap(uint8_t *p, const struct opts *o)
{
	unsigned holdtime = o->holdtime < 0 ? 150 : (unsigned)o->holdtime;

	p = put_short(p, 0x1234);	/* fragment tag */
	p = put_byte(p, o->smasklen);	/* hash mask length */
	p = put_byte(p, o->priority);	/* BSR priority */
	p = put_euaddr(p, o, o->upstream);

	p = put_egaddr(p, o, o->group);
	p = put_byte(p, 1);		/* RP count */
	p = put_byte(p, 1);		/* fragment RP count */
	p = put_short(p, 0);		/* reserved */

	p = put_euaddr(p, o, o->rp);
	p = put_short(p, holdtime);
	p = put_byte(p, o->priority);
	p = put_byte(p, 0);		/* reserved */

	return p;
}

static uint8_t *build_cand_rp_adv(uint8_t *p, const struct opts *o)
{
	unsigned holdtime = o->holdtime < 0 ? 150 : (unsigned)o->holdtime;

	p = put_byte(p, 1);		/* prefix count */
	p = put_byte(p, o->priority);
	p = put_short(p, holdtime);
	p = put_euaddr(p, o, o->rp);

	return put_egaddr(p, o, o->group);
}

/*
 * A Register, with an inner IP header the RP is meant to read the source
 * and group out of.  A Null-Register carries that header and nothing else,
 * which is the one sec. 4.9.3 has the RP checksum -- and F6 of the
 * compliance file is that pimd reads neither the checksum nor the protocol.
 */
static uint8_t *build_register(uint8_t *p, const struct opts *o)
{
	struct in_addr inner_src = o->nsources ? o->sources[0] : o->rp;
	uint8_t *ip;

	p = put_long(p, o->null_register ? PIM_REGISTER_NULL_BIT : 0);

	ip = p;
	p = put_byte(p, 0x45);			/* version 4, 5 word header */
	p = put_byte(p, 0);			/* ToS */
	p = put_short(p, 20);			/* total length */
	p = put_short(p, 0);			/* id */
	p = put_short(p, 0);			/* flags, fragment offset */
	p = put_byte(p, 64);			/* TTL */
	p = put_byte(p, IPPROTO_PIM);		/* sec. 4.9.3 wants 103 here */
	p = put_short(p, 0);			/* checksum, filled in below */
	p = put_addr(p, inner_src);
	p = put_addr(p, o->group);

	/* Three cases the RFC distinguishes, sec. 4.9.3: a correct checksum,
	 * a wrong one that a Null-Register must be discarded for, and a zero
	 * one that MUST NOT be checked at all.
	 */
	if (!o->zerosum) {
		uint16_t sum = cksum(ip, 20);

		if (o->corrupt)
			sum = ~sum;

		ip[10] = (sum) & 0xff;
		ip[11] = (sum >> 8) & 0xff;
	}

	return p;
}

static uint8_t *build_register_stop(uint8_t *p, const struct opts *o)
{
	struct in_addr src = o->nsources ? o->sources[0] : o->rp;

	p = put_egaddr(p, o, o->group);

	return put_euaddr(p, o, src);
}

static uint8_t *build_assert(uint8_t *p, const struct opts *o)
{
	struct in_addr src = o->nsources ? o->sources[0] : o->rp;
	uint32_t pref = o->pref;

	if (o->rpt)
		pref |= PIM_ASSERT_RPT_BIT;

	p = put_egaddr(p, o, o->group);
	p = put_euaddr(p, o, src);
	p = put_long(p, pref);

	return put_long(p, o->metric);
}

static int msgtype(const char *arg)
{
	if (!strcmp(arg, "hello"))
		return PIM_HELLO;
	if (!strcmp(arg, "register"))
		return PIM_REGISTER;
	if (!strcmp(arg, "regstop"))
		return PIM_REGISTER_STOP;
	if (!strcmp(arg, "join") || !strcmp(arg, "prune"))
		return PIM_JOIN_PRUNE;
	if (!strcmp(arg, "bootstrap"))
		return PIM_BOOTSTRAP;
	if (!strcmp(arg, "assert"))
		return PIM_ASSERT;
	if (!strcmp(arg, "candrp"))
		return PIM_CAND_RP_ADV;

	return -1;
}

static unsigned num(const char *arg, const char *what)
{
	char *end;
	long val;

	errno = 0;
	val = strtol(arg, &end, 0);
	if (errno || *end || val < 0 || val > 0xffffffffL)
		errx(1, "invalid %s '%s'", what, arg);

	return (unsigned)val;
}

static struct in_addr addr(const char *arg, const char *what)
{
	struct in_addr in;

	if (inet_pton(AF_INET, arg, &in) != 1)
		errx(1, "invalid %s '%s'", what, arg);

	return in;
}

static int usage(int rc)
{
	fprintf(stderr,
		"usage: pimsend -i IFADDR TYPE [options]\n"
		"\n"
		"TYPE is hello, join, prune, bootstrap, candrp, register, regstop or assert.\n"
		"\n"
		"  -i IFADDR  Local address to send from, and the message's source\n"
		"  -d DST     Unicast destination, default " PIM_ALL_ROUTERS "\n"
		"  -g GROUP   Multicast group the message is about\n"
		"  -s SOURCE  Source address, repeatable for a Join/Prune\n"
		"  -A ADDR    A Hello Address List entry, repeatable\n"
		"  -u ADDR    Join/Prune upstream neighbour, or the BSR of a Bootstrap\n"
		"  -r ADDR    The RP: of a Bootstrap, a candrp, or a (*,G) Join\n"
		"  -w         Make the Join/Prune a (*,G) rather than an (S,G)\n"
		"  -N         Make the Register a Null-Register\n"
		"  -n         Set the Bootstrap No-Forward bit, RFC 5059 sec. 3.5.1:\n"
		"             the receiver skips the RPF check and does not pass it on\n"
		"  -0         Leave the Register's inner header checksum zero, which\n"
		"             sec. 4.9.3 says the RP MUST NOT check\n"
		"  -p PRIO    Priority: DR, BSR or candidate RP, default 1\n"
		"  -P PREF    Assert metric preference, default 101\n"
		"  -C METRIC  Assert metric, default 1024\n"
		"  -R         Set the Assert RPT bit\n"
		"\n"
		"Fields that exist here to be got wrong:\n"
		"  -V VER     PIM version, default 2\n"
		"  -T TYPE    Override the type nibble\n"
		"  -K         Corrupt the checksum\n"
		"  -m LEN     Group mask length, default 32\n"
		"  -M LEN     Source mask length, and a Bootstrap's hash mask length\n"
		"  -f FAMILY  Address family byte, default 1 (IPv4).  Applies to every\n"
		"             encoded address in the message\n"
		"  -e ENC     Encoding type byte, default 0 (native), likewise\n"
		"  -F FAMILY  Address family of the encoded group and source records\n"
		"             only, leaving the unicast addresses alone -- which is how\n"
		"             a parser that checks one and not the other is caught\n"
		"  -E ENC     Encoding type of those records only\n"
		"  -B         Set the Bidir bit of the encoded group\n"
		"  -Z         Set the admin-scope bit of the encoded group\n"
		"  -H TIME    Holdtime, default per message type\n");

	return rc;
}

int main(int argc, char *argv[])
{
	struct sockaddr_in sin, dst;
	struct in_addr ifaddr;
	const char *dest = PIM_ALL_ROUTERS;
	struct opts o;
	uint8_t *p;
	int type, prune = 0;
	unsigned char ttl = 1;
	uint16_t sum;
	size_t len;
	int sd, c, on = 1, rec_set = 0;

	memset(&o, 0, sizeof(o));
	memset(&ifaddr, 0, sizeof(ifaddr));
	o.version  = PIM_VERSION;
	o.type     = -1;
	o.holdtime = -1;
	o.gmasklen = 32;
	o.smasklen = 32;
	o.family   = 1;			/* ADDRF_IPv4 */
	o.encoding = 0;			/* ADDRT_IPv4 */
	o.priority = 1;
	o.pref     = 101;
	o.metric   = 1024;

	/* The type is the one positional argument and comes before the
	 * options, "pimsend -i A join -g G", so getopt() has to be run
	 * twice: once for -i, which may precede it, and once for the rest.
	 */
	while ((c = getopt(argc, argv, "+h?i:")) != -1) {
		switch (c) {
		case 'i':
			ifaddr = addr(optarg, "interface address");
			break;

		default:
			return usage(c == 'h' || c == '?' ? 0 : 1);
		}
	}

	if (optind >= argc)
		return usage(1);

	type = msgtype(argv[optind]);
	if (type < 0)
		errx(1, "unknown message type '%s'", argv[optind]);
	prune = !strcmp(argv[optind], "prune");
	optind++;

	while ((c = getopt(argc, argv, "0A:BC:d:E:e:F:f:g:H:h?i:KM:m:Nnp:P:Rr:s:T:u:V:wZ")) != -1) {
		switch (c) {
		case '0': o.zerosum = 1;				break;
		case 'E': o.rec_encoding = num(optarg, "encoding type"); rec_set = 1; break;
		case 'F': o.rec_family = num(optarg, "address family"); rec_set |= 2; break;
		case 'B': o.bidir = 1;					break;
		case 'C': o.metric = num(optarg, "metric");		break;
		case 'd': dest = optarg;				break;
		case 'e': o.encoding = num(optarg, "encoding type");	break;
		case 'f': o.family = num(optarg, "address family");	break;
		case 'g': o.group = addr(optarg, "group");		break;
		case 'H': o.holdtime = num(optarg, "holdtime");		break;
		case 'i': ifaddr = addr(optarg, "interface address");	break;
		case 'K': o.corrupt = 1;				break;
		case 'M': o.smasklen = num(optarg, "source mask length"); break;
		case 'm': o.gmasklen = num(optarg, "group mask length");	break;
		case 'N': o.null_register = 1;				break;
		case 'n': o.no_forward = 1;				break;
		case 'P': o.pref = num(optarg, "metric preference");	break;
		case 'p': o.priority = num(optarg, "priority");		break;
		case 'R': o.rpt = 1;					break;
		case 'r': o.rp = addr(optarg, "RP address");		break;
		case 'T': o.type = num(optarg, "message type");		break;
		case 'u': o.upstream = addr(optarg, "upstream address");	break;
		case 'V': o.version = num(optarg, "version");		break;
		case 'w': o.wildcard = 1;				break;
		case 'Z': o.scope = 1;					break;

		case 'A':
			if (o.nsecaddrs >= MAX_SOURCES)
				errx(1, "too many secondary addresses, max %d", MAX_SOURCES);
			o.secaddrs[o.nsecaddrs++] = addr(optarg, "secondary address");
			break;

		case 's':
			if (o.nsources >= MAX_SOURCES)
				errx(1, "too many sources, max %d", MAX_SOURCES);
			o.sources[o.nsources++] = addr(optarg, "source");
			break;

		default:
			return usage(c == 'h' || c == '?' ? 0 : 1);
		}
	}

	if (!ifaddr.s_addr)
		return usage(1);

	/* The record fields follow the message-wide ones unless -F or -E
	 * said otherwise, so -f alone still changes every address.
	 */
	if (!(rec_set & 2))
		o.rec_family = o.family;
	if (!(rec_set & 1))
		o.rec_encoding = o.encoding;

	/* PIM header: version and type in one byte, then reserved and the
	 * checksum, which is filled in once the body is built.
	 */
	p = buf;
	p = put_byte(p, ((o.version & 0xf) << 4) |
		     ((o.type < 0 ? type : o.type) & 0xf));
	p = put_byte(p, o.no_forward ? PIM_BOOTSTRAP_NO_FORWARD : 0);
	p = put_short(p, 0);

	switch (type) {
	case PIM_HELLO:		p = build_hello(p, &o);			break;
	case PIM_JOIN_PRUNE:	p = build_join_prune(p, &o, prune);	break;
	case PIM_BOOTSTRAP:	p = build_bootstrap(p, &o);		break;
	case PIM_CAND_RP_ADV:	p = build_cand_rp_adv(p, &o);		break;
	case PIM_REGISTER:	p = build_register(p, &o);		break;
	case PIM_REGISTER_STOP:	p = build_register_stop(p, &o);		break;
	case PIM_ASSERT:	p = build_assert(p, &o);		break;
	}

	len = (size_t)(p - buf);

	/* A Register is checksummed over its header only, sec. 4.9.3, which
	 * is also how pimd verifies one (src/pim_proto.c).
	 */
	sum = cksum(buf, type == PIM_REGISTER ? 8 : len);

	/* For a Register, -K is the inner header's checksum, applied above:
	 * corrupting the outer one too would have pim.c drop the message
	 * before receive_pim_register() ever looked at the dummy header.
	 */
	if (o.corrupt && type != PIM_REGISTER)
		sum = ~sum;
	buf[2] = sum & 0xff;
	buf[3] = (sum >> 8) & 0xff;

	sd = socket(AF_INET, SOCK_RAW, IPPROTO_PIM);
	if (sd < 0)
		err(1, "failed creating raw PIM socket");

	if (setsockopt(sd, IPPROTO_IP, IP_MULTICAST_IF, &ifaddr, sizeof(ifaddr)))
		err(1, "failed selecting outbound interface");
	if (setsockopt(sd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)))
		err(1, "failed setting multicast TTL");
	(void)setsockopt(sd, IPPROTO_IP, IP_MULTICAST_LOOP, &on, sizeof(on));

	/* Bound so the message carries the address asked for: a PIM router
	 * decides who sent it from the IP source and nothing else.
	 */
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr = ifaddr;
	if (bind(sd, (struct sockaddr *)&sin, sizeof(sin)))
		err(1, "failed binding to %s", inet_ntoa(ifaddr));

	memset(&dst, 0, sizeof(dst));
	dst.sin_family = AF_INET;
	dst.sin_addr = addr(dest, "destination");

	if (sendto(sd, buf, len, 0, (struct sockaddr *)&dst, sizeof(dst)) < 0)
		err(1, "failed sending to %s", dest);

	close(sd);

	return 0;
}
