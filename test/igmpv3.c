/*
 * igmpv3 - send one IGMPv3 membership report, exactly as told
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
 * A test tool for the receiving side of pimd, not a host implementation.
 *
 * Asking a kernel to join a group gives its IGMP state machine, not the
 * report the test wants: it picks the version, merges group records,
 * suppresses a report another host already sent, and answers every query
 * afterwards.  A router's membership state cannot be aged out in a test
 * while a real host sits on the LAN refreshing it, and a host taken off
 * the LAN takes its leave report, or the router's interface, with it.
 *
 * This sends one report and then stops existing.  What the router does
 * from there is the router's own behaviour, which is what the test is
 * about.  Refreshing a membership means sending another report.
 *
 * Usage:
 *   igmpv3 -i IFADDR -g GROUP -t TYPE [SOURCE ...]
 *   igmpv3 -i IFADDR -g GROUP -t allow -n COUNT -b BASE
 *
 * TYPE is one of the RFC 3376 sec. 4.2.12 record types: is_in, is_ex,
 * to_in, to_ex, allow, block.  A join of (S,G) is "allow S", dropping
 * that source is "block S", and leaving the group entirely is "to_in"
 * with no sources.
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

#define IGMPV3_HOST_MEMBERSHIP_REPORT	0x22
#define IGMPV3_ALL_ROUTERS		"224.0.0.22"

#define MODE_IS_INCLUDE			1
#define MODE_IS_EXCLUDE			2
#define CHANGE_TO_INCLUDE_MODE		3
#define CHANGE_TO_EXCLUDE_MODE		4
#define ALLOW_NEW_SOURCES		5
#define BLOCK_OLD_SOURCES		6

#define MAX_SOURCES			8192

struct report {
	uint8_t  type;
	uint8_t  resv1;
	uint16_t csum;
	uint16_t resv2;
	uint16_t ngrec;
	/* one group record follows */
	uint8_t  grec_type;
	uint8_t  grec_auxwords;
	uint16_t grec_nsrcs;
	uint32_t grec_mca;
	uint32_t grec_src[MAX_SOURCES];
} __attribute__((packed));

static uint16_t cksum(void *buf, size_t len)
{
	uint16_t *w = buf;
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

static int rectype(const char *arg)
{
	if (!strcmp(arg, "is_in"))
		return MODE_IS_INCLUDE;
	if (!strcmp(arg, "is_ex"))
		return MODE_IS_EXCLUDE;
	if (!strcmp(arg, "to_in"))
		return CHANGE_TO_INCLUDE_MODE;
	if (!strcmp(arg, "to_ex"))
		return CHANGE_TO_EXCLUDE_MODE;
	if (!strcmp(arg, "allow"))
		return ALLOW_NEW_SOURCES;
	if (!strcmp(arg, "block"))
		return BLOCK_OLD_SOURCES;

	return -1;
}

static int usage(int rc)
{
	fprintf(stderr,
		"usage: igmpv3 -i IFADDR -g GROUP -t TYPE [-n COUNT -b BASE] [SOURCE ...]\n"
		"\n"
		"  -i IFADDR  Local address of the interface to send from\n"
		"  -g GROUP   Multicast group to report\n"
		"  -t TYPE    is_in, is_ex, to_in, to_ex, allow, block\n"
		"  -n COUNT   Generate COUNT consecutive sources from -b instead\n"
		"  -b BASE    First address of the generated range\n");

	return rc;
}

int main(int argc, char *argv[])
{
	static struct report rep;	/* 32 KiB of sources, keep it off the stack */
	struct sockaddr_in sin, dst;
	struct in_addr ifaddr, group;
	const char *base = NULL;
	int type = -1, num = 0;
	unsigned char ttl = 1;
	size_t len;
	int nsrcs = 0;
	int sd, i, c;

	memset(&ifaddr, 0, sizeof(ifaddr));
	memset(&group, 0, sizeof(group));

	while ((c = getopt(argc, argv, "b:g:h?i:n:t:")) != -1) {
		switch (c) {
		case 'b':
			base = optarg;
			break;

		case 'g':
			if (inet_pton(AF_INET, optarg, &group) != 1)
				errx(1, "invalid group %s", optarg);
			break;

		case 'i':
			if (inet_pton(AF_INET, optarg, &ifaddr) != 1)
				errx(1, "invalid interface address %s", optarg);
			break;

		case 'n':
			num = atoi(optarg);
			break;

		case 't':
			type = rectype(optarg);
			if (type < 0)
				errx(1, "invalid record type %s", optarg);
			break;

		default:
			return usage(c == 'h' || c == '?' ? 0 : 1);
		}
	}

	if (!group.s_addr || !ifaddr.s_addr || type < 0)
		return usage(1);

	if (num > 0) {
		struct in_addr in;
		uint32_t addr;

		if (!base)
			errx(1, "-n needs -b BASE");
		if (num > MAX_SOURCES)
			errx(1, "-n %d exceeds the %d source limit", num, MAX_SOURCES);
		if (inet_pton(AF_INET, base, &in) != 1)
			errx(1, "invalid base address %s", base);

		addr = ntohl(in.s_addr);
		for (i = 0; i < num; i++)
			rep.grec_src[nsrcs++] = htonl(addr + i);
	}

	for (i = optind; i < argc; i++) {
		if (nsrcs >= MAX_SOURCES)
			errx(1, "too many sources, max %d", MAX_SOURCES);
		if (inet_pton(AF_INET, argv[i], &rep.grec_src[nsrcs]) != 1)
			errx(1, "invalid source %s", argv[i]);
		nsrcs++;
	}

	rep.type = IGMPV3_HOST_MEMBERSHIP_REPORT;
	rep.ngrec = htons(1);
	rep.grec_type = type;
	rep.grec_nsrcs = htons(nsrcs);
	rep.grec_mca = group.s_addr;

	/* Only the sources actually filled in are sent */
	len = sizeof(rep) - sizeof(rep.grec_src) + nsrcs * sizeof(rep.grec_src[0]);
	rep.csum = cksum(&rep, len);

	sd = socket(AF_INET, SOCK_RAW, IPPROTO_IGMP);
	if (sd < 0)
		err(1, "failed creating raw IGMP socket");

	if (setsockopt(sd, IPPROTO_IP, IP_MULTICAST_IF, &ifaddr, sizeof(ifaddr)))
		err(1, "failed selecting outbound interface");
	if (setsockopt(sd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)))
		err(1, "failed setting TTL");

	/* Bind the interface address, it has to be the report's source */
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr = ifaddr;
	if (bind(sd, (struct sockaddr *)&sin, sizeof(sin)))
		err(1, "failed binding to the interface address");

	memset(&dst, 0, sizeof(dst));
	dst.sin_family = AF_INET;
	if (inet_pton(AF_INET, IGMPV3_ALL_ROUTERS, &dst.sin_addr) != 1)
		errx(1, "invalid destination");

	if (sendto(sd, &rep, len, 0, (struct sockaddr *)&dst, sizeof(dst)) < 0)
		err(1, "failed sending report");

	close(sd);

	return 0;
}
