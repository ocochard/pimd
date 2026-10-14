/*
 * mtquery - ask a multicast router what mtrace and mrinfo ask it
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
 * A test tool for src/trace.c, not an mtrace(8): neither of the systems the
 * labs run on ships an mtrace or an mrinfo any more, and what a test wants
 * is the answer as fields rather than as a report for a person.
 *
 * Usage:
 *   mtquery -i IFADDR -s SOURCE -g GROUP -d DEST [-r RESPADDR] [-q QID]
 *           [-t TTL] [-n HOPS] [-T TTL] [-w SECS] trace ROUTER
 *   mtquery -q QID -p FILE trace ROUTER
 *   mtquery -i IFADDR [-T TTL] [-w SECS] neighbors ROUTER
 *
 * -T is the IP TTL of the request, 1 by default: ROUTER is a neighbour, and
 * FreeBSD's igmp_input() drops any IGMP but DVMRP's that arrives with more.
 * -t is the response TTL inside an mtrace query, which is another thing.
 *
 * -p FILE makes "trace" send nothing and read the answer out of a capture
 * instead, the last mtrace response with QID in a pcap file of Ethernet
 * frames, which is how a test reads the answer on FreeBSD: the response
 * comes from a router several hops away, so it arrives with a TTL above
 * one, and igmp_input() drops it before any socket of the querier's sees it.
 *
 * "trace" sends one mtrace query (IGMP type 0x1f, the draft-ietf-idmr-
 * traceroute-ipm format pimd answers) unicast to ROUTER, which is the last
 * hop router for DEST, and waits for the response (type 0x1e) carrying
 * query id QID.  It prints the query id and response TTL the answer came
 * back with, then one line per response block, the last hop router's
 * first:
 *
 *   qid 0a0b0c rttl 64 blocks 3
 *   hop 1 in 10.0.23.3 out 10.0.3.1 rmt 10.0.23.2 proto 3 fttl 1 flags 0
 *
 * "neighbors" sends one DVMRP ask-neighbors2 (IGMP type 0x13, code 5), the
 * request mrinfo makes, and prints each interface of the reply (code 6)
 * with its PIM neighbours:
 *
 *   iface 10.0.12.2 metric 1 ttl 1 flags 0x04 nbrs 1: 10.0.12.1
 *
 * Exits 0 with an answer, 2 with none within SECS (default 5), 1 on error.
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <err.h>
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define MT_QUERY		0x1f	/* IGMP_MTRACE_QUERY */
#define MT_REPLY		0x1e	/* IGMP_MTRACE_REPLY */
#define MT_DVMRP		0x13	/* IGMP_DVMRP */
#define MT_ASK_NEIGHBORS2	5
#define MT_NEIGHBORS2		6

#define MT_QLEN			16	/* source, dest, resp addr, ttl + qid */
#define MT_RLEN			32	/* one response block */

static uint16_t cksum(const uint8_t *p, size_t len)
{
	uint32_t sum = 0;
	size_t i;

	for (i = 0; i + 1 < len; i += 2)
		sum += (uint32_t)(p[i] << 8 | p[i + 1]);
	if (len & 1)
		sum += (uint32_t)(p[len - 1] << 8);
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return (uint16_t)~sum;
}

static uint32_t addr(const char *s, const char *what)
{
	struct in_addr a;

	if (inet_pton(AF_INET, s, &a) != 1)
		errx(1, "invalid %s %s", what, s);

	return a.s_addr;
}

static const char *fmt(const uint8_t *p)
{
	static char buf[4][INET_ADDRSTRLEN];
	static int n;
	struct in_addr a;

	memcpy(&a, p, sizeof(a));
	n = (n + 1) % 4;
	return inet_ntop(AF_INET, &a, buf[n], sizeof(buf[n]));
}

static uint32_t get32(const uint8_t *p)
{
	return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

/* The IGMP message of the last mtrace response for @qid in pcap file @path,
 * Ethernet framed, or NULL */
static const uint8_t *pcap_answer(const char *path, uint32_t qid, size_t *len)
{
	static uint8_t buf[65536], found[65536];
	uint8_t gh[24], rh[16];
	size_t flen = 0;
	int swap, have = 0;
	FILE *fp;

	fp = fopen(path, "r");
	if (!fp)
		err(1, "%s", path);
	if (fread(gh, 1, sizeof(gh), fp) != sizeof(gh))
		errx(1, "%s: no pcap header", path);
	if (gh[0] == 0xd4 && gh[1] == 0xc3 && gh[2] == 0xb2 && gh[3] == 0xa1)
		swap = 1;		/* little endian file */
	else if (gh[0] == 0xa1 && gh[1] == 0xb2 && gh[2] == 0xc3 && gh[3] == 0xd4)
		swap = 0;
	else
		errx(1, "%s: not a pcap file", path);

	while (fread(rh, 1, sizeof(rh), fp) == sizeof(rh)) {
		uint32_t incl = swap ? (uint32_t)rh[8] | (uint32_t)rh[9] << 8 |
					(uint32_t)rh[10] << 16 | (uint32_t)rh[11] << 24
				     : get32(rh + 8);
		const uint8_t *ip, *igmp;
		size_t hl, n;

		if (incl > sizeof(buf) || fread(buf, 1, incl, fp) != incl)
			break;
		if (incl < 14 + 20 || buf[12] != 0x08 || buf[13] != 0x00)
			continue;	/* Not IPv4 over Ethernet */

		ip = buf + 14;
		hl = (size_t)(ip[0] & 0x0f) * 4;
		if (ip[9] != IPPROTO_IGMP || incl < 14 + hl + 8 + MT_QLEN)
			continue;
		igmp = ip + hl;
		n = incl - 14 - hl;
		if (igmp[0] != MT_REPLY || (get32(igmp + 8 + 12) & 0xffffff) != qid)
			continue;

		memcpy(found, igmp, n);
		flen = n;
		have = 1;
	}
	fclose(fp);

	*len = flen;
	return have ? found : NULL;
}

static void usage(void)
{
	fprintf(stderr,
		"usage: mtquery -i IFADDR -s SOURCE -g GROUP -d DEST [-r RESPADDR] [-q QID]\n"
		"               [-t TTL] [-n HOPS] [-T TTL] [-w SECS] trace ROUTER\n"
		"       mtquery -i IFADDR [-T TTL] [-w SECS] neighbors ROUTER\n");
	exit(1);
}

/* The IGMP message of the answer, or NULL: the IP header stripped, the
 * type and the sender checked */
static const uint8_t *wait_answer(int sd, int secs, uint32_t router, int trace, uint32_t qid,
				  size_t *len)
{
	static uint8_t buf[65536];
	time_t until = time(NULL) + secs;

	for (;;) {
		struct pollfd pfd = { .fd = sd, .events = POLLIN };
		struct sockaddr_in from;
		socklen_t fromlen = sizeof(from);
		time_t left = until - time(NULL);
		const uint8_t *igmp;
		ssize_t n;
		size_t hl;

		if (left <= 0)
			return NULL;
		if (poll(&pfd, 1, (int)left * 1000) <= 0)
			continue;

		n = recvfrom(sd, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromlen);
		if (n < 20)
			continue;
		hl = (size_t)(buf[0] & 0x0f) * 4;
		if (hl < 20 || (size_t)n < hl + 8)
			continue;

		igmp = buf + hl;
		*len = (size_t)n - hl;

		if (trace) {
			if (igmp[0] != MT_REPLY || *len < 8 + MT_QLEN)
				continue;
			if ((get32(igmp + 8 + 12) & 0xffffff) != qid)
				continue;
		} else {
			if (igmp[0] != MT_DVMRP || igmp[1] != MT_NEIGHBORS2)
				continue;
			if (from.sin_addr.s_addr != router)
				continue;
		}

		return igmp;
	}
}

int main(int argc, char *argv[])
{
	uint32_t ifaddr = 0, source = 0, group = 0, dest = 0, raddr = 0, router;
	unsigned qid = 0, rttl = 64, hops = 32, secs = 5;
	int ipttl = 1;
	const char *pcap = NULL;
	uint8_t msg[8 + MT_QLEN];
	struct sockaddr_in to;
	const uint8_t *ans;
	size_t len, mlen;
	int c, sd, trace = 0;

	while ((c = getopt(argc, argv, "d:g:i:n:p:q:r:s:t:T:w:")) != -1) {
		switch (c) {
		case 'd': dest   = addr(optarg, "destination");	break;
		case 'g': group  = addr(optarg, "group");		break;
		case 'i': ifaddr = addr(optarg, "interface address");	break;
		case 'n': hops   = (unsigned)strtoul(optarg, NULL, 0);	break;
		case 'p': pcap   = optarg;				break;
		case 'q': qid    = (unsigned)strtoul(optarg, NULL, 0) & 0xffffff; break;
		case 'r': raddr  = addr(optarg, "response address");	break;
		case 's': source = addr(optarg, "source");		break;
		case 't': rttl   = (unsigned)strtoul(optarg, NULL, 0) & 0xff; break;
		case 'T': ipttl  = (int)strtol(optarg, NULL, 0);	break;
		case 'w': secs   = (unsigned)strtoul(optarg, NULL, 0);	break;
		default:  usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 2 || (!ifaddr && !pcap))
		usage();

	if (!strcmp(argv[0], "trace"))
		trace = 1;
	else if (!strcmp(argv[0], "neighbors"))
		trace = 0;
	else
		usage();
	router = addr(argv[1], "router");

	if (pcap) {
		if (!trace || !qid)
			usage();	/* the capture is read for one query's answer */
		ans = pcap_answer(pcap, qid, &len);
		if (!ans) {
			printf("no answer for qid %06x in %s\n", qid, pcap);
			return 2;
		}
		goto print;
	}

	if (trace && (!source || !group || !dest))
		usage();
	if (!raddr)
		raddr = ifaddr;
	if (!qid) {
		srandom((unsigned)getpid() ^ (unsigned)time(NULL));
		qid = ((unsigned)random() & 0xffffff) | 1;
	}

	sd = socket(AF_INET, SOCK_RAW, IPPROTO_IGMP);
	if (sd < 0)
		err(1, "socket");

	memset(&to, 0, sizeof(to));
	to.sin_family = AF_INET;
	to.sin_addr.s_addr = ifaddr;
	if (bind(sd, (struct sockaddr *)&to, sizeof(to)) < 0)
		err(1, "bind %s", fmt((uint8_t *)&ifaddr));
	if (setsockopt(sd, IPPROTO_IP, IP_TTL, &ipttl, sizeof(ipttl)) < 0)
		err(1, "IP_TTL %d", ipttl);

	memset(msg, 0, sizeof(msg));
	if (trace) {
		msg[0] = MT_QUERY;
		msg[1] = (uint8_t)hops;
		memcpy(msg + 4, &group, 4);
		memcpy(msg + 8, &source, 4);
		memcpy(msg + 12, &dest, 4);
		memcpy(msg + 16, &raddr, 4);
		msg[20] = (uint8_t)rttl;
		msg[21] = (uint8_t)(qid >> 16);
		msg[22] = (uint8_t)(qid >> 8);
		msg[23] = (uint8_t)qid;
		mlen = sizeof(msg);
	} else {
		msg[0] = MT_DVMRP;
		msg[1] = MT_ASK_NEIGHBORS2;
		mlen = 8;
	}
	{
		uint16_t s = cksum(msg, mlen);

		msg[2] = (uint8_t)(s >> 8);
		msg[3] = (uint8_t)s;
	}

	to.sin_addr.s_addr = router;
	if (sendto(sd, msg, mlen, 0, (struct sockaddr *)&to, sizeof(to)) != (ssize_t)mlen)
		err(1, "sendto %s", argv[1]);

	ans = wait_answer(sd, (int)secs, router, trace, qid, &len);
	if (!ans) {
		printf("no answer from %s in %us\n", argv[1], secs);
		return 2;
	}

print:
	if (trace) {
		const uint8_t *q = ans + 8;
		size_t off, nblocks = (len - 8 - MT_QLEN) / MT_RLEN;
		unsigned i;

		printf("qid %06x rttl %u blocks %zu\n", get32(q + 12) & 0xffffff, q[12],
		       nblocks);
		for (i = 0, off = 8 + MT_QLEN; off + MT_RLEN <= len; i++, off += MT_RLEN) {
			const uint8_t *r = ans + off;

			printf("hop %u in %s out %s rmt %s proto %u fttl %u flags %u\n", i + 1,
			       fmt(r + 4), fmt(r + 8), fmt(r + 12), r[28], r[29], r[31]);
		}
	} else {
		size_t off = 8;

		printf("level %08x\n", get32(ans + 4));
		while (off + 8 <= len) {
			const uint8_t *e = ans + off;
			unsigned n = e[7], k;

			printf("iface %s metric %u ttl %u flags 0x%02x nbrs %u:", fmt(e), e[4],
			       e[5], e[6], n);
			off += 8;
			for (k = 0; k < n && off + 4 <= len; k++, off += 4)
				printf(" %s", fmt(ans + off));
			printf("\n");
		}
	}

	return 0;
}
