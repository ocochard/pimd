/*
 * autorp - build and send one Auto-RP message
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
 * The mapping agent pimd does not have yet, and the announcing RP either:
 * one Auto-RP message of either type, with every field that can be got
 * wrong exposed as an option, sent once to the group it belongs to.
 *
 * This is what puts Auto-RP in front of a running daemon at all, the way
 * test/pimsend.c does for PIM and test/igmpv3.c for IGMP.  A lab scenario
 * uses it as the mapping agent of a domain whose only other router is
 * pimd; `-o FILE` writes the payload instead of sending it, which is how
 * the seeds of test/fuzz/corpus/autorp/ are built, and `-b FILE` sends the
 * bytes of a file verbatim, which is how a crasher goes back on the wire.
 *
 * The message is UDP to port 496, so it needs no root -- unlike everything
 * else in this directory -- and the payload is what pimd's parser is handed
 * byte for byte, since the kernel keeps the headers.
 */

#include <err.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define AUTORP_ANNOUNCE_GROUP	"224.0.1.39"
#define AUTORP_DISCOVERY_GROUP	"224.0.1.40"
#define AUTORP_PORT		496

#define AUTORP_VERSION		1
#define AUTORP_TYPE_ANNOUNCE	1
#define AUTORP_TYPE_MAPPING	2

#define MAX_PREFIXES		32
#define MAX_MSG			4096

/* How long a -c burst waits for a full send queue, per packet, as in
 * pimsend.c: 1ms at a time, up to a second. */
#define SEND_RETRY_US		1000
#define SEND_RETRIES		1000

struct prefix {
	struct in_addr	group;
	unsigned	masklen;
	int		negative;
};

static size_t put_prefix(uint8_t *p, const struct prefix *pfx)
{
	p[0] = pfx->negative ? 0x01 : 0x00;
	p[1] = (uint8_t)pfx->masklen;
	memcpy(p + 2, &pfx->group.s_addr, sizeof(pfx->group.s_addr));

	return 6;
}

static void write_file(const char *path, const void *buf, size_t len)
{
	FILE *fp;

	fp = fopen(path, "wb");
	if (!fp)
		err(1, "failed opening %s", path);
	if (fwrite(buf, 1, len, fp) != len)
		err(1, "failed writing %s", path);
	if (fclose(fp))
		err(1, "failed closing %s", path);
}

static size_t read_file(const char *path, void *buf, size_t len)
{
	size_t num;
	FILE *fp;

	fp = fopen(path, "rb");
	if (!fp)
		err(1, "failed opening %s", path);

	num = fread(buf, 1, len, fp);
	if (ferror(fp))
		err(1, "failed reading %s", path);
	fclose(fp);

	return num;
}

static int usage(int rc)
{
	fprintf(stderr,
		"usage: autorp [-i IFADDR] [-t TYPE] -r RP [-h HOLDTIME] [-c COUNT]\n"
		"              [-n] GROUP/LEN [GROUP/LEN ...]\n"
		"\n"
		"  -i IFADDR  Local address to send from, i.e. which link\n"
		"  -t TYPE    mapping (default, to " AUTORP_DISCOVERY_GROUP ", what every\n"
		"             router listens for) or announce (to " AUTORP_ANNOUNCE_GROUP ",\n"
		"             what a candidate RP sends to the mapping agents)\n"
		"  -r RP      The RP address the mapping names\n"
		"  -h SEC     Holdtime, default 180; 0 means never time out\n"
		"  -c COUNT   Send the message COUNT times, default 1\n"
		"  -T TTL     Outgoing TTL, default 15 as the draft's scope\n"
		"  -V VER     Version nibble, default 1.  For a message pimd has\n"
		"             to refuse\n"
		"  -R COUNT   Write COUNT in the RP count field rather than the\n"
		"             number of RP blocks actually built\n"
		"  -G COUNT   The same for the group count of the one RP block\n"
		"  -n         The next group prefix is a negative one (deny)\n"
		"  -o FILE    Write the payload instead of sending it.  Needs no\n"
		"             socket.  For seeding test/fuzz/corpus/autorp/\n"
		"  -b FILE    Send the bytes of FILE verbatim, for replaying a\n"
		"             crasher against a live daemon\n");

	return rc;
}

int main(int argc, char *argv[])
{
	struct prefix pfx[MAX_PREFIXES];
	uint8_t msg[MAX_MSG];
	struct sockaddr_in sin, dst;
	struct in_addr ifaddr, rp;
	const char *outfile = NULL;
	const char *bytefile = NULL;
	const char *group = AUTORP_DISCOVERY_GROUP;
	int type = AUTORP_TYPE_MAPPING;
	int holdtime = 180, count = 1, ttl = 15, version = AUTORP_VERSION;
	int rpcnt = -1, grpcnt = -1;
	int negative = 0, npfx = 0;
	uint8_t *p = msg;
	size_t len;
	int sd, i, c;

	memset(&ifaddr, 0, sizeof(ifaddr));
	memset(&rp, 0, sizeof(rp));
	memset(pfx, 0, sizeof(pfx));

	while ((c = getopt(argc, argv, "b:c:G:h:i:no:r:R:t:T:V:?")) != -1) {
		switch (c) {
		case 'b':
			bytefile = optarg;
			break;

		case 'c':
			count = atoi(optarg);
			break;

		case 'G':
			grpcnt = atoi(optarg);
			break;

		case 'h':
			holdtime = atoi(optarg);
			break;

		case 'i':
			if (inet_pton(AF_INET, optarg, &ifaddr) != 1)
				errx(1, "invalid interface address %s", optarg);
			break;

		case 'n':
			negative = 1;
			break;

		case 'o':
			outfile = optarg;
			break;

		case 'r':
			if (inet_pton(AF_INET, optarg, &rp) != 1)
				errx(1, "invalid RP address %s", optarg);
			break;

		case 'R':
			rpcnt = atoi(optarg);
			break;

		case 't':
			if (!strcmp(optarg, "mapping")) {
				type = AUTORP_TYPE_MAPPING;
				group = AUTORP_DISCOVERY_GROUP;
			} else if (!strcmp(optarg, "announce")) {
				type = AUTORP_TYPE_ANNOUNCE;
				group = AUTORP_ANNOUNCE_GROUP;
			} else {
				errx(1, "invalid type %s, want mapping or announce", optarg);
			}
			break;

		case 'T':
			ttl = atoi(optarg);
			break;

		case 'V':
			version = atoi(optarg);
			break;

		default:
			return usage(c == '?' ? 0 : 1);
		}
	}

	if (bytefile) {
		len = read_file(bytefile, msg, sizeof(msg));
		goto send;
	}

	for (i = optind; i < argc; i++) {
		char *slash, *arg = argv[i];

		if (!strcmp(arg, "-n")) {
			/* A deny between two prefixes rather than before
			 * them all, so that one message can carry both */
			negative = 1;
			continue;
		}

		if (npfx >= MAX_PREFIXES)
			errx(1, "too many group prefixes, max %d", MAX_PREFIXES);

		slash = strchr(arg, '/');
		if (!slash)
			errx(1, "%s is not GROUP/LEN", arg);
		*slash++ = 0;

		if (inet_pton(AF_INET, arg, &pfx[npfx].group) != 1)
			errx(1, "invalid group %s", arg);

		pfx[npfx].masklen  = (unsigned)atoi(slash);
		pfx[npfx].negative = negative;
		negative = 0;
		npfx++;
	}

	if (npfx == 0 || rp.s_addr == 0)
		return usage(1);

	/* Header: version and type, RP count, holdtime, reserved */
	*p++ = (uint8_t)(((version & 0x0f) << 4) | (type & 0x0f));
	*p++ = (uint8_t)(rpcnt >= 0 ? rpcnt : 1);
	*p++ = (uint8_t)((holdtime >> 8) & 0xff);
	*p++ = (uint8_t)(holdtime & 0xff);
	memset(p, 0, 4);
	p += 4;

	/* One RP block, then every prefix asked for */
	memcpy(p, &rp.s_addr, sizeof(rp.s_addr));
	p += 4;
	*p++ = 0x02;			/* PIM version 2 in the low bits */
	*p++ = (uint8_t)(grpcnt >= 0 ? grpcnt : npfx);

	for (i = 0; i < npfx; i++)
		p += put_prefix(p, &pfx[i]);

	len = (size_t)(p - msg);

send:
	if (outfile) {
		write_file(outfile, msg, len);
		return 0;
	}

	sd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sd < 0)
		err(1, "failed creating socket");

	if (ifaddr.s_addr != 0) {
		if (setsockopt(sd, IPPROTO_IP, IP_MULTICAST_IF, &ifaddr, sizeof(ifaddr)))
			err(1, "failed selecting outbound interface");

		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_addr   = ifaddr;
		if (bind(sd, (struct sockaddr *)&sin, sizeof(sin)))
			err(1, "failed binding to %s", inet_ntoa(ifaddr));
	}

	{
		unsigned char t = (unsigned char)ttl;

		if (setsockopt(sd, IPPROTO_IP, IP_MULTICAST_TTL, &t, sizeof(t)))
			err(1, "failed setting TTL");
	}

	memset(&dst, 0, sizeof(dst));
	dst.sin_family = AF_INET;
	dst.sin_port   = htons(AUTORP_PORT);
	if (inet_pton(AF_INET, group, &dst.sin_addr) != 1)
		errx(1, "invalid group %s", group);

	/* A full send queue is ENOBUFS here rather than a wait, and giving
	 * up on it would make a -c burst quietly shorter than it says on a
	 * loaded machine; see the same loop in pimsend.c. */
	for (i = 0; i < count; i++) {
		int tries = 0;

		while (sendto(sd, msg, len, 0, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
			if (errno == EINTR)
				continue;
			if (errno != ENOBUFS || tries++ >= SEND_RETRIES)
				err(1, "failed sending to %s", group);
			usleep(SEND_RETRY_US);
		}
	}

	close(sd);

	return 0;
}
