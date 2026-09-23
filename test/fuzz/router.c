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
 * A parser reached with nothing behind it tests almost nothing: a Join for a
 * group no RP answers for, an Assert about a source with no route, an IGMP
 * report on an interface with no neighbors and no querier all turn back
 * within a few lines.  So every harness in this directory runs the real
 * parsers inside a real pimd, and this file is that pimd: the parts of
 * main() and init_vifs() that do not want a kernel.
 *
 * What stands in for what:
 *
 *   - init_vifs() reads getifaddrs() and asks the kernel to add a vif.
 *     fuzz_vifs_reset() writes the vif table by hand instead, as
 *     config_vifs_from_kernel() would leave it on the router of
 *     fuzz/topology.h, register vif and all.
 *
 *   - init_igmp() and init_pim() allocate the receive and send buffers and
 *     then open raw sockets.  Here the buffers are allocated and the socket
 *     numbers are -1, which is deliberate rather than convenient: a harness
 *     must not be able to put a packet on a network, so every send it
 *     reaches has to fail.  --disable-exit-on-error is what makes that
 *     survivable, logit(LOG_ERR) otherwise calling exit(-1).
 *
 *   - init_routesock() opens a routing socket or a netlink socket.
 *     fuzz/mrib.c answers the RPF lookups instead, from a table that is the
 *     same on every machine; see its header for why the daemon's own file is
 *     not linked at all.
 *
 *   - config_vifs_from_file() is the daemon's own, reading a pimd.conf this
 *     file writes to a temporary file at start-up.  Nothing here pokes a
 *     configuration global by hand, so everything a keyword derives --
 *     recommended_rp_holdtime, the hash mask, the IGMP query interval, the
 *     state limits -- is derived the way the daemon derives it.
 *
 *   - add_static_rp() is main.c's and static; the loop in
 *     fuzz_router_build() is that function, marked entry included.
 *
 *   - restart() and cleanup() take the state down.  fuzz_router_reset() does
 *     it in their order, and is the half to get right: what an input made has
 *     to go back before the next input, or a run grows until libFuzzer calls
 *     it an out-of-memory and the growth is the harness rather than the
 *     parser.  Measure it, do not assume it -- see test/fuzz/README.md.
 *
 * And a prologue, which is not scaffolding but messages: three Hellos and
 * two Joins, through the daemon's own receive path, so that the state an
 * input lands on was built by the code that builds it in the field rather
 * than written into the structures from here.
 */

#include "defs.h"

#include "router.h"
#include "topology.h"

#include <fcntl.h>
#include <limits.h>
#include <unistd.h>

#ifndef CONTINUE_ON_ERROR
#error "The fuzz harnesses need --disable-exit-on-error: logit(LOG_ERR) exits"
#endif

/*
 * Where a packet ends, as far as the sanitizer is concerned.
 *
 * Both receive buffers are RECV_BUF_SIZE, a hundred and twenty-eight
 * kilobytes, and a packet is a few dozen bytes at the front of one.  So a
 * parser that reads past the end of the message it was handed reads stale
 * bytes of the same allocation, ASan sees a valid access, and the bug that
 * V5 of doc/rfc7761-compliance.md was -- a kernel upcall read for more than
 * had been delivered -- is invisible to a fuzzer however long it runs.
 *
 * Poisoning the rest of the buffer after each copy is what makes the end of
 * the packet a real boundary: an over-read is then a use-after-poison
 * report naming the function that did it.  Nothing in the daemon writes into
 * either receive buffer -- the read that fills it is the only writer, and
 * every parser downstream only reads -- so there is nothing legitimate to
 * trip over, and inet_cksum() mops up an odd trailing byte one byte at a
 * time rather than reading a short past the end (src/inet.c).
 *
 * MemorySanitizer needs the same thing said its way, and needs it more: the
 * buffers are calloc()ed, so every byte past the packet is a defined zero as
 * far as MSan is concerned and an over-read is a read of zeroes it has
 * nothing to say about.  Poisoning the tail is what turns it back into "use
 * of uninitialised value".  The two sanitizers cannot be built together, so
 * whichever one this is compiled with is the one the macros below reach.
 *
 * Without either of them this is nothing at all, and the harness still works.
 */
#if defined(__has_feature)
# if __has_feature(address_sanitizer)
#  define FUZZ_HAVE_ASAN 1
# endif
# if __has_feature(memory_sanitizer)
#  define FUZZ_HAVE_MSAN 1
# endif
#elif defined(__SANITIZE_ADDRESS__)
# define FUZZ_HAVE_ASAN 1
#endif

#ifdef FUZZ_HAVE_ASAN
#include <sanitizer/asan_interface.h>
#define fuzz_poison(p, n)	__asan_poison_memory_region(p, n)
#define fuzz_unpoison(p, n)	__asan_unpoison_memory_region(p, n)
#elif defined(FUZZ_HAVE_MSAN)
#include <sanitizer/msan_interface.h>
#define fuzz_poison(p, n)	__msan_poison(p, n)
#define fuzz_unpoison(p, n)	__msan_unpoison(p, n)
#else
#define fuzz_poison(p, n)	((void)(p), (void)(n))
#define fuzz_unpoison(p, n)	((void)(p), (void)(n))
#endif

/* The IP header a harness writes, and the TTL a Register copies */
#define FUZZ_TTL	64

/* What fits in the receive buffer behind an IP header of ours */
#define FUZZ_MSG_MAX	(RECV_BUF_SIZE - MIN_IP_HEADER_LEN)

const uint32_t fuzz_senders[4] = {
	FUZZ_NBR0_ADDR,
	FUZZ_NBR1_ADDR,
	FUZZ_NBR2_ADDR,
	FUZZ_STRANGER_ADDR,
};

/*
 * The configuration, as a file, because that is the parser's interface.
 * Both candidacies are load bearing: receive_pim_cand_rp_adv() returns
 * before parsing anything on a router that is not the BSR, and a Register
 * for a group this router is not the RP of is answered with a Register-Stop
 * and no state at all (RFC 7761 sec. 4.4.2), so without the first static RP
 * most of receive_pim_register() is out of reach.  The second one is what
 * makes the other answer reachable: 239.2.0.0/16 is a range this router is
 * *not* the RP for, so a Register for a group in it is refused the way a
 * stranger's is, and a packet from a source in it is one this router would
 * register to somebody else -- which is the whole of send_pim_register(),
 * reached from the IGMPMSG_WHOLEPKT upcall and from nowhere else.
 */
static const char fuzz_conf[] =
	"bsr-candidate 10.0.1.1 priority 5 interval 30\n"
	"rp-candidate 10.0.1.1 priority 20 interval 30\n"
	"rp-address 10.0.1.1 224.0.0.0/4\n"
	"rp-address 10.0.1.2 239.2.0.0/16\n"
	"spt-threshold packets 0 interval 100\n";

static char fuzz_conf_path[PATH_MAX];
static int  fuzz_conf_fd = -1;

static void fuzz_unlink(void)
{
	if (fuzz_conf_fd != -1)
		close(fuzz_conf_fd);
	if (fuzz_conf_path[0])
		unlink(fuzz_conf_path);
}

/*
 * Small builders, for the prologue only: what an input carries is never
 * built here.  Encoded addresses are RFC 7761 sec. 4.9.1, IPv4 and native
 * encoding.
 */
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
	p = put_short(p, (val >> 16) & 0xffff);

	return put_short(p, val & 0xffff);
}

/* Network order already, unlike everything above */
static uint8_t *put_addr(uint8_t *p, uint32_t addr)
{
	memcpy(p, &addr, sizeof(addr));

	return p + sizeof(addr);
}

static uint8_t *put_euaddr(uint8_t *p, uint32_t addr)
{
	p = put_byte(p, ADDRF_IPv4);
	p = put_byte(p, ADDRT_IPv4);

	return put_addr(p, addr);
}

static uint8_t *put_egaddr(uint8_t *p, uint32_t group)
{
	p = put_byte(p, ADDRF_IPv4);
	p = put_byte(p, ADDRT_IPv4);
	p = put_byte(p, 0);			/* No Bidir, no scope zone */
	p = put_byte(p, PIM_MAX_MSKLEN);

	return put_addr(p, group);
}

static uint8_t *put_esaddr(uint8_t *p, uint32_t source, unsigned flags)
{
	p = put_byte(p, ADDRF_IPv4);
	p = put_byte(p, ADDRT_IPv4);
	p = put_byte(p, flags);
	p = put_byte(p, PIM_MAX_MSKLEN);

	return put_addr(p, source);
}

/*
 * The checksum, in place and last, the way every sender computes it and the
 * way `pimsend -x` recomputes it after a mutation.  A Register is
 * checksummed over its header alone (RFC 7761 sec. 4.9.3), and pimd accepts
 * either for one, so this is what a conformant DR would send.
 */
static void fuzz_pim_cksum(uint8_t *msg, size_t len)
{
	size_t sumlen = len;
	uint16_t sum;

	if (len < sizeof(pim_header_t))
		return;

	msg[2] = 0;
	msg[3] = 0;

	if ((msg[0] & 0xf) == PIM_REGISTER &&
	    len >= sizeof(pim_header_t) + sizeof(pim_register_t))
		sumlen = sizeof(pim_header_t) + sizeof(pim_register_t);

	sum = inet_cksum((uint16_t *)msg, sumlen);
	memcpy(msg + 2, &sum, sizeof(sum));
}

void fuzz_buf_load(char *buf, const void *pkt, size_t len)
{
	fuzz_unpoison(buf, RECV_BUF_SIZE);

	if (len)
		memcpy(buf, pkt, len);

	if (len < RECV_BUF_SIZE)
		fuzz_poison(buf + len, RECV_BUF_SIZE - len);
}

void fuzz_pim_feed(uint32_t src, uint32_t dst, const uint8_t *msg, size_t len)
{
	struct ip *ip;
	uint8_t *body;

	if (len > FUZZ_MSG_MAX)
		return;

	fuzz_unpoison(pim_recv_buf, RECV_BUF_SIZE);

	ip = (struct ip *)pim_recv_buf;
	memset(ip, 0, MIN_IP_HEADER_LEN);
	ip->ip_v   = IPVERSION;
	ip->ip_hl  = MIN_IP_HEADER_LEN >> 2;
	ip->ip_ttl = FUZZ_TTL;
	ip->ip_p   = IPPROTO_PIM;
	ip->ip_len = htons(MIN_IP_HEADER_LEN + len);
	ip->ip_src.s_addr = src;
	ip->ip_dst.s_addr = dst;

	body = (uint8_t *)pim_recv_buf + MIN_IP_HEADER_LEN;
	memcpy(body, msg, len);
	fuzz_pim_cksum(body, len);

	/* And the packet ends here, whatever a parser makes of a length
	 * field inside it */
	if (MIN_IP_HEADER_LEN + len < RECV_BUF_SIZE)
		fuzz_poison(pim_recv_buf + MIN_IP_HEADER_LEN + len,
			    RECV_BUF_SIZE - MIN_IP_HEADER_LEN - len);

	accept_pim((ssize_t)(MIN_IP_HEADER_LEN + len));
}

/*
 * A Hello with the three options every pimd sends: Holdtime, DR Priority
 * and Generation ID (RFC 7761 sec. 4.9.2).  The GenID differs per sender so
 * that a fuzzed Hello claiming another one is a neighbor that has restarted,
 * and the DR Priority is the caller's because it decides who the DR is: this
 * router's addresses are the lowest on both links, so with every neighbor at
 * the default priority it would lose both elections and every path behind
 * "am I the DR for this subnet" -- the register side of process_cache_miss()
 * among them -- would be dead code.
 */
static void fuzz_send_hello(uint32_t src, unsigned genid, unsigned dr_prio)
{
	uint8_t msg[64];
	uint8_t *p = msg;

	p = put_byte(p, (PIM_VERSION << 4) | PIM_HELLO);
	p = put_byte(p, 0);
	p = put_short(p, 0);

	p = put_short(p, PIM_HELLO_HOLDTIME);
	p = put_short(p, PIM_HELLO_HOLDTIME_LEN);
	p = put_short(p, (unsigned)PIM_TIMER_HELLO_HOLDTIME);

	p = put_short(p, PIM_HELLO_DR_PRIO);
	p = put_short(p, PIM_HELLO_DR_PRIO_LEN);
	p = put_long(p, dr_prio);

	p = put_short(p, PIM_HELLO_GENID);
	p = put_short(p, PIM_HELLO_GENID_LEN);
	p = put_long(p, genid);

	fuzz_pim_feed(src, allpimrouters_group, msg, (size_t)(p - msg));
}

/*
 * A Join with one group set and one joined source, which is a Join(*,G)
 * when the source is the RP carrying the WC and RPT bits and a Join(S,G)
 * otherwise (sec. 4.9.5.1).  Sent to the group, upstream neighbor this
 * router, so the receiver acts on it.
 */
static void fuzz_send_join(uint32_t src, uint32_t upstream, uint32_t source, unsigned flags)
{
	uint8_t msg[64];
	uint8_t *p = msg;

	p = put_byte(p, (PIM_VERSION << 4) | PIM_JOIN_PRUNE);
	p = put_byte(p, 0);
	p = put_short(p, 0);

	p = put_euaddr(p, upstream);
	p = put_byte(p, 0);			/* Reserved */
	p = put_byte(p, 1);			/* One group set */
	p = put_short(p, (unsigned)PIM_JOIN_PRUNE_HOLDTIME);

	p = put_egaddr(p, htonl(FUZZ_GROUP));
	p = put_short(p, 1);			/* One joined source */
	p = put_short(p, 0);			/* No pruned sources */
	p = put_esaddr(p, source, flags);

	fuzz_pim_feed(src, allpimrouters_group, msg, (size_t)(p - msg));
}

/*
 * The vif table config_vifs_from_kernel() would have left behind on this
 * router: the register vif in the slot reserved for it, addressed out of
 * the first physical interface the way init_reg_vif() does it, and one
 * interface per subnet.
 */
static void fuzz_vifs_reset(void)
{
	struct uvif *v;
	vifi_t vifi;

	for (vifi = 0, v = uvifs; vifi < MAXVIFS; ++vifi, ++v) {
		struct vif_acl *acl;
		struct listaddr *a, *b;

		/* zero_vif() nulls this one without freeing it; stop_vif()
		 * is what frees it, and there is no kernel here to stop a
		 * vif against */
		while (v->uv_acl) {
			acl = v->uv_acl;
			v->uv_acl = acl->acl_next;
			free(acl);
		}

		/* The IGMP memberships, the same way and for the same
		 * reason: a group and every source under it, each with
		 * timers of its own (stop_vif(), src/vif.c)
		 */
		while ((a = v->uv_groups)) {
			v->uv_groups = a->al_next;

			while ((b = a->al_sources)) {
				a->al_sources = b->al_next;

				if (b->al_timerid)
					timer_clear(b->al_timerid);
				if (b->al_versiontimer)
					timer_clear(b->al_versiontimer);
				free(b);
			}

			if (a->al_timerid)
				timer_clear(a->al_timerid);
			if (a->al_query)
				timer_clear(a->al_query);
			if (a->al_versiontimer)
				timer_clear(a->al_versiontimer);
			free(a);
		}

		/* And the querier, which is an allocation of its own that
		 * zero_vif() likewise only nulls
		 */
		if (v->uv_querier) {
			free(v->uv_querier);
			v->uv_querier = NULL;
		}

		zero_vif(v, vifi == PIMREG_VIF);
	}

	v = &uvifs[FUZZ_VIF0];
	strlcpy(v->uv_name, FUZZ_IF0_NAME, sizeof(v->uv_name));
	v->uv_lcl_addr   = htonl(FUZZ_IF0_ADDR);
	v->uv_subnetmask = htonl(FUZZ_MASK24);
	v->uv_subnet     = v->uv_lcl_addr & v->uv_subnetmask;
	v->uv_ifindex    = FUZZ_VIF0;

	v = &uvifs[FUZZ_VIF1];
	strlcpy(v->uv_name, FUZZ_IF1_NAME, sizeof(v->uv_name));
	v->uv_lcl_addr   = htonl(FUZZ_IF1_ADDR);
	v->uv_subnetmask = htonl(FUZZ_MASK24);
	v->uv_subnet     = v->uv_lcl_addr & v->uv_subnetmask;
	v->uv_ifindex    = FUZZ_VIF1;

	v = &uvifs[PIMREG_VIF];
	strlcpy(v->uv_name, "pimreg", sizeof(v->uv_name));
	v->uv_flags      = VIFF_REGISTER;
	v->uv_threshold  = MINTTL;
	v->uv_lcl_addr   = uvifs[FUZZ_VIF0].uv_lcl_addr;
	v->uv_ifindex    = 0;

	numvifs          = FUZZ_NUMVIFS;
	total_interfaces = FUZZ_NUMVIFS;
}

void fuzz_router_reset(void)
{
	struct rp_hold *rph, *rph_next;
	struct uvif *v;
	vifi_t vifi;

	/* The neighbors first, since deleting one walks the routing entries
	 * that name it as their upstream
	 */
	for (vifi = 0, v = uvifs; vifi < MAXVIFS; ++vifi, ++v) {
		while (v->uv_pim_neighbors)
			delete_pim_nbr(v->uv_pim_neighbors);
	}

	/* Then the routing table, which this frees whole and rebuilds empty,
	 * kernel cache mirrors and state limit counts with it
	 */
	init_pim_mrt();

	delete_rp_list(&cand_rp_list, &grp_mask_list);
	delete_rp_list(&segmented_cand_rp_list, &segmented_grp_mask_list);

	/* The static RP list is what add_static_rp() reads and only
	 * del_static_rp() frees, both of them in main.c; parsing the file
	 * again would otherwise stack another copy of every rp-address line
	 * onto it for as long as the run lasts.
	 */
	for (rph = g_rp_hold; rph; rph = rph_next) {
		rph_next = rph->next;
		free(rph);
	}
	g_rp_hold = NULL;

	/* The interfaces last, memberships and all, and then the callout
	 * queue: timer_exit() frees what each entry owns, which is where the
	 * triggered Hello, the Join timers and the IGMP callbacks are, and
	 * leaves the queue as timer_init() would.
	 */
	fuzz_vifs_reset();
	timer_exit();
}

void fuzz_router_build(void)
{
	struct rp_hold *rph;

	config_phyints_from_file(1);
	config_vifs_from_file();

	init_rp_and_bsr();

	/* add_static_rp(), src/main.c: marked, or the first Bootstrap for
	 * 224.0.0.0/4 collects it through the fragment tag
	 */
	for (rph = g_rp_hold; rph; rph = rph->next) {
		rp_grp_entry_t *entry;

		entry = add_rp_grp_entry(&cand_rp_list, &grp_mask_list,
					 rph->address, 1, (uint16_t)0xffffff,
					 rph->group, rph->mask,
					 curr_bsr_hash_mask, curr_bsr_fragment_tag);
		if (entry)
			entry->is_static = TRUE;
	}

	/* The prologue: a neighbor on every link, and a shared tree and a
	 * shortest path tree for the one group, joined from the second link.
	 */
	/* One link this router is the DR of and one it is not: the two
	 * neighbors on the first give up the election on priority, and the
	 * one on the second wins it on its address.
	 */
	fuzz_send_hello(htonl(FUZZ_NBR0_ADDR), 0x1000, 0);
	fuzz_send_hello(htonl(FUZZ_NBR1_ADDR), 0x2000, 0);
	fuzz_send_hello(htonl(FUZZ_NBR2_ADDR), 0x3000, PIM_HELLO_DR_PRIO_DEFAULT);

	fuzz_send_join(htonl(FUZZ_NBR2_ADDR), htonl(FUZZ_IF1_ADDR),
		       htonl(FUZZ_IF0_ADDR), USADDR_S_BIT | USADDR_WC_BIT | USADDR_RP_BIT);
	fuzz_send_join(htonl(FUZZ_NBR2_ADDR), htonl(FUZZ_IF1_ADDR),
		       htonl(FUZZ_SOURCE), USADDR_S_BIT);
}

void fuzz_router_init(char *name)
{
	size_t len = sizeof(fuzz_conf) - 1;
	const char *tmp;

	/* What main() would have set, and what logit() reads.  A parser that
	 * writes a line of stderr per input runs at a thousand executions a
	 * second instead of tens of thousands, and LOG_EMERG is the whole of
	 * the silence: logit() writes to stderr until somebody asks for
	 * syslog, and prints only what is at least as bad as loglevel.
	 *
	 * FUZZ_DEBUG in the environment puts it all back, which is the answer
	 * to "did this input reach a parser at all": a harness whose state is
	 * wrong refuses every message at the first test and looks exactly as
	 * healthy as one that works.  Run a replay driver over its corpus
	 * that way after touching anything here.
	 */
	prognm   = name;
	ident    = prognm;
	debug    = getenv("FUZZ_DEBUG") ? DEBUG_ALL : 0;
	loglevel = getenv("FUZZ_DEBUG") ? LOG_DEBUG : LOG_EMERG;

	/* No socket of any kind: a send that has to fail is the point, since
	 * a harness must not be able to put anything on a network.
	 */
	igmp_socket = -1;
	pim_socket  = -1;
	udp_socket  = -1;

	/* What init_pim() and init_igmp() allocate before they touch a
	 * socket, and the addresses they work out
	 */
	pim_recv_buf  = calloc(1, RECV_BUF_SIZE);
	pim_send_buf  = calloc(1, SEND_BUF_SIZE);
	igmp_recv_buf = calloc(1, RECV_BUF_SIZE);
	igmp_send_buf = calloc(1, SEND_BUF_SIZE);
	if (!pim_recv_buf || !pim_send_buf || !igmp_recv_buf || !igmp_send_buf) {
		perror("calloc");
		exit(1);
	}

	allpimrouters_group = htonl(INADDR_ALL_PIM_ROUTERS);
	allhosts_group	    = htonl(INADDR_ALLHOSTS_GROUP);
	allrouters_group    = htonl(INADDR_ALLRTRS_GROUP);
	allreports_group    = htonl(INADDR_ALLRPTS_GROUP);

	tmp = getenv("TMPDIR");
	if (!tmp || !*tmp)
		tmp = "/tmp";
	snprintf(fuzz_conf_path, sizeof(fuzz_conf_path), "%s/pimd-fuzz-conf-XXXXXX", tmp);

	fuzz_conf_fd = mkstemp(fuzz_conf_path);
	if (fuzz_conf_fd == -1) {
		perror("mkstemp");
		exit(1);
	}

	if (write(fuzz_conf_fd, fuzz_conf, len) != (ssize_t)len) {
		perror("write");
		exit(1);
	}

	atexit(fuzz_unlink);
	config_file = fuzz_conf_path;

	timer_init();
	fuzz_vifs_reset();
}
