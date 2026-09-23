/*
 * autorp.c - Auto-RP discovery, the listening half
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
 * Auto-RP is the other way a router can be told which RP serves which
 * groups: Cisco's, from 1998, specified in doc/pim-autorp-spec01.txt and
 * spoken by IOS, NX-OS and FRR.  A domain that runs it has RPs announcing
 * themselves to 224.0.1.39 and one or more "mapping agents" resolving the
 * conflicts and announcing the result to 224.0.1.40, where every router
 * listens.  Both messages are UDP datagrams to port 496 and share one
 * format.
 *
 * This file is the listening half, which is what makes pimd usable in a
 * domain that already runs Auto-RP: the mappings it hears go into the same
 * RP set the BSR fills, so rp_match(), the remapping of groups and
 * `pimctl show rp` are one code path with one more source behind them.
 * Announcing and the mapping agent are separate work; see
 * aidd_docs/plans/autorp.md.
 *
 * Four things worth knowing before reading on:
 *
 *   - The socket is the parent's.  Port 496 is privileged, and the
 *     unprivileged half cannot bind it -- nor call socket(2) at all under
 *     the Linux filter -- so PRIV_SOCK_AUTORP is created *and bound* on the
 *     other side of privsep.c and arrives here as a descriptor.
 *
 *   - Nothing here trusts a count.  RP count and group count are bytes off
 *     the wire and say how much is supposed to follow; what is actually
 *     there is what the buffer says, and every step checks that first.
 *
 *   - A negative prefix means "dense mode" in the draft (sec. 6), and pimd
 *     has no dense mode.  It is read here as "no RP for this range", which
 *     is the closest honest thing a sparse-mode daemon can do, and sec. 6's
 *     rule that one longest match settles it -- a negative match being
 *     final even where a shorter positive prefix covers the group -- is
 *     what autorp_denied() implements.
 *
 *   - What is learned is mirrored in this file as well as pushed into the
 *     RP set.  The mirror is what `pimctl show autorp` prints and what the
 *     longest-match deny test walks; the RP set holds no entry at all for a
 *     denied range, so it cannot answer that question by itself.
 */

#include "defs.h"
#include "autorp.h"

#include <netinet/udp.h>

/*
 * One mapping as it was heard: an RP, a prefix, and whether the prefix was
 * denied.  Deny entries are the reason this list exists rather than being
 * an accident of it -- the RP set has nothing to hold them.
 */
struct autorp_map {
    struct autorp_map	*next;
    uint32_t		 rp_addr;	/* 0 for a deny, which names no RP */
    uint32_t		 group_addr;
    uint32_t		 group_mask;
    uint8_t		 masklen;
    uint8_t		 negative;
    uint16_t		 holdtime;	/* seconds, 0 is forever	   */
    uint32_t		 origin;	/* the agent we heard it from	   */
};

static struct autorp_map *autorp_maps = NULL;

/* Said once per run of the limit below, and again after a reload */
static int autorp_limit_said = FALSE;

/*
 * How much of the RP set Auto-RP may make this router hold.  Nothing
 * authenticates a mapping message and nothing bounds what one can say: RP
 * count and group count are a byte each, so a single 1.5K datagram names
 * up to 65025 (RP, prefix) pairs, and a sender free to vary the addresses
 * can keep making new ones.  A cap, like the three pimd already has on
 * state other routers create, and the count is in `pimctl show status`
 * beside them.
 */
uint32_t autorp_entries = 0;
uint32_t autorp_limit   = PIM_AUTORP_LIMIT;

/* The datagrams arrive here, and the buffer is this file's */
static char *autorp_buf = NULL;

int autorp_socket  = -1;
int autorp_enabled = TRUE;	/* `no autorp discovery' turns it off */

static void autorp_read(int sd);

/*
 * Every mapping this router has heard goes away.  Called from stop_autorp()
 * and before a reload, since a mapping that is no longer announced must not
 * outlive the daemon's picture of the domain -- restart() rebuilds the RP
 * set from nothing, and this list would otherwise be the one thing that
 * remembered a withdrawn prefix.
 */
static void autorp_maps_clear(void)
{
    struct autorp_map *map, *next;

    for (map = autorp_maps; map; map = next) {
	next = map->next;
	free(map);
    }

    autorp_maps = NULL;
    autorp_entries = 0;
    autorp_limit_said = FALSE;
}

/*
 * The mirror entry for one (RP, prefix), made if it is new.  Keyed on the
 * prefix and the RP together: two RPs may serve the same range, which is
 * what the RP set's own hash is for, and a deny (RP 0.0.0.0) is a key of
 * its own so that it can replace nothing else.
 */
static struct autorp_map *autorp_map_get(uint32_t rp_addr, uint32_t group_addr,
					 uint32_t group_mask, uint8_t masklen)
{
    struct autorp_map *map;

    for (map = autorp_maps; map; map = map->next) {
	if (map->rp_addr == rp_addr && map->group_addr == group_addr &&
	    map->group_mask == group_mask)
	    return map;
    }

    if (autorp_entries >= autorp_limit) {
	if (!autorp_limit_said) {
	    logit(LOG_WARNING, 0, "Auto-RP mapping limit of %u reached, refusing %s for %s"
		  " (autorp-limit in %s raises it)", autorp_limit,
		  inet_fmt(rp_addr, s1, sizeof(s1)),
		  netname(group_addr, group_mask), config_file);
	    autorp_limit_said = TRUE;
	}

	return NULL;
    }

    map = calloc(1, sizeof(*map));
    if (!map) {
	logit(LOG_WARNING, errno, "Failed allocating Auto-RP mapping");
	return NULL;
    }
    autorp_entries++;

    map->rp_addr	= rp_addr;
    map->group_addr	= group_addr;
    map->group_mask	= group_mask;
    map->masklen	= masklen;
    map->next		= autorp_maps;
    autorp_maps		= map;

    return map;
}

/*
 * Sec. 6, rule 1: one longest match decides, and if what it lands on is a
 * negative prefix the group has no RP -- not even from a shorter positive
 * prefix, which is the rule that makes a deny worth anything.  A tie
 * between a positive and a negative prefix of the same length goes to the
 * negative one, rule 2.
 */
int autorp_denied(uint32_t group)
{
    struct autorp_map *map;
    int best_len = -1;
    int denied = FALSE;

    for (map = autorp_maps; map; map = map->next) {
	if ((group & map->group_mask) != (map->group_addr & map->group_mask))
	    continue;

	if ((int)map->masklen < best_len)
	    continue;

	if ((int)map->masklen > best_len) {
	    best_len = map->masklen;
	    denied = map->negative;
	    continue;
	}

	/* Same length: a deny wins the tie */
	if (map->negative)
	    denied = TRUE;
    }

    return denied;
}

/*
 * One mapping into the RP set, which is where every consumer reads it
 * from.  The holdtime and the origin are written here rather than passed
 * into add_rp_grp_entry(): that function is the BSR's, and its rule that a
 * stored entry it did not create keeps its own holdtime is what stops a
 * Bootstrap from making pimd.conf's RP mortal.  An Auto-RP message
 * refreshing its own entry is a different thing, and this is it.
 */
static void autorp_apply(uint32_t rp_addr, uint16_t holdtime,
			 uint32_t group_addr, uint32_t group_mask)
{
    rp_grp_entry_t *entry;

    entry = add_rp_grp_entry(&cand_rp_list, &grp_mask_list,
			     rp_addr, 1, holdtime,
			     group_addr, group_mask,
			     curr_bsr_hash_mask, curr_bsr_fragment_tag);
    if (!entry)
	return;

    entry->origin   = RP_ORIGIN_AUTORP;
    entry->holdtime = holdtime;
}

/*
 * A group prefix, of either sign, from one RP block of one message.
 */
static void autorp_learn(uint32_t from, uint32_t rp_addr, uint16_t holdtime,
			 uint32_t group_addr, uint8_t masklen, int negative)
{
    struct autorp_map *map;
    uint32_t group_mask;

    if (masklen > 32) {
	IF_DEBUG(DEBUG_PIM_CAND_RP)
	    logit(LOG_DEBUG, 0, "Auto-RP: mask length %u from %s is not a prefix",
		  masklen, inet_fmt(from, s1, sizeof(s1)));
	return;
    }

    MASKLEN_TO_MASK(masklen, group_mask);
    group_addr &= group_mask;

    if (!IN_MULTICAST(ntohl(group_addr))) {
	IF_DEBUG(DEBUG_PIM_CAND_RP)
	    logit(LOG_DEBUG, 0, "Auto-RP: %s is not a group prefix, from %s",
		  netname(group_addr, group_mask), inet_fmt(from, s1, sizeof(s1)));
	return;
    }

    map = autorp_map_get(negative ? INADDR_ANY_N : rp_addr,
			 group_addr, group_mask, masklen);
    if (!map)
	return;

    map->negative = negative ? TRUE : FALSE;
    map->holdtime = holdtime;
    map->origin   = from;

    IF_DEBUG(DEBUG_PIM_CAND_RP) {
	/* A deny names no RP, so do not print one: the row it makes says
	 * the groups have none, not that they have that one. */
	if (negative)
	    logit(LOG_DEBUG, 0, "Auto-RP: deny for %s, holdtime %u, from %s",
		  netname(group_addr, group_mask), holdtime,
		  inet_fmt(from, s1, sizeof(s1)));
	else
	    logit(LOG_DEBUG, 0, "Auto-RP: RP %s for %s, holdtime %u, from %s",
		  inet_fmt(rp_addr, s2, sizeof(s2)),
		  netname(group_addr, group_mask), holdtime,
		  inet_fmt(from, s1, sizeof(s1)));
    }

    if (negative) {
	/* Nothing to put in the RP set: the range has no RP, which is what
	 * autorp_denied() answers for.  An RP that used to serve it ages
	 * out of the set on its own holdtime.
	 */
	return;
    }

    autorp_apply(rp_addr, holdtime, group_addr, group_mask);
}

/*
 * One Auto-RP datagram, from `from'.  The payload only: the UDP header is
 * the kernel's, and what the socket hands over starts at the Auto-RP
 * version byte.
 *
 * Declared in defs.h so that the fuzz harness can call it, for the reason
 * accept_pim() and accept_igmp() are: everything a message has to survive
 * before a mapping is believed lives here, and a harness that reproduced
 * any of it would keep a copy to fall out of step.
 */
void accept_autorp(uint32_t from, char *buf, size_t len)
{
    uint8_t *p = (uint8_t *)buf;
    unsigned type, version, rpcnt;
    uint16_t holdtime;
    size_t left = len;

    if (!autorp_enabled)
	return;

    if (left < AUTORP_HDR_LEN) {
	IF_DEBUG(DEBUG_PIM_CAND_RP)
	    logit(LOG_DEBUG, 0, "Auto-RP: %zu bytes from %s is shorter than a header",
		  len, inet_fmt(from, s1, sizeof(s1)));
	return;
    }

    version  = AUTORP_VERSION_OF(p[0]);
    type     = AUTORP_TYPE_OF(p[0]);
    rpcnt    = p[1];
    holdtime = (uint16_t)((p[2] << 8) | p[3]);
    /* p[4..7] reserved, sent as 0 and ignored on reception, sec. 4 */

    p    += AUTORP_HDR_LEN;
    left -= AUTORP_HDR_LEN;

    if (version != AUTORP_VERSION) {
	IF_DEBUG(DEBUG_PIM_CAND_RP)
	    logit(LOG_DEBUG, 0, "Auto-RP: version %u from %s, expected %u",
		  version, inet_fmt(from, s1, sizeof(s1)), AUTORP_VERSION);
	return;
    }

    /*
     * An announcement is addressed to the mapping agents and says what one
     * RP is willing to serve; a router that is not an agent has no business
     * believing it, or two RPs claiming the same range would both be in
     * this router's RP set with nothing having resolved them.  Only a
     * mapping message is the resolved answer.
     */
    if (type != AUTORP_TYPE_MAPPING) {
	IF_DEBUG(DEBUG_PIM_CAND_RP)
	    logit(LOG_DEBUG, 0, "Auto-RP: type %u from %s is not an RP-mapping message",
		  type, inet_fmt(from, s1, sizeof(s1)));
	return;
    }

    while (rpcnt-- > 0) {
	uint32_t rp_addr;
	unsigned grpcnt;

	if (left < AUTORP_RP_LEN) {
	    IF_DEBUG(DEBUG_PIM_CAND_RP)
		logit(LOG_DEBUG, 0, "Auto-RP: message from %s ends inside an RP block",
		      inet_fmt(from, s1, sizeof(s1)));
	    return;
	}

	memcpy(&rp_addr, p, sizeof(rp_addr));
	grpcnt = p[5];
	/* p[4] holds the RP's PIM version in its low two bits, which pimd
	 * has no use for: it speaks PIMv2 and an RP that does not is not
	 * one it can register to anyway. */

	p    += AUTORP_RP_LEN;
	left -= AUTORP_RP_LEN;

	while (grpcnt-- > 0) {
	    uint32_t group_addr;
	    uint8_t masklen;
	    int negative;

	    if (left < AUTORP_GRP_LEN) {
		IF_DEBUG(DEBUG_PIM_CAND_RP)
		    logit(LOG_DEBUG, 0, "Auto-RP: message from %s ends inside a group prefix",
			  inet_fmt(from, s1, sizeof(s1)));
		return;
	    }

	    negative = AUTORP_GRP_NEGATIVE(p[0]);
	    masklen  = p[1];
	    memcpy(&group_addr, p + 2, sizeof(group_addr));

	    p    += AUTORP_GRP_LEN;
	    left -= AUTORP_GRP_LEN;

	    if (!inet_valid_host(rp_addr)) {
		IF_DEBUG(DEBUG_PIM_CAND_RP)
		    logit(LOG_DEBUG, 0, "Auto-RP: %s from %s is not a valid RP address",
			  inet_fmt(rp_addr, s2, sizeof(s2)), inet_fmt(from, s1, sizeof(s1)));
		continue;
	    }

	    autorp_learn(from, rp_addr, holdtime, group_addr, masklen, negative);
	}
    }
}

/*
 * What the mappings are worth in seconds, aged from main.c's timer beside
 * everything else that ages.  A mapping that is not refreshed goes, and
 * with it the deny that may be the only reason a group has no RP; the RP
 * set entry behind a positive one ages on its own holdtime in age_misc().
 */
void age_autorp(void)
{
    struct autorp_map *map, *next, *prev = NULL;

    for (map = autorp_maps; map; map = next) {
	next = map->next;

	if (map->holdtime == AUTORP_HOLDTIME_FOREVER) {
	    prev = map;
	    continue;
	}

	if (map->holdtime > TIMER_INTERVAL) {
	    map->holdtime -= TIMER_INTERVAL;
	    prev = map;
	    continue;
	}

	IF_DEBUG(DEBUG_PIM_CAND_RP)
	    logit(LOG_DEBUG, 0, "Auto-RP: %s for %s timed out",
		  map->negative ? "deny" : inet_fmt(map->rp_addr, s1, sizeof(s1)),
		  netname(map->group_addr, map->group_mask));

	if (prev)
	    prev->next = next;
	else
	    autorp_maps = next;
	free(map);
	autorp_entries--;
    }
}

/*
 * The datagram handler the event loop calls.  One message per call, the
 * sender taken from the kernel rather than from anything in the payload.
 */
static void autorp_read(int sd)
{
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);
    ssize_t len;

    memset(&from, 0, sizeof(from));
    len = recvfrom(sd, autorp_buf, RECV_BUF_SIZE, 0,
		   (struct sockaddr *)&from, &fromlen);
    if (len < 0) {
	if (errno == EINTR || errno == EAGAIN)
	    return;

	logit(LOG_WARNING, errno, "Failed recvfrom() on the Auto-RP socket");
	return;
    }

    accept_autorp(from.sin_addr.s_addr, autorp_buf, (size_t)len);
}

/*
 * Join CISCO-RP-DISCOVERY on every interface pimd runs on, which is what
 * makes the datagrams arrive at all.  The register vif is not one: it is a
 * tunnel to the RP and no Auto-RP speaker is on the other end of it.
 */
static void autorp_join(void)
{
    struct uvif *uv;
    vifi_t vifi;

    for (vifi = 0, uv = uvifs; vifi < numvifs; vifi++, uv++) {
	if (uv->uv_flags & (VIFF_REGISTER | VIFF_DISABLED | VIFF_DOWN))
	    continue;

	k_join(autorp_socket, htonl(AUTORP_DISCOVERY_GROUP), uv);
    }
}

void init_autorp(void)
{
    struct sockaddr_in sin;
    int sd, on = 1;

    if (!autorp_enabled)
	return;

    if (!autorp_buf) {
	autorp_buf = calloc(1, RECV_BUF_SIZE);
	if (!autorp_buf) {
	    logit(LOG_ERR, errno, "Ran out of memory in init_autorp()");
	    return;
	}
    }

    /*
     * Under separation the parent has bound this already: port 496 is
     * privileged and the child is not, quite apart from socket(2) being
     * off the filter's list.
     */
    sd = priv_socket(PRIV_SOCK_AUTORP);
    if (sd < 0) {
	sd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sd < 0) {
	    logit(LOG_WARNING, errno, "Failed creating the Auto-RP socket, discovery disabled");
	    return;
	}

	/* Several routers on one host in a lab, and a mapping agent of our
	 * own later on, both want the port more than once */
	if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0)
	    logit(LOG_WARNING, errno, "Failed setting SO_REUSEADDR on the Auto-RP socket");

	memset(&sin, 0, sizeof(sin));
	sin.sin_family      = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_port        = htons(AUTORP_PORT);
	if (bind(sd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
	    logit(LOG_WARNING, errno, "Failed binding the Auto-RP socket to port %d, discovery disabled",
		  AUTORP_PORT);
	    close(sd);
	    return;
	}
    }

    autorp_socket = sd;
    autorp_join();

    if (register_input_handler(autorp_socket, autorp_read) < 0)
	logit(LOG_ERR, 0, "Failed registering the Auto-RP handler");

    logit(LOG_INFO, 0, "Auto-RP discovery listening on %s:%d",
	  inet_fmt(htonl(AUTORP_DISCOVERY_GROUP), s1, sizeof(s1)), AUTORP_PORT);
}

void stop_autorp(void)
{
    autorp_maps_clear();

    if (autorp_socket > -1) {
	close(autorp_socket);
	autorp_socket = -1;
    }
}

/*
 * `pimctl show autorp', which is the only thing that says where a mapping
 * came from and when it stops being believed.  The RP set itself shows the
 * positive half of this and knows nothing of the rest.
 */
int dump_autorp(FILE *fp, int detail)
{
    struct autorp_map *map;

    (void)detail;

    fprintf(fp, "Auto-RP Mapping Table_\n");
    if (!autorp_enabled) {
	fprintf(fp, "Discovery is disabled\n");
	return 0;
    }

    fprintf(fp, "Group Address     RP Address       Holdtime  Agent           =\n");
    for (map = autorp_maps; map; map = map->next) {
	char ht[10];

	if (map->holdtime == AUTORP_HOLDTIME_FOREVER)
	    snprintf(ht, sizeof(ht), "Forever");
	else
	    snprintf(ht, sizeof(ht), "%u", map->holdtime);

	fprintf(fp, "%-16s  %-15s  %8s  %-15s\n",
		netname(map->group_addr, map->group_mask),
		map->negative ? "DENY" : inet_fmt(map->rp_addr, s1, sizeof(s1)),
		ht, inet_fmt(map->origin, s2, sizeof(s2)));
    }

    return 0;
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "cc-mode"
 * End:
 */
