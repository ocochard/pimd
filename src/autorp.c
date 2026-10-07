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
#ifdef IP_RECVIF
#include <net/if_dl.h>		/* sockaddr_dl, the BSD arrival interface */
#endif

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

/*
 * What candidate RPs have announced, which only a mapping agent keeps: the
 * list above is what this router believes, this one is what it was asked to
 * resolve.  Same shape, and both are state somebody else creates, so both
 * count against autorp_limit.
 */
static struct autorp_map *autorp_announced = NULL;

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

/*
 * What this router announces, if a pimd.conf asked it to be a candidate RP
 * over Auto-RP: an address, the prefixes it is willing to serve, and the
 * three numbers sec. 3.1 leaves to the sender.  A prefix may be a deny,
 * which is how an RP says "not these", and the whole list goes into one
 * message: the format carries a count of prefixes per RP.
 */
struct autorp_prefix {
    struct autorp_prefix *next;
    uint32_t		  group_addr;
    uint32_t		  group_mask;
    uint8_t		  masklen;
    uint8_t		  negative;
};

static int	autorp_announce_flag	 = FALSE;
static uint32_t	autorp_announce_addr	 = INADDR_ANY_N;
static uint16_t	autorp_announce_interval = AUTORP_DEFAULT_INTERVAL;
static uint16_t	autorp_announce_holdtime = AUTORP_DEFAULT_HOLDTIME;
static uint8_t	autorp_announce_ttl	 = AUTORP_DEFAULT_SCOPE;
static uint16_t	autorp_announce_timer	 = 0;
/* Set once init_autorp() has armed the timers and joined the groups of the
 * roles the configuration gave, which is what tells a role configured then
 * from one that turned up later; see autorp_announce_set() */
static int	autorp_inited		 = FALSE;
static struct autorp_prefix *autorp_prefixes = NULL;

/*
 * And what it resolves, if a pimd.conf asked it to be the mapping agent.
 * `autorp_agent_better' is the agent with the higher address sec. 3.2 has
 * this one fall silent for, and its timer is what lets this one speak again
 * when that agent stops.
 */
static int	autorp_agent_flag	 = FALSE;
static uint32_t	autorp_agent_addr	 = INADDR_ANY_N;
static uint16_t	autorp_agent_interval	 = AUTORP_DEFAULT_INTERVAL;
static uint16_t	autorp_agent_holdtime	 = AUTORP_DEFAULT_HOLDTIME;
static uint8_t	autorp_agent_ttl	 = AUTORP_DEFAULT_SCOPE;
static uint16_t	autorp_agent_timer	 = 0;
static uint32_t	autorp_agent_better	 = INADDR_ANY_N;
static uint16_t	autorp_agent_better_timer = 0;

int autorp_socket  = -1;
int autorp_enabled = TRUE;	/* `no autorp discovery' turns it off */

/*
 * The listener of sec. 3.3, `autorp listener' and off by default.  The
 * draft assumes the two well-known groups are flooded to every router in
 * the domain and says nothing about how; a dense-mode cloud does it, and
 * so does a static rp-address for each of them.  A pimd-only sparse
 * domain has neither, and without something this feature reaches one hop:
 * pimd sends its own messages out of every PIM interface, so an agent
 * adjacent to the RPs and to the routers works and anything wider does
 * not.
 *
 * So: a datagram that arrives is re-sent out of every other PIM
 * interface with its TTL decremented, which is what IOS's `ip pim autorp
 * listener' does.  Three things keep it bounded -- the two groups only,
 * a TTL that has to survive the decrement, and never the interface it
 * came in on -- and there is no duplicate suppression beyond that, so a
 * cycle in the topology costs the datagram its remaining TTL and no
 * more.  It is off by default because it puts this router in the
 * forwarding path for traffic nobody asked it to carry.
 *
 * The source address is the original sender's, which is why this needs a
 * raw socket rather than the one the messages arrive on: accept_autorp()
 * reads the agent's identity off the IP source -- `show autorp' prints
 * it, and sec. 3.2 has an agent fall silent for a higher-addressed one --
 * so a relay that put its own address there would make every router look
 * like the agent to its neighbours and decide that election wrongly.
 */
static int      autorp_listener_flag = FALSE;
static int      autorp_relay_socket  = -1;
static uint8_t *autorp_relay_buf     = NULL;
static int      autorp_relay_said    = FALSE;
static int      autorp_listener_said = FALSE;
static uint16_t autorp_relay_id      = 0;

/* The largest datagram this will relay, which is comfortably more than
 * either message can be without being fragmented on any link pimd runs
 * on -- and the bound on the buffers below. */
#define AUTORP_RELAY_MAX	2048

static void autorp_read(int sd);

/*
 * Every mapping this router has heard goes away.  Called from stop_autorp()
 * and before a reload, since a mapping that is no longer announced must not
 * outlive the daemon's picture of the domain -- restart() rebuilds the RP
 * set from nothing, and this list would otherwise be the one thing that
 * remembered a withdrawn prefix.
 */
static void autorp_list_clear(struct autorp_map **head)
{
    struct autorp_map *map, *next;

    for (map = *head; map; map = next) {
	next = map->next;
	free(map);
	if (autorp_entries > 0)
	    autorp_entries--;
    }

    *head = NULL;
}

static void autorp_maps_clear(void)
{
    autorp_list_clear(&autorp_maps);
    autorp_list_clear(&autorp_announced);

    autorp_entries = 0;
    autorp_limit_said = FALSE;
}

/*
 * The mirror entry for one (RP, prefix), made if it is new.  Keyed on the
 * prefix and the RP together: two RPs may serve the same range, which is
 * what the RP set's own hash is for, and a deny (RP 0.0.0.0) is a key of
 * its own so that it can replace nothing else.
 */
static struct autorp_map *autorp_map_get(struct autorp_map **head, uint32_t rp_addr,
					 uint32_t group_addr, uint32_t group_mask,
					 uint8_t masklen)
{
    struct autorp_map *map;

    for (map = *head; map; map = map->next) {
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
    map->next		= *head;
    *head		= map;

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

    map = autorp_map_get(&autorp_maps, negative ? INADDR_ANY_N : rp_addr,
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
 * An announcement, which only a mapping agent has any use for: cached as it
 * was heard, resolved when the agent next speaks.  Nothing is pushed into
 * this router's own RP set from here -- one RP's claim is not the resolved
 * answer, which is the whole reason agents exist (sec. 3.2).
 */
static void autorp_announced_learn(uint32_t from, uint32_t rp_addr, uint16_t holdtime,
				   uint32_t group_addr, uint8_t masklen, int negative)
{
    struct autorp_map *map;
    uint32_t group_mask;

    if (masklen > 32)
	return;

    MASKLEN_TO_MASK(masklen, group_mask);
    group_addr &= group_mask;

    if (!IN_MULTICAST(ntohl(group_addr)))
	return;

    map = autorp_map_get(&autorp_announced, rp_addr, group_addr, group_mask, masklen);
    if (!map)
	return;

    map->negative = negative ? TRUE : FALSE;
    map->holdtime = holdtime;
    map->origin   = from;

    IF_DEBUG(DEBUG_PIM_CAND_RP)
	logit(LOG_DEBUG, 0, "Auto-RP: %s announces %s for %s, holdtime %u",
	      inet_fmt(from, s1, sizeof(s1)), negative ? "no RP" : "itself",
	      netname(group_addr, group_mask), holdtime);
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
    struct autorp_cursor cur;
    struct autorp_wire_prefix pfx;
    struct autorp_hdr hdr;
    int rc;

    if (!autorp_enabled)
	return;

    if (autorp_parse_hdr(&cur, &hdr, buf, len)) {
	IF_DEBUG(DEBUG_PIM_CAND_RP)
	    logit(LOG_DEBUG, 0, "Auto-RP: %zu bytes from %s is shorter than a header",
		  len, inet_fmt(from, s1, sizeof(s1)));
	return;
    }

    if (hdr.version != AUTORP_VERSION) {
	IF_DEBUG(DEBUG_PIM_CAND_RP)
	    logit(LOG_DEBUG, 0, "Auto-RP: version %u from %s, expected %u",
		  hdr.version, inet_fmt(from, s1, sizeof(s1)), AUTORP_VERSION);
	return;
    }

    /*
     * An announcement is addressed to the mapping agents and says what one
     * RP is willing to serve; a router that is not an agent has no business
     * believing it, or two RPs claiming the same range would both be in
     * this router's RP set with nothing having resolved them.  Only a
     * mapping message is the resolved answer.
     */
    if (hdr.type == AUTORP_TYPE_ANNOUNCE && !autorp_agent_flag) {
	IF_DEBUG(DEBUG_PIM_CAND_RP)
	    logit(LOG_DEBUG, 0, "Auto-RP: type %u from %s is not an RP-mapping message",
		  hdr.type, inet_fmt(from, s1, sizeof(s1)));
	return;
    }

    if (hdr.type != AUTORP_TYPE_MAPPING && hdr.type != AUTORP_TYPE_ANNOUNCE) {
	IF_DEBUG(DEBUG_PIM_CAND_RP)
	    logit(LOG_DEBUG, 0, "Auto-RP: type %u from %s is neither an announcement"
		  " nor a mapping", hdr.type, inet_fmt(from, s1, sizeof(s1)));
	return;
    }

    /*
     * Sec. 3.2: an agent that hears another agent with a higher address
     * falls silent, and there is no other election.  Its own mappings stay
     * where they are -- what is suppressed is the sending -- and the timer
     * is what lets it speak again if that agent stops.  Its own message,
     * heard back through a flooding domain, is not another agent.
     */
    if (hdr.type == AUTORP_TYPE_MAPPING && autorp_agent_flag &&
	from != autorp_agent_addr && ntohl(from) > ntohl(autorp_agent_addr)) {
	if (autorp_agent_better != from)
	    logit(LOG_INFO, 0, "Auto-RP: %s is the mapping agent, %s stays quiet",
		  inet_fmt(from, s1, sizeof(s1)),
		  inet_fmt(autorp_agent_addr, s2, sizeof(s2)));

	autorp_agent_better = from;
	SET_TIMER(autorp_agent_better_timer, 3 * autorp_agent_interval);
    }

    /*
     * A message that ends inside a block keeps what came before it: each
     * prefix is acted on as it is read, and the walk stops at the first
     * block the buffer does not hold.
     */
    while ((rc = autorp_parse_next(&cur, &pfx)) == AUTORP_PARSE_PREFIX) {
	if (!inet_valid_host(pfx.rp_addr)) {
	    IF_DEBUG(DEBUG_PIM_CAND_RP)
		logit(LOG_DEBUG, 0, "Auto-RP: %s from %s is not a valid RP address",
		      inet_fmt(pfx.rp_addr, s2, sizeof(s2)), inet_fmt(from, s1, sizeof(s1)));
	    continue;
	}

	if (hdr.type == AUTORP_TYPE_ANNOUNCE)
	    autorp_announced_learn(from, pfx.rp_addr, hdr.holdtime, pfx.group_addr,
				   pfx.masklen, pfx.negative);
	else
	    autorp_learn(from, pfx.rp_addr, hdr.holdtime, pfx.group_addr,
			 pfx.masklen, pfx.negative);
    }

    if (rc == AUTORP_PARSE_SHORT_RP) {
	IF_DEBUG(DEBUG_PIM_CAND_RP)
	    logit(LOG_DEBUG, 0, "Auto-RP: message from %s ends inside an RP block",
		  inet_fmt(from, s1, sizeof(s1)));
    } else if (rc == AUTORP_PARSE_SHORT_GRP) {
	IF_DEBUG(DEBUG_PIM_CAND_RP)
	    logit(LOG_DEBUG, 0, "Auto-RP: message from %s ends inside a group prefix",
		  inet_fmt(from, s1, sizeof(s1)));
    }
}

/*
 * One datagram out of every PIM interface, which is how a domain of pimds
 * hears an announcement or a mapping at all: the draft assumes the two
 * groups are flooded (sec. 3.3) and pimd has no dense mode to flood them
 * with, so what it can reach is every router on a link of its own.  An
 * agent adjacent to the RPs and to the routers is therefore a domain that
 * works; a wider one needs the flooding, which is written down in
 * aidd_docs/plans/autorp.md and is not here.
 *
 * A domain that *does* flood them sees one copy per link instead of one,
 * which the scope TTL and the fact that both messages are idempotent make
 * harmless.
 */
static void autorp_send(uint32_t group, uint8_t ttl, uint8_t *msg, size_t len)
{
    struct sockaddr_in sin;
    struct uvif *uv;
    vifi_t vifi;

    if (autorp_socket < 0)
	return;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family      = AF_INET;
    sin.sin_addr.s_addr = htonl(group);
    sin.sin_port        = htons(AUTORP_PORT);

    for (vifi = 0, uv = uvifs; vifi < numvifs; vifi++, uv++) {
	struct in_addr ifaddr;

	if (uv->uv_flags & (VIFF_REGISTER | VIFF_DISABLED | VIFF_DOWN))
	    continue;

	ifaddr.s_addr = uv->uv_lcl_addr;
	if (setsockopt(autorp_socket, IPPROTO_IP, IP_MULTICAST_IF,
		       &ifaddr, sizeof(ifaddr)) < 0) {
	    logit(LOG_WARNING, errno, "Auto-RP: failed selecting %s to send from", uv->uv_name);
	    continue;
	}

	if (setsockopt(autorp_socket, IPPROTO_IP, IP_MULTICAST_TTL,
		       &ttl, sizeof(ttl)) < 0)
	    logit(LOG_WARNING, errno, "Auto-RP: failed setting the scope TTL");

	if (sendto(autorp_socket, msg, len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
	    logit(LOG_WARNING, errno, "Auto-RP: failed sending on %s", uv->uv_name);
    }
}

/*
 * The header both messages share, sec. 4: version and type in one byte, the
 * RP count, the holdtime, and a reserved word.
 */
static void autorp_put_hdr(struct pim_writer *w, unsigned type, unsigned rpcnt, uint16_t holdtime)
{
    pim_put_u8(w, (uint8_t)(((AUTORP_VERSION & 0x0f) << 4) | (type & 0x0f)));
    pim_put_u8(w, (uint8_t)rpcnt);
    pim_put_u16(w, holdtime);
    pim_put_u32(w, 0);
}

/* An RP block: the address, this router's PIM version, a prefix count */
static void autorp_put_rp(struct pim_writer *w, uint32_t rp_addr, unsigned grpcnt)
{
    pim_put_bytes(w, &rp_addr, sizeof(rp_addr));
    pim_put_u8(w, PIM_VERSION & 0x03);
    pim_put_u8(w, (uint8_t)grpcnt);
}

/* And one encoded group prefix, with the N bit of sec. 4 in its first byte */
static void autorp_put_grp(struct pim_writer *w, uint32_t group_addr, uint8_t masklen, int negative)
{
    pim_put_u8(w, negative ? 0x01 : 0x00);
    pim_put_u8(w, masklen);
    pim_put_bytes(w, &group_addr, sizeof(group_addr));
}

/*
 * `autorp announce', sec. 3.1: what this router is willing to be the RP
 * for, said to the mapping agents every interval.  One message, one RP
 * block -- this router -- and every prefix pimd.conf gave it.
 */
static void autorp_send_announce(void)
{
    uint8_t msg[AUTORP_MSG_MAX];
    struct autorp_prefix *pfx;
    struct pim_writer w;
    unsigned count = 0;
    size_t len;

    for (pfx = autorp_prefixes; pfx; pfx = pfx->next)
	count++;

    if (!count)
	return;

    if (AUTORP_HDR_LEN + AUTORP_RP_LEN + count * AUTORP_GRP_LEN > sizeof(msg)) {
	logit(LOG_WARNING, 0, "Auto-RP: %u group prefixes do not fit one announcement", count);
	return;
    }

    /* Written through a writer bounded by msg (src/pim_encode.c), the
     * count above saying whether it fits and the writer making sure */
    pim_writer_init(&w, msg, sizeof(msg));
    autorp_put_hdr(&w, AUTORP_TYPE_ANNOUNCE, 1, autorp_announce_holdtime);
    autorp_put_rp(&w, autorp_announce_addr, count);
    for (pfx = autorp_prefixes; pfx; pfx = pfx->next)
	autorp_put_grp(&w, pfx->group_addr, pfx->masklen, pfx->negative);
    if (w.full) {
	logit(LOG_WARNING, 0, "Auto-RP: announcement overran its buffer, not sent");
	return;
    }
    len = pim_writer_used(&w, msg);

    IF_DEBUG(DEBUG_PIM_CAND_RP)
	logit(LOG_DEBUG, 0, "Auto-RP: announcing %s for %u prefix%s, holdtime %u",
	      inet_fmt(autorp_announce_addr, s1, sizeof(s1)), count,
	      count == 1 ? "" : "es", autorp_announce_holdtime);

    autorp_send(AUTORP_ANNOUNCE_GROUP, autorp_announce_ttl, msg, len);

    /*
     * An agent in this same daemon has to hear it, and multicast loopback
     * is not the way: the socket would have to be joined to the announce
     * group on a link to itself, and whether a copy comes back is the
     * host's business rather than the protocol's.  An RP that is also the
     * agent is an ordinary deployment (IOS puts both on one router), so the
     * message goes into the cache directly, from this router's own address.
     */
    if (autorp_agent_flag)
	accept_autorp(autorp_announce_addr, (char *)msg, len);
}

/*
 * The three rules of sec. 3.2, asked of one announced prefix: may the agent
 * put it in the mapping message it is about to send?
 *
 *   1) Prefixes of different lengths from different RPs coexist, so nothing
 *      here refuses those.
 *   2) The same prefix from two RPs goes to the higher address -- and sec. 6
 *      rule 2 says a deny beats a positive prefix of the same length,
 *      whoever sent it.
 *   3) A prefix another of the *same* RP's prefixes already covers is not
 *      sent: the longer one says nothing the shorter does not.
 */
static int autorp_resolved(struct autorp_map *map)
{
    struct autorp_map *other;

    for (other = autorp_announced; other; other = other->next) {
	if (other == map)
	    continue;

	/*
	 * Rule 3: same RP, and a shorter prefix of its own covers this one,
	 * saying the same thing.  Of the same *sign*, or the rule would
	 * throw away the one thing Auto-RP can say that a Bootstrap cannot:
	 * an RP announcing 239.0.0.0/8 and denying 239.9.0.0/16 inside it
	 * has said two things, and only the second is redundant with
	 * nothing.
	 */
	if (other->rp_addr == map->rp_addr && other->negative == map->negative &&
	    other->masklen < map->masklen &&
	    (map->group_addr & other->group_mask) == other->group_addr)
	    return FALSE;

	if (other->group_addr != map->group_addr || other->masklen != map->masklen)
	    continue;

	/* Rule 2, and sec. 6's: the deny, then the higher address */
	if (other->negative && !map->negative)
	    return FALSE;
	if (other->negative == map->negative &&
	    ntohl(other->rp_addr) > ntohl(map->rp_addr))
	    return FALSE;
    }

    return TRUE;
}

/*
 * `autorp mapping-agent', sec. 3.2: what the announcements came to, said to
 * every router every interval.  One RP block per RP that survived the rules
 * above, with its prefixes behind it.
 */
static void autorp_send_mapping(void)
{
    uint8_t msg[AUTORP_MSG_MAX];
    struct autorp_map *map, *rp;
    struct pim_writer w;
    unsigned rpcnt = 0;

    if (autorp_agent_better != INADDR_ANY_N) {
	IF_DEBUG(DEBUG_PIM_CAND_RP)
	    logit(LOG_DEBUG, 0, "Auto-RP: not sending mappings, %s is the agent",
		  inet_fmt(autorp_agent_better, s1, sizeof(s1)));
	return;
    }

    /* Written through a writer bounded by msg (src/pim_encode.c) */
    pim_writer_init(&w, msg, sizeof(msg));
    autorp_put_hdr(&w, AUTORP_TYPE_MAPPING, 0, autorp_agent_holdtime);

    /* One pass per RP, the list being keyed by prefix rather than by RP */
    for (rp = autorp_announced; rp; rp = rp->next) {
	unsigned grpcnt = 0;

	/* Have its blocks already gone in under an earlier entry? */
	for (map = autorp_announced; map != rp; map = map->next) {
	    if (map->rp_addr == rp->rp_addr)
		break;
	}
	if (map != rp)
	    continue;

	for (map = autorp_announced; map; map = map->next) {
	    if (map->rp_addr == rp->rp_addr && autorp_resolved(map))
		grpcnt++;
	}
	if (!grpcnt)
	    continue;

	if (!pim_writer_room(&w, AUTORP_RP_LEN + grpcnt * AUTORP_GRP_LEN)) {
	    logit(LOG_WARNING, 0, "Auto-RP: the mapping message is full, %s left out"
		  " (the domain wants more than one agent, or fewer prefixes)",
		  inet_fmt(rp->rp_addr, s1, sizeof(s1)));
	    break;
	}

	autorp_put_rp(&w, rp->rp_addr, grpcnt);
	for (map = autorp_announced; map; map = map->next) {
	    if (map->rp_addr != rp->rp_addr || !autorp_resolved(map))
		continue;

	    autorp_put_grp(&w, map->group_addr, map->masklen, map->negative);
	}

	rpcnt++;
    }

    if (!rpcnt) {
	IF_DEBUG(DEBUG_PIM_CAND_RP)
	    logit(LOG_DEBUG, 0, "Auto-RP: nothing announced, no mapping to send");
	return;
    }

    if (w.full) {
	logit(LOG_WARNING, 0, "Auto-RP: mapping overran its buffer, not sent");
	return;
    }

    msg[1] = (uint8_t)rpcnt;	/* the RP count, known only now */

    IF_DEBUG(DEBUG_PIM_CAND_RP)
	logit(LOG_DEBUG, 0, "Auto-RP: mapping %u RP%s as agent %s, holdtime %u",
	      rpcnt, rpcnt == 1 ? "" : "s",
	      inet_fmt(autorp_agent_addr, s1, sizeof(s1)), autorp_agent_holdtime);

    autorp_send(AUTORP_DISCOVERY_GROUP, autorp_agent_ttl, msg, pim_writer_used(&w, msg));
}

/*
 * What the mappings are worth in seconds, aged from main.c's timer beside
 * everything else that ages.  A mapping that is not refreshed goes, and
 * with it the deny that may be the only reason a group has no RP; the RP
 * set entry behind a positive one ages on its own holdtime in age_misc().
 */
static void age_autorp_list(struct autorp_map **head, const char *what)
{
    struct autorp_map *map, *next, *prev = NULL;

    for (map = *head; map; map = next) {
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
	    logit(LOG_DEBUG, 0, "Auto-RP: %s %s for %s timed out", what,
		  map->negative ? "deny" : inet_fmt(map->rp_addr, s1, sizeof(s1)),
		  netname(map->group_addr, map->group_mask));

	if (prev)
	    prev->next = next;
	else
	    *head = next;
	free(map);
	if (autorp_entries > 0)
	    autorp_entries--;
    }
}

void age_autorp(void)
{
    age_autorp_list(&autorp_maps, "mapping");
    age_autorp_list(&autorp_announced, "announcement");

    /*
     * The two things this router says, each on its own interval, and the
     * timer that ends another agent's turn: sec. 3.2 has an agent fall
     * silent for a higher address, and nothing in the draft says for how
     * long, so it is three intervals -- the same shape as the holdtime an
     * agent puts on its own mappings.
     */
    if (autorp_announce_flag) {
	IF_TIMEOUT(autorp_announce_timer) {
	    autorp_send_announce();
	    SET_TIMER(autorp_announce_timer, autorp_announce_interval);
	}
    }

    if (autorp_agent_better != INADDR_ANY_N) {
	IF_TIMEOUT(autorp_agent_better_timer) {
	    logit(LOG_INFO, 0, "Auto-RP: %s stopped sending mappings, %s speaks again",
		  inet_fmt(autorp_agent_better, s1, sizeof(s1)),
		  inet_fmt(autorp_agent_addr, s2, sizeof(s2)));
	    autorp_agent_better = INADDR_ANY_N;
	}
    }

    if (autorp_agent_flag) {
	IF_TIMEOUT(autorp_agent_timer) {
	    autorp_send_mapping();
	    SET_TIMER(autorp_agent_timer, autorp_agent_interval);
	}
    }
}

/*
 * The UDP checksum of a datagram this relays, RFC 768: the pseudo-header
 * of addresses, protocol and length, then the datagram itself.  Summed
 * out of a copy rather than by writing the pseudo-header over the IP
 * header in place, which is the usual trick and is not worth the
 * confusion here.
 */
static uint16_t autorp_udp_cksum(uint32_t src, uint32_t dst, uint8_t *udp, size_t udplen)
{
    uint8_t buf[12 + AUTORP_RELAY_MAX];
    struct pim_writer w;

    if (udplen > AUTORP_RELAY_MAX)	/* the caller bounds this already */
	return 0;

    /* Both addresses are already in network byte order, and go in as the
     * bytes they are */
    pim_writer_init(&w, buf, sizeof(buf));
    pim_put_bytes(&w, &src, sizeof(src));
    pim_put_bytes(&w, &dst, sizeof(dst));
    pim_put_u8(&w, 0);
    pim_put_u8(&w, IPPROTO_UDP);
    pim_put_u16(&w, (uint16_t)udplen);
    pim_put_bytes(&w, udp, udplen);
    if (w.full)
	return 0;

    return (uint16_t)inet_cksum((uint16_t *)buf, (u_int)(12 + udplen));
}

/*
 * One datagram, out of every PIM interface but the one it arrived on,
 * with the source it came with and one less TTL.  See the comment on
 * autorp_listener_flag for what bounds it and why the source is kept.
 */
static void autorp_relay(uint32_t from, uint32_t group, int ttl, vifi_t iif,
			 uint8_t *msg, size_t len)
{
    size_t udplen = sizeof(struct udphdr) + len;
    size_t iplen  = sizeof(struct ip) + udplen;
    struct sockaddr_in sin;
    struct udphdr *udp;
    struct uvif *uv;
    struct ip *ip;
    uint8_t hops;
    vifi_t vifi;

    if (autorp_relay_socket < 0 || !autorp_relay_buf)
	return;

    /* The scope the sender asked for, sec. 5.  A datagram that would
     * leave here with nothing left has reached the edge of it. */
    if (ttl <= 1)
	return;

    if (iplen > AUTORP_RELAY_MAX) {
	if (!autorp_relay_said) {
	    logit(LOG_WARNING, 0, "Auto-RP: %zu bytes from %s is more than the listener relays",
		  len, inet_fmt(from, s1, sizeof(s1)));
	    autorp_relay_said = TRUE;
	}

	return;
    }

    ip  = (struct ip *)autorp_relay_buf;
    udp = (struct udphdr *)(autorp_relay_buf + sizeof(struct ip));

    memset(ip, 0, sizeof(*ip));
    ip->ip_v          = IPVERSION;
    ip->ip_hl         = sizeof(struct ip) >> 2;
    ip->ip_id         = htons(++autorp_relay_id);
    ip->ip_ttl        = (uint8_t)(ttl - 1);
    ip->ip_p          = IPPROTO_UDP;
    ip->ip_src.s_addr = from;
    ip->ip_dst.s_addr = group;
#ifdef HAVE_IP_HDRINCL_BSD_ORDER
    ip->ip_len        = iplen;
#else
    ip->ip_len        = htons(iplen);
#endif

    udp->uh_sport = htons(AUTORP_PORT);
    udp->uh_dport = htons(AUTORP_PORT);
    udp->uh_ulen  = htons(udplen);
    udp->uh_sum   = 0;
    memcpy(autorp_relay_buf + iplen - len, msg, len);
    udp->uh_sum   = autorp_udp_cksum(from, group, (uint8_t *)udp, udplen);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family      = AF_INET;
    sin.sin_addr.s_addr = group;
    sin.sin_port        = htons(AUTORP_PORT);

    /* The header above carries the TTL for the systems that send what is
     * in it, and this is for the ones that do not: a multicast datagram
     * leaves a BSD with the socket's IP_MULTICAST_TTL whatever the header
     * says, and that defaults to 1 -- which is one hop, and the relay
     * would be pointless.  autorp_send() sets it the same way. */
    hops = (uint8_t)(ttl - 1);
    if (setsockopt(autorp_relay_socket, IPPROTO_IP, IP_MULTICAST_TTL,
		   &hops, sizeof(hops)) < 0)
	logit(LOG_WARNING, errno, "Auto-RP: failed setting the relay TTL");

    for (vifi = 0, uv = uvifs; vifi < numvifs; vifi++, uv++) {
	if (vifi == iif)
	    continue;
	if (uv->uv_flags & (VIFF_REGISTER | VIFF_DISABLED | VIFF_DOWN))
	    continue;

	k_set_if(autorp_relay_socket, uv->uv_lcl_addr);
	if (sendto(autorp_relay_socket, autorp_relay_buf, iplen, 0,
		   (struct sockaddr *)&sin, sizeof(sin)) < 0)
	    logit(LOG_WARNING, errno, "Auto-RP: failed relaying on %s", uv->uv_name);
	else
	    IF_DEBUG(DEBUG_PIM_CAND_RP)
		logit(LOG_DEBUG, 0, "Auto-RP: relayed %s from %s onto %s, TTL %u",
		      inet_fmt(group, s1, sizeof(s1)), inet_fmt(from, s2, sizeof(s2)),
		      uv->uv_name, ttl - 1);
    }
}

/*
 * The group a datagram was addressed to, which recvmsg() does not say:
 * the type nibble does, an announcement being addressed to the agents and
 * a mapping to the routers (sec. 4).  A datagram this cannot place is one
 * accept_autorp() will refuse as well, and is not relayed.
 */
static int autorp_relay_group(uint8_t *msg, size_t len, uint32_t *group)
{
    if (len < AUTORP_HDR_LEN || AUTORP_VERSION_OF(msg[0]) != AUTORP_VERSION)
	return FALSE;

    switch (AUTORP_TYPE_OF(msg[0])) {
    case AUTORP_TYPE_ANNOUNCE:
	*group = htonl(AUTORP_ANNOUNCE_GROUP);
	return TRUE;

    case AUTORP_TYPE_MAPPING:
	*group = htonl(AUTORP_DISCOVERY_GROUP);
	return TRUE;

    default:
	return FALSE;
    }
}

/*
 * The datagram handler the event loop calls.  One message per call, the
 * sender taken from the kernel rather than from anything in the payload,
 * and with it the arrival interface and the TTL where the listener wants
 * them: recvmsg() rather than recvfrom() for those two alone.
 */
static void autorp_read(int sd)
{
    struct sockaddr_in from;
    struct cmsghdr *cmsg;
    struct msghdr msgh;
    char cmbuf[256];
    struct iovec iov;
    vifi_t iif = NO_VIF;
    uint32_t group;
    int ttl = -1;
    ssize_t len;

    memset(&from, 0, sizeof(from));
    memset(&msgh, 0, sizeof(msgh));
    iov.iov_base        = autorp_buf;
    iov.iov_len         = RECV_BUF_SIZE;
    msgh.msg_name       = &from;
    msgh.msg_namelen    = sizeof(from);
    msgh.msg_control    = cmbuf;
    msgh.msg_controllen = sizeof(cmbuf);
    msgh.msg_iov        = &iov;
    msgh.msg_iovlen     = 1;

    len = recvmsg(sd, &msgh, 0);
    if (len < 0) {
	if (errno == EINTR || errno == EAGAIN)
	    return;

	logit(LOG_WARNING, errno, "Failed recvmsg() on the Auto-RP socket");
	return;
    }

    for (cmsg = CMSG_FIRSTHDR(&msgh); cmsg; cmsg = CMSG_NXTHDR(&msgh, cmsg)) {
	if (cmsg->cmsg_level != IPPROTO_IP)
	    continue;

	switch (cmsg->cmsg_type) {
#ifdef IP_PKTINFO
	case IP_PKTINFO:
	{
	    struct in_pktinfo ipi;

	    if (cmsg->cmsg_len < CMSG_LEN(sizeof(ipi)))
		break;

	    memcpy(&ipi, CMSG_DATA(cmsg), sizeof(ipi));
	    iif = find_vif(ipi.ipi_ifindex);
	    break;
	}
#endif
#ifdef IP_RECVIF
	case IP_RECVIF:
	{
	    struct sockaddr_dl sdl;

	    /* Variable length, and the index is what this wants: copy what
	     * the kernel said it wrote and no more. */
	    if (cmsg->cmsg_len < CMSG_LEN(offsetof(struct sockaddr_dl, sdl_data)))
		break;

	    memset(&sdl, 0, sizeof(sdl));
	    memcpy(&sdl, CMSG_DATA(cmsg),
		   MIN(cmsg->cmsg_len - CMSG_LEN(0), sizeof(sdl)));
	    iif = find_vif((int)sdl.sdl_index);
	    break;
	}
#endif
#ifdef IP_RECVTTL
	case IP_RECVTTL:
	    if (cmsg->cmsg_len < CMSG_LEN(sizeof(uint8_t)))
		break;

	    ttl = *(uint8_t *)CMSG_DATA(cmsg);
	    break;
#endif
#if defined(IP_TTL) && IP_TTL != IP_RECVTTL
	case IP_TTL:
	{
	    int val;

	    if (cmsg->cmsg_len < CMSG_LEN(sizeof(val)))
		break;

	    memcpy(&val, CMSG_DATA(cmsg), sizeof(val));
	    ttl = val;
	    break;
	}
#endif
	default:
	    break;
	}
    }

    /* Relayed before it is parsed, and only where both answers came back:
     * without the TTL there is nothing to decrement, and without the
     * arrival interface the relay would go back out of the link it came
     * in on and the two routers would trade it until the TTL ran out.
     * A kernel that answers neither leaves the listener with nothing to
     * work from, which is worth saying once rather than quietly doing
     * nothing. */
    if (autorp_listener_flag) {
	if (ttl < 0 || iif == NO_VIF) {
	    if (!autorp_listener_said) {
		logit(LOG_WARNING, 0, "Auto-RP: the listener has no %s for a datagram"
		      " from %s, not relaying",
		      ttl < 0 ? "TTL" : "arrival interface",
		      inet_fmt(from.sin_addr.s_addr, s1, sizeof(s1)));
		autorp_listener_said = TRUE;
	    }
	} else if (autorp_relay_group((uint8_t *)autorp_buf, (size_t)len, &group)) {
	    autorp_relay(from.sin_addr.s_addr, group, ttl, iif,
			 (uint8_t *)autorp_buf, (size_t)len);
	}
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

	/* Only an agent has anything to do with the announce group, and
	 * joining it otherwise would have this router carry traffic it
	 * would then throw away -- unless it is the one passing it on,
	 * which cannot relay what it does not receive */
	if (autorp_agent_flag || autorp_listener_flag)
	    k_join(autorp_socket, htonl(AUTORP_ANNOUNCE_GROUP), uv);
    }
}

/*
 * The raw socket a relay goes out of.  A datagram keeps the source
 * address it arrived with, which the socket the messages come in on
 * cannot do, so this one carries its own IP header (k_hdr_include()) the
 * way the PIM socket does.  Loopback is off: a relay this router heard
 * back would be relayed again, and the TTL is the only thing that would
 * stop it.
 */
static void autorp_relay_init(void)
{
    int sd;

    if (autorp_relay_socket > -1)
	return;

    if (!autorp_relay_buf) {
	autorp_relay_buf = calloc(1, AUTORP_RELAY_MAX);
	if (!autorp_relay_buf) {
	    logit(LOG_WARNING, errno, "Auto-RP: out of memory for the listener, not relaying");
	    return;
	}
    }

    /* As with the socket above: a raw socket takes root, and under the
     * Linux filter the child may not call socket(2) at all. */
    sd = priv_socket(PRIV_SOCK_AUTORP_RELAY);
    if (sd < 0)
	sd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sd < 0) {
	logit(LOG_WARNING, errno, "Auto-RP: failed creating the listener socket, not relaying");
	return;
    }

    k_hdr_include(sd, TRUE);
    k_set_loop(sd, FALSE);

    autorp_relay_socket = sd;
    logit(LOG_INFO, 0, "Auto-RP: listener relaying %s and %s between PIM interfaces",
	  inet_fmt(htonl(AUTORP_ANNOUNCE_GROUP), s1, sizeof(s1)),
	  inet_fmt(htonl(AUTORP_DISCOVERY_GROUP), s2, sizeof(s2)));
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

    /* The listener wants two things off each datagram that recvfrom()
     * does not give: which interface it came in on and how much TTL is
     * left.  Asked for here rather than in autorp_relay(), the option
     * being a property of the socket. */
    if (autorp_listener_flag) {
	k_set_recvif(autorp_socket, TRUE);
	k_set_recvttl(autorp_socket, TRUE);
	autorp_relay_init();
    }

    autorp_join();

    /* Both say something at once rather than after an interval: a router
     * that has just started is the one a domain most wants to hear from,
     * and an agent with nothing cached sends nothing anyway. */
    if (autorp_announce_flag)
	SET_TIMER(autorp_announce_timer, 1);
    if (autorp_agent_flag)
	SET_TIMER(autorp_agent_timer, autorp_agent_interval);

    autorp_inited = TRUE;

    if (register_input_handler(autorp_socket, autorp_read) < 0)
	logit(LOG_ERR, 0, "Failed registering the Auto-RP handler");

    logit(LOG_INFO, 0, "Auto-RP discovery listening on %s:%d",
	  inet_fmt(htonl(AUTORP_DISCOVERY_GROUP), s1, sizeof(s1)), AUTORP_PORT);
}

/*
 * What pimd.conf says, applied from src/config.c.  Kept here rather than
 * there for the reason the RP set is kept in rp.c: the parser's job is to
 * read the words, and what an announcement or an agent is made of belongs
 * beside the code that sends it.
 */
/* `autorp listener' in pimd.conf, and off again on a reload that drops it */
void autorp_listener_set(int on)
{
    autorp_listener_flag = on;

    logit(LOG_INFO, 0, "Auto-RP listener is %s", on ? "enabled" : "disabled");
}

void autorp_config_reset(void)
{
    struct autorp_prefix *pfx, *next;

    for (pfx = autorp_prefixes; pfx; pfx = next) {
	next = pfx->next;
	free(pfx);
    }
    autorp_prefixes = NULL;

    autorp_announce_flag	= FALSE;
    autorp_announce_addr	= INADDR_ANY_N;
    autorp_announce_interval	= AUTORP_DEFAULT_INTERVAL;
    autorp_announce_holdtime	= AUTORP_DEFAULT_HOLDTIME;
    autorp_announce_ttl		= AUTORP_DEFAULT_SCOPE;

    autorp_agent_flag		= FALSE;
    autorp_agent_addr		= INADDR_ANY_N;
    autorp_agent_interval	= AUTORP_DEFAULT_INTERVAL;
    autorp_agent_holdtime	= AUTORP_DEFAULT_HOLDTIME;
    autorp_agent_ttl		= AUTORP_DEFAULT_SCOPE;
    autorp_agent_better		= INADDR_ANY_N;

    autorp_listener_flag	= FALSE;
}

/*
 * The two roles a pimd.conf can give this router, each at an address it may
 * have named by interface -- so @addr is INADDR_ANY_N where that interface
 * has not appeared yet, or has gone, and the role is off for as long as that
 * lasts.  config_resolve_addrs() (src/config.c) calls these again from every
 * interface rescan.
 *
 * Before init_autorp() these only record: it arms the timers of whichever
 * roles the configuration gave, and joins the groups they need.  Afterwards
 * there is nobody left to do that, so they do it themselves.
 */
void autorp_announce_set(uint32_t addr, int interval, int holdtime, int ttl)
{
    int was = autorp_announce_flag;

    autorp_announce_flag     = addr != INADDR_ANY_N;
    autorp_announce_addr     = addr;
    autorp_announce_interval = (uint16_t)interval;
    autorp_announce_holdtime = (uint16_t)holdtime;
    autorp_announce_ttl      = (uint8_t)ttl;

    /* Nothing to join: an announcement is sent to the announce group, which
     * only an agent has to be a member of. */
    if (autorp_inited && autorp_announce_flag && !was)
	SET_TIMER(autorp_announce_timer, 1);
}

void autorp_agent_set(uint32_t addr, int interval, int holdtime, int ttl)
{
    int was = autorp_agent_flag;

    autorp_agent_flag     = addr != INADDR_ANY_N;
    autorp_agent_addr     = addr;
    autorp_agent_interval = (uint16_t)interval;
    autorp_agent_holdtime = (uint16_t)holdtime;
    autorp_agent_ttl      = (uint8_t)ttl;

    /* An agent resolves what the candidates announce, so it has to be a
     * member of the announce group, which autorp_join() only adds for the
     * roles that were configured by the time it ran. */
    if (autorp_inited && autorp_agent_flag && !was) {
	autorp_join();
	SET_TIMER(autorp_agent_timer, autorp_agent_interval);
    }
}

/*
 * One prefix this router announces, positive or denied.  Appended rather
 * than prepended, so that a message carries them in the order pimd.conf
 * wrote them and a capture reads like the file.
 */
int autorp_prefix_add(uint32_t group_addr, uint8_t masklen, int negative)
{
    struct autorp_prefix *pfx, *last;
    uint32_t group_mask;

    if (masklen > 32)
	return FALSE;

    MASKLEN_TO_MASK(masklen, group_mask);

    pfx = calloc(1, sizeof(*pfx));
    if (!pfx) {
	logit(LOG_WARNING, errno, "Failed allocating Auto-RP group prefix");
	return FALSE;
    }

    pfx->group_addr = group_addr & group_mask;
    pfx->group_mask = group_mask;
    pfx->masklen    = masklen;
    pfx->negative   = negative ? TRUE : FALSE;

    for (last = autorp_prefixes; last && last->next; last = last->next)
	;
    if (last)
	last->next = pfx;
    else
	autorp_prefixes = pfx;

    return TRUE;
}

void stop_autorp(void)
{
    autorp_maps_clear();

    /* A reload goes back through init_autorp(), which arms and joins for
     * whatever the new configuration asks: until it has, the setters must
     * only record, as they do at startup. */
    autorp_inited = FALSE;

    if (autorp_socket > -1) {
	close(autorp_socket);
	autorp_socket = -1;
    }

    if (autorp_relay_socket > -1) {
	close(autorp_relay_socket);
	autorp_relay_socket = -1;
    }

    free(autorp_relay_buf);
    autorp_relay_buf = NULL;
    autorp_relay_said = FALSE;
    autorp_listener_said = FALSE;
}

static void dump_autorp_config(FILE *fp);

/* One mapping this router holds, the same row either way it is rendered */
static void dump_autorp_map(FILE *fp, struct autorp_map *map)
{
    char ht[10];

    if (map->holdtime == AUTORP_HOLDTIME_FOREVER)
	snprintf(ht, sizeof(ht), "Forever");
    else
	snprintf(ht, sizeof(ht), "%u", map->holdtime);

    struct ipc_field row[] = {
	IPC_STR("Group Address", -16, netname(map->group_addr, map->group_mask)),
	IPC_STR("RP Address",	 -15, map->negative ? "DENY" : inet_fmt(map->rp_addr, s1, sizeof(s1))),
	IPC_STR("Holdtime",	   8, ht),
	IPC_STR("Agent",	 -15, inet_fmt(map->origin, s2, sizeof(s2))),
	IPC_END
    };

    ipc_row(fp, row);
}

/*
 * `pimctl show autorp', which is the only thing that says where a mapping
 * came from and when it stops being believed.  The RP set itself shows the
 * positive half of this and knows nothing of the rest.
 *
 * What this router announces and resolves is prose between the title and
 * the table, which is the shape "show status" has: JSON leaves it out and
 * keeps the mappings, which are what a script is after.
 */
int dump_autorp(FILE *fp, int detail)
{
    struct autorp_map *map;

    (void)detail;

    ipc_table(fp, "Auto-RP Mapping Table", "autorp");

    if (!ipc_json()) {
	if (!autorp_enabled) {
	    fprintf(fp, "Discovery is disabled\n");
	    return 0;
	}

	dump_autorp_config(fp);
    }

    for (map = autorp_maps; map; map = map->next)
	dump_autorp_map(fp, map);
    ipc_table_end(fp);

    return 0;
}

/* The prose half: what this router announces, and what it resolves */
static void dump_autorp_config(FILE *fp)
{
    struct autorp_map *map;

    if (autorp_announce_flag) {
	struct autorp_prefix *pfx;

	fprintf(fp, "Announcing %s every %u sec, holdtime %u, scope %u:\n",
		inet_fmt(autorp_announce_addr, s1, sizeof(s1)),
		autorp_announce_interval, autorp_announce_holdtime,
		autorp_announce_ttl);
	for (pfx = autorp_prefixes; pfx; pfx = pfx->next)
	    fprintf(fp, "    %-18s %s\n", netname(pfx->group_addr, pfx->group_mask),
		    pfx->negative ? "deny" : "");
    }

    if (autorp_listener_flag)
	fprintf(fp, "Passing both groups on, %s\n",
		autorp_relay_socket > -1 ? "autorp listener" : "autorp listener, but no socket");

    if (autorp_agent_flag) {
	fprintf(fp, "Mapping agent %s every %u sec, holdtime %u, scope %u%s\n",
		inet_fmt(autorp_agent_addr, s1, sizeof(s1)),
		autorp_agent_interval, autorp_agent_holdtime, autorp_agent_ttl,
		autorp_agent_better != INADDR_ANY_N ? ", quiet" : "");

	if (autorp_agent_better != INADDR_ANY_N)
	    fprintf(fp, "    %s has the higher address and is the agent\n",
		    inet_fmt(autorp_agent_better, s2, sizeof(s2)));

	for (map = autorp_announced; map; map = map->next)
	    fprintf(fp, "    heard %-15s for %-18s %s\n",
		    inet_fmt(map->rp_addr, s1, sizeof(s1)),
		    netname(map->group_addr, map->group_mask),
		    map->negative ? "deny" : "");
    }
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "cc-mode"
 * End:
 */
