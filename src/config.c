/*
 * Copyright (c) 1998-2001
 * University of Southern California/Information Sciences Institute.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * Part of this program has been derived from mrouted.
 * The mrouted program is covered by the license in the accompanying file
 * named "LICENSE.mrouted".
 *
 * The mrouted program is COPYRIGHT 1989 by The Board of Trustees of
 * Leland Stanford Junior University.
 *
 */

#include "defs.h"
#include "queue.h"

#define WARN(fmt, args...)    logit(LOG_WARNING, 0, "%s:%u - " fmt, config_file, lineno, ##args)
#define BAILOUT(msg, arg...)  { WARN(msg ", bailing out!", ##arg); return FALSE; }
#define IGNORING(msg, arg...) { WARN(msg ", ignoring ...", ##arg); continue; }

/* Helper macros */
#define QUERIER_TIMEOUT(qintv) (IGMP_ROBUSTNESS_VARIABLE * (qintv) + IGMP_QUERY_RESPONSE_INTERVAL / 2)

#define LINE_BUFSIZ 1024	/* Max. line length of the config file */

#define CONF_UNKNOWN                           -1
#define CONF_EMPTY                              1
#define CONF_PHYINT                             2
#define CONF_CANDIDATE_RP                       3
#define CONF_RP_ADDRESS                         4
#define CONF_GROUP_PREFIX                       5
#define CONF_BOOTSTRAP_RP                       6
#define CONF_NO                                 7
#define CONF_SPT_THRESHOLD                      8
#define CONF_DEFAULT_ROUTE_METRIC               9
#define CONF_DEFAULT_ROUTE_DISTANCE             10
#define CONF_ALTNET                             11
#define CONF_MASKLEN                            12
#define CONF_SCOPED                             13
#define CONF_IGMP_QUERY_INTERVAL                14
#define CONF_IGMP_QUERIER_TIMEOUT               15
#define CONF_HELLO_INTERVAL                     16
#define CONF_DISABLE_VIFS                       17
#define CONF_SSM_RANGE                          18
#define CONF_REGISTER_ACCEPT_FROM               19
#define CONF_RPT_PRUNE_LIMIT                    20
#define CONF_LOCAL_SG_LIMIT                     21
#define CONF_ANYCAST_RP                         22
#define CONF_REGISTER_SG_LIMIT                  23
#define CONF_ASSERT_PREFERENCE                  24
#define CONF_AUTORP                             25
#define CONF_AUTORP_LIMIT                       26

/*
 * Beginnings of a refactor of the static uvifs[] array
 *
 * Used to when querying the config file for enabled/disabled interfaces
 * during the kernel probe.  All with the purpose of limiting the waste
 * of VIFs in the kernel -- only register an interface and create a VIF
 * for enabled interfaces.
 */
struct iflist {
    LIST_ENTRY(iflist) link;

    int       enabled;
    struct ifaddrs *ifa;	/* Set if found */

    uint32_t  addr;
    char      ifname[IFNAMSIZ + 1];
};

/*
 * One Source Specific Multicast group range, from an ssm-range in
 * pimd.conf.  As soon as one is configured the list replaces the
 * default range, 232.0.0.0/8, rather than adding to it.
 */
struct ssm_range {
    struct ssm_range *next;

    uint32_t  group;		/* Network byte order, masked */
    uint32_t  mask;		/* Network byte order */
    uint32_t  masklen;
};

/* Every ranked lookup of a group walks this list, so it is bounded the
 * same way the Cand-RP group prefixes are, and for the same reason. */
#define SSM_MAX_RANGES 255

/*
 * One prefix from a register-accept-from in pimd.conf: a router whose
 * Register messages this RP is willing to act on.  RFC 7761 sec. 6.2 asks
 * for the option and requires that it default to accepting everything, so
 * an empty list means no restriction rather than no sender.
 */
struct reg_acl {
    struct reg_acl *next;

    uint32_t  addr;		/* Network byte order, masked */
    uint32_t  mask;		/* Network byte order */
    uint32_t  masklen;
};

/* Walked once per Register from an unknown sender, so bounded like the
 * SSM ranges above. */
#define REG_ACL_MAX_ENTRIES 255

/*
 * One member of an Anycast-RP set, from an anycast-rp line in pimd.conf:
 * a router holding the anycast RP address that also has a unique address
 * of its own, the one Registers are copied to (RFC 4610 sec. 2).  A set
 * is every entry sharing an anycast address, this router's own member
 * included, so that the same lines can be pasted into every member.
 *
 * Only the addresses are kept.  Which member is this router is looked up
 * each time it is needed, because an address can be added to or removed
 * from an interface long after the file was read.
 */
struct anycast_rp {
    struct anycast_rp *next;

    uint32_t  anycast;		/* Network byte order */
    uint32_t  member;		/* Network byte order */
    uint32_t  lineno;		/* For the checks made once the file is read */
    uint32_t  copies;		/* Registers copied to this member */
};

/* Every Register accepted from outside a set is copied once to each other
 * member, so the size of a set is the factor a Register is multiplied by.
 * RFC 4610 sec. 4 wants the set kept small for the same reason. */
#define ANYCAST_RP_MAX_MEMBERS 8
#define ANYCAST_RP_MAX_ENTRIES 255

/*
 * Global settings
 */
uint16_t pim_timer_hello_interval = PIM_TIMER_HELLO_INTERVAL;
uint16_t pim_timer_hello_holdtime = PIM_TIMER_HELLO_HOLDTIME;
uint32_t rpt_prune_limit = PIM_RPT_PRUNE_LIMIT;
uint32_t local_sg_limit = PIM_LOCAL_SG_LIMIT;
uint32_t register_sg_limit = PIM_REGISTER_SG_LIMIT;

/*
 * Forward declarations.
 */
static char	*next_word	(char **);
static int       parse_option   (char *s);
static int	 parse_phyint	(char *s);
static int	 parse_state_limit (char *s, const char *name, uint32_t *limit, uint32_t dflt);
static int	 parse_anycast_rp (char *s);
static void	 reset_anycast_rp (void);
static void	 check_anycast_rp (void);
static uint32_t	 ifname2addr	(char *s);

static LIST_HEAD(, iflist) il = LIST_HEAD_INITIALIZER();

/*
 * Lowest VIF parse_phyint() may apply a line to.  Zero for every ordinary
 * pass over the file; config_phyints_from_file() raises it so that a
 * rescan configures the VIFs that have just appeared and touches no
 * other.  The lists a phyint line appends to -- altnet, scoped,
 * accept-nbr-from -- would otherwise collect a second copy of every entry
 * each time an interface turned up somewhere else on the router.
 */
static vifi_t phyint_first = 0;

static uint32_t          lineno;
static struct ssm_range *ssm_list = NULL;
static struct reg_acl   *reg_acl_list = NULL;
static struct anycast_rp *anycast_rp_list = NULL;


/*
 * Populate interface list with interfaces from pimd.conf
 * Returns number of enabled phyint
 */
static int build_iflist(void)
{
    char buf[LINE_BUFSIZ], *line;
    int count = 0;
    FILE *fp;

    fp = priv_fopen_conf();
    if (!fp)
	return 0;

    while ((line = fgets(buf, sizeof(buf), fp))) {
	int enabled = do_vifs;
	uint32_t addr = 0;
	char *token;
	char ifname[IFNAMSIZ + 1] = "";
	struct iflist *entry;

	switch (parse_option(next_word(&line))) {
	    case CONF_NO:
		switch (parse_option(next_word(&line))) {
		    case CONF_PHYINT:
			do_vifs = 0;
			break;

		    default:
			break;
		}
		continue;

	    case CONF_PHYINT:
		break;

	    case CONF_DISABLE_VIFS:
		do_vifs = 0;
		continue;

	    default:
		continue;
	}

	token = next_word(&line);
	if (isdigit(token[0]))
	    addr = inet_parse(token, 4);
	else
	    strlcpy(ifname, token, sizeof(ifname));

	while (!EQUAL((token = next_word(&line)), "")) {
	    if (EQUAL(token, "disable")) {
		enabled = 0;
		continue;
	    }

	    if (EQUAL(token, "enable")) {
		enabled = 1;
		continue;
	    }
	}

	entry = calloc(1, sizeof(struct iflist));
	if (!entry) {
	    logit(LOG_ERR, errno, "Failed allocating memory for iflist");
	    fclose(fp);
	    return 0;
	}

	entry->enabled = enabled;
	if (enabled)
	    count++;

	if (*ifname)
	    strlcpy(entry->ifname, ifname, sizeof(entry->ifname));
	else
	    entry->addr = addr;

	LIST_INSERT_HEAD(&il, entry, link);
    }

    fclose(fp);
    return count;
}

/*
 * The interface list is only needed during config_vifs_from_kernel()
 */
static void tear_iflist(void)
{
	struct iflist *entry, *tmp;

	LIST_FOREACH_SAFE(entry, &il, link, tmp) {
	    LIST_REMOVE(entry, link);
	    free(entry);
	}
}

/*
 * phyint <IFNAME | ADDRESS> -- Select interface based on name or addr
 */
static struct iflist *iface_find(char *ifname, uint32_t addr)
{
    struct iflist *entry;

    LIST_FOREACH(entry, &il, link) {
	if (!strcasecmp(entry->ifname, ifname))
	    return entry;

	if (addr && addr != 0xffffffff && addr == entry->addr)
	    return entry;
    }

    return NULL;
}

static int getifmtu(char *ifname)
{
    struct ifreq ifr = { 0 };

    strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
    if (ioctl(udp_socket, SIOCGIFMTU, &ifr) == -1)
	return 1500;

    return ifr.ifr_mtu;
}

/*
 * Record subnet/mask as an extra subnet ("altnet") of vif v, so that RPF
 * lookups treat a source on it as directly connected.  Both the kernel
 * scan and an altnet in pimd.conf can offer the same subnet, and the vif
 * already covers its own, so duplicates are dropped here rather than at
 * each caller.
 *
 * Returns 1 if the subnet was added, 0 if the vif already had it, and -1
 * on allocation failure.
 */
static int install_altnet(struct uvif *v, uint32_t subnet, uint32_t mask)
{
    struct phaddr *ph;

    if (v->uv_subnet == subnet && v->uv_subnetmask == mask)
	return 0;

    for (ph = v->uv_addrs; ph; ph = ph->pa_next) {
	if (ph->pa_subnet == subnet && ph->pa_subnetmask == mask)
	    return 0;
    }

    ph = calloc(1, sizeof(*ph));
    if (!ph) {
	logit(LOG_WARNING, errno, "Failed allocating altnet for %s", v->uv_name);
	return -1;
    }

    ph->pa_subnet      = subnet;
    ph->pa_subnetmask  = mask;
    ph->pa_subnetbcast = subnet | ~mask;

    ph->pa_next = v->uv_addrs;
    v->uv_addrs = ph;

    return 1;
}

static int compare_requested_with_kernel(struct ifaddrs *ifaddr, int num)
{
    int count = 0;
    struct ifaddrs *ifa;

    if (do_vifs)
	return 0;

    for (ifa = ifaddr; ifa && num; ifa = ifa->ifa_next) {
	struct iflist *entry;
	uint32_t addr;

	/*
	 * Ignore any interface for an address family other than IP.
	 */
	if (!ifa->ifa_addr || !ifa->ifa_netmask || ifa->ifa_addr->sa_family != AF_INET) {
	    total_interfaces++;  /* Eventually may have IP address later */
	    continue;
	}

	/*
	 * Ignore interfaces that do not support multicast.
	 */
	if (!is_set(IFF_MULTICAST, ifa->ifa_flags)) {
	    WARN("Skipping interface %s, does not support multicast.", ifa->ifa_name);
	    continue;
	}

	addr  = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr;
	entry = iface_find(ifa->ifa_name, addr);
	if (!entry || !entry->enabled)
	    continue;

	entry->ifa = ifa;
	count++;
    }

    return count;
}


/*
 * Does the kernel still have an IPv4 address on @ifname?
 *
 * A vif whose interface has gone keeps its slot, its address and its
 * subnet: the slot so that the name can come back to the vif it had (see
 * rescan_vifs() in src/vif.c), the address so that check_vif_addrs() has
 * something to compare the kernel's against when it does.  None of that
 * makes it the owner of its subnet any more, which is what the scan below
 * would otherwise take it for: it would refuse a vif to the interface the
 * address has moved to -- a failover, a VLAN rebuilt under another name --
 * and name an interface the kernel no longer has as the reason.
 *
 * Asked of the addresses rather than of the flags, because an interface
 * that is merely down still owns its subnet and has to keep it, or the
 * subnet is handed to a second interface while the first is only waiting
 * to come back up.
 */
static int iface_has_inet_addr(struct ifaddrs *ifaddr, const char *ifname)
{
    struct ifaddrs *ifa;

    for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
	if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET)
	    continue;

	if (!strcmp(ifa->ifa_name, ifname))
	    return 1;
    }

    return 0;
}


/*
 * Query the kernel to find network interfaces that are multicast-capable
 * and install them in the uvifs array.
 *
 * Called once from init_vifs() with @rescan false, and again from
 * rescan_vifs() (src/vif.c) with it true for every interface the kernel
 * has gained since.  The difference is what may happen to a daemon that
 * is already running and forwarding: it may not wait for an interface
 * that is not there yet, and it may not exit because one is missing, both
 * of which are start-up answers to a start-up question.  The interfaces
 * it already has a VIF for are recognised by name in the loop below, so a
 * rescan adds what is new and leaves the rest alone.
 */
static void scan_vifs_from_kernel(int rescan)
{
    struct uvif *v;
    vifi_t vifi;
    short flags;
    uint32_t addr, mask, subnet;
    struct ifaddrs *ifaddr, *ifa;
    int phyint_num, count, valid, added;
    u_int n;
    struct iflist *entry;

    /* Query config first for list of enabled interfaces */
    phyint_num = build_iflist();

init_vif_list:
    total_interfaces = 0; /* The total number of physical interfaces */
    if (priv_getifaddrs(&ifaddr) == -1) {
	logit(LOG_ERR, errno, "Failed retrieving interface addresses");
	tear_iflist();
	return;
    }

    count = compare_requested_with_kernel(ifaddr, phyint_num);
    if (!rescan && !do_vifs && count < phyint_num) {
	priv_freeifaddrs(ifaddr);

	if (retry_forever) {
	    LIST_FOREACH(entry, &il, link)
		entry->ifa = NULL;

	    usleep(500000);	/* 500 msec */
	    goto init_vif_list;
	}

	tear_iflist();
	logit(LOG_ERR, 0, "Cannot find all required phyint interfaces, exiting.");
    }

    /*
     * Loop through all of the interfaces.
     */
    for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
	/*
	 * Ignore any interface for an address family other than IP.
	 */
	if (!ifa->ifa_addr || !ifa->ifa_netmask || ifa->ifa_addr->sa_family != AF_INET) {
	    total_interfaces++;  /* Eventually may have IP address later */
	    continue;
	}

	addr  = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr;
	mask  = ((struct sockaddr_in *)ifa->ifa_netmask)->sin_addr.s_addr;
	flags = ifa->ifa_flags;

	/*
	 * Check against .conf file
	 */
	entry = iface_find(ifa->ifa_name, addr);
	if (do_vifs) {
	    if (entry && !entry->enabled) {
		logit(LOG_DEBUG, 0, "phyint %s (%s) disabled, skipping VIF",
		      ifa->ifa_name, inet_fmt(addr, s1, sizeof(s1)));
		continue;
	    }
	} else {
	    if (!entry || !entry->ifa) {
		logit(LOG_DEBUG, 0, "phyint %s (%s) disabled, skipping VIF",
		      ifa->ifa_name, inet_fmt(addr, s1, sizeof(s1)));
		continue;
	    }
	}

	/*
	 * Everyone below is a potential vif interface.
	 * We don't care if it has wrong configuration or not configured
	 * at all.
	 */
	total_interfaces++;

	subnet = addr & mask;
	if (mask != 0xffffffff) {
	    valid = inet_valid_subnet(subnet, mask) && addr != subnet && addr != (subnet | ~mask);
	    if (!valid)
		valid = inet_valid_host(addr) && ((mask == htonl(0xfffffffe)) || is_set(IFF_POINTOPOINT, flags));
	} else {
	    /*
	     * A /32 has neither a subnet nor a broadcast address to compare
	     * against, so inet_valid_subnet() has nothing to say about it,
	     * but the address itself must still be one we can talk to.
	     */
	    valid = inet_valid_host(addr);
	}

	if (!valid) {
	    if (!is_set(IFF_LOOPBACK, flags))
		logit(LOG_WARNING, 0, "Ignoring %s, has invalid address %s and/or netmask %s",
		      ifa->ifa_name, inet_fmt(addr, s1, sizeof(s1)), inet_fmt(mask, s2, sizeof(s2)));
	    continue;
	}

	/*
	 * Ignore any interface that is connected to the same subnet as
	 * one already installed in the uvifs array.  Skip reserved vifi
	 * for PIMREG_VIF.
	 */
	for (vifi = 1, v = &uvifs[1]; vifi < numvifs; ++vifi, ++v) {
	    if (strcmp(v->uv_name, ifa->ifa_name) == 0) {
		/*
		 * A second address on an interface that already has a vif.
		 * There can only be one vif per interface, so keep its
		 * subnet as an extra one on that vif, exactly like an
		 * "altnet" in pimd.conf: without it no RPF lookup sees a
		 * source on the alias as directly connected.
		 */
		added = install_altnet(v, subnet, mask);
		if (added > 0)
		    logit(LOG_INFO, 0, "VIF #%u: Adding %s (%s) as altnet %s",
			  vifi, v->uv_name, inet_fmt(addr, s1, sizeof(s1)), netname(subnet, mask));
		else if (!added)
		    logit(LOG_DEBUG, 0, "Ignoring %s (%s on subnet %s), vif#%u already has it",
			  v->uv_name, inet_fmt(addr, s1, sizeof(s1)), netname(subnet, mask), vifi);
		break;
	    }

	    /* A vif whose interface has gone owns no subnet any more,
	     * see iface_has_inet_addr() above */
	    if (!iface_has_inet_addr(ifaddr, v->uv_name))
		continue;

	    /* we don't care about point-to-point links in same subnet */
	    if (is_set(IFF_POINTOPOINT, flags))
		continue;
	    if (is_set(VIFF_POINT_TO_POINT, v->uv_flags))
		continue;

	    if (((addr & mask) == v->uv_subnet) && (v->uv_subnetmask == mask)) {
		logit(LOG_WARNING, 0, "Ignoring %s, same subnet as %s", ifa->ifa_name, v->uv_name);
		break;
	    }
	}
	if (vifi != numvifs)
	    continue;

	/*
	 * If there is room in the uvifs array, install this interface.
	 */
	if (numvifs == MAXVIFS) {
	    logit(LOG_WARNING, 0, "Too many vifs, ignoring %s", ifa->ifa_name);
	    continue;
	}
	v = &uvifs[numvifs];
	zero_vif(v, FALSE);
	v->uv_lcl_addr		= addr;
	v->uv_subnet		= subnet;
	v->uv_subnetmask	= mask;
	if (mask != htonl(0xfffffffe))
		v->uv_subnetbcast = subnet | ~mask;
	else
		v->uv_subnetbcast = 0xffffffff;

	strlcpy(v->uv_name, ifa->ifa_name, IFNAMSIZ);

	/*
	 * The interface's other addresses, for the Address List option of
	 * its Hello (RFC 7761 sec. 4.3.4).  Not the altnets below: those are
	 * subnets, and one configured in pimd.conf has no address of ours
	 * on it at all.
	 */
	n = vif_secaddrs(ifaddr, v->uv_name, addr, v->uv_secaddrs);
	if (n > MAX_SECADDRS) {
	    logit(LOG_WARNING, 0, "%s has %u secondary addresses, only the first %d go in its PIM Hello",
		  v->uv_name, n, MAX_SECADDRS);
	    n = MAX_SECADDRS;
	}
	v->uv_nsecaddrs = n;

	/*
	 * Figure out MTU of interface, needed as a seed value when
	 * fragmenting PIM register messages.  We should really do
	 * a PMTU check on initial PIM register send to a new RP...
	 */
	v->uv_mtu = getifmtu(ifa->ifa_name);

	if (is_set(IFF_POINTOPOINT, flags)) {
	    v->uv_flags |= (VIFF_REXMIT_PRUNES | VIFF_POINT_TO_POINT);
	    v->uv_rmt_addr = ((struct sockaddr_in *)(ifa->ifa_dstaddr))->sin_addr.s_addr;
	} else if (mask == htonl(0xfffffffe)) {
	    /*
	     * Handle RFC 3021 /31 netmasks as point-to-point links
	     */
	    v->uv_flags |= (VIFF_REXMIT_PRUNES | VIFF_POINT_TO_POINT);
	    if (addr == subnet)
		v->uv_rmt_addr = addr + htonl(1);
	    else
		v->uv_rmt_addr = subnet;
	}

	/*
	 * On Linux we can enumerate vifs using ifindex,
	 * no need for an IP address.  Also used for the
	 * VIF lookup in find_vif()
	 */
	v->uv_ifindex = priv_ifindex(v->uv_name);
	if (!v->uv_ifindex)
	    logit(LOG_ERR, errno, "Failed reading ifindex for %s", v->uv_name);

	if (v->uv_flags & VIFF_POINT_TO_POINT) {
	    logit(LOG_INFO, 0, "VIF #%u: Installing %s (%s -> %s) rate %d",
		  numvifs, v->uv_name, inet_fmt(addr, s1, sizeof(s1)), inet_fmt(v->uv_rmt_addr, s2, sizeof(s2)),
		  v->uv_rate_limit);
	} else {
	    logit(LOG_INFO, 0, "VIF #%u: Installing %s (%s on subnet %s) rate %d",
		  numvifs, v->uv_name, inet_fmt(addr, s1, sizeof(s1)), netname(subnet, mask),
		  v->uv_rate_limit);
	}

	++numvifs;

	/*
	 * If the interface is not yet up, set the vifs_down flag to
	 * remind us to check again later.
	 */
	if (!is_set(IFF_UP, flags)) {
	    v->uv_flags |= VIFF_DOWN;
	    vifs_down = TRUE;
	}
    }

    priv_freeifaddrs(ifaddr);
    tear_iflist();
}

void config_vifs_from_kernel(void)
{
    scan_vifs_from_kernel(0);
}

/*
 * The same scan against a running daemon: every interface the kernel has
 * gained since the last one becomes a VIF, appended above the VIFs that
 * are already there.  Returns the first index it may have used, so the
 * caller can tell which ones are new -- there is nothing else to tell them
 * by, a VIF carries no "just added" of its own.
 */
vifi_t config_vifs_rescan(void)
{
    vifi_t first = numvifs;

    scan_vifs_from_kernel(1);

    return first;
}

/*
 * Apply the phyint lines of the configuration file, and only those, to the
 * VIFs from @first up: what a VIF that appeared after start-up has missed.
 *
 * Not config_vifs_from_file(), which is for a (re)start and resets the
 * candidate RP and BSR state, the SSM ranges, the register filter and the
 * anycast-RP sets on its way through.  Running that because an interface
 * turned up would tear down protocol state that has nothing to do with it.
 */
void config_phyints_from_file(vifi_t first)
{
    char linebuf[LINE_BUFSIZ];
    char *w, *s;
    FILE *fp;

    fp = priv_fopen_conf();
    if (!fp)
	return;

    lineno = 0;
    phyint_first = first;

    while (fgets(linebuf, sizeof(linebuf), fp)) {
	lineno++;
	s = linebuf;
	w = next_word(&s);

	if (parse_option(w) == CONF_PHYINT)
	    parse_phyint(s);
    }

    phyint_first = 0;
    fclose(fp);
}

/**
 * parse_option - Convert result of string comparisons into numerics.
 * @input: Pointer to the word
 *
 * This function is called by config_vifs_from_file().
 *
 * Returns:
 * A number corresponding to the code of the word, or %CONF_UNKNOWN.
 */
static int parse_option(char *word)
{
    if (EQUAL(word, ""))
	return CONF_EMPTY;
    if (EQUAL(word, "no"))
	return CONF_NO;
    if (EQUAL(word, "disable-vifs"))
	return CONF_DISABLE_VIFS;
    if (EQUAL(word, "phyint"))
	return CONF_PHYINT;
    if (EQUAL(word, "bsr-candidate"))
	return CONF_BOOTSTRAP_RP;
    if (EQUAL(word, "rp-candidate"))
	return CONF_CANDIDATE_RP;
    if (EQUAL(word, "rp-address"))
	return CONF_RP_ADDRESS;
    if (EQUAL(word, "group-prefix"))
	return CONF_GROUP_PREFIX;
    if (EQUAL(word, "ssm-range"))
	return CONF_SSM_RANGE;
    if (EQUAL(word, "register-accept-from"))
	return CONF_REGISTER_ACCEPT_FROM;
    if (EQUAL(word, "anycast-rp"))
	return CONF_ANYCAST_RP;
    if (EQUAL(word, "spt-threshold"))
	return CONF_SPT_THRESHOLD;
    if (EQUAL(word, "default-route-metric"))
	return CONF_DEFAULT_ROUTE_METRIC;
    if (EQUAL(word, "default-route-distance"))
	return CONF_DEFAULT_ROUTE_DISTANCE;
    if (EQUAL(word, "igmp-query-interval"))
	return CONF_IGMP_QUERY_INTERVAL;
    if (EQUAL(word, "igmp-querier-timeout"))
	return CONF_IGMP_QUERIER_TIMEOUT;
    if (EQUAL(word, "altnet"))
	return CONF_ALTNET;
    if  (EQUAL(word, "masklen"))
	return CONF_MASKLEN;
    if  (EQUAL(word, "scoped"))
	return CONF_SCOPED;
    if (EQUAL(word, "hello-interval"))
	return CONF_HELLO_INTERVAL;
    if (EQUAL(word, "rpt-prune-limit"))
	return CONF_RPT_PRUNE_LIMIT;
    if (EQUAL(word, "local-sg-limit"))
	return CONF_LOCAL_SG_LIMIT;
    if (EQUAL(word, "register-sg-limit"))
	return CONF_REGISTER_SG_LIMIT;
    if (EQUAL(word, "assert-preference"))
	return CONF_ASSERT_PREFERENCE;
    if (EQUAL(word, "autorp"))
	return CONF_AUTORP;
    if (EQUAL(word, "autorp-limit"))
	return CONF_AUTORP_LIMIT;

    return CONF_UNKNOWN;
}

/* Check for optional /PREFIXLEN suffix to the address/group */
static void parse_prefix_len(char *token, uint32_t *len)
{
    char *masklen = strchr(token, '/');

    if (masklen) {
	*masklen = 0;
	masklen++;
	/*
	 * != 1, not !sscanf(): sscanf() answers EOF, not zero, when the
	 * string holds nothing to convert -- "224.0.0.0/" with the length
	 * left off -- so !sscanf() is false on precisely the input this
	 * has to catch, and both the warning and the default below are
	 * skipped.  *len then keeps whatever the caller had in it.
	 */
	if (sscanf(masklen, "%u", len) != 1) {
	    WARN("Invalid masklen '%s'", masklen);
	    *len = PIM_GROUP_PREFIX_DEFAULT_MASKLEN;
	}
    }
}

static void validate_prefix_len(uint32_t *len)
{
    if (*len > (sizeof(uint32_t) * 8)) {
	*len = (sizeof(uint32_t) * 8);
    } else if (*len < PIM_GROUP_PREFIX_MIN_MASKLEN) {
	WARN("Too small masklen %u. Defaulting to %d", *len, PIM_GROUP_PREFIX_MIN_MASKLEN);
	*len = PIM_GROUP_PREFIX_MIN_MASKLEN;
    }
}

static void reset_ssm_ranges(void)
{
    struct ssm_range *range, *next;

    for (range = ssm_list; range; range = next) {
	next = range->next;
	free(range);
    }

    ssm_list = NULL;
}

static int add_ssm_range(uint32_t group, uint32_t masklen)
{
    struct ssm_range *range;
    size_t num = 0;

    /* VAL_TO_MASK() shifts by 32 - masklen, so a masklen of zero, or one
     * larger than the address, is undefined behaviour rather than a wrong
     * answer.  Both callers bound it already, this keeps a third one from
     * having to remember. */
    if (masklen < PIM_GROUP_PREFIX_MIN_MASKLEN || masklen > sizeof(uint32_t) * 8) {
	logit(LOG_WARNING, 0, "Invalid SSM range masklen %u, ignoring", masklen);
	return FALSE;
    }

    for (range = ssm_list; range; range = range->next)
	num++;

    if (num >= SSM_MAX_RANGES) {
	logit(LOG_WARNING, 0, "Too many SSM group ranges configured, at most %d", SSM_MAX_RANGES);
	return FALSE;
    }

    range = calloc(1, sizeof(*range));
    if (!range) {
	logit(LOG_WARNING, 0, "Out of memory when adding SSM range %s/%u",
	      inet_fmt(group, s1, sizeof(s1)), masklen);
	return FALSE;
    }

    VAL_TO_MASK(range->mask, masklen);
    range->group   = group & range->mask;
    range->masklen = masklen;

    range->next = ssm_list;
    ssm_list = range;

    logit(LOG_INFO, 0, "SSM group range %s/%u",
	  inet_fmt(range->group, s1, sizeof(s1)), masklen);

    return TRUE;
}

/*
 * Fall back to the default SSM range, RFC 4607, when pimd.conf has no
 * usable ssm-range of its own.  Called both when the file has been read
 * and, defensively, from is_ssm_group() in case it has not.
 */
static void default_ssm_range(void)
{
    if (!ssm_list)
	add_ssm_range(htonl(PIM_SSM_RANGE_DEFAULT_GROUP), PIM_SSM_RANGE_DEFAULT_MASKLEN);
}

/**
 * is_ssm_group - Is this group Source Specific Multicast?
 * @group: Group address, in network byte order
 *
 * Returns:
 * %TRUE if @group falls in one of the SSM ranges in effect, o.w. %FALSE
 */
int is_ssm_group(uint32_t group)
{
    struct ssm_range *range;

    default_ssm_range();

    for (range = ssm_list; range; range = range->next) {
	if ((group & range->mask) == range->group)
	    return TRUE;
    }

    return FALSE;
}

/*
 * The SSM ranges in effect, for "pimctl show status".  One line, in the
 * column layout the rest of that listing uses.
 */
void dump_ssm_ranges(FILE *fp)
{
    struct ssm_range *range;

    default_ssm_range();

    fprintf(fp, "SSM group ranges     :");
    for (range = ssm_list; range; range = range->next)
	fprintf(fp, " %s/%u", inet_fmt(range->group, s1, sizeof(s1)), range->masklen);
    fprintf(fp, "\n");
}


static void reset_reg_acl(void)
{
    struct reg_acl *acl, *next;

    for (acl = reg_acl_list; acl; acl = next) {
	next = acl->next;
	free(acl);
    }

    reg_acl_list = NULL;
}

static int add_reg_acl(uint32_t addr, uint32_t masklen)
{
    struct reg_acl *acl;
    size_t num = 0;

    /* VAL_TO_MASK() shifts by 32 - masklen, so bound it here the way
     * add_ssm_range() does rather than trust the caller. */
    if (masklen < 1 || masklen > sizeof(uint32_t) * 8) {
	logit(LOG_WARNING, 0, "Invalid register-accept-from masklen %u, ignoring", masklen);
	return FALSE;
    }

    for (acl = reg_acl_list; acl; acl = acl->next)
	num++;

    if (num >= REG_ACL_MAX_ENTRIES) {
	logit(LOG_WARNING, 0, "Too many register-accept-from prefixes, at most %d",
	      REG_ACL_MAX_ENTRIES);
	return FALSE;
    }

    acl = calloc(1, sizeof(*acl));
    if (!acl) {
	logit(LOG_WARNING, 0, "Out of memory when adding register-accept-from %s/%u",
	      inet_fmt(addr, s1, sizeof(s1)), masklen);
	return FALSE;
    }

    VAL_TO_MASK(acl->mask, masklen);
    acl->addr    = addr & acl->mask;
    acl->masklen = masklen;

    acl->next = reg_acl_list;
    reg_acl_list = acl;

    logit(LOG_INFO, 0, "Accepting Register messages from %s/%u",
	  inet_fmt(acl->addr, s1, sizeof(s1)), masklen);

    return TRUE;
}

/**
 * register_accepted_from - May this router register to us?
 * @addr: Source address of the Register message, in network byte order
 *
 * RFC 7761 sec. 6.2: an RP SHOULD be able to restrict the addresses it
 * accepts Register-encapsulated packets from, and every option of that
 * kind MUST default to accepting all of them.  The default here is an
 * empty list, which is that default.
 *
 * Returns:
 * %TRUE if @addr is covered by a register-accept-from prefix, or if none
 * is configured, o.w. %FALSE
 */
int register_accepted_from(uint32_t addr)
{
    struct reg_acl *acl;

    if (!reg_acl_list)
	return TRUE;

    for (acl = reg_acl_list; acl; acl = acl->next) {
	if ((addr & acl->mask) == acl->addr)
	    return TRUE;
    }

    return FALSE;
}

/*
 * The Register senders we accept, for "pimctl show status".  Silent when
 * nothing is configured, so that the common case does not grow a line
 * saying it has no policy.
 */
void dump_reg_acl(FILE *fp)
{
    struct reg_acl *acl;

    if (!reg_acl_list)
	return;

    fprintf(fp, "Register accept list :");
    for (acl = reg_acl_list; acl; acl = acl->next)
	fprintf(fp, " %s/%u", inet_fmt(acl->addr, s1, sizeof(s1)), acl->masklen);
    fprintf(fp, "\n");
}


static void reset_anycast_rp(void)
{
    struct anycast_rp *arp, *next;

    for (arp = anycast_rp_list; arp; arp = next) {
	next = arp->next;
	free(arp);
    }

    anycast_rp_list = NULL;
}

/*
 * Appended rather than pushed, so that a set is listed in the order its
 * lines were written.
 */
static int add_anycast_rp(uint32_t anycast, uint32_t member)
{
    struct anycast_rp *arp, **tail;
    size_t num = 0, members = 0;

    for (tail = &anycast_rp_list; *tail; tail = &(*tail)->next) {
	arp = *tail;
	num++;

	if (arp->anycast != anycast)
	    continue;

	if (arp->member == member) {
	    WARN("anycast-rp %s %s given twice, ignoring", inet_fmt(anycast, s1, sizeof(s1)),
		 inet_fmt(member, s2, sizeof(s2)));
	    return FALSE;
	}
	members++;
    }

    if (num >= ANYCAST_RP_MAX_ENTRIES) {
	WARN("Too many anycast-rp lines, at most %d", ANYCAST_RP_MAX_ENTRIES);
	return FALSE;
    }

    if (members >= ANYCAST_RP_MAX_MEMBERS) {
	WARN("Too many members for anycast-rp %s, at most %d", inet_fmt(anycast, s1, sizeof(s1)),
	     ANYCAST_RP_MAX_MEMBERS);
	return FALSE;
    }

    arp = calloc(1, sizeof(*arp));
    if (!arp) {
	logit(LOG_WARNING, 0, "Out of memory when adding anycast-rp %s %s",
	      inet_fmt(anycast, s1, sizeof(s1)), inet_fmt(member, s2, sizeof(s2)));
	return FALSE;
    }

    arp->anycast = anycast;
    arp->member  = member;
    arp->lineno  = lineno;
    *tail = arp;

    logit(LOG_INFO, 0, "Anycast-RP %s: member %s",
	  inet_fmt(anycast, s1, sizeof(s1)), inet_fmt(member, s2, sizeof(s2)));

    return TRUE;
}

/* The first entry of each set, so that a walk over the list visits every
 * anycast address once. */
static int anycast_rp_first(const struct anycast_rp *arp)
{
    const struct anycast_rp *prev;

    for (prev = anycast_rp_list; prev != arp; prev = prev->next) {
	if (prev->anycast == arp->anycast)
	    return FALSE;
    }

    return TRUE;
}

/*
 * What can be told wrong about a set once the whole file has been read,
 * each said once per set.  Nothing is refused here: interfaces come and go
 * after startup, and a set that does not work yet may work once an
 * address has been added, so these are warnings about the state at
 * startup or reload rather than errors.
 */
static void check_anycast_rp(void)
{
    struct anycast_rp *arp, *m;

    for (arp = anycast_rp_list; arp; arp = arp->next) {
	uint32_t local = INADDR_ANY_N;
	size_t nlocal = 0;

	if (!anycast_rp_first(arp))
	    continue;

	for (m = arp; m; m = m->next) {
	    if (m->anycast != arp->anycast)
		continue;

	    if (local_address(m->member) == NO_VIF) {
		/* The copies another member sends come from this address. */
		if (!register_accepted_from(m->member))
		    logit(LOG_WARNING, 0, "%s:%u - anycast-rp member %s is outside "
			  "register-accept-from", config_file, m->lineno,
			  inet_fmt(m->member, s1, sizeof(s1)));
		continue;
	    }

	    if (nlocal++ == 0)
		local = m->member;
	    else
		logit(LOG_WARNING, 0, "%s:%u - anycast-rp %s: %s and %s are both local, "
		      "a router is one member", config_file, m->lineno,
		      inet_fmt(arp->anycast, s1, sizeof(s1)), inet_fmt(local, s2, sizeof(s2)),
		      inet_fmt(m->member, s3, sizeof(s3)));
	}

	if (nlocal == 0)
	    logit(LOG_WARNING, 0, "%s:%u - anycast-rp %s: no member is local, "
		  "no Register will be copied", config_file, arp->lineno,
		  inet_fmt(arp->anycast, s1, sizeof(s1)));

	if (local_address(arp->anycast) == NO_VIF)
	    logit(LOG_WARNING, 0, "%s:%u - anycast-rp %s is not local, "
		  "this router cannot be the RP for it", config_file, arp->lineno,
		  inet_fmt(arp->anycast, s1, sizeof(s1)));

	/* RFC 3446 sec. 3.1: the anycast address is not unique, so it must
	 * not name the router.  A Cand-RP advertising it is what a member
	 * should do; a Cand-BSR using it is several routers claiming to be
	 * one BSR. */
	if (cand_bsr_flag && my_bsr_address == arp->anycast)
	    logit(LOG_WARNING, 0, "%s:%u - bsr-candidate %s is an anycast-rp address, "
		  "use a unique one", config_file,
		  arp->lineno, inet_fmt(arp->anycast, s1, sizeof(s1)));
    }
}

/**
 * anycast_rp_configured - Is there an Anycast-RP set for this RP address?
 * @anycast: RP address, in network byte order
 *
 * Returns:
 * %TRUE if an anycast-rp line names @anycast, o.w. %FALSE
 */
int anycast_rp_configured(uint32_t anycast)
{
    struct anycast_rp *arp;

    for (arp = anycast_rp_list; arp; arp = arp->next) {
	if (arp->anycast == anycast)
	    return TRUE;
    }

    return FALSE;
}

/**
 * anycast_rp_member - Is this address a member of an Anycast-RP set?
 * @anycast: RP address of the set, in network byte order
 * @addr:    Unique address to look for, in network byte order
 *
 * Returns:
 * %TRUE if @addr is listed as a member of the set for @anycast, o.w. %FALSE
 */
int anycast_rp_member(uint32_t anycast, uint32_t addr)
{
    struct anycast_rp *arp;

    for (arp = anycast_rp_list; arp; arp = arp->next) {
	if (arp->anycast == anycast && arp->member == addr)
	    return TRUE;
    }

    return FALSE;
}

/**
 * anycast_rp_member_at - The members of an Anycast-RP set, one at a time
 * @anycast: RP address of the set, in network byte order
 * @index:   Which member, from 0
 *
 * Returns:
 * The unique address of member @index, in the order the lines were
 * written, or %INADDR_ANY_N past the last one.
 */
uint32_t anycast_rp_member_at(uint32_t anycast, size_t index)
{
    struct anycast_rp *arp;

    for (arp = anycast_rp_list; arp; arp = arp->next) {
	if (arp->anycast != anycast)
	    continue;

	if (index-- == 0)
	    return arp->member;
    }

    return INADDR_ANY_N;
}

/**
 * anycast_rp_local - This router's own member of an Anycast-RP set
 * @anycast: RP address of the set, in network byte order
 *
 * Looked up now rather than when the file was read, see struct anycast_rp.
 *
 * Returns:
 * The first member address that is local, or %INADDR_ANY_N if none is.
 */
uint32_t anycast_rp_local(uint32_t anycast)
{
    struct anycast_rp *arp;

    for (arp = anycast_rp_list; arp; arp = arp->next) {
	if (arp->anycast == anycast && local_address(arp->member) != NO_VIF)
	    return arp->member;
    }

    return INADDR_ANY_N;
}

/**
 * anycast_rp_peers - Has this router other members to register to?
 * @anycast: RP address of the set, in network byte order
 *
 * Returns:
 * %TRUE if this router is a member of the set for @anycast and the set
 * has at least one other member, o.w. %FALSE
 */
int anycast_rp_peers(uint32_t anycast)
{
    uint32_t local, member;
    size_t i;

    local = anycast_rp_local(anycast);
    if (local == INADDR_ANY_N)
	return FALSE;

    for (i = 0; (member = anycast_rp_member_at(anycast, i)) != INADDR_ANY_N; i++) {
	if (member != local)
	    return TRUE;
    }

    return FALSE;
}

/* One more Register copied to @member, for "pimctl show status". */
void anycast_rp_copied(uint32_t anycast, uint32_t member)
{
    struct anycast_rp *arp;

    for (arp = anycast_rp_list; arp; arp = arp->next) {
	if (arp->anycast == anycast && arp->member == member) {
	    arp->copies++;
	    return;
	}
    }
}

/*
 * The Anycast-RP sets, for "pimctl show status", one line per set, with
 * this router's own member marked and the Registers copied to each of the
 * others counted since the file was last read.  Silent when nothing is
 * configured.
 */
void dump_anycast_rp(FILE *fp)
{
    struct anycast_rp *arp, *m;

    for (arp = anycast_rp_list; arp; arp = arp->next) {
	if (!anycast_rp_first(arp))
	    continue;

	fprintf(fp, "Anycast-RP set       : %s, members", inet_fmt(arp->anycast, s1, sizeof(s1)));
	for (m = arp; m; m = m->next) {
	    if (m->anycast != arp->anycast)
		continue;

	    if (local_address(m->member) != NO_VIF)
		fprintf(fp, " %s (this router)", inet_fmt(m->member, s1, sizeof(s1)));
	    else
		fprintf(fp, " %s (%u copies)", inet_fmt(m->member, s1, sizeof(s1)), m->copies);
	}
	fprintf(fp, "\n");
    }
}


/**
 * parse_phyint - Parse physical interface configuration, if any.
 * @s: String token
 *
 * Syntax:
 * phyint <local-addr | ifname> [disable | enable]
 *                              [igmpv2  | igmpv3]
 *                              [dr-priority <1-4294967294>]
 *                              [ttl-threshold <1-255>]
 *                              [distance <1-255>] [metric <1-1024>]
 *                              [altnet <net-addr>/<masklen>]
 *                              [altnet <net-addr> masklen <masklen>]
 *                              [scoped <net-addr>/<masklen>]
 *                              [scoped <net-addr> masklen <masklen>]
 *
 * Returns:
 * %TRUE(1) if the parsing was successful, o.w. %FALSE(0)
 */
static int parse_phyint(char *s)
{
    char *w, c;
    uint32_t local, altnet_addr, scoped_addr;
    vifi_t vifi;
    struct uvif *v;
    uint32_t n, altnet_mask, altnet_masklen = 0, scoped_masklen = 0;
    struct vif_acl *v_acl;
    int added;

    if (EQUAL((w = next_word(&s)), "")) {
	WARN("Missing phyint address");
	return FALSE;
    }

    local = ifname2addr(w);
    if (!local) {
	local = inet_parse(w, 4);
	if (!inet_valid_host(local)) {
	    WARN("Unknown phyint name or invalid address '%s', skipping.", w);
	    return FALSE;
	}
    }

    for (vifi = phyint_first, v = &uvifs[phyint_first]; vifi < numvifs; ++vifi, ++v) {

	if (local != v->uv_lcl_addr)
	    continue;

	while (!EQUAL((w = next_word(&s)), "")) {
	    char *t;

	    if (EQUAL(w, "disable")) {
		v->uv_flags |= VIFF_DISABLED;
		continue;
	    }

	    if (EQUAL(w, "enable")) {
		v->uv_flags &= ~VIFF_DISABLED;
		continue;
	    }

	    if (EQUAL(w, "igmpv2")) {
		v->uv_flags &= ~VIFF_IGMPV1;
		v->uv_flags |=  VIFF_IGMPV2;
		continue;
	    }

	    if (EQUAL(w, "igmpv3")) {
		v->uv_flags &= ~VIFF_IGMPV1;
		v->uv_flags &= ~VIFF_IGMPV2;
		continue;
	    }

	    if (EQUAL(w, "altnet")) {
		if (EQUAL((w = next_word(&s)), "")) {
		    WARN("Missing ALTNET for phyint %s", inet_fmt(local, s1, sizeof(s1)));
		    continue;
		}

		/*
		 * One phyint line may carry several altnets, and
		 * parse_prefix_len() only assigns when the token has a
		 * "/len".  Without this reset the previous altnet's length
		 * is still in there, and an altnet written without one
		 * silently inherits it instead of falling back to the
		 * interface netmask below.
		 */
		altnet_masklen = 0;
		parse_prefix_len (w, &altnet_masklen);

		altnet_addr = ifname2addr(w);
		if (!altnet_addr) {
		    altnet_addr = inet_parse(w, 4);
		    if (!inet_valid_host(altnet_addr)) {
			WARN("Invalid altnet address '%s'", w);
			return FALSE;
		    }
		}

		t = s;
		if (EQUAL((w = next_word(&s)), "masklen")) {
		    if (EQUAL((w = next_word(&s)), "")) {
			WARN("Missing ALTNET masklen for phyint %s", inet_fmt(local, s1, sizeof (s1)));
			continue;
		    }

		    if (sscanf(w, "%u", &altnet_masklen) != 1) {
			WARN("Invalid altnet masklen '%s' for phyint %s", w, inet_fmt(local, s1, sizeof(s1)));
			continue;
		    }
		} else {
		    /* Next token was not "masklen", restore s! */
		    s = t;
		}

		/*
		 * VAL_TO_MASK() shifts by 32 - masklen, so anything above 32
		 * shifts by more than the type is wide.  Zero needs no guard
		 * here, unlike in the scoped branch below: it never reaches
		 * the macro, it is how the vif's own netmask is asked for.
		 */
		if (altnet_masklen > 32) {
		    WARN("Too large (%u) altnet masklen for phyint %s", altnet_masklen,
			 inet_fmt(local, s1, sizeof(s1)));
		    continue;
		}

		if (altnet_masklen) {
		    VAL_TO_MASK(altnet_mask, altnet_masklen);
		} else {
		    altnet_mask = v->uv_subnetmask;
		}

		if (altnet_addr & ~altnet_mask)
		    WARN("Extra subnet %s/%d has host bits set", inet_fmt(altnet_addr, s1, sizeof(s1)), altnet_masklen);

		added = install_altnet(v, altnet_addr & altnet_mask, altnet_mask);
		if (added < 0)
		    return FALSE;

		/* netname(), not the masklen off the line: it is zero whenever
		 * the interface netmask was the one used */
		logit(LOG_DEBUG, 0, "ALTNET: %s%s", netname(altnet_addr & altnet_mask, altnet_mask),
		      added ? "" : ", already known");
	    } /* altnet */

	    /* scoped mcast groups/masklen */
	    if (EQUAL(w, "scoped")) {
		if (EQUAL((w = next_word(&s)), "")) {
		    WARN("Missing SCOPED for phyint %s", inet_fmt(local, s1, sizeof(s1)));
		    continue;
		}

		/* Same as the altnet branch above: one per keyword, not one
		 * per line */
		scoped_masklen = 0;
		parse_prefix_len (w, &scoped_masklen);

		scoped_addr = ifname2addr(w);
		if (!scoped_addr) {
		    scoped_addr = inet_parse(w, 4);
		    if (!IN_MULTICAST(ntohl(scoped_addr))) {
			WARN("Invalid scoped address '%s'", w);
			return FALSE;
		    }
		}

		t = s;
		if (EQUAL((w = next_word(&s)), "masklen")) {
		    if (EQUAL((w = next_word(&s)), "")) {
			WARN("Missing SCOPED masklen for phyint %s", inet_fmt(local, s1, sizeof(s1)));
			continue;
		    }
		    if (sscanf(w, "%u", &scoped_masklen) != 1) {
			WARN("Invalid scoped masklen '%s' for phyint %s", w, inet_fmt(local, s1, sizeof(s1)));
			continue;
		    }
		} else {
		    /* Next token was not "masklen", restore s! */
		    s = t;
		}

		/* Invalid config. VAL_TO_MASK() also requires len > 0 or shift op will fail. */
		if (!scoped_masklen) {
		    WARN("Too small (0) scoped masklen for phyint %s", inet_fmt(local, s1, sizeof(s1)));
		    continue;
		}

		/* And no more than 32, or it shifts by more than the type is wide. */
		if (scoped_masklen > 32) {
		    WARN("Too large (%u) scoped masklen for phyint %s", scoped_masklen,
			 inet_fmt(local, s1, sizeof(s1)));
		    continue;
		}

		v_acl = calloc(1, sizeof(struct vif_acl));
		if (!v_acl)
		    return FALSE;

		VAL_TO_MASK(v_acl->acl_mask, scoped_masklen);
		v_acl->acl_addr = scoped_addr & v_acl->acl_mask;
		if (scoped_addr & ~v_acl->acl_mask)
		    WARN("Boundary spec %s/%d has host bits set", inet_fmt(scoped_addr, s1, sizeof(s1)), scoped_masklen);

		v_acl->acl_next = v->uv_acl;
		v->uv_acl = v_acl;
		logit(LOG_DEBUG, 0, "SCOPED %s/%x", inet_fmt(v_acl->acl_addr, s1, sizeof(s1)), v_acl->acl_mask);
	    } /* scoped */

	    /* RFC 7761 sec. 6.2: "A PIM router SHOULD provide an option to
	     * limit the set of neighbors from which it will accept
	     * Join/Prune, Assert, and Hello messages", by static
	     * configuration of addresses or by an IPsec SA.  This is the
	     * first of those.  Without it every router that sends a
	     * syntactically valid Hello on a subnet pimd has a VIF on
	     * becomes a neighbor of it, and from there can take the DR
	     * role, take part in the assert election, and have its Joins
	     * believed.
	     *
	     * Repeatable on one phyint line, like altnet above, and with
	     * the same "addr/len" or "addr masklen len" spelling.
	     */
	    if (EQUAL(w, "accept-nbr-from")) {
		struct phaddr *pa;
		uint32_t acl_addr;
		uint32_t acl_masklen = 0;

		if (EQUAL((w = next_word(&s)), "")) {
		    WARN("Missing accept-nbr-from prefix for phyint %s", inet_fmt(local, s1, sizeof(s1)));
		    continue;
		}

		parse_prefix_len(w, &acl_masklen);

		acl_addr = inet_parse(w, 4);
		if (acl_addr == 0xffffffff) {
		    WARN("Invalid accept-nbr-from address '%s'", w);
		    continue;
		}

		t = s;
		if (EQUAL((w = next_word(&s)), "masklen")) {
		    if (EQUAL((w = next_word(&s)), "") || sscanf(w, "%u", &acl_masklen) != 1) {
			WARN("Invalid accept-nbr-from masklen for phyint %s", inet_fmt(local, s1, sizeof(s1)));
			continue;
		    }
		} else {
		    s = t;
		}

		if (!acl_masklen)
		    acl_masklen = 32;	/* one router, the common case */

		/* VAL_TO_MASK() shifts by 32 - masklen, the same hazard the
		 * altnet branch above guards.
		 */
		if (acl_masklen > 32) {
		    WARN("Too large (%u) accept-nbr-from masklen for phyint %s",
			 acl_masklen, inet_fmt(local, s1, sizeof(s1)));
		    continue;
		}

		pa = calloc(1, sizeof(*pa));
		if (!pa) {
		    logit(LOG_WARNING, 0, "Out of memory when adding accept-nbr-from");
		    continue;
		}

		VAL_TO_MASK(pa->pa_subnetmask, acl_masklen);
		pa->pa_subnet = acl_addr & pa->pa_subnetmask;
		pa->pa_next = v->uv_nbr_acl;
		v->uv_nbr_acl = pa;

		logit(LOG_INFO, 0, "Accepting PIM on %s from %s/%u", v->uv_name,
		      inet_fmt(pa->pa_subnet, s1, sizeof(s1)), acl_masklen);
		continue;
	    } /* accept-nbr-from */

	    if (EQUAL(w, "ttl-threshold") || EQUAL(w, "threshold")) {
		if (EQUAL((w = next_word(&s)), "")) {
		    WARN("Missing threshold for phyint %s", inet_fmt(local, s1, sizeof(s1)));
		    continue;
		}

		if (sscanf(w, "%u%c", &n, &c) != 1 || n < 1 || n > 255 ) {
		    WARN("Invalid threshold '%s' for phyint %s", w, inet_fmt(local, s1, sizeof(s1)));
		    continue;
		}

		v->uv_threshold = n;
		continue;
	    } /* threshold */

	    if (EQUAL(w, "distance") || EQUAL(w, "preference")) {
		if (EQUAL((w = next_word(&s)), "")) {
		    WARN("Missing distance value for phyint %s", inet_fmt(local, s1, sizeof(s1)));
		    continue;
		}

		if (sscanf(w, "%u%c", &n, &c) != 1 || n < 1 || n > 255 ) {
		    WARN("Invalid distance value '%s' for phyint %s", w, inet_fmt(local, s1, sizeof(s1)));
		    continue;
		}

		IF_DEBUG(DEBUG_PIM_ASSERT)
		    logit(LOG_DEBUG, 0, "Config setting default local preference on %s to %d", inet_fmt(local, s1, sizeof(s1)), n);

		v->uv_local_pref = n;
		continue;
	    }

	    if (EQUAL(w, "metric")) {
		if (EQUAL((w = next_word(&s)), "")) {
		    WARN("Missing metric value for phyint %s", inet_fmt(local, s1, sizeof(s1)));
		    continue;
		}

		if (sscanf(w, "%u%c", &n, &c) != 1 || n < 1 || n > 1024 ) {
		    WARN("Invalid metric value '%s' for phyint %s", w, inet_fmt(local, s1, sizeof(s1)));
		    continue;
		}

		IF_DEBUG(DEBUG_PIM_ASSERT)
		    logit(LOG_DEBUG, 0, "Setting default local metric on %s to %d", inet_fmt(local, s1, sizeof(s1)), n);

		v->uv_local_metric = n;
		continue;
	    }

	    if (EQUAL(w, "dr-priority")) {
		if (EQUAL((w = next_word(&s)), "")) {
		    WARN("Missing dr-priority value for phyint %s", inet_fmt(local, s1, sizeof(s1)));
		    continue;
		}

		if (sscanf(w, "%u%c", &n, &c) != 1 || n < 1 || n > 4294967294u) {
		    WARN("Invalid dr-priority value '%s' for phyint %s", w, inet_fmt(local, s1, sizeof(s1)));
		    continue;
		}

		IF_DEBUG(DEBUG_PIM_HELLO)
		    logit(LOG_DEBUG, 0, "Setting dr-priority on %s to %d", inet_fmt(local, s1, sizeof(s1)), n);

		v->uv_dr_prio = n;
		continue;
	    }
	} /* while(... != "") */

	break;
    }
    if (vifi == numvifs) {
	WARN("phyint %s is not a valid interface", inet_fmt(local, s1, sizeof(s1)));
	return FALSE;
    }

    return TRUE;
}


/**
 * parse_rp_candidate - Parse candidate Rendez-Vous Point information.
 * @s: String token
 *
 * Syntax:
 * rp-candidate [address | ifname] [priority <0-255>] [interval <10-16383>]
 *
 * Returns:
 * %TRUE if the parsing was successful, o.w. %FALSE
 */
static int parse_rp_candidate(char *s)
{
    u_int time = PIM_DEFAULT_CAND_RP_ADV_PERIOD;
    u_int priority = PIM_DEFAULT_CAND_RP_PRIORITY;
    char *w;
    uint32_t local = INADDR_ANY_N;

    while (!EQUAL((w = next_word(&s)), "")) {
	if (EQUAL(w, "priority")) {
	    if (EQUAL((w = next_word(&s)), "")) {
		WARN("Missing Cand-RP priority, defaulting to %u", PIM_DEFAULT_CAND_RP_PRIORITY);
		priority = PIM_DEFAULT_CAND_RP_PRIORITY;
		continue;
	    }

	    if (sscanf(w, "%u", &priority) != 1) {
		WARN("Invalid Cand-RP priority %s, defaulting to %u", w, PIM_DEFAULT_CAND_RP_PRIORITY);
		priority = PIM_DEFAULT_CAND_RP_PRIORITY;
	    }

	    if (priority > PIM_MAX_CAND_RP_PRIORITY) {
		WARN("Too high Cand-RP priority %u, defaulting to %d", priority, PIM_MAX_CAND_RP_PRIORITY);
		priority = PIM_MAX_CAND_RP_PRIORITY;
	    }

	    continue;
	}

	/* 'time' is old syntax, 'interval' new */
	if (EQUAL(w, "time") || EQUAL(w, "interval")) {
	    if (EQUAL((w = next_word(&s)), "")) {
		WARN("Missing Cand-RP announce interval, defaulting to %u", PIM_DEFAULT_CAND_RP_ADV_PERIOD);
		time = PIM_DEFAULT_CAND_RP_ADV_PERIOD;
		continue;
	    }

	    if (sscanf(w, "%u", &time) != 1) {
		WARN("Invalid Cand-RP announce interval, defaulting to %u", PIM_DEFAULT_CAND_RP_ADV_PERIOD);
		time = PIM_DEFAULT_CAND_RP_ADV_PERIOD;
		continue;
	    }

	    if (time < PIM_MIN_CAND_RP_ADV_PERIOD)
		time = PIM_MIN_CAND_RP_ADV_PERIOD;

	    if (time > PIM_MAX_CAND_RP_ADV_PERIOD)
		time = PIM_MAX_CAND_RP_ADV_PERIOD;

	    continue;
	}

	/* Cand-RP interface or address */
	local = ifname2addr(w);
	if (!local)
	    local = inet_parse(w, 4);

	if (!inet_valid_host(local)) {
	    local = max_local_address();
	    WARN("Invalid Cand-RP address '%s', defaulting to %s", w, inet_fmt(local, s1, sizeof(s1)));
	} else if (local_address(local) == NO_VIF) {
	    local = max_local_address();
	    WARN("Cand-RP address '%s' is not local, defaulting to %s", w, inet_fmt(local, s1, sizeof(s1)));
	}
    }

    if (local == INADDR_ANY_N) {
	/* If address not provided, use the max. local */
	local = max_local_address();
    }

    my_cand_rp_address = local;
    my_cand_rp_priority = priority;
    my_cand_rp_adv_period = time;
    cand_rp_flag = TRUE;

    logit(LOG_INFO, 0, "Local Cand-RP address %s, priority %u, interval %u sec",
	  inet_fmt(local, s1, sizeof(s1)), priority, time);

    return TRUE;
}


/**
 * parse_group_prefix - Parse group-prefix configured information.
 * @s: String token

 * Syntax:
 * group-prefix <group>[/<masklen>]
 *              <group> [masklen <masklen>]
 *
 * Returns:
 * %TRUE if the parsing was successful, o.w. %FALSE
 */
static int parse_group_prefix(char *s)
{
    char *w;
    uint32_t group_addr;
    uint32_t  masklen = PIM_GROUP_PREFIX_DEFAULT_MASKLEN;

    w = next_word(&s);
    if (EQUAL(w, "")) {
	WARN("Missing group-prefix address");
	return FALSE;
    }

    parse_prefix_len (w, &masklen);

    group_addr = inet_parse(w, 4);
    if (!IN_MULTICAST(ntohl(group_addr))) {
	WARN("Group address '%s' is not a valid multicast address", inet_fmt(group_addr, s1, sizeof(s1)));
	return FALSE;
    }

    /* Was if (!(~(*cand_rp_adv_message.prefix_cnt_ptr))) which Arm GCC 4.4.2 dislikes:
     *  --> "config.c:693: warning: promoted ~unsigned is always non-zero"
     * The prefix_cnt_ptr is a uint8_t so it seems this check was to prevent overruns.
     * I've changed the check to see if we've already read 255 entries, if so the cnt
     * is maximized and we need to tell the user. --Joachim Wiberg 2010-01-16 */
    if (*cand_rp_adv_message.prefix_cnt_ptr == 255) {
	WARN("Too many multicast groups configured!");
	return FALSE;
    }

    if (EQUAL((w = next_word(&s)), "masklen")) {
	w = next_word(&s);
	if (sscanf(w, "%u", &masklen) != 1)		/* EOF, see parse_prefix_len() */
	    masklen = PIM_GROUP_PREFIX_DEFAULT_MASKLEN;
    }

    validate_prefix_len(&masklen);

    PUT_EGADDR(group_addr, (uint8_t)masklen, 0, cand_rp_adv_message.insert_data_ptr);
    (*cand_rp_adv_message.prefix_cnt_ptr)++;

    logit(LOG_INFO, 0, "Adding Cand-RP group prefix %s/%d", inet_fmt(group_addr, s1, sizeof(s1)), masklen);

    return TRUE;
}


/**
 * parse_ssm_range - Parse ssm-range configured information.
 * @s: String token
 *
 * The configured ranges replace the default one, 232.0.0.0/8 of RFC 4607,
 * the way Cisco's 'ip pim ssm range' does.  Keeping the default alongside
 * a range of your own takes an explicit 'ssm-range default'.
 *
 * Syntax:
 * ssm-range default
 * ssm-range <group>[/<masklen>]
 *           <group> [masklen <masklen>]
 *
 * Returns:
 * %TRUE if the parsing was successful, o.w. %FALSE
 */
static int parse_ssm_range(char *s)
{
    uint32_t masklen = PIM_GROUP_PREFIX_DEFAULT_MASKLEN;
    uint32_t group, mask;
    const char *errstr;
    long long num;
    char *w;

    w = next_word(&s);
    if (EQUAL(w, "")) {
	WARN("Missing ssm-range group address");
	return FALSE;
    }

    if (EQUAL(w, "default")) {
	group   = htonl(PIM_SSM_RANGE_DEFAULT_GROUP);
	masklen = PIM_SSM_RANGE_DEFAULT_MASKLEN;
	goto add;
    }

    parse_prefix_len (w, &masklen);

    group = inet_parse(w, 4);
    if (!IN_MULTICAST(ntohl(group))) {
	WARN("Group address '%s' is not a valid multicast address", inet_fmt(group, s1, sizeof(s1)));
	return FALSE;
    }

    if (EQUAL((w = next_word(&s)), "masklen")) {
	w = next_word(&s);
	num = strtonum(w, PIM_GROUP_PREFIX_MIN_MASKLEN, sizeof(uint32_t) * 8, &errstr);
	if (errstr) {
	    WARN("Invalid ssm-range masklen %s, %s", w, errstr);
	    return FALSE;
	}

	masklen = (uint32_t)num;
    }

    validate_prefix_len(&masklen);

    /* The link-local groups are never source specific, RFC 5771 sec. 4 */
    VAL_TO_MASK(mask, masklen < 24 ? masklen : 24);
    if ((group & mask) == (htonl(INADDR_UNSPEC_GROUP) & mask)) {
	WARN("SSM range %s/%u overlaps the link-local groups 224.0.0.0/24",
	     inet_fmt(group, s1, sizeof(s1)), masklen);
	return FALSE;
    }

  add:
    return add_ssm_range(group, masklen);
}


/**
 * parse_register_accept_from - Parse register-accept-from configuration.
 * @s: String token
 *
 * The prefixes given are the routers whose Register messages this RP will
 * act on; every other sender is ignored, silently, because an answer is
 * what a forged Register wants.  RFC 7761 sec. 6.2 asks for the option and
 * requires it to default to accepting everything, so an empty list, which
 * is what a pimd.conf without this keyword leaves, accepts every sender.
 *
 * Note that this matches the sender of the Register, the DR, and not the
 * source address of the packet inside it -- Cisco's 'ip pim accept-register'
 * is the latter and is a different control.  Note also that it reaches the
 * control plane only; see the comment in receive_pim_register().
 *
 * Syntax:
 * register-accept-from <address>[/<masklen>]
 *                      <address> [masklen <masklen>]
 *
 * Returns:
 * %TRUE if the parsing was successful, o.w. %FALSE
 */
static int parse_register_accept_from(char *s)
{
    uint32_t masklen = sizeof(uint32_t) * 8;
    const char *errstr;
    long long num;
    uint32_t addr;
    char *w;

    w = next_word(&s);
    if (EQUAL(w, "")) {
	WARN("Missing register-accept-from address");
	return FALSE;
    }

    parse_prefix_len(w, &masklen);

    addr = inet_parse(w, 4);
    if (addr == 0xffffff || !inet_valid_host(addr)) {
	WARN("Invalid register-accept-from address '%s'", w);
	return FALSE;
    }

    if (EQUAL((w = next_word(&s)), "masklen")) {
	w = next_word(&s);
	num = strtonum(w, 1, sizeof(uint32_t) * 8, &errstr);
	if (errstr) {
	    WARN("Invalid register-accept-from masklen %s, %s", w, errstr);
	    return FALSE;
	}

	masklen = (uint32_t)num;
    }

    return add_reg_acl(addr, masklen);
}


/**
 * parse_anycast_rp - Parse anycast-rp configuration.
 * @s: String token
 *
 * One member of an Anycast-RP set (RFC 4610): @anycast is the RP address
 * every member holds, @member the unique address of one of them, which is
 * where Registers are copied to.  A set is every line with the same
 * anycast address, this router's own unique address included, as RFC 4610
 * Appendix A suggests so that the lines can be the same on every member.
 *
 * Syntax:
 * anycast-rp <anycast-address> <member-address>
 *
 * Returns:
 * %TRUE if the parsing was successful, o.w. %FALSE
 */
static int parse_anycast_rp(char *s)
{
    uint32_t anycast, member;
    char *w;

    w = next_word(&s);
    if (EQUAL(w, "")) {
	WARN("Missing anycast-rp address");
	return FALSE;
    }

    anycast = inet_parse(w, 4);
    if (anycast == 0xffffff || !inet_valid_host(anycast)) {
	WARN("Invalid anycast-rp address '%s'", w);
	return FALSE;
    }

    w = next_word(&s);
    if (EQUAL(w, "")) {
	WARN("Missing member address for anycast-rp %s", inet_fmt(anycast, s1, sizeof(s1)));
	return FALSE;
    }

    member = inet_parse(w, 4);
    if (member == 0xffffff || !inet_valid_host(member)) {
	WARN("Invalid anycast-rp member address '%s'", w);
	return FALSE;
    }

    /* RFC 4610 sec. 3: the addresses the members talk to each other with
     * must be different from the anycast address. */
    if (member == anycast) {
	WARN("anycast-rp member %s is the anycast address, a member needs a unique one",
	     inet_fmt(member, s1, sizeof(s1)));
	return FALSE;
    }

    return add_anycast_rp(anycast, member);
}


/**
 * parse_bsr_candidate - Parse the candidate BSR configured information.
 * @s: String token
 *
 * Syntax:
 * bsr-candidate [address | ifname] [priority <0-255>] [interval <10-26214>]
 */
static int parse_bsr_candidate(char *s)
{
    u_int time = PIM_BOOTSTRAP_PERIOD;
    uint32_t priority = PIM_DEFAULT_BSR_PRIORITY;
    char *w;
    uint32_t local = INADDR_ANY_N;

    while (!EQUAL((w = next_word(&s)), "")) {
	if (EQUAL(w, "priority")) {
	    if (EQUAL((w = next_word(&s)), "")) {
		WARN("Missing Cand-BSR priority, defaulting to %u", PIM_DEFAULT_BSR_PRIORITY);
		priority = PIM_DEFAULT_BSR_PRIORITY;
		continue;
	    }

	    if (sscanf(w, "%u", &priority) != 1) {
		WARN("Invalid Cand-BSR priority %s, defaulting to %u", w, PIM_DEFAULT_BSR_PRIORITY);
		priority = PIM_DEFAULT_BSR_PRIORITY;
		continue;
	    }

	    if (priority > PIM_MAX_CAND_BSR_PRIORITY) {
		WARN("Too high Cand-BSR priority %u, defaulting to %d", priority, PIM_MAX_CAND_BSR_PRIORITY);
		priority = PIM_MAX_CAND_BSR_PRIORITY;
	    }

	    my_bsr_priority = (uint8_t)priority;
	    continue;
	}

	if (EQUAL(w, "interval")) {
	    if (EQUAL((w = next_word(&s)), "")) {
		WARN("Missing Cand-BSR announce interval, defaulting to %u", PIM_BOOTSTRAP_PERIOD);
		time = PIM_BOOTSTRAP_PERIOD;
		continue;
	    }

	    if (sscanf(w, "%u", &time) != 1) {
		WARN("Invalid Cand-BSR announce interval, defaulting to %u", PIM_BOOTSTRAP_PERIOD);
		time = PIM_BOOTSTRAP_PERIOD;
		continue;
	    }

	    if (time < PIM_MIN_BOOTSTRAP_PERIOD)
		time = PIM_MIN_BOOTSTRAP_PERIOD;

	    if (time > PIM_MAX_BOOTSTRAP_PERIOD)
		time = PIM_MAX_BOOTSTRAP_PERIOD;

	    continue;
	}

	/* Cand-BSR interface or address */
	local = ifname2addr(w);
	if (!local)
	    local = inet_parse(w, 4);

	if (!inet_valid_host(local)) {
	    local = max_local_address();
	    WARN("Invalid Cand-BSR address '%s', defaulting to %s", w, inet_fmt(local, s1, sizeof(s1)));
	    continue;
	}

	if (local_address(local) == NO_VIF) {
	    local = max_local_address();
	    WARN("Cand-BSR address '%s' is not local, defaulting to %s", w, inet_fmt(local, s1, sizeof(s1)));
	}
    }

    if (local == INADDR_ANY_N) {
	/* If address not provided, use the max. local */
	local = max_local_address();
    }

    my_bsr_address  = local;
    my_bsr_priority = priority;
    MASKLEN_TO_MASK(RP_DEFAULT_IPV4_HASHMASKLEN, my_bsr_hash_mask);
    my_bsr_adv_period = time;
    cand_bsr_flag   = TRUE;

    logit(LOG_INFO, 0,
    		"Local Cand-BSR address %s, priority %u, interval %u sec",
		inet_fmt(local, s1, sizeof(s1)), priority, time);

    return TRUE;
}

/**
 * parse_rp_address - Parse rp-address config option.
 * @s: String token.
 *
 * This is an extension to the original pimd to add pimd.conf support for static
 * Rendez-Vous Point addresses.
 *
 * The function has been extended by pjf@asn.pl, of Lintrack, to allow specifying
 * multicast group addresses as well.
 *
 * Syntax:
 * rp-address <ADDRESS> [<GROUP>[</LENGTH> masklen <LENGTH>]
 *
 * Returns:
 * When parsing @s is successful this function returns %TRUE, otherwise %FALSE.
 */
static int parse_rp_address(char *s)
{
    char *w;
    uint32_t local = 0xffffff;
    uint32_t group_addr = htonl(INADDR_UNSPEC_GROUP);
    uint32_t masklen = PIM_GROUP_PREFIX_DEFAULT_MASKLEN;
    struct rp_hold *rph;

    /* next is RP addr */
    w = next_word(&s);
    if (EQUAL(w, "")) {
	logit(LOG_WARNING, 0, "Missing rp-address argument");
	return FALSE;
    }

    local = inet_parse(w, 4);
    if (local == 0xffffff) {
	WARN("Invalid rp-address %s", w);
	return FALSE;
    }

    /* next is group addr if exist */
    w = next_word(&s);
    if (!EQUAL(w, "")) {
	parse_prefix_len (w, &masklen);

	group_addr = inet_parse(w, 4);
	if (!IN_MULTICAST(ntohl(group_addr))) {
	    WARN("%s is not a valid multicast address", inet_fmt(group_addr, s1, sizeof(s1)));
	    return FALSE;
	}

	/* next is prefix or priority if exist */
	while (!EQUAL((w = next_word(&s)), "")) {
	    if (EQUAL(w, "masklen")) {
		w = next_word(&s);
		if (sscanf(w, "%u", &masklen) != 1) {	/* EOF, see parse_prefix_len() */
		    WARN("Invalid masklen %s. Defaulting to %d)", w, PIM_GROUP_PREFIX_DEFAULT_MASKLEN);
		    masklen = PIM_GROUP_PREFIX_DEFAULT_MASKLEN;
		}
	    }

	    /*
	     * Unused.  Kept for backwards compatibility for users that
	     * may still have this option in pimd.conf.  The priority of
	     * a static RP is hardcoded to always be 1, see Juniper's
	     * configuration or similar sources for reference.
	     */
	    if (EQUAL(w, "priority")) {
		w = next_word(&s);
		WARN("Deprecated static RP priority, will always be 1.");
	    }
	}
    } else {
	group_addr = htonl(INADDR_UNSPEC_GROUP);
	masklen = PIM_GROUP_PREFIX_MIN_MASKLEN;
    }

    validate_prefix_len(&masklen);

    rph = calloc(1, sizeof(*rph));
    if (!rph) {
	logit(LOG_WARNING, 0, "Out of memory when parsing rp-address %s",
	      inet_fmt(local, s1, sizeof(s1)));
	return FALSE;
    }

    rph->address = local;
    rph->group = group_addr;
    VAL_TO_MASK(rph->mask, masklen);

    /* attach at the beginning */
    rph->next = g_rp_hold;
    g_rp_hold = rph;

    logit(LOG_INFO, 0, "Local static RP: %s, group %s/%d",
	  inet_fmt(local, s1, sizeof(s1)), inet_fmt(group_addr, s2, sizeof(s2)), masklen);

    return TRUE;
}


/**
 * parse_hello_interval - Parse and assign the hello interval
 * @s: Input data
 *
 * Syntax:
 *	    hello-interval <SEC>
 *
 * Returns:
 * %TRUE if successful, otherwise %FALSE.
 */
static int parse_hello_interval(char *s)
{
    char *w;
    u_int period;
    u_int holdtime;

    if (!EQUAL((w = next_word(&s)), "")) {
	if (sscanf(w, "%u", &period) != 1) {
	    logit(LOG_WARNING, 0, "Invalid hello-interval %s; defaulting to %u", w, PIM_TIMER_HELLO_INTERVAL);
	    period = PIM_TIMER_HELLO_INTERVAL;
	    holdtime = PIM_TIMER_HELLO_HOLDTIME;
	} else {
	    /* The floor matters as much as the ceiling, and man/pimd.conf.5
	     * already documents both: the holdtime is derived from this value,
	     * so 0 has us announce a zero Holdtime -- our own death -- in
	     * every Hello, on a timer that fires every tick.
	     */
	    if (period >= PIM_TIMER_HELLO_INTERVAL && period <= (u_int)(UINT16_MAX / 3.5)) {
		holdtime = period * 3.5;
	    } else {
		logit(LOG_WARNING, 0, "Invalid hello-interval %s, must be %u to %u; defaulting to %u",
		      w, PIM_TIMER_HELLO_INTERVAL, (u_int)(UINT16_MAX / 3.5), PIM_TIMER_HELLO_INTERVAL);
		period = PIM_TIMER_HELLO_INTERVAL;
		holdtime = PIM_TIMER_HELLO_HOLDTIME;
	    }
	}
    } else {
	logit(LOG_WARNING, 0, "Missing hello-interval value; defaulting to %u", PIM_TIMER_HELLO_INTERVAL);
	period = PIM_TIMER_HELLO_INTERVAL;
	holdtime = PIM_TIMER_HELLO_HOLDTIME;
    }

    logit(LOG_INFO, 0, "hello-interval is %u", period);
    pim_timer_hello_interval = period;
    pim_timer_hello_holdtime = holdtime;

    return TRUE;
}


/**
 * parse_spt_threshold - Parse spt-threshold option
 * @s: String token
 *
 * This configuration setting replaces the switch_register_threshold and
 * switch_data_threshold.  It is more intuitive and more in line with
 * what major vendors are also using.
 *
 * Syntax:
 * spt-threshold [rate <KBPS> | packets <NUM> | infinity] [interval <SEC>]
 *
 * Returns:
 * When parsing @s is successful this function returns %TRUE, otherwise %FALSE.
 */
static int parse_spt_threshold(char *s)
{
    char *w;
    uint32_t rate     = SPT_THRESHOLD_DEFAULT_RATE;
    uint32_t packets  = SPT_THRESHOLD_DEFAULT_PACKETS;
    uint32_t interval = SPT_THRESHOLD_DEFAULT_INTERVAL;
    spt_mode_t mode  = SPT_THRESHOLD_DEFAULT_MODE;

    while (!EQUAL((w = next_word(&s)), "")) {
	if (EQUAL(w, "rate")) {
	    mode = SPT_RATE;

	    if (EQUAL((w = next_word(&s)), "")) {
		WARN("Missing spt-threshold rate argument, defaulting to %u", SPT_THRESHOLD_DEFAULT_RATE);
		rate = SPT_THRESHOLD_DEFAULT_RATE;
		continue;
	    }

	    /* 10 --> 1,000,000,000 == 100 Gbps */
	    if (sscanf(w, "%10u", &rate) != 1) {
		WARN("Invalid spt-threshold rate %s, defaulting to %u", w, SPT_THRESHOLD_DEFAULT_RATE);
		rate = SPT_THRESHOLD_DEFAULT_RATE;
	    }

	    continue;
	}

	if (EQUAL(w, "interval")) {
	    if (EQUAL((w = next_word(&s)), "")) {
		WARN("Missing spt-threshold interval; defaulting to %u sec",  SPT_THRESHOLD_DEFAULT_INTERVAL);
		interval = SPT_THRESHOLD_DEFAULT_INTERVAL;
		continue;
	    }

	    /* 5 --> 99,999 ~= 27h */
	    if (sscanf(w, "%5u", &interval) != 1) {
		WARN("Invalid spt-threshold interval %s; defaulting to %u sec", w, SPT_THRESHOLD_DEFAULT_INTERVAL);
		interval = SPT_THRESHOLD_DEFAULT_INTERVAL;
	    }

	    if (interval < TIMER_INTERVAL) {
		WARN("Too low spt-threshold interval %s; defaulting to %u sec", w, TIMER_INTERVAL);
		interval = TIMER_INTERVAL;
	    }

	    continue;
	}

	if (EQUAL(w, "packets")) {
	    mode = SPT_PACKETS;

	    if (EQUAL((w = next_word(&s)), "")) {
		WARN("Missing spt-threshold number of packets; defaulting to %u", SPT_THRESHOLD_DEFAULT_PACKETS);
		packets = SPT_THRESHOLD_DEFAULT_PACKETS;
		continue;
	    }

	    /* 10 --> 4294967295, which is max of uint32_t */
	    if (sscanf(w, "%10u", &packets) != 1) {
		WARN("Invalid spt-threshold packets %s; defaulting to %u",
		     w, SPT_THRESHOLD_DEFAULT_PACKETS);
		packets = SPT_THRESHOLD_DEFAULT_PACKETS;
	    }

	    continue;
	}

	if (EQUAL(w, "infinity")) {
	    mode = SPT_INF;
	    continue;
	}

	WARN("Invalid spt-threshold parameter %s; reverting to defaults.", w);
	mode     = SPT_THRESHOLD_DEFAULT_MODE;
	rate     = SPT_THRESHOLD_DEFAULT_RATE;
	packets  = SPT_THRESHOLD_DEFAULT_PACKETS;
	interval = SPT_THRESHOLD_DEFAULT_INTERVAL;
	break;
    }

    spt_threshold.mode = mode;
    switch (mode) {
	case SPT_INF:
	    logit(LOG_INFO, 0, "spt-threshold infinity => RP and lasthop router will never switch to SPT.");
	    break;

	case SPT_RATE:
	    /* Accounting for headers we can approximate 1 byte/s == 10 bits/s (bps)
	     * Note, in the new spt_threshold setting the rate is in kbps as well! */
	    spt_threshold.bytes    = rate * interval / 10 * 1000;
	    spt_threshold.interval = interval;
	    logit(LOG_INFO, 0, "spt-threshold rate %u interval %u", rate, interval);
	    break;

	case SPT_PACKETS:
	    spt_threshold.packets  = packets;
	    spt_threshold.interval = interval;
	    logit(LOG_INFO, 0, "spt-threshold packets %u interval %u", packets, interval);
	    break;

    }

    return TRUE;
}


/**
 * parse_default_route_metric - Parse default-route-metric option
 * @s: String token
 *
 * Reads and assigns the route metric used for PIM Asserts by default.
 * This is used if pimd cannot read unicast route metrics from the
 * OS/kernel.
 *
 * Syntax:
 * default-route-metric <1-1024>
 *
 * Default routing protocol distance and route metric statements should
 * precede all phyint statements in the config file.
 *
 * Returns:
 * When parsing @s is successful this function returns %TRUE, otherwise %FALSE.
 */
static int parse_default_route_metric(char *s)
{
    char *w;
    u_int value;
    vifi_t vifi;
    struct uvif *v;

    value = UCAST_DEFAULT_ROUTE_METRIC;
    if (EQUAL((w = next_word(&s)), "")) {
	WARN("Missing route metric default; defaulting to %u", UCAST_DEFAULT_ROUTE_METRIC);
    } else if (sscanf(w, "%u", &value) != 1) {
	WARN("Invalid route metric default; defaulting to %u", UCAST_DEFAULT_ROUTE_METRIC);
	value = UCAST_DEFAULT_ROUTE_METRIC;
    }

    default_route_metric = value;
    logit(LOG_INFO, 0, "default-route-metric is %u", value);

    for (vifi = 0, v = uvifs; vifi < MAXVIFS; ++vifi, ++v)
	v->uv_local_metric = default_route_metric;

    return TRUE;
}


/**
 * parse_default_route_distance - Parse default-route-distance option
 * @s: String token
 *
 * Reads and assigns the default source metric preference, i.e. routing
 * protocol distance.  This is used if pimd cannot read unicast routing
 * protocol information from the OS/kernel.
 *
 * Syntax:
 * default-route-distance <1-255>
 *
 * Default routing protocol distance and route metric statements should
 * precede all phyint statements in the config file.
 *
 * Returns:
 * When parsing @s is successful this function returns %TRUE, otherwise %FALSE.
 */
static int parse_default_route_distance(char *s)
{
    char *w;
    u_int value;
    vifi_t vifi;
    struct uvif *v;

    value = UCAST_DEFAULT_ROUTE_DISTANCE;
    if (EQUAL((w = next_word(&s)), "")) {
	WARN("Missing default routing protocol distance; defaulting to %u", UCAST_DEFAULT_ROUTE_DISTANCE);
    } else if (sscanf(w, "%u", &value) != 1) {
	WARN("Invalid default routing protocol distance; defaulting to %u", UCAST_DEFAULT_ROUTE_DISTANCE);
	value = UCAST_DEFAULT_ROUTE_DISTANCE;
    }

    default_route_distance = value;
    logit(LOG_INFO, 0, "default-route-distance is %u", value);
    for (vifi = 0, v = uvifs; vifi < MAXVIFS; ++vifi, ++v)
	v->uv_local_pref = default_route_distance;

    return TRUE;
}

/**
 * parse_assert_preference - Parse assert-preference option
 * @s: String token
 *
 * Says where the metric preference of an Assert comes from.  RFC 7761
 * sec. 4.6.3 wants the administrative distance of the routing protocol
 * that provided the route, and `rib` is that, where the RPF backend can
 * say which protocol it was: netlink carries it in rtm_protocol on Linux
 * and on FreeBSD, a PF_ROUTE socket carries it nowhere.  A route the
 * backend cannot name, and every route at all on a routing socket build,
 * keeps the configured distance, which is what `configured` -- the default
 * -- uses for every route.
 *
 * Off by default because sec. 4.6.3 compares the preference before it ever
 * looks at the metric, so a router deriving one is unanswerable by a router
 * that is not: two pimds on a LAN with the same routing table, one built
 * with netlink and one without, would elect on how they were built.  A
 * domain where every router derives it -- or where none does -- is a
 * decision for whoever runs it, and this is how it is said.
 *
 * Syntax:
 * assert-preference [configured | rib]
 *
 * Returns:
 * When parsing @s is successful this function returns %TRUE, otherwise %FALSE.
 */
static int parse_assert_preference(char *s)
{
    char *w;

    w = next_word(&s);
    if (EQUAL(w, "rib") || EQUAL(w, "routing")) {
	assert_pref_from_rib = TRUE;
    } else if (EQUAL(w, "configured") || EQUAL(w, "")) {
	assert_pref_from_rib = FALSE;
    } else {
	WARN("Invalid assert-preference '%s', expected 'configured' or 'rib'", w);
	return FALSE;
    }

    logit(LOG_INFO, 0, "assert-preference is %s",
	  assert_pref_from_rib ? "rib" : "configured");

    return TRUE;
}

/**
 * parse_autorp - Parse autorp option
 * @s: String token
 *
 * Auto-RP, the RP discovery mechanism of doc/pim-autorp-spec01.txt: a
 * mapping agent somewhere in the domain announces the group-to-RP mappings
 * to 224.0.1.40 and every router listens.  pimd listens for them by
 * default, and this is how to say it should not -- an operator whose
 * domain runs the Bootstrap mechanism and nothing else loses nothing by
 * leaving it on, but a domain that runs both has two sources for one
 * answer, and which of them a router believes should be said out loud.
 *
 * Syntax:
 * autorp discovery [enable | disable]
 *
 * Returns:
 * When parsing @s is successful this function returns %TRUE, otherwise %FALSE.
 */
static int parse_autorp(char *s)
{
    char *w;

    w = next_word(&s);
    if (!EQUAL(w, "discovery")) {
	WARN("Invalid autorp option '%s', expected 'discovery'", w);
	return FALSE;
    }

    w = next_word(&s);
    if (EQUAL(w, "disable")) {
	autorp_enabled = FALSE;
    } else if (EQUAL(w, "enable") || EQUAL(w, "")) {
	autorp_enabled = TRUE;
    } else {
	WARN("Invalid autorp discovery option '%s', expected 'enable' or 'disable'", w);
	return FALSE;
    }

    logit(LOG_INFO, 0, "Auto-RP discovery is %s",
	  autorp_enabled ? "enabled" : "disabled");

    return TRUE;
}

/**
 * parse_igmp_query_interval - Parse igmp-query-interval option
 * @s: String token
 *
 * Reads and assigns the default IGMP query interval.  If the argument
 * is missing or invalid the parser defaults to %IGMP_QUERY_INTERVAL
 *
 * Syntax:
 * igmp-query-interval <SEC>
 *
 * Returns:
 * When parsing @s is successful this function returns %TRUE, otherwise %FALSE.
 */
static int parse_igmp_query_interval(char *s)
{
    uint32_t value = IGMP_QUERY_INTERVAL;
    const char *errstr;
    long long num;
    char *w;

    if (EQUAL((w = next_word(&s)), "")) {
	WARN("Missing argument to igmp-query-interval; defaulting to %u", IGMP_QUERY_INTERVAL);
    } else {
	num = strtonum(w, 1, 65535, &errstr);
	if (errstr)
	    WARN("Invalid igmp-query-interval %s, %s; defaulting to %u", w, errstr, IGMP_QUERY_INTERVAL);
	else
	    value = (uint32_t)num;
    }

    igmp_query_interval = value;

    return TRUE;
}

/**
 * parse_state_limit - Parse a cap on the state others can create
 * @s: String token
 * @name: The keyword, for the warnings
 * @limit: Where the value goes
 * @dflt: What it is when @s gives none, or none that is valid
 *
 * rpt-prune-limit, how many (S,G) entries neighbors' Prune(S,G,rpt) messages
 * may make this router hold, see rpt_prune_entry() in pim_proto.c, and
 * local-sg-limit, how many data from directly connected sources may, see
 * local_sg_entry() in route.c.  Zero makes none.
 *
 * Syntax:
 * rpt-prune-limit <0-1000000>
 * local-sg-limit <0-1000000>
 *
 * Returns:
 * When parsing @s is successful this function returns %TRUE, otherwise %FALSE.
 */
static int parse_state_limit(char *s, const char *name, uint32_t *limit, uint32_t dflt)
{
    uint32_t value = dflt;
    const char *errstr;
    long long num;
    char *w;

    if (EQUAL((w = next_word(&s)), "")) {
	WARN("Missing argument to %s; defaulting to %u", name, dflt);
    } else {
	num = strtonum(w, 0, 1000000, &errstr);
	if (errstr)
	    WARN("Invalid %s %s, %s; defaulting to %u", name, w, errstr, dflt);
	else
	    value = (uint32_t)num;
    }

    *limit = value;

    return TRUE;
}

/**
 * parse_igmp_querier_timeout - Parse igmp-querier-timeout option
 * @s: String token
 *
 * Reads and assigns default querier timeout for an active IGMP querier.
 * This is the time it takes before pimd tries to take over as the
 * active querier.  If the argument is missing or invalid the system
 * will calculate a fallback based on the query interval.
 *
 * The value is only recorded here, it is sanity checked against the
 * query interval in check_igmp_timers(), once the whole file has been
 * read, because the two settings may come in any order.
 *
 * Syntax:
 * igmp-querier-timeout <SEC>
 *
 * Returns:
 * When parsing @s is successful this function returns %TRUE, otherwise %FALSE.
 */
static int parse_igmp_querier_timeout(char *s)
{
    uint32_t value = 0;		/* Zero: derive it from the query interval */
    const char *errstr;
    long long num;
    char *w;

    if (EQUAL((w = next_word(&s)), "")) {
	WARN("Missing argument to igmp-querier-timeout, computing it from the query interval ...");
    } else {
	num = strtonum(w, 8, 65535, &errstr);
	if (errstr)
	    WARN("Invalid igmp-querier-timeout %s, %s; computing it from the query interval ...", w, errstr);
	else
	    value = (uint32_t)num;
    }

    igmp_querier_timeout = value;

    return TRUE;
}

/*
 * Derive the querier timeout from the query interval unless the .conf set
 * one, then sanity check the pair, see GitHub issue troglobit/pimd#31.
 *
 * Called after the whole .conf has been read so that the checks see the
 * final query interval no matter which order the two settings came in,
 * and so that a timeout matching the recommendation is not warned about,
 * see GitHub issue troglobit/pimd#237.
 */
static void check_igmp_timers(void)
{
    uint32_t recommended = QUERIER_TIMEOUT(igmp_query_interval);

    if (!igmp_querier_timeout) {
	igmp_querier_timeout = recommended;
	return;
    }

    /* 1) Prevent invalid configuration */
    if (igmp_querier_timeout <= igmp_query_interval) {
	logit(LOG_WARNING, 0, "IGMP querier timeout %u must be larger than the query interval %u, using %u instead",
	      igmp_querier_timeout, igmp_query_interval, recommended);
	igmp_querier_timeout = recommended;
	return;
    }

    /* 2) Warn power user of potentially too low setting. */
    if (igmp_querier_timeout < recommended)
	logit(LOG_WARNING, 0, "IGMP querier timeout %u is smaller than the recommended %u"
	      " = robustness %u x query interval %u + query response interval %u / 2, allowing ...",
	      igmp_querier_timeout, recommended, IGMP_ROBUSTNESS_VARIABLE, igmp_query_interval,
	      IGMP_QUERY_RESPONSE_INTERVAL);
}

void config_vifs_from_file(void)
{
    FILE *fp;
    char linebuf[LINE_BUFSIZ];
    char *w, *s;
    uint8_t *data_ptr;
    struct ssm_range *range;
    int error_flag;

    error_flag = FALSE;
    lineno = 0;

    /* TODO: HARDCODING!!! */
    if (!cand_rp_adv_message.buffer)
	cand_rp_adv_message.buffer = malloc(4 + sizeof(pim_encod_uni_addr_t) +
					    255 * sizeof(pim_encod_grp_addr_t));

    if (!cand_rp_adv_message.buffer)
	logit(LOG_ERR, errno, "Ran out of memory in config_vifs_from_file()");

    memset(cand_rp_adv_message.buffer, 0, 4 + sizeof(pim_encod_uni_addr_t) +
					  255 * sizeof(pim_encod_grp_addr_t));

    cand_rp_adv_message.prefix_cnt_ptr  = cand_rp_adv_message.buffer;
    /* By default, if no group-prefix configured, then prefix_cnt == 0
     * implies group-prefix = 224.0.0.0 and masklen = 4.
     */
    *cand_rp_adv_message.prefix_cnt_ptr = 0;
    cand_rp_adv_message.insert_data_ptr = cand_rp_adv_message.buffer;
    /* TODO: XXX: HARDCODING!!! */
    cand_rp_adv_message.insert_data_ptr += (4 + 6);

    /* set a sensible defaults */
    my_bsr_adv_period = PIM_BOOTSTRAP_PERIOD;
    my_cand_rp_adv_period = PIM_DEFAULT_CAND_RP_ADV_PERIOD;
    igmp_query_interval = IGMP_QUERY_INTERVAL;
    igmp_querier_timeout = 0;	/* Derived from the query interval below */
    rpt_prune_limit = PIM_RPT_PRUNE_LIMIT;
    local_sg_limit = PIM_LOCAL_SG_LIMIT;
    register_sg_limit = PIM_REGISTER_SG_LIMIT;
    assert_pref_from_rib = FALSE;
    autorp_enabled = TRUE;
    autorp_limit = PIM_AUTORP_LIMIT;

    /* Reset flags on file (re)load */
    cand_rp_flag = FALSE;
    cand_bsr_flag = FALSE;
    reset_ssm_ranges();
    reset_reg_acl();
    reset_anycast_rp();

    fp = priv_fopen_conf();
    if (!fp) {
	if (errno != ENOENT)
	    logit(LOG_WARNING, errno, "Failed opening %s", config_file);
	goto nofile;
    }

    while (fgets(linebuf, sizeof(linebuf), fp)) {
	if (strlen(linebuf) >= (LINE_BUFSIZ - 1)) {
	    WARN("Line length must be shorter than %d", LINE_BUFSIZ);
	    error_flag = TRUE;
	}

	lineno++;
	s = linebuf;
	w = next_word(&s);

	switch (parse_option(w)) {
	    case CONF_EMPTY:
		continue;

	    case CONF_PHYINT:
		parse_phyint(s);
		break;

	    case CONF_NO:
	    case CONF_DISABLE_VIFS:
		/* Ignore, handled in first stage */
		break;

	    case CONF_CANDIDATE_RP:
		parse_rp_candidate(s);
		break;

	    case CONF_RP_ADDRESS:
		parse_rp_address(s);
		break;

	    case CONF_GROUP_PREFIX:
		parse_group_prefix(s);
		break;

	    case CONF_SSM_RANGE:
		parse_ssm_range(s);
		break;

	    case CONF_REGISTER_ACCEPT_FROM:
		parse_register_accept_from(s);
		break;

	    case CONF_ANYCAST_RP:
		parse_anycast_rp(s);
		break;

	    case CONF_BOOTSTRAP_RP:
		parse_bsr_candidate(s);
		break;

	    case CONF_SPT_THRESHOLD:
		parse_spt_threshold(s);
		break;

	    case CONF_DEFAULT_ROUTE_METRIC:
		parse_default_route_metric(s);
		break;

	    case CONF_DEFAULT_ROUTE_DISTANCE:
		parse_default_route_distance(s);
		break;

	    case CONF_IGMP_QUERY_INTERVAL:
		parse_igmp_query_interval(s);
		break;

	    case CONF_IGMP_QUERIER_TIMEOUT:
		parse_igmp_querier_timeout(s);
		break;

	    case CONF_HELLO_INTERVAL:
		parse_hello_interval(s);
		break;

	    case CONF_RPT_PRUNE_LIMIT:
		parse_state_limit(s, "rpt-prune-limit", &rpt_prune_limit, PIM_RPT_PRUNE_LIMIT);
		break;

	    case CONF_LOCAL_SG_LIMIT:
		parse_state_limit(s, "local-sg-limit", &local_sg_limit, PIM_LOCAL_SG_LIMIT);
		break;

	    case CONF_REGISTER_SG_LIMIT:
		parse_state_limit(s, "register-sg-limit", &register_sg_limit, PIM_REGISTER_SG_LIMIT);
		break;

	    case CONF_ASSERT_PREFERENCE:
		parse_assert_preference(s);
		break;

	    case CONF_AUTORP:
		parse_autorp(s);
		break;

	    case CONF_AUTORP_LIMIT:
		parse_state_limit(s, "autorp-limit", &autorp_limit, PIM_AUTORP_LIMIT);
		break;

	    default:
		logit(LOG_WARNING, 0, "%s:%u - Unknown command '%s'", config_file, lineno, w);
		error_flag = TRUE;
		break;
	}
    }

    fclose(fp);

  nofile:
    /* A static RP address is needed for SSM.  We use a link-local
     * address. It is not required to be configured on any interface.
     * One per SSM range in effect, the default one included. */
    default_ssm_range();
    for (range = ssm_list; range; range = range->next) {
	snprintf(linebuf, sizeof(linebuf), "169.254.0.1 %s/%u\n",
		 inet_fmt(range->group, s1, sizeof(s1)), range->masklen);
	s = linebuf;
	parse_rp_address(s);
    }

    if (error_flag)
	logit(LOG_ERR, 0, "%s:%u - Syntax error", config_file, lineno);

    my_bsr_timeout = 2 * my_bsr_adv_period + 10;   /* RFC5059 section 5 */

    recommended_rp_holdtime = 2.5 * my_bsr_adv_period; /* RFC5059 section 3.3 SHOULD BE value */

    cand_rp_adv_message.message_size = cand_rp_adv_message.insert_data_ptr - cand_rp_adv_message.buffer;
    if (cand_rp_flag != FALSE) {
	/* Prepare the RP info */
	my_cand_rp_holdtime = 2.5 * my_cand_rp_adv_period;
	/* Is holdtime in MUST BE interval? (RFC5059 section 3.3) */
	if (my_cand_rp_holdtime <= my_bsr_adv_period)
	    	my_cand_rp_holdtime = recommended_rp_holdtime;

	/* TODO: HARDCODING! */
	data_ptr = cand_rp_adv_message.buffer + 1;
	PUT_BYTE(my_cand_rp_priority, data_ptr);
	PUT_HOSTSHORT(my_cand_rp_holdtime, data_ptr);
	PUT_EUADDR(my_cand_rp_address, data_ptr);
    }

    check_igmp_timers();
    check_anycast_rp();

    IF_DEBUG(DEBUG_IGMP) {
	logit(LOG_INFO, 0, "IGMP query interval  : %u sec", igmp_query_interval);
	logit(LOG_INFO, 0, "IGMP querier timeout : %u sec", igmp_querier_timeout);
    }
}


static uint32_t ifname2addr(char *s)
{
    vifi_t vifi;
    struct uvif *v;

    for (vifi = 0, v = uvifs; vifi < numvifs; vifi++, v++) {
	if (!strcasecmp(v->uv_name, s))
	    return v->uv_lcl_addr;
    }

    return 0;
}

static char *next_word(char **s)
{
    size_t i = 0;
    char *w;
    static char token[42];

    memset(token, 0, sizeof(token));

    w = *s;
    while (*w == ' ' || *w == '\t')
	w++;

    *s = w;
    /* Leave room for the terminator: a word of exactly sizeof(token)
     * characters used to fill the buffer and return it unterminated, and
     * every caller hands what it gets to strcmp(), inet_parse() or
     * strtonum(), which then read on into whatever follows. */
    while (**s != 0 && i < sizeof(token) - 1) {
	switch (**s) {
	    case ' ':
	    case '\t':
		(*s)++;
		__attribute__((fallthrough));
	    case '\n':
	    case '#':
	    return token;

	    default:
		if (isascii((int)**s) && isupper((int)**s))
		    token[i++] = tolower((int)**s);
		else
		    token[i++] = **s;
		(*s)++;
	}
    }

    return token;
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "cc-mode"
 * End:
 */
