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

/*
 * Helper macros
 */
#define is_uv_subnet(src, v) \
    (src & v->uv_subnetmask) == v->uv_subnet && ((v->uv_subnetmask == 0xffffffff) || (src != v->uv_subnetbcast))

#define is_pa_subnet(src, v) \
    (src & p->pa_subnetmask) == p->pa_subnet && ((p->pa_subnetmask == 0xffffffff) || (src != p->pa_subnetbcast))

/*
 * Exported variables.
 */
struct uvif	uvifs[MAXVIFS]; /* array of all virtual interfaces          */
vifi_t		numvifs;	/* Number of vifs in use                    */
int             vifs_down;      /* 1=>some interfaces are down              */
int             phys_vif;       /* An enabled vif                           */
int		udp_socket;	/* Since the honkin' kernel doesn't support
				 * ioctls on raw IP sockets, we need a UDP
				 * socket as well as our IGMP (raw) socket. */
int             total_interfaces; /* Number of all interfaces: including the
				   * non-configured, but excluding the
				   * loopback interface and the non-multicast
				   * capable interfaces.
				   */

uint32_t	default_route_metric   = UCAST_DEFAULT_ROUTE_METRIC;
uint32_t	default_route_distance = UCAST_DEFAULT_ROUTE_DISTANCE;

/*
 * `assert-preference rib`, off unless a pimd.conf asks for it: see
 * parse_assert_preference() in src/config.c for why a router does not take
 * the routing protocol's administrative distance unless it is told to.
 */
int		assert_pref_from_rib   = FALSE;

/*
 * How long a rescan waits after the kernel said an interface changed, in
 * milliseconds.  One interface coming up is several notifications, and an
 * address usually arrives a moment after the link it is on, so this is
 * what keeps that from being several scans -- and what keeps a scan from
 * landing between the two and finding an interface with no address, which
 * is not one a VIF can be built on.
 */
#define VIF_RESCAN_DELAY	1000

/*
 * ... and how long the daemon may go without a scan when no notification
 * arrives at all, in seconds.  The event socket is what makes a rescan
 * prompt; this is what keeps a lost notification from being permanent.
 * The kernel drops them when their queue is full, and on a routing socket
 * that queue carries every unicast route change on the router, so this is
 * not a theoretical case on a box that also runs BGP.  Rounded down to a
 * multiple of TIMER_INTERVAL, which is what it is counted in.
 */
#define VIF_RESCAN_PERIOD	60

/*
 * Forward declarations
 */
static void start_vif      (vifi_t vifi);
static void stop_vif       (vifi_t vifi);
static void start_all_vifs (void);
static int init_reg_vif    (void);
static int update_reg_vif  (vifi_t register_vifi);
static void rescan_timeout (void *arg);

/* Pending rescan, see rescan_vifs_request(), and the tick counter of the
 * periodic one age_vifs() runs, see VIF_RESCAN_PERIOD */
static int rescan_timer = 0;
static int rescan_ticks = 0;


void init_vifs(void)
{
    vifi_t vifi;
    struct uvif *v;
    int enabled_vifs;

    numvifs   = 1;		 /* First one reserved for PIMREG_VIF */
    vifs_down = FALSE;

    /* restart() takes the timer queue down with everything else, so the
     * id of a rescan that was pending across it is not ours any more */
    rescan_timer = 0;
    rescan_ticks = 0;

    /* Configure the vifs based on the interface configuration of the the kernel and
     * the contents of the configuration file.  (Open a UDP socket for ioctl use in
     * the config procedures if the kernel can't handle IOCTL's on the IGMP socket.) */
#ifdef IOCTL_OK_ON_RAW_SOCKET
    udp_socket = igmp_socket;
#else
    udp_socket = priv_enabled() ? priv_socket(PRIV_SOCK_UDP)
				: socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_socket < 0)
	logit(LOG_ERR, errno, "UDP socket");
#endif

    /* Clean up all vifs */
    for (vifi = 0, v = uvifs; vifi < MAXVIFS; ++vifi, ++v)
	zero_vif(v, FALSE);

    config_vifs_from_kernel();

    if (!do_vifs) {
	/* Disable all VIFs by default (no phyint), except PIMREG_VIF */
	for (vifi = 1, v = &uvifs[1]; vifi < numvifs; ++vifi, ++v)
          v->uv_flags |= VIFF_DISABLED;
    }

    config_vifs_from_file();

    init_reg_vif();

    /*
     * Quit unless at least one phyint is enabled.  The count starts at
     * one for the register vif, which always holds vifi 0 and which the
     * loop below therefore skips, so "fewer than two" is how "none of
     * them" reads here.
     */
    enabled_vifs    = 1;
    phys_vif        = -1;

    /* The PIM register tunnel interface should always be vifi 0 */
    for (vifi = 1, v = &uvifs[1]; vifi < numvifs; ++vifi, ++v) {
	/*
	 * Initialize the outgoing timeout for each vif.  Currently use
	 * a fixed time.  Later, we may add a configurable array to feed
	 * these parameters, or compute them as function of the i/f
	 * bandwidth and the overall connectivity...etc.
	 */
	SET_TIMER(v->uv_jp_timer, PIM_JOIN_PRUNE_HOLDTIME);

	if (v->uv_flags & (VIFF_DISABLED | VIFF_DOWN | VIFF_REGISTER | VIFF_TUNNEL))
	    continue;

	if (phys_vif == -1)
	    phys_vif = vifi;

	enabled_vifs++;
    }

    if (enabled_vifs < 2)
	logit(LOG_ERR, 0, "Cannot forward: no enabled vifs");

    k_init_pim(igmp_socket);	/* Call to kernel to initialize structures */

    start_all_vifs();
}

/*
 * Initialize the passed vif with all appropriate default values.
 * "t" is true if a tunnel or register_vif, or false if a phyint.
 */
void zero_vif(struct uvif *v, int t)
{
    struct phaddr *pa, *next;

    /* Extra subnets are allocated, and init_vifs() runs again on restart */
    for (pa = v->uv_addrs; pa; pa = next) {
	next = pa->pa_next;
	free(pa);
    }

    /* As is the list of routers we accept PIM messages from */
    for (pa = v->uv_nbr_acl; pa; pa = next) {
	next = pa->pa_next;
	free(pa);
    }

    v->uv_flags		= 0;	/* Default to IGMPv3 */
    v->uv_metric	= DEFAULT_METRIC;
    v->uv_admetric	= 0;
    v->uv_threshold	= DEFAULT_THRESHOLD;
    v->uv_rate_limit	= t ? DEFAULT_REG_RATE_LIMIT : DEFAULT_PHY_RATE_LIMIT;
    v->uv_lcl_addr	= INADDR_ANY_N;
    v->uv_rmt_addr	= INADDR_ANY_N;
    v->uv_dst_addr	= t ? INADDR_ANY_N : allpimrouters_group;
    v->uv_subnet	= INADDR_ANY_N;
    v->uv_subnetmask	= INADDR_ANY_N;
    v->uv_subnetbcast	= INADDR_ANY_N;
    strlcpy(v->uv_name, "", IFNAMSIZ);
    v->uv_groups	= (struct listaddr *)NULL;
    v->uv_dvmrp_neighbors = (struct listaddr *)NULL;
    NBRM_CLRALL(v->uv_nbrmap);
    v->uv_querier	= (struct listaddr *)NULL;
    v->uv_igmpv1_warn	= 0;
    v->uv_prune_lifetime = 0;
    v->uv_acl		= (struct vif_acl *)NULL;
    RESET_TIMER(v->uv_leaf_timer);
    v->uv_addrs		= (struct phaddr *)NULL;
    v->uv_nsecaddrs	= 0;
    v->uv_nbr_acl	= (struct phaddr *)NULL;
    v->uv_filter	= (struct vif_filter *)NULL;

    RESET_TIMER(v->uv_hello_timer);
    v->uv_hello_trigger = 0;
    v->uv_dr_prio       = PIM_HELLO_DR_PRIO_DEFAULT;
    v->uv_genid         = 0;

    RESET_TIMER(v->uv_gq_timer);
    RESET_TIMER(v->uv_jp_timer);
    v->uv_pim_neighbors	= (struct pim_nbr_entry *)NULL;
    v->uv_pim_neighbor_dr = (struct pim_nbr_entry *)NULL;
    v->uv_local_pref	= default_route_distance;
    v->uv_local_metric	= default_route_metric;
    v->uv_ifindex	= -1;
}


/*
 * Add a (the) register vif to the vif table.
 */
static int init_reg_vif(void)
{
    struct uvif *v;
    vifi_t i;

    v = &uvifs[0];
    v->uv_flags = 0;

    v->uv_flags = VIFF_REGISTER;
#ifdef PIM_EXPERIMENTAL
    v->uv_flags |= VIFF_REGISTER_KERNEL_ENCAP;
#endif
    v->uv_threshold = MINTTL;

#ifdef __linux__
    if (mrt_table_id != 0)
	snprintf(v->uv_name, sizeof(v->uv_name), "pimreg%u", mrt_table_id);
    else
	strlcpy(v->uv_name, "pimreg", sizeof(v->uv_name));
#else
    strlcpy(v->uv_name, "register_vif0", sizeof(v->uv_name));
#endif /* __linux__ */

    /* Use the address of the first available physical interface to
     * create the register vif.
     */
    for (i = 0; i < numvifs; i++) {
	if (uvifs[i].uv_flags & (VIFF_DOWN | VIFF_DISABLED | VIFF_REGISTER | VIFF_TUNNEL))
	    continue;

	break;
    }

    if (i >= numvifs) {
	logit(LOG_ERR, 0, "No physical interface enabled, cannot create %s", v->uv_name);
	return -1;
    }

    v->uv_ifindex  = 0;
    v->uv_lcl_addr = uvifs[i].uv_lcl_addr;
    logit(LOG_DEBUG, 0, "VIF #0: Installing %s, using %s with ifaddr %s",
	  v->uv_name, uvifs[i].uv_name, inet_fmt(v->uv_lcl_addr, s1, sizeof(s1)));

    total_interfaces++;

    return 0;
}


static void start_all_vifs(void)
{
    vifi_t vifi;
    struct uvif *v;
    u_int action;

    /* Start first the NON-REGISTER vifs */
    for (action = 0; ; action = VIFF_REGISTER) {
	for (vifi = 0, v = uvifs; vifi < numvifs; ++vifi, ++v) {
	    /* If starting non-registers but the vif is a register or if starting
	     * registers, but the interface is not a register, then just continue. */
	    if ((v->uv_flags & VIFF_REGISTER) ^ action)
		continue;

	    /* Start vif if not DISABLED or DOWN */
	    if (v->uv_flags & (VIFF_DISABLED | VIFF_DOWN)) {
		if (v->uv_flags & VIFF_DISABLED)
		    logit(LOG_INFO, 0, "Interface %s is DISABLED; VIF #%u out of service", v->uv_name, vifi);
		else
		    logit(LOG_INFO, 0, "Interface %s is DOWN; VIF #%u out of service", v->uv_name, vifi);
	    } else {
		start_vif(vifi);
	    }
	}

	if (action == VIFF_REGISTER)
	    break;   /* We are done */
    }
}


/*
 * stop all vifs
 */
void stop_all_vifs(void)
{
    struct uvif *v;
    vifi_t vifi;

    for (vifi = 0; vifi < numvifs; vifi++) {
	v = &uvifs[vifi];
	if (!(v->uv_flags & (VIFF_DOWN | VIFF_DISABLED)))
	    stop_vif(vifi);
    }
}


/*
 * Initialize the vif and add to the kernel. The vif can be either
 * physical, register or tunnel (tunnels will be used in the future
 * when this code becomes PIM multicast boarder router.
 */
static void start_vif(vifi_t vifi)
{
    struct uvif *v;

    v	= &uvifs[vifi];
    /* Initialy no router on any vif */
    if (v->uv_flags & VIFF_REGISTER)
	v->uv_flags = v->uv_flags & ~VIFF_DOWN;
    else {
	u_int ifindex;

	/*
	 * An interface that was destroyed and created again under the same
	 * name is another ifnet, with an index of its own, and the VIF is
	 * about to be handed to the kernel by that index: k_add_vif() and
	 * k_join() name the interface with it on Linux.  Read it back here
	 * rather than at the one place the address changes as well, since
	 * a link that comes back the way it went carries the same address
	 * and never reaches renumber_vif().  Zero is what if_nametoindex()
	 * answers for a name it cannot find, and it is the register VIF's
	 * index, so an interface that has gone in the meantime keeps the
	 * stale one and fails in k_add_vif() instead of stealing that.
	 */
	ifindex = priv_ifindex(v->uv_name);
	if (ifindex && (int)ifindex != v->uv_ifindex) {
	    IF_DEBUG(DEBUG_IF)
		logit(LOG_DEBUG, 0, "VIF #%u: %s is ifindex %u now, was %d",
		      vifi, v->uv_name, ifindex, v->uv_ifindex);
	    v->uv_ifindex = ifindex;
	}

	v->uv_flags = (v->uv_flags | VIFF_DR | VIFF_NONBRS) & ~VIFF_DOWN;

	/* https://tools.ietf.org/html/draft-ietf-pim-hello-genid-01 */
	v->uv_genid = RANDOM();

	/* RFC 7761 sec. 4.3.1: the first Hello on an interface waits
	 * rand(0, Triggered_Hello_Delay).  The delay used to be drawn from the
	 * whole Hello_Period and then thrown away, because start_vif() went on
	 * to send a Hello itself and send_pim_hello() re-arms this timer: no
	 * randomized value survived a single tick, every router's first Hello
	 * went out at t=0, and the LAN converged onto one clock.
	 */
	SET_TIMER(v->uv_hello_timer, RANDOM() % (PIM_TRIGGERED_HELLO_DELAY + 1));
	SET_TIMER(v->uv_jp_timer, 1 + RANDOM() % PIM_JOIN_PRUNE_PERIOD);
	/* TODO: CHECK THE TIMERS!!!!! Set or reset? */
	RESET_TIMER(v->uv_gq_timer);
	v->uv_pim_neighbors = (pim_nbr_entry_t *)NULL;
	v->uv_pim_neighbor_dr = (pim_nbr_entry_t *)NULL;
    }

    /* Tell kernel to add, i.e. start this vif */
    k_add_vif(igmp_socket, vifi, &uvifs[vifi]);
    logit(LOG_INFO, 0, "VIF #%u: now in service, interface %s UP", vifi, v->uv_name);

    if (!(v->uv_flags & VIFF_REGISTER)) {
	/* Join the PIM multicast group on the interface. */
	k_join(pim_socket, allpimrouters_group, v);

	/*
	 * Join the ALL-ROUTERS multicast group on the interface.  This
	 * allows mtrace requests to loop back if they are run on the
	 * multicast router.
	 */
	k_join(igmp_socket, allrouters_group, v);

	/* Join INADDR_ALLRPTS_GROUP to support IGMPv3 membership reports */
	k_join(igmp_socket, allreports_group, v);

	/*
	 * Until neighbors are discovered, assume responsibility for sending
	 * periodic group membership queries to the subnet.  Send the first
	 * query.
	 */
	v->uv_flags |= VIFF_QUERIER;
	v->uv_stquery_cnt = IGMP_STARTUP_QUERY_COUNT;
	query_groups(v);

	/* No Hello here: age_vifs() sends the first one when the randomized
	 * uv_hello_timer set above runs out, which is what makes that delay
	 * mean anything.
	 */
    }
#ifdef __linux__
    else {
	v->uv_ifindex = priv_ifindex(v->uv_name);
	if (!v->uv_ifindex) {
	    logit(LOG_ERR, errno, "Failed reading ifindex for %s", v->uv_name);
	    /* Not reached */
	    return;
	}
    }
#endif /* __linux__ */
}


/*
 * Stop a vif (either physical interface, tunnel or
 * register.) If we are running only PIM we don't have tunnels.
 */
static void stop_vif(vifi_t vifi)
{
    struct uvif *v;
    struct listaddr *a, *b;
    pim_nbr_entry_t *n, *next;
    struct vif_acl *acl;

    /*
     * TODO: make sure that the kernel viftable is
     * consistent with the daemon table
     */
    v = &uvifs[vifi];
    if (!(v->uv_flags & VIFF_REGISTER)) {
	k_leave(pim_socket, allpimrouters_group, v);
	k_leave(igmp_socket, allrouters_group, v);
	k_leave(igmp_socket, allreports_group, v);

	/*
	 * Discard all group addresses.  (No need to tell kernel;
	 * the k_del_vif() call will clean up kernel state.)
	 */
	while (v->uv_groups) {
	    a = v->uv_groups;
	    v->uv_groups = a->al_next;

	    while (a->al_sources) {
		b = a->al_sources;
		a->al_sources = b->al_next;

		/* Each (S,G) membership holds a timer of its own */
		if (b->al_timerid)
		    timer_clear(b->al_timerid);
		if (b->al_versiontimer)
		    timer_clear(b->al_versiontimer);
		free(b);
	    }

	    /* Clear timers, preventing possible memory double free */
            if (a->al_timerid)
                timer_clear(a->al_timerid);
            if (a->al_versiontimer)
                timer_clear(a->al_versiontimer);
            if (a->al_query)
                timer_clear(a->al_query);
	    free(a);
	}
    }

    if (v->uv_querier) {
	free(v->uv_querier);
	v->uv_querier = NULL;
    }

    /*
     * TODO: inform (eventually) the neighbors I am going down by sending
     * PIM_HELLO with holdtime=0 so someone else should become a DR.
     */
    /* TODO: dummy! Implement it!! Any problems if don't use it? */
    delete_vif_from_mrt(vifi);

    /* Delete the interface from the kernel's vif structure. */
    k_del_vif(igmp_socket, vifi, v);

    v->uv_flags = (v->uv_flags & ~VIFF_DR & ~VIFF_QUERIER & ~VIFF_NONBRS) | VIFF_DOWN;
    if (!(v->uv_flags & VIFF_REGISTER)) {
	RESET_TIMER(v->uv_hello_timer);
	v->uv_hello_trigger = 0;
	RESET_TIMER(v->uv_jp_timer);
	RESET_TIMER(v->uv_gq_timer);

	for (n = v->uv_pim_neighbors; n; n = next) {
	    next = n->next;	/* Free the space for each neighbour */
	    delete_pim_nbr(n);
	}
	v->uv_pim_neighbors = NULL;
	v->uv_pim_neighbor_dr = NULL;
    }

    /* TODO: currently not used */
   /* The Access Control List (list with the scoped addresses) */
    while (v->uv_acl) {
	acl = v->uv_acl;
	v->uv_acl = acl->acl_next;
	free(acl);
    }

    vifs_down = TRUE;
    logit(LOG_INFO, 0, "Interface %s goes down; VIF #%u out of service", v->uv_name, vifi);
}


/*
 * Update the register vif in the multicast routing daemon and the
 * kernel because the interface used initially to get its local address
 * is DOWN. register_vifi is the index to the Register vif which needs
 * to be updated. As a result the Register vif has a new uv_lcl_addr and
 * is UP (virtually :))
 */
static int update_reg_vif(vifi_t register_vifi)
{
    struct uvif *v;
    vifi_t vifi;

    /* Find the first useable vif with solid physical background */
    for (vifi = 0, v = uvifs; vifi < numvifs; ++vifi, ++v) {
	if (v->uv_flags & (VIFF_DISABLED | VIFF_DOWN | VIFF_REGISTER | VIFF_TUNNEL))
	    continue;

        /* Found. Stop the bogus Register vif first */
	stop_vif(register_vifi);
	uvifs[register_vifi].uv_lcl_addr = uvifs[vifi].uv_lcl_addr;

	start_vif(register_vifi);
	IF_DEBUG(DEBUG_PIM_REGISTER | DEBUG_IF) {
	    logit(LOG_NOTICE, 0, "Interface %s has come up; VIF #%u now in service",
		  uvifs[register_vifi].uv_name, register_vifi);
	}

	return 0;
    }

    /* Not uvifs[vifi]: the loop above ran to completion, so vifi is numvifs
     * here and indexes one past the last VIF -- past the array itself once
     * MAXVIFS of them are configured. */
    vifs_down = TRUE;
    logit(LOG_WARNING, 0, "Cannot start Register VIF: %s", uvifs[register_vifi].uv_name);

    return -1;
}


/*
 * An interface renumbered under us leaves the VIF naming an address the
 * kernel no longer has.  pimd goes on sourcing PIM from it, and neighbors
 * hold it, and may elect it DR, for the whole holdtime.  RFC 7761 sec. 4.3.1
 * asks for a Hello with a zero HoldTime carrying the old address, and a Hello
 * carrying the new one once the change has happened.  Taking the VIF out of
 * service and back in is what makes the rest of the state follow: the group
 * memberships, the kernel VIF and the routing entries are all keyed on the
 * address that has just gone.
 *
 * A poll cannot send that first Hello "before the interface changes address",
 * the way the spec puts it, since the address is already gone by the time we
 * look.  It is sent on the chance that the kernel still accepts it -- a
 * netmask change leaves the address in place -- and costs nothing when it
 * does not.
 */
static void renumber_vif(vifi_t vifi, uint32_t addr, uint32_t mask)
{
    struct uvif *v = &uvifs[vifi];
    uint32_t subnet;

    if (addr == v->uv_lcl_addr && mask == v->uv_subnetmask)
	return;			/* Still the address the VIF was built on */

    /* Leave a VIF on a stale address rather than on one we would have
     * refused at startup; the address may be on its way somewhere. */
    if (!inet_valid_host(addr)) {
	IF_DEBUG(DEBUG_IF)
	    logit(LOG_DEBUG, 0, "Ignoring %s on %s, not a valid host address",
		  inet_fmt(addr, s1, sizeof(s1)), v->uv_name);
	return;
    }

    subnet = addr & mask;

    /*
     * A VIF that is out of service has nothing to say goodbye with and
     * nothing to take out of service: this is an interface that was
     * destroyed and built again under the same name, or one that came back
     * with another address while it was down.  Only the fields move, and
     * the VIF is started by the up/down pass that follows, on the address
     * the kernel has now rather than on the one it had before it went.
     */
    if (v->uv_flags & VIFF_DOWN) {
	logit(LOG_NOTICE, 0, "VIF #%u: interface %s came back on %s, was %s",
	      vifi, v->uv_name, inet_fmt(addr, s1, sizeof(s1)),
	      inet_fmt(v->uv_lcl_addr, s2, sizeof(s2)));

	v->uv_lcl_addr   = addr;
	v->uv_subnet     = subnet;
	v->uv_subnetmask = mask;
	if (mask != htonl(0xfffffffe))
	    v->uv_subnetbcast = subnet | ~mask;
	else
	    v->uv_subnetbcast = 0xffffffff;

	return;
    }

    logit(LOG_NOTICE, 0, "VIF #%u: interface %s renumbered from %s to %s",
	  vifi, v->uv_name, inet_fmt(v->uv_lcl_addr, s1, sizeof(s1)),
	  inet_fmt(addr, s2, sizeof(s2)));

    /* Say goodbye while the old address is still the one we send from. */
    send_pim_hello(v, 0);

    stop_vif(vifi);

    v->uv_lcl_addr   = addr;
    v->uv_subnet     = subnet;
    v->uv_subnetmask = mask;
    if (mask != htonl(0xfffffffe))
	v->uv_subnetbcast = subnet | ~mask;
    else
	v->uv_subnetbcast = 0xffffffff;

    /* Back in service; the first Hello off the randomized timer start_vif()
     * arms carries the new address. */
    start_vif(vifi);
}


/*
 * The addresses interface ifname has besides primary, the one its VIF is
 * built on, in the order getifaddrs() gives them: what the Address List
 * option of RFC 7761 sec. 4.3.4 advertises, so that a neighbor whose route
 * names one of them as next hop knows the Join goes to primary.  At most
 * MAX_SECADDRS are written to list, but the count returned is of all of
 * them, so that the one caller that reports a longer list can; the poll
 * below runs every tick and would repeat it.
 */
u_int vif_secaddrs(struct ifaddrs *ifap, const char *ifname, uint32_t primary, uint32_t *list)
{
    struct ifaddrs *ifa;
    u_int num = 0;

    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
	uint32_t addr;

	if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET)
	    continue;

	if (strcmp(ifa->ifa_name, ifname))
	    continue;

	addr = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr;
	if (addr == primary || !inet_valid_host(addr))
	    continue;

	if (num < MAX_SECADDRS)
	    list[num] = addr;
	num++;
    }

    return num;
}


/*
 * Compare each VIF against the address the kernel has for its interface now.
 * The first address of an interface is the one config_vifs_from_kernel()
 * builds the VIF on -- the others become altnets -- so the same walk is used
 * here, rather than SIOCGIFADDR, to be sure the two agree on an interface
 * carrying several addresses.  Otherwise a VIF whose address merely came
 * second in somebody's list would be restarted on every poll.
 *
 * A VIF that is out of service is asked as well, and renumber_vif() then
 * only moves its fields: an interface that was destroyed and created again
 * under the same name keeps the VIF it had, and has to be started on the
 * address the kernel has for it now rather than on the one that went with
 * the ifnet it used to be.  Which is why this runs before the up/down pass
 * in check_vif_state() rather than after it.
 */
static void check_vif_addrs(void)
{
    struct ifaddrs *ifap, *ifa;
    struct uvif *v;
    vifi_t vifi;

    if (priv_getifaddrs(&ifap) < 0) {
	logit(LOG_WARNING, errno, "%s(): getifaddrs()", __func__);
	return;
    }

    for (vifi = 0, v = uvifs; vifi < numvifs; ++vifi, ++v) {
	uint32_t secaddrs[MAX_SECADDRS];
	uint32_t prev_addr = v->uv_lcl_addr;
	u_int nsecaddrs;

	if (v->uv_flags & (VIFF_DISABLED | VIFF_REGISTER | VIFF_TUNNEL))
	    continue;

	/* A point-to-point link carries a peer address as well, and what a
	 * netmask means on one differs per OS; renumbering one is left to a
	 * SIGHUP rather than guessed at here. */
	if (v->uv_flags & VIFF_POINT_TO_POINT)
	    continue;

	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
	    uint32_t addr, mask;

	    if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET)
		continue;

	    if (strcmp(ifa->ifa_name, v->uv_name))
		continue;

	    addr = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr;
	    if (ifa->ifa_netmask)
		mask = ((struct sockaddr_in *)ifa->ifa_netmask)->sin_addr.s_addr;
	    else
		mask = 0xffffffff;

	    renumber_vif(vifi, addr, mask);
	    break;		/* Only the first address of the interface */
	}

	/* Nothing to announce for a VIF that is out of service, and the
	 * interface of one that has gone has no addresses left to read.
	 * The next pass after it is back in service picks the list up, and
	 * sends the Hello that carries it. */
	if (v->uv_flags & VIFF_DOWN)
	    continue;

	/* RFC 7761 sec. 4.3.1: a secondary address that changes is announced
	 * at once, in a Hello with the new Address List.  A renumbered VIF
	 * needs no Hello of its own here, start_vif() has already armed the
	 * one that will carry the list. */
	nsecaddrs = MIN(vif_secaddrs(ifap, v->uv_name, v->uv_lcl_addr, secaddrs), MAX_SECADDRS);
	if (nsecaddrs == v->uv_nsecaddrs &&
	    !memcmp(secaddrs, v->uv_secaddrs, nsecaddrs * sizeof(secaddrs[0])))
	    continue;

	logit(LOG_NOTICE, 0, "VIF #%u: interface %s now has %u secondary address(es)",
	      vifi, v->uv_name, nsecaddrs);
	memcpy(v->uv_secaddrs, secaddrs, nsecaddrs * sizeof(secaddrs[0]));
	v->uv_nsecaddrs = nsecaddrs;

	if (prev_addr == v->uv_lcl_addr && !(v->uv_flags & VIFF_DOWN))
	    send_pim_hello(v, pim_timer_hello_holdtime);
    }

    priv_freeifaddrs(ifap);
}


/*
 * See if any interfaces have changed from up state to down, or vice versa,
 * including any non-multicast-capable interfaces that are in use as local
 * tunnel end-points.  Ignore interfaces that have been administratively
 * disabled.
 */
void check_vif_state(void)
{
    vifi_t vifi;
    struct uvif *v;
    struct ifreq ifr;
    static int checking_vifs = 0;

    /*
     * XXX: TODO: True only for DVMRP?? Check.
     * If we get an error while checking, (e.g. two interfaces go down
     * at once, and we decide to send a prune out one of the failed ones)
     * then don't go into an infinite loop!
     */
    if (checking_vifs)
	return;

    vifs_down = FALSE;
    checking_vifs = 1;

    /* An interface that is still there may have been renumbered, and one
     * that is coming back may have another address than the one its VIF
     * was built on.  Before the flags below, so that a VIF is started on
     * the address the kernel has for it rather than on a stale one. */
    check_vif_addrs();

    /* TODO: Check all potential interfaces!!! */
    /* Check the physical and tunnels only */
    for (vifi = 0, v = uvifs; vifi < numvifs; ++vifi, ++v) {
	if (v->uv_flags & (VIFF_DISABLED | VIFF_REGISTER))
	    continue;

	/* get the interface flags */
	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, v->uv_name, sizeof(ifr.ifr_name));
	if (ioctl(udp_socket, SIOCGIFFLAGS, (char *)&ifr) < 0) {
	    /*
	     * An interface that has been removed is ENODEV on Linux and
	     * ENXIO on *BSD.  Any other error leaves ifr_flags unset, so
	     * there is nothing to decide on either way: take the VIF out
	     * of service instead, rather than leave the kernel forwarding
	     * out an interface we can no longer ask about.
	     */
	    if (!(v->uv_flags & VIFF_DOWN)) {
		if (errno != ENODEV && errno != ENXIO)
		    logit(LOG_WARNING, errno, "%s(): ioctl SIOCGIFFLAGS for %s", __func__, ifr.ifr_name);

		logit(LOG_NOTICE, 0, "Interface %s has gone; VIF #%u taken out of service", v->uv_name, vifi);
		stop_vif(vifi);
	    }

	    vifs_down = TRUE;
	    continue;
	}

	if (v->uv_flags & VIFF_DOWN) {
	    if (ifr.ifr_flags & IFF_UP)
		start_vif(vifi);
	    else
		vifs_down = TRUE;
	} else {
	    if (!(ifr.ifr_flags & IFF_UP)) {
		logit(LOG_NOTICE, 0, "Interface %s has gone down; VIF #%u taken out of service", v->uv_name, vifi);
		stop_vif(vifi);
		vifs_down = TRUE;
	    }
	}
    }

    /* Check the register(s) vif(s) */
    for (vifi = 0, v = uvifs; vifi < numvifs; ++vifi, ++v) {
	vifi_t vifi2;
	struct uvif *v2;
	int found;

	if (!(v->uv_flags & VIFF_REGISTER))
	    continue;

	found = 0;

	/* Find a physical vif with the same IP address as the
	 * Register vif. */
	for (vifi2 = 0, v2 = uvifs; vifi2 < numvifs; ++vifi2, ++v2) {
	    if (v2->uv_flags & (VIFF_DISABLED | VIFF_DOWN | VIFF_REGISTER | VIFF_TUNNEL))
		continue;

	    if (v->uv_lcl_addr != v2->uv_lcl_addr)
		continue;

	    found = 1;
	    break;
	}

	/* The physical interface with the IP address as the Register
	 * vif is probably DOWN. Get a replacement. */
	if (!found)
	    update_reg_vif(vifi);
    }

    checking_vifs = 0;
}


/*
 * Take the interfaces the kernel has gained since the last look and give
 * each of them a VIF, then bring the rest of the table up to date the way
 * the periodic poll does.
 *
 * init_vifs() used to be the only caller of config_vifs_from_kernel(), so
 * the table was whatever the kernel had when pimd started: an interface
 * configured afterwards never became a VIF, and only a restart could fix
 * it.  That is the ordinary case on anything whose links are negotiated
 * rather than configured -- PPP, L2TP, a tunnel that comes up, a VLAN
 * added to a router in service -- and on a daemon started from an rc
 * script beside the thing that builds them.
 *
 * An interface that is merely back, under a name a VIF already has, is not
 * new: the scan recognises it by name and check_vif_state() puts that VIF
 * back in service on whatever address it carries now.  Only a name pimd
 * has never seen takes a slot of its own, so a link that comes and goes
 * costs one VIF and not one per flap.
 */
void rescan_vifs(void)
{
    vifi_t vifi, first;
    struct uvif *v;

    first = config_vifs_rescan();
    if (first != numvifs) {
	/* Whatever pimd.conf has to say about the interfaces that have
	 * just appeared, which nothing has applied to them yet: the lines
	 * naming them were read at startup, when there was no VIF of that
	 * name for parse_phyint() to find. */
	config_phyints_from_file(first);

	for (vifi = first, v = &uvifs[first]; vifi < numvifs; ++vifi, ++v) {
	    /* As in init_vifs(), which arms this on every VIF it installs */
	    SET_TIMER(v->uv_jp_timer, PIM_JOIN_PRUNE_HOLDTIME);

	    if (v->uv_flags & (VIFF_DISABLED | VIFF_DOWN)) {
		logit(LOG_INFO, 0, "Interface %s is %s; VIF #%u out of service",
		      v->uv_name, v->uv_flags & VIFF_DISABLED ? "DISABLED" : "DOWN", vifi);
		continue;
	    }

	    start_vif(vifi);
	}
    }

    /* Also for the VIFs that were already there: an interface that has
     * gone, come back or been renumbered while we were not looking, and
     * the register vif, which may have nothing to sit on until now. */
    check_vif_state();
}


/*
 * Ask for a rescan, from the handler that read the kernel's notification.
 * One interface coming up is several messages -- the link, then each of
 * its addresses -- and each of those is worth the same single scan, so
 * the first schedules one and the rest ride on it.  Short enough not to
 * be noticed, long enough that an interface which arrives before its
 * address is scanned once, with the address.
 */
void rescan_vifs_request(void)
{
    if (rescan_timer)
	return;

    rescan_timer = timer_set_ms(VIF_RESCAN_DELAY, rescan_timeout, NULL);
}

static void rescan_timeout(void *arg __attribute__((unused)))
{
    rescan_timer = 0;
    rescan_vifs();
}


/*
 * Find VIF from ifindex
 */
vifi_t find_vif(int ifi)
{
    struct uvif *v;
    vifi_t vifi;

    if (ifi < 0)
	return NO_VIF;

    for (vifi = 0, v = uvifs; vifi < numvifs; ++vifi, ++v) {
	if (v->uv_ifindex == ifi)
	    return vifi;
    }

    return NO_VIF;
}


/*
 * If the source is directly connected to us, find the vif number for
 * the corresponding physical interface (Register and tunnels excluded).
 * Local addresses are excluded.
 * Return the vif number or NO_VIF if not found.
 */
vifi_t find_vif_direct(uint32_t src)
{
    vifi_t vifi;
    struct uvif *v;
    struct phaddr *p;
    struct rpfctl rpf;

    for (vifi = 0, v = uvifs; vifi < numvifs; ++vifi, ++v) {
	if (v->uv_flags & (VIFF_DISABLED | VIFF_DOWN | VIFF_REGISTER | VIFF_TUNNEL))
	    continue;

	if (src == v->uv_lcl_addr)
	    return NO_VIF;	/* src is one of our IP addresses */

	if (is_uv_subnet(src, v))
	    return vifi;

	/* Check the extra subnets for this vif */
	/* TODO: don't think currently pimd can handle extra subnets */
	for (p = v->uv_addrs; p; p = p->pa_next) {
	    if (is_pa_subnet(src, v))
		return vifi;
	}

	/* POINTOPOINT but not VIFF_TUNNEL interface (e.g., GRE) */
	if ((v->uv_flags & VIFF_POINT_TO_POINT) && (src == v->uv_rmt_addr))
	    return vifi;
    }

    /* Check if the routing table has a direct route (no gateway). */
    if (k_req_incoming(src, &rpf)) {
	if (rpf.source.s_addr == rpf.rpfneighbor.s_addr) {
	    return rpf.iif;
	}
    }

    return NO_VIF;
}


/*
 * Checks if src is local address. If "yes" return the vif index,
 * otherwise return value is NO_VIF.
 */
vifi_t local_address(uint32_t src)
{
    vifi_t vifi;
    struct uvif *v;

    for (vifi = 0, v = uvifs; vifi < numvifs; ++vifi, ++v) {
	/* TODO: XXX: what about VIFF_TUNNEL? */
	if (v->uv_flags & (VIFF_DISABLED | VIFF_DOWN | VIFF_REGISTER))
	    continue;

	if (src == v->uv_lcl_addr)
	    return vifi;
    }

    /* Returning NO_VIF means not a local address */
    return NO_VIF;
}

/*
 * If the source 'src' is directly connected, or is local address, find
 * the VIF number for the corresponding physical interface (Register and
 * tunnels excluded).
 *
 * If it's not a local address, or available on a subnet from a local
 * interface, we optionally check the kernel routing table (RIB) to
 * find a matching VIF.
 *
 * Return the VIF number or NO_VIF if not found.
 */
vifi_t find_vif_direct_local(uint32_t src, int rib)
{
    vifi_t vifi;
    struct uvif *v;
    struct phaddr *p;
    struct rpfctl rpf;

    for (vifi = 0, v = uvifs; vifi < numvifs; ++vifi, ++v) {
	/* TODO: XXX: what about VIFF_TUNNEL? */
	if (v->uv_flags & (VIFF_DISABLED | VIFF_DOWN | VIFF_REGISTER | VIFF_TUNNEL))
	    continue;

	if (src == v->uv_lcl_addr)
	    return vifi;	/* src is one of our IP addresses */

	if (is_uv_subnet(src, v))
	    return vifi;

	/* Check the extra subnets for this vif */
	/* TODO: don't think currently pimd can handle extra subnets */
	for (p = v->uv_addrs; p; p = p->pa_next) {
	    if (is_pa_subnet(src, v))
		return vifi;
	}

	/* POINTOPOINT but not VIFF_TUNNEL interface (e.g., GRE) */
	if ((v->uv_flags & VIFF_POINT_TO_POINT) && (src == v->uv_rmt_addr))
	    return vifi;
    }

    if (rib) {
	/* Check if the routing table has a direct route (no gateway). */
	if (k_req_incoming(src, &rpf)) {
	    if (rpf.source.s_addr == rpf.rpfneighbor.s_addr) {
		return rpf.iif;
	    }
	}
    }

    return NO_VIF;
}

/*
 * Returns the highest address of local vif that is UP and ENABLED.
 * The VIFF_REGISTER interface(s) is/are excluded.
 */
uint32_t max_local_address(void)
{
    vifi_t vifi;
    struct uvif *v;
    uint32_t max_address = 0;

    for (vifi = 0, v = uvifs; vifi < numvifs; ++vifi, ++v) {
	/* Count vif if not DISABLED or DOWN */
	/* TODO: XXX: What about VIFF_TUNNEL? */
	if (v->uv_flags & (VIFF_DISABLED | VIFF_DOWN | VIFF_REGISTER))
	    continue;

	if (ntohl(v->uv_lcl_addr) > ntohl(max_address))
	    max_address = v->uv_lcl_addr;
    }

    return max_address;
}


/*
 * On every timer interrupt, advance (i.e. decrease) the timer for each
 * neighbor and group entry for each vif.
 */
void age_vifs(void)
{
    vifi_t           vifi;
    struct uvif     *v;
    pim_nbr_entry_t *next, *curr;

    /* The vifs_down flag used to gate this, on the assumption that a send
     * on a dead interface fails with ENETDOWN and calls check_vif_state()
     * itself.  It does not: an interface that has been removed altogether
     * takes its addresses with it, so pimd's IP_MULTICAST_IF is silently
     * ignored and the Hello leaves by whatever route the kernel picks
     * instead.  Nothing then ever set vifs_down and the VIF stayed in
     * service forever, so poll the interfaces unconditionally.
     *
     * Every VIF_RESCAN_PERIOD the whole kernel interface list is read
     * instead, which also finds the interfaces pimd has no VIF for at
     * all.  The notifications on the event socket are what make that
     * prompt; this is the floor under them, see VIF_RESCAN_PERIOD.
     */
    if (++rescan_ticks >= VIF_RESCAN_PERIOD / TIMER_INTERVAL) {
	rescan_ticks = 0;
	rescan_vifs();
    } else {
	check_vif_state();
    }

    /* Age many things */
    for (vifi = 0, v = uvifs; vifi < numvifs; ++vifi, ++v) {
	if (v->uv_flags & (VIFF_DISABLED | VIFF_DOWN | VIFF_REGISTER))
	    continue;

	/* Timeout neighbors */
	for (curr = v->uv_pim_neighbors; curr; curr = next) {
	    next = curr->next;

	    /* Never timeout neighbors with holdtime = 0xffff.
	     * This may be used with ISDN lines to avoid keeping the
	     * link up with periodic Hello messages.
	     */
	    /* TODO: XXX: TIMER implem. dependency! */
	    if (PIM_HELLO_HOLDTIME_FOREVER == curr->timer)
		continue;
	    IF_NOT_TIMEOUT(curr->timer)
		continue;

	    logit(LOG_INFO, 0, "Delete PIM neighbor %s on %s (holdtime timeout)",
		  inet_fmt(curr->address, s2, sizeof(s2)), v->uv_name);

	    delete_pim_nbr(curr);
	}

	/* PIM_HELLO periodic */
	IF_TIMEOUT(v->uv_hello_timer)
	    send_pim_hello(v, pim_timer_hello_holdtime);

#ifdef TOBE_DELETED
	/* PIM_JOIN_PRUNE periodic */
	/* TODO: XXX: TIMER implem. dependency! */
	if (v->uv_jp_timer <= TIMER_INTERVAL)
	    /* TODO: need to scan the whole routing table,
	     * because different entries have different Join/Prune timer.
	     * Probably don't need the Join/Prune timer per vif.
	     */
	    send_pim_join_prune(vifi, NULL, PIM_JOIN_PRUNE_HOLDTIME);
	else
	    /* TODO: XXX: TIMER implem. dependency! */
	    v->uv_jp_timer -= TIMER_INTERVAL;
#endif /* TOBE_DELETED */

	/* IGMP query periodic */
	IF_TIMEOUT(v->uv_gq_timer)
	    query_groups(v);

	if (v->uv_querier) {
	    v->uv_querier->al_timer += TIMER_INTERVAL;
	    if (v->uv_querier->al_timer > igmp_querier_timeout) {
		/*
		 * The current querier has timed out.  We must become
		 * the querier.
		 */
		IF_DEBUG(DEBUG_IGMP) {
		    logit(LOG_DEBUG, 0, "IGMP Querier %s timed out.",
			  inet_fmt(v->uv_querier->al_addr, s1, sizeof(s1)));
		}
		free(v->uv_querier);
		v->uv_querier = NULL;
		v->uv_flags |= VIFF_QUERIER;
		query_groups(v);
	    }
	}
    }
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "cc-mode"
 * End:
 */
