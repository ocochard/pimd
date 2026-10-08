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

#include "defs.h"


/*
 * The hash function. Stolen from Eddy's (eddy@isi.edu)
 * implementation (for compatibility ;)
 */
#define SEED1   1103515245
#define SEED2   12345
#define RP_HASH_VALUE(G, M, C) (((SEED1) * (((SEED1) * ((G) & (M)) + (SEED2)) ^ (C)) + (SEED2)) % 0x80000000)

cand_rp_t               *cand_rp_list;
grp_mask_t              *grp_mask_list;
cand_rp_t               *segmented_cand_rp_list;
grp_mask_t              *segmented_grp_mask_list;
uint16_t                 curr_bsr_fragment_tag;
uint8_t                  curr_bsr_priority;
uint32_t                 curr_bsr_address;
uint32_t                 curr_bsr_hash_mask;
uint16_t                 pim_bootstrap_timer;   /* For electing the BSR and
						 * sending Cand-RP-set msgs */
uint8_t                  my_bsr_priority;
uint16_t                 my_bsr_adv_period;
uint16_t                 my_bsr_timeout;
uint16_t                 recommended_rp_holdtime;
uint32_t                 my_bsr_address;
uint32_t                 my_bsr_hash_mask;
uint32_t                 rp_set_limit = PIM_RP_SET_LIMIT;
uint32_t                 rp_set_entries;	/* Group ranges held now */
static int               rp_set_limit_said = FALSE;
static int               rp_per_range_said = FALSE;
static int               bootstrap_truncated_said = FALSE;

uint8_t                  cand_bsr_flag = FALSE; /* Set to TRUE if I am
						 * a candidate BSR */
uint8_t                  cand_bsr_configured = FALSE;
uint32_t                 my_cand_rp_address;
uint8_t                  my_cand_rp_priority;
uint16_t                 my_cand_rp_holdtime;
uint16_t                 my_cand_rp_adv_period; /* The locally configured
						 * Cand-RP adv. period. */
uint16_t                 pim_cand_rp_adv_timer;
uint8_t                  cand_rp_flag  = FALSE;  /* Candidate RP flag */
uint8_t                  cand_rp_configured = FALSE;
uint32_t                 rp_my_ipv4_hashmask;


/*
 * Local functions definition.
 */
static cand_rp_t  *add_cand_rp          (cand_rp_t **used_cand_rp_list, uint32_t address);
static grp_mask_t *add_grp_mask         (grp_mask_t **used_grp_mask_list,
					 uint32_t group_addr,
					 uint32_t group_mask,
					 uint32_t hash_mask);
static void       delete_grp_mask_entry (cand_rp_t **used_cand_rp_list,
					 grp_mask_t **used_grp_mask_list,
					 grp_mask_t *grp_mask_delete);
static void       delete_rp_entry       (cand_rp_t **used_cand_rp_list,
					 grp_mask_t **used_grp_mask_list,
					 cand_rp_t *cand_rp_ptr);
static void       remap_covered_groups  (grp_mask_t *mask_ptr);

/* Set once the two elections below have been started, which is what tells a
 * candidacy resolved at config time from one resolved while pimd runs */
static int        rp_and_bsr_inited = FALSE;

/*
 * Take up the Candidate-BSR role at @addr, the way init_rp_and_bsr() does at
 * startup: this router is the BSR until it hears a better one, which is how
 * the election of RFC 5059 sec. 3.1 is entered.  Declaring ourselves and
 * being corrected on the wire is what a candidate that starts beside an
 * inferior BSR does anyway -- the alternative, waiting for the elected one to
 * time out, leaves a better candidate silent for BS_Timeout.
 */
static void cand_bsr_start(void)
{
    curr_bsr_fragment_tag = RANDOM();
    curr_bsr_priority     = my_bsr_priority;
    curr_bsr_address      = my_bsr_address;
    curr_bsr_hash_mask    = my_bsr_hash_mask;
    SET_TIMER(pim_bootstrap_timer, bootstrap_initial_delay());
}

/*
 * And give it up, for a candidacy whose address has gone: back to the state
 * init_rp_and_bsr() gives a router that is not a candidate, which is to
 * accept a Bootstrap from anyone.  Only where we were the elected BSR -- if
 * somebody else holds the role, nothing about them has changed.
 */
static void cand_bsr_stop(void)
{
    if (curr_bsr_address != my_bsr_address)
	return;

    curr_bsr_fragment_tag = 0;
    curr_bsr_priority     = 0;		  /* Lowest priority */
    curr_bsr_address      = INADDR_ANY_N; /* Lowest priority */
    MASKLEN_TO_MASK(RP_DEFAULT_IPV4_HASHMASKLEN, curr_bsr_hash_mask);
    SET_TIMER(pim_bootstrap_timer, my_bsr_timeout);
}

/*
 * The Candidate-BSR address, once pimd is running: @addr is what the
 * `bsr-candidate' line resolves to now, and INADDR_ANY_N that it resolves to
 * nothing -- the interface it names has not appeared yet, or has gone.
 *
 * config_resolve_addrs() (src/config.c) calls this from the interface rescan,
 * so a candidacy written against an interface that is negotiated rather than
 * configured -- PPP, L2TP, a tunnel -- is taken up when the address arrives
 * instead of being resolved once and wrongly at startup.
 */
void cand_bsr_address_set(uint32_t addr)
{
    if (!rp_and_bsr_inited || addr == my_bsr_address)
	return;

    if (addr == INADDR_ANY_N) {
	if (!cand_bsr_flag)
	    return;

	logit(LOG_NOTICE, 0, "Cand-BSR address %s is gone, standing down",
	      inet_fmt(my_bsr_address, s1, sizeof(s1)));
	cand_bsr_flag = FALSE;
	cand_bsr_stop();
	my_bsr_address = INADDR_ANY_N;

	return;
    }

    logit(LOG_NOTICE, 0, "Cand-BSR address is %s now, was %s",
	  inet_fmt(addr, s1, sizeof(s1)),
	  cand_bsr_flag ? inet_fmt(my_bsr_address, s2, sizeof(s2)) : "unresolved");

    /* An address that moved under an election we are winning moves the
     * election with it: same router, same priority, new address, and a
     * fragment tag that says the set is being sent again. */
    cand_bsr_stop();
    my_bsr_address = addr;
    cand_bsr_flag  = TRUE;

    /* Claim the role only where nobody better holds it.  init_rp_and_bsr()
     * claims it unconditionally and is right to -- a router that has just
     * started has heard nothing -- but by now a Bootstrap may have, and the
     * comparison is receive_pim_bootstrap()'s: the higher priority, and the
     * higher address where the priorities are equal (RFC 5059 sec. 3.1).
     * Where a better BSR holds it there is nothing to do; the Bootstrap
     * Timer is its timeout, and this router is a candidate from now on. */
    if (curr_bsr_address == INADDR_ANY_N ||
	my_bsr_priority > curr_bsr_priority ||
	(my_bsr_priority == curr_bsr_priority &&
	 ntohl(my_bsr_address) > ntohl(curr_bsr_address)))
	cand_bsr_start();
}

/*
 * The same for the Candidate-RP address of the `rp-candidate' line.  There is
 * no election to enter here, only an advertisement to start sending; the BSR
 * ages the address we stop advertising out at its own holdtime, which is what
 * RFC 5059 sec. 4.1 leaves it to do.
 */
void cand_rp_address_set(uint32_t addr)
{
    if (!rp_and_bsr_inited || addr == my_cand_rp_address)
	return;

    if (addr == INADDR_ANY_N) {
	if (!cand_rp_flag)
	    return;

	logit(LOG_NOTICE, 0, "Cand-RP address %s is gone, standing down",
	      inet_fmt(my_cand_rp_address, s1, sizeof(s1)));
	cand_rp_flag = FALSE;
	my_cand_rp_address = INADDR_ANY_N;

	return;
    }

    logit(LOG_NOTICE, 0, "Cand-RP address is %s now, was %s",
	  inet_fmt(addr, s1, sizeof(s1)),
	  cand_rp_flag ? inet_fmt(my_cand_rp_address, s2, sizeof(s2)) : "unresolved");

    my_cand_rp_address = addr;
    cand_rp_flag       = TRUE;
    MASKLEN_TO_MASK(RP_DEFAULT_IPV4_HASHMASKLEN, rp_my_ipv4_hashmask);

    /* At once rather than after an interval, as init_rp_and_bsr() does not:
     * a candidacy that has just become able to speak has waited long enough */
    SET_TIMER(pim_cand_rp_adv_timer, 1);
}


void init_rp_and_bsr(void)
{
    /* TODO: if the grplist is not NULL, remap all groups ASAP! */
    delete_rp_list(&cand_rp_list, &grp_mask_list);
    delete_rp_list(&segmented_cand_rp_list, &segmented_grp_mask_list);

    /* A reload gives the count back, and lets the log say it again */
    rp_set_entries = 0;
    rp_set_limit_said = FALSE;
    rp_per_range_said = FALSE;
    bootstrap_truncated_said = FALSE;

    if (cand_bsr_flag == FALSE) {
	/*
	 * If I am not candidat BSR, initialize the "current BSR"
	 * as having the lowest priority.
	 */
	curr_bsr_fragment_tag = 0;
	curr_bsr_priority = 0;             /* Lowest priority */
	curr_bsr_address  = INADDR_ANY_N;  /* Lowest priority */
	MASKLEN_TO_MASK(RP_DEFAULT_IPV4_HASHMASKLEN, curr_bsr_hash_mask);
	SET_TIMER(pim_bootstrap_timer, my_bsr_timeout);
    } else {
	cand_bsr_start();
    }

    if (cand_rp_flag != FALSE) {
	MASKLEN_TO_MASK(RP_DEFAULT_IPV4_HASHMASKLEN, rp_my_ipv4_hashmask);
	/* Setup the Cand-RP-Adv-Timer */
	SET_TIMER(pim_cand_rp_adv_timer, RANDOM() % my_cand_rp_adv_period);
    }

    rp_and_bsr_inited = TRUE;
}


uint16_t bootstrap_initial_delay(void)
{
    uint32_t addr_delay;
    uint32_t delay;
    uint32_t log_mask;
    int32_t  log_of_2;
    uint8_t  best_priority;

    /*
     * The bootstrap timer initial value (if Cand-BSR).
     * It depends of the bootstrap router priority:
     * higher priority has shorter value:
     *
     * delay = 5 + 2 * log_2(1 + best_priority - myPriority) + addr_delay;
     *
     *    best_priority = Max(storedPriority, myPriority);
     *    if (best_priority == myPriority)
     *        addr_delay = log_2(bestAddr - myAddr)/16;
     *    else
     *        addr_delay = 2 - (myAddr/2^31);
     */

    best_priority = MAX(curr_bsr_priority, my_bsr_priority);
    if (best_priority == my_bsr_priority) {
	addr_delay = ntohl(curr_bsr_address) - ntohl(my_bsr_address);
	/* Calculate the integer part of log_2 of (bestAddr - myAddr) */
	/* To do so, have to find the position number of the first bit
	 * from left which is `1`
	 */
	log_mask = sizeof(addr_delay) << 3;
	log_mask = (1U << (log_mask - 1));  /* Set the leftmost bit to `1` */
	for (log_of_2 = (sizeof(addr_delay) << 3) - 1 ; log_of_2; log_of_2--) {
	    if (addr_delay & log_mask)
		break;

	    log_mask >>= 1;  /* Start shifting `1` on right */
	}
	addr_delay = log_of_2 / 16;
    } else {
	addr_delay = 2 - (ntohl(my_bsr_address) / ( 1U << 31));
    }

    delay = 1 + best_priority - my_bsr_priority;
    /* Calculate log_2(delay) */
    log_mask = sizeof(delay) << 3;
    log_mask = (1U << (log_mask - 1));  /* Set the leftmost bit to `1` */
    for (log_of_2 = (sizeof(delay) << 3) - 1 ; log_of_2; log_of_2--) {
	if (delay & log_mask)
	    break;

	log_mask >>= 1;  /* Start shifting `1` on right */
    }

    delay = 5 + 2 * log_of_2 + addr_delay;

    return (uint16_t)delay;
}


static cand_rp_t *add_cand_rp(cand_rp_t **used_cand_rp_list, uint32_t address)
{
    cand_rp_t *prev = NULL;
    cand_rp_t *next;
    cand_rp_t *ptr;
    rpentry_t *entry;
    uint32_t addr_h = ntohl(address);

    /* The ordering is the bigger first */
    for (next = *used_cand_rp_list; next; prev = next, next = next->next) {
	if (ntohl(next->rpentry->address) > addr_h)
	    continue;

	if (next->rpentry->address == address)
	    return next;
	else
	    break;
    }

    /* Create and insert the new entry between prev and next */
    ptr = calloc(1, sizeof(cand_rp_t));
    if (!ptr) {
	logit(LOG_ERR, 0, "Ran out of memory in add_cand_rp()");
	return NULL;
    }

    ptr->rp_grp_next = NULL;
    ptr->next = next;
    ptr->prev = prev;
    if (next)
	next->prev = ptr;
    if (prev == NULL)
	*used_cand_rp_list = ptr;
    else
	prev->next = ptr;

    entry = calloc(1, sizeof(rpentry_t));
    if (!entry) {
	logit(LOG_ERR, 0, "Ran out of memory in add_cand_rp()");
	return NULL;
    }

    ptr->rpentry = entry;
    entry->next = NULL;
    entry->prev  = NULL;
    entry->address = address;
    entry->mrtlink = NULL;
    entry->incoming = NO_VIF;
    entry->upstream = NULL;
    /* TODO: setup the metric and the preference as ~0 (the lowest)? */
    entry->metric = ~0;
    entry->preference = ~0;
    entry->cand_rp = ptr;

    /* TODO: XXX: check whether there is a route to that RP: if return value
     * is FALSE, then no route.
     *
     * For an RP address of our own set_incoming() gives the register vif,
     * and with it the zero metric and preference of a connected route,
     * which is the MRIB.metric(RP(G)) of RFC 7761 sec. 4.6.3 for the RP
     * itself.  Skipping it for that case, as this used to, left the ~0
     * above in place, so every Assert the RP sent from the shared tree
     * carried the infinite metric of an AssertCancel.
     */
    set_incoming(entry, PIM_IIF_RP);

    return ptr;
}


static grp_mask_t *add_grp_mask(grp_mask_t **used_grp_mask_list, uint32_t group_addr, uint32_t group_mask, uint32_t hash_mask)
{
    grp_mask_t *prev = NULL;
    grp_mask_t *next;
    grp_mask_t *ptr;
    uint32_t prefix_h = ntohl(group_addr & group_mask);

    /* The ordering of group_addr is: bigger first */
    for (next = *used_grp_mask_list; next; prev = next, next = next->next) {
	if (ntohl(next->group_addr & next->group_mask) > prefix_h)
	    continue;

	/* The ordering of group_mask is: bigger (longer) first */
	if ((next->group_addr & next->group_mask) == (group_addr & group_mask)) {
	    if (ntohl(next->group_mask) > ntohl(group_mask))
		continue;
	    else if (next->group_mask == group_mask)
		return next;
	    else
		break;
	}
    }

    /* Every group range of the RP set is created here, whoever asked for
     * it: a Bootstrap, a Candidate-RP Advertisement, an Auto-RP mapping or
     * a line of pimd.conf.  The first two are a stranger's to send -- a
     * Cand-RP-Adv is unicast to the BSR and needs no neighbour
     * relationship -- and what they made this router hold was bounded by
     * nothing at all, which a BSR then wrote into every Bootstrap it built
     * until the send buffer ran out (see create_pim_bootstrap_message()).
     */
    /* The segmented list is scratch: receive_pim_bootstrap() assembles one
     * message in it and frees the lot with delete_rp_list(), which frees
     * the masks directly rather than through delete_grp_mask_entry().  So
     * only the RP set proper is counted, or the count would climb by a
     * range per Bootstrap and refuse everything within a day. */
    if (used_grp_mask_list == &grp_mask_list && rp_set_entries >= rp_set_limit) {
	if (!rp_set_limit_said) {
	    logit(LOG_WARNING, 0, "RP set limit of %u group ranges reached, refusing %s"
		  " (rp-set-limit in %s raises it)", rp_set_limit,
		  netname(group_addr, group_mask), config_file);
	    rp_set_limit_said = TRUE;
	}

	return NULL;
    }

    ptr = calloc(1, sizeof(grp_mask_t));
    if (!ptr) {
	logit(LOG_ERR, 0, "Ran out of memory in add_grp_mask()");
	return NULL;
    }
    if (used_grp_mask_list == &grp_mask_list)
	rp_set_entries++;

    ptr->grp_rp_next = (rp_grp_entry_t *)NULL;
    ptr->next = next;
    ptr->prev = prev;
    if (next)
	next->prev = ptr;
    if (prev == NULL)
	*used_grp_mask_list = ptr;
    else
	prev->next = ptr;

    ptr->group_addr = group_addr;
    ptr->group_mask = group_mask;
    ptr->hash_mask  = hash_mask;
    ptr->group_rp_number = 0;
    ptr->fragment_tag = 0;

    return ptr;
}

/* When C-RP-set is changed it is recommended to send a bootstrap message.
 * There MUST however be a minimum of BS_Min_Interval between each time
 * a BSM is sent.
 */
static void update_bootstrap_timer(void)
{
    if (cand_bsr_flag == TRUE && curr_bsr_address == my_bsr_address) {
	if (pim_bootstrap_timer > PIM_MIN_BOOTSTRAP_PERIOD) {
	    logit(LOG_DEBUG, 0, "RP-set changed; Reducing bootstrap timer.");
	    SET_TIMER(pim_bootstrap_timer, PIM_MIN_BOOTSTRAP_PERIOD);
	}
    }
}

/* TODO: XXX: BUG: a remapping for some groups currently using some other
 * grp_mask may be required by the addition of the new entry!!!
 * Remapping all groups might be a costly process...
 */
rp_grp_entry_t *add_rp_grp_entry(cand_rp_t  **used_cand_rp_list,
				 grp_mask_t **used_grp_mask_list,
				 uint32_t rp_addr,
				 uint8_t  rp_priority,
				 uint16_t rp_holdtime,
				 uint32_t group_addr,
				 uint32_t group_mask,
				 uint32_t bsr_hash_mask,
				 uint16_t fragment_tag)
{
    cand_rp_t *cand_rp_ptr;
    grp_mask_t *mask_ptr;
    rp_grp_entry_t *entry_next;
    rp_grp_entry_t *entry_new;
    rp_grp_entry_t *entry_prev = NULL;
    grpentry_t *grpentry_ptr_prev;
    grpentry_t *grpentry_ptr_next;
    uint32_t rp_addr_h;
    uint8_t old_highest_priority = ~0;  /* Smaller value means "higher" */

    /* Input data verification */
    if (!inet_valid_host(rp_addr))
	return NULL;
    if (!IN_CLASSD(ntohl(group_addr)))
	return NULL;

    mask_ptr = add_grp_mask(used_grp_mask_list, group_addr, group_mask, bsr_hash_mask);
    if (mask_ptr == NULL)
	return NULL;

    rp_addr_h = ntohl(rp_addr);
    mask_ptr->fragment_tag = fragment_tag;   /* For garbage collection */

    entry_prev = NULL;
    entry_next = mask_ptr->grp_rp_next;
    /* TODO: improve it */
    if (entry_next != NULL)
	old_highest_priority = entry_next->priority;
    for ( ; entry_next; entry_prev = entry_next,
	      entry_next = entry_next->grp_rp_next) {
	/* Smaller value means higher priority. The entries are
	 * sorted with the highest priority first.
	 */
	if (entry_next->priority < rp_priority)
	    continue;
	if (entry_next->priority > rp_priority)
	    break;

	/*
	 * Here we don't care about higher/lower addresses, because
	 * higher address does not guarantee higher hash_value,
	 * but anyway we do order with the higher address first,
	 * so it will be easier to find an existing entry and update the
	 * holdtime.
	 */
	if (ntohl(entry_next->rp->rpentry->address) > rp_addr_h)
	    continue;
	if (ntohl(entry_next->rp->rpentry->address) < rp_addr_h)
	    break;
	/* We already have this entry. Update the holdtime.
	 *
	 * This is the common case, not an oddity: a BSR sends the whole RP
	 * set every bootstrap period under a fresh fragment tag -- ours is
	 * incremented per message in create_pim_bootstrap_message() -- so
	 * every RP that is still advertised arrives again and lands here.
	 * Refreshing the tag below is what keeps it: the garbage collection
	 * at the end of receive_pim_bootstrap() runs once the whole message
	 * has been added and deletes only the entries whose tag is still the
	 * previous one, i.e. those this BSR has stopped advertising.
	 *
	 * A change of priority does not reach this branch at all.  Priority
	 * is the first sort key of the loop above, so the entry breaks out
	 * of it, the new priority is linked in as a new entry and the old
	 * one is collected with its stale tag.
	 */
	/* A static entry keeps the holdtime that makes it one.  Letting the
	 * advertisement overwrite it would leave the configured RP mortal:
	 * age_rp_grp_entries() below spares an entry only while its holdtime
	 * is 0xffff, so the next BSR to name the same RP for the same prefix
	 * would arrange for pimd.conf's RP to age out when that BSR died.
	 */
	if (entry_next->origin == RP_ORIGIN_BSR)
	    entry_next->holdtime = rp_holdtime;
	entry_next->fragment_tag = fragment_tag;

	return entry_next;
    }

    /* One more RP for this range, and the count of them is a byte both on
     * the wire and here; see PIM_MAX_RP_PER_RANGE. */
    if (mask_ptr->group_rp_number >= PIM_MAX_RP_PER_RANGE) {
	if (!rp_per_range_said) {
	    logit(LOG_WARNING, 0, "%s already has %u RPs, refusing %s: a Bootstrap counts them in a byte",
		  netname(group_addr, group_mask), mask_ptr->group_rp_number,
		  inet_fmt(rp_addr, s1, sizeof(s1)));
	    rp_per_range_said = TRUE;
	}

	if (mask_ptr->grp_rp_next == NULL)
	    delete_grp_mask(used_cand_rp_list, used_grp_mask_list,
			    group_addr, group_mask);

	return NULL;
    }

    cand_rp_ptr = add_cand_rp(used_cand_rp_list, rp_addr);
    if (cand_rp_ptr == NULL) {
	if (mask_ptr->grp_rp_next == NULL)
	    delete_grp_mask(used_cand_rp_list, used_grp_mask_list,
			    group_addr, group_mask);
	return NULL;
    }
    cand_rp_ptr->rpentry->adv_holdtime = rp_holdtime;

    /* Create and link the new entry */
    entry_new = calloc(1, sizeof(rp_grp_entry_t));
    if (!entry_new) {
	logit(LOG_ERR, 0, "Ran out of memory in add_rp_grp_entry()");
	return NULL;
    }

    entry_new->grp_rp_next = entry_next;
    entry_new->grp_rp_prev = entry_prev;
    if (entry_next)
	entry_next->grp_rp_prev = entry_new;
    if (entry_prev == NULL)
	mask_ptr->grp_rp_next = entry_new;
    else
	entry_prev->grp_rp_next = entry_new;

    /*
     * The rp_grp_entry chain is not ordered, so just plug
     * the new entry at the head.
     */
    entry_new->rp_grp_next = cand_rp_ptr->rp_grp_next;
    if (cand_rp_ptr->rp_grp_next)
	cand_rp_ptr->rp_grp_next->rp_grp_prev = entry_new;
    entry_new->rp_grp_prev = NULL;
    cand_rp_ptr->rp_grp_next = entry_new;

    entry_new->holdtime = rp_holdtime;
    entry_new->fragment_tag = fragment_tag;
    entry_new->priority = rp_priority;
    entry_new->group = mask_ptr;
    entry_new->rp = cand_rp_ptr;
    entry_new->grplink = NULL;

    /* If I am BSR candidate and rp_addr is NOT hacked SSM address, then log it */
    if (cand_bsr_flag && rp_addr != ntohl(0xa9fe0001)) {
	uint32_t mask;
	MASK_TO_MASKLEN(group_mask, mask);
	logit(LOG_INFO, 0, "New RP candidate %s for group %s/%d, priority %d",
	      inet_fmt(rp_addr, s1, sizeof(s1)), inet_fmt(group_addr, s2, sizeof(s2)), mask, rp_priority);
    }

    mask_ptr->group_rp_number++;

    /* A prefix that has just gained its first RP is now the longest match
     * for every group inside it, and those groups are still hanging off
     * the shorter prefixes that matched them before it existed.  The
     * segmented list holds no groups, and rp_grp_match() never reads it.
     */
    if (mask_ptr->group_rp_number == 1 && used_grp_mask_list == &grp_mask_list) {
	remap_covered_groups(mask_ptr);
	/* And the local members that had no RP to be joined towards */
	igmp_resync_leaves();
    }

    if (mask_ptr->grp_rp_next->priority == rp_priority) {
	/* The first entries are with the best priority. */
	/* Adding this rp_grp_entry may result in group_to_rp remapping */
	for (entry_next = mask_ptr->grp_rp_next; entry_next; entry_next = entry_next->grp_rp_next) {
	    if (entry_next->priority > old_highest_priority)
		break;

	    for (grpentry_ptr_prev = entry_next->grplink; grpentry_ptr_prev; ) {
		grpentry_ptr_next = grpentry_ptr_prev->rpnext;
		remap_grpentry(grpentry_ptr_prev);
		grpentry_ptr_prev = grpentry_ptr_next;
	    }
	}
    }

    update_bootstrap_timer();

    return entry_new;
}


/*
 * RFC 7761 sec. 4.7.1: "if the set of possible group-range-to-RP mappings
 * changes, each router will need to check whether any existing groups are
 * affected".  The groups a new prefix can take over are the ones inside it
 * that a shorter prefix covering it holds, so only their grplink chains are
 * walked, not every group this router has state for.
 */
static void remap_covered_groups(grp_mask_t *mask_ptr)
{
    uint32_t prefix = mask_ptr->group_addr & mask_ptr->group_mask;
    rp_grp_entry_t *entry_ptr;
    grpentry_t *grp_ptr, *grp_ptr_next;
    grp_mask_t *ptr;

    for (ptr = grp_mask_list; ptr; ptr = ptr->next) {
	if (ntohl(ptr->group_mask) >= ntohl(mask_ptr->group_mask))
	    continue;
	if ((prefix & ptr->group_mask) != (ptr->group_addr & ptr->group_mask))
	    continue;

	for (entry_ptr = ptr->grp_rp_next; entry_ptr; entry_ptr = entry_ptr->grp_rp_next) {
	    for (grp_ptr = entry_ptr->grplink; grp_ptr; grp_ptr = grp_ptr_next) {
		grp_ptr_next = grp_ptr->rpnext;

		if ((grp_ptr->group & mask_ptr->group_mask) == prefix)
		    remap_grpentry(grp_ptr);
	    }
	}
    }
}

void delete_rp_grp_entry(cand_rp_t **used_cand_rp_list, grp_mask_t **used_grp_mask_list, rp_grp_entry_t *entry)
{
    grpentry_t *ptr;
    grpentry_t *ptr_next;

    if (entry == NULL)
	return;
    entry->group->group_rp_number--;

    /* Free the rp_grp* and grp_rp* links */
    if (entry->rp_grp_prev)
	entry->rp_grp_prev->rp_grp_next = entry->rp_grp_next;
    else
	entry->rp->rp_grp_next = entry->rp_grp_next;
    if (entry->rp_grp_next)
	entry->rp_grp_next->rp_grp_prev = entry->rp_grp_prev;

    if (entry->grp_rp_prev)
	entry->grp_rp_prev->grp_rp_next = entry->grp_rp_next;
    else
	entry->group->grp_rp_next = entry->grp_rp_next;

    if (entry->grp_rp_next)
	entry->grp_rp_next->grp_rp_prev = entry->grp_rp_prev;

    /* Delete Cand-RP or Group-prefix if useless */
    if (entry->group->grp_rp_next == NULL)
	delete_grp_mask_entry(used_cand_rp_list, used_grp_mask_list, entry->group);

    if (entry->rp->rp_grp_next == NULL)
	delete_rp_entry(used_cand_rp_list, used_grp_mask_list, entry->rp);

    /* Remap all affected groups */
    for (ptr = entry->grplink; ptr; ptr = ptr_next) {
	ptr_next = ptr->rpnext;
	remap_grpentry(ptr);
    }

    free((char *)entry);

    update_bootstrap_timer();
}

/* TODO: XXX: the affected group entries will be partially
 * setup, because may have group routing entry, but NULL pointers to RP.
 * After the call to this function, must remap all group entries ASAP.
 */
void delete_rp_list(cand_rp_t  **used_cand_rp_list, grp_mask_t **used_grp_mask_list)
{
    cand_rp_t      *cand_ptr,  *cand_next;
    rp_grp_entry_t *entry_ptr, *entry_next;
    grp_mask_t     *mask_ptr, *mask_next;
    grpentry_t     *gentry_ptr, *gentry_ptr_next;

    for (cand_ptr = *used_cand_rp_list; cand_ptr; ) {
	cand_next = cand_ptr->next;

	/* Free the mrtentry (if any) for this RP */
	if (cand_ptr->rpentry->mrtlink) {
	    if (cand_ptr->rpentry->mrtlink->flags & MRTF_KERNEL_CACHE)
		delete_mrtentry_all_kernel_cache(cand_ptr->rpentry->mrtlink);
	    FREE_MRTENTRY(cand_ptr->rpentry->mrtlink);
	}
	free(cand_ptr->rpentry);

	/* Free the whole chain of entry for this RP */
	for (entry_ptr = cand_ptr->rp_grp_next; entry_ptr; entry_ptr = entry_next) {
	    entry_next = entry_ptr->rp_grp_next;

	    /* Clear the RP related invalid pointers for all group entries */
	    for (gentry_ptr = entry_ptr->grplink; gentry_ptr; gentry_ptr = gentry_ptr_next) {
		gentry_ptr_next = gentry_ptr->rpnext;
		gentry_ptr->rpnext = NULL;
		gentry_ptr->rpprev = NULL;
		gentry_ptr->active_rp_grp = NULL;
		gentry_ptr->rpaddr = INADDR_ANY_N;
	    }

	    free(entry_ptr);
	}

	free(cand_ptr);
	cand_ptr = cand_next;
    }
    *used_cand_rp_list = NULL;

    for (mask_ptr = *used_grp_mask_list; mask_ptr; mask_ptr = mask_next) {
	mask_next = mask_ptr->next;
	free(mask_ptr);
    }
    *used_grp_mask_list = NULL;
}


void delete_grp_mask(cand_rp_t **used_cand_rp_list, grp_mask_t **used_grp_mask_list, uint32_t group_addr, uint32_t group_mask)
{
    rp_grp_entry_t *entry, *entry_next;
    uint32_t prefix_h = ntohl(group_addr & group_mask);
    int keep = FALSE;
    grp_mask_t *ptr;

    for (ptr = *used_grp_mask_list; ptr; ptr = ptr->next) {
	if (ntohl(ptr->group_addr & ptr->group_mask) > prefix_h)
	    continue;

	if (ptr->group_addr == group_addr) {
	    if (ntohl(ptr->group_mask) > ntohl(group_mask))
		continue;
	    else if (ptr->group_mask == group_mask)
		break;
	    else
		return;   /* Not found */
	}
    }

    if (ptr == (grp_mask_t *)NULL)
	return;       /* Not found */

    /* A group prefix withdrawn by a Bootstrap -- RFC 5059 sec. 4.1's RP
     * count of zero -- takes the BSR's RPs with it and not pimd.conf's.
     * Where a static RP is on the prefix the entries are removed one by
     * one and the prefix itself stays, because the static entry is still
     * on it; sec. 4.7 has this router support both sources of a
     * group-to-RP mapping, and only one of them is the BSR's to retract.
     */
    for (entry = ptr->grp_rp_next; entry; entry = entry_next) {
	entry_next = entry->grp_rp_next;

	if (entry->origin != RP_ORIGIN_BSR)
	    keep = TRUE;
    }

    if (!keep) {
	delete_grp_mask_entry(used_cand_rp_list, used_grp_mask_list, ptr);
	return;
    }

    for (entry = ptr->grp_rp_next; entry; entry = entry_next) {
	entry_next = entry->grp_rp_next;

	if (entry->origin == RP_ORIGIN_BSR)
	    delete_rp_grp_entry(used_cand_rp_list, used_grp_mask_list, entry);
    }
}

static void delete_grp_mask_entry(cand_rp_t **used_cand_rp_list, grp_mask_t **used_grp_mask_list, grp_mask_t *grp_mask_delete)
{
    grpentry_t *grp_ptr, *grp_ptr_next;
    rp_grp_entry_t *entry_ptr;
    rp_grp_entry_t *entry_next;

    if (grp_mask_delete == NULL)
	return;

    /* Remove from the grp_mask_list first */
    if (grp_mask_delete->prev)
	grp_mask_delete->prev->next = grp_mask_delete->next;
    else
	*used_grp_mask_list = grp_mask_delete->next;

    if (grp_mask_delete->next)
	grp_mask_delete->next->prev = grp_mask_delete->prev;

    /* Remove all grp_rp entries for this grp_mask */
    for (entry_ptr = grp_mask_delete->grp_rp_next; entry_ptr; entry_ptr = entry_next) {
	entry_next = entry_ptr->grp_rp_next;

	/* Remap all related grpentry */
	for (grp_ptr = entry_ptr->grplink; grp_ptr; grp_ptr = grp_ptr_next) {
	    grp_ptr_next = grp_ptr->rpnext;
	    remap_grpentry(grp_ptr);
	}

	if (entry_ptr->rp_grp_prev != (rp_grp_entry_t *)NULL)
	    entry_ptr->rp_grp_prev->rp_grp_next = entry_ptr->rp_grp_next;
	else
	    entry_ptr->rp->rp_grp_next = entry_ptr->rp_grp_next;

	if (entry_ptr->rp_grp_next != NULL)
	    entry_ptr->rp_grp_next->rp_grp_prev = entry_ptr->rp_grp_prev;

	/* Delete the RP entry */
	if (entry_ptr->rp->rp_grp_next == NULL)
	    delete_rp_entry(used_cand_rp_list, used_grp_mask_list, entry_ptr->rp);

	free(entry_ptr);
    }

    if (used_grp_mask_list == &grp_mask_list && rp_set_entries > 0)
	rp_set_entries--;

    free(grp_mask_delete);
}

void delete_rp(cand_rp_t **used_cand_rp_list, grp_mask_t **used_grp_mask_list, uint32_t rp_addr)
{
    cand_rp_t *ptr;
    uint32_t rp_addr_h = ntohl(rp_addr);

    for (ptr = *used_cand_rp_list; ptr; ptr = ptr->next) {
	if (ntohl(ptr->rpentry->address) > rp_addr_h)
	    continue;

	if (ptr->rpentry->address == rp_addr)
	    break;
	else
	    return;   /* Not found */
    }

    if (!ptr)
	return;       /* Not found */

    delete_rp_entry(used_cand_rp_list, used_grp_mask_list, ptr);
}


static void delete_rp_entry(cand_rp_t **used_cand_rp_list, grp_mask_t **used_grp_mask_list, cand_rp_t *cand_rp_delete)
{
    rp_grp_entry_t *entry_ptr;
    rp_grp_entry_t *entry_next;
    grpentry_t *grp_ptr;
    grpentry_t *grp_ptr_next;

    if (cand_rp_delete == NULL)
	return;

    /* Remove from the cand-RP chain */
    if (cand_rp_delete->prev)
	cand_rp_delete->prev->next = cand_rp_delete->next;
    else
	*used_cand_rp_list = cand_rp_delete->next;

    if (cand_rp_delete->next)
	cand_rp_delete->next->prev = cand_rp_delete->prev;

    if (cand_rp_delete->rpentry->mrtlink) {
	if (cand_rp_delete->rpentry->mrtlink->flags & MRTF_KERNEL_CACHE)
	    delete_mrtentry_all_kernel_cache(cand_rp_delete->rpentry->mrtlink);

	FREE_MRTENTRY(cand_rp_delete->rpentry->mrtlink);
    }
    free ((char *)cand_rp_delete->rpentry);

    /* Remove all rp_grp entries for this RP */
    for (entry_ptr = cand_rp_delete->rp_grp_next; entry_ptr; entry_ptr = entry_next) {
	entry_next = entry_ptr->rp_grp_next;
	entry_ptr->group->group_rp_number--;

	/* First take care of the grp_rp chain */
	if (entry_ptr->grp_rp_prev)
	    entry_ptr->grp_rp_prev->grp_rp_next = entry_ptr->grp_rp_next;
	else
	    entry_ptr->group->grp_rp_next = entry_ptr->grp_rp_next;

	if (entry_ptr->grp_rp_next)
	    entry_ptr->grp_rp_next->grp_rp_prev = entry_ptr->grp_rp_prev;

	if (entry_ptr->grp_rp_next == NULL)
	    delete_grp_mask_entry(used_cand_rp_list, used_grp_mask_list, entry_ptr->group);

	/* Remap the related groups */
	for (grp_ptr = entry_ptr->grplink; grp_ptr; grp_ptr = grp_ptr_next) {
	    grp_ptr_next = grp_ptr->rpnext;
	    remap_grpentry(grp_ptr);
	}

	free(entry_ptr);
    }

    free((char *)cand_rp_delete);
}


/*
 * Rehash the RP for the group.
 * XXX: currently, every time when remap_grpentry() is called, there has
 * being a good reason to change the RP, so for performancy reasons
 * no check is performed whether the RP will be really different one.
 */
int remap_grpentry(grpentry_t *grpentry_ptr)
{
    rpentry_t *rpentry_ptr;
    rp_grp_entry_t *entry_ptr;
    mrtentry_t *grp_route;
    mrtentry_t *mrtentry_ptr;

    if (grpentry_ptr == NULL)
	return FALSE;

    /* Remove from the list of all groups matching to the same RP */
    if (grpentry_ptr->rpprev) {
	grpentry_ptr->rpprev->rpnext = grpentry_ptr->rpnext;
    } else {
	if (grpentry_ptr->active_rp_grp)
	    grpentry_ptr->active_rp_grp->grplink = grpentry_ptr->rpnext;
    }

    if (grpentry_ptr->rpnext)
	grpentry_ptr->rpnext->rpprev = grpentry_ptr->rpprev;

    entry_ptr = rp_grp_match(grpentry_ptr->group);
    if (entry_ptr == NULL) {
	/* If cannot remap, delete the group */
	delete_grpentry(grpentry_ptr);
	return FALSE;
    }
    rpentry_ptr = entry_ptr->rp->rpentry;

    /* Add to the new chain of all groups mapping to the same RP */
    grpentry_ptr->rpaddr  = rpentry_ptr->address;
    grpentry_ptr->active_rp_grp = entry_ptr;
    grpentry_ptr->rpnext = entry_ptr->grplink;
    if (grpentry_ptr->rpnext)
	grpentry_ptr->rpnext->rpprev = grpentry_ptr;
    grpentry_ptr->rpprev = NULL;
    entry_ptr->grplink = grpentry_ptr;

    grp_route = grpentry_ptr->grp_route;
    if (grp_route) {
	grp_route->upstream   = rpentry_ptr->upstream;
	grp_route->metric     = rpentry_ptr->metric;
	grp_route->preference = rpentry_ptr->preference;
	change_interfaces(grp_route, rpentry_ptr->incoming,
			  grp_route->joined_oifs,
			  grp_route->pruned_oifs,
			  grp_route->leaves,
			  grp_route->asserted_oifs, MFC_UPDATE_FORCE);
    }

    for (mrtentry_ptr = grpentry_ptr->mrtlink; mrtentry_ptr; mrtentry_ptr = mrtentry_ptr->grpnext) {
	int resumed = FALSE;

	/* RFC 7761 sec. 4.4.1, the "RP changed" column of the Register
	 * state machine: a DR that stopped encapsulating has to start
	 * again, now toward the new RP, so cancel the suppression and put
	 * the register vif back among the outgoing interfaces.  Without
	 * this the source stays unregistered until the timer of an RP that
	 * is no longer ours runs out, up to 90 seconds during which nobody
	 * joining the new shared tree hears anything.
	 */
	if (PIMD_VIFM_ISSET(PIMREG_VIF, mrtentry_ptr->pruned_oifs)) {
	    RESET_TIMER(mrtentry_ptr->rs_timer);
	    PIMD_VIFM_CLR(PIMREG_VIF, mrtentry_ptr->pruned_oifs);
	    resumed = TRUE;
	}

	if (!(mrtentry_ptr->flags & MRTF_RP)) {
	    if (resumed)
		change_interfaces(mrtentry_ptr, mrtentry_ptr->incoming,
				  mrtentry_ptr->joined_oifs,
				  mrtentry_ptr->pruned_oifs,
				  mrtentry_ptr->leaves,
				  mrtentry_ptr->asserted_oifs, MFC_UPDATE_FORCE);
	    continue;
	}

	mrtentry_ptr->upstream = rpentry_ptr->upstream;
	mrtentry_ptr->metric   = rpentry_ptr->metric;
	mrtentry_ptr->preference = rpentry_ptr->preference;
	change_interfaces(mrtentry_ptr, rpentry_ptr->incoming,
			  mrtentry_ptr->joined_oifs,
			  mrtentry_ptr->pruned_oifs,
			  mrtentry_ptr->leaves,
			  mrtentry_ptr->asserted_oifs, MFC_UPDATE_FORCE);
    }

    return TRUE;
}


/*
 * RFC 7761 sec. 4.4.2: "I_am_RP(G) is true if the group-to-RP mapping
 * indicates that this router is the RP for the group."
 *
 * The mapping, not the candidacy.  A router is the RP for a group
 * whenever the RP that group maps to is one of its own addresses, no
 * matter whether it got there by winning a Cand-RP election or by a
 * static rp-address line in pimd.conf.
 *
 * my_cand_rp_address cannot answer that question and must not be used
 * for it: it is only assigned while parsing cand_rp (config.c), so on a
 * statically configured RP it stays 0.0.0.0 and every test written
 * against it is false on the very router that is the RP.  It is also a
 * single address, while I_am_RP() is a function of the group -- two
 * rp-address lines covering different ranges cannot both be represented
 * in one scalar.  Keep my_cand_rp_address for what it actually means:
 * the address this router advertises in its own Cand-RP-Adv.
 */
int i_am_rp(uint32_t rp_addr)
{
    if (rp_addr == INADDR_ANY_N)
	return FALSE;

    return local_address(rp_addr) != NO_VIF;
}


rpentry_t *rp_match(uint32_t group)
{
    rp_grp_entry_t *ptr;

    ptr = rp_grp_match(group);
    if (ptr)
	return ptr->rp->rpentry;

    return NULL;
}

/*
 * RFC4601 4.7.1 Group-to-RP Mapping:
 * The algorithm for performing the group-to-RP mapping is as follows:
 *
 * 1. Perform longest match on group-range to obtain a list of RPs.
 * 2. From this list of matching RPs, find the one with highest
 *    priority. Eliminate any RPs from the list that have lower
 *    priorities.
 * 3. If only one RP remains in the list, use that RP.
 * 4. If multiple RPs are in the list, use the PIM hash function to
 *    choose one.
 */
rp_grp_entry_t *rp_grp_match(uint32_t group)
{
    grp_mask_t *mask_ptr;
    rp_grp_entry_t *entry_ptr;
    rp_grp_entry_t *best_entry = NULL;
    uint8_t best_priority       = ~0; /* Smaller is better */
    uint32_t best_hash_value    = 0;  /* Bigger is better */
    uint32_t best_address_h     = 0;  /* Bigger is better */
    uint32_t curr_hash_value    = 0;
    uint32_t curr_address_h     = 0;
    uint32_t group_h            = ntohl(group);
    uint32_t curr_hash_mask_h   = 0;
    uint32_t curr_group_mask    = 0; /* longest match */

    if (grp_mask_list == NULL)
	return NULL;

    for (mask_ptr = grp_mask_list; mask_ptr; mask_ptr = mask_ptr->next) {
	/* Search the grp_mask (group-prefix) list */
	if ((group_h & ntohl(mask_ptr->group_mask))
	    != ntohl(mask_ptr->group_mask & mask_ptr->group_addr))
	    continue;

	if (curr_group_mask > mask_ptr->group_mask)
	    continue;

	/* reset best priority/address/hash value while mask get longer */
	if (curr_group_mask < mask_ptr->group_mask)
	{
	    best_priority = ~0;
	    best_address_h = 0;
	    best_hash_value = 0;
	}

	curr_hash_mask_h = ntohl(mask_ptr->hash_mask);
	for (entry_ptr = mask_ptr->grp_rp_next; entry_ptr; entry_ptr = entry_ptr->grp_rp_next) {
	    if (best_priority < entry_ptr->priority)
		break;

	    curr_address_h = ntohl(entry_ptr->rp->rpentry->address);
	    curr_hash_value = RP_HASH_VALUE(group_h, curr_hash_mask_h, curr_address_h);

	    if (best_priority == entry_ptr->priority) {
		/* Compare the hash_value and then the addresses */
		if (curr_hash_value < best_hash_value)
		    continue;

		if (curr_hash_value == best_hash_value) {
		    if (curr_address_h < best_address_h)
			continue;
		}
	    }

	    /* The current entry in the loop is preferred */
	    best_entry = entry_ptr;
	    best_priority = best_entry->priority;
	    best_address_h = curr_address_h;
	    best_hash_value = curr_hash_value;
	    curr_group_mask = mask_ptr->group_mask;
	}
    }

    /*
     * An Auto-RP deny for this group, from a prefix at least as long as
     * whatever was found above, is final: the draft has one longest match
     * decide, and a negative match means the group has no RP even where a
     * shorter positive prefix covers it (doc/pim-autorp-spec01.txt sec. 6,
     * rule 1).  pimd.conf's own RP is the exception -- a configured
     * mapping outlives every domain-wide mechanism, which is also what
     * sec. 8 needs for the two Auto-RP groups themselves.
     */
    if (best_entry && best_entry->origin != RP_ORIGIN_STATIC && autorp_denied(group))
	return NULL;

    return best_entry;
}


rpentry_t *rp_find(uint32_t rp_address)
{
    cand_rp_t *cand_rp_ptr;
    uint32_t address_h = ntohl(rp_address);

    for(cand_rp_ptr = cand_rp_list; cand_rp_ptr != NULL; cand_rp_ptr = cand_rp_ptr->next) {
	if (ntohl(cand_rp_ptr->rpentry->address) > address_h)
	    continue;

	if (cand_rp_ptr->rpentry->address == rp_address)
	    return cand_rp_ptr->rpentry;

	return NULL;
    }

    return NULL;
}


/*
 * Create a bootstrap message in "send_buff" and returns the data size
 * (excluding the IP header and the PIM header) Can be used both by the
 * Bootstrap router to multicast the RP-set or by the DR to unicast it to
 * a new neighbor. It DOES NOT change any timers.
 */
int create_pim_bootstrap_message(char *send_buff, size_t buflen)
{
    const size_t hdrs = sizeof(struct ip) + sizeof(pim_header_t);
    struct pim_writer w;
    uint8_t *start;
    grp_mask_t *mask_ptr;
    rp_grp_entry_t *entry_ptr;
    uint8_t masklen;
    unsigned rps, written;
    uint16_t holdtime;

    if (curr_bsr_address == INADDR_ANY_N)
	return 0;

    /* Everything below is written through w, which has the end of the
     * buffer and writes nothing past it, see src/pim_encode.c. */
    start = (uint8_t *)send_buff + hdrs;
    pim_writer_init(&w, start, buflen > hdrs ? buflen - hdrs : 0);

    /* The fragment tag, hash mask length, priority and BSR address, before
     * any of the set: a buffer too small even for those is a caller's
     * mistake rather than a state this can be in, and saying so beats
     * writing them. */
    if (!pim_writer_room(&w, 4 + PIM_ENCODE_UNI_ADDR_LEN)) {
	logit(LOG_WARNING, 0, "Bootstrap send buffer of %zu bytes is too small for its own header",
	      buflen);
	return 0;
    }
    if (curr_bsr_address == my_bsr_address)
	curr_bsr_fragment_tag++;

    MASK_TO_MASKLEN(curr_bsr_hash_mask, masklen);
    pim_encode_bsr_hdr(&w, curr_bsr_fragment_tag, masklen, curr_bsr_priority, curr_bsr_address);

    /* TODO: XXX: No fragmentation support (yet), so an RP set larger than
     * one message holds is cut short rather than carried in fragments with
     * a shared tag (RFC 5059 sec. 3.2).  What must not happen is writing
     * past the buffer, which is what this did: the set is a stranger's to
     * grow -- see add_grp_mask() -- and 40 Candidate-RP Advertisements of
     * 255 ranges each walked a 128K send buffer off its end, measured with
     * AddressSanitizer.  rp-set-limit bounds the set itself; the writer
     * bounds the message whatever the set is, and the room asked for below
     * keeps what is cut a whole range rather than half of one.
     */
    for (mask_ptr = grp_mask_list; mask_ptr; mask_ptr = mask_ptr->next) {
	if (IN_PIM_SSM_RANGE(mask_ptr->group_addr)) {
	    continue;  /* Do not advertise internal virtual RP for SSM groups */
	}

	/* How many RPs this range actually has, counted from the list this
	 * is about to walk rather than taken from group_rp_number: the
	 * length of the message and the count byte in it both have to agree
	 * with what gets written, and a byte that has drifted -- or wrapped,
	 * which it could before PIM_MAX_RP_PER_RANGE -- would leave the
	 * room asked for below too small and the count on the wire wrong.
	 */
	rps = 0;
	for (entry_ptr = mask_ptr->grp_rp_next; entry_ptr; entry_ptr = entry_ptr->grp_rp_next) {
	    if (rps == PIM_MAX_RP_PER_RANGE)
		break;		/* The count on the wire is a byte */
	    rps++;
	}

	/* The range's own record, and one per RP under it */
	if (!pim_writer_room(&w, PIM_BSR_GRP_SET_LEN + (size_t)rps * PIM_BSR_RP_LEN)) {
	    if (!bootstrap_truncated_said) {
		logit(LOG_WARNING, 0, "RP set does not fit in one Bootstrap message,"
		      " %zu bytes in and %s onwards left out", hdrs + pim_writer_used(&w, start),
		      netname(mask_ptr->group_addr, mask_ptr->group_mask));
		bootstrap_truncated_said = TRUE;
	    }
	    break;
	}

	MASK_TO_MASKLEN(mask_ptr->group_mask, masklen);
	/* TODO: if frag. */
	pim_encode_bsr_group(&w, mask_ptr->group_addr, masklen, (uint8_t)rps, (uint8_t)rps);

	/* Exactly the records the count above promises, so that the message
	 * says what it holds however the list changes underneath. */
	for (entry_ptr = mask_ptr->grp_rp_next, written = 0;
	     entry_ptr && written < rps;
	     entry_ptr = entry_ptr->grp_rp_next, written++) {
	    holdtime = entry_ptr->rp->rpentry->adv_holdtime;
	    /* Is holdtime in MUST BE interval? (RFC5059 section 3.3) */
	    if (holdtime != 0 && holdtime <= my_bsr_adv_period)
		holdtime = recommended_rp_holdtime;
	    pim_encode_bsr_rp(&w, entry_ptr->rp->rpentry->address, holdtime, entry_ptr->priority);
	}
    }

    /* Not reachable while the room asked for above is right, and a message
     * with a field missing is not one to send if it ever is not. */
    if (w.full) {
	logit(LOG_WARNING, 0, "Bootstrap message overran its own room, not sent");
	return 0;
    }

    return (int)pim_writer_used(&w, start);
}


/*
 * Check if the addr is the RP for the group corresponding to mrt.
 * Return TRUE or FALSE.
 */
int check_mrtentry_rp(mrtentry_t *mrt, uint32_t addr)
{
    rp_grp_entry_t *ptr;

    if (!mrt)
	return FALSE;

    if (addr == INADDR_ANY_N)
	return FALSE;

    ptr = mrt->group->active_rp_grp;
    if (!ptr)
	return FALSE;

    if (mrt->group->rpaddr == addr)
	return TRUE;

    return FALSE;
}

/*
 * TODO: timeout the RP-group mapping entries during the scan of the
 * whole routing table?
 */
void age_misc(void)
{
    rp_grp_entry_t *rp;
    rp_grp_entry_t *rp_next;
    grp_mask_t     *grp;
    grp_mask_t     *grp_next;

    /* Timeout the Cand-RP-set entries */
    for (grp = grp_mask_list; grp; grp = grp_next) {
	/* If we timeout an entry, the grp entry might be removed */
	grp_next = grp->next;
	for (rp = grp->grp_rp_next; rp; rp = rp_next) {
	    rp_next = rp->grp_rp_next;

	    if (rp->holdtime < 60000) {
		IF_TIMEOUT(rp->holdtime) {
		    if (rp->group!=NULL) {
			logit(LOG_INFO, 0, "Delete RP group entry for group %s (holdtime timeout)",
			      inet_fmt(rp->group->group_addr, s2, sizeof(s2)));
		    }
		    delete_rp_grp_entry(&cand_rp_list, &grp_mask_list, rp);
		}
	    }
	}
    }

    /* Cand-RP-Adv timer */
    if (cand_rp_flag == TRUE) {
	IF_TIMEOUT(pim_cand_rp_adv_timer) {
	    send_pim_cand_rp_adv();
	    SET_TIMER(pim_cand_rp_adv_timer, my_cand_rp_adv_period);
	}
    }

    /* bootstrap-timer */
    IF_TIMEOUT(pim_bootstrap_timer) {
	if (cand_bsr_flag == FALSE) {
	    /* If I am not Cand-BSR, start accepting Bootstrap messages from anyone.
	     * XXX: Even if the BSR has timeout, the existing Cand-RP-Set is kept. */
	    SET_TIMER(pim_bootstrap_timer, my_bsr_timeout);
	    curr_bsr_fragment_tag = 0;
	    curr_bsr_priority     = 0;		  /* Lowest priority */
	    curr_bsr_address      = INADDR_ANY_N; /* Lowest priority */
	    MASKLEN_TO_MASK(RP_DEFAULT_IPV4_HASHMASKLEN, curr_bsr_hash_mask);
	} else {
	    /* I am Cand-BSR, so set the current BSR to me */
	    if (curr_bsr_address == my_bsr_address) {
		SET_TIMER(pim_bootstrap_timer, my_bsr_adv_period);
		send_pim_bootstrap();
	    } else {
		/* Short delay before becoming the BSR and start sending
		 * of the Cand-RP set (to reduce the transient control
		 * overhead). */
		SET_TIMER(pim_bootstrap_timer, bootstrap_initial_delay());
		curr_bsr_fragment_tag = RANDOM();
		curr_bsr_priority     = my_bsr_priority;
		curr_bsr_address      = my_bsr_address;
		curr_bsr_hash_mask    = my_bsr_hash_mask;
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
