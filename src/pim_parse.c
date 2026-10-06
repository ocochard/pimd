/*
 * pim_parse.c - the bytes of PIM messages, and nothing else
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
 * The decoding halves of the receive_pim_*() of src/pim_proto.c, the
 * formats of RFC 7761 sec. 4.9.  This file includes libc and pimd.h and
 * nothing else of the daemon's, deliberately: test/cbmc/pim.c compiles it
 * alone and proves it reads nothing outside the buffer, and a dependency on
 * the daemon's globals would make that proof a model of the daemon instead.
 *
 * Each decoder is a loop-free step and a loop over it, because that is the
 * shape a bounded model checker can afford: a step is proven for a message
 * of any length, and the loop only for a few iterations of it.  Lengths
 * read off the wire bound nothing; every step asks the buffer first.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>

#include "pimd.h"

/* A position in a message, and how much of it is left */
struct pim_cursor {
    const uint8_t *p;
    size_t left;
};

/* What pim_parse_hello_opt() says besides the verdicts of pimd.h */
#define PIM_HELLO_OPT		-1	/* one option read			*/
#define PIM_HELLO_END		-2	/* too little left for another one	*/

/*
 * One Hello option, RFC 7761 sec. 4.9.2.  An option that does not fit in
 * what is left of the message is refused before its value is read, not
 * after; a known option of a length it cannot have refuses the message;
 * an unknown one is stepped over, sec. 4.9.2 "MUST be ignored".  An
 * Address List is only recorded here, the last one heard standing, and
 * checked once the walk is done: the check is a loop of its own, and
 * putting it here would put a loop in the step.
 */
static int pim_parse_hello_opt(struct pim_cursor *c, pim_hello_opts_t *opts)
{
    const uint8_t *data = c->p;
    uint16_t opt_type, opt_len;
    size_t rec_len;

    if (c->left < sizeof(pim_hello_t))
	return PIM_HELLO_END;

    GET_HOSTSHORT(opt_type, data);
    GET_HOSTSHORT(opt_len,  data);

    rec_len = sizeof(pim_hello_t) + opt_len;
    if (c->left < rec_len) {
	opts->bad_type = opt_type;
	opts->bad_len  = opt_len;
	return PIM_HELLO_SHORT;
    }

    switch (opt_type) {
	case PIM_HELLO_HOLDTIME:
	    if (opt_len != PIM_HELLO_HOLDTIME_LEN)
		goto badlen;

	    opts->holdtime_present = 1;
	    GET_HOSTSHORT(opts->holdtime, data);
	    break;

	case PIM_HELLO_DR_PRIO:
	    if (opt_len != PIM_HELLO_DR_PRIO_LEN)
		goto badlen;

	    opts->dr_prio_present = 1;
	    GET_HOSTLONG(opts->dr_prio, data);
	    break;

	case PIM_HELLO_GENID:
	    if (opt_len != PIM_HELLO_GENID_LEN)
		goto badlen;

	    GET_HOSTLONG(opts->genid, data);
	    break;

	case PIM_HELLO_LAN_PRUNE_DELAY: {
	    uint16_t delay;

	    if (opt_len != PIM_HELLO_LAN_PRUNE_DELAY_LEN)
		goto badlen;

	    GET_HOSTSHORT(delay, data);
	    opts->lan_delay_present = 1;
	    opts->tracking_support  = (delay & PIM_LAN_PRUNE_DELAY_T_BIT) ? 1 : 0;
	    opts->propagation_delay = delay & ~PIM_LAN_PRUNE_DELAY_T_BIT;
	    GET_HOSTSHORT(opts->override_interval, data);
	    break;
	}

	case PIM_HELLO_ADDR_LIST:
	    opts->addr_list     = data;
	    opts->addr_list_len = opt_len;
	    break;

	default:
	    break;		/* Ignore any unknown options */
    }

    c->p    += rec_len;
    c->left -= rec_len;

    return PIM_HELLO_OPT;

  badlen:
    opts->bad_type = opt_type;
    opts->bad_len  = opt_len;
    return PIM_HELLO_BADOPTLEN;
}

/*
 * RFC 7761 sec. 4.3.4: every address in the option is of one family.  A
 * list that is not all IPv4, or is not a whole number of IPv4 entries, is
 * not one this router can map a next hop through, and is read as no list
 * at all -- which takes the neighbor's secondaries away rather than keeping
 * ones it no longer advertises.  The Hello itself stands: the option being
 * there is no reason to lose the neighbor.
 */
static void pim_parse_hello_addrs(pim_hello_opts_t *opts)
{
    const uint8_t *data = opts->addr_list;
    uint16_t i;

    if (opts->addr_list_len % PIM_ENCODE_UNI_ADDR_LEN) {
	opts->addr_list_refused = PIM_HELLO_ADDRS_LEN;
	goto refused;
    }

    for (i = 0; i < opts->addr_list_len; i += PIM_ENCODE_UNI_ADDR_LEN) {
	uint8_t family = data[i], etype = data[i + 1];

	if (family != ADDRF_IPv4 || etype != ADDRT_IPv4) {
	    opts->addr_list_refused = PIM_HELLO_ADDRS_FAMILY;
	    opts->bad_family        = family;
	    opts->bad_etype         = etype;
	    goto refused;
	}
    }

    return;

  refused:
    opts->bad_len       = opts->addr_list_len;
    opts->addr_list     = NULL;
    opts->addr_list_len = 0;
}

/*
 * A whole Hello, PIM header included.  RFC 7761 sec. 4.9.2: unknown options
 * "MUST be ignored and MUST NOT prevent a neighbor relationship from being
 * formed", and neither must a Hello that carries no options at all.  Only
 * an option we do understand, arriving with a length it cannot have, or
 * one that runs past the message, fails it; bytes too few to be an option
 * after the last one are ignored.
 */
int pim_parse_hello(const void *msg, size_t len, pim_hello_opts_t *opts)
{
    struct pim_cursor c;
    int rc;

    memset(opts, 0, sizeof(*opts));

    if (len < sizeof(pim_header_t))
	return PIM_HELLO_SHORT;

    c.p    = (const uint8_t *)msg + sizeof(pim_header_t);
    c.left = len - sizeof(pim_header_t);

    while ((rc = pim_parse_hello_opt(&c, opts)) == PIM_HELLO_OPT)
	;

    if (rc != PIM_HELLO_END)
	return rc;

    if (opts->addr_list)
	pim_parse_hello_addrs(opts);

    return PIM_HELLO_OK;
}

/*
 * Entry i of a Hello's Address List, in network order.  The caller asks
 * only for i < addr_list_len / PIM_ENCODE_UNI_ADDR_LEN, which
 * pim_parse_hello() has checked is inside the message and IPv4 throughout.
 */
uint32_t pim_hello_addr(const pim_hello_opts_t *opts, uint16_t i)
{
    const uint8_t *data = opts->addr_list + (size_t)i * PIM_ENCODE_UNI_ADDR_LEN;
    pim_encod_uni_addr_t eua;

    GET_EUADDR(&eua, data);

    return eua.unicast_addr;
}

/*
 * The header of a Join/Prune: the upstream neighbor, the group count and
 * the holdtime, sec. 4.9.5.  Sec. 4.9.5 processes the addresses of the
 * upstream neighbor's family and ignores the rest; where that address is
 * not one we can read, the whole message is a message for somebody else.
 */
static int pim_parse_jp_hdr(struct pim_cursor *c, const void *msg, size_t len, pim_jp_t *jp)
{
    pim_encod_uni_addr_t eua;
    const uint8_t *data;

    if (len < PIM_JOIN_PRUNE_MINLEN)
	return PIM_JP_SHORT;

    data = (const uint8_t *)msg + sizeof(pim_header_t);
    GET_EUADDR(&eua, data);
    data++;			/* reserved */
    GET_BYTE(jp->num_groups, data);
    GET_HOSTSHORT(jp->holdtime, data);

    if (eua.addr_family != ADDRF_IPv4 || eua.encod_type != ADDRT_IPv4) {
	jp->bad_family = eua.addr_family;
	jp->bad_etype  = eua.encod_type;
	return PIM_JP_UPSTREAM;
    }

    if (jp->num_groups == 0)
	return PIM_JP_NOGROUPS;

    jp->upstream = eua.unicast_addr;
    jp->groups   = data;
    c->p         = data;
    c->left      = len - PIM_JOIN_PRUNE_MINLEN;

    return PIM_JP_OK;
}

/*
 * One group set: the Encoded-Group and the two counts, and the sources
 * behind it in *srcs, whose bytes are inside the message once this says
 * OK.  The Mask Len of the group is checked here rather than where it is
 * converted: MASKLEN_TO_MASK() shifts by 32 - masklen and the byte is the
 * sender's to choose.  Bounded and not required to be SINGLE_GRP_MSKLEN,
 * which sec. 4.9.5.1 asks of a group-specific set: the (*,*,RP) set RFC
 * 7761 Appendix A removed carries STAR_STAR_RP_MSKLEN, and the caller still
 * recognises one in order to skip it.  The family and encoding type are
 * checked because every set is IPv4-sized here: a record that says it is
 * something else is not merely an address we cannot use, it is a record
 * whose fields are not where we look.
 */
static int pim_parse_jp_set(struct pim_cursor *c, pim_jp_t *jp, struct pim_cursor *srcs)
{
    const uint8_t *p = c->p;
    uint16_t num_j, num_p;
    size_t srclen;

    if (c->left < PIM_JP_GRP_SET_LEN)
	return PIM_JP_TRUNCATED;

    if (p[PIM_ENCODE_MSKLEN_OFF] > PIM_MAX_MSKLEN) {
	jp->bad_masklen = p[PIM_ENCODE_MSKLEN_OFF];
	return PIM_JP_GRP_MASKLEN;
    }

    if (p[PIM_ENCODE_FAMILY_OFF] != ADDRF_IPv4 || p[PIM_ENCODE_ETYPE_OFF] != ADDRT_IPv4) {
	jp->bad_family = p[PIM_ENCODE_FAMILY_OFF];
	jp->bad_etype  = p[PIM_ENCODE_ETYPE_OFF];
	return PIM_JP_GRP_FAMILY;
    }

    p += PIM_ENCODE_GRP_ADDR_LEN;
    GET_HOSTSHORT(num_j, p);
    GET_HOSTSHORT(num_p, p);
    srclen = ((size_t)num_j + num_p) * PIM_ENCODE_SRC_ADDR_LEN;
    if (c->left - PIM_JP_GRP_SET_LEN < srclen)
	return PIM_JP_TRUNCATED;

    srcs->p    = p;
    srcs->left = srclen;
    c->p      += PIM_JP_GRP_SET_LEN + srclen;
    c->left   -= PIM_JP_GRP_SET_LEN + srclen;

    return PIM_JP_OK;
}

/*
 * The Encoded-Sources of one set, every one IPv4, and with the Mask Len
 * sec. 4.9.1 pins to the full address length: "The mask length MUST be
 * equal to the mask length in bits for the given Address Family and
 * Encoding Type (32 for IPv4 native) ... A router SHOULD ignore any
 * messages received with any other mask length."
 */
static int pim_parse_jp_srcs(const struct pim_cursor *srcs, pim_jp_t *jp)
{
    const uint8_t *p;
    size_t off;

    for (off = 0; off < srcs->left; off += PIM_ENCODE_SRC_ADDR_LEN) {
	p = srcs->p + off;
	if (p[PIM_ENCODE_FAMILY_OFF] != ADDRF_IPv4 || p[PIM_ENCODE_ETYPE_OFF] != ADDRT_IPv4) {
	    jp->bad_family = p[PIM_ENCODE_FAMILY_OFF];
	    jp->bad_etype  = p[PIM_ENCODE_ETYPE_OFF];
	    return PIM_JP_SRC_FAMILY;
	}

	if (p[PIM_ENCODE_MSKLEN_OFF] != SINGLE_SRC_MSKLEN) {
	    jp->bad_masklen = p[PIM_ENCODE_MSKLEN_OFF];
	    return PIM_JP_SRC_MASKLEN;
	}
    }

    return PIM_JP_OK;
}

/*
 * A whole Join/Prune, PIM header included, refused at the first thing in
 * it that is not inside the message or not readable, the group count off
 * the wire bounding nothing.
 */
int pim_parse_jp(const void *msg, size_t len, pim_jp_t *jp)
{
    struct pim_cursor c, srcs;
    unsigned n;
    int rc;

    memset(jp, 0, sizeof(*jp));

    rc = pim_parse_jp_hdr(&c, msg, len, jp);
    if (rc != PIM_JP_OK)
	return rc;

    for (n = jp->num_groups; n > 0; n--) {
	rc = pim_parse_jp_set(&c, jp, &srcs);
	if (rc == PIM_JP_OK)
	    rc = pim_parse_jp_srcs(&srcs, jp);
	if (rc != PIM_JP_OK)
	    return rc;
    }

    return PIM_JP_OK;
}

/*
 * The group set at set, and the one after it.  Only for a message
 * pim_parse_jp() said OK to, and no further than its num_groups sets.
 */
const uint8_t *pim_jp_group(const uint8_t *set, pim_jp_grp_t *grp)
{
    pim_encod_grp_addr_t ega;
    const uint8_t *p = set;

    GET_EGADDR(&ega, p);
    GET_HOSTSHORT(grp->num_j, p);
    GET_HOSTSHORT(grp->num_p, p);
    grp->group   = ega.mcast_addr;
    grp->masklen = ega.masklen;
    grp->srcs    = p;

    return p + ((size_t)grp->num_j + grp->num_p) * PIM_ENCODE_SRC_ADDR_LEN;
}

/*
 * Entry i of a group set, the joined ones first: i < num_j + num_p, which
 * pim_parse_jp() has checked is inside the message.
 */
void pim_jp_source(const pim_jp_grp_t *grp, uint32_t i, pim_jp_src_t *src)
{
    const uint8_t *p = grp->srcs + (size_t)i * PIM_ENCODE_SRC_ADDR_LEN;
    pim_encod_src_addr_t esa;

    GET_ESADDR(&esa, p);
    src->addr    = esa.src_addr;
    src->flags   = esa.flags;
    src->masklen = esa.masklen;
}

/*
 * The header of a Bootstrap, RFC 5059 sec. 3.1: fragment tag, hash mask
 * length, BSR priority and the BSR's address.  The Hash Mask Len decides
 * the group-to-RP mapping for the whole domain, and it is a byte off the
 * wire, refused here before the caller commits or forwards anything.
 */
static int pim_parse_bsr_hdr(struct pim_cursor *c, const void *msg, size_t len, pim_bsr_t *bsr)
{
    pim_encod_uni_addr_t eua;
    const uint8_t *data;

    if (len < PIM_BOOTSTRAP_MINLEN)
	return PIM_BSR_SHORT;

    bsr->no_forward = ((const pim_header_t *)msg)->pim_reserved & PIM_BOOTSTRAP_NO_FORWARD;

    data = (const uint8_t *)msg + sizeof(pim_header_t);
    GET_HOSTSHORT(bsr->frag_tag, data);
    GET_BYTE(bsr->hash_masklen, data);
    GET_BYTE(bsr->priority, data);
    GET_EUADDR(&eua, data);
    bsr->bsr = eua.unicast_addr;

    if (eua.addr_family != ADDRF_IPv4 || eua.encod_type != ADDRT_IPv4) {
	bsr->bad_family = eua.addr_family;
	bsr->bad_etype  = eua.encod_type;
	return PIM_BSR_FAMILY;
    }

    if (bsr->hash_masklen > PIM_MAX_MSKLEN)
	return PIM_BSR_HASH_MASKLEN;

    bsr->sets = data;
    c->p      = data;
    c->left   = len - PIM_BOOTSTRAP_MINLEN;

    return PIM_BSR_OK;
}

/*
 * One group set of a Bootstrap, and its RP records, stepped over.  The
 * mask length and the family cost the message, because where the next set
 * begins depends on reading this one at the IPv4 strides; the B and Z bits
 * cost only the range and are the caller's, see group_range_ok().  Called
 * only with a set head and one RP record left, which is the condition of
 * the loop in pim_parse_bsr().
 */
static int pim_parse_bsr_set(struct pim_cursor *c, pim_bsr_t *bsr)
{
    const uint8_t *p = c->p;
    size_t rplen;

    if (p[PIM_ENCODE_MSKLEN_OFF] > PIM_MAX_MSKLEN) {
	bsr->bad_masklen = p[PIM_ENCODE_MSKLEN_OFF];
	return PIM_BSR_GRP_MASKLEN;
    }

    if (p[PIM_ENCODE_FAMILY_OFF] != ADDRF_IPv4 || p[PIM_ENCODE_ETYPE_OFF] != ADDRT_IPv4) {
	bsr->bad_family = p[PIM_ENCODE_FAMILY_OFF];
	bsr->bad_etype  = p[PIM_ENCODE_ETYPE_OFF];
	return PIM_BSR_GRP_FAMILY;
    }

    /* RP count, fragment RP count, reserved, then that many records */
    rplen = (size_t)p[PIM_ENCODE_GRP_ADDR_LEN + 1] * PIM_BSR_RP_LEN;
    if (c->left - PIM_BSR_GRP_SET_LEN < rplen) {
	bsr->bad_count = p[PIM_ENCODE_GRP_ADDR_LEN + 1];
	return PIM_BSR_TRUNCATED;
    }

    c->p    += PIM_BSR_GRP_SET_LEN + rplen;
    c->left -= PIM_BSR_GRP_SET_LEN + rplen;

    return PIM_BSR_OK;
}

/*
 * A whole Bootstrap, PIM header included.  The group sets are all walked
 * here, before the caller acts on any of them: everything it does changes
 * state the rest of the domain can see -- the BSR, its priority and
 * fragment tag, the segmented RP list -- and forwards the message onward,
 * so a set refused halfway through would cost a domain its RP set
 * whichever way the check went.
 */
int pim_parse_bsr(const void *msg, size_t len, pim_bsr_t *bsr)
{
    struct pim_cursor c;
    int rc;

    memset(bsr, 0, sizeof(*bsr));

    rc = pim_parse_bsr_hdr(&c, msg, len, bsr);
    if (rc != PIM_BSR_OK)
	return rc;

    while (c.left >= PIM_BSR_GRP_SET_LEN + PIM_BSR_RP_LEN) {
	rc = pim_parse_bsr_set(&c, bsr);
	if (rc != PIM_BSR_OK)
	    return rc;

	bsr->num_sets++;
    }

    return PIM_BSR_OK;
}

/*
 * The group set at set, and the one after it, which is behind its
 * fragment's RP records whatever the RP count says.  Only for a Bootstrap
 * pim_parse_bsr() said OK to, and no further than its num_sets sets.
 */
const uint8_t *pim_bsr_group(const uint8_t *set, pim_bsr_grp_t *grp)
{
    const uint8_t *p = set;

    GET_EGADDR(&grp->grp, p);
    GET_BYTE(grp->rp_count, p);
    GET_BYTE(grp->frag_rp_count, p);
    p += 2;			/* reserved */
    grp->rps = p;

    return p + (size_t)grp->frag_rp_count * PIM_BSR_RP_LEN;
}

/* RP record i of a group set, i < frag_rp_count */
void pim_bsr_rp(const pim_bsr_grp_t *grp, uint8_t i, pim_bsr_rp_t *rp)
{
    const uint8_t *p = grp->rps + (size_t)i * PIM_BSR_RP_LEN;
    pim_encod_uni_addr_t eua;

    GET_EUADDR(&eua, p);
    GET_HOSTSHORT(rp->holdtime, p);
    GET_BYTE(rp->priority, p);
    rp->addr = eua.unicast_addr;
}

/*
 * A Candidate-RP-Advertisement, PIM header included: prefix count,
 * priority, holdtime and the RP's address, then the prefixes, as many of
 * them as are there.  Whether they are as many as the count says is the
 * caller's to act on, since a cut-short advertisement has always had the
 * prefixes before the cut installed.
 */
int pim_parse_crp(const void *msg, size_t len, pim_crp_t *crp)
{
    pim_encod_uni_addr_t eua;
    const uint8_t *data;
    size_t fit;

    memset(crp, 0, sizeof(*crp));

    if (len < PIM_CAND_RP_ADV_MINLEN)
	return PIM_CRP_SHORT;

    data = (const uint8_t *)msg + sizeof(pim_header_t);
    GET_BYTE(crp->prefix_cnt, data);
    GET_BYTE(crp->priority, data);
    GET_HOSTSHORT(crp->holdtime, data);
    GET_EUADDR(&eua, data);
    crp->rp = eua.unicast_addr;

    if (eua.addr_family != ADDRF_IPv4 || eua.encod_type != ADDRT_IPv4) {
	crp->bad_family = eua.addr_family;
	crp->bad_etype  = eua.encod_type;
	return PIM_CRP_FAMILY;
    }

    fit = (len - PIM_CAND_RP_ADV_MINLEN) / PIM_ENCODE_GRP_ADDR_LEN;
    crp->prefixes     = data;
    crp->num_prefixes = fit < crp->prefix_cnt ? (uint8_t)fit : crp->prefix_cnt;

    return PIM_CRP_OK;
}

/* Prefix i of an advertisement, i < num_prefixes */
void pim_crp_prefix(const pim_crp_t *crp, uint8_t i, pim_encod_grp_addr_t *grp)
{
    const uint8_t *p = crp->prefixes + (size_t)i * PIM_ENCODE_GRP_ADDR_LEN;

    GET_EGADDR(grp, p);
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "cc-mode"
 * End:
 */
