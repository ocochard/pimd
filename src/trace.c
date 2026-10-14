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
 *  $Id: trace.c,v 1.13 2002/09/26 00:59:30 pavlin Exp $
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
#include "trace.h"


/* TODO: XXX: implementation incompleted and buggy; check Kame's pim6sd */
/*
 * Traceroute function which returns traceroute replies to the requesting
 * router. Also forwards the request to downstream routers.
 */
/*
 * The two counter ioctls the kernel asks root for -- FreeBSD checks
 * PRIV_NETINET_MROUTE in X_mrt_ioctl(), Linux CAP_NET_ADMIN -- so an
 * unprivileged half has to ask the privileged one for them, the way
 * kern.c does.  mtrace is the only caller, and answering it with
 * 0xffffffff where pimd used to answer with a number would be a
 * regression nothing reports.
 */
static int trace_vif_cnt(struct sioc_vif_req *v_req)
{
    return priv_enabled() ? priv_vif_cnt(v_req) : kern_vif_cnt(udp_socket, v_req);
}


/*
 * Only the fields set below are read, by the kernel here and by the
 * privileged half when there is one, but the whole struct crosses to it
 * now -- so it is cleared first rather than carrying whatever was on this
 * stack.  k_get_vif_count() and k_get_sg_cnt() (src/kern.c) do the same.
 */
static void trace_vif_req(struct sioc_vif_req *v_req, vifi_t vifi)
{
    memset(v_req, 0, sizeof(*v_req));
    v_req->vifi = vifi;
}

void accept_mtrace(uint32_t src, uint32_t dst, uint32_t group, char *data, u_int no, int datalen)
{
    mrtentry_t *mrt;
    mtrace_msg_t qry;
    struct tr_resp resp;
    struct pim_writer w;
    uint8_t *start;
    int vifi;
    u_int rcount;
    int errcode = TR_NO_ERR;
    int resptype;
    struct timeval tp;
    struct sioc_vif_req v_req;
    uint32_t parent_address = INADDR_ANY;

    /* Remember qid across invocations */
    static uint32_t oqid = 0;

    /* timestamp the request/response */
    gettimeofday(&tp, 0);

    /*
     * Check if it is a query or a response.  Every bound of the payload is
     * mtrace_parse()'s, src/igmp_parse.c, which reads its fields at the
     * offsets of the wire.
     */
    if (datalen < 0 || mtrace_parse(data, (size_t)datalen, &qry)) {
        logit(LOG_WARNING, 0, "%s from %s to %s",
              "Non decipherable traceroute request received",
              inet_fmt(src, s1, sizeof(s1)), inet_fmt(dst, s2, sizeof(s2)));
        return;
    }

    if (qry.type == QUERY) {
        IF_DEBUG(DEBUG_TRACE) {
            logit(LOG_DEBUG, 0, "Initial traceroute query rcvd from %s to %s",
                  inet_fmt(src, s1, sizeof(s1)), inet_fmt(dst, s2, sizeof(s2)));
	}
    } else {
        IF_DEBUG(DEBUG_TRACE) {
            logit(LOG_DEBUG, 0, "In-transit traceroute query rcvd from %s to %s",
                  inet_fmt(src, s1, sizeof(s1)), inet_fmt(dst, s2, sizeof(s2)));
	}
        if (IN_MULTICAST(ntohl(dst))) {
            IF_DEBUG(DEBUG_TRACE) {
                logit(LOG_DEBUG, 0, "Dropping multicast response");
	    }
            return;
        }
    }

    /*
     * if it is a packet with all reports filled, drop it
     */
    if ((rcount = qry.rcount) == no) {
        IF_DEBUG(DEBUG_TRACE)
            logit(LOG_DEBUG, 0, "packet with all reports filled in");
        return;
    }

    IF_DEBUG(DEBUG_TRACE) {
        logit(LOG_DEBUG, 0, "s: %s g: %s d: %s ", inet_fmt(qry.src, s1, sizeof(s1)),
              inet_fmt(group, s2, sizeof(s2)), inet_fmt(qry.dst, s3, sizeof(s3)));
        logit(LOG_DEBUG, 0, "rttl: %d rd: %s", qry.rttl,
              inet_fmt(qry.raddr, s1, sizeof(s1)));
        logit(LOG_DEBUG, 0, "rcount:%d, qid:%06x", rcount, qry.qid);
    }

    /* determine the routing table entry for this traceroute */
    mrt = find_route(qry.src, group, MRTF_SG | MRTF_WC,
                     DONT_CREATE);
    IF_DEBUG(DEBUG_TRACE) {
        if (mrt != (mrtentry_t *)NULL) {
            if (mrt->upstream != (pim_nbr_entry_t *)NULL)
                parent_address = mrt->upstream->address;
            else
                parent_address = INADDR_ANY;
            logit(LOG_DEBUG, 0, "mrt parent vif: %d rtr: %s metric: %d",
                  mrt->incoming, inet_fmt(parent_address, s1, sizeof(s1)), mrt->metric);
/* TODO
   logit(LOG_DEBUG, 0, "mrt origin %s",
   RT_FMT(rt, s1));
*/
        } else {
            logit(LOG_DEBUG, 0, "...no route");
        }
    }

    /*
     * Query type packet - check if rte exists
     * Check if the query destination is a vif connected to me.
     * and if so, whether I should start response back
     */
    if (qry.type == QUERY) {
        if (oqid == qry.qid) {
            /*
             * If the multicast router is a member of the group being
             * queried, and the query is multicasted, then the router can
             * recieve multiple copies of the same query.  If we have already
             * replied to this traceroute, just ignore it this time.
             *
             * This is not a total solution, but since if this fails you
             * only get N copies, N <= the number of interfaces on the router,
             * it is not fatal.
             */
            IF_DEBUG(DEBUG_TRACE) {
                logit(LOG_DEBUG, 0, "ignoring duplicate traceroute packet");
	    }
            return;
        }

        if (!mrt) {
            IF_DEBUG(DEBUG_TRACE) {
                logit(LOG_DEBUG, 0, "Mcast traceroute: no route entry %s", inet_fmt(qry.src, s1, sizeof(s1)));
	    }
            if (IN_MULTICAST(ntohl(dst)))
                return;
        }

        vifi = find_vif_direct(qry.dst);
        if (vifi == NO_VIF) {
            /* The traceroute destination is not on one of my subnet vifs. */
            IF_DEBUG(DEBUG_TRACE) {
                logit(LOG_DEBUG, 0, "Destination %s not an interface", inet_fmt(qry.dst, s1, sizeof(s1)));
	    }
            if (IN_MULTICAST(ntohl(dst)))
                return;
            errcode = TR_WRONG_IF;
        } else if (mrt && !PIMD_VIFM_ISSET(vifi, mrt->oifs)) {
            IF_DEBUG(DEBUG_TRACE) {
                logit(LOG_DEBUG, 0,
                      "Destination %s not on forwarding tree for src %s",
                      inet_fmt(qry.dst, s1, sizeof(s1)), inet_fmt(qry.src, s2, sizeof(s2)));
	    }
            if (IN_MULTICAST(ntohl(dst)))
                return;
            errcode = TR_WRONG_IF;
        }
    } else {
        /*
         * determine which interface the packet came in on
         * RESP packets travel hop-by-hop so this either traversed
         * a tunnel or came from a directly attached mrouter.
         */
	vifi = find_vif_direct(src);
	if (vifi == NO_VIF) {
	    IF_DEBUG(DEBUG_TRACE) {
		logit(LOG_DEBUG, 0, "Wrong interface for packet");
	    }
            errcode = TR_WRONG_IF;
        }
    }

    /* Now that we've decided to send a response, save the qid */
    oqid = qry.qid;

    IF_DEBUG(DEBUG_TRACE) {
        logit(LOG_DEBUG, 0, "Sending traceroute response");
    }

    /*
     * Copy the packet to the sending buffer, through a writer bounded by
     * its end (src/pim_encode.c).  The request has to fit before it can be
     * answered at all: datalen is the IGMP payload length of a packet off
     * the socket, so it is whatever the sender's IP total length field
     * said rather than anything this daemon chose.
     */
    start = (uint8_t *)igmp_send_buf + IP_IGMP_HEADER_LEN + IGMP_MINLEN;
    pim_writer_init(&w, start, SEND_BUF_SIZE - IP_IGMP_HEADER_LEN - IGMP_MINLEN);
    if (!pim_put_bytes(&w, data, (size_t)datalen)) {
        logit(LOG_WARNING, 0, "Mcast traceroute from %s is %d bytes, too long to answer",
              inet_fmt(src, s1, sizeof(s1)), datalen);
        return;
    }

    /*
     * If there is no room to insert our reply, coopt the previous hop
     * error indication to relay this fact: the last byte of the copy, the
     * flags of the block the router before us added.  A query that has no
     * such block and no room for ours is not one this buffer can be handed.
     */
    if (!pim_writer_room(&w, RLEN)) {
        if (!rcount)
            return;
        start[datalen - 1] = TR_NO_SPACE;
        mrt = NULL;
        goto sendit;
    }

    /*
     * fill in initial response fields, in a block of our own appended to
     * the copy once it is complete
     */
    memset(&resp, 0, sizeof(resp));
    datalen += RLEN;

    resp.tr_qarr    = htonl(((tp.tv_sec + JAN_1970) << 16) +
			     ((tp.tv_usec << 10) / 15625));
    resp.tr_rproto  = PROTO_PIM;
    resp.tr_outaddr = (vifi == NO_VIF) ? dst : uvifs[vifi].uv_lcl_addr;
    resp.tr_fttl    = (vifi == NO_VIF) ? 0   : uvifs[vifi].uv_threshold;
    resp.tr_rflags  = errcode;

    /*
     * obtain # of packets out on interface
     */
    trace_vif_req(&v_req, vifi);
    if (vifi != NO_VIF && trace_vif_cnt(&v_req) >= 0)
        resp.tr_vifout  =  htonl(v_req.ocount);
    else
        resp.tr_vifout  =  0xffffffff;

    /* TODO: the scoping and pruning flags of the response are not filled in */

    /*
     *  if no rte exists, set NO_RTE error
     */
    if (!mrt) {
        src = dst;		/* the dst address of resp. pkt */
        resp.tr_inaddr   = 0;
        resp.tr_rflags   = TR_NO_RTE;
        resp.tr_rmtaddr  = 0;
    } else {
        /* get # of packets in on interface */
        trace_vif_req(&v_req, mrt->incoming);
        if (trace_vif_cnt(&v_req) >= 0)
            resp.tr_vifin = htonl(v_req.icount);
        else
            resp.tr_vifin = 0xffffffff;

        /* TODO
           MASK_TO_VAL(rt->rt_originmask, resp.tr_smask);
        */
        src = uvifs[mrt->incoming].uv_lcl_addr;
        resp.tr_inaddr = src;
        if (mrt->upstream)
            parent_address = mrt->upstream->address;
        else
            parent_address = INADDR_ANY;

        resp.tr_rmtaddr = parent_address;
        if (vifi != NO_VIF && !PIMD_VIFM_ISSET(vifi, mrt->oifs)) {
            IF_DEBUG(DEBUG_TRACE)
                logit(LOG_DEBUG, 0, "Destination %s not on forwarding tree for src %s",
                      inet_fmt(qry.dst, s1, sizeof(s1)), inet_fmt(qry.src, s2, sizeof(s2)));
            resp.tr_rflags = TR_WRONG_IF;
        }
    }

    pim_put_bytes(&w, &resp, RLEN);

  sendit:
    /*
     * The first hop router answers the requestor, as does a hop that has
     * filled the last block the query asked for or has no route; every
     * other hop passes the query to its upstream router.  The first hop
     * is the one with no upstream router at all -- the source on one of
     * its links, or the register vif the RP takes a source in on.  This
     * asked for a route metric of 1 instead, which is mrouted's way of
     * saying "directly connected"; pimd's metric is the routing table's,
     * where 1 is one hop away, so every router a hop from the source's
     * route answered at once and the trace never got past the last hop.
     */
    IF_DEBUG(DEBUG_TRACE)
        logit(LOG_DEBUG, 0, "rcount:%d, no:%d", rcount, no);

    if ((rcount + 1 == no) || (mrt == NULL) || (mrt->upstream == NULL)) {
        resptype = IGMP_MTRACE_RESP;
        dst = qry.raddr;
    } else {
	    if (mrt->upstream)
		parent_address = mrt->upstream->address;
	    else
		parent_address = INADDR_ANY;
	    dst = parent_address;
	    resptype = IGMP_MTRACE;
    }

    if (IN_MULTICAST(ntohl(dst))) {
	/*
	 * Send the reply on a known multicast capable vif.
	 * If we don't have one, we can't source any multicasts anyway.
	 */
	if (phys_vif != -1) {
	    IF_DEBUG(DEBUG_TRACE)
		logit(LOG_DEBUG, 0, "Sending reply to %s from %s",
		      inet_fmt(dst, s1, sizeof(s1)),
		      inet_fmt(uvifs[phys_vif].uv_lcl_addr, s2, sizeof(s2)));
	    k_set_ttl(igmp_socket, qry.rttl);
	    send_igmp(igmp_send_buf, uvifs[phys_vif].uv_lcl_addr, dst,
		      resptype, no, group, datalen);
	    k_set_ttl(igmp_socket, 1);
	} else {
	    logit(LOG_INFO, 0, "No enabled phyints -- dropping traceroute reply");
	}
    } else {
	IF_DEBUG(DEBUG_TRACE) {
	    logit(LOG_DEBUG, 0, "Sending %s to %s from %s",
		  resptype == IGMP_MTRACE_RESP ?  "reply" : "request on",
		  inet_fmt(dst, s1, sizeof(s1)), inet_fmt(src, s2, sizeof(s2)));
	}
	/* A query passed on goes to the upstream router, a neighbour on
	 * the link it came in on, so TTL 1 reaches it -- and is what gets
	 * it there on FreeBSD, whose igmp_input() drops any IGMP but DVMRP
	 * that arrives with a TTL of more than one.  The response goes to
	 * whoever asked, wherever that is. */
	if (resptype == IGMP_MTRACE)
	    send_igmp_ttl(igmp_send_buf, src, dst, resptype, no, group, datalen, 1);
	else
	    send_igmp(igmp_send_buf, src, dst, resptype, no, group, datalen);
    }
}


/*
 * accept_neighbor_request() supports some old DVMRP messages from mrinfo.
 * Haven't tested it, because I have only the new mrinfo.
 */
/*
 * A writer over the body of a DVMRP reply in igmp_send_buf, bounded by the
 * MAX_DVMRP_DATA_LEN the replies below are flushed at (src/pim_encode.c):
 * a reply that does not fit is sent and a new one begun, and the writer is
 * what makes "does it fit" and "where does it end" the same number.
 */
static uint8_t *dvmrp_reply_start(struct pim_writer *w)
{
    uint8_t *start = (uint8_t *)igmp_send_buf + IP_IGMP_HEADER_LEN + IGMP_MINLEN;

    pim_writer_init(w, start, MAX_DVMRP_DATA_LEN);

    return start;
}

void accept_neighbor_request(uint32_t src, uint32_t dst __attribute__((unused)))
{
    vifi_t vifi;
    struct uvif *v;
    uint8_t *start, *ncount;
/*    struct listaddr *la; */
    pim_nbr_entry_t *pim_nbr;
    struct pim_writer w;
    uint32_t them = src;

    start = dvmrp_reply_start(&w);

    for (vifi = 0, v = uvifs; vifi < numvifs; vifi++, v++) {
	if (v->uv_flags & VIFF_DISABLED)
	    continue;

	ncount = 0;

	/* TODO: XXX: if we are PMBR, then check the DVMRP interfaces too */
	for (pim_nbr = v->uv_pim_neighbors; pim_nbr != (pim_nbr_entry_t *)NULL;
	     pim_nbr = pim_nbr->next) {
	    /* Make sure that there's room for this neighbor... */
	    if (!pim_writer_room(&w, ncount == 0 ? 4 + 3 + 4 : 4)) {
		send_igmp(igmp_send_buf, INADDR_ANY, them, IGMP_DVMRP,
			  DVMRP_NEIGHBORS, htonl(PIMD_LEVEL), (int)pim_writer_used(&w, start));
		start = dvmrp_reply_start(&w);
		ncount = 0;
	    }

	    /* Put out the header for this neighbor list... */
	    if (ncount == 0) {
		pim_put_bytes(&w, &v->uv_lcl_addr, sizeof(v->uv_lcl_addr));
		pim_put_u8(&w, v->uv_metric);
		pim_put_u8(&w, v->uv_threshold);
		ncount = w.p;
		pim_put_u8(&w, 0);
	    }

	    pim_put_bytes(&w, &pim_nbr->address, sizeof(pim_nbr->address));
	    (*ncount)++;
	}
    }

    if (pim_writer_used(&w, start))
	send_igmp(igmp_send_buf, INADDR_ANY, them, IGMP_DVMRP, DVMRP_NEIGHBORS,
		  htonl(PIMD_LEVEL), (int)pim_writer_used(&w, start));
}


/*
 * Send a list of all of our neighbors to the requestor, `src'.
 * Used for mrinfo support.
 * XXX: currently, we cannot specify the used multicast routing protocol;
 * only a protocol version is returned.
 */
void accept_neighbor_request2(uint32_t src, uint32_t dst __attribute__((unused)))
{
    vifi_t vifi;
    struct uvif *v;
    uint8_t *start, *ncount;
/*    struct listaddr *la; */
    pim_nbr_entry_t *pim_nbr;
    struct pim_writer w;
    uint32_t them = src;

    start = dvmrp_reply_start(&w);

    for (vifi = 0, v = uvifs; vifi < numvifs; vifi++, v++) {
	uint32_t vflags = v->uv_flags;
	uint8_t rflags = 0;

	if (vflags & VIFF_TUNNEL)
	    rflags |= DVMRP_NF_TUNNEL;
	if (vflags & VIFF_SRCRT)
	    rflags |= DVMRP_NF_SRCRT;
	if (vflags & VIFF_PIM_NBR)
	    rflags |= DVMRP_NF_PIM;
	if (vflags & VIFF_DOWN)
	    rflags |= DVMRP_NF_DOWN;
	if (vflags & VIFF_DISABLED)
	    rflags |= DVMRP_NF_DISABLED;
	if (vflags & VIFF_QUERIER)
	    rflags |= DVMRP_NF_QUERIER;
	if (vflags & VIFF_LEAF)
	    rflags |= DVMRP_NF_LEAF;

	ncount = 0;
	pim_nbr = v->uv_pim_neighbors;
	if (pim_nbr == (pim_nbr_entry_t *)NULL) {
	    /*
	     * include down & disabled interfaces and interfaces on
	     * leaf nets.
	     */
	    if (rflags & DVMRP_NF_TUNNEL)
		rflags |= DVMRP_NF_DOWN;

	    if (!pim_writer_room(&w, 12)) {
		send_igmp(igmp_send_buf, INADDR_ANY, them, IGMP_DVMRP,
			  DVMRP_NEIGHBORS2, htonl(PIMD_LEVEL), (int)pim_writer_used(&w, start));
		start = dvmrp_reply_start(&w);
	    }

	    pim_put_bytes(&w, &v->uv_lcl_addr, sizeof(v->uv_lcl_addr));
	    pim_put_u8(&w, v->uv_metric);
	    pim_put_u8(&w, v->uv_threshold);
	    pim_put_u8(&w, rflags);
	    pim_put_u8(&w, 1);
	    pim_put_bytes(&w, &v->uv_rmt_addr, sizeof(v->uv_rmt_addr));
	} else {
	    for ( ; pim_nbr; pim_nbr = pim_nbr->next) {
		/* Make sure that there's room for this neighbor... */
		if (!pim_writer_room(&w, ncount == 0 ? 4+4+4 : 4)) {
		    send_igmp(igmp_send_buf, INADDR_ANY, them, IGMP_DVMRP,
			      DVMRP_NEIGHBORS2, htonl(PIMD_LEVEL), (int)pim_writer_used(&w, start));
		    start = dvmrp_reply_start(&w);
		    ncount = 0;
		}

		/* Put out the header for this neighbor list... */
		if (ncount == 0) {
		    pim_put_bytes(&w, &v->uv_lcl_addr, sizeof(v->uv_lcl_addr));
		    pim_put_u8(&w, v->uv_metric);
		    pim_put_u8(&w, v->uv_threshold);
		    pim_put_u8(&w, rflags);
		    ncount = w.p;
		    pim_put_u8(&w, 0);
		}

		pim_put_bytes(&w, &pim_nbr->address, sizeof(pim_nbr->address));
		(*ncount)++;
	    }
	}
    }

    if (pim_writer_used(&w, start))
	send_igmp(igmp_send_buf, INADDR_ANY, them, IGMP_DVMRP,
		  DVMRP_NEIGHBORS2, htonl(PIMD_LEVEL), (int)pim_writer_used(&w, start));
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "cc-mode"
 * End:
 */
