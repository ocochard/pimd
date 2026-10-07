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

#ifndef PIMD_IGMPV3_H_
#define PIMD_IGMPV3_H_

/*
 * IGMPv3 report modes.
 */
#ifndef IGMP_MODE_IS_INCLUDE
#define IGMP_DO_NOTHING			0	/* don't send a record */
#define IGMP_MODE_IS_INCLUDE		1	/* MODE_IN */
#define IGMP_MODE_IS_EXCLUDE		2	/* MODE_EX */
#define IGMP_CHANGE_TO_INCLUDE_MODE	3	/* TO_IN */
#define IGMP_CHANGE_TO_EXCLUDE_MODE	4	/* TO_EX */
#define IGMP_ALLOW_NEW_SOURCES		5	/* ALLOW_NEW */
#define IGMP_BLOCK_OLD_SOURCES		6	/* BLOCK_OLD */
#endif

struct igmpv3_query {
    uint8_t  type;
    uint8_t  code;
    uint16_t csum;
    uint32_t group;
#if defined(BYTE_ORDER) && (BYTE_ORDER == LITTLE_ENDIAN)
    uint8_t  qrv:3,
             suppress:1,
             resv:4;
#else
    uint8_t  resv:4,
	     suppress:1,
	     qrv:3;
#endif
    uint8_t  qqic;
    uint16_t nsrcs;
    uint32_t srcs[0];
};

struct igmpv3_grec {
    uint8_t  grec_type;
    uint8_t  grec_auxwords;
    uint16_t grec_nsrcs;
    uint32_t grec_mca;
    uint32_t grec_src[0];
};

#define IGMP_GRPREC_HDRLEN		8
#define IGMP_V3_GROUP_RECORD_MIN_SIZE	8

/*
 * Sources pimd is willing to hold for one group on one interface.  Not a
 * protocol limit, RFC 3376 has none: a report can name 65535 sources per
 * group record and 65535 group records, and each source pimd accepts is a
 * membership, a timer and an (S,G) entry it keeps until that source is
 * blocked or times out.
 */
#define IGMP_MAX_SOURCES		256

struct igmpv3_report {
    uint8_t  type;
    uint8_t  resv1;
    uint16_t csum;
    uint16_t resv2;
    uint16_t ngrec;
    struct igmpv3_grec grec[0];
};

#ifndef IGMP_V3_REPORT_MINLEN
#define IGMP_V3_REPORT_MINLEN		8
#define IGMP_V3_REPORT_MAXRECS		65535
#endif

/*
 * An IGMPv3 Membership Report, RFC 3376 sec. 4.2, as src/igmp_parse.c
 * decodes it: bytes in, fields out, every bounds check of the message in
 * one place and no global read, so that test/cbmc/ can prove it.  A
 * cursor rather than a decoded message, because a report that goes wrong
 * halfway has always had the records before it acted on.  A record is
 * handed out only once all of it -- its sources and its auxiliary data --
 * is inside the message, and its sources are then read through
 * igmpv3_source(), which is the one way accept_membership_report() reads
 * them.
 */
struct igmpv3_cursor {
    const uint8_t *p;		/* the next record */
    size_t   left;		/* bytes from p to the end of the report */
    unsigned ngrec;		/* records still to read */
};

typedef struct {
    uint8_t  type;
    uint32_t group;		/* network order */
    uint16_t nsrcs;
    const uint8_t *srcs;	/* nsrcs addresses */
    size_t   size;		/* the whole record, header, sources and aux data */
} igmpv3_rec_t;

#define IGMPV3_OK		0	/* igmpv3_parse_report() only		*/
#define IGMPV3_SHORT		1	/* shorter than a report header		*/
#define IGMPV3_DONE		2	/* every record the header counts	*/
#define IGMPV3_RECORD		3	/* one record, in *rec			*/
#define IGMPV3_SHORT_HDR	4	/* a record header runs past the end	*/
#define IGMPV3_SHORT_REC	5	/* a record runs past the end, rec->size says how far */

/*
 * The packet accept_igmp() is handed, IP header included, as
 * src/igmp_parse.c decodes it before anything else reads it: the IP
 * header's length and protocol, then the IGMP header behind it.  A
 * protocol of zero is not IGMP at all but a kernel upcall, a struct
 * igmpmsg laid out to look like an IP header, which only the source and
 * destination are read out of here; process_kernel_call() asks the rest.
 */
typedef struct {
    uint32_t src;		/* network order */
    uint32_t dst;		/* network order */
    uint8_t  proto;
    size_t   iphdrlen;		/* as the header says, bounded by the packet */
    size_t   ipdatalen;		/* the IGMP message, its header included */
    const uint8_t *igmp;	/* that message */
    uint8_t  type;
    uint8_t  code;
    uint32_t group;		/* network order */
    int      query_version;	/* of a query, by its length: 1, 2, 3, or 0 for none */
} igmp_pkt_t;

#define IGMP_PKT_OK		0
#define IGMP_PKT_SHORT		1	/* shorter than an IP header		*/
#define IGMP_PKT_UPCALL		2	/* protocol 0, the kernel's		*/
#define IGMP_PKT_BAD_HLEN	3	/* a header length the packet cannot have */
#define IGMP_PKT_SHORT_IGMP	4	/* no room behind it for an IGMP header	*/

int      igmp_parse_packet  (const void *buf, size_t len, igmp_pkt_t *pkt);
int      igmpv3_parse_report(const void *report, size_t len, struct igmpv3_cursor *c,
			     uint8_t *type, uint16_t *ngrec);
int      igmpv3_parse_record(struct igmpv3_cursor *c, igmpv3_rec_t *rec);
uint32_t igmpv3_source(const igmpv3_rec_t *rec, uint16_t i);

#endif /* PIMD_IGMPV3_H_ */

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "cc-mode"
 * End:
 */
