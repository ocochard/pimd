/*
 * roundtrip.c - prove what src/pim_encode.c writes, src/pim_parse.c reads
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
 * A harness for cbmc(1), not a program: run.sh compiles it alone, with
 * SOURCE naming src/pim_encode.c or a mutant of it, and src/pim_parse.c
 * included as it is.  The other harnesses prove a decoder reads nothing
 * it should not; this one proves a decoder reads back what the encoder of
 * the same message wrote, for every value of every field:
 *
 *   proof_rt_register_stop  pim_encode_register_stop() and
 *                           pim_parse_register_stop()
 *   proof_rt_assert         pim_encode_assert() and pim_parse_assert()
 *   proof_rt_hello          pim_encode_hello() and pim_parse_hello():
 *                           every option, no Address List
 *   proof_rt_hello_addr     the same with one secondary address
 *   proof_rt_crp            pim_encode_crp_hdr() and _prefix(), and
 *                           pim_parse_crp() and pim_crp_prefix(): up to
 *                           CRP_MAX prefixes of any group and mask length
 *   proof_rt_null_register  pim_encode_null_register() and
 *                           pim_parse_register(): the N bit, and a dummy
 *                           header the decoder reads the source, the group
 *                           and, once the sender has checksummed it, the
 *                           header length back out of
 *
 * The body is written behind a PIM header of any four bytes, into a buffer
 * allocated at exactly the message's length, so a field written past the
 * end or read past it is a violation as well as a mismatch.
 *
 * What a round trip cannot see is a field the two get wrong the same way:
 * an encoder and a decoder that agree on the wrong offset agree.  That is
 * what the FRR and vEOS labs are for, a second implementation on the wire.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include SOURCE
#include "pim_parse.c"

uint32_t nondet_uint32_t(void);
uint16_t nondet_uint16_t(void);
uint8_t nondet_uint8_t(void);

void proof_rt_register_stop(void);
void proof_rt_assert(void);
void proof_rt_null_register(void);
void proof_rt_crp(void);
void proof_rt_hello(void);
void proof_rt_hello_addr(void);

/* A message of exactly @body bytes behind a PIM header of any content, and
 * a writer on its body */
static uint8_t *message(size_t body, struct pim_writer *w)
{
    uint8_t *buf = malloc(sizeof(pim_header_t) + body);
    size_t i;

    __CPROVER_assume(buf != NULL);
    for (i = 0; i < sizeof(pim_header_t); i++)
	buf[i] = nondet_uint8_t();

    pim_writer_init(w, buf + sizeof(pim_header_t), body);

    return buf;
}

void proof_rt_register_stop(void)
{
    uint32_t group = nondet_uint32_t(), source = nondet_uint32_t();
    const size_t body = PIM_ENCODE_GRP_ADDR_LEN + PIM_ENCODE_UNI_ADDR_LEN;
    struct pim_writer w;
    pim_sg_msg_t rs;
    uint8_t *buf;

    buf = message(body, &w);
    __CPROVER_assert(pim_encode_register_stop(&w, group, source), "a Register-Stop fits its length");
    __CPROVER_assert(w.left == 0, "and fills it");

    __CPROVER_assert(pim_parse_register_stop(buf, sizeof(pim_header_t) + body, &rs) == PIM_SG_OK,
		     "the decoder takes what the encoder wrote");
    __CPROVER_assert(rs.group == group, "the group comes back");
    __CPROVER_assert(rs.source == source, "the source comes back");

    free(buf);
}

void proof_rt_assert(void)
{
    uint32_t group = nondet_uint32_t(), source = nondet_uint32_t();
    uint32_t pref = nondet_uint32_t(), metric = nondet_uint32_t();
    const size_t body = PIM_ENCODE_GRP_ADDR_LEN + PIM_ENCODE_UNI_ADDR_LEN + 8;
    struct pim_writer w;
    pim_sg_msg_t as;
    uint8_t *buf;

    buf = message(body, &w);
    __CPROVER_assert(pim_encode_assert(&w, group, source, pref, metric), "an Assert fits its length");
    __CPROVER_assert(w.left == 0, "and fills it");

    __CPROVER_assert(pim_parse_assert(buf, sizeof(pim_header_t) + body, &as) == PIM_SG_OK,
		     "the decoder takes what the encoder wrote");
    __CPROVER_assert(as.group == group, "the group comes back");
    __CPROVER_assert(as.source == source, "the source comes back");
    __CPROVER_assert(as.preference == pref, "the preference comes back, RPT bit and all");
    __CPROVER_assert(as.metric == metric, "the metric comes back");

    free(buf);
}

void proof_rt_null_register(void)
{
    uint32_t group = nondet_uint32_t(), source = nondet_uint32_t();
    uint8_t ttl = nondet_uint8_t(), c0 = nondet_uint8_t(), c1 = nondet_uint8_t();
    const size_t body = sizeof(pim_register_t) + IP_HDR_MINLEN;
    struct pim_writer w;
    uint8_t *buf, *hdr;
    pim_reg_t reg;

    buf = message(body, &w);
    __CPROVER_assert(pim_encode_null_register(&w, source, group, ttl, &hdr), "a Null-Register fits its length");
    __CPROVER_assert(w.left == 0, "and fills it");
    __CPROVER_assert(hdr == buf + sizeof(pim_header_t) + sizeof(pim_register_t),
		     "the dummy header is where the decoder reads it");

    /* The sender's checksum, any that is not zero */
    __CPROVER_assume(c0 | c1);
    hdr[IP_OFF_SUM] = c0;
    hdr[IP_OFF_SUM + 1] = c1;

    __CPROVER_assert(pim_parse_register(buf, sizeof(pim_header_t) + body, &reg) == PIM_REG_OK,
		     "the decoder takes what the encoder wrote");
    __CPROVER_assert(reg.is_null, "the N bit comes back");
    __CPROVER_assert(reg.inner_version == IP_HDR_V4, "so does the version");
    __CPROVER_assert(reg.inner_len == IP_HDR_MINLEN, "and the total length");
    __CPROVER_assert(reg.null_hlen == IP_HDR_MINLEN, "and the header length the checksum covers");
    __CPROVER_assert(reg.inner_src == source, "the source comes back");
    __CPROVER_assert(reg.inner_grp == group, "the group comes back");
    __CPROVER_assert(hdr[IP_OFF_PROTO] == IPPROTO_PIM, "the protocol is PIM's");
    __CPROVER_assert(hdr[IP_OFF_TTL] == ttl, "the TTL is the one asked for");

    free(buf);
}

#ifndef CRP_MAX
#define CRP_MAX 3
#endif

void proof_rt_crp(void)
{
    uint8_t priority = nondet_uint8_t(), n = nondet_uint8_t();
    uint16_t holdtime = nondet_uint16_t();
    uint32_t rp = nondet_uint32_t();
    uint32_t group[CRP_MAX];
    uint8_t masklen[CRP_MAX];
    struct pim_writer w;
    pim_encod_grp_addr_t ega;
    uint8_t *buf, *cnt;
    pim_crp_t crp;
    size_t body;
    uint8_t i;

    __CPROVER_assume(n <= CRP_MAX);
    body = 4 + PIM_ENCODE_UNI_ADDR_LEN + (size_t)n * PIM_ENCODE_GRP_ADDR_LEN;

    buf = message(body, &w);
    __CPROVER_assert(pim_encode_crp_hdr(&w, priority, holdtime, rp, &cnt), "the header fits");
    for (i = 0; i < n; i++) {
	group[i] = nondet_uint32_t();
	masklen[i] = nondet_uint8_t();
	__CPROVER_assume(masklen[i] <= 32);
	__CPROVER_assert(pim_encode_crp_prefix(&w, group[i], masklen[i]), "each prefix fits");
    }
    __CPROVER_assert(w.left == 0, "and they fill the message");
    *cnt = n;

    __CPROVER_assert(pim_parse_crp(buf, sizeof(pim_header_t) + body, &crp) == PIM_CRP_OK,
		     "the decoder takes what the encoder wrote");
    __CPROVER_assert(crp.prefix_cnt == n && crp.num_prefixes == n, "every prefix is counted and there");
    __CPROVER_assert(crp.priority == priority, "the priority comes back");
    __CPROVER_assert(crp.holdtime == holdtime, "the holdtime comes back");
    __CPROVER_assert(crp.rp == rp, "the RP comes back");

    for (i = 0; i < n; i++) {
	uint32_t mask;

	pim_crp_prefix(&crp, i, &ega);
	mask = masklen[i] ? htonl(0xffffffffu << (32 - masklen[i])) : 0;
	__CPROVER_assert(ega.masklen == masklen[i], "each mask length comes back");
	__CPROVER_assert(ega.mcast_addr == (group[i] & mask), "each group comes back, masked");
    }

    free(buf);
}

/*
 * The number of secondary addresses is a constant per proof: left to the
 * checker, it makes every offset of the option walk symbolic, and one
 * proof over zero to two of them ran past 49G before it was stopped.
 */
static void rt_hello(size_t nsec)
{
    uint16_t holdtime = nondet_uint16_t(), prop = nondet_uint16_t(), over = nondet_uint16_t();
    uint32_t dr_prio = nondet_uint32_t(), genid = nondet_uint32_t();
    uint32_t sec[1];
    pim_hello_opts_t opts;
    struct pim_writer w;
    uint8_t *buf;
    size_t body, i;

    __CPROVER_assume(!(prop & PIM_LAN_PRUNE_DELAY_T_BIT));
    sec[0] = nondet_uint32_t();

    body = 3 * 2 + 4 * 2 + 2 * (4 + 4) + (nsec ? 4 + nsec * PIM_ENCODE_UNI_ADDR_LEN : 0);
    buf = message(body, &w);
    __CPROVER_assert(pim_encode_hello(&w, holdtime, prop, over, dr_prio, genid, sec, nsec),
		     "a Hello fits its length");
    __CPROVER_assert(w.left == 0, "and fills it");

    __CPROVER_assert(pim_parse_hello(buf, sizeof(pim_header_t) + body, &opts) == PIM_HELLO_OK,
		     "the decoder takes what the encoder wrote");
    __CPROVER_assert(opts.holdtime_present && opts.holdtime == holdtime, "the holdtime comes back");
    __CPROVER_assert(opts.lan_delay_present && !opts.tracking_support, "the LAN Prune Delay, T bit clear");
    __CPROVER_assert(opts.propagation_delay == prop, "the propagation delay comes back");
    __CPROVER_assert(opts.override_interval == over, "the override interval comes back");
    __CPROVER_assert(opts.dr_prio_present && opts.dr_prio == dr_prio, "the DR priority comes back");
    __CPROVER_assert(opts.genid == genid, "the generation ID comes back");
    __CPROVER_assert(!opts.addr_list_refused, "the Address List is taken");
    __CPROVER_assert(opts.addr_list_len == nsec * PIM_ENCODE_UNI_ADDR_LEN, "every secondary address is there");
    for (i = 0; i < nsec; i++)
	__CPROVER_assert(pim_hello_addr(&opts, (uint16_t)i) == sec[i], "and comes back");

    free(buf);
}

void proof_rt_hello(void)
{
    rt_hello(0);
}

void proof_rt_hello_addr(void)
{
    rt_hello(1);
}
