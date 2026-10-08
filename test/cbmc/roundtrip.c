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
uint8_t nondet_uint8_t(void);

void proof_rt_register_stop(void);
void proof_rt_assert(void);

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
