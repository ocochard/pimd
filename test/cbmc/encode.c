/*
 * encode.c - prove src/pim_encode.c writes nothing past its buffer
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
 * SOURCE naming src/pim_encode.c or a mutant of it.  The proof is
 * proof_put: one put of any kind and any value, from any state a writer
 * can be in, on a buffer of any length.  proof_put_bytes beside it is the
 * same for pim_put_bytes(), which copies a list a builder kept apart and
 * whose length is the caller's, any up to MAXLEN, the comparison of what
 * was copied being a loop.  That is the whole of it by
 * induction -- a writer starts in such a state and each put leaves it in
 * one -- which is why there is no proof of a run of puts beside it: the
 * one there was, six puts of any kinds in a row, was redundant and ran
 * the host out of memory before it finished.
 *
 * The buffer is allocated at exactly its length, so a byte written past it
 * is a bounds violation.  Beside that, what a builder relies on:
 *
 *   - a put that fits writes exactly its encoding and moves the writer by
 *     its length, and one that does not writes nothing, moves nothing and
 *     makes the writer full;
 *   - a full writer stays full and writes nothing, so a message is whole
 *     if and only if the writer is not full at its end;
 *   - the writer never leaves its buffer: what was written and what is
 *     left always add up to it.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include SOURCE

/* The send buffer pimd writes into, SEND_BUF_SIZE in defs.h, is 128K */
#define SENDBUF_MAX (128 * 1024)

size_t nondet_size_t(void);
unsigned nondet_unsigned(void);
uint32_t nondet_uint32_t(void);
uint8_t nondet_uint8_t(void);
int nondet_int(void);

#ifndef MAXLEN
#define MAXLEN 16
#endif

void proof_put(void);
void proof_put_bytes(void);

/* One put of kind k, and its length when it fits */
static int put(struct pim_writer *w, unsigned k, uint32_t v, uint8_t a, uint8_t b, size_t *n)
{
    switch (k) {
    case 0: *n = 1; return pim_put_u8(w, (uint8_t)(v & 0xff));
    case 1: *n = 2; return pim_put_u16(w, (uint16_t)(v & 0xffff));
    case 2: *n = 4; return pim_put_u32(w, v);
    case 3: *n = PIM_ENCODE_UNI_ADDR_LEN; return pim_put_euaddr(w, v);
    case 4: *n = PIM_ENCODE_GRP_ADDR_LEN; return pim_put_egaddr(w, v, a, b);
    default: *n = PIM_ENCODE_SRC_ADDR_LEN; return pim_put_esaddr(w, v, a, b);
    }
}

void proof_put(void)
{
    struct pim_writer w, before;
    uint8_t *buf, *at, a, b;
    size_t len, off, n;
    uint32_t v, mask;
    unsigned k;
    int ok;

    len = nondet_size_t();
    __CPROVER_assume(len <= SENDBUF_MAX);
    buf = malloc(len);
    __CPROVER_assume(buf != NULL);

    /* Any state: anywhere on the buffer, full or not */
    off = nondet_size_t();
    __CPROVER_assume(off <= len);
    w.p    = buf + off;
    w.left = len - off;
    w.full = nondet_int() ? 1 : 0;
    before = w;

    k = nondet_unsigned();
    __CPROVER_assume(k <= 5);
    v = nondet_uint32_t();
    a = nondet_uint8_t();
    b = nondet_uint8_t();
    at = w.p;

    ok = put(&w, k, v, a, b, &n);
    __CPROVER_assert(w.p + w.left == buf + len, "the writer stays on its buffer");

    if (!ok) {
	__CPROVER_assert(before.full || before.left < n, "only a full writer or a short buffer refuses");
	__CPROVER_assert(w.full && w.p == before.p && w.left == before.left,
			 "a refusal writes nothing, moves nothing, and leaves the writer full");
	free(buf);
	return;
    }

    __CPROVER_assert(!before.full && n <= before.left, "a full writer writes nothing again");
    __CPROVER_assert(!w.full && w.p == at + n && w.left == before.left - n,
		     "a put moves the writer by its length");

    switch (k) {
    case 0:
	__CPROVER_assert(at[0] == (v & 0xff), "a byte is the byte");
	break;
    case 1:
	__CPROVER_assert(at[0] == ((v >> 8) & 0xff) && at[1] == (v & 0xff), "16 bits big-endian");
	break;
    case 2:
	__CPROVER_assert(at[0] == ((v >> 24) & 0xff) && at[1] == ((v >> 16) & 0xff) &&
			 at[2] == ((v >> 8) & 0xff) && at[3] == (v & 0xff), "32 bits big-endian");
	break;
    case 3:
	__CPROVER_assert(at[0] == ADDRF_IPv4 && at[1] == ADDRT_IPv4 && memcmp(at + 2, &v, 4) == 0,
			 "an Encoded-Unicast is IPv4, native, and the address as kept");
	break;
    default:
	MASKLEN_TO_MASK(a, mask);
	v &= mask;
	__CPROVER_assert(at[0] == ADDRF_IPv4 && at[1] == ADDRT_IPv4 && at[2] == b && at[3] == a &&
			 memcmp(at + 4, &v, 4) == 0,
			 "an Encoded-Group or -Source is IPv4, its flags, its mask, and the address masked");
	break;
    }
    free(buf);
}

void proof_put_bytes(void)
{
    struct pim_writer w, before;
    uint8_t *buf, *src;
    size_t len, off, n;
    int ok;

    len = nondet_size_t();
    __CPROVER_assume(len <= SENDBUF_MAX);
    buf = malloc(len);
    __CPROVER_assume(buf != NULL);

    n = nondet_size_t();
    __CPROVER_assume(n <= MAXLEN);
    src = malloc(n);
    __CPROVER_assume(src != NULL);

    off = nondet_size_t();
    __CPROVER_assume(off <= len);
    w.p    = buf + off;
    w.left = len - off;
    w.full = nondet_int() ? 1 : 0;
    before = w;

    ok = pim_put_bytes(&w, src, n);
    __CPROVER_assert(w.p + w.left == buf + len, "the writer stays on its buffer");
    if (ok) {
	__CPROVER_assert(!before.full && n <= before.left && w.p == before.p + n,
			 "a copy that fits moves the writer by its length");
	__CPROVER_assert(memcmp(before.p, src, n) == 0, "and is the bytes it was given");
    } else {
	__CPROVER_assert(w.full && w.p == before.p && (before.full || n > before.left),
			 "and one that does not writes nothing and leaves the writer full");
    }
    free(src);
    free(buf);
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "cc-mode"
 * End:
 */
