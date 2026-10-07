/*
 * text.c - prove src/text.c over every string up to a length
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
 * SOURCE naming src/text.c or a mutant of it.  Text has no length field
 * to bound it, only its terminator, so every proof here is over strings of
 * any content up to MAXLEN characters, allocated at exactly their length
 * and terminator so that a byte read or written past it is a violation:
 *
 *   proof_next_word   one word out of any line, MAXLEN past the token's
 *                     size so that a word too long for it is among them
 *   proof_chomp       the newlines off the end of any string
 *   proof_strip       a matched prefix and its blanks off any command --
 *                     not run by run.sh: strspn() and memmove() of a length
 *                     the checker cannot know cost 1.9G and more than ten
 *                     minutes at eight characters, and written as index
 *                     loops still 2.3G at eight and over 4G at sixteen.  Its
 *                     only arithmetic is cmd + len, under a precondition its
 *                     two callers meet, and fuzz_ipc exercises it.
 *
 * What the callers rely on, beside memory safety: the word handed back is
 * terminated and no longer than TEXT_WORD_MAX, holds no blank, and the line
 * moves forward without leaving it; a chomped string is the string with no
 * newline at its end; a stripped command is what followed the prefix and
 * its blanks.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include SOURCE

#ifndef MAXLEN
#define MAXLEN 48
#endif

size_t nondet_size_t(void);

void proof_next_word(void);
void proof_chomp(void);
void proof_strip(void);

/* A string of any bytes, n of them before its terminator, n up to max */
static char *string(size_t *n, size_t max)
{
    char *s;
    size_t i;

    *n = nondet_size_t();
    __CPROVER_assume(*n <= max);
    s = malloc(*n + 1);
    __CPROVER_assume(s != NULL);
    for (i = 0; i < *n; i++)
	__CPROVER_assume(s[i] != 0);
    s[*n] = 0;

    return s;
}

void proof_next_word(void)
{
    char *line, *s, *w;
    size_t n, k;

    line = string(&n, MAXLEN);
    s = line;
    w = next_word(&s);

    __CPROVER_assert(s >= line && s <= line + n, "the line moves forward and stays on itself");
    k = strlen(w);
    __CPROVER_assert(k <= TEXT_WORD_MAX, "a word is no longer than the token holds");
    __CPROVER_assert(k == 0 || (w[k - 1] != ' ' && w[k - 1] != '\t'), "and ends in no blank");
    free(line);
}

void proof_chomp(void)
{
    char *s, *r;
    size_t n, k;

    s = string(&n, MAXLEN);
    r = chomp(s);
    if (n == 0) {
	__CPROVER_assert(r == NULL, "an empty string is refused");
    } else {
	k = strlen(s);
	__CPROVER_assert(r == s && k <= n && (k == 0 || s[k - 1] != '\n'),
			 "the string, with no newline left at its end");
    }
    free(s);
}

void proof_strip(void)
{
    char *s;
    size_t n, len;

    s = string(&n, MAXLEN);
    len = nondet_size_t();
    __CPROVER_assume(len <= n);

    text_strip(s, len);
    __CPROVER_assert(strlen(s) <= n - len, "what is left is what followed the prefix, or less");
    free(s);
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "cc-mode"
 * End:
 */
