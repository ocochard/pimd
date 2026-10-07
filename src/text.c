/*
 * text.c - the words of a pimd.conf line and of a pimctl command
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
 * The hand-written pointer walks over text that pimd and pimctl have:
 * next_word(), which every parse_*() of src/config.c splits a line with,
 * and the trimming of a pimctl command in src/ipc.c and src/pimctl.c.  Both
 * have had a bug of the kind such walks have -- a word of exactly the
 * token's size returned unterminated, a run of newlines trimmed off the
 * front of its buffer -- and this file includes libc and text.h and nothing
 * else, so that test/cbmc/text.c proves them over every string up to a
 * length.
 */

#include <errno.h>
#include <string.h>

#include "text.h"

/*
 * The next word of *s, lowercased, in a buffer of its own that the next
 * call writes over, and *s moved past it.  Spaces and tabs separate words,
 * and a newline or a '#' ends the line.  A word longer than TEXT_WORD_MAX
 * is cut there, and what is left of it is the next word.
 */
char *next_word(char **s)
{
    size_t i = 0;
    char *w;
    static char token[TEXT_WORD_MAX + 1];

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
		/* ASCII only, which is what isascii() && isupper() was:
		 * written out, because <ctype.h> is a locale table on some
		 * systems and nothing a checker can reason about */
		if (**s >= 'A' && **s <= 'Z')
		    token[i++] = (char)(**s - 'A' + 'a');
		else
		    token[i++] = **s;
		(*s)++;
	}
    }

    return token;
}

/*
 * The newlines at the end of str, gone.  Counted from the end by length
 * rather than walked with a pointer, which had to step to one before the
 * string to see that the string was all newlines -- a pointer the language
 * does not let a program form.
 */
char *chomp(char *str)
{
    size_t n;

    if (!str || !*str) {
	errno = EINVAL;
	return NULL;
    }

    n = strlen(str);
    while (n > 0 && str[n - 1] == '\n')
	str[--n] = 0;

    return str;
}

/*
 * The first len characters of cmd, and the spaces, tabs and newlines
 * behind them, gone, the rest moved to the front and chomped.  len is at
 * most strlen(cmd): it is the length of something that matched there.
 */
void text_strip(char *cmd, size_t len)
{
    char *ptr = cmd + len;

    ptr += strspn(ptr, " \t\n");
    memmove(cmd, ptr, strlen(ptr) + 1);
    chomp(cmd);
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "cc-mode"
 * End:
 */
