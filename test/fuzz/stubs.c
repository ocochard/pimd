/*
 * stubs - what main.c would have defined
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
 * A harness links every object of the daemon except main.c, whose main() a
 * fuzzer supplies itself, so the globals and the three functions main.c
 * holds have to come from somewhere.  Here, as the emptiest thing that
 * still compiles: nothing below is reached by a parser, and a harness that
 * did reach them would be testing the select() loop rather than a parser.
 *
 * They are declared in src/defs.h like every other symbol that crosses a
 * file in this tree, so this file writes no extern of its own.
 */

#include "defs.h"

uint32_t virtual_time = 0;
char	*ident	      = NULL;
char	*config_file  = NULL;
char	*prognm	      = NULL;
char	 versionstring[100] = "pimd fuzz harness";

int	 do_vifs       = 1;
int	 retry_forever = 0;
int	 mrt_table_id  = 0;

struct rp_hold *g_rp_hold = NULL;

int register_input_handler(int fd, ihfunc_t func)
{
	(void)fd;
	(void)func;

	return 0;
}

int daemon_restart(char *buf, size_t len)
{
	(void)buf;
	(void)len;

	return 0;
}

int daemon_kill(char *buf, size_t len)
{
	(void)buf;
	(void)len;

	return 0;
}
