/*
 * fuzz_config - the pimd.conf parser, one file per call
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
 * The config file is the one parser in this tree that needs no network and
 * no privileges to reach: pimd reads it as root at startup and again on
 * every SIGHUP and every `pimctl restart`, and parses it by hand -- a
 * LINE_BUFSIZ line buffer, next_word() walking it, inet_parse(), strtonum(),
 * and a parse_*() per keyword, each doing its own tokenizing.  That is a lot
 * of hand-written pointer work for input that arrives from a file an
 * operator, an installer or a configuration management system wrote, and
 * nothing in the labs feeds it anything but configurations that are correct.
 *
 * So this: libFuzzer calls LLVMFuzzerTestOneInput() with the bytes of a
 * candidate pimd.conf a few tens of thousands of times a second, and the
 * sanitizers the harness is built with are what says whether the parse was
 * safe.  Fuzzing without one mostly proves that config.c does not SIGSEGV.
 *
 * Four things the harness has to get right, none of them obvious:
 *
 *   - The bytes go to a *file*, because that is the parser's interface:
 *     config_vifs_from_file() fopen()s the global config_file.  One temp
 *     file is made at startup and rewritten per call rather than created
 *     per call, file creation being slower than the parse it feeds.
 *
 *   - The vif table is fabricated first.  A phyint line only reaches its
 *     body once its address or name matches a vif (parse_phyint() in
 *     src/config.c), so with an empty table every one of them dies at the
 *     first word and most of the file is unreachable.  Two phyints and the
 *     reserved register slot is what config_vifs_from_kernel() would leave
 *     behind on the smallest machine that can route.
 *
 *   - The teardown frees what the parse allocated, and it cannot do that
 *     with zero_vif() alone: zero_vif() frees uv_addrs and uv_nbr_acl but
 *     only nulls uv_acl, which stop_vif() is what frees, and the harness
 *     has no kernel to stop a vif against.  Leave that list and a scoped
 *     address line leaks per call until libFuzzer reports an out-of-memory
 *     where the bug is a leak.  The SSM ranges, the register ACL and the
 *     anycast RP set need no such help: config_vifs_from_file() resets all
 *     three itself, on the reload path, which is why a reload does not
 *     stack them either.
 *
 *   - --enable-fuzz implies --disable-exit-on-error.  logit(LOG_ERR) calls
 *     exit(-1) unless CONTINUE_ON_ERROR is defined, and a parser that exits
 *     on the first configuration it refuses reads to a fuzzer as a crash,
 *     ending the run on input number one.  configure.ac takes care of it;
 *     the #error below is there so a hand-built harness cannot get it wrong.
 *
 * The daemon's own logging is turned down to nothing for the same reason the
 * file is reused: a parser that writes a line of stderr per input runs at a
 * thousand executions a second instead of fifty thousand.
 *
 * Running it:
 *
 *   ./configure --enable-fuzz CC=clang				\
 *       CFLAGS="-g -O1 -fno-omit-frame-pointer -fno-strict-aliasing	\
 *               -fsanitize=address,undefined"			\
 *       LDFLAGS="-fsanitize=address,undefined"
 *   make
 *   mkdir work
 *   test/fuzz_config -max_len=4096 work test/fuzz/corpus/config
 *
 * The scratch directory first: libFuzzer writes what it keeps into the first
 * corpus directory it is given, and the committed one holds seeds and
 * crashers rather than a hunt's output.  A crash leaves its input in
 * crash-<sha1>, and
 *
 *   test/fuzz_config_replay crash-<sha1>
 *
 * replays that one file through the same code with no fuzzer involved,
 * which is also how `make check` runs the whole corpus as a regression
 * test -- no clang, no root, no network.
 */

#include "defs.h"
#include "queue.h"

#include <fcntl.h>
#include <limits.h>
#include <unistd.h>

#ifndef CONTINUE_ON_ERROR
#error "The fuzz harnesses need --disable-exit-on-error: logit(LOG_ERR) exits"
#endif

/*
 * A pimd.conf larger than this is not what the parser is interesting for,
 * and libFuzzer spends its time in memcpy() rather than in config.c.
 */
#define FUZZ_MAX_SIZE	(64 * 1024)

/* The two phyints, chosen to look like the smallest machine that can route */
#define FUZZ_IF0_NAME	"fz0"
#define FUZZ_IF0_ADDR	0x0a000101	/* 10.0.1.1/24 */
#define FUZZ_IF1_NAME	"fz1"
#define FUZZ_IF1_ADDR	0x0a000201	/* 10.0.2.1/24 */
#define FUZZ_MASK24	0xffffff00

static char fuzz_path[PATH_MAX];
static int  fuzz_fd = -1;

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static void fuzz_unlink(void)
{
	if (fuzz_fd != -1)
		close(fuzz_fd);
	if (fuzz_path[0])
		unlink(fuzz_path);
}

/*
 * One phyint per subnet, and vif 0 left as config_vifs_from_kernel() leaves
 * it: reserved, addressless, the register vif not being built until after
 * the file has been read.
 */
static void fuzz_vifs_reset(void)
{
	struct uvif *v;
	vifi_t vifi;

	for (vifi = 0, v = uvifs; vifi < MAXVIFS; ++vifi, ++v) {
		struct vif_acl *acl;

		/* zero_vif() nulls this one without freeing it; stop_vif()
		 * is what frees it, and there is no kernel here to stop a
		 * vif against */
		while (v->uv_acl) {
			acl = v->uv_acl;
			v->uv_acl = acl->acl_next;
			free(acl);
		}

		zero_vif(v, FALSE);
	}

	v = &uvifs[1];
	strlcpy(v->uv_name, FUZZ_IF0_NAME, sizeof(v->uv_name));
	v->uv_lcl_addr   = htonl(FUZZ_IF0_ADDR);
	v->uv_subnetmask = htonl(FUZZ_MASK24);
	v->uv_subnet     = v->uv_lcl_addr & v->uv_subnetmask;
	v->uv_ifindex    = 1;

	v = &uvifs[2];
	strlcpy(v->uv_name, FUZZ_IF1_NAME, sizeof(v->uv_name));
	v->uv_lcl_addr   = htonl(FUZZ_IF1_ADDR);
	v->uv_subnetmask = htonl(FUZZ_MASK24);
	v->uv_subnet     = v->uv_lcl_addr & v->uv_subnetmask;
	v->uv_ifindex    = 2;

	numvifs = 3;
}

/*
 * The static RP list, which every rp-address line in the file appends to
 * and only del_static_rp() in main.c ever frees -- and which grows by an
 * entry per input even for a file that configures nothing, since
 * config_vifs_from_file() synthesizes one for each SSM range in effect.
 * Measured over 600k inputs before this was here and after: peak RSS grew
 * 39MB, and grows 12MB now, which is the corpus libFuzzer keeps rather than
 * anything of the parser's.  What the difference bought is a long hunt that
 * ends when it is told to instead of at libFuzzer's own RSS limit, reporting
 * an out-of-memory where nothing had leaked.
 */
static void fuzz_static_rp_reset(void)
{
	struct rp_hold *rph, *next;

	for (rph = g_rp_hold; rph; rph = next) {
		next = rph->next;
		free(rph);
	}

	g_rp_hold = NULL;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	const char *tmp;

	(void)argc;
	(void)argv;

	/* What main() would have set, and what logit() reads */
	prognm   = (char *)"fuzz_config";
	ident    = prognm;
	debug    = 0;
	/* logit() writes to stderr until somebody asks for syslog, and
	 * prints only what is at least as bad as loglevel, so this is the
	 * whole of the silence: WARN() is LOG_WARNING, LOG_EMERG is 0 */
	loglevel = LOG_EMERG;

	tmp = getenv("TMPDIR");
	if (!tmp || !*tmp)
		tmp = "/tmp";
	snprintf(fuzz_path, sizeof(fuzz_path), "%s/pimd-fuzz-conf-XXXXXX", tmp);

	fuzz_fd = mkstemp(fuzz_path);
	if (fuzz_fd == -1) {
		perror("mkstemp");
		exit(1);
	}

	atexit(fuzz_unlink);
	config_file = fuzz_path;

	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size > FUZZ_MAX_SIZE)
		return 0;

	if (ftruncate(fuzz_fd, 0) == -1)
		return 0;
	if (size && pwrite(fuzz_fd, data, size, 0) != (ssize_t)size)
		return 0;

	fuzz_vifs_reset();

	/* Both passes over the file, in the order init_vifs() makes them:
	 * the phyint-only one that runs while the vifs are being built from
	 * the kernel, then the whole file */
	config_phyints_from_file(1);
	config_vifs_from_file();

	/* Not only for tidiness: what the parse allocated has to go before
	 * the next call, or a leak reads as unbounded growth */
	fuzz_vifs_reset();
	fuzz_static_rp_reset();

	return 0;
}
