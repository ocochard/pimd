/*
 * fuzz_ipc - the pimctl command parser, one command per call
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
 * src/ipc.c was the last parser in this tree with no harness.  It is the
 * least dangerous of them -- the socket is bound under umask(0077), so a
 * client is already root and has easier things to do than corrupt this
 * daemon -- and that is the whole of why this harness is sixth rather than
 * second.  What it is not is uninteresting: the command a client sends is
 * bytes somebody else chose, and what walks them is hand-written pointer
 * arithmetic.  ipc_read() prefix-matches the text against cmds[],
 * check_detail() runs strspn() and strcspn() over what is left, strip()
 * memmove()s the remainder down over itself, and chomp() walks backwards
 * from the end -- the bound in chomp() is there because without it a
 * command of nothing but newlines walks the pointer off the front of the
 * buffer, writing as it goes.  That bug was found by reading; this is the
 * machine that would have found it.
 *
 * The input is the bytes a client writes to the socket and nothing else,
 * which is exactly what pimctl sends: one command, no trailing newline
 * (src/pimctl.c chomps it), and the daemon reads at most sizeof(cmd) - 1 of
 * them in a single read().  So an input is a text file, a crasher is
 * readable, and putting one back in front of a running daemon is
 *
 *	nc -U /var/run/pimd.sock < crash-<sha1>
 *
 * rather than anything this directory has to build.
 *
 * The entry point is ipc_handle(), which is what ipc_init() registers with
 * the event loop, for the same reason fuzz_pim calls accept_pim() rather
 * than the receive_pim_*() behind it: the prefix match, the detail
 * argument, the dispatch table, the reply and the close stay in ipc.c
 * where they are written instead of being copied into a harness that would
 * drift away from them.  It accepts a connection, so the harness has to be
 * a real client on a real socket:
 *
 *   - The listening socket is the harness's own rather than ipc_init()'s.
 *     What ipc_init() adds is a path in /var/run, a mode, and a
 *     registration with an event loop no harness has -- none of it the
 *     thing under test -- and what it costs is the buffer sizes below,
 *     which it has no reason to set and this harness cannot do without.
 *
 *   - The whole reply has to fit in the socket buffers, because the only
 *     reader is this file and it reads after ipc_handle() has returned.  A
 *     reply that did not fit would leave ipc_write() waiting for a reader
 *     that cannot run -- forever, or spinning on EAGAIN, the accepted
 *     socket inheriting O_NONBLOCK on the BSDs and not on Linux.  The
 *     longest reply this router produces is `show pim detail`, measured at
 *     2390 bytes, and an input cannot lengthen one -- what the show_*()
 *     print is the router's state and not the command.  FreeBSD's default
 *     unix-domain buffer is 8K (net.local.stream.sendspace) and Linux's
 *     some 200K, so raising both ends of both sockets to 256K leaves two
 *     orders of magnitude between the two numbers and the question stops
 *     being one.
 *
 * The router behind the parser is fuzz/router.c, the same one fuzz_pim and
 * fuzz_igmp use, and here it is built once rather than per input.  That is
 * legitimate for exactly one reason: no command adds protocol state.  The
 * show_*() are readers, `debug` and `log` move two globals this file puts
 * back, and `restart` and `kill` are main.c's, stubbed in fuzz/stubs.c --
 * so the table an input prints is the same table the last one printed.  Add
 * a command that changes the router and this harness has to move to the
 * fuzz_router_reset() / fuzz_router_build() pair the other two call.  What
 * building once buys is that growth per input belongs to ipc.c: there is no
 * rebuild underneath it to hide a temporary file or a reply buffer that is
 * never given back.
 *
 * Putting `debug` and `loglevel` back is not tidiness either.  An input of
 * `debug all` leaves every input after it writing the daemon's log to
 * stderr, which is a hundredfold slowdown that looks like nothing being
 * wrong -- and it would make the run depend on the order libFuzzer happened
 * to try things in.
 *
 * Did an input reach a handler at all?  ipc.c logs nothing -- the two
 * logit(LOG_DEBUG) lines in it are commented out -- so FUZZ_DEBUG=1, which
 * is the daemon's logging everywhere else in this directory, prints the
 * reply here instead.  That is the positive control for a seed: a command
 * that matched no row of cmds[] answers "No such command", one that
 * matched prints a table, and both are silent without it.
 *
 * What this cannot see is the daemon's own end of the socket: ipc_init()'s
 * bind, its 0700 mode and its non-blocking listener, and priv_ipc_socket(),
 * the separated daemon's version of all three.  Nothing separates
 * privileges here, so ipc_show() gets tempfile() rather than the descriptor
 * a privileged parent would pass back, and the privsep scenario of
 * test/lab.sh is what asserts that half.
 *
 * Running it:
 *
 *   ./configure --enable-fuzz CC=clang				\
 *       CFLAGS="-g -O1 -fno-omit-frame-pointer -fno-strict-aliasing	\
 *               -fsanitize=address,undefined"			\
 *       LDFLAGS="-fsanitize=address,undefined"
 *   make
 *   mkdir work
 *   test/fuzz_ipc -max_len=1024 work test/fuzz/corpus/ipc
 *
 * The scratch directory first: libFuzzer writes what it keeps into the
 * first corpus directory it is given, and the committed one holds seeds and
 * crashers rather than a hunt's output.  A crash leaves its input in
 * crash-<sha1>, and
 *
 *   test/fuzz_ipc_replay crash-<sha1>
 *
 * replays that one file with no fuzzer involved, which is also how `make
 * check` runs the whole corpus as a regression test.
 */

#include "defs.h"

#include "router.h"
#include "topology.h"

#include <limits.h>

#ifndef CONTINUE_ON_ERROR
#error "The fuzz harnesses need --disable-exit-on-error: logit(LOG_ERR) exits"
#endif

/*
 * Longer than ipc_handle()'s own buffer, so that a command it has to
 * truncate is an input this can produce, and short enough that libFuzzer
 * spends its time in ipc.c rather than in memcpy().
 */
#define FUZZ_MAX_SIZE	2048

/* Room for every reply this router can produce, see the header comment */
#define FUZZ_SOCKBUF	(256 * 1024)

static char fuzz_sock_path[PATH_MAX];
static int  fuzz_listen = -1;

/* What fuzz_router_init() chose, and what an input is allowed to move */
static int  fuzz_debug;
static int  fuzz_loglevel;

/* FUZZ_DEBUG=1, which here means "show me the reply" */
static int  fuzz_verbose;

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static void fuzz_unlink(void)
{
	if (fuzz_listen != -1)
		close(fuzz_listen);
	if (fuzz_sock_path[0])
		unlink(fuzz_sock_path);
}

/*
 * Both directions of both ends: an accepted socket takes the listening
 * socket's buffer sizes, and which end's the kernel consults when a write
 * has to wait is not the same on Linux as on the BSDs.  The kernel clamps
 * to its own maximum without saying so, which is why the header comment
 * argues the sizes rather than this trusting them.
 */
static void fuzz_sockbuf(int sd)
{
	int size = FUZZ_SOCKBUF;

	(void)setsockopt(sd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size));
	(void)setsockopt(sd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
}

static socklen_t fuzz_sockaddr(struct sockaddr_un *sun)
{
	memset(sun, 0, sizeof(*sun));
#ifdef HAVE_SOCKADDR_UN_SUN_LEN
	sun->sun_len = 0;	/* <- correct length is set by the OS */
#endif
	sun->sun_family = AF_UNIX;
	strlcpy(sun->sun_path, fuzz_sock_path, sizeof(sun->sun_path));

	return offsetof(struct sockaddr_un, sun_path) + strlen(sun->sun_path);
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	struct sockaddr_un sun;
	const char *tmp;
	socklen_t len;
	int fd;

	(void)argc;
	(void)argv;

	/* The pair every harness calls, once here rather than per input:
	 * fuzz_router_reset() is also what makes the routing table exist --
	 * init_pim_mrt() is inside it -- so build without it walks a list
	 * that was never initialised.
	 */
	fuzz_router_init("fuzz_ipc");
	fuzz_router_reset();
	fuzz_router_build();

	fuzz_debug    = debug;
	fuzz_loglevel = loglevel;
	fuzz_verbose  = getenv("FUZZ_DEBUG") ? 1 : 0;

	tmp = getenv("TMPDIR");
	if (!tmp || !*tmp)
		tmp = "/tmp";
	snprintf(fuzz_sock_path, sizeof(fuzz_sock_path), "%s/pimd-fuzz-ipc-XXXXXX", tmp);

	/* mkstemp() for the name rather than the file: two harnesses on one
	 * machine must not share a socket, and bind() wants the node not to
	 * exist yet.
	 */
	fd = mkstemp(fuzz_sock_path);
	if (fd == -1) {
		perror("mkstemp");
		exit(1);
	}
	close(fd);
	unlink(fuzz_sock_path);
	atexit(fuzz_unlink);

	if (strlen(fuzz_sock_path) >= sizeof(sun.sun_path)) {
		fprintf(stderr, "TMPDIR is too long for a UNIX socket path: %s\n",
			fuzz_sock_path);
		exit(1);
	}

	fuzz_listen = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fuzz_listen == -1) {
		perror("socket");
		exit(1);
	}

	/* Blocking, unlike ipc_init()'s: there is one client, it has already
	 * written everything it is going to write, and a non-blocking
	 * accepted socket turns a reply that has to wait into a spin rather
	 * than into a wait.
	 */
	len = fuzz_sockaddr(&sun);
	if (bind(fuzz_listen, (struct sockaddr *)&sun, len) == -1 ||
	    listen(fuzz_listen, 1) == -1) {
		perror("bind");
		exit(1);
	}

	fuzz_sockbuf(fuzz_listen);

	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct sockaddr_un sun;
	char junk[4096];
	socklen_t len;
	ssize_t num;
	int client;

	if (size > FUZZ_MAX_SIZE)
		return 0;

	/* A connection per input, ipc_handle() closing the one it accepts.
	 * A failure below is this harness being broken rather than an input
	 * being interesting, and a harness that quietly tests nothing is the
	 * failure worth being loud about.
	 */
	client = socket(AF_UNIX, SOCK_STREAM, 0);
	if (client == -1) {
		perror("socket");
		exit(1);
	}
	fuzz_sockbuf(client);

	len = fuzz_sockaddr(&sun);
	if (connect(client, (struct sockaddr *)&sun, len) == -1) {
		perror("connect");
		exit(1);
	}

	if (size && write(client, data, size) != (ssize_t)size) {
		perror("write");
		exit(1);
	}

	/* The client is done talking, so the daemon's read() ends at the
	 * bytes of the input instead of waiting for more.  An empty input is
	 * a client that connected and said nothing, which is the IPC_OK arm
	 * of ipc_handle() and a shape worth having.
	 */
	if (shutdown(client, SHUT_WR) == -1) {
		perror("shutdown");
		exit(1);
	}

	ipc_handle(fuzz_listen);

	/* The reply, which went into the socket buffer while ipc_handle()
	 * ran.  Nothing here reads it for content, but printing it is the
	 * only way to tell an input that reached a handler from one the
	 * prefix match turned back, ipc.c logging neither.
	 */
	while ((num = read(client, junk, sizeof(junk))) > 0) {
		if (fuzz_verbose)
			fwrite(junk, 1, (size_t)num, stderr);
	}
	close(client);

	/* `debug` and `log` are commands, so an input can turn the daemon's
	 * logging on for every input after it; the header comment says what
	 * that costs.
	 */
	debug    = fuzz_debug;
	loglevel = fuzz_loglevel;

	return 0;
}
