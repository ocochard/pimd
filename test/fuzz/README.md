Fuzz harnesses
==============

The parsers of pimd, called in-process with generated input, under the
sanitizers.  What each harness is and what it takes care of is in the
header comment of its own file; this is the map.

| Harness            | Entry point                                          | Corpus              |
|--------------------|------------------------------------------------------|---------------------|
| `fuzz_config.c`    | `config_phyints_from_file()`, `config_vifs_from_file()` | `corpus/config/` |
| `fuzz_pim.c`       | `accept_pim()`, so every `receive_pim_*()` behind it  | `corpus/pim/`       |
| `fuzz_igmp.c`      | `accept_igmp()`: IGMP, mtrace, and the kernel upcalls | `corpus/igmp/`      |
| `fuzz_ipc.c`       | `ipc_handle()`: the pimctl command parser and `show_*()` | `corpus/ipc/`     |
| `fuzz_autorp.c`    | `accept_autorp()`: the Auto-RP datagram parser        | `corpus/autorp/`    |

`stubs.c` supplies what `main.c` would have defined, since a harness brings
its own `main()`, and `replay.c` is a `main()` of its own for builds without
libFuzzer: it hands every file it is given to the harness once, which is how
`make check` turns the corpus into a regression test through
`../fuzz-corpus.sh`.

`router.c`, `topology.h` and `mrib.c` are the router the packets arrive at,
shared by `fuzz_pim`, `fuzz_igmp`, `fuzz_ipc` and `fuzz_autorp`: two interfaces, three
neighbours, a DR election this router wins on one link and loses on the
other, an RP set with one range of its own and one a neighbour is the RP
for, a (\*,G) and an (S,G).  `router.c`'s header says
which part of the daemon each piece stands in for; `mrib.c` defines
`k_req_incoming()` itself, which is why neither `netlink.c` nor
`routesock.c` is linked into those harnesses and why an input gets the same
answer on every machine.

None of that is decoration.  A parser reached with nothing behind it turns
back within a few lines: the state is what makes the rest of the function
exist, and getting it wrong shows up as a coverage number rather than as a
failure.  The `INITED` line of a hunt is the measurement -- see below.

Building and running
--------------------

```sh
./configure --enable-fuzz CC=clang					\
    CFLAGS="-g -O1 -fno-omit-frame-pointer -fno-strict-aliasing		\
            -fsanitize=address,undefined"				\
    LDFLAGS="-fsanitize=address,undefined"
make
mkdir work
test/fuzz_config -max_len=4096 work test/fuzz/corpus/config	# hunt
test/fuzz_pim -max_len=512 work test/fuzz/corpus/pim		# hunt
test/fuzz_igmp -max_len=512 work test/fuzz/corpus/igmp		# hunt
test/fuzz_ipc -max_len=1024 work test/fuzz/corpus/ipc		# hunt
test/fuzz_autorp -max_len=512 work test/fuzz/corpus/autorp	# hunt
make check							# replay all five
```

The scratch directory comes first on purpose: libFuzzer writes every new unit
it keeps into the *first* corpus directory it is given, so naming
`test/fuzz/corpus/...` alone drops hundreds of files into the source tree.

`--enable-fuzz` implies `--disable-exit-on-error`, because `logit(LOG_ERR)`
calls `exit(-1)` and a fuzzer reads that as a crash on the first input pimd
merely refuses. It also implies `--enable-test`, test/ being where this
lives. Without clang only the replay drivers are built; `configure` says
which in its summary.

A find leaves `crash-<sha1>` in the working directory. Replay it with the
matching `_replay` driver -- `test/fuzz_igmp_replay crash-<sha1>` and its
kind -- fix the bug, then commit the file into the matching `corpus/`
directory so it is asserted from then on. Crashers are what this
directory is for; a hunt's own corpus is not committed, and does not need to
be. The seeds here are the readable ones, one per shape of input, and a full
corpus rebuilds from them fast:

```sh
test/fuzz_config -max_len=4096 -max_total_time=900 work/          # a hunt
test/fuzz_config -merge=1 -max_len=4096 minimized/ work/          # the useful part of it
```

Measured on this tree: fifteen minutes of one process reached 743 edges of
`config.c`, and `-merge=1` reduced what it kept to 175 files of 88K. Keep
that outside the repository unless something in it is worth asserting.
`fuzz_pim` runs at some ten thousand executions a second under
`-fsanitize=address,undefined` and `fuzz_igmp` at seven and a half, the
difference being what a membership report sets in motion (measured over
60k runs each, poisoning included -- it costs nothing worth naming). Their committed seeds reach 2651
and 2828 edges on their own -- libFuzzer prints that as the `INITED` line,
and it is the positive control for a corpus and for the router behind it: a
harness whose state is wrong, or a seed refused before it is parsed, shows up
as a number well below that and as nothing else. A minute of mutation from
them reaches about 3650 and 3700, a quarter of an hour on four workers 3865.
Most of that is the protocol code; the rest is the `config.c` the per-input
reset parses again and the routing table underneath.

`fuzz_ipc` runs at some fifty thousand executions a second, a connected
socket and a reply per input included, and its `INITED` number is not
comparable with the two above: it builds the router once, in
`LLVMFuzzerInitialize()`, and libFuzzer resets the counters before the first
input, so the 702 edges its seeds reach are `ipc.c` and the `show_*()`
behind it and nothing else. A minute of mutation from them reaches 776.

The PIM corpus
--------------

An input is one PIM message and nothing else, from the PIM header on, which
is exactly what `pimsend -b FILE` sends and what `pimsend -o FILE` writes.
So the seeds are made by the tree's own message builder rather than by hand,
one per message type and per shape worth starting from:

```sh
test/pimsend hello -o test/fuzz/corpus/pim/hello.bin
test/pimsend join -w -g 239.1.1.1 -r 10.0.1.1 -u 10.0.1.1 -o test/fuzz/corpus/pim/join-wc.bin
test/pimsend register -N -g 239.1.1.1 -s 10.0.1.9 -o test/fuzz/corpus/pim/register-null.bin
test/pimsend bootstrap -u 192.0.2.5 -r 192.0.2.5 -p 200 -g 224.0.0.0 -m 4	\
    -o test/fuzz/corpus/pim/bootstrap.bin
```

The round trip closes the other way, a crasher put on the wire against a
running daemon in a lab:

```sh
test/pimsend -i 10.0.1.2 hello -b crash-<sha1>
```

The addresses to build a seed with are `topology.h`'s: this router and the RP
of 224.0.0.0/4 are 10.0.1.1, the senders 10.0.1.2, 10.0.1.3 and 10.0.2.2, the
source 10.0.1.9, and there are two groups -- 239.1.1.1, whose RP is this
router, and 239.2.3.4, whose RP is the neighbour 10.0.1.2, so that both
answers to "am I the RP for this" have a group to be asked about. A message
about anything else is still a useful input -- it is just one the fuzzer has
to work harder from.

A seed is worth checking rather than assuming, and the Bootstrap is why.
Built with the default priority and a BSR on one of the harness's own
subnets it is refused twice over: this router is a BSR candidate of priority
5 and wins the election, and a directly connected BSR fails the RPF check
that the message came from the next hop towards it. The parser is reached
and nothing behind it is. Priority 200 and an address the MRIB routes
through a neighbor is a seed the fuzzer can work from, which is what the
`FUZZ_DEBUG=1` run below is for.

Nothing in an input picks the sender except the Reserved byte, which pimd
ignores: its low two bits choose between the four senders and the next bit
sends a Bootstrap to this router rather than to ALL-PIM-ROUTERS. The top bit
of that byte is the one thing in it pimd does read, RFC 5059's No-Forward,
and the harness leaves it alone. The harness's header comment says why it
borrows the byte at all, and what that costs.

The IGMP corpus
---------------

An input is one IP packet, from the IP header on, because that is what the
daemon is handed and what `accept_igmp()` reads: the protocol byte tells an
IGMP message from a kernel upcall, and the header length says where the IGMP
header begins. `igmpv3 -o FILE` writes packets of that shape, header and
all, so the report seeds are built by the tree's own builder:

```sh
test/igmpv3 -i 10.0.1.2 -g 239.1.1.1 -t allow -o test/fuzz/corpus/igmp/report-v3-allow.bin 10.0.1.9
test/igmpv3 -i 10.0.1.2 -g 239.1.1.1 -v 2 -o test/fuzz/corpus/igmp/report-v2.bin
```

`-o` has to come before the positional sources, `getopt()` stopping at the
first of them.

The other seeds are not reports and no tool in the tree builds them, so they
are committed as the bytes they are. Queries, the leave and the mtrace query
are an IP header and then the IGMP one -- type, code, checksum, group -- with
a v3 query carrying four more bytes (S/QRV, QQIC, source count) and the
mtrace query sixteen, a `struct tr_query` of source, destination, response
address and a word holding the response TTL and the query id.

The three upcall seeds are the interesting ones. A kernel upcall reaches the
daemon on this same socket with an IP protocol of **zero**, and the twenty
bytes it carries are a `struct igmpmsg`, laid out the same on Linux and on
FreeBSD: two unused words, then the message type at offset 8, a zero, the vif
index at offset 10, its high byte, then the source at 12 and the group at 16.
Type 1 is IGMPMSG_NOCACHE, 2 is IGMPMSG_WRONGVIF and 3 is IGMPMSG_WHOLEPKT,
which carries the packet itself behind the header for the RP to encapsulate.
V5 and V6 of `doc/rfc7761-compliance.md` were both on that path, and it is the
one place a harness gets to say something the kernel never would.

The Auto-RP corpus
------------------

An input is the UDP payload of one Auto-RP message and nothing else -- the
IP and UDP headers are the kernel's -- which is byte for byte what
`test/autorp -o FILE` writes and what `test/autorp -b FILE` sends.  So the
seeds are built by the tree's own builder, one per shape the parser treats
differently:

```sh
test/autorp -r 10.0.1.1 -h 180 -o test/fuzz/corpus/autorp/mapping.bin 239.1.0.0/16
test/autorp -r 10.0.1.1 -h 180 -o test/fuzz/corpus/autorp/mapping-deny.bin \
    -n 239.9.0.0/16 239.0.0.0/8
test/autorp -r 10.0.1.1 -R 5 -o test/fuzz/corpus/autorp/rpcount-lies.bin 239.1.0.0/16
```

`-R` and `-G` write an RP count and a group count that do not match what
follows, which is the shape this parser has to survive: both are bytes off
the wire saying how much is there.  `-t announce` is the message type a
router that is not a mapping agent must refuse, and `-V` a version it must
refuse.

The sender is the harness's, not the message's: pimd takes it from the
kernel, and `fuzz_autorp` borrows the low two bits of the first reserved
byte -- sent as zero and ignored on reception -- to pick one of the four
senders of `topology.h`.  A crasher therefore reproduces from whichever jail
it is sent out of.

The IPC corpus
--------------

An input is the bytes a client writes to the pimctl socket: one command, no
trailing newline, which is exactly what `src/pimctl.c` sends. So the seeds
are text files and a crasher is readable, one per shape the parser treats
differently -- a `show` with a `detail` argument, an alias row (`show if`),
the two commands that take an argument of their own (`debug`, `log`) and
their `?` form, the ones that answer out of a table (`help`, `version`), one
that reaches `ipc_wrap()` (`restart`), and one that matches nothing:

```sh
printf 'show mrt detail' > test/fuzz/corpus/ipc/show-mrt-detail.txt
printf 'debug pim_jp,igmp' > test/fuzz/corpus/ipc/debug-list.txt
```

The round trip closes with any raw client, a crasher put back in front of a
running daemon:

```sh
nc -U /var/run/pimd.sock < crash-<sha1>
```

`pimctl` itself is no use for that: it translates what the user types into
the exact command the daemon matches, which is the half a crasher is not.

Did it reach a parser?
----------------------

`FUZZ_DEBUG=1` in the environment turns the daemon's own logging back on,
which is the only way to tell a harness whose state is right from one that
refuses every message at the first test -- both are silent and fast and
neither crashes:

```sh
FUZZ_DEBUG=1 test/fuzz_pim_replay test/fuzz/corpus/pim/join-sg.bin
FUZZ_DEBUG=1 test/fuzz_igmp_replay test/fuzz/corpus/igmp/upcall-wholepkt.bin
FUZZ_DEBUG=1 test/fuzz_ipc_replay test/fuzz/corpus/ipc/show-rp.txt
FUZZ_DEBUG=1 test/fuzz_autorp_replay test/fuzz/corpus/autorp/mapping-deny.bin
```

should show the prologue building neighbours, a DR and an RP set, and then
the input being parsed and acted on -- the second one all the way to a
Register this router builds for a group a neighbour is the RP of, and tries
to send. The third prints something else: `ipc.c` logs nothing at all, its
two `logit(LOG_DEBUG)` lines being commented out, so `FUZZ_DEBUG=1` makes
`fuzz_ipc` print the *reply* instead. A command that matched no row of
`cmds[]` answers "No such command", which is what a corpus of seeds nobody
checked looks like. Run it over every seed after touching anything in `router.c`,
`mrib.c` or `topology.h`: a change there can leave a seed reaching its parser
and nothing beyond, which no test reports.

MemorySanitizer
---------------

ASan and UBSan answer "did this read something it should not have?".  MSan
answers a different question -- "was this value ever written?" -- and nothing
else in this tree asks it.  A struct field an allocation left alone, a stack
variable a parser reads before it has set it, a short message read as if it
were a long one: all of that is inside a live allocation, so ASan is happy with
it, and deviations V5 and V6 of `doc/rfc7761-compliance.md` were both of that
shape.  A build is one sanitizer or the other, so this is a run of its own and
a CI job of its own (`msan` in `ci-linux.yml`).

```sh
./configure --enable-fuzz CC=clang					\
    CFLAGS="-g -O1 -fno-omit-frame-pointer -fno-strict-aliasing		\
            -fsanitize=memory -fsanitize-memory-track-origins=2"	\
    LDFLAGS="-fsanitize=memory"
make
make check                          # the four corpora
test/fuzz_pim -max_len=512 work test/fuzz/corpus/pim
```

Linux and clang only, and the instrumented libc MSan usually wants is not one
of the things this needs: the harnesses reach glibc through the interceptors
the MSan runtime ships, and nothing here calls a function that has none.  That
was the doubt worth settling before any of this was written down, and settling
it took one build.

`router.c` poisons the tail of each receive buffer for MSan as it does for
ASan, through the same `fuzz_poison()`.  Without it the boundary would not
exist here at all: the buffers are `calloc()`ed, so every byte past the packet
is a defined zero and a parser reading past a short message reads zeroes MSan
has nothing to say about.

Numbers, on this tree and with nothing found: the four corpora replay clean,
and fifteen minutes on four workers per harness found nothing either.  The
`INITED` counts are lower than the ASan/UBSan ones above -- 245, 753, 774 and
294 against 473, 2656, 2836 and 702 -- and that is UBSan rather than anything
missing: its checks are branches and branches are edges, so compare a
sanitizer's numbers with its own.

The control, because a checker that has never fired proves nothing: put a read
of one byte past the packet into `accept_pim()` --

```c
    if (recvlen > 0 && ((unsigned char *)pim_recv_buf)[recvlen + 1] == 0x5a)
	logit(LOG_DEBUG, 0, "probe");
```

-- rebuild, and `fuzz_pim_replay` over the corpus stops at
`use-of-uninitialized-value` in `accept_pim`, naming the file and the line.
Take it out again afterwards.

The end of the packet is a boundary
----------------------------------

Both receive buffers are 128K and a packet is a few dozen bytes at the front
of one, so a parser that reads past the message it was handed reads stale
bytes of the same allocation and ASan sees nothing wrong. That is exactly the
bug V5 of `doc/rfc7761-compliance.md` was -- a kernel upcall read for more
than had been delivered -- and it would have been invisible to a hunt of any
length. So `router.c` poisons the rest of the buffer after each copy
(`__asan_poison_memory_region()`), which turns an over-read into a
use-after-poison report naming the function that did it. Nothing in the
daemon writes into either receive buffer, and `inet_cksum()` mops up an odd
trailing byte one byte at a time, so there is nothing legitimate to trip
over; without a sanitizer to write a shadow the poisoning compiles to nothing.
Under MSan it is `__msan_poison()` instead, for the reason that section gives.

Leak checking is off by default (`ASAN_OPTIONS=detect_leaks=1` asks for it,
Linux only). The harnesses free what a parse allocates, but pimd itself
keeps some of its configuration until exit, so a leak report needs reading
rather than believing. What a harness must not do is grow per input: the
state a message makes has to go back before the next one, or a hunt ends at
libFuzzer's RSS limit reporting an out-of-memory where nothing leaked.
Measure that rather than assume it -- run with `-runs=N` and `-runs=4N` and
compare `peak_rss_mb` under `-print_final_stats=1`.

OSS-Fuzz
--------

`oss-fuzz/` holds the three files Google's fleet needs, kept here rather than
only in `google/oss-fuzz` so that a harness added, or a source file moved, is
fixed in the commit that causes it: `project.yaml` (who is contacted and
which sanitizers are built), `Dockerfile` (the image, which clones this
repository), and `build.sh`, which is the whole build. The `build.sh` of
`projects/pimd/` over there is two lines and no more, so that there is
nothing to drift:

```sh
#!/bin/bash -eu
exec "$SRC/pimd/test/fuzz/oss-fuzz/build.sh"
```

That script does not use `--enable-fuzz`. The `ENABLE_FUZZ` rules of
`../Makefile.am` hardcode `-fsanitize=fuzzer`, which is libFuzzer's alone,
while OSS-Fuzz builds the same harnesses under AFL++, honggfuzz and
Centipede and says which in `$LIB_FUZZING_ENGINE`; what it configures instead
is `--disable-exit-on-error` (the half of `--enable-fuzz` that is not
optional, see above) and `--disable-hardening`, for the reason
`.github/workflows/sanitize.yml` gives, with `-fno-strict-aliasing` put back
by hand. The daemon's own objects are still `src/libpimd.a` built by `make`,
so they carry whatever instrumentation `$CFLAGS` brought.

The build runs without Docker, which is how it was checked here:

```sh
CC=clang \
CFLAGS="-g -O1 -fno-omit-frame-pointer -fsanitize=address,undefined -fsanitize=fuzzer-no-link" \
LIB_FUZZING_ENGINE="-fsanitize=fuzzer" OUT=/tmp/out \
    test/fuzz/oss-fuzz/build.sh
```

The verdict is the `INITED` line, not the exit status. Built that way and
replayed over the committed seeds with `-runs=0`, the four reach 473, 2648,
2828 and 702 edges, which is the same tree the recipe at the top of this file
builds (473, 2656, 2836, 702 -- the few edges between them are the hardening
flags this build drops). A number well below that is a build that lost the
instrumentation on the daemon's objects and kept it on the harness, which
runs at full speed and looks healthy; the same `INITED` line is what says so.
An OSS-Fuzz `address` build alone prints about a third of those, UBSan's
checks being branches and branches being edges, so compare like with like.

With Docker, the fleet's own path:

```sh
python3 infra/helper.py build_image pimd
python3 infra/helper.py build_fuzzers --sanitizer address pimd
python3 infra/helper.py check_build pimd
```

MemorySanitizer is not in `project.yaml` yet, and no longer for the reason it
was: the harnesses run clean under it here, and a `msan` job of
`ci-linux.yml` keeps them that way (see above).  What is left is the fleet's
side of it, which is a line in that file and a build nobody here can try --
OSS-Fuzz builds MSan against a sysroot of its own -- so it goes in the same
change as the `projects/pimd/` pull request rather than ahead of it.
