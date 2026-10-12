EXTRA_DIST         = README.md autorp.c igmpv3.c mping.c pimsend.c
# Not in TESTS: needs root and FreeBSD vnet jails or Linux named netns, see the script header
EXTRA_DIST        += lab.sh lab-freebsd.sh lab-linux.sh
# Not in TESTS: cbmc(1) is not a build dependency, and a proof takes minutes
EXTRA_DIST        += cbmc/run.sh cbmc/autorp.c cbmc/pim.c cbmc/igmp.c \
		     cbmc/encode.c cbmc/text.c cbmc/assert.c cbmc/roundtrip.c
# Nor this one: needs root and FRR installed beside pimd, see the script header
EXTRA_DIST        += frr-interop.sh
# Not in TESTS either: needs bhyve and a licensed Arista vEOS image on top
EXTRA_DIST        += freebsd-interop.sh veos-bhyve.sh
# Reports over a --enable-coverage build, runs nothing itself
EXTRA_DIST        += coverage.sh
CLEANFILES         = *~ *.trs *.log

AUTOMAKE_OPTIONS   = subdir-objects

AM_CFLAGS          = @PIMD_CFLAGS@
AM_LDFLAGS         = @PIMD_LDFLAGS@
AM_CPPFLAGS        = -I$(top_srcdir)/src -I$(top_srcdir)/include

noinst_PROGRAMS    = mping igmpv3 pimsend autorp
mping_SOURCES      = mping.c
igmpv3_SOURCES     = igmpv3.c
pimsend_SOURCES    = pimsend.c
autorp_SOURCES     = autorp.c

# The corpus is dist'ed whether or not this build has the harnesses, so a
# tarball can be fuzzed and, more to the point, so the replay test below
# has something to replay wherever it is unpacked.
EXTRA_DIST        += fuzz-corpus.sh fuzz/README.md
# The OSS-Fuzz integration, canonical here rather than in google/oss-fuzz
EXTRA_DIST        += fuzz/oss-fuzz/build.sh fuzz/oss-fuzz/project.yaml	\
		     fuzz/oss-fuzz/Dockerfile

# The corpus itself goes in by directory rather than by name: a list kept by
# hand fell behind the files committed beside it.  Only the extensions the
# seeds use are taken, so the hash-named inputs a hunt writes and the
# crash-* files libFuzzer leaves behind stay out of a tarball even when
# they sit in the same directory.
dist-hook:
	@for f in `cd $(srcdir) && find fuzz/corpus -type f \( -name '*.bin' \
		  -o -name '*.txt' -o -name '*.conf' \) | sort`; do		\
		$(MKDIR_P) $(distdir)/`dirname $$f` &&				\
		cp -p $(srcdir)/$$f $(distdir)/$$f || exit 1;			\
	done

# The fuzz harnesses, --enable-fuzz.  Two programs out of one harness: the
# replay driver, which needs no fuzzer and is what `make check` runs over
# the corpus, and the libFuzzer one, built only where the compiler has it.
# Both link the daemon's own objects out of src/libpimd.a rather than
# recompiling them, so what they test is what pimd ships.
if ENABLE_FUZZ
FUZZ_LDADD         = $(top_builddir)/src/libpimd.a $(LIBS)

noinst_PROGRAMS   += fuzz_config_replay
fuzz_config_replay_SOURCES = fuzz/fuzz_config.c fuzz/stubs.c fuzz/replay.c
fuzz_config_replay_LDADD   = $(FUZZ_LDADD)

# The PIM parsers.  fuzz/mrib.c defines k_req_incoming(), so neither
# netlink.c nor routesock.c is pulled out of libpimd.a and an RPF lookup
# answers the same on every machine; see its header.
FUZZ_ROUTER        = fuzz/router.c fuzz/router.h fuzz/mrib.c	\
		     fuzz/topology.h fuzz/stubs.c

noinst_PROGRAMS   += fuzz_pim_replay
fuzz_pim_replay_SOURCES = fuzz/fuzz_pim.c $(FUZZ_ROUTER) fuzz/replay.c
fuzz_pim_replay_LDADD   = $(FUZZ_LDADD)

# The IGMP socket: igmp_proto.c, trace.c, and the kernel upcall path of
# route.c, which arrives on the same socket with an IP protocol of zero.
noinst_PROGRAMS   += fuzz_igmp_replay
fuzz_igmp_replay_SOURCES = fuzz/fuzz_igmp.c $(FUZZ_ROUTER) fuzz/replay.c
fuzz_igmp_replay_LDADD   = $(FUZZ_LDADD)

# The Auto-RP datagram parser, which walks two counts and a mask length
# off the wire with no neighbour relationship behind any of it.
noinst_PROGRAMS   += fuzz_autorp_replay
fuzz_autorp_replay_SOURCES = fuzz/fuzz_autorp.c $(FUZZ_ROUTER) fuzz/replay.c
fuzz_autorp_replay_LDADD   = $(FUZZ_LDADD)

# The pimctl socket: ipc.c's command parser and the show_*() it dispatches
# to, which need the same router to have something to print.
noinst_PROGRAMS   += fuzz_ipc_replay
fuzz_ipc_replay_SOURCES = fuzz/fuzz_ipc.c $(FUZZ_ROUTER) fuzz/replay.c
fuzz_ipc_replay_LDADD   = $(FUZZ_LDADD)

# The one test in TESTS, and only in a fuzz build: everything else here
# wants root and namespaces (see above), while replaying a corpus wants
# nothing at all.
TESTS              = fuzz-corpus.sh

if HAVE_LIBFUZZER
noinst_PROGRAMS   += fuzz_config
fuzz_config_SOURCES = fuzz/fuzz_config.c fuzz/stubs.c
fuzz_config_CFLAGS  = $(AM_CFLAGS) -fsanitize=fuzzer
fuzz_config_LDFLAGS = $(AM_LDFLAGS) -fsanitize=fuzzer
fuzz_config_LDADD   = $(FUZZ_LDADD)

noinst_PROGRAMS   += fuzz_pim
fuzz_pim_SOURCES    = fuzz/fuzz_pim.c $(FUZZ_ROUTER)
fuzz_pim_CFLAGS     = $(AM_CFLAGS) -fsanitize=fuzzer
fuzz_pim_LDFLAGS    = $(AM_LDFLAGS) -fsanitize=fuzzer
fuzz_pim_LDADD      = $(FUZZ_LDADD)

noinst_PROGRAMS   += fuzz_igmp
fuzz_igmp_SOURCES   = fuzz/fuzz_igmp.c $(FUZZ_ROUTER)
fuzz_igmp_CFLAGS    = $(AM_CFLAGS) -fsanitize=fuzzer
fuzz_igmp_LDFLAGS   = $(AM_LDFLAGS) -fsanitize=fuzzer
fuzz_igmp_LDADD     = $(FUZZ_LDADD)

noinst_PROGRAMS   += fuzz_autorp
fuzz_autorp_SOURCES = fuzz/fuzz_autorp.c $(FUZZ_ROUTER)
fuzz_autorp_CFLAGS  = $(AM_CFLAGS) -fsanitize=fuzzer
fuzz_autorp_LDFLAGS = $(AM_LDFLAGS) -fsanitize=fuzzer
fuzz_autorp_LDADD   = $(FUZZ_LDADD)

noinst_PROGRAMS   += fuzz_ipc
fuzz_ipc_SOURCES    = fuzz/fuzz_ipc.c $(FUZZ_ROUTER)
fuzz_ipc_CFLAGS     = $(AM_CFLAGS) -fsanitize=fuzzer
fuzz_ipc_LDFLAGS    = $(AM_LDFLAGS) -fsanitize=fuzzer
fuzz_ipc_LDADD      = $(FUZZ_LDADD)
endif
endif

# No other TESTS: every script that was here is a scenario of lab.sh now,
# which asserts the same and more and runs on FreeBSD as well, but wants
# real root and named namespaces -- neither of which automake's
# `unshare -mrun` can give it.  CI runs it as a job of its own on both
# systems.
