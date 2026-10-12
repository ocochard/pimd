# Only the corpus replay below runs under `make check`, and only in a fuzz
# build.  The rest wants what automake cannot give it and runs by hand or as
# a CI job of its own: lab.sh real root and FreeBSD vnet jails or Linux named
# netns, frr-interop.sh FRR installed beside pimd, freebsd-interop.sh bhyve
# and a licensed Arista vEOS image, cbmc/run.sh cbmc(1) and minutes per
# proof; coverage.sh reports over a --enable-coverage build and runs nothing.
EXTRA_DIST         = README.md lab.sh lab-freebsd.sh lab-linux.sh	\
		     frr-interop.sh freebsd-interop.sh veos-bhyve.sh	\
		     coverage.sh cbmc/run.sh cbmc/autorp.c cbmc/pim.c	\
		     cbmc/igmp.c cbmc/encode.c cbmc/text.c cbmc/assert.c	\
		     cbmc/roundtrip.c					\
		     fuzz-corpus.sh fuzz/README.md			\
		     fuzz/oss-fuzz/build.sh fuzz/oss-fuzz/project.yaml	\
		     fuzz/oss-fuzz/Dockerfile
CLEANFILES         = *~ *.trs *.log

AUTOMAKE_OPTIONS   = subdir-objects

AM_CFLAGS          = @PIMD_CFLAGS@
AM_LDFLAGS         = @PIMD_LDFLAGS@
AM_CPPFLAGS        = -I$(top_srcdir)/src -I$(top_srcdir)/include

# One source each, named after the program, which is automake's default
noinst_PROGRAMS    = mping igmpv3 pimsend autorp

# The corpus goes in whether or not this build has the harnesses, so the
# replay test has something to replay wherever a tarball is unpacked, and by
# directory rather than by name: a list kept by hand fell behind the files
# committed beside it.  Only the extensions the seeds use are taken, so the
# hash-named inputs a hunt writes and the crash-* files libFuzzer leaves
# behind stay out of a tarball even when they sit in the same directory.
dist-hook:
	@for f in `cd $(srcdir) && find fuzz/corpus -type f \( -name '*.bin' \
		  -o -name '*.txt' -o -name '*.conf' \) | sort`; do		\
		$(MKDIR_P) $(distdir)/`dirname $$f` &&				\
		cp -p $(srcdir)/$$f $(distdir)/$$f || exit 1;			\
	done

# The fuzz harnesses, --enable-fuzz.  Two programs out of each harness: the
# replay driver, which needs no fuzzer and is what `make check` runs over
# the corpus, and the libFuzzer one, built only where the compiler has it.
# Both link the daemon's own objects out of src/libpimd.a rather than
# recompiling them, so what they test is what pimd ships.
#
#   fuzz_config  config.c, from generated pimd.conf files
#   fuzz_pim     the PIM parsers
#   fuzz_igmp    the IGMP socket: igmp_proto.c, trace.c, and the kernel
#                upcall path of route.c, which arrives on the same socket
#                with an IP protocol of zero
#   fuzz_autorp  the Auto-RP datagram parser, two counts and a mask length
#                off the wire with no neighbour relationship behind them
#   fuzz_ipc     the pimctl socket: ipc.c's command parser and the show_*()
#                it dispatches to
#
# All but fuzz_config run inside the router of fuzz/router.c.  fuzz/mrib.c
# defines k_req_incoming(), so neither netlink.c nor routesock.c is pulled
# out of libpimd.a and an RPF lookup answers the same on every machine.
if ENABLE_FUZZ
TESTS              = fuzz-corpus.sh

FUZZ_LDADD         = $(top_builddir)/src/libpimd.a $(LIBS)
FUZZ_ROUTER        = fuzz/router.c fuzz/router.h fuzz/mrib.c	\
		     fuzz/topology.h fuzz/stubs.c

noinst_PROGRAMS   += fuzz_config_replay fuzz_pim_replay fuzz_igmp_replay \
		     fuzz_autorp_replay fuzz_ipc_replay
fuzz_config_replay_SOURCES = fuzz/fuzz_config.c fuzz/stubs.c fuzz/replay.c
fuzz_pim_replay_SOURCES    = fuzz/fuzz_pim.c    $(FUZZ_ROUTER) fuzz/replay.c
fuzz_igmp_replay_SOURCES   = fuzz/fuzz_igmp.c   $(FUZZ_ROUTER) fuzz/replay.c
fuzz_autorp_replay_SOURCES = fuzz/fuzz_autorp.c $(FUZZ_ROUTER) fuzz/replay.c
fuzz_ipc_replay_SOURCES    = fuzz/fuzz_ipc.c    $(FUZZ_ROUTER) fuzz/replay.c
fuzz_config_replay_LDADD   = $(FUZZ_LDADD)
fuzz_pim_replay_LDADD      = $(FUZZ_LDADD)
fuzz_igmp_replay_LDADD     = $(FUZZ_LDADD)
fuzz_autorp_replay_LDADD   = $(FUZZ_LDADD)
fuzz_ipc_replay_LDADD      = $(FUZZ_LDADD)

if HAVE_LIBFUZZER
# Per program, so that only these five link libFuzzer's main()
FUZZER_CFLAGS      = $(AM_CFLAGS) -fsanitize=fuzzer
FUZZER_LDFLAGS     = $(AM_LDFLAGS) -fsanitize=fuzzer

noinst_PROGRAMS   += fuzz_config fuzz_pim fuzz_igmp fuzz_autorp fuzz_ipc
fuzz_config_SOURCES = fuzz/fuzz_config.c fuzz/stubs.c
fuzz_pim_SOURCES    = fuzz/fuzz_pim.c    $(FUZZ_ROUTER)
fuzz_igmp_SOURCES   = fuzz/fuzz_igmp.c   $(FUZZ_ROUTER)
fuzz_autorp_SOURCES = fuzz/fuzz_autorp.c $(FUZZ_ROUTER)
fuzz_ipc_SOURCES    = fuzz/fuzz_ipc.c    $(FUZZ_ROUTER)
fuzz_config_CFLAGS  = $(FUZZER_CFLAGS)
fuzz_pim_CFLAGS     = $(FUZZER_CFLAGS)
fuzz_igmp_CFLAGS    = $(FUZZER_CFLAGS)
fuzz_autorp_CFLAGS  = $(FUZZER_CFLAGS)
fuzz_ipc_CFLAGS     = $(FUZZER_CFLAGS)
fuzz_config_LDFLAGS = $(FUZZER_LDFLAGS)
fuzz_pim_LDFLAGS    = $(FUZZER_LDFLAGS)
fuzz_igmp_LDFLAGS   = $(FUZZER_LDFLAGS)
fuzz_autorp_LDFLAGS = $(FUZZER_LDFLAGS)
fuzz_ipc_LDFLAGS    = $(FUZZER_LDFLAGS)
fuzz_config_LDADD   = $(FUZZ_LDADD)
fuzz_pim_LDADD      = $(FUZZ_LDADD)
fuzz_igmp_LDADD     = $(FUZZ_LDADD)
fuzz_autorp_LDADD   = $(FUZZ_LDADD)
fuzz_ipc_LDADD      = $(FUZZ_LDADD)
endif
endif
