EXTRA_DIST         = README.md igmpv3.c mping.c pimsend.c
# Not in TESTS: needs root and FreeBSD vnet jails or Linux named netns, see the script header
EXTRA_DIST        += lab.sh lab-freebsd.sh lab-linux.sh
# Not in TESTS either: needs bhyve and a licensed Arista vEOS image on top
EXTRA_DIST        += freebsd-interop.sh veos-bhyve.sh
# Reports over a --enable-coverage build, runs nothing itself
EXTRA_DIST        += coverage.sh
CLEANFILES         = *~ *.trs *.log

AUTOMAKE_OPTIONS   = subdir-objects

AM_CFLAGS          = @PIMD_CFLAGS@
AM_LDFLAGS         = @PIMD_LDFLAGS@
AM_CPPFLAGS        = -I$(top_srcdir)/src -I$(top_srcdir)/include

noinst_PROGRAMS    = mping igmpv3 pimsend
mping_SOURCES      = mping.c
igmpv3_SOURCES     = igmpv3.c
pimsend_SOURCES    = pimsend.c

# The corpus is dist'ed whether or not this build has the harnesses, so a
# tarball can be fuzzed and, more to the point, so the replay test below
# has something to replay wherever it is unpacked.
EXTRA_DIST        += fuzz-corpus.sh fuzz/README.md
# The OSS-Fuzz integration, canonical here rather than in google/oss-fuzz
EXTRA_DIST        += fuzz/oss-fuzz/build.sh fuzz/oss-fuzz/project.yaml	\
		     fuzz/oss-fuzz/Dockerfile
EXTRA_DIST        += fuzz/corpus/config/minimal.conf		\
		     fuzz/corpus/config/sample.conf		\
		     fuzz/corpus/config/phyint.conf		\
		     fuzz/corpus/config/anycast-rp.conf		\
		     fuzz/corpus/config/limits.conf		\
		     fuzz/corpus/config/ssm-acl.conf
EXTRA_DIST        += fuzz/corpus/pim/hello.bin			\
		     fuzz/corpus/pim/hello-addrlist.bin		\
		     fuzz/corpus/pim/join-wc.bin		\
		     fuzz/corpus/pim/join-sg.bin		\
		     fuzz/corpus/pim/prune-sg-rpt.bin		\
		     fuzz/corpus/pim/assert.bin			\
		     fuzz/corpus/pim/assert-rpt.bin		\
		     fuzz/corpus/pim/bootstrap.bin		\
		     fuzz/corpus/pim/bootstrap-noforward.bin	\
		     fuzz/corpus/pim/candrp.bin			\
		     fuzz/corpus/pim/register.bin		\
		     fuzz/corpus/pim/register-null.bin		\
		     fuzz/corpus/pim/regstop.bin
EXTRA_DIST        += fuzz/corpus/ipc/show-pim-detail.txt	\
		     fuzz/corpus/ipc/show-mrt-detail.txt	\
		     fuzz/corpus/ipc/show-status.txt		\
		     fuzz/corpus/ipc/show-rp.txt		\
		     fuzz/corpus/ipc/show-igmp-groups.txt	\
		     fuzz/corpus/ipc/show-neighbor.txt		\
		     fuzz/corpus/ipc/show-mfc.txt		\
		     fuzz/corpus/ipc/show-compat-detail.txt	\
		     fuzz/corpus/ipc/show-alias.txt		\
		     fuzz/corpus/ipc/help.txt			\
		     fuzz/corpus/ipc/version.txt		\
		     fuzz/corpus/ipc/debug-list.txt		\
		     fuzz/corpus/ipc/debug-query.txt		\
		     fuzz/corpus/ipc/log-level.txt		\
		     fuzz/corpus/ipc/restart.txt		\
		     fuzz/corpus/ipc/nonsense.txt
EXTRA_DIST        += fuzz/corpus/igmp/query-v2.bin		\
		     fuzz/corpus/igmp/query-v3.bin		\
		     fuzz/corpus/igmp/report-v2.bin		\
		     fuzz/corpus/igmp/leave-v2.bin		\
		     fuzz/corpus/igmp/report-v3-allow.bin	\
		     fuzz/corpus/igmp/report-v3-is-ex.bin	\
		     fuzz/corpus/igmp/report-v3-to-in.bin	\
		     fuzz/corpus/igmp/report-v3-many.bin	\
		     fuzz/corpus/igmp/report-v3-ssm.bin		\
		     fuzz/corpus/igmp/mtrace.bin		\
		     fuzz/corpus/igmp/upcall-nocache.bin	\
		     fuzz/corpus/igmp/upcall-wrongvif.bin	\
		     fuzz/corpus/igmp/upcall-wholepkt.bin

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
