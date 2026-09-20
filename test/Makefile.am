EXTRA_DIST         = README.md igmpv3.c mping.c pimsend.c
# Not in TESTS: needs root and FreeBSD vnet jails or Linux named netns, see the script header
EXTRA_DIST        += lab.sh lab-freebsd.sh lab-linux.sh
# Not in TESTS either: needs bhyve and a licensed Arista vEOS image on top
EXTRA_DIST        += freebsd-interop.sh veos-bhyve.sh
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
EXTRA_DIST        += fuzz/corpus/config/minimal.conf		\
		     fuzz/corpus/config/sample.conf		\
		     fuzz/corpus/config/phyint.conf		\
		     fuzz/corpus/config/anycast-rp.conf		\
		     fuzz/corpus/config/limits.conf		\
		     fuzz/corpus/config/ssm-acl.conf

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
endif
endif

# No other TESTS: every script that was here is a scenario of lab.sh now,
# which asserts the same and more and runs on FreeBSD as well, but wants
# real root and named namespaces -- neither of which automake's
# `unshare -mrun` can give it.  CI runs it as a job of its own on both
# systems.
