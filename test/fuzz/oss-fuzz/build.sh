#!/bin/bash -eu
#
# Build the three fuzz harnesses of test/fuzz/ the way OSS-Fuzz wants them
#
# This is the canonical copy: the build.sh of the projects/pimd/ directory in
# google/oss-fuzz is two lines that exec this one, so that a harness added
# here, or a source file moved, is fixed in the same commit as the change
# that caused it rather than in another repository weeks later.
#
# What OSS-Fuzz hands us is an environment, not a build system: $CC and
# $CFLAGS carry the compiler and the instrumentation for whichever engine and
# sanitizer this build is for, $LIB_FUZZING_ENGINE is what supplies the
# main() a harness does not have, and $OUT is where the binaries and their
# seed corpora go.  So the harnesses are compiled here rather than by
# test/Makefile.am, whose ENABLE_FUZZ rules hardcode -fsanitize=fuzzer and
# are therefore libFuzzer's alone; everything they link, the daemon's own
# objects in src/libpimd.a, is built by make with $CFLAGS in force.
#
# The source lists below are test/Makefile.am's, and have to stay that way:
# fuzz_config is the harness and the stubs, the other two add the router the
# packets arrive at.  A file added to FUZZ_ROUTER there is added here too.

cd "$(dirname "$0")/../../.."

# --disable-exit-on-error is not a preference: logit(LOG_ERR) calls exit(-1),
# which every fuzzer reads as a crash on the first input pimd merely refuses.
# --enable-fuzz would imply it, but it also probes -fsanitize=fuzzer and
# builds the harnesses itself, which is the part we are replacing.
#
# --disable-hardening for the reason sanitize.yml gives: -ftrivial-auto-var-init=zero
# zeroes precisely the stack residue a short-packet read would show, and
# _FORTIFY_SOURCE wraps what the sanitizer interposes.  -fno-strict-aliasing
# is in that set without being hardening -- pim.c and igmp.c cast the char *
# receive buffers to struct ip * on nearly every path -- so it goes back by
# hand, before configure, so that libpimd.a is built with it as well.
export CFLAGS="$CFLAGS -fno-strict-aliasing"

./autogen.sh
./configure --disable-hardening --disable-exit-on-error --disable-dependency-tracking
make -j"$(nproc)"

fuzz_cppflags="-I$PWD/src -I$PWD/include -I$PWD"

# Harness objects before the archive, which is what keeps netlink.c and
# routesock.c out of the link: mrib.c defines every symbol either of them
# exports to anything but main.c, so the archive members are never pulled in
# and an RPF lookup answers the same on every machine.  See its header.
for harness in config pim igmp; do
	case $harness in
	config)	sources="test/fuzz/fuzz_config.c test/fuzz/stubs.c" ;;
	*)	sources="test/fuzz/fuzz_$harness.c test/fuzz/router.c test/fuzz/mrib.c test/fuzz/stubs.c" ;;
	esac

	# shellcheck disable=SC2086  # $CFLAGS and $sources are lists
	$CC $CFLAGS $fuzz_cppflags $sources src/libpimd.a $LIB_FUZZING_ENGINE \
	    -o "$OUT/fuzz_$harness"

	# The seeds of test/fuzz/corpus/, one readable file per shape of input,
	# are what a hunt starts from here as well; the fleet keeps its own
	# corpus on top of them.
	(cd "test/fuzz/corpus/$harness" && zip -q -r "$OUT/fuzz_${harness}_seed_corpus.zip" .)
done
