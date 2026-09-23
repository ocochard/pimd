#!/bin/sh
# Replay the fuzz corpus through the harnesses, as a test
#
# This is the one entry of TESTS, and only in a build configured
# --enable-fuzz.  Everything else in test/ wants root and vnet jails or
# named netns; replaying a corpus wants nothing -- no fuzzer, no clang, no
# network, no privileges -- so it runs wherever `make check` runs.
#
# What it is for is regression rather than discovery: every input the
# fuzzer ever found interesting, and every crasher it ever produced, is
# committed under fuzz/corpus/ and replayed here.  A bug that comes back
# then fails the test suite instead of waiting for somebody to remember to
# fuzz.  The verdict is the harness's own behaviour, so build the tree with
# -fsanitize=address,undefined or this only proves the parsers do not
# segfault.
#
# Exits 77, automake's "skipped", when no harness was built.

set -u

: "${srcdir:=.}"

rc=0
found=0

for h in config pim igmp ipc; do
	bin="./fuzz_${h}_replay"
	dir="$srcdir/fuzz/corpus/$h"

	[ -x "$bin" ] || continue

	if [ ! -d "$dir" ]; then
		echo "$bin: no corpus at $dir"
		rc=1
		continue
	fi

	found=1
	echo "== $bin over $dir"
	"$bin" "$dir" || rc=1
done

if [ "$found" -eq 0 ]; then
	echo "no fuzz harness in this build, skipping"
	exit 77
fi

exit $rc
