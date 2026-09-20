#!/bin/sh
# run.sh - run rules/security.cocci over the daemon's sources
#
# Two passes, and both have to hold:
#
#   1. control.c has to light up every rule.  spatch(1) is silent both when
#      a rule finds nothing and when a rule is broken, so a ruleset that
#      was never proven to fire is a ruleset that proves nothing.  Any rule
#      missing from the control pass fails the run.
#   2. src/ and lib/ have to stay silent.  The tree is clean as of this
#      writing, so anything printed is a regression.
#
# Needs spatch(1) from Coccinelle: pkg install coccinelle on FreeBSD,
# apt-get install coccinelle on Debian and Ubuntu.  Exits 77 (the automake
# "skipped" status) when it is not installed, so this is not a hard build
# dependency.

set -eu

top=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cocci="$top/rules/security.cocci"
ctrl="$top/rules/control.c"

if ! command -v spatch >/dev/null 2>&1; then
	echo "rules: spatch(1) not found, skipping the Coccinelle checks" >&2
	exit 77
fi

# spatch(1) honours only the last --dir on its command line, silently
# dropping any earlier one, so walk the directories one at a time.
run() {
	spatch --very-quiet --no-show-diff --timeout 300		\
	       -I "$top/src" -I "$top/include" -I "$top"		\
	       --sp-file "$cocci" "$@" 2>&1
}

run_tree() {
	for dir in src lib; do
		run --dir "$top/$dir"
	done
}

# 1. Every rule fires on the control file.  Each message carries its rule
#    name in brackets, so the two lists are directly comparable.
rules=$(sed -n 's/^@\([a-z][a-z_]*\)\( exists\)\{0,1\}@$/\1/p' "$cocci" | sort -u)
fired=$(run "$ctrl" | sed -n 's/.*: \[\([a-z_]*\)\] .*/\1/p' | sort -u)
missing=$(echo "$rules" | grep -vxF "$fired" || true)
if [ -n "$missing" ]; then
	echo "rules: these rules did not fire on control.c:" >&2
	echo "$missing" | sed 's/^/    /' >&2
	echo "rules: a rule that matches nothing here is broken, not clean;" >&2
	echo "rules: add its counter-example to rules/control.c" >&2
	exit 1
fi
echo "rules: all $(echo "$rules" | wc -l | tr -d ' ') rules fire on control.c"

# 2. The tree is silent.
out=$(run_tree)
if [ -n "$out" ]; then
	echo "rules: Coccinelle found something:" >&2
	echo "$out" >&2
	exit 1
fi
echo "rules: src/ and lib/ are clean"
