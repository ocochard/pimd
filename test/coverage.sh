#!/bin/sh
# coverage.sh - which lines of pimd the tests reach, and which they do not
#
# Reports over a tree configured --enable-coverage, where every object
# carries gcov instrumentation: the compiler leaves a .gcno beside each
# object, and each program writes a .gcda beside it as it exits.  This
# script does not run anything -- it turns what a run left behind into a
# table, so that "no test reaches dvmrp_proto.c" is a number rather than a
# thing somebody remembers reading.
#
#   ./configure --enable-coverage --enable-test CFLAGS="-O0 -g"
#   make
#   test/coverage.sh reset             # counters from an earlier run
#   sudo env COVERAGE=yes sh test/lab.sh -j 4 run all
#   test/coverage.sh report
#
# -O0 is not decoration: at -O2 a line count is the optimiser's idea of
# which line the code came from, and whole functions report as never
# executed because they were inlined into their only caller.
#
# Two things bound what the number means, and both are in
# doc/README-coverage.md at length:
#
#   - A .gcda is written when the program exits.  A pimd that is killed
#     with SIGKILL writes nothing, which is why COVERAGE=yes in lab.sh
#     stops the daemons with SIGTERM, and why the incarnations that
#     restart_pimd() cuts off on purpose (assert-recover, privsep) give
#     back less than the others.
#   - The unprivileged half of a separated daemon cannot write one at all:
#     the file is an open(2) the seccomp filter kills it for on Linux, at
#     a path the chroot took away on every system.  COVERAGE=yes therefore
#     runs the scenarios --no-privsep, except the privsep scenario itself,
#     where the split is the subject and only the privileged half counts.
#
# Needs gcov(1), or llvm-cov(1) for a tree built with clang: it is picked
# from the compiler the tree was configured with, and $GCOV overrides.
# Exits 77, automake's "skipped", when neither is installed.

set -eu

top=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
outdir=
name=coverage
TAB=$(printf '\t')

usage()
{
	cat <<-EOF
	usage: coverage.sh [-o DIR] [-n NAME] [-t TREE] reset|report

	  reset    delete every .gcda under the tree, keeping the .gcno, so
	           that the next run is measured on its own
	  report   read every .gcda and write the table

	  -o DIR   where the report goes, default: TREE/coverage
	  -n NAME  base name of the report files, default: coverage.  Two
	           runs of different things (the lab, the fuzz corpus) are
	           two builds and two names
	  -t TREE  the build tree, default: the one this script is in
	EOF
}

die() { echo "coverage: $*" >&2; exit 1; }

# gcc and clang both write .gcda, and neither reads the other's: gcc's
# gcov(1) refuses a clang tree with a version mismatch, and llvm-cov gcov
# is the one that takes it.  The compiler the tree was configured with is
# in its Makefile, which is the only place that knows.
find_gcov()
{
	[ -z "${GCOV:-}" ] || return 0

	cc=$(sed -n 's/^CC = //p' "$top/src/Makefile" 2>/dev/null | head -1)
	case "$cc" in
		*clang*)
			if command -v llvm-cov >/dev/null 2>&1; then
				GCOV="llvm-cov gcov"
				return 0
			fi
			;;
	esac

	if command -v gcov >/dev/null 2>&1; then
		GCOV=gcov
		return 0
	fi

	echo "coverage: neither gcov(1) nor llvm-cov(1) found, skipping" >&2
	exit 77
}

reset()
{
	n=$(find "$top" -name '*.gcda' | wc -l | tr -d ' ')
	find "$top" -name '*.gcda' -exec rm -f {} +
	echo "coverage: $n counter file(s) removed, the .gcno are kept"
}

# gcov(1) is run in the directory the .gcda is in, which is where the
# compiler was when it made the object: the source name it carries is
# relative to that -- "Source:config.c" -- and a gcov run anywhere else
# finds no source and writes an empty report, which counts as nothing
# reached rather than as an error.  What comes out is one record per
# instrumented line, "file, line, reached", and the rest is sorting and
# counting.  The .gcov files themselves are gcov's own scratch, removed
# again here.
records()
{
	rec=$1
	work=$2
	failed=0

	: > "$rec"
	for gcda in $(find "$top" -name '*.gcda' | sort); do
		d=$(dirname "$gcda")
		rel=${d#"$top"/}
		[ "$rel" != "$d" ] || rel=

		rm -f "$d"/*.gcov
		# shellcheck disable=SC2086
		if ! (cd "$d" && $GCOV "$(basename "$gcda")" >/dev/null 2>"$work/err"); then
			failed=$((failed + 1))
			sed 's/^/coverage: /' "$work/err" >&2
			continue
		fi

		[ -n "$(find "$d" -maxdepth 1 -name '*.gcov' -print -quit)" ] || continue
		awk -v base="${rel:+$rel/}" '
			# Collapse a "dir/../" the way a filesystem would:
			# a harness in test/fuzz/ names the daemon sources
			# it was built from as ../../src/route.c.
			function norm(p,	n) {
				while (sub(/[^\/]+\/\.\.\//, "", p))
					n++
				return p
			}
			# The header lines carry a line number of 0, and the
			# one that matters names the source this file is
			# about.  A source line may hold colons of its own,
			# so the two fields are cut off the front rather
			# than split out of the whole line.
			{
				c = index($0, ":")
				if (c == 0)
					next
				cnt = substr($0, 1, c - 1)
				gsub(/[ \t]/, "", cnt)
				rest = substr($0, c + 1)

				c = index(rest, ":")
				if (c == 0)
					next
				line = substr(rest, 1, c - 1)
				gsub(/[ \t]/, "", line)
				text = substr(rest, c + 1)

				if (line + 0 == 0) {
					if (substr(text, 1, 7) == "Source:")
						src = substr(text, 8)
					next
				}

				# "-" is a line with no code on it
				if (cnt == "-" || src == "")
					next

				path = (substr(src, 1, 1) == "/") ? src : norm(base src)

				# Only the daemon and its fallbacks: the
				# harnesses, the lab tools and the system
				# headers are not what is being measured.
				if (path !~ /^(src|lib)\//)
					next

				reached = (cnt == "#####" || cnt == "=====" || cnt + 0 == 0) ? 0 : 1
				printf "%s\t%d\t%d\n", path, line, reached
			}
		' "$d"/*.gcov >> "$rec"
		rm -f "$d"/*.gcov
	done

	[ "$failed" -eq 0 ] || \
		echo "coverage: $failed .gcda file(s) could not be read, see above" >&2
	[ -s "$rec" ] || die "no counters found under $top." \
		"Was the tree configured --enable-coverage, and has anything run since?"
}

report()
{
	mkdir -p "$outdir"
	: > "$outdir/$name-uncovered.txt"
	work=$(mktemp -d "${TMPDIR:-/tmp}/pimd-coverage.XXXXXX") || die "mktemp failed"
	trap 'rm -rf "$work"' EXIT INT TERM

	records "$work/records" "$work"

	# Sorted by file, then by line, then reached before unreached: one
	# line compiled into two objects gives two records, and a line
	# reached through either of them is a line reached.
	sort -t"$TAB" -k1,1 -k2,2n -k3,3r "$work/records" | awk -F"$TAB" \
		-v table="$work/table" -v miss="$outdir/$name-uncovered.txt" '
		function report_file(	pct, i, s, e) {
			if (cur == "")
				return
			pct = total ? covered * 100 / total : 0
			printf "%s\t%d\t%d\t%.1f\t%d\n", cur, total, covered,
			       pct, total - covered > table

			if (nun == 0)
				return
			# The uncovered lines as ranges: a function nothing
			# calls is one range, and that is the thing worth
			# reading in this file.
			s = un[1]
			e = un[1]
			out = ""
			for (i = 2; i <= nun; i++) {
				if (un[i] == e + 1) {
					e = un[i]
					continue
				}
				out = out (out == "" ? "" : ", ") (s == e ? s : s "-" e)
				s = un[i]
				e = un[i]
			}
			out = out (out == "" ? "" : ", ") (s == e ? s : s "-" e)
			printf "%s: %d line(s) never reached\n  %s\n\n", cur, nun, out > miss
		}
		{
			# The second record for one line says nothing new,
			# the sort having put the reached one first.
			if ($1 == pf && $2 + 0 == pl)
				next
			pf = $1
			pl = $2 + 0

			if ($1 != cur) {
				report_file()
				cur = $1
				total = 0
				covered = 0
				nun = 0
				delete un
			}
			total++
			if ($3 + 0)
				covered++
			else
				un[++nun] = $2 + 0
			gtotal++
			gcovered += ($3 + 0 ? 1 : 0)
		}
		END {
			report_file()
			printf "TOTAL\t%d\t%d\t%.1f\t%d\n", gtotal, gcovered,
			       gtotal ? gcovered * 100 / gtotal : 0,
			       gtotal - gcovered > table
		}'

	# Most uncovered lines first: the top of this table is the answer to
	# "what does no test reach", and the bottom is noise.
	{
		printf '%-28s %8s %8s %9s %7s\n' File Lines Reached Unreached Percent
		printf '%-28s %8s %8s %9s %7s\n' \
		    ---------------------------- -------- -------- --------- -------
		grep -v '^TOTAL'"$TAB" "$work/table" | sort -t"$TAB" -k5,5nr | \
			awk -F"$TAB" '{ printf "%-28s %8d %8d %9d %6.1f%%\n", $1, $2, $3, $5, $4 }'
		printf '%-28s %8s %8s %9s %7s\n' \
		    ---------------------------- -------- -------- --------- -------
		grep '^TOTAL'"$TAB" "$work/table" | \
			awk -F"$TAB" '{ printf "%-28s %8d %8d %9d %6.1f%%\n", $1, $2, $3, $5, $4 }'
	} > "$outdir/$name.txt"

	cat "$outdir/$name.txt"
	echo
	echo "coverage: $outdir/$name.txt, uncovered lines in $outdir/$name-uncovered.txt"
}

while getopts "o:n:t:h" opt; do
	case "$opt" in
		o) outdir=$OPTARG ;;
		n) name=$OPTARG ;;
		t) top=$(CDPATH= cd -- "$OPTARG" && pwd) ;;
		h) usage; exit 0 ;;
		*) usage >&2; exit 1 ;;
	esac
done
shift $((OPTIND - 1))

# After the options, -t having moved the tree the default is relative to
: "${outdir:=$top/coverage}"

[ $# -eq 1 ] || { usage >&2; exit 1; }

case "$1" in
	reset)
		reset
		;;
	report)
		find_gcov
		report
		;;
	*)
		usage >&2
		exit 1
		;;
esac
