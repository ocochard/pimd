#!/bin/sh
# run.sh - prove the wire decoders with cbmc(1), and prove the proofs bite
#
# Two passes, and both have to hold, for the reason rules/run.sh has two:
# a checker that says nothing has either found nothing or checked nothing,
# and only a control tells the two apart.
#
#   1. Each harness against the decoder as it is in src/: cbmc has to
#      answer VERIFICATION SUCCESSFUL.
#   2. Each harness against mutants of that decoder, each with one check
#      removed or one offset moved: cbmc has to answer VERIFICATION FAILED
#      for every one.  A mutation that no longer applies, because the line
#      it edits has moved, fails the run as well -- silently proving the
#      unmutated file a second time is the failure this pass exists for.
#
# The header and the step of each decoder have no loop and are proven for
# any datagram; MAXLEN bounds the messages the loop over the step is proven
# for, which costs four times as much per doubling (32 bytes 32s, 64 bytes
# 3m37s, measured), and the step being proven already, what the loop adds
# needs no more than a few blocks.

set -eu

top=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
here="$top/test/cbmc"
MAXLEN=${MAXLEN:-32}

if ! command -v cbmc >/dev/null 2>&1; then
	echo "cbmc: cbmc(1) not found, skipping the model checks" >&2
	exit 77
fi

checks="--bounds-check --pointer-check --pointer-overflow-check
	--signed-overflow-check --unsigned-overflow-check --conversion-check
	--undefined-shift-check --memory-leak-check --unwinding-assertions"

work=$(mktemp -d "${TMPDIR:-/tmp}/pimd-cbmc.XXXXXX")
trap 'rm -rf "$work"' EXIT INT TERM

fail=0

# prove NAME HARNESS SOURCE PROOF: run one entry point of a harness against
# one source, print cbmc's verdict line, and set rc to cbmc's status -- 0
# proved, 10 a property failed, anything else broken.  The unwind bound is
# for the proofs that have a loop: the decoders step six bytes at a time
# at least, so MAXLEN / 6 iterations and a margin cover every one.
prove()
{
	# shellcheck disable=SC2086
	cbmc -DMAXLEN="$MAXLEN" -DSOURCE="\"$3\"" -I "$top/src" "$2" \
	    --function "$4" $checks --unwind $((MAXLEN / 6 + 3)) \
	    >"$work/$1.log" 2>&1 && rc=0 || rc=$?
	printf '%-32s %s\n' "$1" "$(grep -E '^VERIFICATION' "$work/$1.log" || echo "cbmc exit $rc")"
}

# proof NAME HARNESS SOURCE PROOF: the decoder as it is has to be proven.
proof()
{
	prove "$@"
	if [ "$rc" -ne 0 ]; then
		grep -E 'FAILURE|rror' "$work/$1.log" | head -10 >&2
		fail=1
	fi
}

# mutant NAME HARNESS SOURCE PROOF SED: SOURCE with SED applied has to have
# changed, and the proof has to fail on it.
mutant()
{
	dst="$work/$1.c"
	sed -e "$5" "$3" >"$dst"
	if cmp -s "$3" "$dst"; then
		printf '%-32s %s\n' "$1" "MUTATION DID NOT APPLY: $5"
		fail=1
		return
	fi
	prove "$1" "$2" "$dst" "$4"
	if [ "$rc" -eq 0 ]; then
		echo "  the proof did not catch this mutant" >&2
		fail=1
	elif [ "$rc" -ne 10 ]; then
		grep -E 'rror' "$work/$1.log" | head -5 >&2
		fail=1
	fi
}

# Auto-RP, src/autorp_parse.c
h="$here/autorp.c"
s="$top/src/autorp_parse.c"
proof  autorp-hdr                  "$h" "$s" proof_hdr
proof  autorp-step                 "$h" "$s" proof_step
proof  autorp-next                 "$h" "$s" proof_next
mutant autorp-no-header-bound      "$h" "$s" proof_hdr  's/len < AUTORP_HDR_LEN/0/'
mutant autorp-holdtime-order       "$h" "$s" proof_hdr  's/(p\[2\] << 8) | p\[3\]/(p[3] << 8) | p[2]/'
mutant autorp-no-rp-bound          "$h" "$s" proof_step 's/c->left < AUTORP_RP_LEN/0/'
mutant autorp-no-prefix-bound      "$h" "$s" proof_step 's/c->left < AUTORP_GRP_LEN/0/'
mutant autorp-group-offset         "$h" "$s" proof_step 's/c->p + 2, sizeof/c->p + 1, sizeof/'
mutant autorp-no-rp-count          "$h" "$s" proof_step 's/c->rpcnt -= 1;/;/'
mutant autorp-loop-past-verdict    "$h" "$s" proof_next 's/== AUTORP_PARSE_BLOCK)/!= AUTORP_PARSE_PREFIX)/'

exit $fail
