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
# any datagram; a proof with a loop is proven for messages up to a length
# given beside it below, picked from measurements: a whole message costs
# about four times as much per doubling (Auto-RP 32 bytes 32s, 64 bytes
# 3m37s; a Hello 24 bytes 21s, 32 bytes 2m30s), and the step being proven
# already, what the loop adds needs no more than a few iterations of it.
# SCALE multiplies every one of those lengths, for a longer run by hand.

set -eu

top=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
here="$top/test/cbmc"
SCALE=${SCALE:-1}

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

# prove NAME HARNESS SOURCE PROOF LEN STEP: run one entry point of a harness
# against one source, for messages up to LEN bytes where it has a loop,
# print cbmc's verdict line, and set rc to cbmc's status -- 0 proved, 10 a
# property failed, anything else broken.  STEP is the fewest bytes one
# iteration of the proof's loops consumes, so LEN / STEP iterations and a
# margin unwind every one of them.
prove()
{
	len=$(($5 * SCALE))
	# and five whatever the length, for the memcmp() of four bytes the
	# harnesses compare a decoded address with
	unwind=$((len / $6 + 3))
	[ "$unwind" -ge 5 ] || unwind=5
	# shellcheck disable=SC2086
	cbmc -DMAXLEN="$len" -DSOURCE="\"$3\"" -I "$top/src" -I "$top/include" "$2" \
	    --function "$4" $checks --unwind "$unwind" \
	    >"$work/$1.log" 2>&1 && rc=0 || rc=$?
	printf '%-32s %s\n' "$1" "$(grep -E '^VERIFICATION' "$work/$1.log" || echo "cbmc exit $rc")"
}

# proof NAME HARNESS SOURCE PROOF LEN STEP: the decoder as it is has to be proven.
proof()
{
	prove "$@"
	if [ "$rc" -ne 0 ]; then
		grep -E 'FAILURE|rror' "$work/$1.log" | head -10 >&2
		fail=1
	fi
}

# mutant NAME HARNESS SOURCE PROOF LEN STEP SED: SOURCE with SED applied has
# to have changed, and the proof has to fail on it.
mutant()
{
	dst="$work/$1.c"
	sed -e "$7" "$3" >"$dst"
	if cmp -s "$3" "$dst"; then
		printf '%-32s %s\n' "$1" "MUTATION DID NOT APPLY: $7"
		fail=1
		return
	fi
	prove "$1" "$2" "$dst" "$4" "$5" "$6"
	if [ "$rc" -eq 10 ]; then
		# What it was caught by, so that a control caught by the harness
		# itself -- an unwinding bound too small, say -- reads as one.
		sed -n 's/^\[\([^]]*\)\] \(.*\): FAILURE$/	\1: \2/p' "$work/$1.log" | head -1
	elif [ "$rc" -eq 0 ]; then
		echo "  the proof did not catch this mutant" >&2
		fail=1
	else
		grep -E 'rror' "$work/$1.log" | head -5 >&2
		fail=1
	fi
}

# Auto-RP, src/autorp_parse.c.  The header and the step have no loop, and
# the 0 0 they are given is never read.
h="$here/autorp.c"
s="$top/src/autorp_parse.c"
proof  autorp-hdr                  "$h" "$s" proof_hdr   0 1
proof  autorp-step                 "$h" "$s" proof_step  0 1
proof  autorp-next                 "$h" "$s" proof_next 32 6
mutant autorp-no-header-bound      "$h" "$s" proof_hdr   0 1 's/len < AUTORP_HDR_LEN/0/'
mutant autorp-holdtime-order       "$h" "$s" proof_hdr   0 1 's/(p\[2\] << 8) | p\[3\]/(p[3] << 8) | p[2]/'
mutant autorp-no-rp-bound          "$h" "$s" proof_step  0 1 's/c->left < AUTORP_RP_LEN/0/'
mutant autorp-no-prefix-bound      "$h" "$s" proof_step  0 1 's/c->left < AUTORP_GRP_LEN/0/'
mutant autorp-group-offset         "$h" "$s" proof_step  0 1 's/c->p + 2, sizeof/c->p + 1, sizeof/'
mutant autorp-no-rp-count          "$h" "$s" proof_step  0 1 's/c->rpcnt -= 1;/;/'
mutant autorp-loop-past-verdict    "$h" "$s" proof_next 32 6 's/== AUTORP_PARSE_BLOCK)/!= AUTORP_PARSE_PREFIX)/'

# PIM, src/pim_parse.c
h="$here/pim.c"
s="$top/src/pim_parse.c"
proof  hello-opt                   "$h" "$s" proof_hello_opt    0 1
proof  hello-addr                  "$h" "$s" proof_hello_addr   0 1
proof  hello-addrs                 "$h" "$s" proof_hello_addrs 512 6
proof  hello                       "$h" "$s" proof_hello       24 4
mutant hello-no-header-bound       "$h" "$s" proof_hello       24 4 's/len < sizeof(pim_header_t)/0/'
mutant hello-no-opthdr-bound       "$h" "$s" proof_hello_opt    0 1 's/c->left < sizeof(pim_hello_t)/0/'
mutant hello-no-option-bound       "$h" "$s" proof_hello_opt    0 1 's/c->left < rec_len/0/'
mutant hello-holdtime-any-length   "$h" "$s" proof_hello_opt    0 1 's/opt_len != PIM_HELLO_HOLDTIME_LEN/0/'
mutant hello-tbit-kept             "$h" "$s" proof_hello_opt    0 1 's/delay & ~PIM_LAN_PRUNE_DELAY_T_BIT/delay/'
mutant hello-addrs-partial-entry   "$h" "$s" proof_hello_addrs 32 6 's/opts->addr_list_len % PIM_ENCODE_UNI_ADDR_LEN/0/'
mutant hello-addrs-any-etype       "$h" "$s" proof_hello_addrs 32 6 's/ || etype != ADDRT_IPv4//'
mutant hello-addr-stride           "$h" "$s" proof_hello_addr   0 1 's/(size_t)i \* PIM_ENCODE_UNI_ADDR_LEN/(size_t)i * 4/'

exit $fail
