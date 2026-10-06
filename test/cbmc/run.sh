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
# 3m37s; a Hello 24 bytes 21s, 32 bytes 2m30s; a Join/Prune 34 bytes 27s,
# 48 bytes 1m12s; a Bootstrap 60 bytes 8s, 128 bytes 1m48s; an IGMPv3
# report 32 bytes 3s, 64 bytes 19s), and the step being proven already,
# what the loop adds needs no more than a few iterations of it.
# SCALE multiplies every one of those lengths, for a longer run by hand.
#
# The proofs and the mutants are independent, so they are queued as the
# list below is read and run JOBS at a time (the core count by default):
# one after another they take about seven minutes, nearly all of it a
# handful of proofs, and in parallel what is left is the longest of them.
# The report is printed afterwards, in the order of the list, and the exit
# status is the whole run's.
#
# Each job runs under a memory limit, CBMC_MEM megabytes (4096 by
# default), so that a proof that blows up fails as one proof rather than
# taking the host with it: a redundant one did, running a 64G machine out
# of memory twice before it was dropped from test/cbmc/encode.c.  What
# the proofs here need was measured, peak resident: 2.9G for the whole
# Join/Prune, under 1G for every other one.  It is the unwind depth rather
# than the length that costs: that proof at 34 and at 38 bytes unwinds
# seven times and needs the same 2.9G, at 40 eight and 4.4G, which is
# why it stops at 38, still two group sets.  A job
# over the limit reports "cbmc exit" and cbmc's out of memory message.  The
# default JOBS is bounded by memory as well as by cores, so that every job
# at its limit at once still fits in half the physical memory.

set -eu

top=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
here="$top/test/cbmc"
SCALE=${SCALE:-1}
CBMC_MEM=${CBMC_MEM:-4096}

# Physical memory in megabytes, or nothing: getconf spells it PHYS_PAGES
# on FreeBSD and _PHYS_PAGES on glibc
physmem_mb()
{
	pages=$(getconf PHYS_PAGES 2>/dev/null || getconf _PHYS_PAGES 2>/dev/null) || return 0
	echo $((pages / 1024 * $(getconf PAGESIZE) / 1024))
}

if [ -z "${JOBS:-}" ]; then
	JOBS=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)
	mem=$(physmem_mb)
	if [ -n "$mem" ] && [ $((mem / 2 / CBMC_MEM)) -lt "$JOBS" ]; then
		JOBS=$((mem / 2 / CBMC_MEM))
	fi
	[ "$JOBS" -ge 1 ] || JOBS=1
fi

if ! command -v cbmc >/dev/null 2>&1; then
	echo "cbmc: cbmc(1) not found, skipping the model checks" >&2
	exit 77
fi

checks="--bounds-check --pointer-check --pointer-overflow-check
	--signed-overflow-check --unsigned-overflow-check --conversion-check
	--undefined-shift-check --memory-leak-check --unwinding-assertions"

# A worker, which is this script run by xargs below: run job N of the
# queue in WORK and leave cbmc's status beside its log -- 0 proved, 10 a
# property failed, anything else broken.
if [ "${1:-}" = "--job" ]; then
	work=$2
	{
		read -r name
		read -r harness
		read -r source
		read -r function
		read -r len
		read -r unwind
	} <"$work/job.$3"
	ulimit -v $((CBMC_MEM * 1024))
	# shellcheck disable=SC2086
	cbmc -DMAXLEN="$len" -DSOURCE="\"$source\"" -I "$top/src" -I "$top/include" \
	    "$harness" --function "$function" $checks --unwind "$unwind" \
	    >"$work/$name.log" 2>&1 && rc=0 || rc=$?
	echo "$rc" >"$work/$name.rc"
	exit 0
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/pimd-cbmc.XXXXXX")
trap 'rm -rf "$work"' EXIT INT TERM

fail=0
njobs=0
: >"$work/order"

# queue KIND NAME HARNESS SOURCE PROOF LEN STEP: one entry point of a
# harness against one source, for messages up to LEN bytes where it has a
# loop.  STEP is the fewest bytes one iteration of the proof's loops
# consumes, so LEN / STEP iterations and a margin unwind every one of them,
# and five whatever the length, for the memcmp() of four bytes the
# harnesses compare a decoded address with.
queue()
{
	len=$(($6 * SCALE))
	unwind=$((len / $7 + 3))
	[ "$unwind" -ge 5 ] || unwind=5
	njobs=$((njobs + 1))
	printf '%s\n' "$2" "$3" "$4" "$5" "$len" "$unwind" >"$work/job.$njobs"
	echo "$1 $2" >>"$work/order"
}

# proof NAME HARNESS SOURCE PROOF LEN STEP: the decoder as it is has to be proven.
proof()
{
	queue proof "$@"
}

# mutant NAME HARNESS SOURCE PROOF LEN STEP SED: SOURCE with SED applied has
# to have changed, and the proof has to fail on it.  Whether it changed is
# known now, before anything runs.
mutant()
{
	dst="$work/$1.c"
	sed -e "$7" "$3" >"$dst"
	if cmp -s "$3" "$dst"; then
		printf '%s\n' "$7" >"$work/$1.sed"
		echo "unapplied $1" >>"$work/order"
		return
	fi
	queue mutant "$1" "$2" "$dst" "$4" "$5" "$6"
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
proof  jp-hdr                      "$h" "$s" proof_jp_hdr       0 1
proof  jp-set                      "$h" "$s" proof_jp_set       0 1
proof  jp-srcs                     "$h" "$s" proof_jp_srcs    512 8
proof  jp-group                    "$h" "$s" proof_jp_group     0 1
proof  jp-source                   "$h" "$s" proof_jp_source    0 1
proof  jp                          "$h" "$s" proof_jp          38 8
mutant jp-no-header-bound          "$h" "$s" proof_jp_hdr       0 1 's/len < PIM_JOIN_PRUNE_MINLEN/0/'
mutant jp-upstream-any-family      "$h" "$s" proof_jp_hdr       0 1 's/eua.addr_family != ADDRF_IPv4 || //'
mutant jp-no-set-bound             "$h" "$s" proof_jp_set       0 1 's/c->left < PIM_JP_GRP_SET_LEN/0/'
mutant jp-no-source-bound          "$h" "$s" proof_jp_set       0 1 's/c->left - PIM_JP_GRP_SET_LEN < srclen/0/'
mutant jp-group-mask-unchecked     "$h" "$s" proof_jp_set       0 1 '/^static int pim_parse_jp_set/,/^}/s/p\[PIM_ENCODE_MSKLEN_OFF\] > PIM_MAX_MSKLEN/0/'
mutant jp-source-mask-unchecked    "$h" "$s" proof_jp_srcs     32 8 's/p\[PIM_ENCODE_MSKLEN_OFF\] != SINGLE_SRC_MSKLEN/0/'
mutant jp-sources-unchecked        "$h" "$s" proof_jp          38 8 's/rc = pim_parse_jp_srcs(&srcs, jp);/rc = PIM_JP_OK;/'
mutant jp-group-count-ignored      "$h" "$s" proof_jp          38 8 's/for (n = jp->num_groups; n > 0; n--)/for (n = 1; n > 0; n--)/'
mutant jp-source-stride            "$h" "$s" proof_jp_source    0 1 's/(size_t)i \* PIM_ENCODE_SRC_ADDR_LEN/(size_t)i * 6/'
mutant jp-next-set                 "$h" "$s" proof_jp_group     0 1 's/return p + ((size_t)grp->num_j + grp->num_p) \* PIM_ENCODE_SRC_ADDR_LEN;/return p;/'
proof  bsr-hdr                     "$h" "$s" proof_bsr_hdr      0 1
proof  bsr-set                     "$h" "$s" proof_bsr_set      0 1
proof  bsr-group                   "$h" "$s" proof_bsr_group    0 1
proof  bsr-rp                      "$h" "$s" proof_bsr_rp       0 1
proof  bsr                         "$h" "$s" proof_bsr         60 10
proof  crp                         "$h" "$s" proof_crp          0 1
mutant bsr-no-header-bound         "$h" "$s" proof_bsr_hdr      0 1 's/len < PIM_BOOTSTRAP_MINLEN/0/'
mutant bsr-hash-mask-unchecked     "$h" "$s" proof_bsr_hdr      0 1 's/bsr->hash_masklen > PIM_MAX_MSKLEN/0/'
mutant bsr-no-record-bound         "$h" "$s" proof_bsr_set      0 1 's/c->left - PIM_BSR_GRP_SET_LEN < rplen/0/'
mutant bsr-group-mask-unchecked    "$h" "$s" proof_bsr_set      0 1 '/^static int pim_parse_bsr_set/,/^}/s/p\[PIM_ENCODE_MSKLEN_OFF\] > PIM_MAX_MSKLEN/0/'
mutant bsr-next-set-by-rp-count    "$h" "$s" proof_bsr_group    0 1 's/(size_t)grp->frag_rp_count \* PIM_BSR_RP_LEN/(size_t)grp->rp_count * PIM_BSR_RP_LEN/'
mutant bsr-rp-stride               "$h" "$s" proof_bsr_rp       0 1 's/(size_t)i \* PIM_BSR_RP_LEN/(size_t)i * 8/'
mutant bsr-sets-uncounted          "$h" "$s" proof_bsr         60 10 's/bsr->num_sets++;/;/'
mutant crp-prefix-count-trusted    "$h" "$s" proof_crp          0 1 's/fit < crp->prefix_cnt ? (uint8_t)fit : crp->prefix_cnt/crp->prefix_cnt/'
mutant crp-no-header-bound         "$h" "$s" proof_crp          0 1 's/len < PIM_CAND_RP_ADV_MINLEN/0/'
proof  register                    "$h" "$s" proof_register     0 1
proof  register-stop               "$h" "$s" proof_register_stop 0 1
proof  assert                      "$h" "$s" proof_assert       0 1
mutant reg-no-length-check         "$h" "$s" proof_register     0 1 's/len < PIM_REGISTER_MINLEN/0/'
mutant reg-version-ignored         "$h" "$s" proof_register     0 1 's/reg->inner_version != IP_HDR_V4 \&\& !reg->is_null/0/'
mutant reg-null-hlen-unbounded     "$h" "$s" proof_register     0 1 's/hlen < IP_HDR_MINLEN || hlen > reg->avail/hlen < IP_HDR_MINLEN/'
mutant reg-whole-unbounded         "$h" "$s" proof_register     0 1 's/ \&\& reg->inner_len <= reg->avail;/;/'
mutant regstop-no-length-check     "$h" "$s" proof_register_stop 0 1 's/pim_parse_sg(msg, \&p, len, PIM_REGISTER_STOP_MINLEN, rs)/pim_parse_sg(msg, \&p, len, 0, rs)/'
mutant regstop-family-ignored      "$h" "$s" proof_register_stop 0 1 '/^static int pim_parse_sg/,/^}/s/ega.addr_family != ADDRF_IPv4 || ega.encod_type != ADDRT_IPv4 ||/0 ||/'
mutant assert-read-past-length     "$h" "$s" proof_assert       0 1 's/pim_parse_sg(msg, \&p, len, PIM_ASSERT_MINLEN, as)/pim_parse_sg(msg, \&p, len, PIM_REGISTER_STOP_MINLEN, as)/'

# IGMPv3 reports, src/igmp_parse.c
h="$here/igmp.c"
s="$top/src/igmp_parse.c"
proof  igmp-report                 "$h" "$s" proof_report       0 1
proof  igmp-record                 "$h" "$s" proof_record       0 1
proof  igmp-source                 "$h" "$s" proof_source       0 1
proof  igmp-walk                   "$h" "$s" proof_walk        64 8
mutant igmp-no-header-bound        "$h" "$s" proof_report       0 1 's/len < IGMPV3_REPORT_HDRLEN/0/'
mutant igmp-no-record-header-bound "$h" "$s" proof_record       0 1 's/c->left < IGMPV3_REC_HDRLEN/0/'
mutant igmp-no-record-bound        "$h" "$s" proof_record       0 1 's/c->left < rec->size/0/'
mutant igmp-aux-words-ignored      "$h" "$s" proof_record       0 1 's/ + (size_t)p\[1\] \* 4;/;/'
mutant igmp-record-not-counted     "$h" "$s" proof_record       0 1 's/c->ngrec -= 1;/;/'
mutant igmp-source-stride          "$h" "$s" proof_source       0 1 's/(size_t)i \* sizeof(uint32_t)/(size_t)i * 2/'

# The writer the message builders write through, src/pim_encode.c
h="$here/encode.c"
s="$top/src/pim_encode.c"
proof  writer-put                  "$h" "$s" proof_put          0 1
mutant writer-no-room-check        "$h" "$s" proof_put          0 1 's/return !w->full \&\& n <= w->left;/return !w->full;/'
mutant writer-full-not-sticky      "$h" "$s" proof_put          0 1 's/return !w->full \&\& n <= w->left;/return n <= w->left;/'
mutant writer-full-not-set         "$h" "$s" proof_put          0 1 's/	w->full = 1;/	;/'
mutant writer-left-not-counted     "$h" "$s" proof_put          0 1 's/w->left -= n;/;/'
mutant writer-u16-byte-order       "$h" "$s" proof_put          0 1 's/{ (uint8_t)((val >> 8) \& 0xff), (uint8_t)(val \& 0xff) }/{ (uint8_t)(val \& 0xff), (uint8_t)((val >> 8) \& 0xff) }/'
mutant writer-group-unmasked       "$h" "$s" proof_put          0 1 '/^int pim_put_egaddr/,/^}/s/addr \&= mask;/;/'

# Run the queue
seq 1 "$njobs" | xargs -n 1 -P "$JOBS" sh "$0" --job "$work"

# And report on it, in the order of the list above
while read -r kind name; do
	if [ "$kind" = unapplied ]; then
		printf '%-32s %s\n' "$name" "MUTATION DID NOT APPLY: $(cat "$work/$name.sed")"
		fail=1
		continue
	fi

	rc=$(cat "$work/$name.rc" 2>/dev/null || echo "missing")
	printf '%-32s %s\n' "$name" \
	    "$(grep -E '^VERIFICATION' "$work/$name.log" 2>/dev/null || echo "cbmc exit $rc")"

	if [ "$kind" = proof ]; then
		if [ "$rc" = 10 ]; then
			grep -E 'FAILURE' "$work/$name.log" | head -10 >&2
			fail=1
		elif [ "$rc" != 0 ]; then
			tail -3 "$work/$name.log" >&2
			fail=1
		fi
	elif [ "$rc" = 10 ]; then
		# What it was caught by, so that a control caught by the harness
		# itself -- an unwinding bound too small, say -- reads as one.
		# An unwinding assertion is shown only when nothing else failed,
		# and says so: it is the right catch for a loop that no longer
		# ends, and no catch at all for anything else.
		sed -n 's/^\[\([^]]*\)\] \(.*\): FAILURE$/	\1: \2/p' "$work/$name.log" \
		    >"$work/$name.why"
		grep -v '\.unwind\.' "$work/$name.why" | head -1 | grep . ||
		    sed -e 's/$/ (unwinding only)/' "$work/$name.why" | head -1
	elif [ "$rc" = 0 ]; then
		echo "  the proof did not catch this mutant" >&2
		fail=1
	else
		# Neither proved nor refuted: cbmc could not run it at all, and
		# says why at the end of its log, rarely with the word "error".
		tail -3 "$work/$name.log" >&2
		fail=1
	fi
done <"$work/order"

exit $fail
