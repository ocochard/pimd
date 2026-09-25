#!/bin/sh
# PIM-SM interoperability lab: pimd against FRRouting, on FreeBSD and Linux
#
# Everything in this directory but test/freebsd-interop.sh tests pimd
# against pimd.  That answers "does pimd still do what it did yesterday",
# never "does pimd do what the RFC says", because both ends of every
# exchange share one reading of it: a field pimd encodes wrongly it also
# decodes wrongly, and the lab stays green.  The vEOS lab was the first way
# past that and it costs a licensed image, 4G of guest memory and bhyve.
# This one is the cheap half of the same idea: FRR's pimd is a second
# implementation, written from the same RFCs by other people, and it is a
# package away on both systems this tree supports.  Nothing here needs a
# VM, a vendor image or an account -- net/frr10 on FreeBSD, frr on Debian
# and Ubuntu -- so it is the interop test that can be run on a laptop,
# before the expensive one.
#
# It is not a replacement for freebsd-interop.sh: EOS is a third reading
# again, and a bug the two open source daemons share is exactly the bug
# neither lab would show.  Run both.
#
# Topology, one box per router, all links /24.  The boxes are vnet jails on
# FreeBSD and named network namespaces on Linux, as in lab.sh, and
# R2 is the FRR router -- the only box in this file that does not run the
# pimd under test:
#
#    ED1            R1             R2             R3            ED2
#     |              |            (FRR)            |             |
#     +--10.0.1.0/24-+-10.0.12.0/24-+-10.0.23.0/24-+--10.0.3.0/24-+
#      .10        .1   .1        .2   .2        .3   .1        .10
#     ${EP}901       ${EP}912       ${EP}923       ${EP}903
#
#                                  |
#                    pimd-rp adds  +--10.0.4.0/24--- ED4 .10
#                                 .2      ${EP}924
#
# Three scenarios run on it, and the first two are each other's mirror.
# Who writes a message and who parses it is the whole difference: a parser
# that is wrong in the same way as its own encoder passes one of them and
# fails the other.
#
#   frr-rp      FRR is the RP.  R1 is the BSR, FRR the Candidate-RP, R1 the
#               first hop router for ED1 and R3 the last hop one for ED2.
#
#                 - Hello and DR election on two links at once, each
#                   outcome read from both sides rather than from pimd's
#                   opinion of it.  FRR wins on 10.0.12.0/24 (higher
#                   address) and R3 wins on 10.0.23.0/24.
#                 - Candidate-RP-Advertisement written by FRR, parsed by
#                   pimd's BSR: the priority is asserted beside the
#                   address, so a field that arrives mangled is visible.
#                 - Bootstrap written by pimd, parsed by FRR, and
#                   forwarded by FRR -- R3 is two hops from the BSR, so it
#                   can only hold the RP set because FRR flooded a
#                   Bootstrap pimd originated.
#                 - Register written by pimd, decapsulated by FRR as RP,
#                   and the Register-Stop it answers with obeyed by pimd:
#                   counted over a second stream once the tree is up, a
#                   Register-Stop nobody acted on being one Register per
#                   data packet.
#                 - (*,G) Join written by pimd, believed by FRR, measured
#                   as traffic arriving at ED2 rather than as a table.
#
#   pimd-rp     The roles reversed: FRR is the BSR, R1 the Candidate-RP and
#               so the RP, and FRR is the first and last hop router for a
#               LAN of its own.  That LAN is why this scenario has a sixth
#               box, ED4 on 10.0.4.0/24.
#
#                 - Candidate-RP-Advertisement written by pimd, parsed by
#                   FRR's BSR.
#                 - Bootstrap written by FRR, parsed by pimd, on R1 and on
#                   R3 two hops away.
#                 - (*,G) Join written by FRR as last hop router, believed
#                   by pimd -- asserted on R1's own outgoing list.
#                 - Register written by FRR as first hop router for ED4,
#                   decapsulated by pimd, and pimd's Register-Stop obeyed
#                   by FRR.
#
#               The stream runs ED1 -> ED4 and mping's receiver answers to
#               the same group, so one run builds a tree in each direction:
#               (ED1,G) with pimd as first hop router and FRR as last, and
#               (ED4,G) the other way about.
#
#   autorp      Auto-RP (doc/pim-autorp-spec01.txt), which pimd learned to
#               speak in all three roles only recently and which FRR 10.x
#               implements as well -- so this is the one place in the tree
#               where pimd's newest wire format meets a parser that is not
#               its own.  Run in both directions, on the chain above, with
#               no BSR anywhere: any RP either daemon holds can only have
#               come from an Auto-RP message.
#
#                 a. R1 announces itself a candidate RP for $AUTORP_RANGE
#                    and FRR is the mapping agent: pimd's Announcement is
#                    parsed by FRR, FRR's Discovery is parsed by pimd, and
#                    pimd puts what it read in its RP set rather than only
#                    in its Auto-RP table.
#                 b. The roles swapped without rebuilding the lab: FRR
#                    announces $AUTORP_RANGE_B and R1 is the mapping
#                    agent.  FRR's Announcement is parsed by pimd's agent,
#                    pimd's Discovery is parsed by FRR, and FRR installs
#                    the RP with Auto-RP as its source.
#
#               No stream, and the reason is a gap both implementations
#               have.  Sec. 3.3 of the draft floods the Announcement and
#               the Discovery hop by hop, and neither daemon floods them:
#               pimd sends its own out of every PIM interface, FRR sends
#               its Discovery out of the one link its source address is on
#               -- measured here, with an explicit source and without one
#               -- so between them they cover one link.  R3, one hop
#               further, learns nothing in either direction and is not
#               asserted on; the streams that prove an RP works are in the
#               two scenarios above.
#
# What this lab found about FRR 10.7.1, and what the scenarios are shaped
# around: an FRR that is itself the BSR never puts its own Candidate-RP
# into the Bootstrap it originates.  Its candidate-rp-database stays empty,
# nothing leaves the box, and the Bootstrap on the wire carries no RP at
# all -- while the same FRR, as a Candidate-RP to somebody else's BSR,
# sends a correct Advertisement, and the same FRR, as BSR, takes a
# Candidate-RP-Advertisement from pimd and floods it on.  So the two BSR
# scenarios put the two daemons in the roles that work, which is also the
# pairing that tests the most: every Bootstrap here carries an RP the other
# implementation wrote the Advertisement for.
#
# Requirements: root (or passwordless sudo), a multicast kernel, a built
# pimd tree, and FRR installed with its pimd daemon -- net/frr10 on
# FreeBSD, the frr package on Debian and Ubuntu.  On Ubuntu that package
# also brings an AppArmor profile which allows FRR's pimd no pathspace of
# its own; check_apparmor() below says so, and says what to allow.  The daemons are found
# under $FRR_LIB (/usr/local/lib/frr, /usr/lib/frr), and they run as the
# packaged user, $FRR_USER: FRR's own privs_init() exits when the user it
# runs as is not in the vty group, so running them as root is not an
# option and the lab does not try.
#
# Each box's FRR state lives in $FRR_RUNDIR/$FRR_NS, its pathspace (-N),
# because jails and namespaces share the host filesystem and two labs
# would otherwise write each other's sockets and pid files.
#
# Scenarios run in parallel as they do in the other labs and for the same
# reason: -s picks a slot, 0 to 31, every host-visible name carries it, and
# "run all -j N" does the bookkeeping.  The addresses inside the boxes are
# the same in every slot and need no tag, a vnet or a netns having a stack
# of its own.
#
# Usage: frr-interop.sh [-s SLOT] [-j JOBS] start|check|run [scenario...]
#        | run all | stop

# The options come before the command, "$0 -s 3 run autorp", and are read
# here rather than beside the dispatch at the foot of the file: -s picks
# the slot, and the slot is what the names below are derived from.
SLOT=${SLOT:-0}
JOBS=${JOBS:-1}
HELP=
while getopts "s:j:h" opt; do
	case "$opt" in
	s) SLOT=$OPTARG ;;
	j) JOBS=$OPTARG ;;
	h) HELP=yes ;;
	*) echo "EXIT: run \"$0 -h\" for usage" >&2; exit 2 ;;
	esac
done
shift $((OPTIND - 1))

set -eu

case $JOBS in
""|*[!0-9]*|0) echo "EXIT: -j wants a job count of 1 or more, not \"$JOBS\"" >&2; exit 1 ;;
esac

case $SLOT in
[0-9]|[12][0-9]|3[01]) ;;
*) echo "EXIT: slot must be 0 to 31, not \"$SLOT\"" >&2; exit 1 ;;
esac

# Root needs no sudo, and the places this runs unattended -- CI in a VM, a
# jail host -- often do not have it installed at all.  An explicitly empty
# SUDO= is honoured either way.
if [ "$(id -u)" -eq 0 ]; then
	SUDO=${SUDO-}
else
	SUDO=${SUDO-sudo}
fi

LAB_DIR=$(cd "$(dirname "$0")" && pwd)
LAB_SELF=$LAB_DIR/${0##*/}
PIMD_SRC=${PIMD_SRC:-$(cd "$LAB_DIR/.." && pwd)}

if [ "$SLOT" -eq 0 ]; then
	TAG=
else
	TAG=$SLOT
fi

# The links.  900 and up, so that a lab.sh (100s) or a
# freebsd-interop.sh (800s) in the same slot is a different set of
# interfaces on the host.
EP=epair$TAG

# The host side of a lab -- boxes, links, addresses, routes, and what the
# kernel made of pimd's requests -- is one file per system, shared with
# lab.sh.  Sourced this early because a backend may set a default
# the rest of this file is derived from, NETLINK on Linux.
case $(uname -s) in
FreeBSD) . "$LAB_DIR/lab-freebsd.sh" ;;
Linux)   . "$LAB_DIR/lab-linux.sh" ;;
*)       echo "EXIT: no lab backend for $(uname -s)" >&2; exit 1 ;;
esac

# Names of our own, after the backend has set its own: this lab's boxes are
# called ed1, r1, r2, r3 and ed2 like everything else here, so only the
# prefix keeps them apart from a lab.sh or a freebsd-interop.sh in
# the same slot.  All three labs can then be up at once on one machine.
JAIL_PREFIX=pimf${TAG}_
NETNS_PREFIX=pimf${TAG}_
IFGROUP=pimf$(echo "$SLOT" | tr 0-9 a-j)

# Which RPF backend the pimd under test was built with.  Nothing here
# asserts on it -- both are equally foreign to FRR -- but the FreeBSD
# backend loads netlink.ko for a tree built --enable-netlink, and reads
# this to know whether to.  Linux has no other answer and lab-linux.sh has
# already said so by the time this runs.
NETLINK=${NETLINK:-no}

WORKDIR_PINNED=${WORKDIR:+yes}
WORKDIR=${WORKDIR:-/tmp/pimd-frr$TAG}

PIMD="$PIMD_SRC/src/pimd"
PIMCTL="$PIMD_SRC/src/pimctl"
MPING="$WORKDIR/mping"

# Nothing here asks for a sanitizer or a coverage build, but box_daemon()
# in both backends passes this to env(1), so it has to exist.
PIMD_ENV=

# pimd debug flags.  bsr and crp are what the two Bootstrap scenarios read
# their logs for; "all" is the knob a human reaches for.
DEBUG=${DEBUG:-"-l debug -d bsr,crp,registers,pim"}

SCENARIO=${SCENARIO:-frr-rp}
SCENARIOS="frr-rp pimd-rp autorp"

GROUP=${GROUP:-225.1.2.3}

# The addresses the assertions name.  The RP is an interface address of
# whichever router holds the role in the scenario.
SRC_ADDR=10.0.1.10
ED2_ADDR=10.0.3.10
ED4_ADDR=10.0.4.10
R1_ADDR=10.0.12.1
FRR_ADDR=10.0.12.2
FRR_R3_ADDR=10.0.23.2
R3_ADDR=10.0.23.3

# What each side advertises, so that an assertion can say the number
# crossed the wire rather than that something did.  FRR's Candidate-RP
# priority is not configurable per group range in the way pimd's is, and
# 192 is what it advertises by default.
PIMD_BSR_PRIORITY=${PIMD_BSR_PRIORITY:-5}
PIMD_CRP_PRIORITY=${PIMD_CRP_PRIORITY:-20}
FRR_BSR_PRIORITY=${FRR_BSR_PRIORITY:-200}
FRR_CRP_PRIORITY=${FRR_CRP_PRIORITY:-192}

# autorp: the ranges each side offers to be RP for, and how fast.  The
# intervals are the lowest either daemon takes, so a scenario that waits
# for a mapping waits seconds and not minutes.
AUTORP_RANGE=${AUTORP_RANGE:-225.1.0.0/16}
AUTORP_RANGE_B=${AUTORP_RANGE_B:-225.2.0.0/16}
AUTORP_INTERVAL=${AUTORP_INTERVAL:-10}
AUTORP_HOLDTIME=${AUTORP_HOLDTIME:-30}

# Packets the sender sends, one per second, and how many replies have to
# come back before the stream counts as forwarded.  The first seconds are
# always lost: they are what builds the tree.
STREAM_PKTS=${STREAM_PKTS:-40}
MIN_REPLIES=${MIN_REPLIES:-20}

# A second, short stream once the tree has settled, and how many Registers
# the RP may decapsulate while it is in flight.  Counting over the first
# stream would measure the wrong thing: an RP cannot Register-Stop anything
# until it has the (S,G) and has joined the shortest path tree towards it,
# so a cold lab legitimately registers the first packets.  The bound is not
# zero because RFC 7761 sec. 4.4.1 has the first hop router probe with a
# Null-Register once per Register-Suppression-Timer.
SETTLED_PKTS=${SETTLED_PKTS:-10}
MAX_REGISTERS=${MAX_REGISTERS:-3}

# How long to wait for a daemon to answer on its control socket.
PIMD_START_WAIT=${PIMD_START_WAIT:-20}
FRR_START_WAIT=${FRR_START_WAIT:-30}

# --- FRR on the host --------------------------------------------------

# Where the packages put the daemons.  FreeBSD's net/frr10 configures
# --sbindir=/usr/local/lib/frr, Debian and Ubuntu use /usr/lib/frr; both
# ship vtysh on $PATH.  $FRR_LIB overrides the search for a build that is
# somewhere else again.
FRR_LIB=${FRR_LIB:-}
if [ -z "$FRR_LIB" ]; then
	for d in /usr/local/lib/frr /usr/lib/frr /usr/lib/frr/bin; do
		if [ -x "$d/pimd" ] && [ -x "$d/zebra" ]; then
			FRR_LIB=$d
			break
		fi
	done
fi
VTYSH=${VTYSH:-$(command -v vtysh 2>/dev/null || echo /usr/bin/vtysh)}

# The user FRR runs as.  Not a preference: lib/privs.c exits when the user
# it is told to run as is not a member of the vty group, so "-u root" ends
# the daemon before it opens a socket.  The packaged user is in that group,
# which is why this lab uses it and why $WORKDIR and the FRR log are given
# to it below.
FRR_USER=${FRR_USER:-frr}

# One pathspace per lab, which is what keeps two slots -- and lab.sh's own
# FRR, if one is ever added there -- out of each other's sockets and pid
# files.  Boxes share the host filesystem on both systems: a jail created
# with jail(8) has the host root, and "ip netns exec" only replaces
# /etc/netns/<name> overlays.
FRR_RUNDIR=${FRR_RUNDIR:-/var/run/frr}
FRR_NS=pimf${SLOT}
FRR_DIR=$FRR_RUNDIR/$FRR_NS

# The FRR box.  It is called r2 rather than "frr" so that the backends'
# create_box() turns IP forwarding on for it -- both of them key that on
# the box name starting with r -- and so that the chain reads like
# lab.sh's.
FRR_BOX=r2

# --- output -----------------------------------------------------------

die() { echo -n "EXIT: " >&2; echo "$@" >&2; exit 1; }
print() { printf "\033[7m>> %-76s\033[0m\n" "$1"; }
dprint() { printf "\033[2m%-76s\033[0m\n" "$1"; }

FAILED=0
XFAILED=0
ok()   { printf "  \033[32mok\033[0m    %s\n" "$1"; }
fail() { printf "  \033[31mFAIL\033[0m  %s\n" "$1"; FAILED=$((FAILED + 1)); }

# A case this build, this system or this FRR cannot be asked, rather than
# one it answered wrongly.  Printed on every run, so a sub-case nobody has
# run for months is visible rather than absent.
skip() { printf "  \033[33mSKIP\033[0m  %s\n" "$1"; }

# A behaviour that is wrong but known to be wrong: the assertion reproduces
# it on purpose and the run is not red because of it.  The moment the
# daemon starts doing the right thing it turns into an ok and says so.
xfail() { printf "  \033[33mKNOWN\033[0m %s\n" "$1"; XFAILED=$((XFAILED + 1)); }

usage() {
	cat <<-EOF
	usage: $0 [-s SLOT] [-j JOBS] start|check|run [scenario...]
	          | run all | stop

	  -s SLOT   which lab this is, 0 to 31, default 0.  A slot names its
	            boxes, links, work directory and FRR pathspace apart from
	            every other, so one machine can hold several at once.
	  -j JOBS   how many scenarios to run at the same time, in slots
	            \$SLOT upwards, one slot each.  Default 1.

	Scenarios: $SCENARIOS.  "run all" walks them in that order.
	EOF
}

set_scenario() {
	case ${1:-$SCENARIO} in
	frr-rp|pimd-rp|autorp) SCENARIO=${1:-$SCENARIO} ;;
	*) usage; exit 2 ;;
	esac

	# Read by everything that walks the topology, so a scenario left
	# behind by a previous "run all" cannot leak into the next one.
	case $SCENARIO in
	pimd-rp)
		BOXES=$RP_BOXES
		EPAIRS=$RP_EPAIRS
		RP_ADDR=$R1_ADDR ;;
	*)
		BOXES=$DEFAULT_BOXES
		EPAIRS=$DEFAULT_EPAIRS
		RP_ADDR=$FRR_ADDR ;;
	esac
}

# --- topology ---------------------------------------------------------
#
# The tables create_box() in the backends reads.  One case per box, and
# nothing in them is scenario dependent except ED4's link, which only
# pimd-rp builds.

DEFAULT_BOXES="ed1 r1 r2 r3 ed2"
DEFAULT_EPAIRS="${EP}901 ${EP}912 ${EP}923 ${EP}903"
RP_BOXES="ed1 r1 r2 r3 ed2 ed4"
RP_EPAIRS="$DEFAULT_EPAIRS ${EP}924"

# Every box and link either scenario can build, for a teardown that has to
# clean up after a run that is not the current one.
ALL_BOXES=$RP_BOXES
ALL_EPAIRS=$RP_EPAIRS

# The pimd routers.  R2 is FRR and is started and stopped by hand.
ROUTERS="r1 r3"

BOXES=$DEFAULT_BOXES
EPAIRS=$DEFAULT_EPAIRS
RP_ADDR=$FRR_ADDR

ED1_IF=${EP}901a
ED2_IF=${EP}903b
ED4_IF=${EP}924b
R1_LAN_IF=${EP}901b
R1_FRR_IF=${EP}912a
FRR_R1_IF=${EP}912b
FRR_R3_IF=${EP}923a
FRR_LAN_IF=${EP}924a
R3_FRR_IF=${EP}923b
R3_LAN_IF=${EP}903a

# There are no shared segments here: every link has exactly two ends.  The
# backends' create_lans() and destroy_links() ask, so answer.
is_shared_lan() { false; }
BR_UPSTREAM=
BR_RECEIVER=
BR_UPSTREAM_EPAIRS=
BR_RECEIVER_EPAIRS=

ifaces() {
	case $1 in
	ed1) echo "${EP}901a" ;;
	r1)  echo "${EP}901b ${EP}912a" ;;
	r2)  if [ "$SCENARIO" = pimd-rp ]; then
		echo "${EP}912b ${EP}923a ${EP}924a"
	     else
		echo "${EP}912b ${EP}923a"
	     fi ;;
	r3)  echo "${EP}923b ${EP}903a" ;;
	ed2) echo "${EP}903b" ;;
	ed4) echo "${EP}924b" ;;
	esac
}

addrs() {
	case $1 in
	ed1) echo "${EP}901a 10.0.1.10/24" ;;
	r1)  echo "${EP}901b 10.0.1.1/24 ${EP}912a 10.0.12.1/24" ;;
	r2)  if [ "$SCENARIO" = pimd-rp ]; then
		echo "${EP}912b 10.0.12.2/24 ${EP}923a 10.0.23.2/24 ${EP}924a 10.0.4.2/24"
	     else
		echo "${EP}912b 10.0.12.2/24 ${EP}923a 10.0.23.2/24"
	     fi ;;
	r3)  echo "${EP}923b 10.0.23.3/24 ${EP}903a 10.0.3.1/24" ;;
	ed2) echo "${EP}903b 10.0.3.10/24" ;;
	ed4) echo "${EP}924b 10.0.4.10/24" ;;
	esac
}

routes() {
	case $1 in
	ed1) echo "default 10.0.1.1" ;;
	r1)  echo "10.0.23.0/24 10.0.12.2 10.0.3.0/24 10.0.12.2 10.0.4.0/24 10.0.12.2" ;;
	r2)  echo "10.0.1.0/24 10.0.12.1 10.0.3.0/24 10.0.23.3" ;;
	r3)  echo "10.0.12.0/24 10.0.23.2 10.0.1.0/24 10.0.23.2 10.0.4.0/24 10.0.23.2" ;;
	ed2) echo "default 10.0.3.1" ;;
	ed4) echo "default 10.0.4.2" ;;
	esac
}

# Nothing here renames an interface, carries a second address, builds a
# tunnel, or needs a route metric or a route protocol.  The backends walk
# all five tables for every box, so all five have to answer.
renames()      { :; }
aliases()      { :; }
tunnels()      { :; }
route_metrics() { :; }
route_protos() { :; }

# --- helpers ----------------------------------------------------------

# Retry a command until it succeeds or $1 seconds have passed.  PIM is slow
# by design, so every assertion polls instead of sleeping a fixed amount.
wait_for() {
	timeout=$1
	shift
	while [ "$timeout" -gt 0 ]; do
		if "$@" >/dev/null 2>&1; then
			return 0
		fi
		sleep 1
		timeout=$((timeout - 1))
	done
	return 1
}

check_req() {
	[ "$(id -u)" -eq 0 ] || ${SUDO} -n true 2>/dev/null || \
		die "need root or passwordless sudo"
	[ -x "$PIMD" ] || die "$PIMD not found, build it first (PIMD_SRC=$PIMD_SRC)"
	[ -x "$PIMCTL" ] || die "$PIMCTL not found, build it first"
	[ -f "$PIMD_SRC/test/mping.c" ] || die "$PIMD_SRC/test/mping.c not found"

	[ -n "$FRR_LIB" ] || \
		die "no FRR daemons found; install FRR (net/frr10, or the frr" \
		    "package) or set FRR_LIB to where zebra and pimd live"
	[ -x "$FRR_LIB/pimd" ] || die "$FRR_LIB/pimd not found"
	[ -x "$FRR_LIB/zebra" ] || die "$FRR_LIB/zebra not found"
	[ -x "$VTYSH" ] || die "$VTYSH not found, FRR's vtysh is how this lab reads FRR"
	id "$FRR_USER" >/dev/null 2>&1 || \
		die "no such user \"$FRR_USER\"; FRR must run as its packaged" \
		    "user, set FRR_USER if the package here uses another"

	check_apparmor

	backend_check_req
}

# Ubuntu confines FRR's pimd with AppArmor, and the packaged profile grants
# it exactly @{run}/frr/<daemon>.pid and @{run}/frr/<daemon>.vty -- no
# subdirectory -- so the pathspace this lab gives every slot is denied and
# FRR's pimd exits before it opens anything.  The symptom is
# indistinguishable from a daemon that crashed, "FRR pimd never opened its
# vty" and an empty log, and the denial is only in dmesg.  So it is asked
# about here, with the fix the profile itself points at: /etc/apparmor.d/
# local/<profile> is the override file Canonical ships the profile with.
#
# Not applied automatically.  A test script that edits the host's mandatory
# access control policy behind the user's back is worse than one that
# stops and says which two commands to run.
check_apparmor() {
	[ "$(uname -s)" = Linux ] || return 0
	[ -r /sys/kernel/security/apparmor/profiles ] || \
		${SUDO} test -r /sys/kernel/security/apparmor/profiles || return 0

	${SUDO} grep -q '^pimd (enforce)' /sys/kernel/security/apparmor/profiles \
		2>/dev/null || return 0
	grep -q 'frr' /etc/apparmor.d/local/pimd 2>/dev/null && return 0

	# Printed rather than passed to die(): the override is two commands to
	# copy, and die() would run them together on one line -- and turn the
	# two characters the printf needs into real newlines.
	cat >&2 <<-EOF
	EXIT: AppArmor confines $FRR_LIB/pimd, and the profile it ships with
	allows no pathspace under $FRR_RUNDIR, which is where each slot keeps
	its FRR state.  The daemon exits before it opens anything, which looks
	exactly like a crash.  Allow it once, with the override file the
	profile itself points at, and run this again:

	  printf '@{run}/frr/*/ rw,\n@{run}/frr/** rwk,\n' | sudo tee /etc/apparmor.d/local/pimd
	  sudo apparmor_parser -r /etc/apparmor.d/pimd
	EOF
	exit 1
}

# --- configuration ----------------------------------------------------

# One pimd.conf per pimd router, plus the FRR configuration the lab feeds
# to vtysh once the FRR daemons are up.
#
# Why vtysh rather than a config file FRR reads at startup: interface level
# "ip pim" in a file handed to pimd with -f is silently dropped by FRR 10.7
# in this arrangement -- the running config comes up with the router pim
# block and no interfaces -- while the same lines applied over vtysh take
# every time.  A lab that cannot tell "FRR refused the message" from "FRR
# was never configured for that interface" is worth nothing, so the
# configuration is applied the way that can be read back.
write_configs() {
	# hello-interval is moved off the 30s default in every scenario, and
	# only so that neighbour discovery takes seconds: nothing here
	# asserts on the timer itself.
	cat > "$WORKDIR/r1.conf" <<-EOF
		# R1, $SCENARIO
		hello-interval 10
		phyint $R1_LAN_IF enable
		phyint $R1_FRR_IF enable
	EOF

	case $SCENARIO in
	frr-rp)
		# BSR and nothing else: the RP in this scenario is FRR's,
		# and an rp-candidate here would hide a Candidate-RP-
		# Advertisement that never arrived behind pimd's own.
		cat >> "$WORKDIR/r1.conf" <<-EOF
			bsr-candidate $R1_ADDR priority $PIMD_BSR_PRIORITY interval 10
		EOF
		;;
	pimd-rp)
		# Candidate-RP and nothing else: FRR is the BSR here, and a
		# bsr-candidate on R1 would race it for the role the
		# scenario is about.
		#
		# spt-threshold is the other timer that has to move.  An RP
		# re-evaluates the switch to the shortest path tree only
		# every spt_threshold.interval, 100s by default
		# (SPT_THRESHOLD_DEFAULT_INTERVAL in src/pimd.h), and until
		# it has switched it is still legitimately asking FRR to
		# encapsulate: measured over a shorter stream, assertion 6
		# would report which side of a timer it landed on rather
		# than whether the Register-Stop was honoured.  Left at the
		# default it reports one Register per data packet, which is
		# pimd on both ends of the same exchange as well -- an RP
		# that does not want the source tree keeps the DR
		# encapsulating, and RFC 7761 sec. 4.4.2 has it that way.
		cat >> "$WORKDIR/r1.conf" <<-EOF
			rp-candidate $R1_ADDR priority $PIMD_CRP_PRIORITY interval 10
			group-prefix 224.0.0.0 masklen 4
			spt-threshold packets 0 interval 10
		EOF
		;;
	autorp)
		# No BSR, no Candidate-RP: an RP that turns up anywhere in
		# this scenario came out of an Auto-RP message.
		cat >> "$WORKDIR/r1.conf" <<-EOF
			autorp announce $R1_ADDR interval $AUTORP_INTERVAL holdtime $AUTORP_HOLDTIME
			autorp group-prefix ${AUTORP_RANGE%/*} masklen ${AUTORP_RANGE#*/}
		EOF
		;;
	esac

	cat > "$WORKDIR/r3.conf" <<-EOF
		# R3, $SCENARIO.  Last hop router, no candidacy of any kind:
		# every RP it holds was learned from the wire.
		hello-interval 10
		phyint $R3_FRR_IF enable
		phyint $R3_LAN_IF enable
	EOF

	# The two FRR daemons want a file each at startup.  They hold the
	# hostname and the log, and every line the scenario is about is
	# applied afterwards through vtysh; see frr_start().
	cat > "$WORKDIR/zebra.conf" <<-EOF
		hostname r2
		log file $WORKDIR/r2.log
	EOF
	cat > "$WORKDIR/frr-pimd.conf" <<-EOF
		hostname r2
		log file $WORKDIR/r2.log
	EOF

	write_frr_conf
}

# The FRR configuration proper, in the form vtysh -f reads: config mode
# commands, no "configure terminal" line (vtysh -f is a config file reader,
# and would reject one).
write_frr_conf() {
	{
		echo "interface $FRR_R1_IF"
		echo " ip pim"
		echo "exit"
		echo "interface $FRR_R3_IF"
		echo " ip pim"
		echo "exit"
		if [ "$SCENARIO" = pimd-rp ]; then
			echo "interface $FRR_LAN_IF"
			echo " ip pim"
			echo " ip igmp"
			echo "exit"
		fi
		echo "router pim"
		case $SCENARIO in
		frr-rp)
			# Candidate-RP to R1's BSR, for everything.
			echo " bsr candidate-rp source address $FRR_ADDR"
			echo " bsr candidate-rp group 224.0.0.0/4"
			;;
		pimd-rp)
			echo " bsr candidate-bsr priority $FRR_BSR_PRIORITY source address $FRR_ADDR"
			;;
		autorp)
			# Step (a): listener and mapping agent.  The
			# announcing half is added by frr_autorp_swap()
			# once the first half has been asserted.
			echo " autorp discovery"
			echo " autorp send-rp-discovery source address $FRR_ADDR"
			echo " autorp send-rp-discovery interval $AUTORP_INTERVAL holdtime $AUTORP_HOLDTIME"
			;;
		esac
		echo "exit"
	} > "$WORKDIR/frr.conf"
}

# autorp, step (b): the same two daemons with the roles swapped, without
# rebuilding anything.  FRR stops being the mapping agent and becomes a
# candidate RP; R1 stops announcing and becomes the agent.  Both halves are
# needed -- an FRR that kept sending Discovery messages would answer step
# (b)'s assertions with step (a)'s state.
frr_autorp_swap() {
	cat > "$WORKDIR/frr-swap.conf" <<-EOF
		router pim
		 no autorp send-rp-discovery
		 autorp announce $FRR_ADDR $AUTORP_RANGE_B
		 autorp announce interval $AUTORP_INTERVAL holdtime $AUTORP_HOLDTIME
		exit
	EOF
	frr_apply "$WORKDIR/frr-swap.conf"

	cat > "$WORKDIR/r1.conf" <<-EOF
		# R1, autorp step (b): the mapping agent
		hello-interval 10
		phyint $R1_LAN_IF enable
		phyint $R1_FRR_IF enable
		autorp mapping-agent $R1_ADDR interval $AUTORP_INTERVAL holdtime $AUTORP_HOLDTIME
	EOF
	restart_pimd r1
}

# --- pimd -------------------------------------------------------------

pimctl() { pc_box=$1; shift; box_run "$pc_box" "$PIMCTL" -u "$WORKDIR/$pc_box.sock" "$@"; }

start_pimd() {
	sp_r=$1

	# shellcheck disable=SC2086
	box_daemon "$sp_r" "$WORKDIR/$sp_r.daemon.pid" "$WORKDIR/$sp_r.log" \
		"$PIMD" -i "frr$TAG$sp_r" -n $DEBUG \
		-f "$WORKDIR/$sp_r.conf" \
		-p "$WORKDIR/$sp_r.pid" \
		-u "$WORKDIR/$sp_r.sock"
}

pimd_is_up()   { pimctl "$1" show status >/dev/null 2>&1; }
pimd_is_down() { ! pimd_is_up "$1"; }

stop_pimd() {
	[ -f "$WORKDIR/$1.daemon.pid" ] || return 0
	${SUDO} pkill -F "$WORKDIR/$1.daemon.pid" 2>/dev/null || true
	${SUDO} rm -f "$WORKDIR/$1.daemon.pid"
	wait_for 15 pimd_is_down "$1" || true
}

# The same command line again, which is what keeps a router that comes back
# the router the rest of the scenario was written against.
restart_pimd() {
	stop_pimd "$1"
	start_pimd "$1"
	wait_for "$PIMD_START_WAIT" pimd_is_up "$1" || \
		die "$1 did not come back after a restart"
}

# --- FRR --------------------------------------------------------------

# vtysh, in the FRR box, against this lab's pathspace.
#
# --config_dir is not decoration: with -N alone vtysh looks for
# <sysconfdir>/<pathspace>/vtysh.conf, does not find it, and says so on
# every single call.  Pointed at the work directory, where start() leaves
# an empty pair of files, it is quiet, and nothing outside the lab is
# written.  stderr carries FRR's socket buffer grumbling and is dropped;
# a command that fails says so on stdout, which is what the callers read.
frr_cli() {
	box_run "$FRR_BOX" "$VTYSH" -N "$FRR_NS" --config_dir "$WORKDIR" "$@" 2>/dev/null
}

frr_show() { frr_cli -c "$1"; }

# Feed a config file to the running daemons.  vtysh prints a line per
# daemon it hands the configuration to, which is noise here.
frr_apply() {
	frr_cli -f "$1" | grep -v -e '^\[[0-9]*|' -e '^Waiting for children' || true
}

frr_is_up() { frr_show "show ip pim interface" >/dev/null 2>&1; }

frr_start() {
	${SUDO} mkdir -p "$FRR_DIR"
	${SUDO} chown "$FRR_USER" "$FRR_DIR"

	# The FRR daemons run as $FRR_USER and write their log where the
	# pimd logs are, so the file has to be theirs.  Created here rather
	# than left to them: a log they cannot open is a log the run loses.
	${SUDO} rm -f "$WORKDIR/r2.log"
	: > "$WORKDIR/r2.log"
	${SUDO} chown "$FRR_USER" "$WORKDIR/r2.log"

	# vtysh reads a vtysh.conf and an frr.conf out of --config_dir/-N;
	# empty ones keep it quiet, see frr_cli().
	mkdir -p "$WORKDIR/$FRR_NS"
	: > "$WORKDIR/$FRR_NS/vtysh.conf"
	: > "$WORKDIR/$FRR_NS/frr.conf"
	chmod -R a+rX "$WORKDIR"

	# A vnet jail starts with its loopback down, and FRR wants one: a
	# Candidate-RP-Advertisement is a unicast packet to the BSR, and
	# with the BSR on this box it has nowhere else to go.
	box_if_up "$FRR_BOX" "$LOOPBACK_IF" >/dev/null 2>&1 || true

	box_run "$FRR_BOX" "$FRR_LIB/zebra" -d -N "$FRR_NS" \
		-f "$WORKDIR/zebra.conf" >/dev/null 2>&1 || \
		die "could not start FRR zebra in $FRR_BOX"
	wait_for "$FRR_START_WAIT" test -S "$FRR_DIR/zebra.vty" || \
		die "FRR zebra never opened $FRR_DIR/zebra.vty"

	box_run "$FRR_BOX" "$FRR_LIB/pimd" -d -N "$FRR_NS" \
		-f "$WORKDIR/frr-pimd.conf" >/dev/null 2>&1 || \
		die "could not start FRR pimd in $FRR_BOX"
	wait_for "$FRR_START_WAIT" test -S "$FRR_DIR/pimd.vty" || \
		die "FRR pimd never opened $FRR_DIR/pimd.vty"

	wait_for "$FRR_START_WAIT" frr_is_up || \
		die "FRR never answered vtysh, see $WORKDIR/r2.log"

	frr_apply "$WORKDIR/frr.conf"
}

frr_stop() {
	for d in pimd zebra; do
		[ -f "$FRR_DIR/$d.pid" ] || continue
		${SUDO} pkill -F "$FRR_DIR/$d.pid" 2>/dev/null || true
	done
	${SUDO} rm -rf "$FRR_DIR"
}

# --- what each side believes -------------------------------------------

has_neighbor() { pimctl "$1" show neighbor 2>/dev/null | grep -q "$2"; }
has_rp()       { pimctl "$1" show rp 2>/dev/null | grep -q "$2"; }
has_mrt()      { pimctl "$1" show mrt 2>/dev/null | grep -q "$2"; }

# The DR pimd elected on interface $2 of router $1.  "show interface"
# prints "Interface State Address Priority Hello Nbr DR-Address DR-Priority".
pimd_dr() {
	pimctl "$1" show interface 2>/dev/null | awk -v i="$2" '$1 == i { print $7 }'
}
pimd_dr_is() { [ "$(pimd_dr "$1" "$2")" = "$3" ]; }

# The BSR pimd elected, and the priority it read out of that Bootstrap.
# "show status" prints an "Elected BSR" block of indented "key : value".
pimd_bsr() {
	pimctl "$1" show status 2>/dev/null | awk '
		/^Elected BSR/       { in_bsr = 1; next }
		in_bsr && /^[A-Za-z]/ { exit }
		in_bsr && $1 == "Address" { print $3; exit }'
}
pimd_bsr_is() { [ "$(pimd_bsr "$1")" = "$2" ]; }

pimd_bsr_priority() {
	pimctl "$1" show status 2>/dev/null | awk '
		/^Elected BSR/        { in_bsr = 1; next }
		in_bsr && /^[A-Za-z]/ { exit }
		in_bsr && $1 == "Priority" { print $3; exit }'
}

# The RP pimd holds for a group range, and where it says it came from.
# "show rp" prints "Group-Address RP-Address Prio Holdtime Type", and Type
# is what tells a Bootstrap RP from an Auto-RP one from a configured one --
# an assertion on the address alone would pass on a static rp-address.
pimd_rp_row() {
	pimctl "$1" -t show rp 2>/dev/null | awk -v g="$2" '$1 == g { print; exit }'
}
#
# The wanted values are saved before "set --" walks the row, or the
# positional parameters the caller passed would be the ones being compared
# against themselves.
pimd_rp_is() {
	pr_rp=$3
	set -- $(pimd_rp_row "$1" "$2")
	[ "${2:-}" = "$pr_rp" ]
}
pimd_rp_origin_is() {
	pr_rp=$3
	pr_origin=$4
	set -- $(pimd_rp_row "$1" "$2")
	[ "${2:-}" = "$pr_rp" ] && [ "${5:-}" = "$pr_origin" ]
}

# The candidate RPs pimd's BSR has heard Advertisements from.  "show crp"
# is the BSR's own table, so this is the message FRR wrote as parsed by
# pimd and not an RP pimd was configured with.
pimd_crp_row() {
	pimctl "$1" -t show crp 2>/dev/null | awk -v rp="$2" '$2 == rp || $1 == rp { print; exit }'
}
pimd_has_crp() { [ -n "$(pimd_crp_row "$1" "$2")" ]; }

# Auto-RP, as pimd has it: "show autorp" prints the agent or announcer
# configuration and then one row per mapping, "Group RP Holdtime Agent".
# "show autorp" prints the announcing or agent configuration first, and the
# ranges under it are lines whose first field is a group range too -- so a
# mapping row is told from one by having all four fields.
pimd_autorp_row() {
	pimctl "$1" -t show autorp 2>/dev/null | \
		awk -v g="$2" 'NF >= 4 && $1 == g { print; exit }'
}
pimd_autorp_is() {
	pa_rp=$3
	set -- $(pimd_autorp_row "$1" "$2")
	[ "${2:-}" = "$pa_rp" ]
}
pimd_autorp_agent_is() {
	pa_rp=$3
	pa_agent=$4
	set -- $(pimd_autorp_row "$1" "$2")
	[ "${2:-}" = "$pa_rp" ] && [ "${4:-}" = "$pa_agent" ]
}

# What pimd's own mapping agent has heard from the candidate RPs, which is
# a line of its own in "show autorp": "heard <rp> for <range>".
pimd_autorp_heard() {
	pimctl "$1" show autorp 2>/dev/null | \
		grep -q "heard $2 .*${3}"
}

# Vif index of interface $2 on router $1.  "show interface" prints one row
# per vif in vif order and skips the register vif, which src/vif.h reserves
# as vif 0, so the Nth row is vif N.
vif_index() {
	pimctl "$1" -t show interface 2>/dev/null | \
		awk -v ifn="$2" 'NF { n++; if ($1 == ifn) { print n; exit } }'
}

# Any of the per-vif maps of ($2,$3) on router $1, named by the first word
# of its line in "show mrt detail": Joined, Pruned, Leaves, Asserted or
# Outgoing.  One character per vif, '.' where the vif is not in the set.
route_map() {
	pimctl "$1" show mrt detail 2>/dev/null | awk -v s="$2" -v g="$3" -v k="$4" '
		$1 == s && $2 == g { want = 1; next }
		want && $1 == k    { print $3; want = 0 }
	'
}

map_isset() {
	mi_idx=$(vif_index "$1" "$2")
	[ -n "$mi_idx" ] || return 1
	[ -n "$3" ] || return 1

	[ "$(printf '%s' "$3" | cut -c "$((mi_idx + 1))")" != "." ]
}

# Has router $1 put interface $2 in the outgoing list of its (*,$3), i.e.
# did it act on a Join that arrived there?
joined_on() {
	map_isset "$1" "$2" "$(route_map "$1" ANY "$3" Joined)"
}

# Vif index of the incoming interface of ($2,$3) on router $1.  "show mrt
# detail" prints the iif as a per-vif map with 'I' on the incoming one, so
# the offset of the 'I' is the vif number, and vif 0 is the register vif --
# a non-zero answer means the traffic arrives natively.
route_iif() {
	pimctl "$1" show mrt detail 2>/dev/null | awk -v s="$2" -v g="$3" '
		$1 == s && $2 == g       { want = 1; next }
		want && $1 == "Incoming" { print index($3, "I") - 1; want = 0 }
	'
}

# --- what FRR believes -------------------------------------------------

frr_has_neighbor() { frr_show "show ip pim neighbor" 2>/dev/null | grep -q "$1"; }

# The DR FRR elected on one interface.  The per-interface detail prints a
# "Designated Router" block with an indented "Address : <addr>"; the brief
# table says "local" for FRR's own win and would need a second lookup to
# turn that into an address.
frr_dr() {
	frr_show "show ip pim interface $1" 2>/dev/null | awk '
		/^Designated Router/  { in_dr = 1; next }
		in_dr && $1 == "Address" { print $3; exit }'
}
frr_dr_is() { [ "$(frr_dr "$1")" = "$2" ]; }

# The BSR FRR elected, and the priority it read out of pimd's Bootstrap.
# "show ip pim bsr" prints "Current preferred BSR address: <addr>" and then
# a "Priority Fragment-Tag State UpTime" table with one row.
frr_bsr() {
	frr_show "show ip pim bsr" 2>/dev/null | \
		awk '/Current preferred BSR address:/ { print $NF; exit }'
}
frr_bsr_is() { [ "$(frr_bsr)" = "$1" ]; }

frr_bsr_priority() {
	frr_show "show ip pim bsr" 2>/dev/null | awk '
		/^Priority/ { want = 1; next }
		want && NF  { print $1; exit }'
}

# The candidate RPs FRR's BSR has heard Advertisements from, "show ip pim
# bsr candidate-rp-database": "RP/Group NHT Prio Uptime Hold" with the RP
# address in the first column.
frr_crp_row() {
	frr_show "show ip pim bsr candidate-rp-database" 2>/dev/null | \
		awk -v rp="$1" '$1 == rp { print; exit }'
}
frr_has_crp() { [ -n "$(frr_crp_row "$1")" ]; }
frr_crp_priority() {
	set -- $(frr_crp_row "$1")
	echo "${3:-}"
}

# Does FRR hold this RP?  "show ip pim rp-info" prints "RP-address
# group/prefix-list OIF I-am-RP Source Group-Type", and Source is what says
# whether it came from a Bootstrap, from Auto-RP or from its own config.
frr_rp_row() {
	frr_show "show ip pim rp-info" 2>/dev/null | \
		awk -v rp="$1" -v g="$2" '$1 == rp && $2 == g { print; exit }'
}
frr_has_rp()    { [ -n "$(frr_rp_row "$1" "$2")" ]; }
frr_rp_source() {
	set -- $(frr_rp_row "$1" "$2")
	echo "${5:-}"
}
frr_rp_source_is() { [ "$(frr_rp_source "$1" "$2")" = "$3" ]; }

# Is FRR the RP for that range, as it sees it -- the "I am RP" column.
frr_is_rp_for() {
	set -- $(frr_rp_row "$1" "$2")
	[ "${4:-}" = yes ]
}

# Auto-RP as FRR has it.  "show ip pim autorp" prints three blocks --
# Discovered RP's, Candidate RP's, Advertised RP's -- each a table of
# "RP-address Group-Range".  Which block a row is in is the whole point:
# Discovered is what FRR learned from a Discovery message somebody else
# sent, Advertised is what FRR's own mapping agent resolved.
frr_autorp_in_block() {
	frr_show "show ip pim autorp" 2>/dev/null | awk -v b="$1" -v rp="$2" -v g="$3" '
		index($0, b) == 1 { in_block = 1; next }
		in_block && index($0, "AutoRP") == 1 { in_block = 0 }
		in_block && $1 == rp && $2 == g { found = 1 }
		END { exit !found }'
}
frr_autorp_discovered() { frr_autorp_in_block "Discovered RP's" "$1" "$2"; }
frr_autorp_advertised() { frr_autorp_in_block "Advertised RP's" "$1" "$2"; }

# Does FRR hold an (S,G)?  "show ip mroute" prints "Source Group Flags Proto
# Input Output TTL Uptime".
frr_has_sg() {
	frr_show "show ip mroute" 2>/dev/null | \
		awk -v s="$1" -v g="$2" '$1 == s && $2 == g { found = 1 } END { exit !found }'
}

# --- streams ------------------------------------------------------------

# mping's receiver answers every packet to the same group, so one run
# builds a tree in each direction and the sender's own statistics line is
# the measurement: a reply exists only because a packet arrived.
stream() {
	st_rbox=$1
	st_rif=$2
	st_sbox=$3
	st_sif=$4
	st_count=$5
	st_group=$6
	st_log=$7

	box_run "$st_rbox" "$MPING" -r -i "$st_rif" -t 5 -W 300 "$st_group" \
		> "$WORKDIR/receiver.log" 2>&1 &
	st_receiver=$!
	sleep 2

	box_run "$st_sbox" "$MPING" -s -i "$st_sif" -t 5 -c "$st_count" \
		-w $((st_count + 60)) "$st_group" > "$st_log" 2>&1 || true

	kill "$st_receiver" 2>/dev/null || true
	wait "$st_receiver" 2>/dev/null || true
	# mping is killed rather than stopped, so the receiver's own log
	# never reaches the disk; the sender's does.
	${SUDO} pkill -f "$MPING -r" 2>/dev/null || true
}

replies_in() {
	r_n=$(awk '/packets transmitted/ { print $4 }' "$1" 2>/dev/null)
	echo "${r_n:-0}"
}

# --- start and stop -----------------------------------------------------

start() {
	check_req

	if box_exists r1; then
		die "lab already running in slot $SLOT, run '$0 -s $SLOT stop' first"
	fi

	# Past that guard the boxes of this slot are this run's to take down
	# again, which is what run_one_died() asks before it does.
	LAB_OURS=yes

	mkdir -p "$WORKDIR"

	print "Building mping (multicast ping) from the pimd tree ..."
	cc -O2 -o "$MPING" "$PIMD_SRC/test/mping.c" || \
		die "failed building $PIMD_SRC/test/mping.c"

	print "Disabling multicast loopback on the host (restored by stop) ..."
	disable_mcast_loop

	write_configs

	print "Creating boxes and links ..."
	create_lans
	for box in $BOXES; do
		create_box "$box"
	done

	print "Starting pimd on $(echo $ROUTERS | tr ' ' ',') ..."
	for r in $ROUTERS; do
		# box_daemon() appends to the log, and assertions that read
		# it would otherwise be reading the previous run too.
		${SUDO} rm -f "$WORKDIR/$r.log"
		start_pimd "$r"
	done
	for r in $ROUTERS; do
		wait_for "$PIMD_START_WAIT" pimd_is_up "$r" || \
			die "pimd on $r never answered on its socket, see $WORKDIR/$r.log"
	done

	print "Starting FRR ($($FRR_LIB/pimd --version 2>&1 | head -1)) on $FRR_BOX ..."
	frr_start

	print "Lab is up ($SCENARIO).  Poke at it with:"
	echo "  $(box_hint r1) $PIMCTL -u $WORKDIR/r1.sock show pim detail"
	echo "  $(box_hint $FRR_BOX) $VTYSH -N $FRR_NS --config_dir $WORKDIR -c 'show ip pim rp-info'"
	echo "  tail -f $WORKDIR/r1.log $WORKDIR/r2.log"
}

stop() {
	frr_stop

	for r in $ROUTERS; do
		stop_pimd "$r"
	done

	${SUDO} pkill -f "$MPING " 2>/dev/null || true

	# Every box and link any scenario can have built, not just this
	# one's: "run all" switches scenarios between runs, and a stop that
	# only tore down what $SCENARIO names would leave the other one's
	# box behind to collide with the next run.
	for box in $ALL_BOXES; do
		destroy_box "$box"
	done
	destroy_links

	restore_mcast_loop
	print "Lab stopped"
}

# --- assertions ---------------------------------------------------------

# The two links, from both sides.  Every scenario starts here: an
# assertion about a Bootstrap means nothing until the two daemons agree on
# who is on the wire and who is the DR.
check_adjacency() {
	print "1. pimd and FRR become PIM neighbours on both links"
	if wait_for 60 has_neighbor r1 "$FRR_ADDR"; then
		ok "R1 sees FRR at $FRR_ADDR"
	else
		fail "R1 never saw a PIM neighbour at $FRR_ADDR"
	fi
	if wait_for 60 has_neighbor r3 "$FRR_R3_ADDR"; then
		ok "R3 sees FRR at $FRR_R3_ADDR"
	else
		fail "R3 never saw a PIM neighbour at $FRR_R3_ADDR"
	fi
	if wait_for 60 frr_has_neighbor "$R1_ADDR"; then
		ok "FRR sees R1 at $R1_ADDR"
	else
		fail "FRR never saw a PIM neighbour at $R1_ADDR"
	fi
	if wait_for 60 frr_has_neighbor "$R3_ADDR"; then
		ok "FRR sees R3 at $R3_ADDR"
	else
		fail "FRR never saw a PIM neighbour at $R3_ADDR"
	fi
	[ "$FAILED" -eq 0 ] || return 1

	print "2. DR election, one link each way, agreed by both sides"
	# 10.0.12.0/24: both daemons run the default priority, so the
	# highest address wins and that is FRR.  10.0.23.0/24: R3's .3 beats
	# FRR's .2.  Each is read from both ends, because a DR election both
	# sides get wrong in the same way is the failure this lab exists for.
	if wait_for 60 pimd_dr_is r1 "$R1_FRR_IF" "$FRR_ADDR"; then
		ok "R1 makes FRR the DR on 10.0.12.0/24"
	else
		fail "R1 has DR '$(pimd_dr r1 "$R1_FRR_IF")' on 10.0.12.0/24, expected $FRR_ADDR"
	fi
	if wait_for 60 frr_dr_is "$FRR_R1_IF" "$FRR_ADDR"; then
		ok "FRR makes itself the DR on 10.0.12.0/24"
	else
		fail "FRR has DR '$(frr_dr "$FRR_R1_IF")' on 10.0.12.0/24, expected $FRR_ADDR"
	fi
	if wait_for 60 pimd_dr_is r3 "$R3_FRR_IF" "$R3_ADDR"; then
		ok "R3 makes itself the DR on 10.0.23.0/24"
	else
		fail "R3 has DR '$(pimd_dr r3 "$R3_FRR_IF")' on 10.0.23.0/24, expected $R3_ADDR"
	fi
	if wait_for 60 frr_dr_is "$FRR_R3_IF" "$R3_ADDR"; then
		ok "FRR makes R3 the DR on 10.0.23.0/24"
	else
		fail "FRR has DR '$(frr_dr "$FRR_R3_IF")' on 10.0.23.0/24, expected $R3_ADDR"
	fi

	return $((FAILED > 0))
}

# frr-rp: pimd writes the Bootstrap, FRR writes the Candidate-RP-
# Advertisement, and FRR is the RP the traffic goes through.
check_frr_rp() {
	check_adjacency || return 1

	print "3. pimd's BSR takes the Candidate-RP-Advertisement FRR wrote"
	if wait_for 90 pimd_has_crp r1 "$FRR_ADDR"; then
		ok "R1's candidate RP set holds $FRR_ADDR"
	else
		fail "R1 never heard a Candidate-RP-Advertisement from $FRR_ADDR"
		dprint "$(pimctl r1 show crp)"
		return 1
	fi
	# The priority beside the address: a field that arrives mangled is
	# invisible as long as only the address is looked at.
	if wait_for 60 pimd_rp_is r1 224.0.0.0/4 "$FRR_ADDR"; then
		ok "R1 holds RP $FRR_ADDR for 224.0.0.0/4"
	else
		fail "R1's RP for 224.0.0.0/4 is '$(pimd_rp_row r1 224.0.0.0/4)'"
	fi
	set -- $(pimd_rp_row r1 224.0.0.0/4)
	if [ "${3:-}" = "$FRR_CRP_PRIORITY" ]; then
		ok "R1 read Candidate-RP priority $FRR_CRP_PRIORITY out of it"
	else
		fail "R1 read Candidate-RP priority '${3:-}', expected $FRR_CRP_PRIORITY"
	fi

	print "4. FRR parses the Bootstrap pimd wrote, and floods it on"
	if wait_for 120 frr_bsr_is "$R1_ADDR"; then
		ok "FRR elected R1 at $R1_ADDR as BSR"
	else
		fail "FRR's BSR is '$(frr_bsr)', expected $R1_ADDR"
		dprint "$(frr_show 'show ip pim bsr')"
		return 1
	fi
	if [ "$(frr_bsr_priority)" = "$PIMD_BSR_PRIORITY" ]; then
		ok "FRR read BSR priority $PIMD_BSR_PRIORITY out of it"
	else
		fail "FRR read BSR priority '$(frr_bsr_priority)', expected $PIMD_BSR_PRIORITY"
		dprint "$(frr_show 'show ip pim bsr')"
	fi
	if wait_for 60 frr_is_rp_for "$FRR_ADDR" 224.0.0.0/4; then
		ok "FRR knows it is the RP for 224.0.0.0/4"
	else
		fail "FRR does not hold itself as RP for 224.0.0.0/4"
		dprint "$(frr_show 'show ip pim rp-info')"
	fi
	# R3 is two hops from the BSR with FRR in between, so it can only
	# hold the RP set because FRR forwarded a Bootstrap pimd originated.
	if wait_for 120 pimd_rp_origin_is r3 224.0.0.0/4 "$FRR_ADDR" Dynamic; then
		ok "R3 learned RP $FRR_ADDR through FRR, origin Dynamic"
	else
		fail "R3 never learned RP $FRR_ADDR from a Bootstrap FRR forwarded"
		dprint "$(pimctl r3 show rp)"
		return 1
	fi
	[ "$FAILED" -eq 0 ] || return 1

	print "5. FRR decapsulates the Register pimd writes, and ED2 is reached"
	regs_before=$(registers_rcvd "$FRR_BOX")
	stream ed2 "$ED2_IF" ed1 "$ED1_IF" "$STREAM_PKTS" "$GROUP" "$WORKDIR/sender.log"

	if frr_has_sg "$SRC_ADDR" "$GROUP"; then
		ok "FRR built ($SRC_ADDR, $GROUP) from pimd's Register"
	else
		fail "FRR never built ($SRC_ADDR, $GROUP)"
		dprint "$(frr_show 'show ip mroute')"
	fi
	regs=$(( $(registers_rcvd "$FRR_BOX") - regs_before ))
	if [ "$regs" -gt 0 ]; then
		ok "FRR's kernel decapsulated $regs Register(s) written by pimd"
	else
		fail "FRR decapsulated no Register at all"
	fi

	replies=$(replies_in "$WORKDIR/sender.log")
	if [ "$replies" -ge "$MIN_REPLIES" ]; then
		ok "$replies of $STREAM_PKTS packets answered by ED2 across FRR"
	else
		fail "only $replies of $STREAM_PKTS packets answered, wanted $MIN_REPLIES"
		dprint "$(frr_show 'show ip mroute')"
		dprint "$(pimctl r3 show mrt)"
	fi

	print "6. pimd stops registering once FRR has sent a Register-Stop"
	# Measured after the tree is up: the question is whether the first
	# hop router is still encapsulating a source it has been told to
	# stop encapsulating, not how fast the domain converged.
	regs_before=$(registers_rcvd "$FRR_BOX")
	stream ed2 "$ED2_IF" ed1 "$ED1_IF" "$SETTLED_PKTS" "$GROUP" "$WORKDIR/sender2.log"
	regs=$(( $(registers_rcvd "$FRR_BOX") - regs_before ))
	if [ "$regs" -le "$MAX_REGISTERS" ]; then
		ok "$regs Registers over $SETTLED_PKTS settled packets"
	else
		fail "$regs Registers over $SETTLED_PKTS settled packets, the Register-Stop was ignored"
	fi

	return $((FAILED > 0))
}

# pimd-rp: the mirror.  FRR writes the Bootstrap, pimd writes the
# Candidate-RP-Advertisement, and FRR is the first and last hop router.
check_pimd_rp() {
	check_adjacency || return 1

	print "3. FRR's BSR takes the Candidate-RP-Advertisement pimd wrote"
	if wait_for 120 frr_has_crp "$R1_ADDR"; then
		ok "FRR's candidate RP database holds $R1_ADDR"
	else
		fail "FRR never heard a Candidate-RP-Advertisement from $R1_ADDR"
		dprint "$(frr_show 'show ip pim bsr candidate-rp-database')"
		return 1
	fi
	if [ "$(frr_crp_priority "$R1_ADDR")" = "$PIMD_CRP_PRIORITY" ]; then
		ok "FRR read Candidate-RP priority $PIMD_CRP_PRIORITY out of it"
	else
		fail "FRR read Candidate-RP priority '$(frr_crp_priority "$R1_ADDR")'," \
		     "expected $PIMD_CRP_PRIORITY"
	fi
	if wait_for 60 frr_has_rp "$R1_ADDR" 224.0.0.0/4; then
		ok "FRR holds RP $R1_ADDR for 224.0.0.0/4"
	else
		fail "FRR never installed $R1_ADDR as RP"
		dprint "$(frr_show 'show ip pim rp-info')"
	fi

	print "4. pimd parses the Bootstrap FRR wrote, here and one hop on"
	if wait_for 120 pimd_bsr_is r1 "$FRR_ADDR"; then
		ok "R1 elected FRR at $FRR_ADDR as BSR"
	else
		fail "R1's BSR is '$(pimd_bsr r1)', expected $FRR_ADDR"
		dprint "$(pimctl r1 show status)"
		return 1
	fi
	if [ "$(pimd_bsr_priority r1)" = "$FRR_BSR_PRIORITY" ]; then
		ok "R1 read BSR priority $FRR_BSR_PRIORITY out of it"
	else
		fail "R1 read BSR priority '$(pimd_bsr_priority r1)', expected $FRR_BSR_PRIORITY"
	fi
	# R3 is two hops from the BSR, so its RP set came through FRR's own
	# Bootstrap and names an RP FRR learned from pimd: both directions
	# of the exchange in one assertion.
	if wait_for 120 pimd_rp_origin_is r3 224.0.0.0/4 "$R1_ADDR" Dynamic; then
		ok "R3 learned RP $R1_ADDR from FRR's Bootstrap"
	else
		fail "R3 never learned RP $R1_ADDR"
		dprint "$(pimctl r3 show rp)"
		return 1
	fi
	[ "$FAILED" -eq 0 ] || return 1

	print "5. pimd believes FRR's (*,G) Join and decapsulates FRR's Register"
	# ED4 hangs off FRR, so FRR is the last hop router for the stream
	# and the first hop router for the replies.  Both messages are
	# FRR's, and both are asserted on R1, the RP.
	regs_before=$(registers_rcvd r1)
	stream ed4 "$ED4_IF" ed1 "$ED1_IF" "$STREAM_PKTS" "$GROUP" "$WORKDIR/sender.log"

	if joined_on r1 "$R1_FRR_IF" "$GROUP"; then
		ok "R1 has $R1_FRR_IF in the oifs of (*, $GROUP), from FRR's Join"
	else
		fail "R1 never added $R1_FRR_IF to (*, $GROUP)"
		dprint "$(pimctl r1 show mrt detail | head -20)"
	fi
	if has_mrt r1 "$ED4_ADDR"; then
		ok "R1 built ($ED4_ADDR, $GROUP) from FRR's Register"
	else
		fail "R1 never built ($ED4_ADDR, $GROUP)"
		dprint "$(pimctl r1 show mrt)"
	fi
	regs=$(( $(registers_rcvd r1) - regs_before ))
	if [ "$regs" -gt 0 ]; then
		ok "R1's kernel decapsulated $regs Register(s) written by FRR"
	else
		fail "R1 decapsulated no Register at all"
	fi
	# A source still incoming on vif 0 is an RP living off the
	# encapsulated copies alone, which is also the only state in which
	# Register-Stopping FRR would be wrong.
	iif=$(route_iif r1 "$ED4_ADDR" "$GROUP")
	if [ -n "$iif" ] && [ "$iif" -ne 0 ]; then
		ok "R1 receives ($ED4_ADDR, $GROUP) natively on vif $iif"
	else
		fail "R1 still has ($ED4_ADDR, $GROUP) incoming on the register vif"
	fi

	replies=$(replies_in "$WORKDIR/sender.log")
	if [ "$replies" -ge "$MIN_REPLIES" ]; then
		ok "$replies of $STREAM_PKTS packets answered by ED4 behind FRR"
	else
		fail "only $replies of $STREAM_PKTS packets answered, wanted $MIN_REPLIES"
		dprint "$(frr_show 'show ip mroute')"
		dprint "$(pimctl r1 show mrt)"
	fi

	print "6. FRR stops registering once pimd has sent a Register-Stop"
	regs_before=$(registers_rcvd r1)
	stream ed4 "$ED4_IF" ed1 "$ED1_IF" "$SETTLED_PKTS" "$GROUP" "$WORKDIR/sender2.log"
	regs=$(( $(registers_rcvd r1) - regs_before ))
	if [ "$regs" -le "$MAX_REGISTERS" ]; then
		ok "$regs Registers over $SETTLED_PKTS settled packets"
	else
		fail "$regs Registers over $SETTLED_PKTS settled packets, the Register-Stop was ignored"
	fi

	return $((FAILED > 0))
}

# autorp: the same chain with no BSR anywhere, run in both directions.
#
# Control plane only, and the reason is a gap both implementations have:
# the Announcement and the Discovery are flooded hop by hop in the draft
# (sec. 3.3), and neither daemon floods them.  pimd sends its own out of
# every PIM interface, FRR sends its Discovery out of the one link its
# source address is on -- measured here, with and without an explicit
# source -- so the pair of them cover one link and nothing beyond it.  R3,
# one hop further, holds no mapping in either direction and is not asserted
# on; a run where it does would mean an FRR that started flooding, and the
# streams that prove an RP works live in the two BSR scenarios.
check_autorp() {
	check_adjacency || return 1

	print "3. FRR's mapping agent resolves the RP pimd announces"
	if wait_for 90 frr_autorp_advertised "$R1_ADDR" "$AUTORP_RANGE"; then
		ok "FRR's agent resolved $R1_ADDR for $AUTORP_RANGE"
	else
		fail "FRR's agent never heard pimd's Announcement for $AUTORP_RANGE"
		dprint "$(frr_show 'show ip pim autorp')"
		return 1
	fi
	# The announcing router hearing its own mapping back is FRR's
	# Discovery parsed by pimd, with the agent's address in it -- which
	# an assertion on the range alone could not tell from pimd's own
	# announcement.
	if wait_for 60 pimd_autorp_agent_is r1 "$AUTORP_RANGE" "$R1_ADDR" "$FRR_ADDR"; then
		ok "R1 holds $AUTORP_RANGE -> $R1_ADDR from agent $FRR_ADDR"
	else
		fail "R1 never learned its own mapping back from FRR's Discovery"
		dprint "$(pimctl r1 show autorp)"
		return 1
	fi
	# ... and acts on it: an Auto-RP mapping that stays in the Auto-RP
	# table and never reaches the RP set is a message parsed and dropped.
	if wait_for 60 pimd_rp_origin_is r1 "$AUTORP_RANGE" "$R1_ADDR" Auto-RP; then
		ok "R1 installed it in the RP set, origin Auto-RP"
	else
		fail "R1 has no Auto-RP entry for $AUTORP_RANGE in its RP set"
		dprint "$(pimctl r1 show rp)"
	fi
	[ "$FAILED" -eq 0 ] || return 1

	print "4. The roles swapped: FRR announces, pimd's agent resolves"
	frr_autorp_swap
	if wait_for 90 pimd_autorp_heard r1 "$FRR_ADDR" "$AUTORP_RANGE_B"; then
		ok "R1's agent heard $FRR_ADDR for $AUTORP_RANGE_B"
	else
		fail "R1's agent never heard FRR's Announcement"
		dprint "$(pimctl r1 show autorp)"
		return 1
	fi
	# ... and FRR reading back the Discovery pimd's agent wrote for it,
	# which is the half of the exchange the line above cannot see.
	if wait_for 90 frr_autorp_discovered "$FRR_ADDR" "$AUTORP_RANGE_B"; then
		ok "FRR learned $AUTORP_RANGE_B -> $FRR_ADDR from pimd's Discovery"
	else
		fail "FRR never parsed a Discovery message from R1's agent"
		dprint "$(frr_show 'show ip pim autorp')"
		return 1
	fi
	if wait_for 60 frr_rp_source_is "$FRR_ADDR" "$AUTORP_RANGE_B" AutoRP; then
		ok "FRR installed it as an RP of Auto-RP origin"
	else
		fail "FRR holds '$(frr_rp_row "$FRR_ADDR" "$AUTORP_RANGE_B")' for $AUTORP_RANGE_B"
		dprint "$(frr_show 'show ip pim rp-info')"
	fi

	return $((FAILED > 0))
}

check() {
	if ! box_exists r1; then
		die "lab is not running in slot $SLOT, run '$0 -s $SLOT start' first"
	fi

	FAILED=0
	XFAILED=0

	case $SCENARIO in
	frr-rp)  check_frr_rp; return $? ;;
	pimd-rp) check_pimd_rp; return $? ;;
	autorp)  check_autorp; return $? ;;
	esac
}

# --- running ------------------------------------------------------------

verdict() {
	known=""
	[ "$XFAILED" -gt 0 ] && known=", $XFAILED known deviation(s)"

	if [ "$FAILED" -eq 0 ]; then
		print "$SCENARIO: all assertions passed$known"
	else
		print "$SCENARIO: $FAILED assertion(s) failed$known"
	fi
}

# What run_one() does when a step gave up rather than failed an assertion.
# die() exits this shell wherever it is called from, so without this the
# stop() below is skipped and the lab of this slot is left running, which
# every later scenario of the slot then dies on before it has started
# anything -- see the same handler in lab.sh, and run 36077110847 of
# CI-FreeBSD, which is what it is named after.  There is more to leave
# behind here than there: frr_start() gives up when zebra or FRR's pimd
# never opens its vty, and those two are what stop() takes down before the
# boxes, along with the pathspace of this slot under /run/frr.
run_one_died() {
	trap - EXIT
	# Not ours to clean up: start() refused because a lab of this slot was
	# already up, and it belongs to whoever left it there.
	[ "${LAB_OURS:-no}" = yes ] || exit 1
	stop || true
	exit 1
}

run_one() {
	set_scenario "$1"
	trap run_one_died EXIT
	start
	# "set -e" is on, and a scenario that fails an assertion is exactly
	# what has to be reported rather than exited on
	rc=0
	check || rc=$?
	verdict
	trap - EXIT
	stop
	return $rc
}

PARALLEL_BUSY=
PARALLEL_PIDS=

parallel_abort() {
	trap - INT TERM

	echo
	print "Interrupted, taking down the labs that were still up ..."
	for pid in $PARALLEL_PIDS; do
		kill "$pid" 2>/dev/null || true
	done
	for entry in $PARALLEL_BUSY; do
		sh "$LAB_SELF" -s "${entry%%:*}" stop >/dev/null 2>&1 || true
	done

	exit 130
}

# Several scenarios at a time, each in a slot of its own.  What makes that
# safe is the slot: every box, link, work directory and FRR pathspace
# carries one, so two scenarios meet only on the host itself.
#
# Each scenario's output is collected and printed whole when it ends.
# Interleaved line by line the assertions of three runs are unreadable, and
# worse, unattributable: each one prints "3." and means a different thing.
run_parallel() {
	jobs=$JOBS
	pending=$1

	[ -z "$WORKDIR_PINNED" ] || \
		die "WORKDIR is set in the environment, so every slot would" \
		    "share one work directory; unset it to run in parallel"

	last=$((SLOT + jobs - 1))
	[ "$last" -le 31 ] || \
		die "-j $jobs from slot $SLOT wants slots up to $last, and 31 is the last one"

	out=$(mktemp -d "${TMPDIR:-/tmp}/pimd-frr-parallel.XXXXXX")
	free=
	n=$SLOT
	while [ "$n" -le "$last" ]; do
		free="$free $n"
		n=$((n + 1))
	done

	results=
	rc=0

	trap parallel_abort INT TERM

	while [ -n "$pending" ] || [ -n "$PARALLEL_BUSY" ]; do
		while [ -n "$pending" ] && [ -n "$free" ]; do
			# shellcheck disable=SC2086
			set -- $pending; scenario=$1; shift; pending=$*
			# shellcheck disable=SC2086
			set -- $free; slot=$1; shift; free=$*

			print "===== scenario: $scenario, slot $slot, started ====="
			(
				set +e
				sh "$LAB_SELF" -s "$slot" run "$scenario" \
					> "$out/$slot.log" 2>&1
				echo $? > "$out/$slot.rc.part"
				mv "$out/$slot.rc.part" "$out/$slot.rc"
			) &
			PARALLEL_PIDS="$PARALLEL_PIDS $!"
			PARALLEL_BUSY="$PARALLEL_BUSY $slot:$scenario"
		done

		sleep 2

		# A child cannot be waited for one at a time in POSIX sh, so
		# it says it is done by writing its exit status out.
		running=
		for entry in $PARALLEL_BUSY; do
			slot=${entry%%:*}
			scenario=${entry#*:}
			if [ ! -f "$out/$slot.rc" ]; then
				running="$running $entry"
				continue
			fi

			status=$(cat "$out/$slot.rc")
			print "===== scenario: $scenario, slot $slot, done ====="
			cat "$out/$slot.log"
			[ "$status" -eq 0 ] || rc=1
			results="$results $scenario:$status"
			mv "$out/$slot.log" "$out/$scenario.log"
			rm -f "$out/$slot.rc"
			free="$free $slot"
		done
		PARALLEL_BUSY=$running
	done

	trap - INT TERM
	wait

	echo
	print "===== $(echo $results | wc -w | tr -d " ") scenarios, $jobs at a time ====="
	for entry in $results; do
		if [ "${entry#*:}" -eq 0 ]; then
			printf "  \033[32mpass\033[0m  %s\n" "${entry%:*}"
		else
			printf "  \033[31mFAIL\033[0m  %s (exit %s)\n" \
			    "${entry%:*}" "${entry#*:}"
		fi
	done

	if [ "$rc" -eq 0 ]; then
		rm -rf "$out"
	else
		echo
		echo "per-scenario logs kept in $out"
	fi

	return $rc
}

run() {
	if [ "${1:-}" = all ]; then
		list=$SCENARIOS
	elif [ $# -gt 1 ]; then
		list=$*
	else
		# One scenario, the common case: run it in this shell, so
		# its assertions reach the terminal as they are made.
		[ "$JOBS" -eq 1 ] || \
			die "-j needs more than one scenario to run in parallel"
		run_one "${1:-}"
		exit $?
	fi

	# Every name, before anything is built: a typo in the last of them
	# is worth hearing about now and not in ten minutes.
	for s in $list; do
		set_scenario "$s"
	done

	if [ "$JOBS" -gt 1 ]; then
		run_parallel "$list"
		exit $?
	fi

	# Every scenario runs even when an earlier one failed: the point of
	# a second implementation is the whole matrix, and a red first
	# scenario says nothing about the second.
	total=0
	for s in $list; do
		run_one "$s" || total=$((total + 1))
	done
	[ "$total" -eq 0 ] || die "$total scenario(s) failed"
	exit 0
}

[ -z "$HELP" ] || { usage; exit 0; }

cmd=${1:-}
[ $# -eq 0 ] || shift
case $cmd in
start) set_scenario "${1:-}"; start ;;
check)
	set_scenario "${1:-}"
	rc=0
	check || rc=$?
	verdict
	exit $rc
	;;
run)   run "$@" ;;
stop)  set_scenario "${1:-}"; stop ;;
*)     usage; exit 2 ;;
esac

# Local Variables:
#  indent-tabs-mode: t
#  c-file-style: "linux"
# End:
