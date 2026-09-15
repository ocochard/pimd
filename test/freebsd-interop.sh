#!/bin/sh
# PIM-SM interoperability lab: pimd against an Arista vEOS, on FreeBSD
#
# Everything else in this directory tests pimd against pimd.  That answers
# "does pimd still do what it did yesterday", never "does pimd do what the
# RFC says", because both ends of every exchange share the same reading of
# it: a message pimd encodes wrongly is a message pimd decodes wrongly in
# the same way, and the lab stays green.  This one puts a second, unrelated
# implementation on the wire - EOS, which is not derived from the same code
# and was not written from the same reading - so an assertion that passes
# here says the bytes on the wire were right, not merely self-consistent.
#
# Topology, one vnet jail per pimd box, the Arista in bhyve, all links /24:
#
#    ED1            R1            vEOS             R3            ED2
#     |              |              |              |              |
#     +--10.0.1.0/24-+-10.0.12.0/24-+-10.0.23.0/24-+--10.0.3.0/24-+
#      .10        .1   .1        .2   .2        .3   .1        .10
#     epair801a/b    bridge812      bridge823     epair803a/b
#                    epair812b       epair823b
#                     + tap812        + tap823
#                        Et1             Et2
#
#                              Ma1
#                               |
#                          bridge800, 172.20.0.0/24
#                               |
#                        host 172.20.0.1, eAPI to 172.20.0.2
#
# The two middle links are host bridges rather than epairs, because one end
# of each is a bhyve tap and the other is a jail: a bridge is the only thing
# that joins the two.  They carry no host address, the host is a wire here.
#
# Those names, and the management subnet with them, are the ones slot 0
# uses; -s N puts N in front of every epair, bridge and tap unit number,
# names the VM veosN and moves the management segment to 172.20.N.0/24,
# see SLOT below.
#
# Two scenarios run on that topology, and they are each other's mirror.  Who
# holds which role is the whole difference: every message below is a message
# one implementation builds and the other has to believe, and swapping the
# roles swaps which side is the writer and which is the reader.  A parser
# that is wrong in the same way as its encoder passes the first scenario and
# fails the second.
#
#   arista-rp   The Arista is the router in the middle, the BSR and the RP,
#               R1 is the first hop router and R3 the last hop one.
#
#                 - Hello and DR election, on two links at once.  R1 loses
#                   the election on 10.0.12.0/24 (EOS has the higher
#                   address) and R3 wins it on 10.0.23.0/24, so both
#                   outcomes are asserted, each from both sides rather than
#                   from pimd's own opinion of it.
#                 - Bootstrap and Candidate-RP-Advertisement written by EOS,
#                   parsed by pimd.
#                 - Register written by pimd, decapsulated by EOS.
#                 - (*,G) Join written by pimd, believed by EOS.
#               Takes about 3 minutes, most of it booting the VM.
#
#   pimd-rp     The roles reversed: R1 is the BSR and the RP, and the Arista
#               is the first hop router and the last hop one.  That needs a
#               LAN of its own hanging off the Arista, so this scenario adds
#               a third data interface and a fifth box:
#
#                 ED1 --- R1 --- vEOS --- R3 --- ED2
#                 .10   (BSR+RP)   |
#                                  | Et3, 10.0.4.0/24, bridge804 + tap804
#                                  |
#                                 ED4 .10
#
#               The stream runs between ED1 and ED4, and mping's receiver
#               answers by sending to the same group, so one run builds a
#               tree in each direction: (ED1,G) with pimd as the first hop
#               router and EOS as the last hop one, and (ED4,G) the other
#               way around.  What that reverses:
#
#                 - Bootstrap and Candidate-RP-Advertisement written by
#                   pimd, parsed by EOS.  R3 has to learn the same RP set
#                   through the Arista, which only works if EOS forwards a
#                   Bootstrap pimd originated.
#                 - Register written by EOS, decapsulated by pimd, and
#                   Register-Stop written by pimd, obeyed by EOS - asserted
#                   by counting how many registers the RP decapsulates over
#                   a stream, since a Register-Stop that EOS ignores shows
#                   up as one register per data packet.
#                 - (*,G) Join written by EOS, believed by pimd.
#               Takes about 4 minutes.
#
# The RP sits on R1 rather than R3 in pimd-rp on purpose: R1 is then the RP
# for a source it is directly attached to, so the (ED4,G) traffic goes
# EOS -> R1 -> ED1 and the (ED1,G) traffic R1 -> EOS -> ED4, neither of them
# doubling back over a link they arrived on.  With the RP on R3 the (ED4,G)
# tree would climb to R3 and come straight back out the same interface, and
# the asserts and SPT switches that follow would be the thing under test
# instead of the exchange that is.
#
#   assert-lan  The assert election, which needs a topology of its own: two
#               routers with a reason to forward the same (S,G) onto one
#               segment.  Three PIM routers share the LAN, and the two
#               contenders get their reason by different routes -- R5's
#               Join gives R3 an oif there, ED3's IGMP report gives the
#               Arista one as DR:
#
#                                        10.0.3.0/24, bridge803
#                                             |
#                 ED1 --- R1 --- bridge812 -- + -- R5 --- ED2
#                 .10  (BSR+RP)    |          |   .1      .10
#                                 vEOS -------+
#                                  Et1      Et2 .3
#                                             |
#                                    R3 .2 ---+--- ED3 .10
#                                     |
#                                    ED6 .10, 10.0.6.0/24
#
#               What it was written for, and what it actually found, are
#               not the same thing, so both are here.
#
#               It was written for the assert metric.  pimd's metric
#               preference is a configured constant rather than the
#               distance of the protocol the route came from (deviation M4
#               in doc/rfc7761-compliance.md), so between two pimds every
#               router on a LAN advertises the same one; the metric beside
#               it is the routing table's, and shared-lan in
#               freebsd-lab.sh moves it with route(8), but that is the
#               second field compared and only after this scenario had
#               been written.  EOS fills both from its own RIB, so this is
#               the LAN where the preference comparison sec. 4.6.1 runs
#               before the metric one is anything but dead code.
#
#               They did not at first, and that was the finding.  pimd
#               evaluated SPTbit only when an upcall reached
#               update_sptbit(), never per packet as sec. 4.2 asks, so R3
#               never got onto the shortest path tree here and kept
#               asserting from (*,G) state with the RPT bit set -- which
#               sec. 4.6.1 compares first, so its metric was never reached.
#               That was deviation M10, this scenario is what turned it up,
#               and it is fixed: age_routes() re-runs the check for as long
#               as data is arriving.  The assertion that reported it stays
#               as a tripwire and goes back to KNOWN if R3 stops reaching
#               the tree.
#
#               So what it asserts: DR and IGMP querier election on a
#               segment shared with a foreign implementation, decided by
#               different routers and agreed by both ends; the RP set
#               learned through it; all four sub-cases of the election,
#               including rpt-bit, the one that wants pimd held off the
#               SPT, where the Arista must win on the RPT bit despite pimd
#               holding the better preference; and the two halves of the
#               assert state machine no pimd-only lab can reach, a received
#               AssertCancel and the winner's resend at Assert_Time -
#               Assert_Override_Interval.  Those two were deviation M3 and
#               are fixed; their reports stay as tripwires.
#
#               Takes about 12 minutes, most of it the last sub-case,
#               which has to outlive Assert_Time (180s).
#
# Which is also why this is not another scenario in freebsd-lab.sh: that
# script needs nothing but jails, and this one needs a 4G VM image, bhyve
# and a vendor OS.
#
# Scenarios run in parallel, as they do there and for the same reason: -s
# picks a slot, 0 to 31, and every name this lab puts on the host carries
# it -- jails, epairs, bridges, taps, the bhyve VM, the management subnet
# and the work directory -- so two of them never meet.  "run all -j N", or
# a list of scenarios and -j, does the bookkeeping.  Unlike the jail-only
# lab it is not cores that bound N: every scenario boots a vEOS of its
# own, 4G of memory and a converted 4G disk apiece.
#
# The same slot of freebsd-lab.sh must not be up at the same time -- the
# two labs use the same 10.0.0.0/8 addresses and check_req() says so --
# but another slot of it may be, and the one piece of host state they both
# want, net.inet.ip.mcast.loop, they now hold between them; see
# disable_mcast_loop().
#
# The VM is driven by veos-bhyve.sh (see $VEOS_SH), which boots the vEOS
# image under bhyve, writes the startup-config this script generates onto
# the guest flash before boot, and exposes eAPI.  Assertions about what the
# Arista believes are read over eAPI, so they are the switch's own view of
# the exchange, not an inference from pimd's logs.
#
# Requirements: root, VIMAGE, ip_mroute.ko, if_bridge.ko, bhyve, python3
# (eAPI is JSON), a built pimd, and a vEOS-lab image named with -i.
#
# That image is vEOS64-lab-<version>.qcow2, from the Software Download area
# of arista.com under vEOS-lab, with a free account; 4.36.1F is what this
# was written against.  The Aboot-veos-serial ISO offered beside it is not
# needed, see the header of veos-bhyve.sh.  Neither can ship here, which is
# why there is no default path and why this lab is not in TESTS.
#
# Usage: freebsd-interop.sh [-i image] [-s SLOT] [-j JOBS] start|check|run
#        [scenario...] | run all | stop

# The options come before the command, "$0 -i image.qcow2 -s 1 run
# pimd-rp", and are read here rather than beside the dispatch at the foot
# of the file: -s picks the slot, and the slot is what the names in the
# next hundred lines are derived from.  usage() cannot be called yet for
# the same reason, so a bad option says where to find it instead.
SLOT=${SLOT:-0}
JOBS=${JOBS:-1}
HELP=
# The vEOS-lab image.  No default: it is a licensed Arista download that
# cannot live in this tree, and where a given machine keeps it is nothing
# this script can guess -- so it is named with -i, or in $VEOS_QCOW, and
# the run stops with a usage message if neither says where it is.
VEOS_QCOW=${VEOS_QCOW:-}
while getopts "i:s:j:h" opt; do
	case "$opt" in
	i) VEOS_QCOW=$OPTARG ;;
	s) SLOT=$OPTARG ;;
	j) JOBS=$OPTARG ;;
	h) HELP=yes ;;
	*) echo "EXIT: run \"$0 -h\" for usage" >&2; exit 2 ;;
	esac
done
shift $((OPTIND - 1))

case $JOBS in
""|*[!0-9]*|0) echo "EXIT: -j wants a job count of 1 or more, not \"$JOBS\"" >&2; exit 1 ;;
esac

# Root needs no sudo, and the places this runs unattended -- CI in a VM,
# a jail host -- often do not have it installed at all.  An explicitly
# empty SUDO= is honoured either way; ${SUDO:-sudo} would have quietly
# put sudo back.
if [ "$(id -u)" -eq 0 ]; then
	SUDO=${SUDO-}
else
	SUDO=${SUDO-sudo}
fi

PIMD_SRC=${PIMD_SRC:-$(cd "$(dirname "$0")/.." && pwd)}

# Which of the interoperability labs this invocation is, 0 to 31, from -s.
# Everything this lab puts on the host carries it -- the jails, the
# epairs, the bridges, the taps, the bhyve VM, the management subnet eAPI
# is reached over and the work directory -- so scenarios can be run
# several at a time.  Slot 0 is spelled the way this lab always was, so a
# single run reads as it used to.
#
# The addresses inside the jails are not per slot and do not need to be: a
# vnet jail has an interface namespace and a forwarding cache of its own.
# The management segment is the exception, because the host itself holds
# an address on it and talks eAPI over it, so that one is
# 172.20.<slot>.0/24.
#
# A vEOS is 4G of RAM and a converted 4G disk image apiece, which is the
# real limit on how many of these run at once; see run_parallel().
# 31 is where the kernel stops, not where the lab does: an epair unit is
# the slot followed by this lab's own three digits, and if_clone refuses a
# unit above 32767 -- slot 32 would ask for epair32863.
case $SLOT in
[0-9]|[12][0-9]|3[01]) ;;
*) echo "EXIT: slot must be 0 to 31, not \"$SLOT\"" >&2; exit 1 ;;
esac
if [ "$SLOT" -eq 0 ]; then
	TAG=
else
	TAG=$SLOT
fi

EP=epair$TAG
JAIL_PREFIX=pimx${TAG}_

# The ifconfig(8) group everything this lab creates is put in, and which
# stop() sweeps.  The slot is spelled in letters, digit by digit -- slot 0
# is "pimxa" and slot 31 "pimxdb" -- because a group name may not end in a
# digit: it would be ambiguous with an interface name and setifgroup
# refuses it.
IFGROUP=pimx$(echo "$SLOT" | tr 0-9 a-j)

# Set in the environment it is one directory for every slot, which cannot
# work once more than one of them runs; run_parallel() refuses it.
WORKDIR_PINNED=${WORKDIR:+yes}
WORKDIR=${WORKDIR:-/tmp/pimd-interop$TAG}

PIMD="$PIMD_SRC/src/pimd"
PIMCTL="$PIMD_SRC/src/pimctl"
MPING="$WORKDIR/mping"
EAPI="$WORKDIR/eapi.py"

DEBUG=${DEBUG:-"-l debug -d mrt,rpf,pim_register,pim_bootstrap,pim_jp"}

# The VM runner: a bhyve script that knows how to boot a vEOS image and
# nothing about PIM.  It lives next to this one because this lab cannot run
# without it, and most of what it knows - the ZTP gate, writing the
# startup-config onto the guest flash, restarting bhyve when the guest
# reboots - was learned for this lab.  The image itself is not in the tree
# and cannot be: it is a licensed Arista download.
VEOS_SH=${VEOS_SH:-$(cd "$(dirname "$0")" && pwd)/veos-bhyve.sh}
VEOS_VM=${VEOS_VM:-veos$TAG}

SCENARIO=${SCENARIO:-arista-rp}
SCENARIOS="arista-rp pimd-rp assert-lan"

# Jails.  A prefix of their own so this lab and freebsd-lab.sh can be built
# in the same tree without either one destroying the other's boxes.  ED4
# only exists in pimd-rp, where the Arista needs a LAN of its own to be the
# first and last hop router for.
DEFAULT_BOXES="ed1 r1 r3 ed2"
REVERSED_BOXES="ed1 r1 r3 ed2 ed4"
ASSERT_BOXES="ed1 r1 r3 r5 ed2 ed3 ed6"
BOXES=$DEFAULT_BOXES

DEFAULT_ROUTERS="r1 r3"
ASSERT_ROUTERS="r1 r3 r5"
ROUTERS=$DEFAULT_ROUTERS

# Host bridges: the PIM links the Arista sits on, plus the management
# segment eAPI is reached over.
BR12=bridge${TAG}812
BR23=bridge${TAG}823
BR4=bridge${TAG}804
BR3=bridge${TAG}803
BR_MGMT=bridge${TAG}800

# bhyve taps, in PCI order.  The first NIC a vEOS sees is Management1, the
# ones after it are Ethernet1, Ethernet2, ...  All four are always plugged
# in, because the guest numbers its interfaces by PCI slot and Ethernet3
# would move if the list changed between scenarios; only pimd-rp bridges
# the last one to anything.
TAP_MGMT=tap${TAG}800
TAP_ET1=tap${TAG}812
TAP_ET2=tap${TAG}823
TAP_ET3=tap${TAG}804

# epairs.  The "b" end goes into a jail; for the bridged links the "a" end
# stays on the host and joins the bridge.
DEFAULT_EPAIRS="${EP}801 ${EP}812 ${EP}823 ${EP}803"
REVERSED_EPAIRS="$DEFAULT_EPAIRS ${EP}804"
ASSERT_EPAIRS="${EP}801 ${EP}812 ${EP}832 ${EP}833 ${EP}853 ${EP}863 ${EP}805 ${EP}836"
EPAIRS=$DEFAULT_EPAIRS

# Every epair either scenario can create, for a teardown that does not
# depend on which one built the lab
ALL_EPAIRS="$DEFAULT_EPAIRS ${EP}804 ${EP}832 ${EP}833 ${EP}853 ${EP}863 ${EP}805 ${EP}836"
ALL_BOXES="ed1 r1 r3 r5 ed2 ed3 ed4 ed6"

ED1_IF=${EP}801a
ED2_IF=${EP}803b
ED4_IF=${EP}804b

# assert-lan renames things: ED2 moves behind R5, and ED3 sits on the
# contested LAN itself
AL_ED2_IF=${EP}805b
AL_ED3_IF=${EP}863b
AL_ED6_IF=${EP}836b
AL_R3_LAN_IF=${EP}833b
AL_R3_UP_IF=${EP}832b

SRC_ADDR=${SRC_ADDR:-10.0.1.10}
RCV_ADDR=${RCV_ADDR:-10.0.3.10}
ED4_ADDR=${ED4_ADDR:-10.0.4.10}
GROUP=${GROUP:-225.1.2.3}

# The RP address of whichever router holds the role, and every "did the
# other end learn the RP" assertion demands exactly this rather than "some
# RP": an address misparsed out of the Bootstrap would otherwise still look
# like success.  arista-rp puts the C-RP on the Arista's Ethernet1, pimd-rp
# on R1's interface towards it.
ARISTA_RP_ADDR=10.0.12.2
PIMD_RP_ADDR=10.0.12.1
RP_ADDR=$ARISTA_RP_ADDR

# pimd-rp: what R1 puts in the Bootstrap header, and what EOS therefore has
# to read back out of it.  The priority is configured in r1.conf below and
# asserted from the same variable so the two cannot drift; the hash mask
# length is not configurable in pimd, RP_DEFAULT_IPV4_HASHMASKLEN in
# src/pimd.h fixes it at 30.
PIMD_BSR_PRIORITY=5
PIMD_BSR_HASHLEN=30

# assert-lan ------------------------------------------------------------
#
# The contested LAN.  R3 and the Arista are the two contenders, R5 is the
# downstream router whose Join gives R3 its reason to forward, and ED3 is
# the local member that gives the Arista its own.  The addresses put the
# two elections on different routers on purpose: PIM takes the highest
# address, so the Arista is the DR, IGMP takes the lowest, so R5 is the
# querier, and neither election is the one under test.
#
# The Arista also has to win the assert tiebreak, which is the same
# highest-address rule, so the tiebreak sub-case has a predictable answer.
AL_R3_ADDR=10.0.3.2
AL_EOS_ADDR=10.0.3.3
AL_R5_ADDR=10.0.3.1
AL_ED3_ADDR=10.0.3.10
AL_ED6_ADDR=10.0.6.10
AL_ED2_ADDR=10.0.5.10

# What the Arista advertises in its Asserts: sec. 4.6.3 says the metric
# preference and metric are the unicast routing protocol's, and EOS obeys
# that, so these are the distance and metric of its static route to the
# source.  Both are set explicitly rather than left at the static-route
# defaults, because pimd's side of the comparison has to be able to match
# them: the preference through default-route-distance, documented as
# 1-255, and the metric through the metric of R3's own route to the
# source, which is where pimd reads it from.
AL_EOS_PREF=${AL_EOS_PREF:-100}
AL_EOS_METRIC=${AL_EOS_METRIC:-500}

# ED3 joins on a port of its own.  IGMP membership is per group, not per
# port, so the Arista sees a report and takes the leaf while the stream
# never reaches ED3's socket and it answers none of it - every reply the
# sender counts then comes from ED2, at the far end of the tree.
AL_JOIN_PORT=${AL_JOIN_PORT:-4322}
AL_JOIN_PORT6=${AL_JOIN_PORT6:-4323}

# The sub-cases.  RFC 7761 sec. 4.6.3 (doc/rfc7761.txt:5174) defines the
# assert metric as
#
#     struct assert_metric { rpt_bit_flag; metric_preference;
#                            route_metric; ip_address; };
#
# and says the first three "are compared in order, where the first lower
# value wins.  If all fields are equal, the primary IP address of the
# router that sourced the Assert message is used as a tie-breaker, with
# the highest IP address winning."  One sub-case per field, so each is
# decided by exactly one comparison and the ones before it are equal:
#
#   pimd-wins    equal rpt_bit, pimd's metric_preference lower.  pimd
#                must keep the LAN and the Arista must give it up.
#   arista-wins  the same field, the other way round.
#   tiebreak     rpt_bit, preference and metric all equal, so the address
#                decides and the highest wins - the Arista, deliberately
#                given the higher address on this LAN.
#   rpt-bit      pimd is held on the shared tree while the Arista is on
#                the shortest path tree, and pimd is given the *better*
#                preference.  rpt_bit is compared first, so the Arista has
#                to win regardless; a router that got the bit wrong would
#                win on a metric it should never have been asked about.
#                This is the mixed-vendor counterpart of shared-lan-spt in
#                freebsd-lab.sh, whose xfail() the fix in 4cb79f1 cleared
#                against pimd's own encoder.
#
#                What holds pimd on the shared tree is spt-threshold
#                infinity, and this sub-case used to be order dependent
#                because of it: the setting is a policy about sending
#                Join(S,G), and pimd read the SPTbit off the outgoing
#                interfaces alone, three of whose conditions R3 meets here
#                -- data from S on RPF_interface(S), an olist from ED6, and
#                RPF'(S,G) == RPF'(*,G), R1 being the upstream for the
#                source and for the RP both.  Whether it had an (S,G) entry
#                to set the bit on then depended on what the Arista had
#                asserted with earlier in the run.  That was deviation M13:
#                the fourth condition is JoinDesired(S,G) (sec. 4.5.5,
#                doc/rfc7761.txt:3738), which is source specific state --
#                joins(S,G), an IGMPv3 source-specific membership, or a
#                Keepalive Timer -- and R3 has none of it, spt-threshold
#                infinity being exactly what stops sec. 4.2.1 from starting
#                the timer.  join_desired() (src/route.c) answers it now,
#                so the sub-case stands on its own in either order and a
#                failure here means pimd is back to claiming a tree it is
#                not on.
#
# route_metric is held equal throughout and only metric_preference is
# moved, so no sub-case can be decided by a field it is not about.
#
# Getting this wrong the first time is worth recording, because the lab
# looked broken while both implementations were right.  With the RP on R1,
# one hop upstream of both contenders, R3 reached the source and the RP
# through the same interface and never held (S,G) state, so
# my_assert_metric() (doc/rfc7761.txt:5194) fell to rpt_assert_metric(G,I)
# = {1, MRIB.pref(RP), MRIB.metric(RP), ...} and R3 asserted {1,0,0} - the
# RP was directly connected, hence the zeroes.  Against the Arista's
# {0,100,500} that loses on rpt_bit before any metric is read, in every
# sub-case, which is correct behaviour by both ends and no test at all.
# What fixes it is not a knob on R3: see write_case_confs().
AL_CASES=${AL_CASES:-"pimd-wins arista-wins tiebreak rpt-bit"}
# Carried twice: onto R3's route to the source by route_metrics(), which is
# where pimd reads the metric it asserts with, and into default-route-metric
# for a kernel that reports none
AL_PIMD_METRIC=$AL_EOS_METRIC
AL_PREF_BETTER=$((AL_EOS_PREF - 50))
AL_PREF_WORSE=$((AL_EOS_PREF + 50))

# The short stream run after the election has settled, to show the LAN is
# still carrying traffic, and how much of it has to come back
AL_CONFIRM_PKTS=${AL_CONFIRM_PKTS:-20}
AL_MIN_CONFIRM=${AL_MIN_CONFIRM:-12}

# RFC 7761 Assert_Time, and what the "winner never resends" sub-case has
# to outlive.  PIM_ASSERT_TIMEOUT in src/pimd.h is the same 180.
AL_ASSERT_TIME=${AL_ASSERT_TIME:-180}

# How long to wait for someone to start forwarding onto the contested LAN,
# and how long to let the election settle once someone has.  Polled rather
# than slept through: the chain that has to complete first is long - the
# RP has to see the Register, the shared tree has to reach R5, R5's
# spt-threshold timer has to fire, its (S,G) Join has to reach R3 and R3
# has to build forwarding state - and a fixed sleep either samples a race
# or pads every sub-case by the worst case.
AL_FWD_WAIT=${AL_FWD_WAIT:-150}

# How long to give the AssertCancel case: the Arista's membership for ED3
# has to expire before it can cancel, which is an IGMP timeout, not a PIM
# one.  Still far short of the Assert_Time a loser waits out otherwise,
# which is the whole point of the message.
AL_CANCEL_WAIT=${AL_CANCEL_WAIT:-75}

# What R5 queries with on the contested LAN, and the reason the
# AssertCancel case can run at all.  The Arista's reason to forward there
# is ED3's membership, and a non-querier derives its group membership
# interval from the Querier's Query Interval the queries carry -- QQIC,
# RFC 3376 sec. 4.1.7 -- so the querier sets how long that leaf outlives
# the last report.  R5 is the querier here, and on the RFC default of 125s
# the Arista holds the group for 2 x 125 + 10 = 260s, three times the wait
# below: measured on the lab, "show ip igmp groups" reporting Expires
# 0:04:20 with the default and 0:00:17 with this.  The winner then never
# deletes the state sec. 4.6.4 has it send the cancel for, and the case
# reported pimd ignoring a message the Arista had never sent.
AL_QUERY_INTERVAL=${AL_QUERY_INTERVAL:-5}
AL_ELECTION_WAIT=${AL_ELECTION_WAIT:-30}

# How long every stream in this scenario has to stay up for, worked out
# from the waits above rather than guessed, because guessing it wrong is
# invisible: the sender, the receiver behind R5 and ED3's joiner are all
# started before the election is established, and if any of them expires
# during the measurement the reading is of a lab that has quietly gone
# away.  ED3's is the dangerous one -- its membership is the Arista's only
# reason to forward, so a joiner that has exited makes the Arista look
# like a router that is honouring an assert.
#
# The longest path through a case is establish_election() waiting out
# AL_FWD_WAIT and AL_ELECTION_WAIT, then the resend case polling across
# Assert_Time and AL_ELECTION_WAIT again.  Plus a wide margin: nothing is
# gained by cutting it fine, since every stream is killed as soon as its
# case has an answer.
AL_STREAM_LIFE=$((AL_FWD_WAIT + AL_ASSERT_TIME + 2 * AL_ELECTION_WAIT + 150))

# The stream the election is held over, one packet a second, so the count
# is also its duration in seconds.
AL_STREAM_PKTS=${AL_STREAM_PKTS:-$AL_STREAM_LIFE}

# One /24 per slot: the host has an address on this segment, unlike every
# other one in this lab, so two slots cannot share it.
MGMT_HOST=172.20.$SLOT.1
MGMT_VEOS=172.20.$SLOT.2

EAPI_USER=${EAPI_USER:-admin}
EAPI_PASS=${EAPI_PASS:-admin}

# Packets the sender sends, one every second, and how many replies have to
# come back before the stream counts as forwarded.  The first seconds are
# always lost: they are what builds the tree.
STREAM_PKTS=${STREAM_PKTS:-40}
MIN_REPLIES=${MIN_REPLIES:-20}

# pimd-rp: a second, short stream run once the tree has settled, and how
# many PIM Registers the RP may decapsulate while it is in flight.
#
# Counting registers over the first stream would measure the wrong thing.
# The RP cannot Register-Stop anything until it has built the (S,G) and
# joined the shortest path tree towards it, so a cold lab spends the first
# seconds legitimately registering every packet, and how many that is
# depends on how fast the domain converged rather than on whether anyone
# honoured anything.  Measured after the tree is up, the question is the one
# worth asking: is the Arista still encapsulating a source it has been told
# to stop encapsulating?  The bound is not zero because RFC 7761 4.4.1 has
# the first hop router probe with a Null-Register once per
# Register-Suppression-Timer.
SETTLED_PKTS=${SETTLED_PKTS:-10}
MAX_REGISTERS=${MAX_REGISTERS:-3}

# How long to wait for the VM.  A vEOS reaches eAPI in well under a minute
# on this hardware, but it converts a 4G image on the first run.
VEOS_BOOT_WAIT=${VEOS_BOOT_WAIT:-300}

die() { echo -n "EXIT: " >&2; echo "$@" >&2; exit 1; }
print() { printf "\033[7m>> %-76s\033[0m\n" "$1"; }
dprint() { printf "\033[2m%-76s\033[0m\n" "$1"; }

FAILED=0
XFAILED=0
ok()   { printf "  \033[32mok\033[0m    %s\n" "$1"; }
fail() { printf "  \033[31mFAIL\033[0m  %s\n" "$1"; FAILED=$((FAILED + 1)); }

# A behaviour that is wrong but known to be wrong: pimd deviates from the
# spec here, the assertion reproduces it on purpose, and the run is not
# red because of it.  Same convention as freebsd-lab.sh -- it is still
# printed on every run, and the moment pimd starts doing the right thing
# the assertion turns into an ok and says so.
xfail() { printf "  \033[33mKNOWN\033[0m %s\n" "$1"; XFAILED=$((XFAILED + 1)); }

usage() {
	cat <<-EOF
	usage: $0 [-i image.qcow2] [-s SLOT] [-j JOBS] start|check|run
	          [scenario...] | run all | stop

	  -i FILE   the vEOS-lab qcow2 image to boot.  Required for start and
	            run, and \$VEOS_QCOW is read when -i is not given.  There is
	            no default: the image is a licensed Arista download that
	            cannot ship with this tree.
	  -s SLOT   which lab this is, 0 to 31, default 0.  A slot names its
	            jails, links, taps, bhyve VM and work directory apart from
	            every other, so one machine can hold several at once.
	  -j JOBS   how many scenarios to run at the same time, in slots \$SLOT
	            upwards, one slot each.  Default 1, one after another.
	            Each one boots a vEOS of its own, so this is bounded by
	            memory and disk before it is bounded by cores.

	Scenarios: $SCENARIOS.  "run all" walks them in that order.
	EOF
}

set_scenario() {
	case ${1:-$SCENARIO} in
	arista-rp|pimd-rp|assert-lan) SCENARIO=${1:-$SCENARIO} ;;
	*) usage; exit 2 ;;
	esac

	# Read by everything that walks the topology, so a scenario left
	# behind by a previous "run all" cannot leak into the next one.
	case $SCENARIO in
	pimd-rp)
		BOXES=$REVERSED_BOXES
		ROUTERS=$DEFAULT_ROUTERS
		EPAIRS=$REVERSED_EPAIRS
		RP_ADDR=$PIMD_RP_ADDR ;;
	assert-lan)
		BOXES=$ASSERT_BOXES
		ROUTERS=$ASSERT_ROUTERS
		EPAIRS=$ASSERT_EPAIRS
		# R1 is the RP here too, on the same interface as in
		# pimd-rp, so the two share the address
		RP_ADDR=$PIMD_RP_ADDR ;;
	*)
		BOXES=$DEFAULT_BOXES
		ROUTERS=$DEFAULT_ROUTERS
		EPAIRS=$DEFAULT_EPAIRS
		RP_ADDR=$ARISTA_RP_ADDR ;;
	esac
}

# --- boxes ------------------------------------------------------------

jname() { echo "$JAIL_PREFIX$1"; }
jrun() { j=$1; shift; ${SUDO} jexec "$(jname "$j")" "$@"; }
pimctl() { j=$1; shift; jrun "$j" "$PIMCTL" -u "$WORKDIR/$j.sock" "$@"; }

ifaces() {
	if [ "$SCENARIO" = assert-lan ]; then
		case $1 in
		ed1) echo "${EP}801a" ;;
		r1)  echo "${EP}801b ${EP}812b" ;;
		r3)  echo "${EP}832b ${EP}833b ${EP}836a" ;;
		r5)  echo "${EP}853b ${EP}805a" ;;
		ed2) echo "${EP}805b" ;;
		ed3) echo "${EP}863b" ;;
		ed6) echo "${EP}836b" ;;
		esac
		return
	fi

	case $1 in
	ed1) echo "${EP}801a" ;;
	r1)  echo "${EP}801b ${EP}812b" ;;
	r3)  echo "${EP}823b ${EP}803a" ;;
	ed2) echo "${EP}803b" ;;
	ed4) echo "${EP}804b" ;;
	esac
}

addrs() {
	if [ "$SCENARIO" = assert-lan ]; then
		case $1 in
		ed1) echo "${EP}801a 10.0.1.10/24" ;;
		r1)  echo "${EP}801b 10.0.1.1/24 ${EP}812b 10.0.12.1/24" ;;
		r3)  echo "${EP}832b 10.0.12.3/24 ${EP}833b $AL_R3_ADDR/24 ${EP}836a 10.0.6.1/24" ;;
		r5)  echo "${EP}853b $AL_R5_ADDR/24 ${EP}805a 10.0.5.1/24" ;;
		ed2) echo "${EP}805b $AL_ED2_ADDR/24" ;;
		ed3) echo "${EP}863b $AL_ED3_ADDR/24" ;;
		ed6) echo "${EP}836b $AL_ED6_ADDR/24" ;;
		esac
		return
	fi

	case $1 in
	ed1) echo "${EP}801a 10.0.1.10/24" ;;
	r1)  echo "${EP}801b 10.0.1.1/24 ${EP}812b 10.0.12.1/24" ;;
	r3)  echo "${EP}823b 10.0.23.3/24 ${EP}803a 10.0.3.1/24" ;;
	ed2) echo "${EP}803b 10.0.3.10/24" ;;
	ed4) echo "${EP}804b $ED4_ADDR/24" ;;
	esac
}

# Static unicast routes, "<destination> <gateway>" pairs.  pimd needs a
# unicast RPF answer for the source and for the RP, and the Arista needs one
# for both edge LANs; its own are in its startup-config.
routes() {
	if [ "$SCENARIO" = assert-lan ]; then
		# R5's route to the source is the whole reason R3 gets an oif
		# on the contested LAN: it makes R3 R5's RPF neighbour, so
		# R5's Join names R3, and receive_pim_join_prune() lets only
		# the router named in a Join add the oif.  Pointed at the
		# Arista instead there would be one forwarder on the LAN and
		# no assert to elect.
		case $1 in
		ed1) echo "default 10.0.1.1" ;;
		r1)  echo "10.0.3.0/24 10.0.12.3 10.0.5.0/24 10.0.12.3 10.0.6.0/24 10.0.12.3" ;;
		r3)  echo "10.0.1.0/24 10.0.12.1 10.0.5.0/24 $AL_R5_ADDR" ;;
		r5)  echo "10.0.1.0/24 $AL_R3_ADDR 10.0.12.0/24 $AL_R3_ADDR 10.0.6.0/24 $AL_R3_ADDR" ;;
		ed2) echo "default 10.0.5.1" ;;
		ed3) echo "default $AL_EOS_ADDR" ;;
		ed6) echo "default 10.0.6.1" ;;
		esac
		return
	fi

	if [ "$SCENARIO" = pimd-rp ]; then
		# 10.0.4.0/24 hangs off the Arista, and both pimd routers
		# have to be able to RPF towards a source sitting there
		case $1 in
		ed1) echo "default 10.0.1.1" ;;
		r1)  echo "10.0.23.0/24 10.0.12.2 10.0.3.0/24 10.0.12.2 10.0.4.0/24 10.0.12.2" ;;
		r3)  echo "10.0.1.0/24 10.0.23.2 10.0.12.0/24 10.0.23.2 10.0.4.0/24 10.0.23.2" ;;
		ed2) echo "default 10.0.3.1" ;;
		ed4) echo "default 10.0.4.1" ;;
		esac
		return
	fi

	case $1 in
	ed1) echo "default 10.0.1.1" ;;
	r1)  echo "10.0.23.0/24 10.0.12.2 10.0.3.0/24 10.0.12.2" ;;
	r3)  echo "10.0.1.0/24 10.0.23.2 10.0.12.0/24 10.0.23.2" ;;
	ed2) echo "default 10.0.3.1" ;;
	esac
}

# "destination gateway metric" triples, applied to routes() output once the
# box has it.  Only assert-lan needs any, and only on R3: the route_metric
# field of its Asserts is MRIB.metric(S) now, the metric of this very route
# (set_incoming(), src/route.c), so this is where pimd's half of the
# comparison against the Arista is set.  It is deliberately the same number
# the Arista advertises, $AL_EOS_METRIC, so that every sub-case is decided
# by the one field it is about; write_case_confs() moves the preference
# beside it and nothing else.
route_metrics() {
	case $SCENARIO in
	assert-lan)
		case $1 in
		r3) echo "10.0.1.0/24 10.0.12.1 $AL_PIMD_METRIC" ;;
		esac
		;;
	esac
}

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
	[ "$(sysctl -n kern.features.vimage 2>/dev/null || echo 0)" = "1" ] || \
		die "kernel has no VIMAGE support, cannot create vnet jails"
	[ -x "$PIMD" ] || die "$PIMD not found, build it first (PIMD_SRC=$PIMD_SRC)"
	[ -x "$PIMCTL" ] || die "$PIMCTL not found, build it first"
	[ -f "$PIMD_SRC/test/mping.c" ] || die "$PIMD_SRC/test/mping.c not found"
	[ -x "$VEOS_SH" ] || \
		die "$VEOS_SH not found, set VEOS_SH to the vEOS bhyve runner"
	if [ -z "$VEOS_QCOW" ]; then
		usage >&2
		die "no vEOS image given, pass -i FILE or set VEOS_QCOW"
	fi
	[ -f "$VEOS_QCOW" ] || die "no such vEOS image: $VEOS_QCOW"
	command -v python3 >/dev/null 2>&1 || \
		die "python3 not found, it is what talks JSON to eAPI"
	${SUDO} kldload -n ip_mroute 2>/dev/null || \
		die "cannot load ip_mroute.ko, kernel has no multicast routing"
	${SUDO} kldload -n if_bridge 2>/dev/null || \
		die "cannot load if_bridge.ko, needed for the two PIM links"
	${SUDO} kldload -n vmm nmdm 2>/dev/null || \
		die "cannot load vmm.ko, bhyve is not available"

	if ${SUDO} jls -j "pimd${TAG}_r1" jid >/dev/null 2>&1; then
		die "freebsd-lab.sh is running in slot $SLOT, the two labs share" \
		    "addresses -- stop it, or run this one in another slot"
	fi
}

# net.inet.ip.mcast.loop must be 0 for any PIM router on FreeBSD; see the
# long comment on the same sysctl in freebsd-lab.sh.  It is a plain global,
# not VNET-ized, so it has to be changed on the host -- which makes it the
# one thing the slots, and the two labs, cannot each have their own of.
#
# So it is not restored by whoever happens to stop first: the value is
# saved once, by whichever lab arrives first, in a directory on the host
# they all share, each one leaves a file of its own there while it runs,
# and the last to leave is the one that puts the value back.  The same
# directory and the same lock as freebsd-lab.sh, deliberately -- the two
# labs want the same 0 and must not undo it under each other.
MCAST_LOOP_DIR=${MCAST_LOOP_DIR:-/var/run/pimd-lab-mcastloop}
MCAST_LOOP_LOCK=$MCAST_LOOP_DIR.lock
MCAST_LOOP_TOKEN=interop$SLOT

disable_mcast_loop() {
	${SUDO} lockf -k "$MCAST_LOOP_LOCK" /bin/sh -c '
		dir=$1
		if [ ! -d "$dir" ]; then
			mkdir -p "$dir" || exit 1
			sysctl -n net.inet.ip.mcast.loop > "$dir/saved"
		fi
		: > "$dir/$2"
		sysctl -q net.inet.ip.mcast.loop=0
	' mcastloop "$MCAST_LOOP_DIR" "$MCAST_LOOP_TOKEN"
}

restore_mcast_loop() {
	[ -d "$MCAST_LOOP_DIR" ] || return 0
	${SUDO} lockf -k "$MCAST_LOOP_LOCK" /bin/sh -c '
		dir=$1
		rm -f "$dir/$2"
		for f in "$dir"/*; do
			[ -e "$f" ] || continue
			[ "${f##*/}" = saved ] || exit 0
		done
		if [ -f "$dir/saved" ]; then
			sysctl -q net.inet.ip.mcast.loop="$(cat "$dir/saved")"
		fi
		rm -rf "$dir"
	' mcastloop "$MCAST_LOOP_DIR" "$MCAST_LOOP_TOKEN"
}

# --- configuration ----------------------------------------------------

# assert-lan: the per-sub-case configuration, which is R3's metrics and
# whether R3 and R5 may leave the shared tree.  $1 is the sub-case.
#
# The preference is R3's, and it is the first of the two Assert metric
# fields: set_incoming() (src/route.c) gives every source that is not
# directly connected the interface's uv_local_pref, which comes from here
# and nowhere else.  That is deviation M4 in doc/rfc7761-compliance.md --
# a configured constant where sec. 4.6.3 asks for the distance of the
# routing protocol that provided the route -- and it is also what makes
# the sub-cases below moveable from a config file.  The second field, the
# route metric, is the routing table's, so R3's half of it is set on the
# route itself in route_metrics(); default-route-metric below is what pimd
# falls back to where a kernel reports no metric at all, and is the same
# number so that both paths compare equal against the Arista.
#
# The shortest-path-tree policy decides the RPT bit, which sec. 4.6.1
# compares before either metric -- so it decides whether the metrics are
# looked at at all -- and it has to be settled before the Arista ever
# contends, not after.  R3 has a receiver of its own on 10.0.6.0/24 for
# exactly that reason: it makes R3 a last hop router, so try_switch_to_spt()
# (src/route.c:1246, gated on MRT_IS_LASTHOP or MRT_IS_RP) will consider
# it, and R3 reaches SPTbit off its own traffic rather than waiting for an
# (S,G) Join from R5.
#
# Which matters more than it sounds.  Without that receiver the LAN is
# R3's only outgoing interface, and the ordering becomes a race R3 can
# lose permanently: if the Arista's Assert lands before R3 has (S,G)
# state, R3 asserts from (*,G) with the RPT bit set, loses, and has its
# only oif removed -- after which update_sptbit() (src/route.c:532)
# returns early on an empty calc_oifs() and SPTbit is never set at all.
# Nothing then changes on either side, so nothing re-runs the election,
# and the metric sub-cases passed or failed on which message arrived
# first.  A sub-case about metric_preference must not be decided by the
# order two packets happened to land in.
write_case_confs() {
	case $1 in
	pimd-wins)   pref=$AL_PREF_BETTER; spt="spt-threshold packets 0 interval 10" ;;
	arista-wins) pref=$AL_PREF_WORSE;  spt="spt-threshold packets 0 interval 10" ;;
	tiebreak)    pref=$AL_EOS_PREF;    spt="spt-threshold packets 0 interval 10" ;;
	# Held on the shared tree, and given the better preference on
	# purpose: it must not save pimd, because the RPT bit is compared
	# first.  Both routers are pinned, since either one switching would
	# give R3 (S,G) state and take the bit away.
	rpt-bit)     pref=$AL_PREF_BETTER; spt="spt-threshold infinity" ;;
	esac

	cat <<-EOF > "$WORKDIR/r3.conf"
	# R3: one of the two contenders on the shared LAN, sub-case $1.
	# Last hop router for ED6 as well, which is what lets it reach the
	# shortest path tree without waiting on R5.
	hello-interval 10
	default-route-distance $pref
	default-route-metric $AL_PIMD_METRIC
	$spt
	EOF

	cat <<-EOF > "$WORKDIR/r5.conf"
	# R5: last hop router for ED2 and IGMP querier on the shared LAN,
	# never a contender on it.  Sub-case $1.  It queries often because
	# the Arista ages ED3's membership by what the querier asks for, and
	# the AssertCancel case needs that leaf to expire while it watches.
	hello-interval 10
	igmp-query-interval $AL_QUERY_INTERVAL
	$spt
	EOF
}

write_configs() {
	if [ "$SCENARIO" = assert-lan ]; then
		# R1 is the BSR and the RP as well as the first hop router.
		# One router fewer to boot, and it keeps every address the
		# assertions name on the contested LAN rather than spread
		# over a chain that has nothing to do with the election.
		cat <<-EOF > "$WORKDIR/r1.conf"
		# R1: first hop router, BSR and candidate RP.  It is one hop
		# upstream of both contenders and never on the contested LAN,
		# so nothing it does decides the election.
		hello-interval 10
		bsr-candidate ${EP}812b priority $PIMD_BSR_PRIORITY interval 10
		rp-candidate ${EP}812b priority 20 interval 10
		group-prefix 224.0.0.0 masklen 4
		EOF

		# R3's and R5's configs are per sub-case
		write_case_confs "$(echo "$AL_CASES" | awk '{print $1}')"
		write_veos_assert_conf
		write_eapi_helper
		return
	fi

	# hello-interval is tuned in both scenarios, and only to make
	# neighbour discovery take seconds instead of the 30s default.
	if [ "$SCENARIO" = pimd-rp ]; then
		# R1 originates the RP set the Arista has to parse.  The
		# candidacies name the interface facing it, so the RP address
		# is 10.0.12.1 rather than whichever of R1's addresses
		# happens to be numerically highest, and the assertions can
		# demand one exact address.  The intervals are the RFC
		# minimum, the default 60 would have the lab spend a minute
		# waiting for the first Bootstrap.
		#
		# spt-threshold is the other timer that has to move.  The RP
		# only re-evaluates the switch to the shortest path tree
		# every spt_threshold.interval, 100s by default
		# (SPT_THRESHOLD_DEFAULT_INTERVAL in src/pimd.h), and until
		# it has switched it is still legitimately asking the Arista
		# to encapsulate.  A stream shorter than that interval would
		# measure which side of a timer it landed on rather than
		# whether the Register-Stop was honoured, and assertion 4
		# would pass or fail by phase.
		cat <<-EOF > "$WORKDIR/r1.conf"
		# R1: BSR and candidate RP.  The Arista is the first and the
		# last hop router in this scenario, R1 only holds the roles
		# it originates protocol state for.
		hello-interval 10
		bsr-candidate ${EP}812b priority $PIMD_BSR_PRIORITY interval 10
		rp-candidate ${EP}812b priority 20 interval 10
		group-prefix 224.0.0.0 masklen 4
		spt-threshold packets 0 interval 10
		EOF
	else
		# Neither pimd router is a BSR or RP candidate: the Arista is
		# both, and the point of the scenario is that pimd learns the
		# RP set from it rather than from another pimd.
		cat <<-EOF > "$WORKDIR/r1.conf"
		# R1: first hop router, DR for the source on 10.0.1.0/24.
		# No bsr-candidate and no rp-candidate on purpose.
		hello-interval 10
		EOF
	fi

	cat <<-EOF > "$WORKDIR/r3.conf"
	# R3: no candidacy in either scenario.  In pimd-rp it is the router
	# that has to learn R1's RP set through the Arista.
	hello-interval 10
	EOF

	# The Arista's whole configuration, written onto the guest flash as
	# startup-config before the VM boots.  Declaring it here rather than
	# pushing it over eAPI at runtime keeps the switch reproducible: a
	# run always starts from exactly this text, and a vEOS with a
	# startup-config skips Zero Touch Provisioning.
	cat <<-EOF > "$WORKDIR/veos.cfg"
	! Generated by freebsd-interop.sh, do not edit in place
	no aaa root
	username $EAPI_USER privilege 15 role network-admin secret 0 $EAPI_PASS
	!
	hostname veos-interop
	no logging console
	spanning-tree mode none
	!
	interface Management1
	   ip address $MGMT_VEOS/24
	!
	management api http-commands
	   no shutdown
	   protocol http
	!
	interface Ethernet1
	   no switchport
	   ip address 10.0.12.2/24
	   pim ipv4 sparse-mode
	!
	interface Ethernet2
	   no switchport
	   ip address 10.0.23.2/24
	   pim ipv4 sparse-mode
	!
	ip routing
	!
	ip route 10.0.1.0/24 10.0.12.1
	ip route 10.0.3.0/24 10.0.23.3
	!
	router multicast
	   ipv4
	      routing
	!
	EOF

	if [ "$SCENARIO" = pimd-rp ]; then
		# The Arista holds no RP or BSR role here, it only learns
		# both from R1.  Ethernet3 is its edge LAN, and the only
		# interface in the lab where EOS rather than pimd answers an
		# IGMP report and registers a directly connected source.
		cat <<-EOF >> "$WORKDIR/veos.cfg"
		interface Ethernet3
		   no switchport
		   ip address 10.0.4.1/24
		   pim ipv4 sparse-mode
		!
		end
		EOF
	else
		# "candidate ... interval 10" is the BSR interval, the
		# default is 60: left there the lab spends a minute waiting
		# for the first Bootstrap before anything can be asserted.
		cat <<-EOF >> "$WORKDIR/veos.cfg"
		router pim sparse-mode
		   ipv4
		      rp candidate Ethernet1 priority 20
		!
		router pim bsr
		   ipv4
		      candidate Ethernet1 priority 64 hashmask 30 interval 10
		!
		end
		EOF
	fi

	write_eapi_helper
}

# eAPI is JSON-RPC over HTTP and there is no JSON in base, so the one
# piece of python in this lab lives here.  It prints the text output of
# each command, which is what the assertions grep.
write_eapi_helper() {
	cat <<-'PYEOF' > "$EAPI"
	import base64, json, sys, urllib.error, urllib.request

	url, user, password = sys.argv[1], sys.argv[2], sys.argv[3]
	cmds = sys.argv[4:]

	body = json.dumps({
	    "jsonrpc": "2.0", "method": "runCmds", "id": "pimd-interop",
	    "params": {"version": 1, "cmds": cmds, "format": "text"},
	}).encode()
	auth = base64.b64encode(("%s:%s" % (user, password)).encode()).decode()
	req = urllib.request.Request(url, body, {
	    "Content-Type": "application/json",
	    "Authorization": "Basic " + auth,
	})

	try:
	    raw = urllib.request.urlopen(req, timeout=30).read().decode("utf-8", "replace")
	except (urllib.error.URLError, OSError) as e:
	    sys.exit("eAPI unreachable: %s" % e)

	# strict=False: EOS puts raw control characters in some command output
	reply = json.loads(raw, strict=False)
	if "error" in reply:
	    sys.exit("eAPI error: %s" % reply["error"]["message"])
	for result in reply["result"]:
	    sys.stdout.write(result.get("output", ""))
	PYEOF
}

# assert-lan: the Arista's configuration.  It is the second contender on
# the shared LAN and the DR there, and it holds no BSR or RP role - R1
# does, so that the roles under test on this LAN are only the ones the
# election needs.
#
# The distance and metric on the route to the source are the whole point.
# Sec. 4.6.3 says the Assert metric preference and metric are the unicast
# routing protocol's, and EOS obeys that, so these two numbers are what it
# puts on the wire and what pimd's own constants are compared against.
# Written as a static route because a routing daemon would put the lab at
# the mercy of whatever metric it chose.
write_veos_assert_conf() {
	cat <<-EOF > "$WORKDIR/veos.cfg"
	! Generated by freebsd-interop.sh, do not edit in place
	no aaa root
	username $EAPI_USER privilege 15 role network-admin secret 0 $EAPI_PASS
	!
	hostname veos-assert
	no logging console
	spanning-tree mode none
	!
	interface Management1
	   ip address $MGMT_VEOS/24
	!
	management api http-commands
	   no shutdown
	   protocol http
	!
	interface Ethernet1
	   no switchport
	   ip address 10.0.12.2/24
	   pim ipv4 sparse-mode
	!
	interface Ethernet2
	   no switchport
	   ip address $AL_EOS_ADDR/24
	   pim ipv4 sparse-mode
	!
	ip routing
	!
	ip route 10.0.1.0/24 10.0.12.1 $AL_EOS_PREF metric $AL_EOS_METRIC
	ip route 10.0.5.0/24 $AL_R5_ADDR
	!
	router multicast
	   ipv4
	      routing
	!
	end
	EOF
}

# Run one or more EOS commands and print their text output.  Every command
# runs from enable mode, which is where all the show commands live.
eos() {
	python3 "$EAPI" "http://$MGMT_VEOS/command-api" \
		"$EAPI_USER" "$EAPI_PASS" enable "$@"
}

# --- topology ---------------------------------------------------------

create_lans() {
	if [ "$SCENARIO" = assert-lan ]; then
		# Two segments, and both are real broadcast domains rather
		# than point-to-point links: $BR12 carries R1, R3 and the
		# Arista's Ethernet1, and $BR3 is the contested LAN with R3,
		# R5, ED3 and the Arista's Ethernet2 on it.  Nothing else in
		# this file has more than two things on a wire.
		for br in $BR12 $BR3 $BR_MGMT; do
			if ifconfig "$br" >/dev/null 2>&1; then
				die "$br already exists, it is not ours to reuse"
			fi
			${SUDO} ifconfig bridge create name "$br" group "$IFGROUP" up >/dev/null
		done
		${SUDO} ifconfig "$BR_MGMT" inet "$MGMT_HOST/24" alias

		for e in ${EP}812 ${EP}832 ${EP}833 ${EP}853 ${EP}863; do
			${SUDO} ifconfig "$e" create group "$IFGROUP" >/dev/null
			${SUDO} ifconfig "${e}a" up
		done
		# R1 and R3 meet the Arista's Ethernet1 here
		${SUDO} ifconfig "$BR12" addm ${EP}812a
		${SUDO} ifconfig "$BR12" addm ${EP}832a
		# The contested LAN: R3, R5 and ED3, plus tap for Ethernet2
		${SUDO} ifconfig "$BR3" addm ${EP}833a
		${SUDO} ifconfig "$BR3" addm ${EP}853a
		${SUDO} ifconfig "$BR3" addm ${EP}863a

		return 0
	fi

	bridges="$BR12 $BR23 $BR_MGMT"
	bridged_epairs="${EP}812 ${EP}823"
	if [ "$SCENARIO" = pimd-rp ]; then
		bridges="$bridges $BR4"
		bridged_epairs="$bridged_epairs ${EP}804"
	fi

	for br in $bridges; do
		if ifconfig "$br" >/dev/null 2>&1; then
			die "$br already exists, it is not ours to reuse"
		fi
		${SUDO} ifconfig bridge create name "$br" group "$IFGROUP" up >/dev/null
	done

	# The management segment is the only one the host has an address on:
	# eAPI has to be reachable from where the assertions run.
	${SUDO} ifconfig "$BR_MGMT" inet "$MGMT_HOST/24" alias

	# The host ends of the PIM links.  Their peers are in the jails.
	for e in $bridged_epairs; do
		${SUDO} ifconfig "$e" create group "$IFGROUP" >/dev/null
		${SUDO} ifconfig "${e}a" up
	done
	${SUDO} ifconfig "$BR12" addm ${EP}812a
	${SUDO} ifconfig "$BR23" addm ${EP}823a
	[ "$SCENARIO" = pimd-rp ] && ${SUDO} ifconfig "$BR4" addm ${EP}804a

	return 0
}

create_box() {
	box=$1
	name=$(jname "$box")

	if [ "$(jls -d -j "$name" dying 2>/dev/null || true)" = "true" ]; then
		die "previous jail $name stuck dying, see FreeBSD bug 264981"
	fi

	set -- $(ifaces "$box")
	vnetargs=""
	for i in "$@"; do
		# The "a" end creates both ends of the pair; the two bridged
		# links were created by create_lans, which kept their "a" end
		case $i in
		*a) ifconfig "${i%a}" >/dev/null 2>&1 || \
			${SUDO} ifconfig "${i%a}" create group "$IFGROUP" >/dev/null ;;
		esac
		vnetargs="$vnetargs vnet.interface=$i"
	done

	# shellcheck disable=SC2086
	${SUDO} jail -c name="$name" host.hostname="$box" persist vnet $vnetargs

	set -- $(addrs "$box")
	while [ $# -ge 2 ]; do
		jrun "$box" ifconfig "$1" inet "$2" up
		shift 2
	done

	set -- $(routes "$box")
	while [ $# -ge 2 ]; do
		jrun "$box" route -q add "$1" "$2" >/dev/null
		shift 2
	done

	# After the routes: a metric is a property of one that already exists
	set -- $(route_metrics "$box")
	while [ $# -ge 3 ]; do
		jrun "$box" route -q change "$1" "$2" -metric "$3" >/dev/null
		shift 3
	done

	case $box in
	r*) jrun "$box" sysctl -q net.inet.ip.forwarding=1 >/dev/null ;;
	esac
}

destroy_box() {
	name=$(jname "$1")
	jls -j "$name" jid >/dev/null 2>&1 || return 0
	${SUDO} jail -r "$name" 2>/dev/null || true
}

# Ethernet3's tap is plugged in whatever the scenario, so the guest numbers
# Ethernet1 and Ethernet2 the same way in both; only pimd-rp bridges it to
# the LAN behind it.
veos() {
	# assert-lan puts Ethernet2 on the contested LAN instead of on a
	# link of its own, and has no use for Ethernet3
	et2="$TAP_ET2:$BR23"
	et3=$TAP_ET3
	case $SCENARIO in
	pimd-rp)    et3="$TAP_ET3:$BR4" ;;
	assert-lan) et2="$TAP_ET2:$BR3" ;;
	esac

	# -q only when there is an image to name: stop and console do not
	# need one, and stop runs on paths where none was given
	qarg=""
	[ -n "$VEOS_QCOW" ] && qarg="-q $VEOS_QCOW"

	# shellcheck disable=SC2086
	${SUDO} "$VEOS_SH" $qarg -n "$VEOS_VM" \
		-t "$TAP_MGMT:$BR_MGMT" -t "$TAP_ET1:$BR12" \
		-t "$et2" -t "$et3" \
		-a "$MGMT_VEOS" "$@"
}

# --- start / stop -----------------------------------------------------

start() {
	check_req

	if jls -j "$(jname r1)" jid >/dev/null 2>&1; then
		die "lab already running, run '$0 stop' first"
	fi

	mkdir -p "$WORKDIR"

	print "Building mping (multicast ping) from the pimd tree ..."
	cc -O2 -o "$MPING" "$PIMD_SRC/test/mping.c" || \
		die "failed building $PIMD_SRC/test/mping.c"

	print "Disabling multicast loopback on the host (restored by stop) ..."
	disable_mcast_loop

	write_configs

	print "Creating bridges, vnet jails and links ..."
	create_lans
	for box in $BOXES; do
		create_box "$box"
	done

	print "Starting pimd on $(echo $ROUTERS | tr ' ' ',') ..."
	for r in $ROUTERS; do
		# daemon(8) appends, and assertions that count log lines would
		# otherwise be reading the previous run as well as this one.
		# Removed rather than truncated: the file belongs to the root
		# daemon that wrote it, not to whoever runs this script.
		${SUDO} rm -f "$WORKDIR/$r.log"
		start_pimd "$r"
	done

	print "Writing the generated startup-config onto the vEOS flash ..."
	veos inject "$WORKDIR/veos.cfg" || die "could not inject the vEOS config"

	print "Booting the vEOS ..."
	veos -D start || die "could not start the vEOS"

	print "Waiting for eAPI on $MGMT_VEOS (up to ${VEOS_BOOT_WAIT}s) ..."
	if ! wait_for "$VEOS_BOOT_WAIT" eos "show version"; then
		die "vEOS never answered eAPI, try '$VEOS_SH -n $VEOS_VM console'"
	fi
	dprint "  $(eos 'show version' | awk -F': ' '/Software image version/ { print $2 }')"

	print "Lab is up ($SCENARIO).  Poke at it with:"
	echo "  ${SUDO} jexec $(jname r1) $PIMCTL -u $WORKDIR/r1.sock show pim detail"
	echo "  ${SUDO} $VEOS_SH -n $VEOS_VM cli 'show ip pim neighbor'"
	echo "  ${SUDO} $VEOS_SH -n $VEOS_VM console"
	echo "  tail -f $WORKDIR/r1.log"
}

stop() {
	for r in $ROUTERS; do
		[ -f "$WORKDIR/$r.daemon.pid" ] || continue
		${SUDO} pkill -F "$WORKDIR/$r.daemon.pid" 2>/dev/null
		rm -f "$WORKDIR/$r.daemon.pid"
	done

	veos stop >/dev/null 2>&1 || true

	# Every box and link either scenario can have built, not just the
	# current one's: "run all" switches scenarios between runs, and a
	# stop that only tore down what $SCENARIO happens to name would leave
	# the other one's jail or bridge behind to collide with the next run.
	for box in $ALL_BOXES; do
		destroy_box "$box"
	done

	# An epair that was moved into a jail comes back to the host when the
	# jail dies, but not to the group it was created in: moving an
	# interface between vnets drops its groups.  So the epairs have to be
	# destroyed by name rather than by group, and destroying the "a" end
	# takes the "b" end with it.  The bridges never left the host, but
	# naming them too keeps the teardown in one place.
	for e in $ALL_EPAIRS; do
		${SUDO} ifconfig "${e}a" destroy 2>/dev/null || true
	done
	for br in $BR12 $BR23 $BR3 $BR4 $BR_MGMT; do
		${SUDO} ifconfig "$br" destroy 2>/dev/null || true
	done

	# Anything else this lab created and did not hand to a jail
	for i in $(ifconfig -g "$IFGROUP" 2>/dev/null); do
		${SUDO} ifconfig "$i" destroy 2>/dev/null || true
	done

	restore_mcast_loop
	print "Lab stopped"
}

# --- assertions -------------------------------------------------------

has_neighbor() { pimctl "$1" show neighbor 2>/dev/null | grep -q "$2"; }
has_rp()       { pimctl "$1" show rp 2>/dev/null | grep -q "$2"; }
has_mrt()      { pimctl "$1" show mrt 2>/dev/null | grep -q "$2"; }

eos_has_neighbor() { eos "show ip pim neighbor" 2>/dev/null | grep -q "$1"; }
eos_has_mroute()   { eos "show ip mroute" 2>/dev/null | grep -q "$1"; }

# The DR pimd elected on the interface.  "show interface" prints
# "Interface State Address Priority Hello Nbr DR-Address DR-Priority".
pimd_dr() {
	pimctl "$1" show interface 2>/dev/null | awk -v i="$2" '$1 == i { print $7 }'
}

# The DR EOS elected on the interface.  "show ip pim interface" prints
# "Address Interface Mode Neighbor-Count Hello-Intvl DR-Pri DR-Address ...",
# so the interface is the second field and the DR address is the last field
# on the row that looks like an address - taking it that way rather than by
# number keeps the assertion working if a release adds a column.
eos_dr() {
	eos "show ip pim interface" 2>/dev/null | awk -v i="$1" '
		$2 == i {
			for (n = NF; n > 0; n--)
				if ($n ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {
					print $n
					exit
				}
		}'
}

pimd_dr_is() { [ "$(pimd_dr "$1" "$2")" = "$3" ]; }
eos_dr_is()  { [ "$(eos_dr "$1")" = "$2" ]; }

# The IGMP querier pimd shows for interface $2 on router $1, "Local" when
# this router won the election.  "show igmp" prints an interface table and
# a group table, both keyed on the interface name and both stripped of
# their headings by -t, so the rows are told apart by the interface state
# in the second column.
iface_querier() {
	pimctl "$1" -t show igmp 2>/dev/null | \
		awk -v ifn="$2" '$1 == ifn && $2 ~ /^(Up|Down|Disabled)$/ { print $3; exit }'
}

# Does the Arista hold this RP, and did it learn it from a Bootstrap rather
# than from its own configuration?  Both halves matter: an "rp address" line
# in the startup-config would satisfy the address on its own, and what is
# being asserted is what EOS parsed out of what pimd sent.  "show ip pim rp
# detail" prints an origin per entry, "bsrRp" for one learned through BSR.
eos_learned_rp() {
	eos "show ip pim rp detail" 2>/dev/null | awk -v rp="$1" '
		$1 == "RP:"                             { cur = ($2 == rp); next }
		cur && $1 == "Type:" && $2 == "bsrRp"   { found = 1 }
		END { exit !found }'
}

# The BSR the Arista elected, and the priority and hash mask length it read
# out of that Bootstrap.  Together they say pimd's Bootstrap header decoded
# field for field, not just that something arrived.
eos_bsr()      { eos "show ip pim bsr" 2>/dev/null | \
			awk '$1 == "BSR" && $2 == "address:" { print $3; exit }'; }
eos_bsr_is()   { [ "$(eos_bsr)" = "$1" ]; }

# Vif index of interface $2 on router $1.  "show interface" prints one row
# per vif in vif order and skips the register vif, which src/vif.h reserves
# as vif 0 (PIMREG_VIF), so the Nth row is vif N.  -t drops the headings.
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

# Is the slot interface $2 owns set in the map $3 read out of router $1?
map_isset() {
	idx=$(vif_index "$1" "$2")
	[ -n "$idx" ] || return 1
	[ -n "$3" ] || return 1

	[ "$(printf '%s' "$3" | cut -c "$((idx + 1))")" != "." ]
}

# Has router $1 put interface $2 in the outgoing list of its (*,$3), i.e.
# did it act on a Join that arrived there?  Re-read on every call so it can
# be polled with wait_for().
joined_on() {
	map_isset "$1" "$2" "$(route_map "$1" ANY "$3" Joined)"
}

# Vif index of the incoming interface of ($2,$3) on router $1, or nothing
# when there is no such entry.  "show mrt detail" prints the iif as a
# per-vif map with 'I' on the incoming one ("Incoming : .I."), so the offset
# of the 'I' is the vif number.  Vif 0 is the register vif, PIMREG_VIF in
# src/vif.h reserves it, so a non-zero answer means native traffic.
route_iif() {
	pimctl "$1" show mrt detail 2>/dev/null | awk -v s="$2" -v g="$3" '
		$1 == s && $2 == g       { want = 1; next }
		want && $1 == "Incoming" { print index($3, "I") - 1; want = 0 }
	'
}

# PIM Registers R1 has decapsulated so far
registers_seen() {
	${SUDO} grep -c "Received PIM register:" "$WORKDIR/r1.log" 2>/dev/null || true
}

# --- assert-lan helpers -----------------------------------------------

# Does router $1 actually forward this scenario's stream onto interface
# $2?  Read out of the kernel rather than out of pimd, because neither
# pimd entry answers it on its own: a router that lost the assert can
# still show the LAN in the oifs of its (*,G), which is state about the
# group and not about this source.  The MFC is the forwarding decision
# itself, and its vif numbers are the ones pimd handed the kernel.
forwards_on() {
	idx=$(vif_index "$1" "$2")
	[ -n "$idx" ] || return 1

	jrun "$1" netstat -gn 2>/dev/null | awk -v s="$SRC_ADDR" -v g="$GROUP" -v v="$idx" '
		$1 == s && $2 == g {
			# "Origin Group Packets In-Vif Out-Vifs:Ttls", the
			# out-vifs being "<vif>:<ttl>" from field 5 on
			for (i = 5; i <= NF; i++) {
				split($i, oif, ":")
				if (oif[1] == v)
					found = 1
			}
			exit
		}
		END { exit !found }
	'
}

# Has router $1 been asserted off interface $2, on the entry $3 names?
#
# One entry, never both.  They are separate elections and this scenario
# routinely splits them: R3 asserts from (*,G) state in the first round,
# with the RPT bit set, and loses that one for good, then reaches SPTbit
# and wins the (S,G) round on its metric.  A winner that is still marked
# asserted on its (*,G) is that split, not a failure, and reading both
# entries here would report every metric win as a loss.  Which one the
# sub-case is about is establish_election()'s AL_ASSERT_ENTRY.
asserted_on() {
	map_isset "$1" "$2" "$(route_map "$1" "${3:-$SRC_ADDR}" "$GROUP" Asserted)"
}

# Does the Arista forward the stream onto the contested LAN?  There is no
# "show ip pim assert" on EOS, so the observable is the same one used on
# pimd's side: whether the interface is in the outgoing list of the
# (S,G).  "show ip mroute" prints one two-space indented "<source>, <age>,
# flags: ..." heading per entry under the group, with an "Outgoing
# interface list:" and its members indented further under each:
#
#   225.1.2.3
#     10.0.1.10, 0:00:44, flags: SRP
#       Incoming interface: Ethernet1
#       Outgoing interface list:
#         Ethernet2
#
# so the entry is found by its heading and ended by the next one.
eos_forwards_on_lan() {
	eos "show ip mroute $GROUP" 2>/dev/null | awk -v s="$SRC_ADDR" '
		$1 == s","          { want = 1; oifs = 0; next }
		# The next entry heading ends this one
		want && /^  [0-9]/  { exit }
		want && /Outgoing interface list:/ { oifs = 1; next }
		want && oifs && $1 == "Ethernet2"  { found = 1; exit }
		END { exit !found }
	'
}

# The two contenders, sampled together.  Nothing here can be read before
# traffic flows - an assert is started by a data packet arriving on an
# interface that is not the receiver's iif - and nothing survives long
# after it stops, so both sides are read while the stream is in flight.
# Sets: al_pimd_fwd, al_eos_fwd, al_pimd_asserted.
sample_assert() {
	al_pimd_fwd=
	al_eos_fwd=
	al_pimd_asserted=
	al_pimd_asserted_wc=

	forwards_on r3 "$AL_R3_LAN_IF" && al_pimd_fwd=yes
	eos_forwards_on_lan && al_eos_fwd=yes

	# The (S,G) is where sec. 4.6.1 keeps the state of the machine every
	# Assert in this scenario belongs to, the Arista's carrying the RPT
	# bit clear.  The (*,G) is sampled beside it, and only so that the
	# loser branch can tell the loss recorded on the shared tree's entry
	# -- deviation M14, fixed, and this is its tripwire -- from no loss
	# recorded at all.
	asserted_on r3 "$AL_R3_LAN_IF" "$AL_ASSERT_ENTRY" && al_pimd_asserted=yes
	asserted_on r3 "$AL_R3_LAN_IF" ANY && al_pimd_asserted_wc=yes
}

# Does router $1 have a local member on interface $2, i.e. did an IGMP
# report there reach it?  Read off the (*,G), which is where a leaf lands
# before any source is known.
has_leaf() {
	map_isset "$1" "$2" "$(route_map "$1" ANY "$GROUP" Leaves)"
}

# Is router $1 on the shortest path tree for source $2?  "show mrt" prints
# an entry's flags, and SPT is set once the router holds (S,G) forwarding
# state of its own rather than an RPT-derived entry -- which is exactly
# what decides the RPT bit in the Assert it sends.
has_spt() {
	pimctl "$1" show mrt 2>/dev/null | \
		awk -v s="$2" -v g="$GROUP" '$1 == s && $2 == g && /SPT/ { found = 1 }
			END { exit !found }'
}

# Has the election reached the state the sub-case is about?
#
# "Exactly one forwarder" is not enough on its own, and taking it for
# enough cost two runs that passed by luck and a third that did not.  The
# election takes two rounds here: R3 asserts first from (*,G) state with
# the RPT bit set and loses, and for as long as that is where things
# stand the Arista is the only forwarder -- which satisfies "exactly one"
# perfectly well while being the answer to a question no sub-case asked.
# Sampling there reports round one, and whether round two had happened by
# then came down to whether it fitted inside the margin.
#
# So the metric sub-cases wait for R3 to hold (S,G) state as well, which
# is round two having happened: losing round one is what sets SPTbit
# (assert_loser in update_sptbit(), src/route.c:532) and R3 re-asserts
# with the SPT metric off the back of it.  rpt-bit wants R3 held on the
# shared tree and so has nothing further to wait for.
#
# Still blind to which side won: this waits for the election to be the
# one the sub-case set up, never for a particular outcome of it.
election_settled() {
	sample_assert

	[ -n "$al_pimd_fwd" ] && [ -z "$al_eos_fwd" ] && return 0
	[ -z "$al_pimd_fwd" ] && [ -n "$al_eos_fwd" ] && return 0

	return 1
}

# Start pimd on one router of this lab, from whatever its .conf now says
start_pimd() {
	r=$1

	# shellcheck disable=SC2086
	${SUDO} daemon -f -p "$WORKDIR/$r.daemon.pid" \
		-o "$WORKDIR/$r.log" \
		jexec "$(jname "$r")" "$PIMD" -i "$r" -n $DEBUG \
		-f "$WORKDIR/$r.conf" \
		-p "$WORKDIR/$r.pid" \
		-u "$WORKDIR/$r.sock"
}

# Switch the lab to a sub-case: rewrite R3's and R5's configs and restart
# pimd on both.  Seconds, where rebooting the vEOS to change its side
# would cost minutes, which is why all four sub-cases run in one lab.
#
# Restarted rather than SIGHUPed, and both routers together.  The old
# assert state has to be gone from the *Arista* as well, and only a new
# GenID in a Hello makes a neighbour drop what it held for the router that
# sent it; a reload keeps the GenID and the Arista would go on applying
# the previous sub-case's election to the new one.
switch_case() {
	write_case_confs "$1"

	for r in r3 r5; do
		[ -f "$WORKDIR/$r.daemon.pid" ] && \
			${SUDO} pkill -F "$WORKDIR/$r.daemon.pid" 2>/dev/null
		rm -f "$WORKDIR/$r.daemon.pid"
		${SUDO} rm -f "$WORKDIR/$r.log"
	done
	sleep 3

	for r in r3 r5; do
		start_pimd "$r"
	done

	for r in r3 r5; do
		wait_for 60 has_neighbor "$r" "$AL_EOS_ADDR" || \
			die "$r did not come back up in sub-case $1"
		wait_for 120 has_rp "$r" "$RP_ADDR" || \
			die "$r did not relearn the RP in sub-case $1"
	done
}

# pimd-rp: every exchange below has the writer and the reader swapped
# relative to check().  The stream runs between ED1 and ED4, and mping's
# receiver answers to the same group, so the single run builds (ED1,G) with
# pimd as first hop router and EOS as last hop one, and (ED4,G) the other
# way around.
check_pimd_rp() {
	print "1. pimd and EOS become PIM neighbours on both links"
	if wait_for 60 has_neighbor r1 10.0.12.2; then
		ok "R1 sees the Arista at 10.0.12.2"
	else
		fail "R1 never saw a PIM neighbour at 10.0.12.2"
	fi
	if wait_for 60 eos_has_neighbor 10.0.12.1; then
		ok "the Arista sees R1 at 10.0.12.1"
	else
		fail "the Arista never saw a PIM neighbour at 10.0.12.1"
	fi
	if wait_for 60 eos_has_neighbor 10.0.23.3; then
		ok "the Arista sees R3 at 10.0.23.3"
	else
		fail "the Arista never saw a PIM neighbour at 10.0.23.3"
	fi
	[ "$FAILED" -eq 0 ] || return 1

	print "2. The Arista learns the RP set from pimd's Bootstrap"
	# The exchange check() cannot reach: here pimd writes the Bootstrap
	# and the Candidate-RP-Advertisement and EOS parses them.  The origin
	# is asserted along with the address, or a static RP would pass.
	if wait_for 120 eos_bsr_is "$PIMD_RP_ADDR"; then
		ok "the Arista elected R1 at $PIMD_RP_ADDR as BSR"
	else
		fail "the Arista's BSR is '$(eos_bsr)', expected $PIMD_RP_ADDR"
		dprint "$(eos 'show ip pim bsr')"
		return 1
	fi
	# The header fields of that same Bootstrap, read back by a decoder
	# pimd did not write: a priority or a hash mask length that arrives
	# mangled is invisible as long as both ends are pimd.
	bsr=$(eos "show ip pim bsr")
	if echo "$bsr" | grep -q "BSR Priority: $PIMD_BSR_PRIORITY"; then
		ok "the Arista read BSR priority $PIMD_BSR_PRIORITY out of it"
	else
		fail "the Arista did not read BSR priority $PIMD_BSR_PRIORITY"
		dprint "$bsr"
	fi
	if echo "$bsr" | grep -q "Hash mask length: $PIMD_BSR_HASHLEN"; then
		ok "the Arista read hash mask length $PIMD_BSR_HASHLEN out of it"
	else
		fail "the Arista did not read hash mask length $PIMD_BSR_HASHLEN"
		dprint "$bsr"
	fi
	if wait_for 120 eos_learned_rp "$RP_ADDR"; then
		ok "the Arista learned RP $RP_ADDR, origin bsrRp"
	else
		fail "the Arista never learned RP $RP_ADDR from pimd's Bootstrap"
		dprint "$(eos 'show ip pim rp detail')"
		return 1
	fi
	# R3 is two hops from the BSR with the Arista in between, so it can
	# only have the RP set if EOS forwarded a Bootstrap pimd originated.
	if wait_for 120 has_rp r3 "$RP_ADDR"; then
		ok "R3 learned RP $RP_ADDR through the Arista"
	else
		fail "R3 never learned RP $RP_ADDR, the Arista did not forward the Bootstrap"
	fi
	[ "$FAILED" -eq 0 ] || return 1

	print "3. pimd accepts the (*,G) Join the Arista sends it"
	# ED4 hangs off the Arista, so its report makes EOS the last hop
	# router and EOS builds the Join.  The assertion is on R1's own
	# outgoing list: the interface towards the Arista can only be in it
	# because pimd believed a Join built by EOS.
	jrun ed4 "$MPING" -r -i "$ED4_IF" -t 5 -W 180 "$GROUP" \
		>"$WORKDIR/receiver.log" 2>&1 &
	receiver=$!

	if wait_for 90 joined_on r1 ${EP}812b "$GROUP"; then
		ok "R1 has ${EP}812b in the oifs of (*, $GROUP)"
	else
		fail "R1 never added ${EP}812b to (*, $GROUP) from the Arista's Join"
		dprint "$(pimctl r1 show mrt detail | head -20)"
		kill "$receiver" 2>/dev/null
		return 1
	fi

	print "4. pimd decapsulates the Arista's Register, and it stops"
	# ED4's replies make the Arista the first hop router for a source of
	# its own, so it encapsulates to R1.  Three things follow, and each
	# is asserted separately: pimd understood a Register written by EOS,
	# pimd then got itself off the register vif, and EOS acted on the
	# Register-Stop pimd answered with.
	jrun ed1 "$MPING" -s -i "$ED1_IF" -t 5 -c "$STREAM_PKTS" -w 120 "$GROUP" \
		>"$WORKDIR/sender.log" 2>&1 || true

	if has_mrt r1 "$ED4_ADDR"; then
		ok "R1 built ($ED4_ADDR, $GROUP) from the Arista's Register"
	else
		fail "R1 never built ($ED4_ADDR, $GROUP)"
		dprint "$(pimctl r1 show mrt)"
		kill "$receiver" 2>/dev/null
		return 1
	fi

	# Vif 0 is the register vif.  An (S,G) still incoming on it is an RP
	# living off the encapsulated copies alone, which is also the only
	# state in which register-stopping the Arista would be wrong.
	iif=$(route_iif r1 "$ED4_ADDR" "$GROUP")
	if [ -n "$iif" ] && [ "$iif" -ne 0 ]; then
		ok "R1 receives ($ED4_ADDR, $GROUP) natively on vif $iif, off the register vif"
	else
		fail "R1 still has ($ED4_ADDR, $GROUP) incoming on the register vif"
	fi

	regs_before=$(registers_seen)
	jrun ed1 "$MPING" -s -i "$ED1_IF" -t 5 -c "$SETTLED_PKTS" -w 60 "$GROUP" \
		>"$WORKDIR/sender2.log" 2>&1 || true
	regs=$(( $(registers_seen) - regs_before ))

	if [ "$regs" -le "$MAX_REGISTERS" ]; then
		ok "$regs registers over $SETTLED_PKTS packets once the tree was up"
	else
		fail "$regs registers over $SETTLED_PKTS settled packets, the Register-Stop was ignored"
	fi

	kill "$receiver" 2>/dev/null
	wait "$receiver" 2>/dev/null

	print "5. Multicast reaches ED4 across the Arista"
	# Counted from the replies rather than from the receiver's log: mping
	# block buffers stdout and is killed, not stopped, so that log never
	# reaches the disk.  A reply only exists because a packet arrived,
	# and it arrived over a tree the Arista built as last hop router.
	replies=$(awk '/packets transmitted/ { print $4 }' "$WORKDIR/sender.log")
	replies=${replies:-0}
	if [ "$replies" -ge "$MIN_REPLIES" ]; then
		ok "$replies of $STREAM_PKTS packets answered by ED4"
	else
		fail "only $replies of $STREAM_PKTS packets answered, wanted $MIN_REPLIES"
		dprint "$(eos 'show ip mroute')"
	fi

	return $((FAILED > 0))
}

# assert-lan: bring the lab to a settled election for sub-case $1, with
# the streams left running, and leave the reading in al_pimd_fwd,
# al_eos_fwd and al_pimd_asserted.  Returns non-zero if no election
# settled, having said why.
#
# Split out from assert_case() because the two state machine cases need the same
# setup and then measure something else entirely.  Calling assert_case()
# for its side effects and discarding its output, which is what they used
# to do, hid any failure it reported: the message went to /dev/null while
# the counter behind it still went up, so a broken setup showed as a run
# that was one assertion short and otherwise green.
establish_election() {
	case_name=$1

	# Where the loss is recorded is not pimd's bookkeeping to choose: the
	# RPT bit of the Assert says which of the two state machines it
	# belongs to, sec. 4.6.2.  In the three metric sub-cases R3 is on the
	# shortest path tree and trades Asserts with the bit clear, which is
	# the (S,G) machine of sec. 4.6.1, so the (S,G) entry is where the
	# state lands -- pimd creating one for it if it had none.  This used
	# to accept the (*,G) as well, which is what pimd recorded it on when
	# one election ran on whichever entry the lookup returned.
	#
	# rpt-bit asks for the same entry and is the sub-case that used to
	# fail to get it.  R3 is held on the shared tree there, so it holds no
	# (S,G) state of its own; run on its own, the first Assert it hears
	# from the Arista is the (*,G) one of sec. 4.6.2, source 0.0.0.0 on
	# the wire, and losing that takes the LAN away.  The Arista's (S,G)
	# Assert arrives behind it and has to put the (S,G) machine into Loser
	# as well, sec. 4.6.1 asking only for AssertTrackingDesired(S,G,I).
	# pimd could not reach that machine once the shared tree had lost the
	# interface and left the loss on the (*,G) -- deviation M14, fixed in
	# assert_machine(), and the assertion stays as its tripwire.  It asks
	# for the entry sec. 4.6.1 names and reports KNOWN when it lands
	# elsewhere, rather than being rewritten to match whatever pimd does.
	AL_ASSERT_ENTRY=$SRC_ADDR

	switch_case "$case_name"

	# ED3's report gives the Arista, as DR, a leaf on the LAN; R5's Join
	# gives R3 its oif there.  Two forwarders on one segment is what an
	# assert needs, and they get there by different routes on purpose:
	# add_leaf() (src/route.c) only lets the DR act on a report, so IGMP
	# alone could never produce the second one.
	# The order the three receivers are brought up in is the scenario, not
	# housekeeping, and getting it wrong costs a sub-case that passes or
	# fails on a race.
	#
	# The tree is built to the point where R3 holds (S,G) state of its
	# own, and only then is the Arista given a reason to forward.  ED6 is
	# what makes that possible without waiting on R5: its membership makes
	# R3 a last hop router, so try_switch_to_spt() (src/route.c) will
	# consider R3 at all.
	#
	# That order used to decide the sub-cases on its own.  pimd evaluated
	# SPTbit once per upcall and not per packet, so if the Arista was
	# already forwarding when R3's one evaluation happened, R3 was losing
	# an assert from (*,G) state, never reached SPTbit, and asserted with
	# the RPT bit for the rest of the run -- deviation M10, which this
	# scenario turned up.  check_sptbit() (src/route.c) re-runs the check
	# while data is arriving now, so the order no longer decides anything;
	# it is kept because a sub-case that has to wait out an election it did
	# not set up is slower and harder to read.
	jrun ed6 "$MPING" -r -i "$AL_ED6_IF" -p "$AL_JOIN_PORT6" -t 5 -W "$AL_STREAM_LIFE" "$GROUP" \
		>"$WORKDIR/joiner6.log" 2>&1 &
	joiner6=$!
	jrun ed2 "$MPING" -r -i "$AL_ED2_IF" -t 5 -W "$AL_STREAM_LIFE" "$GROUP" \
		>"$WORKDIR/receiver.log" 2>&1 &
	receiver=$!

	# R3 has to know about ED6 before the first packet, or the SPTbit
	# check sees an empty outgoing list and returns early on every pass
	if ! wait_for 90 has_leaf r3 ${EP}836a; then
		fail "$case_name: R3 never saw ED6's membership, it cannot reach the SPT"
		kill "$receiver" "$joiner6" 2>/dev/null
		wait "$receiver" "$joiner6" 2>/dev/null
		return 1
	fi

	jrun ed1 "$MPING" -s -i "$ED1_IF" -t 5 -c "$AL_STREAM_PKTS" -w "$AL_STREAM_LIFE" "$GROUP" \
		>"$WORKDIR/sender.log" 2>&1 &
	sender=$!

	# The metric sub-cases need R3 on the shortest path tree before it is
	# asked to assert; rpt-bit needs it held off, and has nothing to wait
	# for beyond the traffic arriving.
	if [ "$case_name" != rpt-bit ]; then
		# This was deviation M10: pimd evaluated SPTbit only when an
		# upcall reached update_sptbit() (src/route.c), so an (S,G)
		# that met the sec. 4.2 conditions only after its first packet
		# never set it.  R3 is exactly that entry here -- traffic on
		# RPF_interface(S), a non-empty olist from ED6, and
		# RPF'(S,G) == RPF'(*,G) -- and it sat on the shared tree
		# anyway, which made its Assert carry the RPT bit and lose on
		# sec. 4.6.1's first comparison whatever its metric said.
		#
		# check_sptbit() (src/route.c) fixed that, and the report
		# stays as the tripwire for it: a pimd that stops reaching the
		# tree cannot compare metrics at all, so the sub-case says so
		# where it happens rather than failing the election it makes
		# unreachable.
		if ! wait_for "$AL_FWD_WAIT" has_spt r3 "$SRC_ADDR"; then
			if [ -z "$AL_M10_SEEN" ]; then
				xfail "R3 holds (S,G) with an olist and traffic on its RPF interface but never set SPTbit, so its Assert carries the RPT bit and no metric of its is ever compared (M10, src/route.c:532)"
				dprint "$(pimctl r3 show mrt | head -8)"
				AL_M10_SEEN=yes
			elif [ "$AL_IN_SUBCASE" = yes ]; then
				dprint "  $case_name: unreachable for the same reason, see M10 above"
			fi
			kill "$sender" "$receiver" "$joiner6" 2>/dev/null
			wait "$sender" "$receiver" "$joiner6" 2>/dev/null
			return 1
		fi
	else
		if ! wait_for "$AL_FWD_WAIT" forwards_on r3 "$AL_R3_LAN_IF"; then
			fail "$case_name: R3 never forwarded onto the LAN, there is no election to hold"
			kill "$sender" "$receiver" "$joiner6" 2>/dev/null
			wait "$sender" "$receiver" "$joiner6" 2>/dev/null
			return 1
		fi
	fi

	# Now the second forwarder.  add_leaf() (src/route.c) only lets the DR
	# act on an IGMP report, and the Arista is the DR here, so ED3's report
	# gives it a leaf and gives nobody else one.
	jrun ed3 "$MPING" -r -i "$AL_ED3_IF" -p "$AL_JOIN_PORT" -t 5 -W "$AL_STREAM_LIFE" "$GROUP" \
		>"$WORKDIR/joiner.log" 2>&1 &
	joiner=$!

	if ! wait_for "$AL_FWD_WAIT" election_settled; then
		spt=no
		has_spt r3 "$SRC_ADDR" && spt=yes
		fail "$case_name: no settled election after ${AL_FWD_WAIT}s (pimd fwd='$al_pimd_fwd' Arista fwd='$al_eos_fwd' pimd SPT=$spt)"
		dprint "$(pimctl r3 show mrt | head -8)"
		dprint "$(eos "show ip mroute $GROUP")"
		kill "$sender" "$receiver" "$joiner" "$joiner6" 2>/dev/null
		wait "$sender" "$receiver" "$joiner" "$joiner6" 2>/dev/null
		return 1
	fi

	# A margin past the first settled reading, so a second round in
	# flight is not mistaken for the answer
	sleep "$AL_ELECTION_WAIT"
	sample_assert

	return 0
}

# assert-lan: establish the election for sub-case $1 and say whether the
# side that should have won did.  $2 is the side expected to keep the
# LAN, $3 why.
assert_case() {
	case_name=$1
	winner=$2
	because=$3

	print "Sub-case $case_name: $because"

	AL_IN_SUBCASE=yes
	establish_election "$case_name"
	rc=$?
	AL_IN_SUBCASE=
	[ $rc -eq 0 ] || return 1

	kill "$sender" 2>/dev/null
	wait "$sender" 2>/dev/null

	if [ -z "$al_pimd_fwd" ] && [ -z "$al_eos_fwd" ]; then
		fail "$case_name: neither router forwarded onto the LAN, nothing was elected"
		dprint "$(eos "show ip mroute $GROUP")"
		return 1
	fi

	case $winner in
	pimd)
		if [ -n "$al_pimd_fwd" ] && [ -z "$al_eos_fwd" ]; then
			ok "$case_name: pimd kept the LAN, the Arista gave it up"
		else
			fail "$case_name: pimd forward='$al_pimd_fwd' Arista forward='$al_eos_fwd', wanted pimd only"
			dprint "$(eos "show ip mroute $GROUP")"
		fi
		if [ -z "$al_pimd_asserted" ]; then
			ok "$case_name: pimd holds no asserted oif, as the winner"
		else
			fail "$case_name: pimd won but marked $AL_R3_LAN_IF asserted"
		fi ;;
	arista)
		if [ -n "$al_eos_fwd" ] && [ -z "$al_pimd_fwd" ]; then
			ok "$case_name: the Arista kept the LAN, pimd gave it up"
		else
			fail "$case_name: pimd forward='$al_pimd_fwd' Arista forward='$al_eos_fwd', wanted the Arista only"
			dprint "$(eos "show ip mroute $GROUP")"
		fi
		if [ -n "$al_pimd_asserted" ]; then
			ok "$case_name: pimd recorded $AL_R3_LAN_IF as asserted, as the loser"
		elif [ -n "$al_pimd_asserted_wc" ]; then
			xfail "$case_name: pimd recorded the loss on its (*,G), not on the (S,G) machine the Arista's Assert belongs to (M14, src/pim_proto.c)"
		else
			fail "$case_name: pimd lost the LAN but never marked $AL_R3_LAN_IF asserted"
			dprint "$(pimctl r3 show mrt detail)"
		fi ;;
	esac

	# Either way the receiver behind R5 must still be served: an assert
	# decides which router forwards, never whether anything does.  A
	# second short stream, run to completion now that the election has
	# settled, rather than the long one above - that one is killed at
	# the sampling point and never writes its summary line.
	jrun ed1 "$MPING" -s -i "$ED1_IF" -t 5 -c "$AL_CONFIRM_PKTS" -w $((AL_CONFIRM_PKTS + 30)) "$GROUP" \
		>"$WORKDIR/sender2.log" 2>&1 || true
	replies=$(awk '/packets transmitted/ { print $4 }' "$WORKDIR/sender2.log")
	replies=${replies:-0}
	if [ "$replies" -ge "$AL_MIN_CONFIRM" ]; then
		ok "$case_name: $replies of $AL_CONFIRM_PKTS packets still reached ED2 past the election"
	else
		fail "$case_name: only $replies of $AL_CONFIRM_PKTS reached ED2, the LAN was black-holed"
	fi

	kill "$receiver" "$joiner" "$joiner6" 2>/dev/null
	wait "$receiver" "$joiner" "$joiner6" 2>/dev/null
}

check_assert_lan() {
	print "1. Everyone on the contested LAN sees everyone else"
	# Three PIM routers on one segment, which nothing else in this file
	# has: the two contenders and the downstream router.
	for pair in "r3 $AL_EOS_ADDR" "r3 $AL_R5_ADDR" \
		    "r5 $AL_EOS_ADDR" "r5 $AL_R3_ADDR"; do
		# shellcheck disable=SC2086
		set -- $pair
		if wait_for 90 has_neighbor "$1" "$2"; then
			ok "$1 sees $2 on the shared LAN"
		else
			fail "$1 never saw $2, PIM hello is not crossing $BR3"
		fi
	done
	if wait_for 90 eos_has_neighbor "$AL_R3_ADDR"; then
		ok "the Arista sees R3 at $AL_R3_ADDR"
	else
		fail "the Arista never saw R3 at $AL_R3_ADDR"
	fi
	if wait_for 90 eos_has_neighbor "$AL_R5_ADDR"; then
		ok "the Arista sees R5 at $AL_R5_ADDR"
	else
		fail "the Arista never saw R5 at $AL_R5_ADDR"
	fi
	[ "$FAILED" -eq 0 ] || return 1

	print "2. DR and IGMP querier election, against a foreign implementation"
	# Two elections over one wire, deliberately won by different
	# routers: PIM takes the highest address (the Arista), IGMP the
	# lowest (R5).  Neither is the assert, and both are asserted from
	# both sides.
	if wait_for 60 pimd_dr_is r3 "$AL_R3_LAN_IF" "$AL_EOS_ADDR"; then
		ok "R3 made the Arista DR on the shared LAN"
	else
		fail "R3 says the DR is '$(pimd_dr r3 "$AL_R3_LAN_IF")', expected $AL_EOS_ADDR"
	fi
	if wait_for 60 pimd_dr_is r5 ${EP}853b "$AL_EOS_ADDR"; then
		ok "R5 agrees the Arista is DR"
	else
		fail "R5 says the DR is '$(pimd_dr r5 ${EP}853b)', expected $AL_EOS_ADDR"
	fi
	if wait_for 60 eos_dr_is Ethernet2 "$AL_EOS_ADDR"; then
		ok "the Arista agrees it is DR"
	else
		fail "the Arista says the DR is '$(eos_dr Ethernet2)', expected $AL_EOS_ADDR"
	fi
	q=$(iface_querier r3 "$AL_R3_LAN_IF")
	if [ "$q" = "$AL_R5_ADDR" ]; then
		ok "R3 says the IGMP querier is R5 at $AL_R5_ADDR, not the DR"
	else
		fail "R3 says the querier is '$q', expected $AL_R5_ADDR"
	fi
	[ "$FAILED" -eq 0 ] || return 1

	print "3. Both pimd routers learn the RP from R1"
	for r in r3 r5; do
		if wait_for 120 has_rp "$r" "$RP_ADDR"; then
			ok "$r learned RP $RP_ADDR"
		else
			fail "$r never learned RP $RP_ADDR"
		fi
	done
	[ "$FAILED" -eq 0 ] || return 1

	print "4. The Arista advertises the routing metrics sec. 4.6.3 asks for"
	# The premise of every sub-case below.  pimd's preference is a
	# configured constant (M4 in doc/rfc7761-compliance.md) and its
	# metric is the one route_metrics() put on R3's route to the source,
	# so unless the Arista really does put its route's distance and
	# metric on the wire, the numbers the sub-cases move are being
	# compared against something else entirely.
	rt=$(eos "show ip route 10.0.1.0/24")
	if echo "$rt" | grep -q "\[$AL_EOS_PREF/$AL_EOS_METRIC\]"; then
		ok "the Arista's route to the source is [$AL_EOS_PREF/$AL_EOS_METRIC]"
	else
		fail "the Arista's route to the source is not [$AL_EOS_PREF/$AL_EOS_METRIC]"
		dprint "$rt"
		return 1
	fi

	# The four elections.  Each rewrites r3.conf and restarts pimd on
	# R3; nothing else changes, so the only variable is what pimd puts
	# in the two metric fields and whether it is on the SPT.
	for c in $AL_CASES; do
		case $c in
		pimd-wins)
			assert_case pimd-wins pimd \
				"pimd's metric preference $AL_PREF_BETTER beats the Arista's $AL_EOS_PREF" ;;
		arista-wins)
			assert_case arista-wins arista \
				"the Arista's $AL_EOS_PREF beats pimd's $AL_PREF_WORSE" ;;
		tiebreak)
			assert_case tiebreak arista \
				"equal metrics, so the highest address wins" ;;
		rpt-bit)
			assert_case rpt-bit arista \
				"pimd is off the SPT, so RFC 7761 4.6.1 decides on the RPT bit before the metric" ;;
		esac
		[ "$FAILED" -eq 0 ] || return 1
	done

	# The two state machine cases, which need an assert pimd has *lost* to work
	# from, so they run last and reuse the state the tiebreak left.
	check_assert_cancel
	check_assert_no_resend

	return $((FAILED > 0))
}

# The AssertCancel of sec. 4.6.4, received.
#
# Sec. 4.6.4 has the winner send an Assert with an infinite metric when it
# stops forwarding, so the losers return to NoInfo at once instead of
# waiting out Assert_Time.  pimd now sends one too
# (send_pim_assert_cancel(), src/pim_proto.c), but between two pimds an
# assert only ever resolves one way, so a *received* cancel still has no
# other source than a foreign implementation.  EOS sends it, which is what
# makes this reachable here at all.
#
# This was the first half of deviation M3: pimd gated all downstream assert
# processing on the interface still being in mrt->oifs, and losing removed
# it, so the cancel could not be acted on.  The Loser state of sec. 4.6.1
# now has its own transitions (src/pim_proto.c:3203), and a loser is no
# longer required to hold a kernel cache to hear an assert at all
# (src/pim_proto.c:3185), which was the gate behind it.  The report stays
# as the tripwire for both.
check_assert_cancel() {
	print "5. An AssertCancel from the Arista (RFC 7761 4.6.4)"

	# pimd has to be the assert loser for a cancel to mean anything, and
	# rpt-bit is the sub-case that gets it there with the fewest moving
	# parts: pimd is held off the shortest path tree, asserts from (*,G),
	# the Arista wins on the RPT bit, pimd is the loser.  tiebreak does
	# the same job now that pimd reaches the SPT, and is what this used
	# before M10 was understood.
	establish_election rpt-bit || return
	if [ -z "$al_pimd_asserted$al_pimd_asserted_wc" ] || [ -n "$al_pimd_fwd" ]; then
		fail "could not make pimd the assert loser, the cancel case cannot run"
		kill "$sender" "$receiver" "$joiner" "$joiner6" 2>/dev/null
		wait "$sender" "$receiver" "$joiner" "$joiner6" 2>/dev/null
		return
	fi

	# Take away every reason the winner has to forward on this LAN, which
	# is more than ED3's membership, and finding that out cost a run.
	# Shutting Ethernet2 down would take the whole LAN with it, so the
	# receivers go instead -- but stopping ED3 alone leaves the Arista
	# with R3's old downstream state: sec. 4.5.5 has R5 send its Join to
	# RPF'(*,G), which is the assert winner now, and the log says it does
	# ("Assert lost on epair853b ... winner 10.0.3.3", then its Joins go
	# there).  A winner still holding a Join on the interface has not
	# deleted the forwarding state that caused the assert and owes
	# nobody a cancel, and the case used to read pimd's silence as it
	# ignoring a message that was never sent.  ED2 goes too, so that R5
	# stops joining at all and the Arista's outgoing list on Ethernet2
	# really empties -- the trigger sec. 4.6.4 names.
	kill "$joiner" "$receiver" 2>/dev/null
	wait "$joiner" "$receiver" 2>/dev/null
	receiver=

	# Long enough for both memberships to expire, R5's Join to stop, the
	# cancel to be sent and acted on, and far short of the Assert_Time a
	# loser would otherwise have to wait out.  What makes it long enough
	# for the memberships is AL_QUERY_INTERVAL; see it.
	sleep "$AL_CANCEL_WAIT"
	sample_assert

	# The premise, checked rather than assumed.
	if [ -n "$al_eos_fwd" ]; then
		fail "the Arista still forwards $GROUP onto the LAN after ${AL_CANCEL_WAIT}s, so no AssertCancel was ever due"
		dprint "$(eos "show ip mroute $GROUP")"
		dprint "$(eos "show ip igmp groups")"
		kill "$sender" "$joiner6" 2>/dev/null
		wait "$sender" "$joiner6" 2>/dev/null
		return
	fi

	# Back to NoInfo is what sec. 4.6.4 asks of the loser, and it is the
	# observable here: with both receivers gone nobody forwards onto this
	# LAN whatever the assert state says, so "pimd forwards again" would
	# measure the receivers rather than the cancel.  Both entries are
	# asked: the cancel reaches the (S,G) machine that holds the loss and
	# then the (*,G) machine behind it, which is the half of M14 that is
	# not about reaching the (S,G) machine in the first place.
	if [ -z "$al_pimd_asserted$al_pimd_asserted_wc" ]; then
		ok "pimd returned to NoInfo on $AL_R3_LAN_IF, as sec. 4.6.4 asks, rather than waiting out Assert_Time"
	else
		xfail "pimd ignored the AssertCancel and stayed the assert loser on $AL_R3_LAN_IF (M3 is back, src/pim_proto.c:3203)"
		dprint "$(pimctl r3 show mrt detail)"
	fi

	kill "$sender" "$joiner6" 2>/dev/null
	wait "$sender" "$joiner6" 2>/dev/null
}

# The winner's resend of sec. 4.6.1 Actions A3.
#
# Sec. 4.6.1 has the winner rearm at Assert_Time - Assert_Override_Interval
# and resend, so a conformant loser is refreshed before its own timer
# expires.  This was the second half of deviation M3: pimd armed nothing,
# so at Assert_Time the Arista returned to NoInfo and started forwarding
# again, and the LAN carried every packet twice until pimd noticed the
# duplicate on the wrong interface and asserted afresh.  assert_won()
# (src/pim_proto.c:2874) arms PIM_ASSERT_WINNER_TIMEOUT now and
# age_asserts() resends on it; the report stays as the tripwire.
#
# That last part is why this has to be sampled continuously rather than
# once at the end.  The re-election is quick -- one data packet on the
# wrong iif is enough -- so a single reading taken after Assert_Time finds
# the Arista off the LAN again and looks exactly like a winner that had
# refreshed its assert properly.  The deviation is the window, not the
# state either side of it, so the whole crossing is polled and the
# question is whether the Arista ever came back at all.
#
# Slow by nature: it has to outlive Assert_Time.  AL_SKIP_RESEND=yes
# leaves it out of a quick run.
check_assert_no_resend() {
	print "6. pimd as assert winner, past Assert_Time (RFC 7761 4.6.1)"

	if [ "${AL_SKIP_RESEND:-no}" = yes ]; then
		dprint "  skipped, AL_SKIP_RESEND=yes"
		return
	fi

	# This one needs pimd to be the assert *winner*, which it could not
	# be while M10 stood: without SPTbit its Assert carried the RPT bit
	# and lost to the Arista before any metric was read, so the case
	# reported which deviation blocked it instead of measuring anything.
	# With M10 fixed it runs, and the guard stays for the day pimd cannot
	# win here again.
	if ! establish_election pimd-wins; then
		xfail "pimd could not be made the assert winner here, so the winner resend of sec. 4.6.1 is untested"
		return
	fi
	if [ -z "$al_pimd_fwd" ] || [ -n "$al_eos_fwd" ]; then
		fail "could not make pimd the assert winner, the resend case cannot run"
		kill "$sender" "$receiver" "$joiner" "$joiner6" 2>/dev/null
		wait "$sender" "$receiver" "$joiner" "$joiner6" 2>/dev/null
		return
	fi

	# Poll across the Assert_Time boundary rather than sleeping through
	# it, and remember whether the Arista ever resumed, not what it was
	# doing when the clock ran out.
	resumed=
	deadline=$(($(date +%s) + AL_ASSERT_TIME + AL_ELECTION_WAIT))
	while [ "$(date +%s)" -lt "$deadline" ]; do
		if eos_forwards_on_lan; then
			resumed=yes
			break
		fi
		sleep 5
	done

	# "It never resumed" is only worth anything if it still could have.
	# The Arista's one reason to forward is ED3's membership, and the
	# streams outlive the window by design (AL_STREAM_LIFE) -- but if
	# that ever stops being true, the Arista goes quiet for a reason
	# that has nothing to do with asserts and this case prints a
	# confident ok about a lab that had gone away underneath it.
	if ! eos_has_mroute "$GROUP"; then
		fail "the Arista has no state for $GROUP left, it could not have resumed either way"
		dprint "$(eos "show ip mroute $GROUP")"
	elif [ -z "$resumed" ]; then
		ok "the Arista never resumed in ${AL_ASSERT_TIME}s+, and still holds $GROUP"
	else
		xfail "the Arista resumed forwarding before Assert_Time was out, pimd never resent its Assert (M3 is back, src/pim_proto.c:2874)"
	fi

	kill "$sender" "$receiver" "$joiner" "$joiner6" 2>/dev/null
	wait "$sender" "$receiver" "$joiner" "$joiner6" 2>/dev/null
}

check() {
	jls -j "$(jname r1)" jid >/dev/null 2>&1 || die "lab is not running, run '$0 start'"
	FAILED=0
	XFAILED=0

	case $SCENARIO in
	pimd-rp)    check_pimd_rp;    return $? ;;
	assert-lan) check_assert_lan; return $? ;;
	esac

	print "1. pimd and EOS become PIM neighbours on both links"
	# Both directions, because a Hello pimd sends and EOS silently drops
	# would still leave pimd's own neighbour table looking right.
	if wait_for 60 has_neighbor r1 10.0.12.2; then
		ok "R1 sees the Arista at 10.0.12.2"
	else
		fail "R1 never saw a PIM neighbour at 10.0.12.2"
	fi
	if wait_for 60 has_neighbor r3 10.0.23.2; then
		ok "R3 sees the Arista at 10.0.23.2"
	else
		fail "R3 never saw a PIM neighbour at 10.0.23.2"
	fi
	if wait_for 60 eos_has_neighbor 10.0.12.1; then
		ok "the Arista sees R1 at 10.0.12.1"
	else
		fail "the Arista never saw a PIM neighbour at 10.0.12.1"
	fi
	if wait_for 60 eos_has_neighbor 10.0.23.3; then
		ok "the Arista sees R3 at 10.0.23.3"
	else
		fail "the Arista never saw a PIM neighbour at 10.0.23.3"
	fi
	[ "$FAILED" -eq 0 ] || return 1

	print "2. Both ends elect the same DR on both links"
	# Neither router sets a DR priority, so RFC 7761 4.3.2 leaves the
	# election to the highest address: the Arista on 10.0.12.0/24
	# (.2 > .1), R3 on 10.0.23.0/24 (.3 > .2).  Asserting the two links
	# separately is what makes this a test of the election rather than of
	# one lucky address ordering: pimd has to lose one and win the other.
	#
	# Polled, like every other assertion here: a neighbour that came up
	# one second ago has not been through an election yet, and the first
	# router to answer would otherwise report whatever it believed while
	# it was still alone on the link.
	if wait_for 60 pimd_dr_is r1 ${EP}812b 10.0.12.2; then
		ok "R1 made the Arista DR on 10.0.12.0/24"
	else
		fail "R1 says the DR on 10.0.12.0/24 is '$(pimd_dr r1 ${EP}812b)', expected 10.0.12.2"
	fi
	if wait_for 60 eos_dr_is Ethernet1 10.0.12.2; then
		ok "the Arista agrees it is DR on 10.0.12.0/24"
	else
		fail "the Arista says the DR on 10.0.12.0/24 is '$(eos_dr Ethernet1)', expected 10.0.12.2"
		dprint "$(eos 'show ip pim interface')"
	fi
	if wait_for 60 pimd_dr_is r3 ${EP}823b 10.0.23.3; then
		ok "R3 made itself DR on 10.0.23.0/24"
	else
		fail "R3 says the DR on 10.0.23.0/24 is '$(pimd_dr r3 ${EP}823b)', expected 10.0.23.3"
	fi
	if wait_for 60 eos_dr_is Ethernet2 10.0.23.3; then
		ok "the Arista agrees R3 is DR on 10.0.23.0/24"
	else
		fail "the Arista says the DR on 10.0.23.0/24 is '$(eos_dr Ethernet2)', expected 10.0.23.3"
		dprint "$(eos 'show ip pim interface')"
	fi
	[ "$FAILED" -eq 0 ] || return 1

	print "3. pimd learns the RP set from the Arista's Bootstrap"
	# The exchange no pimd-only test can check: EOS originates the
	# Bootstrap and the Candidate-RP-Advertisement, pimd only parses
	# them.  Demanding $RP_ADDR rather than "an RP" is deliberate, a
	# misparsed address would otherwise pass.
	for r in $ROUTERS; do
		if wait_for 90 has_rp "$r" "$RP_ADDR"; then
			ok "$r learned RP $RP_ADDR"
		else
			fail "$r never learned RP $RP_ADDR from the Arista's Bootstrap"
		fi
	done
	[ "$FAILED" -eq 0 ] || return 1

	print "4. The Arista accepts the (*,G) Join pimd sends it"
	# ED2 joining makes R3 the last hop router for the group and sends a
	# (*,G) Join up the shared tree.  The assertion is on the Arista's
	# own mroute table: the oif can only be there because it believed a
	# Join built by src/pim_proto.c.
	jrun ed2 "$MPING" -r -i "$ED2_IF" -t 5 -W 180 "$GROUP" \
		>"$WORKDIR/receiver.log" 2>&1 &
	receiver=$!

	if wait_for 90 eos_has_mroute "$GROUP"; then
		ok "the Arista has (*, $GROUP) after R3's Join"
	else
		fail "the Arista never built (*, $GROUP) from R3's Join"
		kill "$receiver" 2>/dev/null
		return 1
	fi
	if eos "show ip mroute $GROUP" | grep -q Ethernet2; then
		ok "the Arista put Ethernet2 in the outgoing list"
	else
		fail "the Arista has (*, $GROUP) but not Ethernet2 as an oif"
		dprint "$(eos "show ip mroute $GROUP")"
	fi

	print "5. pimd registers the source to an RP that is not pimd"
	# R1 encapsulates ED1's first packets to the Arista, which has to
	# decapsulate them, build (S,G) and send back a Register-Stop.  Both
	# halves are asserted: the Arista's (S,G) proves the encapsulation
	# was understood, the replies prove the tree carries data.
	jrun ed1 "$MPING" -s -i "$ED1_IF" -t 5 -c "$STREAM_PKTS" -w 120 "$GROUP" \
		>"$WORKDIR/sender.log" 2>&1 || true

	if eos_has_mroute "$SRC_ADDR"; then
		ok "the Arista built ($SRC_ADDR, $GROUP) from R1's Register"
	else
		fail "the Arista never built ($SRC_ADDR, $GROUP)"
		dprint "$(eos "show ip mroute")"
	fi
	if has_mrt r1 "$SRC_ADDR"; then
		ok "R1 holds ($SRC_ADDR, $GROUP)"
	else
		fail "R1 has no ($SRC_ADDR, $GROUP) of its own"
	fi

	kill "$receiver" 2>/dev/null
	wait "$receiver" 2>/dev/null

	print "6. Multicast reaches ED2 across the Arista"
	# Counted from the replies rather than from the receiver's log: mping
	# block buffers stdout and is killed, not stopped, so that log never
	# reaches the disk.  A reply only exists because a packet arrived.
	replies=$(awk '/packets transmitted/ { print $4 }' "$WORKDIR/sender.log")
	replies=${replies:-0}
	if [ "$replies" -ge "$MIN_REPLIES" ]; then
		ok "$replies of $STREAM_PKTS packets answered by ED2"
	else
		fail "only $replies of $STREAM_PKTS packets answered, wanted $MIN_REPLIES"
		dprint "$(eos "show ip mroute")"
	fi

	return $((FAILED > 0))
}

# --- main -------------------------------------------------------------

verdict() {
	known=""
	[ "$XFAILED" -gt 0 ] && known=", $XFAILED known deviation(s)"

	if [ "$FAILED" -eq 0 ]; then
		print "$SCENARIO: all assertions passed$known"
	else
		print "$SCENARIO: $FAILED assertion(s) failed$known"
	fi
}

run_one() {
	set_scenario "$1"
	start
	check
	rc=$?
	verdict
	stop
	return $rc
}

# Scenarios started by run_parallel() and not yet reaped, "slot:name", and
# the shells they run in.  Globals because the INT handler is what reads
# them, and it runs in this shell however deep the loop below is.
PARALLEL_BUSY=
PARALLEL_PIDS=

parallel_abort() {
	trap - INT TERM

	echo
	print "Interrupted, taking down the labs that were still up ..."
	for pid in $PARALLEL_PIDS; do
		kill "$pid" 2>/dev/null || true
	done
	# The scenario shell is gone, its jails and its VM are not: each
	# slot is asked to stop itself, which is the teardown a finished
	# run does, vEOS included.
	for entry in $PARALLEL_BUSY; do
		"$0" -s "${entry%%:*}" stop >/dev/null 2>&1 || true
	done

	exit 130
}

# Several scenarios at a time, each in a slot of its own.
#
# What makes that safe is the slot: every jail, link, bridge, tap, VM name
# and work directory carries one, so two scenarios meet only on the host
# itself.  What bounds it is the vEOS, not the lab -- each scenario boots
# one, and each one is 4G of RAM and a 4G raw disk converted from the
# qcow2 the first time that VM name is used.  Three scenarios in parallel
# is 12G of guest memory and 12G of disk.
#
# Each scenario's output is collected and printed whole when it ends.
# Interleaved line by line the assertions of three runs are unreadable,
# and worse, unattributable: each scenario prints "ok 3." and means a
# different thing by it.
run_parallel() {
	jobs=$JOBS
	pending=$1

	[ -z "$WORKDIR_PINNED" ] || \
		die "WORKDIR is set in the environment, so every slot would" \
		    "share one work directory; unset it to run in parallel"

	last=$((SLOT + jobs - 1))
	[ "$last" -le 31 ] || \
		die "-j $jobs from slot $SLOT wants slots up to $last, and 31 is the last one"

	out=$(mktemp -d "${TMPDIR:-/tmp}/pimd-interop-parallel.XXXXXX")
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
				# set +e because the redirection failing, or
				# the run itself, would otherwise take the
				# subshell out before it could say so; the
				# status is moved into place rather than
				# written there, so the file cannot be seen
				# half written by the loop below
				set +e
				"$0" -i "$VEOS_QCOW" -s "$slot" run "$scenario" \
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

# "run", "run <scenario>", "run <scenario> <scenario>", "run all".  With
# -j the named scenarios are run several at a time, each in a slot of its
# own; without it they are run one after another, as they always were.
run() {
	if [ "${1:-}" = all ]; then
		list=$SCENARIOS
	elif [ $# -gt 1 ]; then
		list=$*
	else
		# One scenario, which is the common case: run it in this
		# shell, so its assertions reach the terminal as they are
		# made rather than in one block at the end.
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
	check
	rc=$?
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
